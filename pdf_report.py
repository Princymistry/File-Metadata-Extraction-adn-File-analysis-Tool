"""
pdf_report.py  —  File Metadata Extraction and Analysis Tool PDF Report Generator
=====================================================
Drop-in replacement for the plain-text export in frontend.py.

Usage (called from ForensicApp.export_report):
    from pdf_report import export_pdf_report
    export_pdf_report(record, filepath)

The generated PDF has:
  • White background
  • Diagonal "File Metadata" watermark on every page
  • Colour-coded risk banner
  • All forensic fields organised in themed sections
  • SHA-256 hash
  • Entropy bar
  • Page numbers + header/footer on every page
"""

import datetime
import os
from xml.sax.saxutils import escape as _xml_escape

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.platypus.flowables import Flowable


# ─────────────────────────────────────────────────────────────
# SAFE TEXT HELPER  — prevents XML/ReportLab injection
# ─────────────────────────────────────────────────────────────
def _safe(value, default="—") -> str:
    """
    Escape special XML/HTML characters in a string for safe PDF embedding.
    
    Prevents XML injection attacks by escaping characters like <, >, &, ",
    that could break the PDF generation or be used maliciously. Returns a
    default value if the input is None or empty.
    
    Args:
        value: The string to escape
        default: Default string to return if value is empty/None
    
    Returns:
        XML-escaped string safe for embedding in PDF content
    """
    if value is None or str(value).strip() == "":
        return default
    return _xml_escape(str(value))


# ─────────────────────────────────────────────────────────────
# COLOUR PALETTE
# ─────────────────────────────────────────────────────────────
C = {
    "blue":      colors.HexColor("#3B6FEA"),
    "blue_lt":   colors.HexColor("#EBF0FD"),
    "teal":      colors.HexColor("#0EA5B4"),
    "green":     colors.HexColor("#16A34A"),
    "green_lt":  colors.HexColor("#DCFCE7"),
    "amber":     colors.HexColor("#D97706"),
    "amber_lt":  colors.HexColor("#FEF3C7"),
    "red":       colors.HexColor("#DC2626"),
    "red_lt":    colors.HexColor("#FEE2E2"),
    "purple":    colors.HexColor("#7C3AED"),
    "purple_lt": colors.HexColor("#EDE9FE"),
    "grey":      colors.HexColor("#64748B"),
    "grey_lt":   colors.HexColor("#F1F5F9"),
    "dark":      colors.HexColor("#0F172A"),
    "muted":     colors.HexColor("#94A3B8"),
    "white":     colors.white,
    "border":    colors.HexColor("#E3E8EF"),
}

RISK_COLORS = {
    "critical": (C["red"],    C["red_lt"],    "⚠  VT HIT — MALICIOUS"),
    "mismatch": (C["amber"],  C["amber_lt"],  "⚡  TYPE MISMATCH DETECTED"),
    "highent":  (C["amber"],  colors.HexColor("#FEF9C3"), "◈  HIGH ENTROPY"),
    "hidden":   (C["purple"], C["purple_lt"], "👁  HIDDEN FILE"),
    "clean":    (C["green"],  C["green_lt"],  "✓  CLEAN"),
}

PAGE_W, PAGE_H = A4
MARGIN = 20 * mm


# ─────────────────────────────────────────────────────────────
# RISK HELPER
# ─────────────────────────────────────────────────────────────
def _get_risk(record):
    """
    Determine the risk level of a file for PDF report coloring.
    
    Analyzes file metadata (VirusTotal score, entropy, extension mismatch,
    hidden status) and returns the highest risk category. Used to color-code
    the risk banner in the PDF report.
    
    Args:
        record: Dictionary containing file analysis data
    
    Returns:
        Risk level string: 'critical', 'mismatch', 'highent', 'hidden', or 'clean'
    """
    vt = record.get("vt_score") or "N/A"
    vt_hit = (
        "/" in str(vt)
        and not str(vt).startswith("0/")
        and str(vt) not in ("N/A", "Not Found", "Error")
    )
    if vt_hit:
        return "critical"

    ft   = (record.get("file_type") or "").lower()
    rext = (record.get("real_file_extension") or "").lower()

    if ft and rext and ft != rext and ft not in ("unknown", "empty") and rext not in ("unknown", "empty"):
        try:
            import backend
            if backend.is_extension_mismatch(ft, rext):
                return "mismatch"
        except ImportError:
            return "mismatch"

    if (record.get("entropy") or 0.0) > 7.0:
        return "highent"
    if record.get("is_hidden"):
        return "hidden"
    return "clean"


def _fmt_size(sz):
    """
    Format a file size in bytes to human-readable format.
    
    Converts bytes to GB, MB, or KB with appropriate formatting and
    includes the original byte count in parentheses.
    
    Args:
        sz: Size in bytes (integer)
    
    Returns:
        Formatted string like "1.50 GB  (1,610,612,736 bytes)"
    """
    sz = sz or 0
    if sz >= 1_073_741_824: return f"{sz / 1_073_741_824:.2f} GB  ({sz:,} bytes)"
    if sz >= 1_048_576:     return f"{sz / 1_048_576:.2f} MB  ({sz:,} bytes)"
    if sz >= 1024:          return f"{sz / 1024:.2f} KB  ({sz:,} bytes)"
    return f"{sz} bytes"


# ─────────────────────────────────────────────────────────────
# ENTROPY BAR FLOWABLE
# ─────────────────────────────────────────────────────────────
class EntropyBar(Flowable):
    """
    Custom ReportLab flowable for drawing an entropy bar chart.
    
    Draws a horizontal bar showing entropy level with color coding:
    - Green for low entropy (text/structured data)
    - Yellow/Orange for medium entropy (compressed)
    - Red for high entropy (possibly encrypted)
    
    The bar includes tick marks and labels showing the 0.0 to 8.0 scale.
    """

    def __init__(self, entropy, width=140 * mm, height=14 * mm):
        super().__init__()
        self.entropy = entropy
        self.width   = width
        self.height  = height

    def draw(self):
        c = self.canv
        zones = [
            (0, 1,   "#DCFCE7"),
            (1, 4,   "#D1FAE5"),
            (4, 6,   "#FEF3C7"),
            (6, 7,   "#FED7AA"),
            (7, 7.5, "#FECACA"),
            (7.5, 8, "#FEE2E2"),
        ]
        bar_h  = 8 * mm
        zone_w = self.width / 8.0

        for lo, hi, col in zones:
            c.setFillColor(colors.HexColor(col))
            c.rect(lo * zone_w, 0, (hi - lo) * zone_w, bar_h, stroke=0, fill=1)

        ent_col = "#16A34A" if self.entropy < 4 else ("#D97706" if self.entropy < 7 else "#DC2626")
        c.setFillColor(colors.HexColor(ent_col))
        c.setFillAlpha(0.35)
        c.rect(0, 0, self.entropy * zone_w, bar_h, stroke=0, fill=1)
        c.setFillAlpha(1.0)

        c.setStrokeColor(colors.HexColor(ent_col))
        c.setLineWidth(2)
        x_marker = self.entropy * zone_w
        c.line(x_marker, -1 * mm, x_marker, bar_h + 1 * mm)

        c.setFont("Helvetica-Bold", 9)
        c.setFillColor(colors.HexColor(ent_col))
        lx = min(x_marker + 2 * mm, self.width - 14 * mm)
        c.drawString(lx, bar_h + 1.5 * mm, f"{self.entropy:.4f}")

        c.setFont("Helvetica", 6)
        c.setFillColor(colors.HexColor("#64748B"))
        for v in range(9):
            c.drawCentredString(v * zone_w, -4 * mm, str(v))

        c.setStrokeColor(colors.HexColor("#E3E8EF"))
        c.setLineWidth(0.5)
        c.rect(0, 0, self.width, bar_h, stroke=1, fill=0)


# ─────────────────────────────────────────────────────────────
# WATERMARK + HEADER/FOOTER CANVAS
# ─────────────────────────────────────────────────────────────
class WatermarkCanvas(rl_canvas.Canvas):
    """
    Custom PDF canvas with watermark and page headers/footers.
    
    Extends the standard ReportLab Canvas to add:
    - Diagonal "File Metadata" watermark on every page
    - Page header with title
    - Page footer with page numbers
    
    Applied automatically to every page of the generated PDF.
    """

    def __init__(self, filename, **kwargs):
        super().__init__(filename, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_watermark()
            self._draw_header_footer(self._pageNumber, total)
            rl_canvas.Canvas.showPage(self)
        rl_canvas.Canvas.save(self)

    def _draw_watermark(self):
        self.saveState()
        self.setFont("Helvetica-Bold", 52)
        self.setFillColor(colors.HexColor("#E3E8EF"))
        self.setFillAlpha(0.55)
        self.translate(PAGE_W / 2, PAGE_H / 2)
        self.rotate(40)
        self.drawCentredString(0, 30,  "File Metadata")
        self.drawCentredString(0, -40, "File Metadata")
        self.restoreState()

    def _draw_header_footer(self, page_num, total_pages):
        self.saveState()
        self.setFillColor(colors.HexColor("#1A2238"))
        self.rect(0, PAGE_H - 14 * mm, PAGE_W, 14 * mm, stroke=0, fill=1)
        self.setFont("Helvetica-Bold", 10)
        self.setFillColor(colors.white)
        self.drawString(MARGIN, PAGE_H - 9 * mm, "File Metadata Extraction and Analysis Tool  —  File Metadata Report")
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#94A3B8"))
        ts = datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
        self.drawRightString(PAGE_W - MARGIN, PAGE_H - 9 * mm, ts)
        self.restoreState()

        self.saveState()
        self.setStrokeColor(colors.HexColor("#E3E8EF"))
        self.setLineWidth(0.5)
        self.line(MARGIN, 10 * mm, PAGE_W - MARGIN, 10 * mm)
        self.setFont("Helvetica", 7)
        self.setFillColor(colors.HexColor("#94A3B8"))
        self.drawString(MARGIN, 6 * mm, "Generated by File Metadata Extraction and Analysis Tool v2.5  •  Confidential")
        self.drawRightString(
            PAGE_W - MARGIN, 6 * mm,
            f"Page {page_num} of {total_pages}"
        )
        self.restoreState()


# ─────────────────────────────────────────────────────────────
# STYLE SHEET
# ─────────────────────────────────────────────────────────────
def _build_styles():
    """
    Build and return the paragraph styles for the PDF report.
    
    Creates a dictionary of ReportLab paragraph styles including:
    - Title, section headers, normal text
    - Risk-colored styles (critical, warning, success)
    - Monospace style for hashes
    
    Returns:
        Dictionary of named ParagraphStyle objects
    """
    base = getSampleStyleSheet()
    styles = {}

    styles["report_title"] = ParagraphStyle(
        "report_title", parent=base["Title"],
        fontSize=20, textColor=C["dark"], fontName="Helvetica-Bold",
        spaceAfter=2 * mm, leading=24,
    )
    styles["section_head"] = ParagraphStyle(
        "section_head", parent=base["Heading2"],
        fontSize=11, textColor=C["blue"], fontName="Helvetica-Bold",
        spaceBefore=4 * mm, spaceAfter=2 * mm, leading=14,
    )
    styles["label"] = ParagraphStyle(
        "label", parent=base["Normal"],
        fontSize=8, textColor=C["grey"], fontName="Helvetica-Bold",
        leading=12,
    )
    styles["value"] = ParagraphStyle(
        "value", parent=base["Normal"],
        fontSize=9, textColor=C["dark"], fontName="Helvetica",
        leading=12, wordWrap="CJK",
    )
    styles["mono"] = ParagraphStyle(
        "mono", parent=base["Normal"],
        fontSize=8, textColor=C["purple"], fontName="Courier",
        leading=11, wordWrap="CJK",
    )
    styles["risk_text"] = ParagraphStyle(
        "risk_text", parent=base["Normal"],
        fontSize=12, fontName="Helvetica-Bold",
        alignment=TA_CENTER, leading=16,
    )
    styles["caption"] = ParagraphStyle(
        "caption", parent=base["Normal"],
        fontSize=7.5, textColor=C["muted"], fontName="Helvetica",
        leading=10, alignment=TA_CENTER,
    )
    styles["footer_note"] = ParagraphStyle(
        "footer_note", parent=base["Normal"],
        fontSize=7, textColor=C["muted"], fontName="Helvetica-Oblique",
        alignment=TA_CENTER, leading=10,
    )
    return styles


# ─────────────────────────────────────────────────────────────
# TABLE BUILDER HELPER  (with XML escaping)
# ─────────────────────────────────────────────────────────────
def _build_field_table(rows, styles, col_widths=(50 * mm, 110 * mm)):
    """
    rows: list of (label_str, value_str, optional_value_style_key)
    All user-controlled values are XML-escaped before embedding.
    Returns a styled Table flowable.
    """
    data = []
    for item in rows:
        label     = _safe(item[0])
        value     = _safe(item[1])
        val_style = styles.get(item[2] if len(item) > 2 else "value", styles["value"])
        data.append([
            Paragraph(label, styles["label"]),
            Paragraph(value, val_style),
        ])

    tbl = Table(data, colWidths=col_widths, repeatRows=0)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), C["white"]),
        ("ROWBACKGROUNDS",(0, 0), (-1, -1), [C["white"], C["grey_lt"]]),
        ("TOPPADDING",   (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
        ("LEFTPADDING",  (0, 0), (0, -1), 6),
        ("LEFTPADDING",  (1, 0), (1, -1), 8),
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW",    (0, 0), (-1, -2), 0.3, C["border"]),
    ]))
    return tbl


# ─────────────────────────────────────────────────────────────
# MAIN EXPORT FUNCTION
# ─────────────────────────────────────────────────────────────
def export_pdf_report(record: dict, output_path: str,
                      db_path: str = "forensic_data.db",
                      investigator_name: str = None,
                      investigator_badge: str = None,
                      investigator_org: str = None,
                      sign_report: bool = False) -> None:
    """
    Generate a forensic analysis PDF report for a file.
    
    Creates a professional PDF report containing all forensic metadata
    about a file, organized into themed sections:
    - File Overview (name, size, type, timestamps)
    - Type Detection (claimed vs actual type, magic bytes)
    - Cryptographic Hashes (SHA-256)
    - Entropy Analysis (entropy value and visualization)
    - Timestamps (created, modified, accessed)
    - Metadata (author, owner, source)
    - Security (permissions, hidden status, VirusTotal score)
    
    The report includes color-coded risk indicators, visual entropy bar,
    and watermark on every page.
    
    Args:
        record: Dictionary containing all file analysis data
        output_path: Path where the PDF file should be saved
        db_path: Path to forensic database (for fetching related data)
        investigator_name: Optional name to include as investigator
        sign_report: Whether to include a signature line
    
    Returns:
        None (PDF is written to output_path)
    """
    """
    Generate a PDF forensic report for *record* and save to *output_path*.

    Parameters
    ----------
    record             : dict returned by backend.get_all_records()
    output_path        : full path including .pdf extension
    db_path            : path to the SQLite database (used for integrity data)
    investigator_name  : name of investigator (informational; signing not available)
    sign_report        : reserved for future use (signing module not included)
    """
    styles = _build_styles()
    risk   = _get_risk(record)
    r_fg, r_bg, r_label = RISK_COLORS.get(risk, RISK_COLORS["clean"])

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=18 * mm, bottomMargin=16 * mm,
        title=f"File Metadata Extraction and Analysis Tool Report — {record.get('filename', 'Unknown')}",
        author="File Metadata Extraction and Analysis Tool v2.5",
        subject="File Metadata Forensic Report",
    )

    story = []

    # ── Title ──────────────────────────────────────────────────────────────
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("FILE FORENSIC REPORT", styles["report_title"]))
    story.append(Paragraph(
        f"<font color='#94A3B8' size='8'>Generated: "
        f"{datetime.datetime.now().strftime('%A, %d %B %Y  %H:%M:%S')}</font>",
        styles["caption"]
    ))
    if investigator_name:
        story.append(Paragraph(
            f"<font color='#64748B' size='8'>Investigator: {_safe(investigator_name)}</font>",
            styles["caption"]
        ))
    story.append(Spacer(1, 3 * mm))
    story.append(HRFlowable(width="100%", thickness=1.5,
                             color=C["blue"], spaceAfter=4 * mm))

    # ── Risk Banner ────────────────────────────────────────────────────────
    risk_para = Paragraph(
        f"<font color='{r_fg.hexval()}'>{r_label}</font>",
        styles["risk_text"]
    )
    risk_tbl = Table([[risk_para]], colWidths=[PAGE_W - 2 * MARGIN])
    risk_tbl.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, -1), r_bg),
        ("TOPPADDING",  (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",(0,0), (-1, -1), 6),
        ("ROUNDEDCORNERS", [4]),
    ]))
    story.append(KeepTogether([risk_tbl]))
    story.append(Spacer(1, 4 * mm))

    # ── Section: Identity ──────────────────────────────────────────────────
    story.append(Paragraph("Identity", styles["section_head"]))
    story.append(_build_field_table([
        ("File Name",  record.get("filename", "—")),
        ("File Path",  record.get("filepath", "—")),
        ("File Size",  _fmt_size(record.get("file_size", 0))),
        ("Extension (declared)", record.get("file_type", "—")),
    ], styles))
    story.append(Spacer(1, 3 * mm))

    # ── Section: File Signature ────────────────────────────────────────────
    story.append(Paragraph("File Signature (Magic Bytes)", styles["section_head"]))
    real_ext  = record.get("real_file_extension", "") or "—"
    real_desc = record.get("real_file_description", "") or "—"
    magic     = record.get("magic_bits", "") or "—"
    ft        = record.get("file_type", "") or ""
    is_mm     = False
    try:
        import backend
        is_mm = backend.is_extension_mismatch(ft, real_ext)
    except ImportError:
        is_mm = (ft and real_ext and ft.lower() != real_ext.lower()
                 and ft not in ("unknown", "empty")
                 and real_ext not in ("unknown", "empty"))

    ext_display = (
        f"{real_ext}  WARNING: MISMATCH with '.{ft}'" if is_mm else real_ext
    )
    story.append(_build_field_table([
        ("Real Extension",  ext_display),
        ("Description",     real_desc),
        ("Magic Bytes",     magic, "mono"),
    ], styles))
    story.append(Spacer(1, 3 * mm))

    # ── Section: Cryptographic Hashes ─────────────────────────────────────
    story.append(Paragraph("Cryptographic Hashes", styles["section_head"]))
    sha    = record.get("sha256_hash", "") or "—"
    hash_rows = [("SHA-256", sha, "mono")]
    story.append(_build_field_table(hash_rows, styles))
    story.append(Spacer(1, 3 * mm))

    # ── Section: Entropy Analysis ─────────────────────────────────────────
    story.append(Paragraph("Entropy Analysis", styles["section_head"]))
    entropy = record.get("entropy", 0.0) or 0.0
    if entropy > 7.5:
        ent_note = "VERY HIGH — possible encryption / packing"
    elif entropy > 6.0:
        ent_note = "Elevated — may indicate compression"
    elif entropy < 1.0:
        ent_note = "Very low — likely plain text or empty"
    else:
        ent_note = "Normal range"

    ent_rows = [
        ("Shannon Entropy", f"{entropy:.4f} / 8.0000"),
        ("Interpretation",  ent_note),
    ]
    story.append(_build_field_table(ent_rows, styles))
    story.append(Spacer(1, 2 * mm))
    story.append(EntropyBar(entropy, width=PAGE_W - 2 * MARGIN - 4 * mm))
    story.append(Spacer(1, 6 * mm))

    # ── Section: Timestamps ────────────────────────────────────────────────
    story.append(Paragraph("Timestamps", styles["section_head"]))
    story.append(_build_field_table([
        ("Created",     record.get("created_time",  "—")),
        ("Modified",    record.get("modified_time", "—")),
        ("Accessed",    record.get("accessed_time", "—")),
        ("Analyzed At", record.get("analyzed_at",   "—")),
    ], styles))
    story.append(Spacer(1, 3 * mm))

    # ── Section: Ownership & Permissions ──────────────────────────────────
    story.append(Paragraph("Ownership & Permissions", styles["section_head"]))
    hidden = record.get("is_hidden", False)
    story.append(_build_field_table([
        ("Author",      record.get("author", "—")),
        ("Owner",       record.get("owner",  "—")),
        ("Permissions", record.get("permissions", "—")),
        ("Hidden File", "Yes  (WARNING)" if hidden else "No"),
    ], styles))
    story.append(Spacer(1, 3 * mm))

    # ── Section: Source & Origin ───────────────────────────────────────────
    story.append(Paragraph("Source & Origin", styles["section_head"]))
    source = record.get("source_of_file", "—")
    url    = record.get("download_url",   "—")
    story.append(_build_field_table([
        ("Source",       source),
        ("Download URL", url),
    ], styles))
    story.append(Spacer(1, 3 * mm))

    # ── Section: VirusTotal ────────────────────────────────────────────────
    story.append(Paragraph("Reputation (VirusTotal)", styles["section_head"]))
    vt = record.get("vt_score", "N/A")
    vt_note = ""
    if vt == "Not Found":          vt_note = "(Unique / new file — not in VT database)"
    elif vt == "Rate Limited":     vt_note = "(API rate limited — retry later)"
    elif vt == "Invalid API Key":  vt_note = "(Check your API key settings)"
    elif "/" in str(vt):
        if not str(vt).startswith("0/"):
            vt_note = "WARNING: MALICIOUS DETECTIONS"
        else:
            vt_note = "No detections"
    vt_display = f"{vt}  {vt_note}".strip()
    vt_link = ""
    if sha and sha != "—":
        vt_link = f"https://www.virustotal.com/gui/file/{sha}"
    story.append(_build_field_table([
        ("VT Score",      vt_display),
        ("Analysis Link", vt_link, "mono"),
    ], styles))
    story.append(Spacer(1, 5 * mm))

    # ── File Integrity ─────────────────────────────────────────────────────
    story.append(Paragraph("File Integrity", styles["section_head"]))
    try:
        import backend as _backend
        ic = _backend.get_integrity_check_for_file(db_path, record.get("filename", ""))
    except Exception:
        ic = None

    if ic is None:
        story.append(Paragraph(
            "No integrity check recorded for this file yet.",
            styles["value"]))
    else:
        st = ic.get("status", "new")
        status_map = {
            "new":       ("NEW — first time this file was analysed",       "#2563EB"),
            "unchanged": ("UNCHANGED — content matches stored hash",       "#15803D"),
            "modified":  ("MODIFIED — hash differs from stored record!",   "#B91C1C"),
        }
        status_text, status_color = status_map.get(st, (st.upper(), "#000000"))
        story.append(Paragraph(
            f'<font color="{status_color}"><b>{_safe(status_text)}</b></font>',
            styles["value"]))
        rows = []
        new_h = ic.get("new_hash") or ""
        if new_h:
            rows.append(("Current Hash", new_h, "mono"))
        stored_h = ic.get("stored_hash") or ""
        if stored_h and st == "modified":
            rows.append(("Stored Hash",  stored_h, "mono"))
        rows.append(("Checked At", ic.get("checked_at") or "—"))
        if rows:
            story.append(_build_field_table(rows, styles))
    story.append(Spacer(1, 5 * mm))

    # ── Digital Signature Block ────────────────────────────────────────────
    story.append(Paragraph("Digital Signature", styles["section_head"]))

    import hashlib as _hashlib
    import uuid    as _uuid

    # Compute a report integrity hash from key forensic fields
    # so anyone can verify the report has not been tampered with.
    _hash_src = "|".join(str(record.get(k, "")) for k in [
        "filename", "filepath", "sha256_hash", "file_size",
        "created_time", "modified_time", "permissions",
        "source_of_file", "entropy", "vt_score",
    ])
    report_hash = _hashlib.sha256(_hash_src.encode("utf-8")).hexdigest()
    report_id   = str(_uuid.uuid4()).upper()
    signed_at   = datetime.datetime.now().strftime("%A, %d %B %Y  %H:%M:%S")

    if investigator_name:
        # ── Filled signature block ────────────────────────────────────────
        sig_rows = [
            ("Investigator",   investigator_name),
            ("Badge / ID",     investigator_badge or "—"),
            ("Organization",   investigator_org   or "—"),
            ("Signed At",      signed_at),
            ("Report ID",      report_id),
        ]
        story.append(_build_field_table(sig_rows, styles))
        story.append(Spacer(1, 4 * mm))

        # Report integrity hash
        story.append(Paragraph("Report Integrity Hash (SHA-256)", styles["section_head"]))
        story.append(Paragraph(
            "This hash is computed from the key forensic fields in this report. "
            "If any field is altered after signing, this hash will no longer match.",
            styles["value"]
        ))
        story.append(Spacer(1, 2 * mm))
        story.append(_build_field_table([
            ("SHA-256 (Report)", report_hash, "mono"),
        ], styles))
        story.append(Spacer(1, 6 * mm))

        # Visual signature line
        sig_line_data = [[
            Paragraph(
                f"<font size='9' color='#0F172A'><b>Signed by:</b>  "
                f"{_safe(investigator_name)}"
                + (f"  |  {_safe(investigator_badge)}" if investigator_badge else "")
                + (f"  |  {_safe(investigator_org)}"   if investigator_org   else "")
                + f"  |  {signed_at}</font>",
                styles["value"]),
        ]]
        sig_tbl = Table(sig_line_data, colWidths=[PAGE_W - 2 * MARGIN])
        sig_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), C["blue_lt"]),
            ("LINEABOVE",     (0, 0), (-1, 0),  1.5, C["blue"]),
            ("LEFTPADDING",   (0, 0), (-1, -1), 10),
            ("TOPPADDING",    (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(KeepTogether([sig_tbl]))
    else:
        # ── No investigator provided — show placeholder fields ────────────
        story.append(Paragraph(
            "No investigator details were provided when this report was generated. "
            "For court-admissible use, re-export the report and enter the "
            "investigator's name and credentials when prompted.",
            styles["value"]
        ))
        story.append(Spacer(1, 4 * mm))
        blank_rows = [
            ("Investigator",  "________________________________"),
            ("Badge / ID",    "________________________________"),
            ("Organization",  "________________________________"),
            ("Signature",     "________________________________"),
            ("Date",          "________________________________"),
        ]
        story.append(_build_field_table(blank_rows, styles))
    story.append(Spacer(1, 5 * mm))


    # ── Disclaimer footer ──────────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=0.5,
                             color=C["border"], spaceAfter=3 * mm))
    story.append(Paragraph(
        "This report was automatically generated by the File Metadata Extraction and Analysis Tool v2.5. "
        "All findings should be validated by a qualified digital forensics professional. "
        "This document is confidential and intended for authorised use only.",
        styles["footer_note"]
    ))

    # ── Build ──────────────────────────────────────────────────────────────
    doc.build(story, canvasmaker=WatermarkCanvas)


# ─────────────────────────────────────────────────────────────
# STANDALONE TEST
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    sample = {
        "id": 42,
        "filename":               "suspicious_document.docx",
        "filepath":               "C:\\Users\\Analyst\\Downloads\\suspicious_document.docx",
        "file_size":              2_457_600,
        "file_type":              "docx",
        "real_file_extension":    "exe",
        "real_file_description":  "Windows Executable (PE)",
        "magic_bits":             "4D5A9000",
        "sha256_hash":            "a3f5b2c1d4e6f7890abc123456def7890abc123456def7890abc12345678",
        "md5_hash":               "d41d8cd98f00b204e9800998ecf8427e",
        "sha1_hash":              "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "entropy":                7.82,
        "chi_square":             180.5,
        "serial_correlation":     0.002341,
        "created_time":           "Local: 2024-11-15 09:32:00 | UTC: 2024-11-15 04:02:00",
        "modified_time":          "Local: 2025-01-20 14:10:45 | UTC: 2025-01-20 08:40:45",
        "accessed_time":          "Local: 2025-03-28 11:05:30 | UTC: 2025-03-28 05:35:30",
        "analyzed_at":            "Local: 2025-03-29 08:00:00 | UTC: 2025-03-29 02:30:00",
        "author":                 "Unknown",
        "owner":                  "DESKTOP-XYZ\\Analyst",
        "source_of_file":         "Internet",
        "download_url":           "https://malicious-site.example.com/payload",
        "permissions":            "Read/Write",
        "is_hidden":              True,
        "vt_score":               "8/72",
    }

    out = "forensic_report_sample.pdf"
    export_pdf_report(sample, out)
    print(f"PDF saved → {out}")
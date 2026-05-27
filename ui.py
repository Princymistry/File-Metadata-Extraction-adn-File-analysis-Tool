import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import threading
import os
import json
import webbrowser
import datetime
import backend

# ══════════════════════════════════════════════════════════════
# DESIGN TOKENS
# ══════════════════════════════════════════════════════════════
C = {
    # ── Sidebar (dark blue — unchanged) ──────────────────
    "sidebar":      "#111827",
    "sidebar_hi":   "#1F2937",
    "sidebar_sec":  "#0B1120",
    "sep_side":     "#1F2D45",
    "t_side":       "#6B7280",
    "t_side_hi":    "#FFFFFF",

    # ── Content area (light / white theme) ───────────────
    "page":         "#F8FAFC",
    "card":         "#FFFFFF",
    "card_alt":     "#F1F5F9",
    "header":       "#FFFFFF",
    "border":       "#E2E8F0",
    "border_dark":  "#CBD5E1",

    # ── Accent colours ───────────────────────────────────
    "blue":         "#2563EB",
    "blue_lt":      "#DBEAFE",
    "blue_dk":      "#1D4ED8",
    "teal":         "#0891B2",
    "teal_lt":      "#CCFBF1",
    "green":        "#16A34A",
    "green_lt":     "#DCFCE7",
    "amber":        "#D97706",
    "amber_lt":     "#FEF3C7",
    "red":          "#DC2626",
    "red_lt":       "#FEE2E2",
    "red_dark":     "#991B1B",
    "purple":       "#7C3AED",
    "purple_lt":    "#EDE9FE",

    # ── Text on light backgrounds ────────────────────────
    "t_primary":    "#0F172A",
    "t_secondary":  "#475569",
    "t_muted":      "#94A3B8",
    "t_white":      "#F8FAFC",

    # ── Treeview rows (light) ────────────────────────────
    "row_even":     "#FFFFFF",
    "row_odd":      "#F8FAFC",
    "row_sel":      "#DBEAFE",
    "row_sel_fg":   "#1D4ED8",
    "row_warn":     "#FEF2F2",
    "row_warn_fg":  "#DC2626",
    "row_mismatch": "#FFFBEB",
    "row_mis_fg":   "#B45309",
    "row_hidden":   "#F5F3FF",
    "row_hid_fg":   "#7C3AED",
    "row_highent":  "#FFFBEB",
    "row_hent_fg":  "#B45309",
    "row_dup":      "#FDF2F8",
    "row_dup_fg":   "#BE185D",
    "th_bg":        "#F1F5F9",
    "th_fg":        "#475569",
    "scrollbar":    "#CBD5E1",
    "progress":     "#2563EB",
    "accent1":      "#06B6D4",
    "accent2":      "#8B5CF6",

    # ── Duplicate colours (light-friendly) ───────────────
    "dup_orig_bg":  "#F0FDF4",
    "dup_orig_bd":  "#22C55E",
    "dup_copy_bg":  "#FDF2F8",
    "dup_copy_bd":  "#F472B6",
    "dup_dark":     "#9D174D",
    "dup_mid":      "#BE185D",

    # ── Integrity check status colours (light) ───────────
    "integ_new":        "#DBEAFE",
    "integ_new_fg":     "#1D4ED8",
    "integ_ok":         "#DCFCE7",
    "integ_ok_fg":      "#15803D",
    "integ_mod":        "#FEE2E2",
    "integ_mod_fg":     "#DC2626",
}

F = {
    "h1":        ("Segoe UI Semibold", 16, "bold"),
    "h2":        ("Segoe UI", 13, "bold"),
    "h3":        ("Segoe UI", 12, "bold"),
    "body":      ("Segoe UI", 10),
    "body_sm":   ("Segoe UI", 9),
    "caption":   ("Segoe UI", 8),
    "mono":      ("Consolas", 10),
    "mono_sm":   ("Consolas", 9),
    "btn":       ("Segoe UI Semibold", 9, "bold"),
    "side_nav":  ("Segoe UI", 10),
    "label_up":  ("Segoe UI", 7, "bold"),
    "badge":     ("Segoe UI", 8, "bold"),
    "stat_num":  ("Segoe UI Semibold", 24, "bold"),
    "stat_lbl":  ("Segoe UI", 9),
    "brand":     ("Segoe UI Semibold", 11, "bold"),
    "brand_sub": ("Segoe UI", 7),
}

# ══════════════════════════════════════════════════════════════
# RISK HELPER
# ══════════════════════════════════════════════════════════════
def get_risk(record):
    """
    Determine the primary risk level of a file based on analysis data.
    
    Analyzes file metadata to determine the highest risk category that
    applies. Checks for VirusTotal detections, high entropy, type mismatches,
    internet origin, hidden status, and duplicates. Returns the most severe risk.
    
    Args:
        record: Dictionary containing file analysis data
    
    Returns:
        Risk category string: 'critical', 'mismatch', 'highent', 'hidden', or 'clean'
    """
    vt = record.get("vt_score") or "N/A"
    vt_hit = (
        "/" in str(vt)
        and not str(vt).startswith("0/")
        and str(vt) not in ("N/A", "Not Found", "Error")
    )
    if vt_hit:
        return "critical"
    
    file_type = (record.get("file_type") or " ").lower()
    real_ext  = (record.get("real_file_extension") or " ").lower()
    
    if backend.is_extension_mismatch(file_type, real_ext):
        return "mismatch"
    
    if (record.get("entropy") or 0.0) > 7.0:
        return "highent"
    
    if record.get("is_hidden"):
        return "hidden"
    
    return "clean"

def get_all_risk_alerts(record, all_records=None, db_path=None):
    """
    Get all risk alerts that apply to a file, not just the primary one.
    
    Returns a list of all risk conditions detected for a file, including
    high entropy, type mismatch, internet download, hidden file, duplicates,
    and VirusTotal detections. Used to display all alerts in the UI.
    
    Args:
        record: Dictionary containing file analysis data
        all_records: List of all records (for duplicate detection)
        db_path: Database path for integrity checks
    
    Returns:
        List of alert name strings describing all detected risks
    """
    alerts = []
    
    # VT Malicious
    vt = record.get("vt_score") or " "
    vt_hit = (
        vt and isinstance(vt, str) and
        any(x in str(vt).lower() for x in ["malicious", "suspicious", "threat", "phishing"]) and
        not str(vt).startswith("0/") and
        str(vt) not in ("N/A", "Not Found", "Error")
    )
    if vt_hit:
        alerts.append("VT Malicious")
    
    # Type Mismatch
    file_type = (record.get("file_type") or " ").lower()
    real_ext = (record.get("real_file_extension") or " ").lower()
    if backend.is_extension_mismatch(file_type, real_ext):
        alerts.append("Type Mismatch")
    
    # High Entropy
    if (record.get("entropy") or 0.0) > 7.0:
        alerts.append("High Entropy")
    
    # Hidden File
    if record.get("is_hidden"):
        alerts.append("Hidden File")
    
    # Internet Download
    if record.get("source_of_file") == "Internet":
        alerts.append("Internet Download")
    
    # Duplicate File
    if all_records is not None:
        sha = record.get("sha256_hash") or " "
        if sha:
            from collections import defaultdict
            hash_map = defaultdict(list)
            for rec in all_records:
                h = rec.get("sha256_hash") or " "
                if h:
                    hash_map[h].append(rec)
            if len(hash_map.get(sha, [])) > 1:
                alerts.append("Duplicate File")
    
    # File Modified (integrity check)
    if db_path:
        try:
            ic = backend.get_integrity_check_for_file(db_path, record.get("filename", ""))
            if ic and ic.get("status") == "modified":
                alerts.append("File Modified")
        except Exception:
            pass
    
    # Clean File (no other alerts)
    if not alerts:
        alerts.append("Clean File")
    
    return alerts

RISK_LABEL = {
    "critical":  "⚠ VT HIT",
    "mismatch":  "⚡ MISMATCH",
    "highent":   "◈ HIGH ENT",
    "hidden":    "👁 HIDDEN",
    "clean":     "✓ CLEAN",
}

RISK_FG = {
    "critical": C["red"],
    "mismatch": C["amber"],
    "highent":   "#B45309",
    "hidden":   C["purple"],
    "clean":    C["green"],
}

RISK_BG = {
    "critical": C["red_lt"],
    "mismatch": C["amber_lt"],
    "highent":   "#FEF9C3",
    "hidden":   C["purple_lt"],
    "clean":    C["green_lt"],
}

# ── Per-alert colour map (fg, bg) for individual alert badges ──
ALERT_COLORS = {
    "Clean File":        {"fg": "#15803D", "bg": "#DCFCE7"},  # Green
    "High Entropy":      {"fg": "#B45309", "bg": "#FEF3C7"},  # Amber / Yellow
    "Duplicate File":    {"fg": "#BE185D", "bg": "#FDF2F8"},  # Pink
    "Internet Download": {"fg": "#0E7490", "bg": "#CFFAFE"},  # Cyan / Teal
    "Hidden File":       {"fg": "#7C3AED", "bg": "#EDE9FE"},  # Purple
    "Type Mismatch":     {"fg": "#C2410C", "bg": "#FFEDD5"},  # Orange
    "VT Malicious":      {"fg": "#DC2626", "bg": "#FEE2E2"},  # Red
    "File Modified":     {"fg": "#DC2626", "bg": "#FEE2E2"},  # Red (integrity)
}

# ══════════════════════════════════════════════════════════════
# DUPLICATE ALERT DIALOG
# ══════════════════════════════════════════════════════════════
class DuplicateAlertDialog(tk.Toplevel):
    """
    Shows ORIGINAL (already in DB) vs NEW FILE (COPY just uploaded).
    The existing DB record is always the ORIGINAL.
    The newly analysed file is always the COPY.
    """
    def __init__(self, parent, new_data: dict, duplicates: list):
        super().__init__(parent)
        self.transient(parent)
        self.grab_set()
        self.resizable(False, False)
        self.title("Duplicate File Detected")
        self.configure(bg=C["card"])
        self._build(new_data, duplicates)
        self.update_idletasks()
        pw = parent.winfo_width();  ph = parent.winfo_height()
        px = parent.winfo_rootx();  py = parent.winfo_rooty()
        dw = self.winfo_reqwidth(); dh = self.winfo_reqheight()
        self.geometry(f"+{px + (pw - dw)//2}+{py + (ph - dh)//2}")
        self.focus_set()

    def _build(self, new_data, duplicates):
        # ── Title bar ──────────────────────────────────────────
        title_bar = tk.Frame(self, bg="#7F1D1D")
        title_bar.pack(fill=tk.X)
        tk.Label(title_bar, text="  🔁  DUPLICATE FILE DETECTED ",
                 bg="#7F1D1D", fg="#FEE2E2",
                 font=("Segoe UI Semibold", 12, "bold"),
                 pady=14).pack(side=tk.LEFT)
        tk.Label(title_bar,
                 text=f"  {len(duplicates)} match{'es' if len(duplicates) >1 else ''} found   ",
                 bg="#991B1B", fg="#FCA5A5",
                 font=("Segoe UI", 9, "bold"),
                 pady=14).pack(side=tk.RIGHT)

        body = tk.Frame(self, bg=C["card"], padx=24, pady=18)
        body.pack(fill=tk.BOTH, expand=True)

        # Explanation strip
        expl = tk.Frame(body, bg="#FFFBEB",
                        highlightbackground="#FDE68A", highlightthickness=1)
        expl.pack(fill=tk.X, pady=(0, 18))
        tk.Label(expl,
                 text="⚠  What does this mean? ",
                 bg="#FFFBEB", fg="#92400E",
                 font=("Segoe UI", 9, "bold"),
                 padx=14, pady=6).pack(anchor="w")
        tk.Label(expl,
                 text="The file you just analysed has the SAME SHA-256 hash as a file already in the database.\n"
                      "Same hash = byte-for-byte identical content.\n"
                      "The file already in the database is the ORIGINAL. Your new file is the COPY. ",
                 bg="#FFFBEB", fg="#78350F",
                 font=("Segoe UI", 9),
                 justify=tk.LEFT, padx=14).pack(anchor="w", pady=(0, 8))

        for dup_idx, dup in enumerate(duplicates):
            compare = tk.Frame(body, bg=C["card"])
            compare.pack(fill=tk.X, pady=(0, 14))

            # LEFT – ORIGINAL (already in DB)
            left_outer = tk.Frame(compare, bg=C["dup_orig_bd"], padx=1, pady=1)
            left_outer.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 6))
            left = tk.Frame(left_outer, bg=C["dup_orig_bg"], padx=14, pady=12)
            left.pack(fill=tk.BOTH, expand=True)

            orig_badge = tk.Frame(left, bg="#15803D")
            orig_badge.pack(anchor="w", pady=(0, 8))
            tk.Label(orig_badge, text="  ORIGINAL FILE   ",
                     bg="#15803D", fg="white",
                     font=("Segoe UI", 8, "bold"),
                     padx=4, pady=3).pack()
            tk.Label(left, text="Already in database — came first ",
                     bg=C["dup_orig_bg"], fg="#15803D",
                     font=("Segoe UI", 7)).pack(anchor="w", pady=(0, 8))

            tk.Label(left, text="📄 ", bg=C["dup_orig_bg"],
                     font=("Segoe UI", 22)).pack(anchor="w")
            tk.Label(left,
                     text=dup.get("filename", "— "),
                     bg=C["dup_orig_bg"], fg=C["t_primary"],
                     font=("Segoe UI", 10, "bold"),
                     wraplength=220, justify=tk.LEFT).pack(anchor="w", pady=(4, 2))
            tk.Label(left,
                     text=dup.get("filepath", "— "),
                     bg=C["dup_orig_bg"], fg=C["t_muted"],
                     font=("Consolas", 7),
                     wraplength=220, justify=tk.LEFT).pack(anchor="w")

            tk.Frame(left, bg=C["dup_orig_bd"], height=1).pack(fill=tk.X, pady=8)
            ts_orig = (dup.get("analyzed_at") or " ").split("| ")[0].replace("Local: ", " ").strip()
            self._meta_row(left, C["dup_orig_bg"], "🕐 First seen ", ts_orig or "— ")
            self._meta_row(left, C["dup_orig_bg"], "🆔 DB Record ", f"#{dup.get('id','?')} ")
            self._meta_row(left, C["dup_orig_bg"], "📦 Type ",
                           f".{dup.get('file_type','?').upper()} ")

            # Arrow
            arrow_frame = tk.Frame(compare, bg=C["card"], width=40)
            arrow_frame.pack(side=tk.LEFT, fill=tk.Y)
            arrow_frame.pack_propagate(False)
            tk.Label(arrow_frame, text="⟵\nCOPY\nOF ",
                     bg=C["card"], fg=C["t_muted"],
                     font=("Segoe UI", 7, "bold"),
                     justify=tk.CENTER).place(relx=0.5, rely=0.5, anchor="center")

            # RIGHT – NEW FILE (COPY, just uploaded)
            right_outer = tk.Frame(compare, bg=C["dup_copy_bd"], padx=1, pady=1)
            right_outer.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(6, 0))
            right = tk.Frame(right_outer, bg=C["dup_copy_bg"], padx=14, pady=12)
            right.pack(fill=tk.BOTH, expand=True)

            copy_badge = tk.Frame(right, bg="#BE185D")
            copy_badge.pack(anchor="w", pady=(0, 8))
            tk.Label(copy_badge, text="  NEW FILE (COPY)   ",
                     bg="#BE185D", fg="white",
                     font=("Segoe UI", 8, "bold"),
                     padx=4, pady=3).pack()
            tk.Label(right, text="Just uploaded — this is a duplicate copy ",
                     bg=C["dup_copy_bg"], fg="#BE185D",
                     font=("Segoe UI", 7)).pack(anchor="w", pady=(0, 8))

            tk.Label(right, text="🆕 ", bg=C["dup_copy_bg"],
                     font=("Segoe UI", 22)).pack(anchor="w")
            tk.Label(right,
                     text=new_data.get("filename", "— "),
                     bg=C["dup_copy_bg"], fg=C["t_primary"],
                     font=("Segoe UI", 10, "bold"),
                     wraplength=220, justify=tk.LEFT).pack(anchor="w", pady=(4, 2))
            tk.Label(right,
                     text=new_data.get("filepath", "— "),
                     bg=C["dup_copy_bg"], fg=C["t_muted"],
                     font=("Consolas", 7),
                     wraplength=220, justify=tk.LEFT).pack(anchor="w")

            tk.Frame(right, bg=C["dup_copy_bd"], height=1).pack(fill=tk.X, pady=8)
            ts_new = (new_data.get("analyzed_at") or " ").split("| ")[0].replace("Local: ", " ").strip()
            self._meta_row(right, C["dup_copy_bg"], "🕐 Uploaded at ", ts_new or "— ")
            self._meta_row(right, C["dup_copy_bg"], "🆔 Status ",       "Copy — added to DB ")
            self._meta_row(right, C["dup_copy_bg"], "📦 Type ",
                           f".{new_data.get('file_type','?').upper()} ")

        # SHA256
        sha = new_data.get("sha256_hash", " ")
        if sha:
            tk.Frame(body, bg=C["border"], height=1).pack(fill=tk.X, pady=(4, 10))
            hash_card = tk.Frame(body, bg="#F8F0FF",
                                 highlightbackground="#DDD6FE", highlightthickness=1)
            hash_card.pack(fill=tk.X)
            inner_h = tk.Frame(hash_card, bg="#F8F0FF")
            inner_h.pack(fill=tk.X, padx=12, pady=8)
            tk.Label(inner_h, text="🔐  SHARED SHA-256 HASH  (proves they are identical) ",
                     bg="#F8F0FF", fg=C["purple"],
                     font=("Segoe UI", 8, "bold")).pack(anchor="w")
            tk.Label(inner_h, text=sha,
                     bg="#F8F0FF", fg=C["purple"],
                     font=("Consolas", 8),
                     wraplength=540, justify=tk.LEFT).pack(anchor="w", pady=(3, 0))

        btn_row = tk.Frame(body, bg=C["card"])
        btn_row.pack(fill=tk.X, pady=(16, 0))
        if sha:
            self._action_btn(btn_row, "📋  Copy Hash ", C["purple_lt"], C["purple"],
                             lambda: self._copy(sha)).pack(side=tk.LEFT, padx=(0, 8))
        self._action_btn(btn_row, "✓  Understood, Close ", C["green_lt"], C["green"],
                         self.destroy).pack(side=tk.RIGHT)
        self.protocol("WM_DELETE_WINDOW", self.destroy)

    def _meta_row(self, parent, bg, label, value):
        row = tk.Frame(parent, bg=bg)
        row.pack(fill=tk.X, pady=1)
        tk.Label(row, text=label, bg=bg, fg=C["t_muted"],
                 font=("Segoe UI", 7, "bold"), width=14, anchor="w").pack(side=tk.LEFT)
        tk.Label(row, text=value,  bg=bg, fg=C["t_primary"],
                 font=("Segoe UI", 8), anchor="w").pack(side=tk.LEFT, padx=(4, 0))

    def _action_btn(self, parent, text, bg, fg, cmd):
        b = tk.Label(parent, text=text, bg=bg, fg=fg,
                     font=("Segoe UI", 9, "bold"),
                     padx=14, pady=7, cursor="hand2")
        b.bind("<Enter>",           lambda e: b.config(bg=fg, fg="white"))
        b.bind("<Leave>",           lambda e: b.config(bg=bg, fg=fg))
        b.bind("<ButtonRelease-1>", lambda e: cmd())
        return b

    def _copy(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)


# ══════════════════════════════════════════════════════════════
# METADATA CHANGE SUMMARY DIALOG
# ══════════════════════════════════════════════════════════════
class MetadataChangeSummaryDialog(tk.Toplevel):
    """
    Dialog showing metadata changes when re-analyzing a file.
    
    When a previously analyzed file is scanned again, this dialog displays
    a side-by-side comparison of the old metadata versus the new metadata.
    Changes are highlighted to show what fields have been modified.
    
    This helps users track file modifications over time.
    """

    COMPARE_FIELDS = [
        # (db_key, display_label, field_type, is_security_critical)
        ("sha256_hash",         "SHA-256 Hash",     "hash",  True),
        ("md5_hash",            "MD5 Hash",         "hash",  True),
        ("sha1_hash",           "SHA-1 Hash",       "hash",  False),
        ("file_size",           "File Size",        "size",  False),
        ("modified_time",       "Modified Time",    "time",  False),
        ("created_time",        "Created Time",     "time",  False),
        ("accessed_time",       "Accessed Time",    "time",  False),
        ("entropy",             "Entropy",          "float", False),
        ("filename",            "File Name",        "text",  False),
        ("filepath",            "File Path",        "text",  False),
        ("file_type",           "Extension",        "text",  False),
        ("real_file_extension", "Real Extension",   "text",  False),
        ("permissions",         "Permissions",      "text",  False),
        ("is_hidden",           "Hidden",           "bool",  False),
        ("author",              "Author",           "text",  False),
        ("owner",               "Owner",            "text",  False),
        ("source_of_file",      "Source",           "text",  False),
        ("vt_score",            "VT Score",         "text",  False),
    ]

    def __init__(self, parent, filename, old_record, new_data):
        super().__init__(parent)
        self.transient(parent)
        self.grab_set()
        self.title(f"Metadata Change Summary — {filename}")
        self.configure(bg=C["card"])
        self.resizable(True, True)
        self._show_all    = tk.BooleanVar(value=False)
        self._old         = old_record or {}
        self._new         = new_data  or {}
        self._filename    = filename
        self._rows_data   = []
        self._btn_changes = None
        self._btn_all     = None
        self._precompute_rows()
        self._build()
        W, H = 900, 620
        self.geometry(f"{W}x{H}")
        self.update_idletasks()
        try:
            px = parent.winfo_rootx(); py = parent.winfo_rooty()
            pw = parent.winfo_width(); ph = parent.winfo_height()
            x  = px + (pw - W) // 2
            y  = py + (ph - H) // 2
            self.geometry(f"{W}x{H}+{x}+{y}")
        except Exception:
            pass
        self.focus_set()

    def _fmt(self, key, val, ftype):
        if val is None or str(val).strip() in ("", " ", "None"):
            return "N/A"
        if ftype == "hash":
            s = str(val)
            return (s[:28] + "...") if len(s) > 28 else s
        if ftype == "size":
            try:
                sz = int(val)
                if sz >= 1_073_741_824: return f"{sz/1_073_741_824:.2f} GB  ({sz:,} B)"
                if sz >= 1_048_576:     return f"{sz/1_048_576:.2f} MB  ({sz:,} B)"
                if sz >= 1024:          return f"{sz/1024:.2f} KB  ({sz:,} B)"
                return f"{sz:,} bytes"
            except Exception:
                return str(val)
        if ftype == "float":
            try:   return f"{float(val):.4f}"
            except: return str(val)
        if ftype == "bool":
            return "Yes" if val else "No"
        s = str(val)
        if ftype == "time":
            s = s.split("| ")[0].replace("Local: ", "").strip()
        return s

    def _precompute_rows(self):
        self._rows_data = []
        # Values that mean "truthy" for bool fields (DB stores 0/1, Python uses True/False)
        _BOOL_TRUE  = {1, True, "1", "True", "true", "Yes", "yes"}
        _BOOL_FALSE = {0, False, "0", "False", "false", "No", "no"}
        for key, label, ftype, critical in self.COMPARE_FIELDS:
            old_raw  = self._old.get(key)
            new_raw  = self._new.get(key)
            old_disp = self._fmt(key, old_raw, ftype)
            new_disp = self._fmt(key, new_raw, ftype)
            # Normalise to a canonical string for comparison
            if ftype == "bool":
                old_n = ("1" if old_raw in _BOOL_TRUE else "0") if old_raw is not None else None
                new_n = ("1" if new_raw in _BOOL_TRUE else "0") if new_raw is not None else None
            else:
                old_n = None if old_raw in (None, "", " ") else str(old_raw).strip()
                new_n = None if new_raw in (None, "", " ") else str(new_raw).strip()
            if old_n is None and new_n is None:
                continue
            changed = (old_n != new_n)
            self._rows_data.append((key, label, old_disp, new_disp, changed, critical))

    def _build(self):
        n_changed  = sum(1 for r in self._rows_data if r[4])
        n_critical = sum(1 for r in self._rows_data if r[4] and r[5])

        # HEADER
        hdr = tk.Frame(self, bg="#0F172A")
        hdr.pack(fill=tk.X)
        hi  = tk.Frame(hdr, bg="#0F172A")
        hi.pack(fill=tk.X, padx=20, pady=12)
        tk.Label(hi, text="METADATA CHANGE SUMMARY",
                 bg="#0F172A", fg="#F8FAFC",
                 font=("Segoe UI Semibold", 13, "bold")).pack(side=tk.LEFT)
        tk.Label(hi, text=f"  {self._filename}  ",
                 bg="#1E3A5F", fg="#93C5FD",
                 font=("Segoe UI", 10), padx=8, pady=3).pack(side=tk.LEFT, padx=10)

        # SUMMARY STRIP
        strip = tk.Frame(self, bg=C["card"],
                         highlightbackground=C["border"], highlightthickness=1)
        strip.pack(fill=tk.X, padx=20, pady=(10, 0))
        si = tk.Frame(strip, bg=C["card"])
        si.pack(fill=tk.X, padx=16, pady=10)

        if n_changed == 0:
            s_bg, s_fg = C["green_lt"], C["green"]
            s_txt = "  No Changes Detected  "
        elif n_critical:
            s_bg, s_fg = C["red_lt"], C["red"]
            s_txt = f"  {n_changed} Change{'s' if n_changed > 1 else ''} Detected  ({n_critical} Critical)  "
        else:
            s_bg, s_fg = "#FEF3C7", "#92400E"
            s_txt = f"  {n_changed} Change{'s' if n_changed > 1 else ''} Detected  "

        tk.Label(si, text=s_txt, bg=s_bg, fg=s_fg,
                 font=("Segoe UI", 10, "bold"), padx=8, pady=6).pack(side=tk.LEFT)

        prev_date = (self._old.get("analyzed_at") or "Unknown").split("| ")[0].replace("Local: ", "").strip()
        tk.Label(si, text=f"  Previous scan: {prev_date}",
                 bg=C["card"], fg=C["t_secondary"],
                 font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=14)

        # Toggle
        tog = tk.Frame(si, bg=C["card"])
        tog.pack(side=tk.RIGHT)
        tk.Label(tog, text="Show: ", bg=C["card"], fg=C["t_muted"],
                 font=("Segoe UI", 8)).pack(side=tk.LEFT)

        def make_tog(text, val):
            b = tk.Label(tog, text=f"  {text}  ", bg=C["border"], fg=C["t_secondary"],
                         font=("Segoe UI", 8, "bold"), padx=4, pady=4, cursor="hand2")
            b.pack(side=tk.LEFT, padx=3)
            b.bind("<ButtonRelease-1>",
                   lambda e, v=val: (self._show_all.set(v), self._refresh_table()))
            return b

        self._btn_changes = make_tog("Changes Only", False)
        self._btn_all     = make_tog("All Fields",   True)

        # CRITICAL BANNER
        if n_critical:
            wb = tk.Frame(self, bg="#FEF2F2",
                          highlightbackground="#FECACA", highlightthickness=2)
            wb.pack(fill=tk.X, padx=20, pady=(8, 0))
            tk.Label(wb,
                     text="  FILE CONTENT MODIFIED  --  SHA-256 hash has changed since the last scan!",
                     bg="#FEF2F2", fg="#B91C1C",
                     font=("Segoe UI", 10, "bold"),
                     padx=12, pady=10).pack(anchor="w")

        # TABLE HEADER
        th = tk.Frame(self, bg=C["th_bg"],
                      highlightbackground=C["border"], highlightthickness=1)
        th.pack(fill=tk.X, padx=20, pady=(8, 0))
        for txt, w in [("Field", 18), ("Previous Value", 26), ("New Value", 26), ("Status", 9)]:
            tk.Label(th, text=txt, bg=C["th_bg"], fg=C["th_fg"],
                     font=("Segoe UI", 9, "bold"), width=w, anchor="w",
                     padx=10, pady=7).pack(side=tk.LEFT)
            tk.Frame(th, bg=C["border"], width=1).pack(side=tk.LEFT, fill=tk.Y)

        # SCROLLABLE TABLE
        outer = tk.Frame(self, bg=C["border"])
        outer.pack(fill=tk.BOTH, expand=True, padx=20)
        self._canvas = tk.Canvas(outer, bg=C["card"], highlightthickness=0)
        vsb = ttk.Scrollbar(outer, orient=tk.VERTICAL, command=self._canvas.yview)
        self._canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self._canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._tbl = tk.Frame(self._canvas, bg=C["card"])
        self._win = self._canvas.create_window((0, 0), window=self._tbl, anchor="nw")
        self._tbl.bind("<Configure>",
                       lambda e: self._canvas.configure(scrollregion=self._canvas.bbox("all")))
        self._canvas.bind("<Configure>",
                          lambda e: self._canvas.itemconfig(self._win, width=e.width))
        self._canvas.bind("<Enter>",
                          lambda e: self._canvas.bind_all(
                              "<MouseWheel>",
                              lambda ev: self._canvas.yview_scroll(-1*(ev.delta//120), "units")))
        self._canvas.bind("<Leave>",
                          lambda e: self._canvas.unbind_all("<MouseWheel>"))
        self._refresh_table()

        # FOOTER
        foot = tk.Frame(self, bg=C["card"],
                        highlightbackground=C["border"], highlightthickness=1)
        foot.pack(fill=tk.X, padx=20, pady=(0, 12))
        fi = tk.Frame(foot, bg=C["card"])
        fi.pack(fill=tk.X, padx=16, pady=10)
        n_total = len(self._rows_data)
        tk.Label(fi,
                 text=f"  {n_total} fields compared   {n_changed} changed   {n_total - n_changed} unchanged  ",
                 bg=C["card"], fg=C["t_muted"],
                 font=("Segoe UI", 8)).pack(side=tk.LEFT)
        close = tk.Label(fi, text="  Close  ",
                         bg="#1D4ED8", fg="white",
                         font=("Segoe UI", 9, "bold"), padx=16, pady=6, cursor="hand2")
        close.pack(side=tk.RIGHT)
        close.bind("<Enter>",           lambda e: close.config(bg="#1E40AF"))
        close.bind("<Leave>",           lambda e: close.config(bg="#1D4ED8"))
        close.bind("<ButtonRelease-1>", lambda e: self.destroy())
        self.protocol("WM_DELETE_WINDOW", self.destroy)

    def _refresh_table(self):
        for w in self._tbl.winfo_children():
            w.destroy()
        show_all = self._show_all.get()
        if self._btn_changes and self._btn_all:
            if show_all:
                self._btn_all.config(bg="#1D4ED8", fg="white")
                self._btn_changes.config(bg=C["border"], fg=C["t_secondary"])
            else:
                self._btn_changes.config(bg="#1D4ED8", fg="white")
                self._btn_all.config(bg=C["border"], fg=C["t_secondary"])

        rows = self._rows_data if show_all else [r for r in self._rows_data if r[4]]

        if not rows:
            ph = tk.Frame(self._tbl, bg=C["card"])
            ph.pack(fill=tk.X, pady=50)
            tk.Label(ph, text="No changes detected since the last scan.",
                     bg=C["card"], fg=C["t_muted"],
                     font=("Segoe UI", 12)).pack(pady=6)
            return

        for idx, (key, label, old_d, new_d, changed, critical) in enumerate(rows):
            if changed and critical:
                rbg = "#FFF5F5"; lfg = "#B91C1C"; vfg = "#DC2626"
                stxt, sbg, sfg = "CHANGED", "#FEE2E2", "#DC2626"
            elif changed:
                rbg = "#FFFBEB"; lfg = "#92400E"; vfg = "#D97706"
                stxt, sbg, sfg = "CHANGED", "#FEF3C7", "#D97706"
            else:
                rbg = C["row_even"] if idx % 2 == 0 else C["row_odd"]
                lfg = C["t_muted"]; vfg = C["t_secondary"]
                stxt, sbg, sfg = "SAME", C["green_lt"], C["green"]

            row = tk.Frame(self._tbl, bg=rbg,
                           highlightbackground=C["border"], highlightthickness=1)
            row.pack(fill=tk.X, pady=(0, 1))
            tk.Label(row, text=label, bg=rbg, fg=lfg,
                     font=("Segoe UI", 9, "bold"), width=18, anchor="w",
                     padx=10, pady=7).pack(side=tk.LEFT)
            tk.Frame(row, bg=C["border"], width=1).pack(side=tk.LEFT, fill=tk.Y)
            tk.Label(row, text=old_d, bg=rbg, fg=vfg,
                     font=("Consolas", 8), width=26, anchor="w",
                     padx=10, pady=7, wraplength=210, justify=tk.LEFT).pack(side=tk.LEFT)
            tk.Frame(row, bg=C["border"], width=1).pack(side=tk.LEFT, fill=tk.Y)
            nfg  = "#DC2626" if (changed and critical) else ("#D97706" if changed else vfg)
            nfnt = ("Consolas", 8, "bold") if changed else ("Consolas", 8)
            tk.Label(row, text=new_d, bg=rbg, fg=nfg,
                     font=nfnt, width=26, anchor="w",
                     padx=10, pady=7, wraplength=210, justify=tk.LEFT).pack(side=tk.LEFT)
            tk.Frame(row, bg=C["border"], width=1).pack(side=tk.LEFT, fill=tk.Y)
            sf = tk.Frame(row, bg=sbg)
            sf.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4)
            tk.Label(sf, text=stxt, bg=sbg, fg=sfg,
                     font=("Segoe UI", 8, "bold")).pack(expand=True, pady=4)


# ══════════════════════════════════════════════════════════════
# HELPER WIDGETS
# ══════════════════════════════════════════════════════════════
class SidebarButton(tk.Canvas):
    """
    Custom sidebar navigation button with icon and text.
    
    A styled canvas-based button for the sidebar that shows an icon,
    text label, and optional badge count. Supports hover effects and
    active state highlighting.
    
    Attributes:
        _active: Whether this button is currently selected
        _hover: Whether mouse is currently over the button
        _command: Function to call when clicked
        _badge_count: Number to show in badge (0 to hide)
    """
    def __init__(self, parent, text="", icon="", command=None,
                 active=False, badge_count=0, **kw):
        super().__init__(parent, height=40, bg=C["sidebar"],
                         highlightthickness=0, cursor="hand2", **kw)
        self._text   = text
        self._icon   = icon
        self.command = command
        self._hover  = False
        self._active = active
        self._badge  = badge_count
        
        self.bind("<Enter>",           lambda e: self._set_hover(True))
        self.bind("<Leave>",           lambda e: self._set_hover(False))
        self.bind("<ButtonRelease-1>", lambda e: self.command() if self.command else None)
        self.bind("<Configure>",       lambda e: self._draw())

    def _set_hover(self, state):
        self._hover = state
        self._draw()

    def set_active(self, state):
        self._active = state
        self._draw()

    def set_badge(self, count):
        self._badge = count
        self._draw()

    def _draw(self):
        self.delete("all")
        w = self.winfo_width()  or 200
        h = self.winfo_height() or 40
        if self._active:
            self.create_rectangle(0, 0, w, h, fill=C["sidebar_hi"], outline="")
            self.create_rectangle(0, 0, 3, h, fill=C["blue"], outline="")
        elif self._hover:
            self.create_rectangle(0, 0, w, h, fill=C["sep_side"], outline="")
        
        label = f"  {self._icon}  {self._text}" if self._icon else f"  {self._text}"
        fg    = C["t_side_hi"] if (self._active or self._hover) else C["t_side"]
        self.create_text(30, h // 2, text=label, anchor="w", fill=fg, font=F["side_nav"])

class StatCard(tk.Frame):
    """
    Statistics display card for the dashboard.
    
    A card widget that displays a statistic with an icon, large number,
    label, and optional trend indicator. Used in the dashboard to show
    file counts, threat counts, and other metrics.
    
    Attributes:
        _num_var: StringVar holding the display number
        icon_bg: Background color for the icon circle
        icon_fg: Foreground color for the icon
        accent_color: Color used for the bottom border accent
    """
    def __init__(self, parent, icon=" ", number="0", label=" ",
                 icon_bg="#DBEAFE", icon_fg="#2563EB",
                 trend=" ", trend_color=None, accent_color=None, **kw):
        super().__init__(parent, bg=C["card"],
                         highlightbackground=C["border"],
                         highlightthickness=1, **kw)
        ac = accent_color or icon_fg
        tk.Frame(self, bg=ac, height=3).pack(fill=tk.X)
        body = tk.Frame(self, bg=C["card"])
        body.pack(fill=tk.BOTH, expand=True, padx=14, pady=10)
        
        icon_frame = tk.Frame(body, bg=icon_bg, width=44, height=44)
        icon_frame.pack(side=tk.LEFT, padx=(0, 12))
        icon_frame.pack_propagate(False)
        tk.Label(icon_frame, text=icon, bg=icon_bg, fg=icon_fg,
                 font=("Segoe UI", 18)).place(relx=0.5, rely=0.5, anchor="center")
        
        text_frame = tk.Frame(body, bg=C["card"])
        text_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self._num_var = tk.StringVar(value=str(number))
        tk.Label(text_frame, textvariable=self._num_var,
                 bg=C["card"], fg=C["t_primary"], font=F["stat_num"]).pack(anchor="w")
        tk.Label(text_frame, text=label,
                 bg=C["card"], fg=C["t_muted"], font=F["stat_lbl"]).pack(anchor="w")
        
        if trend:
            tc = trend_color or C["blue"]
            tk.Label(text_frame, text=trend,
                     bg=C["card"], fg=tc, font=F["caption"]).pack(anchor="w")

    def set_value(self, val):
        self._num_var.set(str(val))

class Divider(tk.Frame):
    """
    Simple horizontal divider line widget.
    
    A thin horizontal line used to visually separate sections in the UI.
    Can be customized with different colors.
    """
    def __init__(self, parent, color=None, **kw):
        super().__init__(parent, bg=color or C["border"], height=1, **kw)

# ══════════════════════════════════════════════════════════════
# SCROLLABLE SIDEBAR FRAME
# ══════════════════════════════════════════════════════════════
class ScrollableSidebar(tk.Frame):
    """
    Scrollable sidebar container for navigation buttons.
    
    A sidebar widget that can contain multiple navigation buttons.
    When the content exceeds the available height, it provides
    vertical scrolling with a scrollbar.
    
    Attributes:
        canvas: The scrollable canvas containing the content
        scrollbar: The vertical scrollbar widget
        content_frame: The frame holding the actual sidebar buttons
    """
    def __init__(self, parent, width=230, **kw):
        super().__init__(parent, bg=C["sidebar"], width=width, **kw)
        self.pack_propagate(False)
        
        self._canvas = tk.Canvas(self, bg=C["sidebar"], highlightthickness=0,
                                 width=width, bd=0)
        self._vsb = tk.Scrollbar(self, orient=tk.VERTICAL,
                                 command=self._canvas.yview, width=4)
        self._canvas.configure(yscrollcommand=self._vsb.set)

        # Only show scrollbar on hover/when needed
        self._canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.inner = tk.Frame(self._canvas, bg=C["sidebar"])
        self._win = self._canvas.create_window((0, 0), window=self.inner,
                                                anchor="nw", tags="inner")

        self.inner.bind("<Configure>", self._on_inner_configure)
        self._canvas.bind("<Configure>", self._on_canvas_configure)

        # Mouse wheel scrolling on sidebar
        self._canvas.bind("<Enter>", self._bind_wheel)
        self._canvas.bind("<Leave>", self._unbind_wheel)
        self.inner.bind("<Enter>", self._bind_wheel)
        self.inner.bind("<Leave>", self._unbind_wheel)

    def _on_inner_configure(self, event):
        self._canvas.configure(scrollregion=self._canvas.bbox("all"))
        # Show scrollbar only if content overflows
        if self.inner.winfo_reqheight() > self._canvas.winfo_height():
            self._vsb.pack(side=tk.RIGHT, fill=tk.Y)
        else:
            self._vsb.pack_forget()

    def _on_canvas_configure(self, event):
        self._canvas.itemconfig("inner", width=event.width)
        self._on_inner_configure(None)

    def _bind_wheel(self, event):
        self._canvas.bind_all("<MouseWheel>", self._on_mousewheel)

    def _unbind_wheel(self, event):
        self._canvas.unbind_all("<MouseWheel>")

    def _on_mousewheel(self, event):
        self._canvas.yview_scroll(-1 * (event.delta // 120), "units")

# ══════════════════════════════════════════════════════════════
# VISUAL ANALYTICS PANEL
# ══════════════════════════════════════════════════════════════
class VisualAnalyticsPanel:
    """
    Panel displaying visual analytics for a selected file.
    
    Shows visual representations of file data including:
    - Metadata completeness chart (horizontal bars)
    - Byte distribution histogram
    - Risk assessment indicators
    
    Updates dynamically when a different file is selected.
    """
    def __init__(self, parent):
        self.parent = parent
        self._current_record = None
        self._all_records    = []
        self._db_path        = None
        self._build()

    def set_all_records(self, records):
        self._all_records = records

    def set_db_path(self, db_path):
        self._db_path = db_path

    def _build(self):
        self.outer = tk.Frame(self.parent, bg=C["page"])
        self.outer.pack(fill=tk.BOTH, expand=True)

        self.top_bar = tk.Frame(self.outer, bg=C["card"],
                                highlightbackground=C["border"], highlightthickness=1)
        self.top_bar.pack(fill=tk.X, padx=20, pady=(14, 0))

        top_inner = tk.Frame(self.top_bar, bg=C["card"])
        top_inner.pack(fill=tk.X, padx=16, pady=10)

        tk.Label(top_inner, text="📈  Visual Analytics ", bg=C["card"],
                 fg=C["t_primary"], font=F["h3"]).pack(side=tk.LEFT)

        self._file_label_var = tk.StringVar(
            value="No file selected — choose a record from All Files tab ")
        self._file_pill = tk.Label(top_inner, textvariable=self._file_label_var,
                                   bg=C["blue_lt"], fg=C["blue"],
                                   font=F["badge"], padx=10, pady=3)
        self._file_pill.pack(side=tk.LEFT, padx=12)

        self._risk_pill_var = tk.StringVar(value=" ")
        self._risk_pill = tk.Label(top_inner, textvariable=self._risk_pill_var,
                                   bg=C["green_lt"], fg=C["green"],
                                   font=F["badge"], padx=10, pady=3)

        scroll_outer = tk.Frame(self.outer, bg=C["page"])
        scroll_outer.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        self._canvas_scroll = tk.Canvas(scroll_outer, bg=C["page"], highlightthickness=0)
        vsb = ttk.Scrollbar(scroll_outer, orient=tk.VERTICAL,
                             command=self._canvas_scroll.yview)
        self._canvas_scroll.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self._canvas_scroll.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self._inner_frame = tk.Frame(self._canvas_scroll, bg=C["page"])
        self._canvas_scroll.create_window((0, 0), window=self._inner_frame,
                                          anchor="nw", tags="inner")
        self._inner_frame.bind("<Configure>", self._on_frame_configure)
        self._canvas_scroll.bind("<Configure>", self._on_canvas_configure)
        self._canvas_scroll.bind("<Enter>",
            lambda e: self._canvas_scroll.bind_all("<MouseWheel>", self._on_mousewheel))
        self._canvas_scroll.bind("<Leave>",
            lambda e: self._canvas_scroll.unbind_all("<MouseWheel>"))

        self._show_placeholder()

    def _on_mousewheel(self, event):
        self._canvas_scroll.yview_scroll(-1 * (event.delta // 120), "units")

    def _on_frame_configure(self, event):
        self._canvas_scroll.configure(scrollregion=self._canvas_scroll.bbox("all"))

    def _on_canvas_configure(self, event):
        self._canvas_scroll.itemconfig("inner", width=event.width)

    def _show_placeholder(self):
        for w in self._inner_frame.winfo_children():
            w.destroy()
        ph = tk.Frame(self._inner_frame, bg=C["card"],
                      highlightbackground=C["border"], highlightthickness=1)
        ph.pack(fill=tk.BOTH, expand=True, pady=40, padx=10)
        tk.Label(ph, text="📊 ", bg=C["card"],
                 font=("Segoe UI", 48)).pack(pady=(50, 10))
        tk.Label(ph,
                 text="Select a file from the All Files tab,\n"
                      "then click  📈 Visual Analytics  to see charts here. ",
                 bg=C["card"], fg=C["t_muted"],
                 font=("Segoe UI", 12), justify=tk.CENTER).pack(pady=(0, 50))

    def render(self, record):
        self._current_record = record
        self._file_label_var.set(record.get("filename", "Unknown "))

        risk = get_risk(record)

        # Check integrity — if modified, override risk pill to show red warning
        _integ_quick = None
        if self._db_path:
            try:
                _integ_quick = backend.get_integrity_check_for_file(
                    self._db_path, record.get("filename", ""))
            except Exception:
                pass

        if _integ_quick and _integ_quick.get("status") == "modified":
            self._risk_pill_var.set("⚠ MODIFIED")
            self._risk_pill.config(bg=C["red_lt"], fg=C["red"])
        else:
            self._risk_pill_var.set(RISK_LABEL.get(risk, " "))
            self._risk_pill.config(bg=RISK_BG.get(risk, C["green_lt"]),
                                   fg=RISK_FG.get(risk, C["green"]))
        self._risk_pill.pack(side=tk.RIGHT)

        for w in self._inner_frame.winfo_children():
            w.destroy()

        import matplotlib
        matplotlib.use("TkAgg")
        import matplotlib.pyplot as plt
        import matplotlib.dates as mdates
        from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
        import matplotlib.gridspec as gridspec
        from collections import defaultdict

        BLUE   = "#2563EB"; TEAL = "#0891B2"; GREEN = "#16A34A"
        AMBER  = "#D97706"; RED  = "#DC2626"; PURPLE = "#7C3AED"
        PINK   = "#BE185D"; GREY = "#94A3B8"; BG    = "#FFFFFF"; PANEL = "#F8FAFC"

        plt.rcParams.update({
            "font.family":  "DejaVu Sans",
            "axes.facecolor": PANEL, "figure.facecolor": BG,
            "axes.edgecolor": "#E2E8F0", "axes.labelcolor": "#475569",
            "axes.titlecolor": "#0F172A", "xtick.color": "#94A3B8",
            "ytick.color": "#94A3B8", "grid.color": "#E2E8F0",
            "grid.linestyle": "--", "grid.alpha": 0.6, "text.color": "#0F172A",
        })

        # ── Determine duplicate status ─────────────────────────
        sha = record.get("sha256_hash", " ")
        is_duplicate = False
        is_original  = False
        duplicate_copies    = []   # records that are copies of THIS record
        duplicate_originals = []   # records that are originals of THIS record

        # ── Fetch integrity status for this record ──────────────────────
        ic_for_viz   = None
        integ_status = None
        integ_stored_fp = " "
        if self._db_path:
            try:
                ic_for_viz = backend.get_integrity_check_for_file(
                    self._db_path, record.get("filename", ""))
            except Exception:
                pass
        if ic_for_viz:
            integ_status    = ic_for_viz.get("status")
            integ_stored_fp = ic_for_viz.get("stored_filepath") or " "

        # ── Integrity alert banner ────────────────────────────────
        if integ_status == "modified":
            ibanner = tk.Frame(self._inner_frame, bg="#FEF2F2",
                               highlightbackground="#FECACA", highlightthickness=2)
            ibanner.pack(fill=tk.X, padx=4, pady=(4, 0))
            ib_in = tk.Frame(ibanner, bg="#FEF2F2")
            ib_in.pack(fill=tk.X, padx=16, pady=10)
            tk.Label(ib_in, text="\u26a0  INTEGRITY ALERT: FILE MODIFIED! ",
                     bg="#FEF2F2", fg="#B91C1C",
                     font=("Segoe UI", 11, "bold")).pack(side=tk.LEFT)
            if integ_stored_fp:
                tk.Label(ib_in, text=f"  vs DB: {integ_stored_fp} ",
                         bg="#FEF2F2", fg="#7F1D1D",
                         font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=8)
        elif integ_status == "unchanged":
            ibanner = tk.Frame(self._inner_frame, bg="#F0FDF4",
                               highlightbackground="#86EFAC", highlightthickness=2)
            ibanner.pack(fill=tk.X, padx=4, pady=(4, 0))
            ib_in = tk.Frame(ibanner, bg="#F0FDF4")
            ib_in.pack(fill=tk.X, padx=16, pady=8)
            tk.Label(ib_in, text="\u2713  INTEGRITY OK \u2014 CONTENT UNCHANGED ",
                     bg="#F0FDF4", fg="#15803D",
                     font=("Segoe UI", 11, "bold")).pack(side=tk.LEFT)

        # ── Duplicate/Original banner ──────────────────────────────
        if sha and self._all_records:
            hash_map = defaultdict(list)
            for r in self._all_records:
                h = r.get("sha256_hash") or " "
                if h:
                    hash_map[h].append(r)
            group = hash_map.get(sha, [])
            if len(group) > 1:
                group_sorted = sorted(group, key=lambda r: r["id"])
                original_record = group_sorted[0]
                if record["id"] == original_record["id"]:
                    is_original  = True
                    duplicate_copies = [r for r in group_sorted if r["id"] != record["id"]]
                else:
                    is_duplicate = True
                    duplicate_originals = [original_record]

        if is_original and duplicate_copies:
            banner = tk.Frame(self._inner_frame, bg="#F0FDF4",
                              highlightbackground="#86EFAC", highlightthickness=2)
            banner.pack(fill=tk.X, padx=4, pady=(4, 0))
            inner_b = tk.Frame(banner, bg="#F0FDF4")
            inner_b.pack(fill=tk.X, padx=16, pady=10)
            tk.Label(inner_b, text="📄  ORIGINAL FILE ",
                     bg="#F0FDF4", fg="#15803D",
                     font=("Segoe UI", 11, "bold")).pack(side=tk.LEFT)
            copy_names = ", ".join(d.get("filename", "? ") for d in duplicate_copies[:3])
            tk.Label(inner_b,
                     text=f"  Copies found: {copy_names} ",
                     bg="#F0FDF4", fg="#166534",
                     font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=8)
        elif is_duplicate:
            banner = tk.Frame(self._inner_frame, bg="#FFF0F6",
                              highlightbackground="#FBCFE8", highlightthickness=2)
            banner.pack(fill=tk.X, padx=4, pady=(4, 0))
            inner_b = tk.Frame(banner, bg="#FFF0F6")
            inner_b.pack(fill=tk.X, padx=16, pady=10)
            tk.Label(inner_b, text="🔁  COPY (DUPLICATE) ",
                     bg="#FFF0F6", fg="#BE185D",
                     font=("Segoe UI", 11, "bold")).pack(side=tk.LEFT)
            orig_names = ", ".join(d.get("filename", "? ") for d in duplicate_originals[:2])
            tk.Label(inner_b,
                     text=f"  Original: {orig_names} ",
                     bg="#FFF0F6", fg="#9D174D",
                     font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=8)

        def parse_ts(ts_str):
            if not ts_str:
                return None
            try:
                part = ts_str.split("| ")[0].replace("Local: ", " ").strip()
                return datetime.datetime.strptime(part, "%Y-%m-%d %H:%M:%S")
            except Exception:
                return None

        ts_created  = parse_ts(record.get("created_time"))
        ts_modified = parse_ts(record.get("modified_time"))
        ts_accessed = parse_ts(record.get("accessed_time"))
        ts_analyzed = parse_ts(record.get("analyzed_at"))

        file_size = record.get("file_size", 0) or 0
        entropy   = record.get("entropy", 0.0) or 0.0
        vt_score  = record.get("vt_score", "N/A") or "N/A"
        is_hidden = record.get("is_hidden", False)
        source    = record.get("source_of_file", "Local")
        perms     = record.get("permissions", " ") or " "

        # ── Grid of charts ─────────────────────────────────────
        has_dup_row = is_duplicate or (is_original and duplicate_copies)
        n_rows = 4 if has_dup_row else 3
        fig = plt.figure(figsize=(14, 5 * n_rows), dpi=88, facecolor=BG)
        fig.subplots_adjust(hspace=0.58, wspace=0.38,
                            left=0.07, right=0.97, top=0.97, bottom=0.03)
        gs = gridspec.GridSpec(n_rows, 3, figure=fig,
                               height_ratios=([1.3, 1, 1, 1] if has_dup_row else [1.3, 1, 1]))

        # Row 0: Timeline
        ax_time = fig.add_subplot(gs[0, :])
        ax_time.set_title("File Lifecycle Timeline ", fontsize=11,
                          fontweight="bold", pad=10, loc="left")
        ts_events = []
        if ts_created:  ts_events.append(("Created",  ts_created,  GREEN))
        if ts_modified: ts_events.append(("Modified", ts_modified, AMBER))
        if ts_accessed: ts_events.append(("Accessed", ts_accessed, BLUE))
        if ts_analyzed: ts_events.append(("Analyzed", ts_analyzed, PURPLE))

        if ts_events:
            dates = [mdates.date2num(e[1]) for e in ts_events]
            d_min, d_max = min(dates), max(dates)
            span = d_max - d_min
            pad  = max(span * 0.15, 2)
            ax_time.set_xlim(d_min - pad, d_max + pad)
            ax_time.set_ylim(-2.4, 2.4)
            ax_time.axhline(0, color="#CBD5E1", linewidth=2.5, zorder=1)
            if len(dates) > 1:
                ax_time.axvspan(dates[0], dates[-1], alpha=0.04, color=BLUE, zorder=0)
            y_positions = [1.4, -1.4, 1.4, -1.4]
            for i, (label, dt, col) in enumerate(ts_events):
                x = mdates.date2num(dt)
                y_tip = y_positions[i % len(y_positions)]
                is_above = y_tip > 0
                ax_time.plot([x, x], [0, y_tip * 0.80],
                             color=col, linewidth=1.5, linestyle="--", alpha=0.55, zorder=2)
                ax_time.scatter([x], [0], color=col, s=170, zorder=5,
                                edgecolors="white", linewidths=2.5)
                va  = "bottom" if is_above else "top"
                ytx = y_tip * 0.86
                ax_time.text(x, ytx,
                             f"{label}\n{dt.strftime('%Y-%m-%d')}\n{dt.strftime('%H:%M:%S')}",
                             ha="center", va=va, fontsize=8, color=col, fontweight="bold",
                             bbox=dict(boxstyle="round,pad=0.3", facecolor="white",
                                       edgecolor=col, linewidth=1.2, alpha=0.93))
            ax_time.xaxis_date()
            total_days = d_max - d_min
            if total_days < 1:
                ax_time.xaxis.set_major_formatter(mdates.DateFormatter("%b %d  %H:%M"))
                ax_time.xaxis.set_major_locator(
                    mdates.HourLocator(interval=max(1, int(total_days * 24 / 6))))
            elif total_days < 60:
                ax_time.xaxis.set_major_formatter(mdates.DateFormatter("%b %d"))
                ax_time.xaxis.set_major_locator(mdates.WeekdayLocator())
            elif total_days < 400:
                ax_time.xaxis.set_major_formatter(mdates.DateFormatter("%b %Y"))
                ax_time.xaxis.set_major_locator(mdates.MonthLocator())
            else:
                ax_time.xaxis.set_major_formatter(mdates.DateFormatter("%Y"))
                ax_time.xaxis.set_major_locator(mdates.YearLocator())
            plt.setp(ax_time.xaxis.get_majorticklabels(), rotation=0, ha="center", fontsize=8)
            ax_time.set_yticks([])
            ax_time.tick_params(axis="x", which="both", length=4, color="#CBD5E1")
            for spine in ["left", "right", "top"]:
                ax_time.spines[spine].set_visible(False)
            ax_time.spines["bottom"].set_color("#E2E8F0")
            if len(ts_events) >= 2:
                delta = ts_events[-1][1] - ts_events[0][1]
                d = delta.days; h = delta.seconds // 3600
                ax_time.set_xlabel(
                    f"Total span: {d} days  {h} hours "
                    f"   ({ts_events[0][1].strftime('%Y-%m-%d')} "
                    f"to {ts_events[-1][1].strftime('%Y-%m-%d')})",
                    fontsize=8, color=GREY)
        else:
            ax_time.text(0.5, 0.5, "No timestamp data available",
                         ha="center", va="center", color=GREY, fontsize=11,
                         transform=ax_time.transAxes)
            ax_time.set_axis_off()

        # Row 1: Entropy gauge
        ax_ent = fig.add_subplot(gs[1, 0])
        ax_ent.set_title("Shannon Entropy ", fontsize=10, fontweight="bold", pad=6, loc="left")
        zones = [(0, 1, "#DCFCE7", "Plain\nEmpty"), (1, 4, "#D1FAE5", "Text /\nCode"),
                 (4, 6, "#FEF3C7", "Mixed /\nDocs"), (6, 7, "#FED7AA", "Compressed"),
                 (7, 7.5, "#FECACA", "Packed"), (7.5, 8, "#FEE2E2", "Encrypted")]
        for lo, hi, color, _ in zones:
            ax_ent.barh(0, hi - lo, left=lo, height=0.55, color=color, edgecolor="none", zorder=1)
        ent_color = GREEN if entropy < 4 else (AMBER if entropy < 7 else RED)
        ax_ent.barh(0, entropy, height=0.55, color=ent_color, alpha=0.28, zorder=2, edgecolor="none")
        ax_ent.axvline(entropy, color=ent_color, linewidth=3.5, zorder=3)
        text_x = min(entropy + 0.15, 7.4)
        ax_ent.text(text_x, 0.38, f"{entropy:.3f}", color=ent_color,
                    fontsize=11, fontweight="bold", va="bottom")
        ax_ent.set_xlim(0, 8); ax_ent.set_ylim(-0.60, 0.78); ax_ent.set_yticks([])
        ax_ent.set_xticks([0,1,2,3,4,5,6,7,8])
        ax_ent.set_xticklabels(["0", "1", "2", "3", "4", "5", "6", "7", "8"], fontsize=7)
        ax_ent.set_xlabel("bits / byte ", fontsize=8)
        for lo, hi, _, label in zones:
            ax_ent.text((lo + hi) / 2, -0.50, label, ha="center", fontsize=5.5,
                        color="#475569", va="top", linespacing=1.2)
        ax_ent.grid(axis="x", zorder=0, alpha=0.5)

        # Row 1: Risk Radar (with Duplicate axis)
        ax_radar = fig.add_subplot(gs[1, 1], polar=True)
        ax_radar.set_title("Risk Profile ", fontsize=10, fontweight="bold", pad=14, loc="left")
        categories = ["Entropy", "VT\nScore", "Hidden\nFile",
                       "Internet\nOrigin", "Type\nMismatch", "Duplicate\nFile"]
        N = len(categories)
        ent_score  = min(entropy / 8.0, 1.0)
        vt_score_n = 0.0
        if "/" in str(vt_score):
            try:
                mal, tot = [int(x) for x in str(vt_score).split("/")]
                vt_score_n = min(mal / max(tot, 1), 1.0)
            except Exception:
                pass
        hid_score  = 1.0 if is_hidden else 0.0
        inet_score = 1.0 if source == "Internet" else 0.0
        mis_score  = 1.0 if get_risk(record) == "mismatch" else 0.0
        dup_score  = 1.0 if (is_duplicate or is_original) else 0.0

        values  = [ent_score, vt_score_n, hid_score, inet_score, mis_score, dup_score]
        values += values[:1]
        angles  = [n / float(N) * 2 * 3.14159 for n in range(N)]
        angles += angles[:1]
        ax_radar.set_theta_offset(3.14159 / 2)
        ax_radar.set_theta_direction(-1)
        ax_radar.set_xticks(angles[:-1])
        ax_radar.set_xticklabels(categories, fontsize=7)
        ax_radar.set_ylim(0, 1)
        ax_radar.set_yticks([0.25, 0.5, 0.75, 1.0])
        ax_radar.set_yticklabels(["25%", "50%", "75%", "100%"], fontsize=5.5, color=GREY)
        fill_col = GREEN if is_original else (PINK if is_duplicate else RED)
        ax_radar.fill(angles, values, color=fill_col, alpha=0.15)
        ax_radar.plot(angles, values, color=fill_col, linewidth=2)
        for a, v in zip(angles[:-1], values[:-1]):
            c = GREEN if (v > 0.5 and is_original) else \
                (PINK if (v > 0.5 and is_duplicate) else (RED if v > 0.5 else (AMBER if v > 0.2 else GREEN)))
            ax_radar.scatter([a], [v], color=c, s=50, zorder=5, edgecolors="white")

        # Row 1: Permissions
        ax_perm = fig.add_subplot(gs[1, 2])
        ax_perm.set_title("Permissions ", fontsize=10, fontweight="bold", pad=6, loc="left")
        perm_map  = {"Read": BLUE, "Write": AMBER, "Execute": RED}
        has_perms = [k for k in ["Read", "Write", "Execute"] if k in perms]
        no_perms  = [k for k in ["Read", "Write", "Execute"] if k not in perms]
        perm_sizes = [1]*len(has_perms) + [1]*len(no_perms)
        perm_cols  = [perm_map[k] for k in has_perms] + ["#E2E8F0"]*len(no_perms)
        perm_labs  = [f"✓ {k}" for k in has_perms] + [f"✗ {k}" for k in no_perms]
        if perm_sizes:
            ax_perm.pie(perm_sizes, labels=perm_labs, colors=perm_cols, startangle=90,
                        wedgeprops=dict(width=0.52, edgecolor="white", linewidth=2.5),
                        textprops={"fontsize": 9})
            ax_perm.text(0, 0, "RWX", ha="center", va="center",
                         fontsize=10, fontweight="bold", color="#0F172A")
        else:
            ax_perm.text(0.5, 0.5, "No permission data", ha="center", va="center",
                         color=GREY, fontsize=9, transform=ax_perm.transAxes)
            ax_perm.set_axis_off()

        # Row 2: Metadata completeness
        ax_meta = fig.add_subplot(gs[2, 0])
        ax_meta.set_title("Metadata Completeness ", fontsize=10, fontweight="bold", pad=6, loc="left")
        meta_fields = [
            ("Filename",    bool(record.get("filename"))),
            ("SHA-256",     bool(record.get("sha256_hash"))),
            ("Author",      bool(record.get("author") and record["author"] != "Unknown")),
            ("Owner",       bool(record.get("owner") and record["owner"] != "Unknown")),
            ("Created",     bool(record.get("created_time"))),
            ("Modified",    bool(record.get("modified_time"))),
            ("VT Score",    bool(record.get("vt_score") and
                                record["vt_score"] not in ("N/A", "Not Found"))),
            ("Magic Bytes", bool(record.get("magic_bits"))),
        ]
        m_labels = [f[0] for f in meta_fields]
        m_vals   = [1 if f[1] else 0 for f in meta_fields]
        m_cols   = [GREEN if f[1] else "#E2E8F0" for f in meta_fields]
        bars_m   = ax_meta.barh(m_labels, m_vals, color=m_cols, height=0.62, edgecolor="none")
        for bar, val in zip(bars_m, m_vals):
            ax_meta.text(0.03, bar.get_y() + bar.get_height() / 2,
                          "ok" if val else "✗", va="center", fontsize=8,
                         color="white" if val else GREY, fontweight="bold")
        pct = int(sum(m_vals) / len(m_vals) * 100)
        ax_meta.set_xlim(0, 1.28); ax_meta.set_xticks([])
        ax_meta.text(1.14, len(m_labels)/2 - 0.5, f"{pct}% ", va="center", ha="center",
                     fontsize=20, fontweight="bold", color=GREEN if pct >= 70 else AMBER)
        ax_meta.text(1.14, -1.2, "complete", va="center", ha="center", fontsize=8, color=GREY)
        ax_meta.grid(False)

        # Row 2: Quick summary card
        ax_card = fig.add_subplot(gs[2, 1:])
        ax_card.set_title("Quick Summary ", fontsize=10, fontweight="bold", pad=6, loc="left")
        ax_card.set_axis_off()
        risk_color_map = {
            "critical": RED, "mismatch": AMBER,
            "highent":  "#B45309", "hidden": PURPLE, "clean": GREEN,
        }
        r_color = risk_color_map.get(risk, GREEN)

        # If integrity says modified, override the risk label shown in summary
        if integ_status == "modified":
            risk_display_label = "⚠ MODIFIED"
            r_color = RED
        else:
            risk_display_label = RISK_LABEL.get(risk, "CLEAN")

        # Duplicate status row in summary
        if is_original and duplicate_copies:
            dup_status = f"ORIGINAL — {len(duplicate_copies)} cop{'ies' if len(duplicate_copies) >1 else 'y'} exist"
            dup_color  = GREEN
        elif is_duplicate:
            dup_status = "COPY — see Duplicates tab for original"
            dup_color  = PINK
        else:
            dup_status = "No"
            dup_color  = GREEN

        summary_rows = [
            ("Risk Level",   risk_display_label,                                   r_color),
            ("Dup Status",   dup_status,                                            dup_color),
            ("File Type",    f".{record.get('file_type','?').upper()}",             BLUE),
            ("Real Type",    f".{record.get('real_file_extension','?').upper()}",   TEAL),
            ("Entropy",      f"{entropy:.4f} / 8.0000",
             RED if entropy > 7 else (AMBER if entropy > 6 else GREY)),
            ("VT Score",     str(vt_score),
             RED if ("/" in str(vt_score) and not str(vt_score).startswith("0/")) else GREEN),
            ("Hidden",        "Yes" if is_hidden else "No",
             PURPLE if is_hidden else GREEN),
            ("Source",       source, RED if source == "Internet" else GREEN),
            ("Permissions",  perms or "None", GREY),
            ("Integrity",    ("\u26a0 MODIFIED" if integ_status == "modified"
                         else ("\u2713 UNCHANGED" if integ_status == "unchanged"
                         else ("\U0001f195 NEW" if integ_status == "new" else "N/A"))),
             RED if integ_status == "modified" else
             (GREEN if integ_status in ("unchanged", "new") else GREY)),
        ]
        y = 0.96; step = 0.10
        for label, val, col in summary_rows:
            ax_card.text(0.02, y, f"{label}: ", fontsize=9, color="#64748B",
                         transform=ax_card.transAxes, va="top")
            ax_card.text(0.98, y, val, fontsize=9, color=col, fontweight="bold",
                         ha="right", transform=ax_card.transAxes, va="top")
            y -= step
            ax_card.plot([0.02, 0.98], [y+0.04, y+0.04], color="#E2E8F0", linewidth=0.5,
                         transform=ax_card.transAxes, clip_on=False)

        # Row 3 (dup row): Duplicate group chart
        if has_dup_row:
            ax_dup = fig.add_subplot(gs[3, :])
            if is_original and duplicate_copies:
                ax_dup.set_title("[ORIGINAL]  File — Its Copies in Database ",
                                 fontsize=10, fontweight="bold", pad=8, loc="left", color=GREEN)
                ax_dup.set_facecolor("#F0FDF4")
            else:
                ax_dup.set_title("[COPY]  Duplicate Group — Files with Identical Content ",
                                 fontsize=10, fontweight="bold", pad=8, loc="left", color=PINK)
                ax_dup.set_facecolor("#FFF0F6")

            all_in_group = [record] + (duplicate_copies if is_original else duplicate_originals)
            all_in_group.sort(key=lambda r: r.get("id", 0))
            names  = [r.get("filename", "? ")[:30] for r in all_in_group]
            sizes  = [r.get("file_size", 0) or 0 for r in all_in_group]
            colors = [GREEN if r["id"] == all_in_group[0]["id"] else PINK for r in all_in_group]
            labels = ["ORIGINAL" if r["id"] == all_in_group[0]["id"] else "COPY" for r in all_in_group]

            y_pos = range(len(names))
            bars  = ax_dup.barh(list(y_pos), sizes, color=colors, alpha=0.8,
                                edgecolor="white", linewidth=1.5, height=0.5)
            ax_dup.set_yticks(list(y_pos))
            ax_dup.set_yticklabels(names, fontsize=8)
            for i, (bar, lbl, r) in enumerate(zip(bars, labels, all_in_group)):
                w = bar.get_width()
                sz_str = self._fmt_size(w)
                id_str = f"DB #{r.get('id','?')}"
                ax_dup.text(w + max(w*0.01, 100), bar.get_y() + bar.get_height()/2,
                            f"  {lbl}  |  {sz_str}  |  {id_str}",
                            va="center", fontsize=8, color=colors[i], fontweight="bold")
            ax_dup.set_xlabel("File Size (bytes)", fontsize=8)
            ax_dup.set_xlim(0, max(sizes)*1.55 if sizes else 1)
            ax_dup.grid(axis="x", alpha=0.4)
            ax_dup.spines["top"].set_visible(False)
            ax_dup.spines["right"].set_visible(False)

            from matplotlib.patches import Patch
            legend_elements = [
                Patch(facecolor=GREEN, label="Original (first seen)"),
                Patch(facecolor=PINK,  label="Copy (duplicate)"),
            ]
            ax_dup.legend(handles=legend_elements, loc="lower right", fontsize=8, framealpha=0.9)

        canvas = FigureCanvasTkAgg(fig, master=self._inner_frame)
        canvas.draw()
        widget = canvas.get_tk_widget()
        widget.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self._canvas_scroll.yview_moveto(0)

    @staticmethod
    def _fmt_size(sz):
        if sz >= 1_073_741_824: return f"{sz/1_073_741_824:.1f} GB"
        if sz >= 1_048_576:     return f"{sz/1_048_576:.1f} MB"
        if sz >= 1024:          return f"{sz/1024:.1f} KB"
        return f"{sz} B"

# ══════════════════════════════════════════════════════════════
# MAIN APPLICATION
# ══════════════════════════════════════════════════════════════
class ForensicApp:
    """
    Main application class for the File Metadata Extraction Tool.
    
    This is the main application window that provides:
    - File upload and analysis
    - Database browsing and searching
    - Visual analytics display
    - PDF report generation
    - Settings management
    - Activity logging
    
    The app has a sidebar navigation with different views and a main
    content area that changes based on the selected view.
    
    Attributes:
        root: The main Tkinter window
        current_view: Currently active view name
        analysis_history: List of recently analyzed files
        all_records: List of all records from database
        db_path: Path to the forensic database file
    """
    def __init__(self, root):
        self.root = root
        self.root.title("File Metadata Extraction Tool  •  Analysis Dashboard")
        self.root.geometry("1380x840")
        self.root.minsize(1100, 680)
        self.root.configure(bg=C["page"])
        
        self._configure_styles()

        self.db_path       = "forensic_data.db"
        self.activity_db   = "activity_logs.db"
        self.settings_path = "settings.json"

        backend.init_db(self.db_path)
        backend.init_activity_db(self.activity_db)
        self._load_settings()

        self.signatures      = backend.load_signatures("file_signatures_clean.csv")
        self.selected_record = None
        self._all_records    = []
        self._nav_buttons    = {}
        self._sort_col       = "id"
        self._sort_rev       = True

        self._build_ui()
        self.root.update_idletasks()
        self.refresh_database()

    def _configure_styles(self):
        s = ttk.Style(self.root)
        if "clam" in s.theme_names():
            s.theme_use("clam")
        s.configure("TFrame",    background=C["page"])
        s.configure("Card.TFrame", background=C["card"])
        s.configure("TLabel",    background=C["page"],
                    foreground=C["t_primary"], font=F["body"])
        s.configure("Treeview",
                    background=C["row_even"], foreground=C["t_primary"],
                    fieldbackground=C["row_even"], borderwidth=0,
                    font=F["body_sm"], rowheight=34)
        s.configure("Treeview.Heading",
                    background=C["th_bg"], foreground=C["th_fg"],
                    font=("Segoe UI", 9, "bold"), relief="flat")
        s.map("Treeview.Heading", background=[("active", C["border"])])
        s.map("Treeview",
              background=[("selected", C["row_sel"])],
              foreground=[("selected", C["row_sel_fg"])])
        for o in ("Vertical", "Horizontal"):
            s.configure(f"{o}.TScrollbar",
                        troughcolor=C["card_alt"], background=C["scrollbar"],
                        borderwidth=2, relief="solid", width=16, arrowcolor=C["t_primary"])
            s.map(f"{o}.TScrollbar", background=[("active", C["border_dark"])])
        s.configure("Vertical.TScrollbar", darkcolor=C["scrollbar"], lightcolor=C["card_alt"])
        s.configure("Blue.Horizontal.TProgressbar",
                    troughcolor=C["blue_lt"], background=C["blue"],
                    borderwidth=0, thickness=4)
        s.configure("NoTabs.TNotebook", padding=0, borderwidth=0)
        s.layout("NoTabs.TNotebook.Tab", [])

    def _build_ui(self):
        self._build_sidebar()
        self._build_content()

    # ══════════════════════════════════════════════════════
    # SIDEBAR — scrollable
    # ══════════════════════════════════════════════════════
    def _build_sidebar(self):
        self._sidebar = ScrollableSidebar(self.root, width=230)
        self._sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sb  = self._sidebar.inner  # All widgets go inside the scrollable inner frame

        brand = tk.Frame(sb, bg=C["sidebar"])
        brand.pack(fill=tk.X)
        tk.Frame(brand, bg=C["blue"], height=3).pack(fill=tk.X)
        tk.Label(brand, text="🔬", bg=C["sidebar"],
                 font=("Segoe UI", 26)).pack(pady=(18, 2))
        tk.Label(brand, text="File Metadata", bg=C["sidebar"],
                 fg=C["t_white"], font=F["brand"]).pack()
        tk.Label(brand, text="Extraction Tool", bg=C["sidebar"],
                 fg=C["t_white"], font=F["brand"]).pack()
        tk.Label(brand, text="ANALYSIS DASHBOARD", bg=C["sidebar"],
                 fg=C["t_side"], font=F["brand_sub"]).pack(pady=(2, 10))

        self._threat_frame = tk.Frame(sb, bg=C["sidebar"])
        self._threat_frame.pack(fill=tk.X, padx=12, pady=(0, 8))

        tk.Frame(sb, bg=C["sep_side"], height=1).pack(fill=tk.X, padx=16)

        def section_label(text):
            tk.Label(sb, text=text, bg=C["sidebar"], fg="#4B5563",
                     font=F["label_up"]).pack(anchor="w", padx=22, pady=(14, 3))

        section_label("NAVIGATION")
        navs = [
            ("dash",   "Dashboard",          "📊", 0),
            ("files",  "All Files",           "📂", 1),
            ("dups",   "Duplicate Files",     "🔁", 2),
            ("inet",   "Internet Downloads",  "🌐", 3),
            ("logs",   "Activity Logs",       "📋", 4),
            ("viz",    "Visual Analytics",    "📈", 5),
            ("integ",  "Integrity Checks",    "🔒", 6),
        ]
        for key, text, icon, idx in navs:
            btn = SidebarButton(sb, text=text, icon=icon,
                                command=lambda i=idx, k=key: self._switch_tab(i),
                                active=(key == "dash"))
            btn.pack(fill=tk.X, padx=8, pady=1)
            self._nav_buttons[key] = btn

        tk.Frame(sb, bg=C["sep_side"], height=1).pack(fill=tk.X, padx=16, pady=(10, 0))
        section_label("ACTIONS")

        # Consolidated actions
        actions = [
            ("Analyze File",    "🔍", self.analyze_file),
            ("Scan Folder",     "📁", self.scan_folder),
            ("Set VT API Key",  "🔑", self.set_vt_key),
            ("Get VT Score",    "🛡️", self.fetch_vt_score),
            ("Refresh",         "🔄", self.refresh_database),
        ]
        for text, icon, cmd in actions:
            SidebarButton(sb, text=text, icon=icon,
                          command=cmd).pack(fill=tk.X, padx=8, pady=1)

        tk.Frame(sb, bg=C["sep_side"], height=1).pack(fill=tk.X, padx=16, pady=(10, 0))
        section_label("EXPORT  & MANAGE")

        exports = [
            ("Export PDF Report",  "📄", self.export_report),
            ("Export All (CSV)",   "📊", self.export_all_csv),
            ("Clear Database",     "🗑️", self.clear_database),
            ("Clear Logs",         "🧹", self.clear_logs),  # <--- ADDED CLEAR LOGS BUTTON
        ]
        for text, icon, cmd in exports:
            SidebarButton(sb, text=text, icon=icon,
                          command=cmd).pack(fill=tk.X, padx=8, pady=1)

        # Spacer
        tk.Frame(sb, bg=C["sidebar"], height=20).pack(fill=tk.X)
        tk.Frame(sb, bg=C["sep_side"], height=1).pack(fill=tk.X, padx=16)

        footer = tk.Frame(sb, bg=C["sidebar"])
        footer.pack(fill=tk.X, padx=16, pady=10)
        tk.Label(footer, text="●", bg=C["sidebar"],
                 fg=C["green"], font=("Segoe UI", 7)).pack(side=tk.LEFT)
        tk.Label(footer, text="  System Online", bg=C["sidebar"],
                 fg=C["t_side"], font=F["caption"]).pack(side=tk.LEFT)

    def _update_threat_pill(self, records):
        for w in self._threat_frame.winfo_children():
            w.destroy()
        flagged = [r for r in records if get_risk(r) != "clean"]
        if not flagged:
            return
        pill = tk.Frame(self._threat_frame, bg="#1F0A0A",
                        highlightbackground="#3A1515", highlightthickness=1)
        pill.pack(fill=tk.X)
        tk.Label(pill, text="🚨", bg="#1F0A0A",
                 font=("Segoe UI", 13)).pack(side=tk.LEFT, padx=(10, 4), pady=6)
        info = tk.Frame(pill, bg="#1F0A0A")
        info.pack(side=tk.LEFT, pady=6)
        tk.Label(info, text=f"{len(flagged)} threats detected",
                 bg="#1F0A0A", fg="#FCA5A5",
                 font=("Segoe UI", 9, "bold")).pack(anchor="w")
        tk.Label(info, text="Requires investigation",
                 bg="#1F0A0A", fg=C["t_muted"], font=F["caption"]).pack(anchor="w")

    # ══════════════════════════════════════════════════════
    # CONTENT AREA
    # ══════════════════════════════════════════════════════
    def _build_content(self):
        self.content = tk.Frame(self.root, bg=C["page"])
        self.content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._build_header(self.content)

        self.notebook = ttk.Notebook(self.content, style="NoTabs.TNotebook")
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self._build_dashboard_tab()
        self._build_files_tab()
        self._build_duplicates_tab()
        self._build_inet_tab()
        self._build_logs_tab()
        self._build_visual_analytics_tab()
        self._build_integrity_tab()
        self._build_status_bar(self.content)

    def _switch_tab(self, index):
        self.notebook.select(index)
        keys   = ["dash", "files", "dups", "inet", "logs", "viz", "integ"]
        titles = ["Dashboard", "Forensic Data Explorer",
                   "Duplicate Files", "Internet Downloads",
                   "Activity Logs", "Visual Analytics", "Integrity Checks"]
        for i, key in enumerate(keys):
            self._nav_buttons[key].set_active(i == index)
        self.header_title.config(text=titles[index])

    def _open_visual_analytics(self):
        self._switch_tab(5)
        if self.selected_record:
            self.update_status("Rendering charts…", busy=True)
            self.root.after(50, self._render_analytics)
        else:
            self.update_status("📈 Visual Analytics — select a file from All Files tab first")

    def _render_analytics(self):
        try:
            self._viz_panel.set_all_records(self._all_records)
            self._viz_panel.set_db_path(self.db_path)  # pass db_path directly
            self._viz_panel.render(self.selected_record)
            self.update_status(
                f"📈 Charts rendered for: {self.selected_record.get('filename', '')}")
        except Exception as e:
            self.update_status(f"Chart error: {e}")
            messagebox.showerror("Visualisation Error", f"Could not render charts:\n{e}")

    # ── HEADER ──────────────────────────────────────────────
    def _build_header(self, parent):
        header = tk.Frame(parent, bg=C["header"],
                          highlightbackground=C["border"], highlightthickness=1)
        header.pack(fill=tk.X)
        inner = tk.Frame(header, bg=C["header"])
        inner.pack(fill=tk.X, padx=20, pady=11)

        left = tk.Frame(inner, bg=C["header"])
        left.pack(side=tk.LEFT, fill=tk.Y)
        self.header_title = tk.Label(left, text="Dashboard",
                                     bg=C["header"], fg=C["t_primary"], font=F["h1"])
        self.header_title.pack(anchor="w")
        tk.Label(left, text="File forensic metadata extraction and analysis",
                 bg=C["header"], fg=C["t_primary"], font=F["body_sm"]).pack(anchor="w")

        right = tk.Frame(inner, bg=C["header"])
        right.pack(side=tk.RIGHT, fill=tk.Y)

    def _make_header_btn(self, parent, text, bg, hover_bg, cmd):
        b = tk.Label(parent, text=f"  {text}   ", bg=bg,
                     fg=C["t_white"], font=F["btn"], padx=12, pady=8, cursor="hand2")
        b.bind("<Enter>",           lambda e: b.config(bg=hover_bg))
        b.bind("<Leave>",           lambda e: b.config(bg=bg))
        b.bind("<ButtonRelease-1>", lambda e: cmd())
        return b

    # ══════════════════════════════════════════════════════
    # TAB: DASHBOARD
    # ══════════════════════════════════════════════════════
    def _build_dashboard_tab(self):
        dash = tk.Frame(self.notebook, bg=C["page"])
        self.notebook.add(dash, text="Dashboard")

        self._stat_row = tk.Frame(dash, bg=C["page"])
        self._stat_row.pack(fill=tk.X, padx=20, pady=(16, 0))

        self._sc_total    = StatCard(self._stat_row, icon="📁", number="0",
                                     label="Total Files",
                                     icon_bg=C["blue_lt"],   icon_fg=C["blue"],
                                     accent_color=C["blue"])
        self._sc_flagged  = StatCard(self._stat_row, icon="⚠",  number="0",
                                     label="Flagged Items",
                                     icon_bg=C["red_lt"],    icon_fg=C["red"],
                                     trend="Needs review",   trend_color=C["red"],
                                     accent_color=C["red"])
        self._sc_hidden   = StatCard(self._stat_row, icon="👁",  number="0",
                                     label="Hidden Files",
                                     icon_bg=C["purple_lt"], icon_fg=C["purple"],
                                     accent_color=C["purple"])
        self._sc_dups     = StatCard(self._stat_row, icon="🔁",  number="0",
                                     label="Duplicates",
                                     icon_bg=C["dup_copy_bg"], icon_fg=C["dup_mid"],
                                     accent_color=C["dup_mid"])
        self._sc_internet = StatCard(self._stat_row, icon="🌐", number="0",
                                     label="Internet Origin",
                                     icon_bg=C["teal_lt"],   icon_fg=C["teal"],
                                     accent_color=C["teal"])
        self._sc_integ    = StatCard(self._stat_row, icon="🔒", number="0",
                                     label="Modified Files",
                                     icon_bg=C["integ_mod"],  icon_fg=C["integ_mod_fg"],
                                     trend="Integrity alerts", trend_color=C["integ_mod_fg"],
                                     accent_color=C["integ_mod_fg"])

        for sc in (self._sc_total, self._sc_flagged, self._sc_hidden,
                   self._sc_dups, self._sc_internet, self._sc_integ):
            sc.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10), ipady=2)

        panels = tk.Frame(dash, bg=C["page"])
        panels.pack(fill=tk.BOTH, expand=True, padx=20, pady=14)

        left = tk.Frame(panels, bg=C["card"],
                        highlightbackground=C["border"], highlightthickness=1)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))

        lhdr = tk.Frame(left, bg=C["card"])
        lhdr.pack(fill=tk.X, padx=14, pady=(12, 8))
        tk.Label(lhdr, text="⏱  Recently Analyzed", bg=C["card"],
                 fg=C["t_primary"], font=F["h3"]).pack(side=tk.LEFT)
        self._dash_count_var = tk.StringVar(value=" ")
        tk.Label(lhdr, textvariable=self._dash_count_var,
                 bg=C["blue_lt"], fg=C["blue"],
                 font=F["badge"], padx=8, pady=2).pack(side=tk.LEFT, padx=8)
        Divider(left).pack(fill=tk.X)

        cols = ("Filename", "Risk", "Dup", "Entropy", "VT", "Time")
        self.dash_tree = ttk.Treeview(left, columns=cols,
                                      show="headings", selectmode="browse")
        cfg = [("Filename", "File Name",170,tk.W),
               ("Risk",     "Risk",      90,tk.CENTER),
               ("Dup",      "Dup?",      50,tk.CENTER),
               ("Entropy",  "Entropy",   65,tk.CENTER),
               ("VT",       "VT Score",  70,tk.CENTER),
               ("Time",     "Time",     100,tk.W)]
        for col, heading, width, anchor in cfg:
            self.dash_tree.heading(col, text=heading)
            self.dash_tree.column(col, width=width, anchor=anchor)
        self._apply_tree_tags(self.dash_tree)

        dsv = ttk.Scrollbar(left, orient=tk.VERTICAL, command=self.dash_tree.yview)
        dsh = ttk.Scrollbar(left, orient=tk.HORIZONTAL, command=self.dash_tree.xview)
        self.dash_tree.configure(yscroll=dsv.set, xscroll=dsh.set)
        dsv.pack(side=tk.RIGHT, fill=tk.Y)
        dsh.pack(side=tk.BOTTOM, fill=tk.X)
        self.dash_tree.pack(fill=tk.BOTH, expand=True)
        self.dash_tree.bind("<<TreeviewSelect>>", self._on_dash_select)

        right = tk.Frame(panels, bg=C["card"],
                         highlightbackground=C["red_lt"], highlightthickness=1)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        rhdr = tk.Frame(right, bg="#FFF5F5")
        rhdr.pack(fill=tk.X)
        tk.Frame(right, bg=C["red_lt"], height=1).pack(fill=tk.X)
        rinner = tk.Frame(rhdr, bg="#FFF5F5")
        rinner.pack(fill=tk.X, padx=14, pady=10)
        tk.Label(rinner, text="⚠  Flagged Threats", bg="#FFF5F5",
                 fg=C["red"], font=F["h3"]).pack(side=tk.LEFT)
        self._threat_count_var = tk.StringVar(value="0 items")
        tk.Label(rinner, textvariable=self._threat_count_var,
                 bg=C["red_lt"], fg=C["red"],
                 font=F["badge"], padx=8, pady=3).pack(side=tk.LEFT, padx=8)
        Divider(right).pack(fill=tk.X)

        tcols = ("File", "Threat", "Entropy", "VT")
        self.threat_tree = ttk.Treeview(right, columns=tcols,
                                        show="headings", selectmode="browse")
        tcfg = [("File",    "File Name", 160, tk.W),
                ("Threat",  "Threat",     95, tk.CENTER),
                ("Entropy", "Entropy",    68, tk.CENTER),
                ("VT",      "VT Score",   70, tk.CENTER)]
        for col, heading, width, anchor in tcfg:
            self.threat_tree.heading(col, text=heading)
            self.threat_tree.column(col, width=width, anchor=anchor)
        self._apply_tree_tags(self.threat_tree)

        tsv = ttk.Scrollbar(right, orient=tk.VERTICAL, command=self.threat_tree.yview)
        self.threat_tree.configure(yscroll=tsv.set)
        tsv.pack(side=tk.RIGHT, fill=tk.Y)
        self.threat_tree.pack(fill=tk.BOTH, expand=True)
        self.threat_tree.bind("<<TreeviewSelect>>", self._on_threat_select)

    def _apply_tree_tags(self, tree):
        tree.tag_configure("critical",  background=C["row_warn"],    foreground=C["row_warn_fg"])
        tree.tag_configure("mismatch",  background=C["row_mismatch"],foreground=C["row_mis_fg"])
        tree.tag_configure("highent",   background=C["row_highent"], foreground=C["row_hent_fg"])
        tree.tag_configure("hidden",    background=C["row_hidden"],  foreground=C["row_hid_fg"])
        tree.tag_configure("duplicate", background=C["row_dup"],     foreground=C["row_dup_fg"])
        tree.tag_configure("original",  background=C["dup_orig_bg"], foreground="#15803D")
        tree.tag_configure("even",      background=C["row_even"])
        tree.tag_configure("odd",       background=C["row_odd"])

    def _on_dash_select(self, event):
        sel = self.dash_tree.selection()
        if sel:
            rid = int(sel[0])
            r = next((x for x in self._all_records if x["id"] == rid), None)
            if r:
                self.selected_record = r
                self._show_details(r)
                self._switch_tab(1)

    def _on_threat_select(self, event):
        sel  = self.threat_tree.selection()
        if sel:
            rid = int(sel[0])
            r = next((x for x in self._all_records if x["id"] == rid), None)
            if r:
                self.selected_record = r
                self._show_details(r)
                self._switch_tab(1)

    # ══════════════════════════════════════════════════════
    # TAB: ALL FILES
    # ══════════════════════════════════════════════════════
    def _build_files_tab(self):
        files = tk.Frame(self.notebook, bg=C["page"])
        self.notebook.add(files, text="All Files")
        self._build_main_pane(files)

    def _build_main_pane(self, parent):
        container = tk.Frame(parent, bg=C["page"])
        container.pack(fill=tk.BOTH, expand=True, padx=20, pady=14)
        self.paned = ttk.PanedWindow(container, orient=tk.HORIZONTAL)
        self.paned.pack(fill=tk.BOTH, expand=True) 
        self._build_table_panel(self.paned)
        self._build_details_panel(self.paned)

    def _build_table_panel(self, paned):
        wrap = tk.Frame(paned, bg=C["card"],
                        highlightbackground=C["border"], highlightthickness=1)
        paned.add(wrap, weight=55)

        hdr = tk.Frame(wrap, bg=C["card"])
        hdr.pack(fill=tk.X, padx=14, pady=(12, 0))
        tk.Label(hdr, text="Analyzed Files", bg=C["card"],
                 fg=C["t_primary"], font=F["h3"]).pack(side=tk.LEFT)
        self.record_count_var = tk.StringVar(value="0 records")
        tk.Label(hdr, textvariable=self.record_count_var,
                 bg=C["blue_lt"], fg=C["blue"],
                 font=F["badge"], padx=8, pady=2).pack(side=tk.LEFT, padx=10)

        # Filter/Search box
        search_wrap  = tk.Frame(hdr, bg=C["border"])
        search_wrap.pack(side=tk.RIGHT)
        search_inner = tk.Frame(search_wrap, bg="#0F172A")
        search_inner.pack(padx=1, pady=1)
        tk.Label(search_inner, text="🔎", bg=C["card"],
                 fg=C["t_muted"], font=F["body_sm"]).pack(side=tk.LEFT, padx=(8, 0))
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", self.on_filter_change)
        search_entry = tk.Entry(search_inner, textvariable=self.filter_var,
                 bg=C["card"], fg=C["t_primary"],
                 insertbackground=C["blue"], font=F["body"],
                 bd=0, width=26, relief="flat")
        search_entry.configure(insertbackground="#60A5FA")
        search_entry.pack(side=tk.LEFT, ipady=6, padx=(4, 10))

        Divider(wrap).pack(fill=tk.X, pady=(10, 0))

        cols = ("ID", "Filename", "RealExt", "Description",
                 "Size", "Entropy", "VTScore", "DupRole", "Hidden", "Created")
        self.tree = ttk.Treeview(wrap, columns=cols,
                                 show="headings", selectmode="browse")
        col_cfg = [
            ("ID",           "ID",          46,  tk.CENTER,  "id"),
            ("Filename",     "File Name",   165, tk.W,       "filename"),
            ("RealExt",      "Real Type",   74,  tk.CENTER,  "real_file_extension"),
            ("Description",  "Description", 145, tk.W,       "real_file_description"),
            ("Size",         "Size",        74,  tk.E,       "file_size"),
            ("Entropy",      "Entropy",     65,  tk.CENTER,  "entropy"),
            ("VTScore",      "VT Score",    72,  tk.CENTER,  "vt_score"),
            ("DupRole",      "Dup Role",    80,  tk.CENTER,  "sha256_hash"),
            ("Hidden",       "Hidden",      52,  tk.CENTER,  "is_hidden"),
            ("Created",      "Created",     135, tk.W,       "created_time"),
        ]
        for col, heading, width, anchor, sort_key in col_cfg:
            self.tree.heading(col, text=heading,
                              command=lambda sk=sort_key: self._sort_table(sk))
            self.tree.column(col, width=width, anchor=anchor,
                             minwidth=max(40, width - 20))
        self._apply_tree_tags(self.tree)

        sv = ttk.Scrollbar(wrap, orient=tk.VERTICAL,   command=self.tree.yview)
        sh = ttk.Scrollbar(wrap, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscroll=sv.set, xscroll=sh.set)
        sv.pack(side=tk.RIGHT, fill=tk.Y)
        sh.pack(side=tk.BOTTOM, fill=tk.X)
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)

    def _sort_table(self, key):
        if self._sort_col == key:
            self._sort_rev = not self._sort_rev
        else:
            self._sort_col = key
            self._sort_rev = True
        query   = self.filter_var.get().lower().strip()
        records = self._filtered_records(query)
        records.sort(key=lambda r: r.get(key) or 0, reverse=self._sort_rev)
        self._populate_tree(records)

    def _filtered_records(self, query):
        if not query:
            return list(self._all_records)
        return [r for r in self._all_records if
                query in (r.get("filename") or " ").lower() or
                query in (r.get("real_file_extension") or " ").lower() or
                query in (r.get("real_file_description") or " ").lower() or
                query in (r.get("file_type") or " ").lower() or
                query in (r.get("sha256_hash") or " ").lower() or
                query in (r.get("vt_score") or " ").lower()]

    # ── DETAILS PANEL ─────────────────────────────────────
    def _build_details_panel(self, paned):
        wrap = tk.Frame(paned, bg=C["card"],
                        highlightbackground=C["border"], highlightthickness=1)
        paned.add(wrap, weight=45)

        hdr = tk.Frame(wrap, bg=C["card"])
        hdr.pack(fill=tk.X, padx=14, pady=(12, 0))
        tk.Label(hdr, text="�  File Metadata",
                 bg=C["card"], fg=C["t_primary"], font=F["h3"]).pack(side=tk.LEFT)
        tk.Frame(wrap, bg=C["blue"], height=2).pack(fill=tk.X, padx=14, pady=(6, 0))

        # Consolidated action buttons — no duplicates
        btn_row = tk.Frame(wrap, bg=C["card"])
        btn_row.pack(fill=tk.X, padx=14, pady=(8, 0))
        self._copy_btn = self._make_action_btn(
            btn_row, "📋 Copy Hash",  C["blue_lt"],   C["blue_dk"],  self._copy_hash)
        self._vt_btn   = self._make_action_btn(
            btn_row, "🛡 Open in VT", C["teal_lt"],   C["teal"],     self._open_vt)
        self._viz_btn  = self._make_action_btn(
            btn_row, "📈 Visualize",  C["purple_lt"], C["purple"],   self._open_visual_analytics)
        self._exp_btn  = self._make_action_btn(
            btn_row, "📄 PDF",        C["green_lt"],  C["green"],    self.export_report)

        Divider(wrap).pack(fill=tk.X, padx=0, pady=(8, 0))

        self.details_text = tk.Text(
            wrap, wrap=tk.WORD,
            bg=C["card"], fg=C["t_primary"],
            font=F["mono"], relief=tk.FLAT,
            borderwidth=0, padx=14, pady=10,
            insertbackground=C["blue"],
            selectbackground=C["blue_lt"],
            selectforeground=C["t_primary"],
            spacing1=2, spacing3=3,
        )
        ds = ttk.Scrollbar(wrap, orient=tk.VERTICAL, command=self.details_text.yview)
        self.details_text.configure(yscrollcommand=ds.set)
        ds.pack(side=tk.RIGHT, fill=tk.Y)
        self.details_text.pack(fill=tk.BOTH, expand=True, pady=(0, 8))
        self.details_text.config(state=tk.DISABLED)

        tags = {
            "section":   {"foreground": C["t_muted"],      "font": ("Segoe UI", 8, "bold")},
            "sep":       {"foreground": C["border"]},
            "title":     {"foreground": C["blue"],          "font": ("Consolas", 11, "bold")},
            "label":     {"foreground": C["t_secondary"],   "font": ("Consolas", 9)},
            "value":     {"foreground": C["t_primary"],     "font": ("Consolas", 9)},
            "warning":   {"foreground": C["red"],           "font": ("Consolas", 9, "bold")},
            "success":   {"foreground": C["green"],         "font": ("Consolas", 9)},
            "amber":     {"foreground": C["amber"],         "font": ("Consolas", 9, "bold")},
            "hash":      {"foreground": C["purple"],        "font": ("Consolas", 8)},
            "url":       {"foreground": C["teal"],          "font": ("Consolas", 9)},
            "dup_title": {"foreground": "#BE185D",          "font": ("Consolas", 10, "bold"),
                          "background": "#FFF0F6"},
            "dup_val":   {"foreground": "#BE185D",          "font": ("Consolas", 9),
                          "background": "#FFF0F6"},
            "dup_label": {"foreground": "#9D174D",          "font": ("Consolas", 9),
                          "background": "#FFF0F6"},
            "dup_orig":  {"foreground": "#15803D",          "font": ("Consolas", 9, "bold"),
                          "background": "#F0FDF4"},
            "orig_title":{"foreground": "#15803D",          "font": ("Consolas", 10, "bold"),
                          "background": "#F0FDF4"},
            "orig_val":  {"foreground": "#15803D",          "font": ("Consolas", 9),
                          "background": "#F0FDF4"},
            "orig_label":{"foreground": "#166534",          "font": ("Consolas", 9),
                          "background": "#F0FDF4"},
            # ── Per-alert colour-coded tags ────────────────
            "alert_clean":    {"foreground": ALERT_COLORS["Clean File"]["fg"],
                              "background": ALERT_COLORS["Clean File"]["bg"],
                              "font": ("Segoe UI", 9, "bold")},
            "alert_highent":  {"foreground": ALERT_COLORS["High Entropy"]["fg"],
                              "background": ALERT_COLORS["High Entropy"]["bg"],
                              "font": ("Segoe UI", 9, "bold")},
            "alert_dup":      {"foreground": ALERT_COLORS["Duplicate File"]["fg"],
                              "background": ALERT_COLORS["Duplicate File"]["bg"],
                              "font": ("Segoe UI", 9, "bold")},
            "alert_inet":     {"foreground": ALERT_COLORS["Internet Download"]["fg"],
                              "background": ALERT_COLORS["Internet Download"]["bg"],
                              "font": ("Segoe UI", 9, "bold")},
            "alert_hidden":   {"foreground": ALERT_COLORS["Hidden File"]["fg"],
                              "background": ALERT_COLORS["Hidden File"]["bg"],
                              "font": ("Segoe UI", 9, "bold")},
            "alert_mismatch": {"foreground": ALERT_COLORS["Type Mismatch"]["fg"],
                              "background": ALERT_COLORS["Type Mismatch"]["bg"],
                              "font": ("Segoe UI", 9, "bold")},
            "alert_vt":       {"foreground": ALERT_COLORS["VT Malicious"]["fg"],
                              "background": ALERT_COLORS["VT Malicious"]["bg"],
                              "font": ("Segoe UI", 9, "bold")},
            # ── Risk level tags ────────────────────────────
            "risk_critical":  {"foreground": C["red"],    "font": ("Consolas", 10, "bold"),
                              "background": C["red_lt"]},
            "risk_mismatch":  {"foreground": C["amber"],  "font": ("Consolas", 10, "bold"),
                              "background": C["amber_lt"]},
            "risk_highent":   {"foreground": "#B45309",   "font": ("Consolas", 10, "bold"),
                              "background": "#FEF3C7"},
            "risk_hidden":    {"foreground": C["purple"], "font": ("Consolas", 10, "bold"),
                              "background": C["purple_lt"]},
            "risk_clean":     {"foreground": C["green"],  "font": ("Consolas", 10, "bold"),
                              "background": C["green_lt"]},
        }
        for tag, cfg in tags.items():
            self.details_text.tag_configure(tag, **cfg)

    def _make_action_btn(self, parent, text, bg, hover_bg, cmd):
        b = tk.Label(parent, text=text, bg=bg, fg=C["t_primary"],
                     font=F["body_sm"], padx=10, pady=5, cursor="hand2")
        b.pack(side=tk.LEFT, padx=(0, 6))
        b.bind("<Enter>",          lambda e, b=b, f=hover_bg: b.config(bg=f, fg="white"))
        b.bind("<Leave>",          lambda e, b=b, bg=bg: b.config(bg=bg, fg=C["t_primary"]))
        b.bind("<ButtonRelease-1>", lambda e: cmd())
        return b

    def _copy_hash(self):
        if self.selected_record:
            h = self.selected_record.get("sha256_hash", " ")
            if h:
                self.root.clipboard_clear()
                self.root.clipboard_append(h)
                self.update_status("✓ SHA-256 hash copied to clipboard")

    def _open_vt(self):
        if self.selected_record:
            h = self.selected_record.get("sha256_hash", " ")
            if h:
                webbrowser.open(f"https://www.virustotal.com/gui/file/{h}")

    # ══════════════════════════════════════════════════════
    # TAB: DUPLICATE FILES
    # ══════════════════════════════════════════════════════
    def _build_duplicates_tab(self):
        dup_tab = tk.Frame(self.notebook, bg=C["page"])
        self.notebook.add(dup_tab, text="Duplicate Files")

        top_bar = tk.Frame(dup_tab, bg=C["card"],
                           highlightbackground=C["border"], highlightthickness=1)
        top_bar.pack(fill=tk.X, padx=20, pady=(14, 0))
        top_inner = tk.Frame(top_bar, bg=C["card"])
        top_inner.pack(fill=tk.X, padx=16, pady=12)

        tk.Label(top_inner, text="🔁  Duplicate File Groups",
                 bg=C["card"], fg=C["t_primary"], font=F["h3"]).pack(side=tk.LEFT)

        self._dup_group_var = tk.StringVar(value="0 groups")
        tk.Label(top_inner, textvariable=self._dup_group_var,
                 bg=C["dup_copy_bg"], fg=C["dup_mid"],
                 font=F["badge"], padx=10, pady=3).pack(side=tk.LEFT, padx=10)

        self._dup_file_var = tk.StringVar(value="0 duplicate files")
        tk.Label(top_inner, textvariable=self._dup_file_var,
                 bg=C["red_lt"], fg=C["red"],
                 font=F["badge"], padx=10, pady=3).pack(side=tk.LEFT, padx=4)

        help_lbl = tk.Label(top_inner, text="  ❓ How to read this   ",
                            bg=C["blue_lt"], fg=C["blue"],
                            font=F["badge"], padx=8, pady=3, cursor="hand2")
        help_lbl.pack(side=tk.RIGHT)
        help_lbl.bind("<ButtonRelease-1>", lambda e: self._show_dup_help())

        # Explanation strip
        expl = tk.Frame(dup_tab, bg="#FFFBEB",
                        highlightbackground="#FDE68A", highlightthickness=1)
        expl.pack(fill=tk.X, padx=20, pady=(8, 0))
        expl_i = tk.Frame(expl, bg="#FFFBEB")
        expl_i.pack(fill=tk.X, padx=16, pady=8)
        tk.Label(expl_i, text="🟢 ORIGINAL", bg="#FFFBEB", fg="#15803D",
                 font=("Segoe UI", 8, "bold")).pack(side=tk.LEFT)
        tk.Label(expl_i, text=" = First file added to database (came first in time)      ",
                 bg="#FFFBEB", fg="#78350F", font=("Segoe UI", 8)).pack(side=tk.LEFT)
        tk.Label(expl_i, text="🔴 COPY", bg="#FFFBEB", fg="#BE185D",
                 font=("Segoe UI", 8, "bold")).pack(side=tk.LEFT)
        tk.Label(expl_i, text=" = Added later — identical bytes to the original",
                 bg="#FFFBEB", fg="#78350F", font=("Segoe UI", 8)).pack(side=tk.LEFT)

        # Scrollable group area
        outer = tk.Frame(dup_tab, bg=C["page"])
        outer.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        canvas = tk.Canvas(outer, bg=C["page"], highlightthickness=0)
        vsb    = ttk.Scrollbar(outer, orient=tk.VERTICAL, command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self._dup_inner = tk.Frame(canvas, bg=C["page"])
        win_id = canvas.create_window((0, 0), window=self._dup_inner, anchor="nw", tags="inner")

        def on_configure(e):
            canvas.configure(scrollregion=canvas.bbox("all"))
        def on_canvas_resize(e):
            canvas.itemconfig("inner", width=e.width)

        self._dup_inner.bind("<Configure>", on_configure)
        canvas.bind("<Configure>", on_canvas_resize)
        canvas.bind("<Enter>",
            lambda e: canvas.bind_all("<MouseWheel>",
                lambda ev: canvas.yview_scroll(-1*(ev.delta//120), "units")))
        canvas.bind("<Leave>", lambda e: canvas.unbind_all("<MouseWheel>"))
        self._dup_canvas = canvas

        # Bottom flat list
        bottom = tk.Frame(dup_tab, bg=C["card"],
                          highlightbackground=C["border"], highlightthickness=1)
        bottom.pack(fill=tk.X, padx=20, pady=(0, 10))

        bot_hdr = tk.Frame(bottom, bg=C["card"])
        bot_hdr.pack(fill=tk.X, padx=14, pady=10)
        tk.Label(bot_hdr, text="📋  All Duplicate Files — Flat List",
                 bg=C["card"], fg=C["t_primary"], font=F["h3"]).pack(side=tk.LEFT)
        Divider(bottom).pack(fill=tk.X)

        dcols = ("Role", "ID", "Filename", "Filepath", "Hash (short)", "Size", "First Seen")
        self.dup_tree = ttk.Treeview(bottom, columns=dcols,
                                     show="headings", selectmode="browse", height=8)
        dcol_cfg = [
            ("Role",         "Role",            80,  tk.CENTER),
            ("ID",           "DB ID",           50,  tk.CENTER),
            ("Filename",     "File Name",       170, tk.W),
            ("Filepath",     "Full Path",       260, tk.W),
            ("Hash (short)", "SHA-256 (short)", 140, tk.W),
            ("Size",         "Size",             80, tk.E),
            ("First Seen",   "First Seen",      140, tk.W),
        ]
        for col, heading, width, anchor in dcol_cfg:
            self.dup_tree.heading(col, text=heading)
            self.dup_tree.column(col, width=width, anchor=anchor)

        self.dup_tree.tag_configure("original", background=C["dup_orig_bg"],
                                    foreground="#15803D")
        self.dup_tree.tag_configure("copy",     background=C["dup_copy_bg"],
                                    foreground="#BE185D")
        self.dup_tree.tag_configure("sep",      background="#E2E8F0",
                                    foreground="#94A3B8")

        dsv2 = ttk.Scrollbar(bottom, orient=tk.VERTICAL,   command=self.dup_tree.yview)
        dsh2 = ttk.Scrollbar(bottom, orient=tk.HORIZONTAL, command=self.dup_tree.xview)
        self.dup_tree.configure(yscroll=dsv2.set, xscroll=dsh2.set)
        dsv2.pack(side=tk.RIGHT, fill=tk.Y)
        dsh2.pack(side=tk.BOTTOM, fill=tk.X)
        self.dup_tree.pack(fill=tk.BOTH, expand=True)
        self.dup_tree.bind("<<TreeviewSelect>>", self._on_dup_tree_select)

    def _show_dup_help(self):
        messagebox.showinfo(
            "How to Read the Duplicates Page",
            "DUPLICATE DETECTION EXPLAINED\n\n"
            "Files are identified as duplicates when they share the same SHA-256\n"
            "hash — meaning their content is byte-for-byte identical.\n\n"
            "🟢 ORIGINAL\n"
            "   The FIRST record in the database with that hash.\n"
            "   This is always the file that was added first.\n\n"
            "🔴 COPY\n"
            "   Any record added LATER with the same hash.\n"
            "   This file is a byte-for-byte copy of the original.\n\n"
            "The Original file record now shows how many copies exist.\n"
            "The Copy record shows which file it is a copy of.\n\n"
            "Having duplicates may indicate:\n"
            "  • A file was moved or renamed\n"
            "  • Malware was copied to multiple locations\n"
            "  • Backup files exist\n\n"
            "Click any row in the flat list to jump to that file's\n"
            "full details in the All Files tab."
        )

    def _on_dup_tree_select(self, event):
        sel = self.dup_tree.selection()
        if sel:
            iid = sel[0]
            if iid.startswith("sep_"):
                return
            try:
                rid = int(iid)
                r = next((x for x in self._all_records if x["id"] == rid), None)
                if r:
                    self.selected_record = r
                    self._show_details(r)
                    self._switch_tab(1)
            except ValueError:
                pass

    def _populate_duplicates_tab(self, records):
        for w in self._dup_inner.winfo_children():
            w.destroy()
        for item in self.dup_tree.get_children():
            self.dup_tree.delete(item)

        from collections import defaultdict
        hash_map = defaultdict(list)
        for r in records:
            h = r.get("sha256_hash") or " "
            if h:
                hash_map[h].append(r)

        dup_groups = {h: rs for h, rs in hash_map.items() if len(rs) > 1}
        sorted_groups = sorted(dup_groups.values(),
                                key=lambda rs: (-len(rs), min(r["id"] for r in rs)))

        n_groups  = len(sorted_groups)
        n_copies  = sum(len(rs) - 1 for rs in sorted_groups)
        self._dup_group_var.set(f"{n_groups} group{'s' if n_groups != 1 else ''}")
        self._dup_file_var.set(f"{n_copies} duplicate cop{'ies' if n_copies != 1 else 'y'}")

        if not sorted_groups:
            empty = tk.Frame(self._dup_inner, bg=C["card"],
                             highlightbackground=C["border"], highlightthickness=1)
            empty.pack(fill=tk.X, padx=4, pady=20)
            tk.Label(empty, text="✅", bg=C["card"],
                     font=("Segoe UI", 36)).pack(pady=(30, 8))
            tk.Label(empty, text="No duplicate files found in the database.",
                     bg=C["card"], fg=C["t_muted"],
                     font=("Segoe UI", 12)).pack(pady=(0, 30))
            return

        for g_idx, group in enumerate(sorted_groups):
            # Sort within group: lowest id = ORIGINAL
            group_sorted = sorted(group, key=lambda r: r["id"])
            original     = group_sorted[0]
            copies       = group_sorted[1:]

            sha = original.get("sha256_hash", " ")
            short_hash = sha[:16] + "…" if len(sha) > 16 else sha

            card_outer = tk.Frame(self._dup_inner, bg=C["border"], padx=1, pady=1)
            card_outer.pack(fill=tk.X, padx=4, pady=(0, 10))
            card = tk.Frame(card_outer, bg=C["card"])
            card.pack(fill=tk.X)

            card_hdr = tk.Frame(card, bg="#FFF0F6")
            card_hdr.pack(fill=tk.X)
            hdr_inner = tk.Frame(card_hdr, bg="#FFF0F6")
            hdr_inner.pack(fill=tk.X, padx=16, pady=10)
            tk.Label(hdr_inner, text=f"  Group {g_idx + 1}   ",
                     bg="#BE185D", fg="white",
                     font=("Segoe UI", 8, "bold")).pack(side=tk.LEFT)
            tk.Label(hdr_inner,
                     text=f"  {len(group)} identical files  ({len(copies)} cop{'ies' if len(copies) >1 else 'y'})",
                     bg="#FFF0F6", fg="#9D174D",
                     font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=8)
            tk.Label(hdr_inner, text=f"🔐 {short_hash}",
                     bg="#FFF0F6", fg=C["purple"],
                     font=("Consolas", 8)).pack(side=tk.RIGHT)

            tk.Frame(card, bg="#FBCFE8", height=1).pack(fill=tk.X)

            body = tk.Frame(card, bg=C["card"])
            body.pack(fill=tk.X, padx=16, pady=12)

            # ORIGINAL first, then COPIES
            all_in_group = [(original, "original")] + [(c, "copy") for c in copies]
            for r, role in all_in_group:
                is_orig  = (role == "original")
                row_bg   = C["dup_orig_bg"] if is_orig else C["dup_copy_bg"]
                row_bd   = C["dup_orig_bd"] if is_orig else C["dup_copy_bd"]
                role_bg  = "#15803D"       if is_orig else "#BE185D"
                role_lbl = "ORIGINAL"   if is_orig else "COPY"
                icon     = "📄"            if is_orig else "🔁"

                row_outer = tk.Frame(body, bg=row_bd, padx=1, pady=1)
                row_outer.pack(fill=tk.X, pady=(0, 6))
                row_inner = tk.Frame(row_outer, bg=row_bg, padx=12, pady=8)
                row_inner.pack(fill=tk.X)

                left_col = tk.Frame(row_inner, bg=row_bg)
                left_col.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 12))
                tk.Label(left_col, text=icon, bg=row_bg,
                         font=("Segoe UI", 20)).pack()
                tk.Label(left_col, text=f"  {role_lbl}   ",
                         bg=role_bg, fg="white",
                         font=("Segoe UI", 7, "bold"),
                         padx=2, pady=1).pack()

                mid_col = tk.Frame(row_inner, bg=row_bg)
                mid_col.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

                name_row = tk.Frame(mid_col, bg=row_bg)
                name_row.pack(fill=tk.X)
                tk.Label(name_row, text=r.get("filename", "—"),
                         bg=row_bg, fg=C["t_primary"],
                         font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT)
                tk.Label(name_row, text=f"  DB #{r.get('id','?')}",
                         bg=row_bg, fg=C["t_muted"],
                         font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=6)

                # For originals, show how many copies exist
                if is_orig and copies:
                    copy_count_lbl = f"  ← {len(copies)} cop{'ies' if len(copies) >1 else 'y'} of this file exist"
                    tk.Label(name_row, text=copy_count_lbl,
                             bg=row_bg, fg="#BE185D",
                             font=("Segoe UI", 7, "bold")).pack(side=tk.LEFT)

                # For copies, show which original it copies
                if not is_orig:
                    orig_name = original.get("filename", "?")
                    tk.Label(name_row, text=f"  ← copy of: {orig_name}",
                             bg=row_bg, fg="#15803D",
                             font=("Segoe UI", 7)).pack(side=tk.LEFT)

                tk.Label(mid_col, text=r.get("filepath", "—"),
                         bg=row_bg, fg=C["t_secondary"],
                         font=("Consolas", 7), anchor="w").pack(fill=tk.X)

                meta_row = tk.Frame(mid_col, bg=row_bg)
                meta_row.pack(fill=tk.X, pady=(4, 0))
                ts_clean = (r.get("analyzed_at") or " ").split("| ")[0].replace("Local: ", " ").strip()
                size_str = self._format_size(r.get("file_size", 0) or 0)
                for lbl, val in [("🕐", ts_clean), ("📦", f".{r.get('file_type','?').upper()}"),
                                  ("💾", size_str)]:
                    tk.Label(meta_row, text=f"{lbl} {val}",
                             bg=row_bg, fg=C["t_muted"],
                             font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=(0, 16))

                jump_btn = tk.Label(row_inner, text="  View Details →   ",
                                    bg=row_bd, fg=role_bg,
                                    font=("Segoe UI", 8, "bold"),
                                    padx=8, pady=4, cursor="hand2")
                jump_btn.pack(side=tk.RIGHT, padx=(8, 0))
                _r = r
                jump_btn.bind("<ButtonRelease-1>",
                              lambda e, rec=_r: self._jump_to_record(rec))
                jump_btn.bind("<Enter>",
                              lambda e, b=jump_btn, bg=role_bg: b.config(bg=bg, fg="white"))
                jump_btn.bind("<Leave>",
                              lambda e, b=jump_btn, bg=row_bd, fg=role_bg:
                              b.config(bg=bg, fg=fg))

            # Flat list entries
            for r, role in all_in_group:
                is_orig  = (role == "original")
                tag      = "original" if is_orig else "copy"
                role_lbl = "🟢 ORIGINAL" if is_orig else "🔴 COPY"
                sha_short = (r.get("sha256_hash") or " ")[:20] + "…" if len(r.get("sha256_hash") or " ") > 20 else (r.get("sha256_hash") or "—")
                ts_clean = (r.get("analyzed_at") or " ").split("| ")[0].replace("Local: ", " ").strip()
                self.dup_tree.insert("", tk.END, iid=str(r["id"]), values=(
                    role_lbl,
                    f"#{r.get('id','?')}",
                    r.get("filename", "—"),
                    r.get("filepath", "—"),
                    sha_short,
                    self._format_size(r.get("file_size", 0) or 0),
                    ts_clean,
                ), tags=(tag,))

            if g_idx < len(sorted_groups) - 1:
                sep_iid = f"sep_{g_idx}"
                self.dup_tree.insert("", tk.END, iid=sep_iid, values=(
                    "─────", "─────", "─────────────────────",
                    "────────────────────────────────────────────",
                    "────────────────────", "─────", "─────────────",
                ), tags=("sep",))

    def _jump_to_record(self, record):
        self.selected_record = record
        self._show_details(record)
        self._switch_tab(1)

    # ══════════════════════════════════════════════════════
    # TAB: INTERNET DOWNLOADS
    # ══════════════════════════════════════════════════════
    def _build_inet_tab(self):
        inet = tk.Frame(self.notebook, bg=C["page"])
        self.notebook.add(inet, text="Internet Downloads")

        container = tk.Frame(inet, bg=C["page"])
        container.pack(fill=tk.BOTH, expand=True, padx=20, pady=14)
        wrap = tk.Frame(container, bg=C["card"],
                        highlightbackground=C["border"], highlightthickness=1)
        wrap.pack(fill=tk.BOTH, expand=True)

        hdr = tk.Frame(wrap, bg=C["card"])
        hdr.pack(fill=tk.X, padx=14, pady=(12, 8))
        tk.Label(hdr, text="🌐  Files Downloaded from Internet",
                 bg=C["card"], fg=C["t_primary"], font=F["h3"]).pack(side=tk.LEFT)
        self._inet_count_var = tk.StringVar(value="0 files")
        tk.Label(hdr, textvariable=self._inet_count_var,
                 bg=C["red_lt"], fg=C["red"],
                 font=F["badge"], padx=8, pady=2).pack(side=tk.LEFT, padx=10)
        Divider(wrap).pack(fill=tk.X)

        cols = ("ID", "Filename", "Size", "VTScore", "Risk", "URL")
        self.inet_tree = ttk.Treeview(wrap, columns=cols,
                                      show="headings", selectmode="browse")
        col_cfg = [
            ("ID",        "ID",          46,  tk.CENTER),
            ("Filename",  "File Name",  200, tk.W),
            ("Size",      "Size",        80, tk.E),
            ("VTScore",   "VT Score",    80, tk.CENTER),
            ("Risk",      "Risk",        90, tk.CENTER),
            ("URL",       "Source URL", 340, tk.W),
        ]
        for col, heading, width, anchor in col_cfg:
            self.inet_tree.heading(col, text=heading)
            self.inet_tree.column(col, width=width, anchor=anchor)
        self._apply_tree_tags(self.inet_tree)

        sv = ttk.Scrollbar(wrap, orient=tk.VERTICAL,   command=self.inet_tree.yview)
        sh = ttk.Scrollbar(wrap, orient=tk.HORIZONTAL, command=self.inet_tree.xview)
        self.inet_tree.configure(yscroll=sv.set, xscroll=sh.set)
        sv.pack(side=tk.RIGHT, fill=tk.Y)
        sh.pack(side=tk.BOTTOM, fill=tk.X)
        self.inet_tree.pack(fill=tk.BOTH, expand=True)
        self.inet_tree.bind("<<TreeviewSelect>>", self._on_inet_select)

    def _on_inet_select(self, event):
        sel = self.inet_tree.selection()
        if sel:
            rid = int(sel[0])
            r = next((x for x in self._all_records if x["id"] == rid), None)
            if r:
                self.selected_record = r
                self._show_details(r)
                self._switch_tab(1)

    # ══════════════════════════════════════════════════════
    # TAB: ACTIVITY LOGS
    # ══════════════════════════════════════════════════════
    def _build_logs_tab(self):
        logs_tab = tk.Frame(self.notebook, bg=C["page"])
        self.notebook.add(logs_tab, text="Activity Logs")

        container = tk.Frame(logs_tab, bg=C["page"])
        container.pack(fill=tk.BOTH, expand=True, padx=20, pady=14)
        wrap = tk.Frame(container, bg=C["card"],
                        highlightbackground=C["border"], highlightthickness=1)
        wrap.pack(fill=tk.BOTH, expand=True)

        top = tk.Frame(wrap, bg=C["card"])
        top.pack(fill=tk.X, padx=14, pady=12)
        tk.Label(top, text="📋  System Activity Logs",
                 bg=C["card"], fg=C["t_primary"], font=F["h3"]).pack(side=tk.LEFT)

        filter_wrap  = tk.Frame(top, bg=C["border"])
        filter_wrap.pack(side=tk.RIGHT)
        filter_inner = tk.Frame(filter_wrap, bg=C["card"])
        filter_inner.pack(padx=1, pady=1)
        tk.Label(filter_inner, text="🔎", bg=C["card"],
                 fg=C["t_muted"], font=F["body_sm"]).pack(side=tk.LEFT, padx=(6, 0))
        self.log_filter_var = tk.StringVar()
        self.log_filter_var.trace_add("write", lambda *a: self._populate_logs())
        tk.Entry(filter_inner, textvariable=self.log_filter_var,
                 width=28, bg=C["card"], relief="flat",
                 font=F["body_sm"]).pack(side=tk.LEFT, ipady=5, padx=(2, 8))
        Divider(wrap).pack(fill=tk.X)

        cols = ("ID", "Time", "Action", "Details")
        self.log_tree = ttk.Treeview(wrap, columns=cols,
                                     show="headings", selectmode="browse")
        self.log_tree.column("ID",      width=52,  anchor=tk.CENTER)
        self.log_tree.column("Time",    width=170)
        self.log_tree.column("Action",  width=140)
        self.log_tree.column("Details", width=500)
        for col in cols:
            self.log_tree.heading(col, text=col)
        self.log_tree.tag_configure("analyze",   foreground=C["purple"])
        self.log_tree.tag_configure("scan",      foreground=C["teal"])
        self.log_tree.tag_configure("init",      foreground=C["blue"])
        self.log_tree.tag_configure("duplicate", foreground=C["row_dup_fg"],
                                    background=C["row_dup"])
        self.log_tree.tag_configure("even",      background=C["row_even"])
        self.log_tree.tag_configure("odd",       background=C["row_odd"])

        sv = ttk.Scrollbar(wrap, orient=tk.VERTICAL, command=self.log_tree.yview)
        sh = ttk.Scrollbar(wrap, orient=tk.HORIZONTAL, command=self.log_tree.xview)
        self.log_tree.configure(yscroll=sv.set, xscroll=sh.set)
        sv.pack(side=tk.RIGHT, fill=tk.Y)
        sh.pack(side=tk.BOTTOM, fill=tk.X)
        self.log_tree.pack(fill=tk.BOTH, expand=True)

    # ══════════════════════════════════════════════════════
    # TAB: VISUAL ANALYTICS
    # ══════════════════════════════════════════════════════
    def _build_visual_analytics_tab(self):
        viz_tab  = tk.Frame(self.notebook, bg=C["page"])
        self.notebook.add(viz_tab, text="Visual Analytics")
        self._viz_panel = VisualAnalyticsPanel(viz_tab)

    # ══════════════════════════════════════════════════════
    # TAB: INTEGRITY CHECKS
    # ══════════════════════════════════════════════════════
    def _build_integrity_tab(self):
        integ_tab = tk.Frame(self.notebook, bg=C["page"])
        self.notebook.add(integ_tab, text="Integrity Checks")

        # ── Top bar ───────────────────────────────────────
        top = tk.Frame(integ_tab, bg=C["card"],
                       highlightbackground=C["border"], highlightthickness=1)
        top.pack(fill=tk.X, padx=20, pady=(14, 0))
        top_inner = tk.Frame(top, bg=C["card"])
        top_inner.pack(fill=tk.X, padx=16, pady=12)

        tk.Label(top_inner, text="🔒  File Integrity Checks",
                 bg=C["card"], fg=C["t_primary"], font=F["h3"]).pack(side=tk.LEFT)

        self._integ_count_var = tk.StringVar(value="0 checks")
        tk.Label(top_inner, textvariable=self._integ_count_var,
                 bg=C["blue_lt"], fg=C["blue"],
                 font=F["badge"], padx=10, pady=3).pack(side=tk.LEFT, padx=10)

        self._integ_mod_var = tk.StringVar(value="0 modified")
        tk.Label(top_inner, textvariable=self._integ_mod_var,
                 bg=C["red_lt"], fg=C["red"],
                 font=F["badge"], padx=10, pady=3).pack(side=tk.LEFT, padx=4)

        # Help button
        help_lbl = tk.Label(top_inner, text="  ❓ How this works   ",
                            bg=C["blue_lt"], fg=C["blue"],
                            font=F["badge"], padx=8, pady=3, cursor="hand2")
        help_lbl.pack(side=tk.RIGHT)
        help_lbl.bind("<ButtonRelease-1>", lambda e: self._show_integ_help())

        # ── Explanation strip ─────────────────────────────
        expl = tk.Frame(integ_tab, bg="#FFFBEB",
                        highlightbackground="#FDE68A", highlightthickness=1)
        expl.pack(fill=tk.X, padx=20, pady=(8, 0))
        ei = tk.Frame(expl, bg="#FFFBEB")
        ei.pack(fill=tk.X, padx=16, pady=8)

        badges = [
            ("🆕 NEW",       C["integ_new_fg"],   "= First time this filename was seen"),
            ("✓ UNCHANGED",  C["integ_ok_fg"],    "= Hash matches DB  •  file untouched"),
            ("⚠ MODIFIED",  C["integ_mod_fg"],   "= Hash changed  •  content was altered"),
        ]
        for label, fg, desc in badges:
            tk.Label(ei, text=label, bg="#FFFBEB", fg=fg,
                     font=("Segoe UI", 8, "bold")).pack(side=tk.LEFT)
            tk.Label(ei, text=f"  {desc}      ", bg="#FFFBEB", fg="#78350F",
                     font=("Segoe UI", 8)).pack(side=tk.LEFT)

        # ── Table ─────────────────────────────────────────
        wrap = tk.Frame(integ_tab, bg=C["card"],
                        highlightbackground=C["border"], highlightthickness=1)
        wrap.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        cols = ("ID", "Status", "Filename", "Filepath",
                 "New Hash", "Stored Hash", "Checked At")
        self.integ_tree = ttk.Treeview(wrap, columns=cols,
                                       show="headings", selectmode="browse")

        col_cfg = [
            ("ID",          "ID",             46,  tk.CENTER),
            ("Status",      "Status",        110,  tk.CENTER),
            ("Filename",    "File Name",     180,  tk.W),
            ("Filepath",    "Full Path",     240,  tk.W),
            ("New Hash",    "New Hash",      130,  tk.W),
            ("Stored Hash", "Stored Hash",   130,  tk.W),
            ("Checked At",  "Checked At",   160,  tk.W),
        ]
        for col, heading, width, anchor in col_cfg:
            self.integ_tree.heading(col, text=heading)
            self.integ_tree.column(col, width=width, anchor=anchor,
                                   minwidth=max(40, width - 20))

        # Row colour tags
        self.integ_tree.tag_configure(
            "integ_new",  background=C["integ_new"],  foreground=C["integ_new_fg"])
        self.integ_tree.tag_configure(
            "integ_ok",   background=C["integ_ok"],   foreground=C["integ_ok_fg"])
        self.integ_tree.tag_configure(
            "integ_mod",  background=C["integ_mod"],  foreground=C["integ_mod_fg"])
        self.integ_tree.tag_configure("even", background=C["row_even"])
        self.integ_tree.tag_configure("odd",  background=C["row_odd"])

        sv = ttk.Scrollbar(wrap, orient=tk.VERTICAL,   command=self.integ_tree.yview)
        sh = ttk.Scrollbar(wrap, orient=tk.HORIZONTAL, command=self.integ_tree.xview)
        self.integ_tree.configure(yscroll=sv.set, xscroll=sh.set)
        sv.pack(side=tk.RIGHT, fill=tk.Y)
        sh.pack(side=tk.BOTTOM, fill=tk.X)
        self.integ_tree.pack(fill=tk.BOTH, expand=True)

    def _populate_integrity_tab(self):
        """Fill the Integrity Checks treeview from the DB."""
        if not hasattr(self, "integ_tree"):
            return
        for item in self.integ_tree.get_children():
            self.integ_tree.delete(item)

        checks = backend.get_integrity_checks(self.db_path)
        n_mod  = sum(1 for c in checks if c.get("status") == "modified")
        if hasattr(self, "_integ_count_var"):
            self._integ_count_var.set(f"{len(checks)} check{'s' if len(checks) != 1 else ''}")
        if hasattr(self, "_integ_mod_var"):
            self._integ_mod_var.set(f"{n_mod} modified")

        status_labels = {
            "new":        "🆕 NEW",
            "unchanged":  "✓ UNCHANGED",
            "modified":   "⚠ MODIFIED",
        }
        status_tags = {
            "new":        "integ_new",
            "unchanged":  "integ_ok",
            "modified":   "integ_mod",
        }

        for idx, c in enumerate(checks):
            status = c.get("status", "new")
            label  = status_labels.get(status, status.upper())
            tag    = status_tags.get(status, ("even" if idx % 2 == 0 else "odd"))

            new_h  = (c.get("new_hash")    or " ")[:20] + "…" if len(c.get("new_hash") or " ") > 20 else (c.get("new_hash") or "—")
            stor_h = (c.get("stored_hash") or " ")[:20] + "…" if len(c.get("stored_hash") or " ") > 20 else (c.get("stored_hash") or "—")

            self.integ_tree.insert("", tk.END, values=(
                c.get("id", " "),
                label,
                c.get("filename", "—"),
                c.get("filepath", "—"),
                new_h,
                stor_h,
                c.get("checked_at", "—"),
            ), tags=(tag,))

    def _show_integ_help(self):
        messagebox.showinfo(
            "How Integrity Detection Works",
            "FILE INTEGRITY DETECTION\n\n"
            "Every time you upload/analyze a file, ForensicLens checks whether\n"
            "a file with the same name has been seen before in the database.\n\n"
            "🆕 NEW\n"
            "   This is the first time this filename has been analyzed.\n"
            "   No previous record to compare against.\n\n"
            "✓ UNCHANGED\n"
            "   The file's SHA-256 hash matches the hash stored from the\n"
            "   previous analysis. The content is byte-for-byte identical.\n\n"
            "⚠ MODIFIED\n"
            "   The SHA-256 hash is DIFFERENT from what was stored.\n"
            "   This means the file's content changed between analyses.\n"
            "   The timestamp shows exactly when the change was detected.\n\n"
            "All check results are stored permanently so you can review\n"
            "the full integrity history of any file at any time."
        )

    # ══════════════════════════════════════════════════════
    # STATUS BAR
    # ══════════════════════════════════════════════════════
    def _build_status_bar(self, parent):
        bar  = tk.Frame(parent, bg=C["card"],
                       highlightbackground=C["border"], highlightthickness=1,
                       height=30)
        bar.pack(fill=tk.X, side=tk.BOTTOM)
        bar.pack_propagate(False)

        inner = tk.Frame(bar, bg=C["card"])
        inner.pack(fill=tk.BOTH, expand=True, padx=14)

        self._status_dot = tk.Label(inner, text="●", bg=C["card"],
                                    fg=C["green"], font=("Segoe UI", 7))
        self._status_dot.pack(side=tk.LEFT, padx=(0, 5))

        self.status_var = tk.StringVar(value="Ready")
        tk.Label(inner, textvariable=self.status_var, bg=C["card"],
                 fg=C["t_secondary"], font=F["body_sm"]).pack(side=tk.LEFT)

        self.progress = ttk.Progressbar(inner, orient=tk.HORIZONTAL,
                                        mode="indeterminate", length=130,
                                        style="Blue.Horizontal.TProgressbar")
        tk.Label(inner, text="File Metadata Extraction Tool", bg=C["card"],
                 fg=C["t_muted"], font=F["caption"]).pack(side=tk.RIGHT)

    def update_status(self, msg, busy=False):
        self.status_var.set(msg)
        if busy:
            self._status_dot.config(fg=C["amber"])
            self.progress.pack(side=tk.RIGHT, padx=(8, 20))
            self.progress.start(10)
        else:
            self._status_dot.config(fg=C["green"])
            self.progress.stop()
            self.progress.pack_forget()
        self.root.update_idletasks()

    # ══════════════════════════════════════════════════════
    # DATABASE OPERATIONS
    # ══════════════════════════════════════════════════════
    def refresh_database(self):
        self.update_status("Loading database…", busy=True)
        self.filter_var.set("")
        self._all_records = backend.get_all_records(self.db_path)
        self._populate_tree(self._all_records)
        self._populate_inet_tree(self._all_records)
        self._populate_dashboard(self._all_records)
        self._populate_logs()
        self._populate_duplicates_tab(self._all_records)
        self._populate_integrity_tab()
        self._update_stat_cards(self._all_records)
        self._update_nav_badges(self._all_records)
        self._update_threat_pill(self._all_records)
        n = len(self._all_records)
        self.update_status(f"Database loaded  —  {n} record{'s' if n != 1 else ''}")

    def clear_database(self):
        if messagebox.askyesno("Confirm Clear",
                                "Permanently delete all records?", icon="warning"):
            backend.clear_database(self.db_path)
            self._all_records = []
            self._populate_tree([])
            self._populate_inet_tree([])
            self._populate_dashboard([])
            self._populate_duplicates_tab([])
            self._update_stat_cards([])
            self._update_nav_badges([])
            self._clear_details()
            self._populate_integrity_tab()  # clear integrity tab too
            self.update_status("Database cleared")

    def clear_logs(self):
        """Clear all activity logs (a deletion record is automatically kept)."""
        if messagebox.askyesno(
                "Confirm Clear Logs",
                "This will delete all activity logs.\n"
                "Note: A record of this deletion will be kept automatically.",
                icon="warning"):
            try:
                backend.clear_activity_logs(self.activity_db)
                self._populate_logs()
                self.update_status("Activity logs cleared (deletion recorded)")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to clear logs:\n{e}")

    def _build_duplicate_set(self, records):
        """
        Returns two sets:
        - dup_copy_ids: IDs that are COPIES (not the first with that hash)
        - dup_orig_ids: IDs that are ORIGINALS (first with their hash, but have copies)
        """
        from collections import defaultdict
        hash_to_records = defaultdict(list)
        for r in records:
            h = r.get("sha256_hash") or " "
            if h:
                hash_to_records[h].append(r)

        dup_copy_ids = set()
        dup_orig_ids = set()
        for recs in hash_to_records.values():
            if len(recs) > 1:
                sorted_recs = sorted(recs, key=lambda r: r["id"])
                dup_orig_ids.add(sorted_recs[0]["id"])   # lowest id = original
                for r in sorted_recs[1:]:
                    dup_copy_ids.add(r["id"])
        return dup_orig_ids, dup_copy_ids

    def _populate_tree(self, records):
        for item in self.tree.get_children():
            self.tree.delete(item)

        dup_orig_ids, dup_copy_ids = self._build_duplicate_set(records)

        count = 0
        for idx, r in enumerate(records):
            created = " "
            if r.get("created_time"):
                parts   = r["created_time"].split("| ")
                created = parts[0].replace("Local: ", " ").strip()
            size_str   = self._format_size(r.get("file_size", 0))
            entropy    = r.get("entropy", 0.0) or 0.0
            ent_str    = f"{entropy:.2f}"
            hidden_str = "Yes" if r.get("is_hidden") else "No"

            # Dup Role column: clear distinction
            if r["id"] in dup_orig_ids:
                dup_str = "📄 Original"
            elif r["id"] in dup_copy_ids:
                dup_str = "🔁 Copy"
            else:
                dup_str = "—"

            # ── Risk-based row colour coding ──────────────
            risk = get_risk(r)
            if r["id"] in dup_copy_ids:
                tag = "duplicate"
            elif r["id"] in dup_orig_ids:
                tag = "original"
            elif risk != "clean":
                tag = risk      # critical / mismatch / highent / hidden
            else:
                tag = "even" if idx % 2 == 0 else "odd"

            self.tree.insert("", tk.END, iid=str(r["id"]), values=(
                r["id"],
                r.get("filename", " "),
                r.get("real_file_extension", " "),
                r.get("real_file_description", " ") or r.get("file_type", " "),
                size_str, ent_str,
                r.get("vt_score", "N/A"),
                dup_str,
                hidden_str, created,
            ), tags=(tag,))
            count += 1
        self.record_count_var.set(f"{count} record{'s' if count != 1 else ''}")

    def _populate_dashboard(self, records):
        for item in self.dash_tree.get_children():
            self.dash_tree.delete(item)
        for item in self.threat_tree.get_children():
            self.threat_tree.delete(item)
        dup_orig_ids, dup_copy_ids = self._build_duplicate_set(records)
        for idx, r in enumerate(records[:50]):
            risk    = get_risk(r)
            rlabel  = RISK_LABEL.get(risk, "✓")
            entropy = r.get("entropy", 0.0) or 0.0
            t       = (r.get("analyzed_at") or " ").replace("Local: ", " ").strip().split("  ")
            time_str = t[1][:5] if len(t) > 1 else "—"
            vt      = r.get("vt_score", "N/A")
            if r["id"] in dup_orig_ids:    dup_str = "📄"
            elif r["id"] in dup_copy_ids:  dup_str = "🔁"
            else:                          dup_str = ""

            # ── Risk-based row colour coding ──────────────
            if r["id"] in dup_copy_ids:
                tag = "duplicate"
            elif r["id"] in dup_orig_ids:
                tag = "original"
            elif risk != "clean":
                tag = risk
            else:
                tag = "even" if idx % 2 == 0 else "odd"

            self.dash_tree.insert("", tk.END, iid=str(r["id"]), values=(
                r.get("filename", " "), rlabel, dup_str, f"{entropy:.2f}", vt, time_str
            ), tags=(tag,))
        self._dash_count_var.set(f"{len(records)} total")

        flagged = [r for r in records if get_risk(r) != "clean"]
        self._threat_count_var.set(f"{len(flagged)} items")
        for idx, r in enumerate(flagged):
            alerts = get_all_risk_alerts(r, records)
            issue = ", ".join(alerts) if alerts else "Unknown"
            entropy = r.get("entropy", 0.0) or 0.0
            vt      = r.get("vt_score", "N/A")
            # ── Risk-based row colour coding ──────────────
            risk = get_risk(r)
            tag  = risk if risk != "clean" else ("even" if idx % 2 == 0 else "odd")
            self.threat_tree.insert("", tk.END, iid=str(r["id"]), values=(
                r.get("filename", " "), issue, f"{entropy:.2f}", vt
            ), tags=(tag,))

    def _populate_inet_tree(self, records):
        for item in self.inet_tree.get_children():
            self.inet_tree.delete(item)
        inet = [r for r in records if r.get("source_of_file") == "Internet"]
        self._inet_count_var.set(f"{len(inet)} files")
        dup_orig_ids, dup_copy_ids = self._build_duplicate_set(inet)
        for idx, r in enumerate(inet):
            risk   = get_risk(r)
            rlabel = RISK_LABEL.get(risk, "✓")
            # ── Risk-based row colour coding ──────────────
            if r["id"] in dup_copy_ids:
                tag = "duplicate"
            elif risk != "clean":
                tag = risk
            else:
                tag = "even" if idx % 2 == 0 else "odd"
            self.inet_tree.insert("", tk.END, iid=str(r["id"]), values=(
                r["id"],
                r.get("filename", " "),
                self._format_size(r.get("file_size", 0)),
                r.get("vt_score", "N/A"),
                rlabel,
                r.get("download_url", "N/A"),
            ), tags=(tag,))

    def _populate_logs(self):
        if not hasattr(self, "log_tree"):
            return
        for item in self.log_tree.get_children():
            self.log_tree.delete(item)
        logs  = backend.get_activity_logs(self.activity_db)
        query = self.log_filter_var.get().lower()
        idx   = 0
        for log in logs:
            if (query in str(log.get("action", " ")).lower() or
                    query in str(log.get("details", " ")).lower() or
                    query in str(log.get("timestamp", " ")).lower()):
                # Remove color coding - only use even/odd for row alternating
                tag = "even" if idx % 2 == 0 else "odd"
                self.log_tree.insert("", tk.END, values=(
                    log["id"], log["timestamp"], log["action"], log["details"]
                ), tags=(tag,))
                idx += 1

    def _update_stat_cards(self, records):
        flagged  = [r for r in records if get_risk(r) != "clean"]
        hidden   = [r for r in records if r.get("is_hidden")]
        internet = [r for r in records if r.get("source_of_file") == "Internet"]

        from collections import defaultdict
        hash_map = defaultdict(list)
        for r in records:
            h = r.get("sha256_hash") or " "
            if h:
                hash_map[h].append(r)
        n_dup_copies = sum(len(rs) - 1 for rs in hash_map.values() if len(rs) > 1)

        self._sc_total.set_value(len(records))
        self._sc_flagged.set_value(len(flagged))
        self._sc_hidden.set_value(len(hidden))
        self._sc_dups.set_value(n_dup_copies)
        self._sc_internet.set_value(len(internet))
        # Integrity modified count
        try:
            all_integ = backend.get_integrity_checks(self.db_path)
            n_integ_m = sum(1 for c in all_integ if c.get("status") == "modified")
        except Exception:
            n_integ_m = 0
        if hasattr(self, "_sc_integ"):
            self._sc_integ.set_value(n_integ_m)

    def _update_nav_badges(self, records):
        flagged  = sum(1 for r in records if get_risk(r) != "clean")
        internet = sum(1 for r in records if r.get("source_of_file") == "Internet")

        from collections import defaultdict
        hash_map = defaultdict(list)
        for r in records:
            h = r.get("sha256_hash") or " "
            if h: hash_map[h].append(r)
        n_dup_copies = sum(len(rs) - 1 for rs in hash_map.values() if len(rs) > 1)

        # Count modified files from integrity_checks table
        try:
            integ_checks = backend.get_integrity_checks(self.db_path)
            n_integ_mod  = sum(1 for c in integ_checks if c.get("status") == "modified")
        except Exception:
            n_integ_mod = 0

        self._nav_buttons["files"].set_badge(len(records))
        self._nav_buttons["dups"].set_badge(n_dup_copies)
        self._nav_buttons["inet"].set_badge(internet)
        self._nav_buttons["logs"].set_badge(flagged)
        self._nav_buttons["integ"].set_badge(n_integ_mod)

    def _format_size(self, sz):
        if sz >= 1_073_741_824: return f"{sz/1_073_741_824:.1f} GB"
        if sz >= 1_048_576:     return f"{sz/1_048_576:.1f} MB"
        if sz >= 1024:          return f"{sz/1024:.1f} KB"
        return f"{sz} B"

    # ══════════════════════════════════════════════════════
    # FILTER / SEARCH
    # ══════════════════════════════════════════════════════
    def on_filter_change(self, *args):
        query    = self.filter_var.get().lower().strip()
        records = self._filtered_records(query)
        records.sort(key=lambda r: r.get(self._sort_col) or 0, reverse=self._sort_rev)
        self._populate_tree(records)

    # ══════════════════════════════════════════════════════
    # TREE SELECTION → DETAIL PANE
    # ══════════════════════════════════════════════════════
    def on_tree_select(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        rid = int(sel[0])
        r = next((x for x in self._all_records if x["id"] == rid), None)
        if r:
            # ── Live permission refresh ─────────────────────────────────────
            # Always re-read permissions from disk on every click so that
            # ACL-based changes (Security tab Deny) and Read-only attribute
            # changes are immediately visible without needing to re-upload.
            filepath = r.get("filepath", "")
            if filepath and os.path.exists(filepath):
                live_perms = backend.update_permissions_in_db(self.db_path, filepath)
                r = dict(r)          # make a local copy so we don't mutate cache
                r["permissions"] = live_perms
                # Also update the in-memory record so tree badge stays in sync
                for i, rec in enumerate(self._all_records):
                    if rec["id"] == rid:
                        self._all_records[i] = dict(rec)
                        self._all_records[i]["permissions"] = live_perms
                        break
            self.selected_record = r
            self._show_details(r)

    def _clear_details(self):
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)
        self.details_text.config(state=tk.DISABLED)

    def _show_details(self, r):
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)
        ins = self.details_text.insert

        def line(label, value, val_tag="value"):
            ins(tk.END, f"  {label:<22}", "label")
            ins(tk.END, f"  {value}\n",   val_tag)

        def section(title):
            ins(tk.END, f"\n  {title}\n", "section")
            ins(tk.END, "   " + "─" * 46 + "\n", "sep")

        # ── Determine duplicate / original role ─────────────
        sha = r.get("sha256_hash", " ") or " "
        is_copy     = False
        is_original = False
        orig_records  = []   # the original(s) of this file if it's a copy
        copy_records  = []   # the copies of this file if it's the original

        if sha:
            # Use the full all_records to determine roles
            from collections import defaultdict
            hash_to_records = defaultdict(list)
            for rec in self._all_records:
                h = rec.get("sha256_hash") or " "
                if h:
                    hash_to_records[h].append(rec)
            group = hash_to_records.get(sha, [])
            if len(group) > 1:
                group_sorted = sorted(group, key=lambda rec: rec["id"])
                if r["id"] == group_sorted[0]["id"]:
                    is_original  = True
                    copy_records = [rec for rec in group_sorted if rec["id"] != r["id"]]
                else:
                    is_copy     = True
                    orig_records = [group_sorted[0]]

        # ── Show ORIGINAL banner if this is the original ────
        if is_original and copy_records:
            ins(tk.END, "\n  ┌─────────────────────────────────────────────┐\n", "sep")
            ins(tk.END,    "  │  📄  THIS IS THE ORIGINAL FILE              │\n", "orig_title")
            ins(tk.END,    "  └─────────────────────────────────────────────┘\n", "sep")
            ins(tk.END,
                f"  This file was the FIRST with its SHA-256 hash.\n"
                f"  {len(copy_records)} cop{'ies' if len(copy_records) >1 else 'y'} of this file exist in the database:\n\n",
                 "orig_val")
            for cp in copy_records:
                ts_clean = (cp.get("analyzed_at") or " ").split("| ")[0].replace("Local: ", " ").strip()
                ins(tk.END, f"  🔁 COPY  DB #{cp.get('id','?')}\n",          "dup_title")
                ins(tk.END, f"  {'File Name':<22}  {cp.get('filename','—')}\n", "dup_label")
                ins(tk.END, f"  {'File Path':<22}  {cp.get('filepath','—')}\n", "dup_label")
                ins(tk.END, f"  {'Added At':<22}  {ts_clean}\n\n",             "dup_label")
            ins(tk.END, "   " + "─" * 46 + "\n\n", "sep")

        # ── Show COPY banner if this is a copy ──────────────
        elif is_copy and orig_records:
            ins(tk.END, "\n  ┌─────────────────────────────────────────────┐\n", "sep")
            ins(tk.END,    "  │  🔁  THIS FILE IS A COPY (DUPLICATE)        │\n", "dup_title")
            ins(tk.END,    "  └─────────────────────────────────────────────┘\n", "sep")
            ins(tk.END,
                 "  This file is an exact copy of the ORIGINAL below.\n"
                 "  Same SHA-256 hash = byte-for-byte identical content.\n\n",
                 "dup_val")
            for orig in orig_records:
                ts_clean = (orig.get("analyzed_at") or " ").split("| ")[0].replace("Local: ", " ").strip()
                ins(tk.END, "  ORIGINAL FILE (in database)\n",               "orig_title")
                ins(tk.END, f"  {'File Name':<22}  {orig.get('filename','—')}\n",  "dup_orig")
            ins(tk.END, "   " + "─" * 46 + "\n\n", "sep")

        # ── Risk level (color-coded) ─────────────────────────
        risk   = get_risk(r)
        rlabel = RISK_LABEL.get(risk, " ")
        risk_tag = f"risk_{risk}"
        ins(tk.END, f"  Risk Level:  {rlabel} \n\n", risk_tag)

        # ── Alerts section (each alert gets its own colour) ──
        ALERT_TAG_MAP = {
            "Clean File":        "alert_clean",
            "High Entropy":      "alert_highent",
            "Duplicate File":    "alert_dup",
            "Internet Download": "alert_inet",
            "Hidden File":       "alert_hidden",
            "Type Mismatch":     "alert_mismatch",
            "VT Malicious":      "alert_vt",
            "File Modified":     "alert_vt",   # reuse red colour tag
        }
        ALERT_ICONS = {
            "Clean File":        "\u2713",
            "High Entropy":      "\u25c8",
            "Duplicate File":    "\U0001f501",
            "Internet Download": "\U0001f310",
            "Hidden File":       "\U0001f441",
            "Type Mismatch":     "\u26a1",
            "VT Malicious":      "\u26a0",
            "File Modified":     "\u26a0",     # warning icon
        }
        file_alerts = get_all_risk_alerts(r, self._all_records, db_path=self.db_path)
        ins(tk.END, "  ALERTS  ", "section")
        ins(tk.END, f"  ({len(file_alerts)})\n", "section")
        ins(tk.END, "   " + "\u2500" * 46 + "\n", "sep")
        for alert_name in file_alerts:
            tag  = ALERT_TAG_MAP.get(alert_name, "value")
            icon = ALERT_ICONS.get(alert_name, "\u2022")
            ins(tk.END, f"   {icon}  {alert_name}  ", tag)
            ins(tk.END, "\n", "value")
        ins(tk.END, "\n", "value")

        section("🗂  IDENTITY")
        line("File Name",  r.get("filename", "—"))
        line("File Path",  r.get("filepath", "—"))
        sz = r.get("file_size", 0) or 0
        if   sz >= 1_073_741_824: size_disp = f"{sz:,} bytes  ({sz/1_073_741_824:.2f} GB)"
        elif sz >= 1_048_576:     size_disp = f"{sz:,} bytes  ({sz/1_048_576:.2f} MB)"
        elif sz >= 1024:          size_disp = f"{sz:,} bytes  ({sz/1024:.2f} KB)"
        else:                     size_disp = f"{sz} bytes"
        line("File Size",  size_disp)
        line("Extension",  r.get("file_type", "—"))

        section("🔏  FILE SIGNATURE")
        real_ext  = r.get("real_file_extension", " ") or "—"
        real_desc = r.get("real_file_description", " ") or "—"
        magic     = r.get("magic_bits", " ") or "—"
        file_type = r.get("file_type", " ") or " "
        is_mismatch = backend.is_extension_mismatch(file_type, real_ext)
        ext_tag = "warning" if is_mismatch else "value"
        ext_val = f"{real_ext}  ⚠ MISMATCH with '.{file_type}'" if is_mismatch else real_ext
        line("Real Extension",  ext_val,   ext_tag)
        line("Description",     real_desc)
        line("Magic Bytes",     magic,      "hash")

        section("🔐  CRYPTOGRAPHIC")
        short_sha = sha[:32] + "…" if len(sha) > 32 else sha
        line("SHA-256", short_sha, "hash")
        if len(sha) > 32:
            ins(tk.END, f"           {sha[32:]}\n", "hash")
        md5  = r.get("md5_hash", "") or ""
        sha1 = r.get("sha1_hash", "") or ""
        if md5:
            line("MD5", md5, "hash")
        if sha1:
            line("SHA-1", sha1, "hash")

        entropy = r.get("entropy", 0.0) or 0.0
        if   entropy > 7.5: ent_tag, ent_note = "warning", "  ⚠ Very high — possible encryption/packing"
        elif entropy > 6.0: ent_tag, ent_note = "amber",    "  — Elevated"
        elif entropy < 1.0: ent_tag, ent_note = "success",  "  ✓ Very low — likely plain text"
        else:               ent_tag, ent_note = "success",  "  ✓ Normal range"
        line("Entropy", f"{entropy:.4f}{ent_note}", ent_tag)
        bar_filled = int((entropy / 8.0) * 32)
        bar_str    = "█" * bar_filled + "░" * (32 - bar_filled)
        ins(tk.END, f"  {'':22}  [{bar_str}]\n", ent_tag)
        ins(tk.END, f"  {'':22}   0.0─────────4.0─────────8.0\n", "sep")
        chi   = r.get("chi_square", None)
        scorr = r.get("serial_correlation", None)
        if chi is not None:
            chi_note = "  ✓ Uniform (encrypted/random)" if float(chi) < 300 else "  — Structured"
            line("Chi-Square", f"{float(chi):.2f}{chi_note}",
                 "warning" if float(chi) < 300 else "value")
        if scorr is not None:
            line("Serial Corr.", f"{float(scorr):.6f}", "value")

        section("🕒  TIMESTAMPS")
        line("Created",     r.get("created_time",   "—"))
        line("Modified",    r.get("modified_time",   "—"))
        line("Accessed",    r.get("accessed_time",   "—"))
        line("Analyzed At", r.get("analyzed_at",     "—"))

        section("👤  OWNERSHIP & PERMISSIONS")
        line("Author",      r.get("author", "—"))
        line("Owner",       r.get("owner",   "—"))
        line("Permissions", r.get("permissions", "—"))
        is_hidden = r.get("is_hidden")
        line("Hidden File", "Yes  ⚠" if is_hidden else "No",
              "amber" if is_hidden else "success")

        section("🌐  SOURCE & ORIGIN")
        source = r.get("source_of_file", "—")
        url    = r.get("download_url",    "—")
        line("Source",       source, "warning" if source == "Internet" else "value")
        line("Download URL", url,     "url" if url and url != "N/A" else "value")

        section("🛡  REPUTATION (VirusTotal)")
        vt_score = r.get("vt_score", "N/A")
        vt_tag, vt_note = "value", " "
        if   vt_score == "Not Found":       vt_tag, vt_note = "amber",    " (Unique / New File)"
        elif vt_score == "Rate Limited":    vt_tag, vt_note = "warning",  " (Wait 1 minute)"
        elif vt_score == "Invalid API Key": vt_tag, vt_note = "warning",  " (Check Settings)"
        elif "/" in str(vt_score):
            vt_tag = "warning" if not vt_score.startswith("0/") else "success"
        line("VT Score", f"{vt_score}{vt_note}", vt_tag)
        if sha and sha != "—":
            line("Analysis Link",
                 f"https://www.virustotal.com/gui/file/{sha}", "url")

        # ── Integrity Status ──────────────────────────────────
        section("🔒  FILE INTEGRITY")
        fname_for_integ = r.get("filename", " ")
        ic = backend.get_integrity_check_for_file(self.db_path, fname_for_integ)
        if ic is None:
            ins(tk.END, "  No integrity check recorded yet for this file.\n", "value")
        else:
            st = ic.get("status", "new")
            status_labels = {
                "new":       ("🆕 NEW",        "success"),
                "unchanged": ("✓ UNCHANGED",   "success"),
                "modified":  ("⚠ MODIFIED!",   "warning"),
            }
            slabel, stag = status_labels.get(st, (st.upper(), "value"))
            line("Status",  slabel, stag)
            new_h = ic.get("new_hash") or " "
            if new_h:
                short_new = new_h[:32] + "…" if len(new_h) > 32 else new_h
                line("Current Hash", short_new, "hash")
            stored_h = ic.get("stored_hash") or " "
            if stored_h and st == "modified":
                short_stored = stored_h[:32] + "…" if len(stored_h) > 32 else stored_h
                line("Stored Hash",  short_stored, "hash")
            line("Checked At", ic.get("checked_at") or "—", "value")

        self.details_text.config(state=tk.DISABLED)

    # ══════════════════════════════════════════════════════
    # SETTINGS & API KEY
    # ══════════════════════════════════════════════════════
    def _load_settings(self):
        self.vt_api_key = os.environ.get("VT_API_KEY", "")
        if not self.vt_api_key and os.path.exists(self.settings_path):
            try:
                with open(self.settings_path, "r") as f:
                    self.vt_api_key = json.load(f).get("vt_api_key", "")
            except Exception:
                pass

    def _save_settings(self):
        try:
            with open(self.settings_path, "w") as f:
                json.dump({"vt_api_key": self.vt_api_key}, f)
        except Exception as e:
            messagebox.showerror("Settings Error", f"Failed to save settings:\n{e}")

    def set_vt_key(self):
        key = simpledialog.askstring(
            "VirusTotal API Key",
            "Enter your VirusTotal API Key:",
            initialvalue=self.vt_api_key)
        if key is not None:
            self.vt_api_key = key.strip()
            self._save_settings()
            messagebox.showinfo("Saved", "VirusTotal API Key saved successfully.")

    def fetch_vt_score(self):
        if not self.selected_record:
            messagebox.showwarning("No Selection", "Select a file from the table first.")
            return
        if not self.vt_api_key:
            messagebox.showwarning("No API Key", "Set your VirusTotal API Key first.")
            return
        r   = self.selected_record
        sha = r.get("sha256_hash")
        if not sha:
            messagebox.showerror("Error", "No hash found for this file.")
            return
        self.update_status(f"Fetching VT score for {r['filename']}…", busy=True)

        def _task():
            score = backend.check_virustotal(sha, self.vt_api_key)
            backend.update_vt_score(self.db_path, r["id"], score)
            backend.log_activity("VT_SCORE", f"{r['filename']} — {score}", self.activity_db)
            self._all_records = backend.get_all_records(self.db_path)
            self.root.after(0, self.refresh_database)
            self.root.after(0, lambda: self.update_status(f"VT Score updated: {score}"))

        threading.Thread(target=_task, daemon=True).start()

    # ══════════════════════════════════════════════════════
    # FILE ANALYSIS
    # ══════════════════════════════════════════════════════
    def analyze_file(self):
        filepath = filedialog.askopenfilename(title="Select File to Analyze")
        if not filepath:
            return
        sz_mb = os.path.getsize(filepath) / (1024 * 1024)
        self.update_status(
            f"Analyzing {os.path.basename(filepath)} ({sz_mb:.1f} MB)…", busy=True)
        threading.Thread(target=self._analyze_thread, args=(filepath,), daemon=True).start()

    def _build_change_meta(self, filepath, sha, prev_record):
        """Build 'new scan' metadata for the MetadataChangeSummaryDialog.

        Seeds the dict from prev_record (so entropy, extension, author etc.
        are always populated) and then overlays fresh filesystem values
        (size, timestamps, path, hash, permissions, hidden flag).
        This prevents N/A appearing for fields we didn't re-compute on re-scan.
        """
        new_data = dict(prev_record) if prev_record else {}
        # Always refresh path + identity
        new_data["filename"]    = os.path.basename(filepath)
        new_data["filepath"]    = os.path.abspath(filepath)
        if sha:
            new_data["sha256_hash"] = sha
        # Refresh in-place filesystem metadata
        try:
            st = os.stat(filepath)
            new_data["file_size"]     = st.st_size
            new_data["modified_time"] = backend.format_time(st.st_mtime)
            new_data["accessed_time"] = backend.format_time(st.st_atime)
            new_data["created_time"]  = backend.format_time(st.st_ctime)
        except Exception:
            pass
        try:
            new_data["permissions"] = backend.get_permissions_string(filepath)
        except Exception:
            pass
        try:
            new_data["is_hidden"] = int(backend.is_hidden_file(filepath))  # normalise to int like DB
        except Exception:
            pass
        return new_data



    def _analyze_thread(self, filepath):
        try:
            def progress_cb(done, total):
                pct = (done / total) * 100 if total else 0
                self.root.after(0, lambda: self.status_var.set(
                    f"Analyzing  {os.path.basename(filepath)}  — {pct:.0f}%"))

            filename = os.path.basename(filepath)

            # ── Step 0: Fetch previous record for metadata comparison ───────
            prev_record = None
            try:
                prev_record = backend.get_latest_record_by_filename(self.db_path, filename)
            except Exception:
                pass

            # ── Step 1: compute hash for integrity check ─────────────
            import hashlib
            sha = ""
            try:
                h = hashlib.sha256()
                with open(filepath, "rb") as fobj:
                    for chunk in iter(lambda: fobj.read(65536), b""):
                        h.update(chunk)
                sha = h.hexdigest()
            except Exception:
                pass   # hash failure is non-fatal

            # ── Step 2: integrity check (BEFORE any early-return) ─────
            now_str = datetime.datetime.now(
                datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            integ = {"status": "new"}
            if sha:
                integ = backend.check_file_changed(self.db_path, filename, sha)
                backend.save_integrity_check(self.db_path, {
                    "filename":        filename,
                    "filepath":        filepath,
                    "status":          integ["status"],
                    "new_hash":        sha,
                    "stored_hash":     integ.get("stored_hash") or "",
                    "stored_filepath": integ.get("stored_filepath") or "",
                    "checked_at":      now_str,
                })
                # NOTE: integrity alert is now shown via MetadataChangeSummaryDialog below

            # ── Step 3: refresh integrity tab ─────────────────────
            self.root.after(0, self._populate_integrity_tab)
            self.root.after(0, lambda: self._update_nav_badges(self._all_records))

            # ── Step 4: same path + same mtime → already scanned ───────
            existing_same_path = backend.check_if_analyzed(self.db_path, filepath)
            if existing_same_path:
                # ── Permission live-refresh fix ────────────────────────────
                # Windows does NOT update mtime when only permissions change,
                # so we always re-read permissions from disk and update the DB.
                backend.update_permissions_in_db(self.db_path, filepath)
                self._all_records = backend.get_all_records(self.db_path)
                self.root.after(0, lambda: self._populate_tree(self._all_records))
                self.root.after(0, lambda: self._populate_dashboard(self._all_records))
                # Always update the status bar so it doesn't stay on "Analyzing…"
                self.root.after(0, lambda: self.update_status(
                    f"✓  Already scanned (permissions refreshed) — {filename}"))
                if prev_record:
                    new_meta = self._build_change_meta(filepath, sha, prev_record)
                    self.root.after(50, lambda p=prev_record, n=new_meta:
                        MetadataChangeSummaryDialog(self.root, filename, p, n))
                return

            # ── Step 5: same filename + same hash → content unchanged ──
            if sha:
                same_file = backend.check_same_filename_and_hash(
                    self.db_path, filename, sha)
                if same_file:
                    # ── Permission live-refresh fix ────────────────────────
                    backend.update_permissions_in_db(self.db_path, filepath)
                    self._all_records = backend.get_all_records(self.db_path)
                    self.root.after(0, lambda: self._populate_tree(self._all_records))
                    self.root.after(0, lambda: self._populate_dashboard(self._all_records))
                    self.root.after(0, lambda: self._populate_integrity_tab())
                    self.root.after(0, lambda: self._update_nav_badges(self._all_records))
                    # Always update the status bar so it doesn't stay on "Analyzing…"
                    self.root.after(0, lambda: self.update_status(
                        f"✓  Already scanned (permissions refreshed) — {filename}"))
                    if prev_record:
                        new_meta = self._build_change_meta(filepath, sha, prev_record)
                        self.root.after(50, lambda p=prev_record, n=new_meta:
                            MetadataChangeSummaryDialog(self.root, filename, p, n))
                    return

            # ── Step 6: duplicate (same hash, different filename) ─────
            if sha:
                dupes = backend.check_duplicate_by_hash(self.db_path, sha, filepath)
                if dupes:
                    data = backend.analyze_file(
                        filepath, self.signatures,
                        progress_callback=progress_cb,
                        vt_api_key=self.vt_api_key,
                        db_path=self.db_path)
                    backend.save_analysis(self.db_path, data)
                    dup_names = ", ".join(d["filename"] for d in dupes)
                    backend.log_activity(
                        "DUPLICATE_DETECTED",
                        f"{filename} is a COPY of: {dup_names}",
                        self.activity_db)
                    self._all_records = backend.get_all_records(self.db_path)
                    self.root.after(0, lambda: self._populate_tree(self._all_records))
                    self.root.after(0, lambda: self._populate_dashboard(self._all_records))
                    self.root.after(0, lambda: self._populate_duplicates_tab(self._all_records))
                    self.root.after(0, lambda: self._update_stat_cards(self._all_records))
                    self.root.after(0, lambda: self._update_nav_badges(self._all_records))
                    self.root.after(0, lambda: self._update_threat_pill(self._all_records))
                    self.root.after(0, lambda: self._populate_logs())
                    self.root.after(0, lambda: self._populate_integrity_tab())
                    self.root.after(0, lambda: self.update_status(
                        f"Duplicate (copy) detected: {filename}"))
                    self.root.after(0, lambda d=data, dp=dupes:
                                    DuplicateAlertDialog(self.root, d, dp))
                    return

            # ── Step 7: full analysis (new or modified file) ────────
            data = backend.analyze_file(
                filepath, self.signatures,
                progress_callback=progress_cb,
                vt_api_key=self.vt_api_key,
                db_path=self.db_path)
            sha  = data.get("sha256_hash", sha)
            backend.save_analysis(self.db_path, data)
            backend.log_activity("ANALYZE_FILE",
                                  f"{filename} — entropy {data.get('entropy', 0):.2f}",
                                  self.activity_db)

            self._all_records = backend.get_all_records(self.db_path)
            self.root.after(0, lambda: self._populate_tree(self._all_records))
            self.root.after(0, lambda: self._populate_dashboard(self._all_records))
            self.root.after(0, lambda: self._populate_duplicates_tab(self._all_records))
            self.root.after(0, lambda: self._update_stat_cards(self._all_records))
            self.root.after(0, lambda: self._update_nav_badges(self._all_records))
            self.root.after(0, lambda: self._update_threat_pill(self._all_records))
            self.root.after(0, lambda: self._populate_integrity_tab())

            # Show MetadataChangeSummaryDialog if file was previously scanned
            if prev_record:
                self.root.after(200, lambda p=prev_record, d=dict(data):
                    MetadataChangeSummaryDialog(self.root, filename, p, d))
            elif integ["status"] == "modified":
                # Fallback: no prev_record but hash changed (edge case)
                stored_short = (integ.get("stored_hash") or "")[:24] + "..."
                new_short    = sha[:24] + "..."
                self.root.after(0, lambda: messagebox.showwarning(
                    "File Modified!",
                    f"INTEGRITY ALERT — file content has changed!\n\n"
                    f"File   :  {filename}\n"
                    f"Stored :  {stored_short}\n"
                    f"New    :  {new_short}\n\n"
                    f"Detected at: {now_str}"
                ))

            status_msgs = {
                "new":       f"✅  Finished (new file) — {filename}",
                "unchanged": f"✅  Finished (unchanged) — {filename}",
                "modified":  f"⚠  Finished (MODIFIED) — {filename}",
            }
            self.root.after(0, lambda msg=status_msgs.get(integ["status"],
                f"✅  Finished — {filename}"): self.update_status(msg))
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Analysis Error", str(e)))
            self.root.after(0, lambda: self.update_status("Error during analysis"))


    def scan_folder(self):
        folderpath = filedialog.askdirectory(title="Select Folder to Scan")
        if not folderpath:
            return
        self.update_status("Scanning folder…", busy=True)
        threading.Thread(target=self._scan_thread, args=(folderpath,), daemon=True).start()

    def _scan_thread(self, folderpath):
        """
        Fast folder scan — NO VirusTotal calls during scan (eliminates 15s-per-file delay).
        After scan completes, user is offered a batch VT fetch option.
        """
        all_files = []
        for root_dir, _, files in os.walk(folderpath):
            for filename in files:
                all_files.append(os.path.join(root_dir, filename))
        total = len(all_files)
        count = 0
        new_count = 0
        duplicates_found = []

        for i, fp in enumerate(all_files):
            try:
                msg = f"Scanning {i+1}/{total} — {os.path.basename(fp)}…"
                self.root.after(0, lambda m=msg: self.status_var.set(m))

                fname   = os.path.basename(fp)
                now_str = datetime.datetime.now(
                    datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

                # Step 1: Skip if already scanned at this exact path with same mtime
                existing_same_path = backend.check_if_analyzed(self.db_path, fp)
                if existing_same_path:
                    count += 1
                    continue

                # Step 2: Analyze file — NO VT call (vt_api_key=None for speed)
                data = backend.analyze_file(fp, self.signatures, vt_api_key=None,
                                             db_path=self.db_path)
                sha  = data.get("sha256_hash", "")

                # Step 3: Skip if same filename + hash already in DB (unchanged)
                if sha:
                    same_file = backend.check_same_filename_and_hash(
                        self.db_path, fname, sha)
                    if same_file:
                        integ = backend.check_file_changed(self.db_path, fname, sha)
                        backend.save_integrity_check(self.db_path, {
                            "filename":       fname,
                            "filepath":       fp,
                            "status":         "unchanged",
                            "new_hash":       sha,
                            "stored_hash":    integ.get("stored_hash") or "",
                            "stored_filepath": integ.get("stored_filepath") or "",
                            "checked_at":     now_str,
                        })
                        count += 1
                        continue

                # Step 4: Integrity check
                integ = backend.check_file_changed(self.db_path, fname, sha)
                backend.save_integrity_check(self.db_path, {
                    "filename":       fname,
                    "filepath":       fp,
                    "status":         integ["status"],
                    "new_hash":       sha,
                    "stored_hash":    integ.get("stored_hash") or "",
                    "stored_filepath": integ.get("stored_filepath") or "",
                    "checked_at":     now_str,
                })

                # Step 5: Check for content duplicates (same hash, different name)
                if sha:
                    dupes = backend.check_duplicate_by_hash(self.db_path, sha, fp)
                    if dupes:
                        backend.save_analysis(self.db_path, data)
                        dup_names = ", ".join(d["filename"] for d in dupes)
                        backend.log_activity(
                            "DUPLICATE_DETECTED",
                            f"{fname} is a COPY of: {dup_names}",
                            self.activity_db)
                        duplicates_found.append((data, dupes))
                        count += 1
                        continue

                # Step 6: Save new file analysis
                backend.save_analysis(self.db_path, data)
                backend.log_activity("SCAN_FOLDER",
                                     f"{fname} — {i+1}/{total}",
                                     self.activity_db)
                count += 1
                new_count += 1
            except Exception:
                pass

        self._all_records = backend.get_all_records(self.db_path)
        self.root.after(0, lambda: self.filter_var.set(""))
        self.root.after(0, lambda: self._populate_tree(self._all_records))
        self.root.after(0, lambda: self._populate_dashboard(self._all_records))
        self.root.after(0, lambda: self._populate_duplicates_tab(self._all_records))
        self.root.after(0, lambda: self._update_stat_cards(self._all_records))
        self.root.after(0, lambda: self._update_nav_badges(self._all_records))
        self.root.after(0, lambda: self._update_threat_pill(self._all_records))
        self.root.after(0, lambda: self._populate_integrity_tab())
        self.root.after(0, lambda: self._populate_logs())

        for dup_data, dup_originals in duplicates_found:
            self.root.after(0, lambda d=dup_data, dp=dup_originals:
                            DuplicateAlertDialog(self.root, d, dp))

        finish_msg = f"✓  Scan complete — {count} files ({new_count} new)"
        self.root.after(0, lambda: self.update_status(finish_msg, busy=False))

        # Offer VT batch scan only if API key is set and there are new files
        if self.vt_api_key and new_count > 0:
            self.root.after(
                200,
                lambda: self._offer_vt_batch_scan(new_count)
            )

    def _offer_vt_batch_scan(self, new_count):
        """After folder scan, ask user if they want to batch-fetch VT scores."""
        if messagebox.askyesno(
            "VirusTotal Scan",
            f"{new_count} new file(s) were scanned without VirusTotal scores\n"
            f"(skipped for speed during folder scan).\n\n"
            f"Fetch VirusTotal scores now?\n"
            f"Note: This will take ~15s per file due to API rate limits.",
            icon="question"
        ):
            threading.Thread(
                target=self._batch_vt_thread,
                daemon=True
            ).start()

    def _batch_vt_thread(self):
        """Background thread: fetch VT scores for all records with vt_score='N/A'."""
        import time
        if not self.vt_api_key:
            return
        records = backend.get_all_records(self.db_path)
        pending = [r for r in records if (r.get("vt_score") or "N/A") == "N/A"
                   and r.get("sha256_hash")]
        total = len(pending)
        for i, r in enumerate(pending):
            msg = f"VT scan {i+1}/{total}: {r.get('filename', '?')}…"
            self.root.after(0, lambda m=msg: self.update_status(m, busy=True))
            score = backend.check_virustotal(r["sha256_hash"], self.vt_api_key)
            backend.update_vt_score(self.db_path, r["id"], score)
            if i < total - 1:
                time.sleep(15)   # VT free-tier rate limit
        self._all_records = backend.get_all_records(self.db_path)
        self.root.after(0, lambda: self._populate_tree(self._all_records))
        self.root.after(0, lambda: self._populate_dashboard(self._all_records))
        self.root.after(0, lambda: self._update_stat_cards(self._all_records))
        self.root.after(0, lambda: self.update_status(
            f"✅  VirusTotal scan complete — {total} file(s) checked", busy=False))

    # ══════════════════════════════════════════════════════
    # EXPORT
    # ══════════════════════════════════════════════════════
    def export_report(self):
        if not self.selected_record:
            messagebox.showwarning("No Selection", "Select a record first.")
            return
        try:
            from pdf_report import export_pdf_report
        except ImportError:
            messagebox.showerror(
                "Missing Module",
                "pdf_report.py not found.\n"
                "Place pdf_report.py in the same folder as frontend.py and try again.")
            return

        # ── Investigator Details Dialog ─────────────────────────────────
        inv_dialog = tk.Toplevel(self.root)
        inv_dialog.title("Investigator Details")
        inv_dialog.configure(bg=C["card"])
        inv_dialog.resizable(False, False)
        inv_dialog.transient(self.root)
        inv_dialog.grab_set()

        # Centre the dialog
        inv_dialog.update_idletasks()
        pw = self.root.winfo_width();  ph = self.root.winfo_height()
        px = self.root.winfo_rootx(); py = self.root.winfo_rooty()
        dw, dh = 420, 310
        inv_dialog.geometry(f"{dw}x{dh}+{px+(pw-dw)//2}+{py+(ph-dh)//2}")

        # Header
        hdr = tk.Frame(inv_dialog, bg=C["blue"])
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text="  🖊  Investigator Details",
                 bg=C["blue"], fg="white",
                 font=("Segoe UI Semibold", 12, "bold"),
                 pady=12).pack(side=tk.LEFT)

        body = tk.Frame(inv_dialog, bg=C["card"], padx=24, pady=16)
        body.pack(fill=tk.BOTH, expand=True)

        tk.Label(body,
                 text="These details will appear in the PDF Digital Signature block.",
                 bg=C["card"], fg=C["t_muted"],
                 font=("Segoe UI", 8), wraplength=370,
                 justify=tk.LEFT).pack(anchor="w", pady=(0, 12))

        fields = {}
        field_defs = [
            ("Investigator Name *", "inv_name",   True),
            ("Badge / ID Number",   "inv_badge",  False),
            ("Organization / Unit", "inv_org",    False),
        ]
        for label_text, key, required in field_defs:
            row = tk.Frame(body, bg=C["card"])
            row.pack(fill=tk.X, pady=4)
            tk.Label(row, text=label_text,
                     bg=C["card"], fg=C["t_primary"],
                     font=("Segoe UI", 9, "bold"),
                     width=22, anchor="w").pack(side=tk.LEFT)
            entry = tk.Entry(row,
                             font=("Segoe UI", 10),
                             bg=C["card_alt"], fg=C["t_primary"],
                             relief="flat", bd=0,
                             highlightbackground=C["border"],
                             highlightthickness=1)
            entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=5, padx=(6, 0))
            fields[key] = (entry, required)

        result = {"submitted": False}

        def on_submit():
            name = fields["inv_name"][0].get().strip()
            if not name:
                messagebox.showwarning("Name Required",
                                       "Please enter the Investigator Name.",
                                       parent=inv_dialog)
                return
            result["submitted"]   = True
            result["inv_name"]    = name
            result["inv_badge"]   = fields["inv_badge"][0].get().strip()
            result["inv_org"]     = fields["inv_org"][0].get().strip()
            inv_dialog.destroy()

        def on_cancel():
            inv_dialog.destroy()

        btn_row = tk.Frame(body, bg=C["card"])
        btn_row.pack(fill=tk.X, pady=(14, 0))

        cancel_btn = tk.Label(btn_row, text="  Cancel  ",
                              bg=C["card_alt"], fg=C["t_secondary"],
                              font=("Segoe UI", 9, "bold"),
                              padx=14, pady=7, cursor="hand2")
        cancel_btn.pack(side=tk.RIGHT, padx=(8, 0))
        cancel_btn.bind("<Enter>",           lambda e: cancel_btn.config(bg=C["border"]))
        cancel_btn.bind("<Leave>",           lambda e: cancel_btn.config(bg=C["card_alt"]))
        cancel_btn.bind("<ButtonRelease-1>", lambda e: on_cancel())

        ok_btn = tk.Label(btn_row, text="  Generate PDF  ",
                          bg=C["blue"], fg="white",
                          font=("Segoe UI", 9, "bold"),
                          padx=14, pady=7, cursor="hand2")
        ok_btn.pack(side=tk.RIGHT)
        ok_btn.bind("<Enter>",           lambda e: ok_btn.config(bg=C["blue_dk"]))
        ok_btn.bind("<Leave>",           lambda e: ok_btn.config(bg=C["blue"]))
        ok_btn.bind("<ButtonRelease-1>", lambda e: on_submit())

        inv_dialog.bind("<Return>", lambda e: on_submit())
        fields["inv_name"][0].focus_set()
        self.root.wait_window(inv_dialog)

        if not result.get("submitted"):
            return   # user cancelled

        # ── File save dialog ────────────────────────────────────────────
        safe_name = "".join(
            c for c in (self.selected_record.get("filename") or "report")
            if c.isalnum() or c in ("_", "-", "."))
        filepath = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF Files", "*.pdf"), ("All Files", "*.*")],
            initialfile=f"forensic_report_{safe_name}.pdf",
            title="Save PDF Report")
        if not filepath:
            return
        try:
            self.update_status("Generating PDF report…", busy=True)
            export_pdf_report(
                self.selected_record, filepath,
                db_path=self.db_path,
                investigator_name=result["inv_name"],
                investigator_badge=result["inv_badge"],
                investigator_org=result["inv_org"],
            )
            self.update_status(f"✓  PDF exported → {os.path.basename(filepath)}")
            messagebox.showinfo("Export Successful", f"PDF report saved:\n{filepath}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to generate PDF:\n{e}")
            self.update_status("PDF export failed")
    
    # clear_logs is defined above at line ~2383 — duplicate removed

    def export_all_csv(self):
        records = backend.get_all_records(self.db_path)
        if not records:
            messagebox.showwarning("Empty Database", "No records to export.")
            return
        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv")],
            initialfile="forensic_export.csv",
            title="Save CSV")
        if not filepath:
            return
        self.update_status("Exporting to CSV…", busy=True)
        try:
            import csv
            with open(filepath, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=records[0].keys())
                writer.writeheader()
                writer.writerows(records)
            self.update_status(
                f"✓  Exported {len(records)} records to {os.path.basename(filepath)}")
            messagebox.showinfo("Export Successful", "Database exported to CSV!")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))
            self.update_status("Export failed")

if __name__ == "__main__":
    root = tk.Tk()
    app  = ForensicApp(root)
    root.mainloop()
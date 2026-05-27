import os
import sqlite3
import hashlib
import math
import csv
import stat
import datetime
from collections import Counter
import json
import urllib.request
import urllib.error


# ─────────────────────────────────────────────────────────────────────────────
# EXTENSION FAMILIES
# ─────────────────────────────────────────────────────────────────────────────
EXTENSION_FAMILIES = {
    "exe":   {"exe", "dll", "sys", "scr", "ocx", "cpl", "ax", "acm", "drv", "mui", "efi"},
    "dll":   {"exe", "dll", "sys", "scr", "ocx", "cpl", "ax", "acm", "drv", "mui", "efi"},
    "sys":   {"exe", "dll", "sys", "scr", "ocx", "cpl", "ax", "acm", "drv"},
    "scr":   {"exe", "dll", "sys", "scr", "ocx"},
    "ocx":   {"exe", "dll", "sys", "scr", "ocx"},
    "cpl":   {"exe", "dll", "sys", "scr", "ocx", "cpl"},
    "ax":    {"exe", "dll", "ax"},
    "acm":   {"exe", "dll", "acm"},
    "drv":   {"exe", "dll", "sys", "drv"},
    "mui":   {"exe", "dll", "mui"},
    "efi":   {"exe", "efi"},
    "zip":   {"zip", "docx", "xlsx", "pptx", "odt", "ods", "odp", "odg",
              "jar", "apk", "epub", "aab", "war", "aar", "xpi", "nupkg"},
    "docx":  {"zip", "docx", "odt"},
    "xlsx":  {"zip", "xlsx", "ods"},
    "pptx":  {"zip", "pptx", "odp"},
    "odt":   {"zip", "docx", "odt"},
    "ods":   {"zip", "xlsx", "ods"},
    "odp":   {"zip", "pptx", "odp"},
    "odg":   {"zip", "odg"},
    "jar":   {"zip", "jar", "war", "aar"},
    "apk":   {"zip", "apk", "aab"},
    "aab":   {"zip", "apk", "aab"},
    "epub":  {"zip", "epub"},
    "war":   {"zip", "jar", "war"},
    "xpi":   {"zip", "xpi"},
    "ole":   {"ole", "doc", "xls", "ppt", "msg", "msi", "pub", "vsd", "mpp", "wps"},
    "doc":   {"ole", "doc", "wps"},
    "xls":   {"ole", "xls"},
    "ppt":   {"ole", "ppt"},
    "msg":   {"ole", "msg"},
    "msi":   {"ole", "msi"},
    "pub":   {"ole", "pub"},
    "vsd":   {"ole", "vsd"},
    "jpg":   {"jpg", "jpeg", "jfif", "jpe"},
    "jpeg":  {"jpg", "jpeg", "jfif", "jpe"},
    "jfif":  {"jpg", "jpeg", "jfif"},
    "tif":   {"tif", "tiff"},
    "tiff":  {"tif", "tiff"},
    "mp4":   {"mp4", "m4v", "m4a", "mov", "f4v", "f4a", "3gp", "3g2", "heic", "avif", "mif1"},
    "m4v":   {"mp4", "m4v", "m4a", "mov"},
    "m4a":   {"mp4", "m4v", "m4a", "mov"},
    "mov":   {"mp4", "m4v", "m4a", "mov"},
    "3gp":   {"mp4", "3gp", "3g2"},
    "3g2":   {"mp4", "3gp", "3g2"},
    "heic":  {"mp4", "heic", "heif", "avif"},
    "avif":  {"mp4", "heic", "avif"},
    "mkv":   {"mkv", "webm", "mka", "mks"},
    "webm":  {"mkv", "webm"},
    "mka":   {"mkv", "mka"},
    "mpg":   {"mpg", "mpeg", "vob", "m2v", "ts"},
    "mpeg":  {"mpg", "mpeg", "vob", "m2v"},
    "vob":   {"mpg", "vob"},
    "asf":   {"asf", "wmv", "wma"},
    "wmv":   {"asf", "wmv"},
    "wma":   {"asf", "wma"},
    "riff":  {"riff", "wav", "avi", "webp", "ani", "cda"},
    "wav":   {"riff", "wav"},
    "avi":   {"riff", "avi"},
    "webp":  {"riff", "webp"},
    "ogg":   {"ogg", "ogv", "oga", "opus", "spx"},
    "ogv":   {"ogg", "ogv"},
    "oga":   {"ogg", "oga", "opus"},
    "opus":  {"ogg", "oga", "opus"},
    "elf":   {"elf", "so", "axf", "prx", "ko"},
    "so":    {"elf", "so"},
    "ko":    {"elf", "ko"},
    "macho": {"macho", "dylib", "bundle", "o", "kext"},
    "dylib": {"macho", "dylib"},
    "db":    {"db", "sqlite", "sqlite3", "db3"},
    "sqlite":{"db", "sqlite", "sqlite3"},
    "txt":   {"txt", "log", "md", "ini", "cfg", "conf", "nfo", "text"},
    "log":   {"txt", "log"},
    "md":    {"txt", "md"},
    "rar":   {"rar"},
    "gz":    {"gz", "tgz"},
    "tgz":   {"gz", "tgz"},
    "bz2":   {"bz2", "tbz2"},
    "7z":    {"7z"},
    "pcap":  {"pcap", "cap"},
    "cap":   {"pcap", "cap"},
}


def is_extension_mismatch(file_type: str, real_ext: str) -> bool:
    """
    Check if the file's actual extension matches its claimed extension.
    
    This function compares what the file says it is (file_type) with what it 
    actually is (real_ext from magic bytes). For example, a file named 'document.pdf'
    that actually contains executable code would be flagged as a mismatch.
    
    Args:
        file_type: The file extension from the filename (e.g., 'pdf', 'exe')
        real_ext: The real file type detected from magic bytes
    
    Returns:
        True if extensions don't match, False if they match or are related
    """
    ft  = (file_type or "").lower().strip().lstrip(".")
    re_ = (real_ext  or "").lower().strip().lstrip(".")
    if not ft or not re_:
        return False
    if ft in ("unknown", "empty") or re_ in ("unknown", "empty"):
        return False
    if ft == re_:
        return False
    if ft in EXTENSION_FAMILIES.get(re_, set()):
        return False
    if re_ in EXTENSION_FAMILIES.get(ft, set()):
        return False
    return True


# ─────────────────────────────────────────────────────────────────────────────
# DATABASE HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def get_db_connection(db_path="forensic_data.db"):
    """
    Create and return a connection to the SQLite database.
    
    This opens the database file and sets up the connection so that 
    query results can be accessed like dictionaries (by column name).
    
    Args:
        db_path: Path to the SQLite database file
    
    Returns:
        A sqlite3 connection object with row_factory set to Row
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_activity_db(db_path="activity_logs.db"):
    """
    Initialize the activity logs database with required tables.
    
    Creates the activity_logs table if it doesn't exist. This table stores
    a history of all actions performed in the application (file scans, 
    exports, etc.) for auditing purposes.
    
    Args:
        db_path: Path to the activity logs database file
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            action TEXT,
            details TEXT
        )
    ''')
    conn.commit()
    conn.close()


def init_db(db_path="forensic_data.db"):
    """
    Initialize the main forensic database with all required tables.
    
    Creates the forensic_files table to store file analysis results and
    the integrity_checks table to track file modifications. Also handles
    database migrations by adding any missing columns to existing tables.
    
    Args:
        db_path: Path to the forensic database file
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS forensic_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            filepath TEXT,
            file_size INTEGER,
            file_type TEXT,
            created_time TEXT,
            modified_time TEXT,
            accessed_time TEXT,
            sha256_hash TEXT,
            author TEXT,
            owner TEXT,
            source_of_file TEXT,
            download_url TEXT,
            permissions TEXT,
            is_hidden INTEGER,
            entropy REAL,
            magic_bits TEXT,
            real_file_extension TEXT,
            real_file_description TEXT,
            analyzed_at TEXT,
            vt_score TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS integrity_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            filepath TEXT,
            status TEXT,
            new_hash TEXT,
            stored_hash TEXT,
            checked_at TEXT
        )
    ''')

    # Migrate existing databases — add any missing columns
    _ensure_columns(cursor, "integrity_checks", {
        "filename":        "TEXT",
        "filepath":        "TEXT",
        "status":          "TEXT",
        "new_hash":        "TEXT",
        "stored_hash":     "TEXT",
        "stored_filepath": "TEXT",
        "checked_at":      "TEXT",
    })
    _ensure_columns(cursor, "forensic_files", {
        "vt_score":              "TEXT",
        "real_file_extension":   "TEXT",
        "real_file_description": "TEXT",
        "magic_bits":            "TEXT",
        "entropy":               "REAL",
        "is_hidden":             "INTEGER",
        "download_url":          "TEXT",
        "source_of_file":        "TEXT",
    })

    conn.commit()
    conn.close()


def _ensure_columns(cursor, table: str, columns: dict) -> None:
    """
    Add missing columns to an existing database table.
    
    This is used for database migrations - when new features need new fields,
    this function adds them without losing existing data.
    
    Args:
        cursor: Database cursor object
        table: Name of the table to check
        columns: Dictionary of column_name -> column_type to ensure exist
    """
    cursor.execute(f"PRAGMA table_info({table})")
    existing = {row["name"] for row in cursor.fetchall()}
    for col, col_type in columns.items():
        if col not in existing:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}")


# ─────────────────────────────────────────────────────────────────────────────
# DUPLICATE / ALREADY-UPLOADED DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def check_already_uploaded(db_path: str, filepath: str, sha256_hash: str) -> bool:
    """
    Check if this exact file has already been analyzed.(integrity check)
    
    Determines if a file with the same name and same content (SHA-256 hash)
    already exists in the database. This prevents re-analyzing files that
    haven't changed.
    
    Args:
        db_path: Path to the forensic database
        filepath: Full path to the file being checked
        sha256_hash: SHA-256 hash of the file content
    
    Returns:
        True if this exact file (same name + same hash) already exists
    """
    if not sha256_hash:
        return False
    filename = os.path.basename(filepath)
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id FROM forensic_files
        WHERE  filename    = ?
          AND  sha256_hash = ?
        LIMIT  1
        """,
        (filename, sha256_hash),
    )
    row = cursor.fetchone()
    conn.close()
    return row is not None


def check_duplicate_by_hash(db_path: str, sha256_hash: str, current_filepath: str) -> list:
    """
    Find files with identical content but different names.
    
    Searches the database for files that have the same SHA-256 hash (same
    content) but different filenames. These are duplicate files - exact
    copies with different names or locations.
    
    Args:
        db_path: Path to the forensic database
        sha256_hash: SHA-256 hash to search for
        current_filepath: Path of the current file (excluded from results)
    
    Returns:
        List of database records that are content duplicates
    """
    if not sha256_hash:
        return []
    current_name = os.path.basename(current_filepath)
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, filename, filepath, analyzed_at, file_type
        FROM   forensic_files
        WHERE  sha256_hash = ?
          AND  filename    != ?
        ORDER  BY id ASC
        """,
        (sha256_hash, current_name),
    )
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def check_same_filename_and_hash(db_path: str, filename: str, sha256_hash: str) -> list:
    """
    Find previously analyzed files with same name and unchanged content.
    
    Looks for database entries with the same filename and same SHA-256 hash.
    These represent files that were analyzed before and haven't changed.
    
    Args:
        db_path: Path to the forensic database
        filename: Name of the file to search for
        sha256_hash: SHA-256 hash to match
    
    Returns:
        List of matching database records
    """
    if not sha256_hash:
        return []
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, filename, filepath, analyzed_at, file_type
        FROM   forensic_files
        WHERE  filename    = ?
          AND  sha256_hash = ?
        ORDER  BY id ASC
        """,
        (filename, sha256_hash),
    )
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


# ─────────────────────────────────────────────────────────────────────────────
# FILE CHANGE DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def check_file_changed(db_path: str, filename: str, new_sha256: str) -> dict:
    """
    Check if a file's content has changed since last analysis.
    
    Compares the current SHA-256 hash of a file against the stored hash
    from the most recent analysis of a file with the same name. Determines
    if the file is new, unchanged, or modified.
    
    Args:
        db_path: Path to the forensic database
        filename: Name of the file being checked
        new_sha256: Current SHA-256 hash of the file
    
    Returns:
        Dictionary with status ('new', 'unchanged', or 'modified'),
        stored_hash (previous hash if any), and stored_filepath

    Returns a dict with keys:
        "status"          → "new" | "unchanged" | "modified"
        "stored_hash"     → hash stored in DB (None if new)
        "stored_filepath" → filepath stored in DB (None if new)
        "stored_db_id"    → DB id of stored record (None if new)
        "first_seen"      → analyzed_at of stored record (None if new)
        "timestamp"       → UTC detection time (None unless modified)
    """
    conn   = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, sha256_hash, filepath, analyzed_at
        FROM   forensic_files
        WHERE  filename = ?
        ORDER  BY id DESC
        LIMIT  1
        """,
        (filename,),
    )
    row = cursor.fetchone()
    conn.close()

    if row is None:
        return {"status": "new", "stored_hash": None, "timestamp": None,
                "first_seen": None, "stored_filepath": None, "stored_db_id": None}

    stored_hash     = row["sha256_hash"]
    first_seen      = row["analyzed_at"]
    stored_filepath = row["filepath"]
    stored_db_id    = row["id"]

    if new_sha256 == stored_hash:
        return {"status": "unchanged", "stored_hash": stored_hash,
                "timestamp": None, "first_seen": first_seen,
                "stored_filepath": stored_filepath, "stored_db_id": stored_db_id}

    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC")
    return {"status": "modified", "stored_hash": stored_hash,
            "timestamp": timestamp, "first_seen": first_seen,
            "stored_filepath": stored_filepath, "stored_db_id": stored_db_id}


# ─────────────────────────────────────────────────────────────────────────────
# INTEGRITY CHECK — SAVE & FETCH
# ─────────────────────────────────────────────────────────────────────────────

def save_integrity_check(db_path: str, data: dict) -> None:
    """
    Save a file integrity check result to the database.
    
    Records the result of comparing a file's current state against its
    previous state. Stores the hash comparison result for tracking file
    modifications over time.
    
    Args:
        db_path: Path to the forensic database
        data: Dictionary containing filename, filepath, status, hashes, timestamp
    """
    conn   = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO integrity_checks
            (filename, filepath, status, new_hash, stored_hash,
             stored_filepath, checked_at)
        VALUES
            (:filename, :filepath, :status, :new_hash, :stored_hash,
             :stored_filepath, :checked_at)
        """,
        {
            "filename":       data.get("filename", ""),
            "filepath":       data.get("filepath", ""),
            "status":         data.get("status", "new"),
            "new_hash":       data.get("new_hash", ""),
            "stored_hash":    data.get("stored_hash") or "",
            "stored_filepath":data.get("stored_filepath") or "",
            "checked_at":     data.get("checked_at", ""),
        },
    )
    conn.commit()
    conn.close()


def get_integrity_checks(db_path: str) -> list:
    """
    Retrieve all integrity check records from the database.
    
    Gets the complete history of file integrity checks, sorted with
    newest entries first. Used for displaying the integrity monitoring log.
    
    Args:
        db_path: Path to the forensic database
    
    Returns:
        List of dictionaries containing all integrity check records
    """
    conn   = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM integrity_checks ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_integrity_check_for_file(db_path: str, filename: str) -> dict:
    """
    Get the most recent integrity check for a specific file.
    
    Retrieves the latest integrity check record for a given filename.
    Used when displaying file details to show if the file has been
    modified since its last analysis.
    
    Args:
        db_path: Path to the forensic database
        filename: Name of the file to look up
    
    Returns:
        Dictionary with integrity check data, or None if no record exists
    """
    conn   = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM integrity_checks WHERE filename = ? ORDER BY id DESC LIMIT 1",
        (filename,),
    )
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


# ─────────────────────────────────────────────────────────────────────────────
# SIGNATURE & KNOWN EXTENSION LOADING
# ─────────────────────────────────────────────────────────────────────────────

def load_known_binary_extensions(csv_path="known_binary_extensions.csv"):
    """
    Load a list of known binary file extensions from a CSV file.
    
    Reads a CSV file containing file extensions that are known to be binary
    (non-text) formats. Used to help identify suspicious file types.
    
    Args:
        csv_path: Path to the CSV file containing binary extensions
    
    Returns:
        Dictionary mapping extensions to their descriptions
    """
    result = {}
    if not os.path.exists(csv_path):
        return result
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ext  = (row.get("Extension") or "").strip().lower().lstrip(".")
            desc = (row.get("Description") or "").strip()
            if ext and desc:
                result[ext] = desc
    return result


def load_signatures(csv_path="file_signatures_clean.csv"):
    """
    Load file signature (magic bytes) definitions from a CSV file.
    
    Reads a CSV file containing file signatures - the byte patterns at the
    beginning of files that identify their true format (like 'MZ' for EXE files
    or '%PDF' for PDF files). These are used to detect files with misleading extensions.
    
    Args:
        csv_path: Path to the CSV file containing file signatures
    
    Returns:
        List of dictionaries with signature patterns and their corresponding file types
    """
    import re
    signatures = []
    if not os.path.exists(csv_path):
        return signatures

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            raw_hex = (row.get("Hex Signature") or row.get("Hex signature") or "").strip()
            clean   = re.sub(r"[^0-9A-Fa-f]", "", raw_hex)
            if len(clean) % 2 != 0:
                clean = clean[:-1]
            if len(clean) < 4:
                continue
            try:
                sig_bytes = bytes.fromhex(clean)
            except ValueError:
                continue

            offset_str = str(row.get("Offset", "0")).strip().split(",")[0].strip()
            try:
                offset = int(offset_str, 16) if offset_str.lower().startswith("0x") else int(offset_str)
            except ValueError:
                offset = 0

            ext  = (row.get("Extension", "") or "").strip().lower().split("/")[0].strip()
            desc = (row.get("Description", "") or ext).strip()

            signatures.append({"bytes": sig_bytes, "offset": offset,
                                "ext": ext, "desc": desc})

    signatures.sort(key=lambda x: -len(x["bytes"]))
    return signatures


# ─────────────────────────────────────────────────────────────────────────────
# ENTROPY CALCULATION
# ─────────────────────────────────────────────────────────────────────────────

def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of a byte sequence.
    
    Shannon entropy measures how random or unpredictable data is. Higher values
    (closer to 8.0) indicate more randomness, which may suggest encryption or
    compression. Lower values indicate structured or text data.
    
    Args:
        data: Raw bytes to analyze
    
    Returns:
        Entropy value between 0.0 and 8.0 (bits per byte)
    """
    if not data:
        return 0.0
    total = len(data)
    counter = Counter(data)
    entropy = 0.0
    for count in counter.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(min(max(entropy, 0.0), 8.0), 4)


def calculate_entropy_from_counter(counter, total_bytes):
    """
    Calculate entropy from a pre-built byte frequency counter.
    
    This is an optimized version that calculates entropy when you already
    have a Counter object with byte frequencies, avoiding re-counting.
    
    Args:
        counter: Counter object mapping byte values to their frequencies
        total_bytes: Total number of bytes counted
    
    Returns:
        Entropy value between 0.0 and 8.0
    """
    if not counter or total_bytes == 0:
        return 0.0
    entropy = 0.0
    for count in counter.values():
        if count > 0:
            p = count / total_bytes
            entropy -= p * math.log2(p)
    return round(min(max(entropy, 0.0), 8.0), 4)


def calculate_chi_square(counter, total_bytes):
    """
    Calculate Chi-Square statistic for byte distribution.
    
    Chi-Square test determines if bytes are uniformly distributed (random)
    or have structure. Low values suggest encryption/randomness, high values
    suggest structured data.
    
    Args:
        counter: Counter object with byte frequencies
        total_bytes: Total number of bytes
    
    Returns:
        Chi-Square statistic value
    """
    if total_bytes == 0:
        return 0.0
    actual_total = sum(counter.values())
    if actual_total == 0:
        return 0.0
    expected = actual_total / 256.0
    chi_sq = sum(((counter.get(b, 0) - expected) ** 2) / expected for b in range(256))
    return round(chi_sq, 4)


def calculate_serial_correlation(data_bytes):
    """
    Calculate serial correlation coefficient of byte sequence.
    
    Measures how correlated adjacent bytes are. Encrypted/compressed data has
    low correlation (near 0), while text has higher correlation.
    
    Args:
        data_bytes: Bytes or list of byte values
    
    Returns:
        Correlation coefficient between -1.0 and 1.0
    """
    # Calculate serial correlation from a bytes or list object (no file I/O)
    n = len(data_bytes)
    if n < 2:
        return 0.0
    vals = list(data_bytes) if isinstance(data_bytes, (bytes, bytearray)) else data_bytes
    sum_val  = sum(vals)
    sum_sq   = sum(v * v for v in vals)
    sum_prod = sum(vals[i] * vals[(i + 1) % n] for i in range(n))
    denom = n * sum_sq - sum_val * sum_val
    if denom == 0:
        return 0.0
    return round(max(-1.0, min(1.0, (n * sum_prod - sum_val * sum_val) / denom)), 6)


def classify_entropy(shannon, file_type=None):
    """
    Classify entropy level into human-readable categories.
    
    Takes a Shannon entropy value and returns a classification describing
    what type of data it likely represents (empty, text, compressed, encrypted, etc.)
    along with a risk level.
    
    Args:
        shannon: Shannon entropy value (0.0 to 8.0)
        file_type: Optional file extension for context-aware classification
    
    Returns:
        Dictionary with 'category', 'risk_level', and 'description' keys
    """
    ftype = (file_type or "").lower()

    if shannon < 1.0:
        cat, risk, desc = "empty",        "low",      "Empty or uniform data"
    elif shannon < 4.0:
        cat, risk, desc = "plain_text",   "low",      "Plain text, source code, or structured data"
    elif shannon < 6.0:
        cat, risk, desc = "mixed_content","low",      "Formatted documents or mixed content"
    elif shannon < 7.0:
        cat, risk, desc = "compressed",   "medium",   "Compressed or binary data"
    elif shannon < 7.5:
        cat, risk, desc = "packed",       "high",     "Packed executable or strong compression"
    else:
        cat, risk, desc = "encrypted",    "critical", "Possibly encrypted or random data"

    if ftype in ("exe", "dll", "elf", "so", "dylib", "sys", "macho",
                 "drv", "ocx", "cpl", "scr", "ax", "acm", "ko"):
        if shannon >= 7.0:
            cat, risk, desc = "executable_binary", "medium", \
                "Executable machine code (naturally high entropy)"

    return {"category": cat, "risk_level": risk, "description": desc}


# ─────────────────────────────────────────────────────────────────────────────
# CONTENT-AWARE ENTROPY DISPATCHERS
# ─────────────────────────────────────────────────────────────────────────────

def calculate_pixel_entropy(filepath):
    """
    Calculate entropy from image pixel data.
    
    Opens an image file and calculates entropy from its actual pixel values
    rather than the compressed file bytes. This gives a true measure of the
    image's information content.
    
    Args:
        filepath: Path to the image file
    
    Returns:
        Entropy value (0.0 to 8.0) or None if calculation fails
    """
    try:
        from PIL import Image
        import numpy as np
        with Image.open(filepath) as img:
            # Limit to 512x512 sample for performance on large images
            img.thumbnail((512, 512))
            img = img.convert("RGB")
            pixels = np.array(img, dtype=np.uint8).flatten()
            counter = Counter(pixels.tolist())
            return calculate_entropy_from_counter(counter, len(pixels))
    except Exception:
        return None


def calculate_pdf_entropy(filepath):
    """
    Calculate entropy from PDF text content.
    
    Extracts the actual text from a PDF file and calculates entropy from
    the readable content, not the PDF structure bytes. This gives a better
    indication of whether the PDF contains meaningful text or hidden data.
    
    Args:
        filepath: Path to the PDF file
    
    Returns:
        Entropy value (0.0 to 8.0) or None if extraction fails
    """
    text = None
    try:
        from pdfminer.high_level import extract_text
        text = extract_text(filepath)
        if text and len(text.strip()) > 0:
            encoded = text.encode("utf-8", errors="ignore")
            return calculate_entropy_from_counter(Counter(encoded), len(encoded))
    except Exception:
        pass
    if not text:
        try:
            import pypdf
            reader = pypdf.PdfReader(filepath)
            parts  = [p.extract_text() or "" for p in reader.pages]
            text   = "\n".join(p for p in parts if p.strip())
            if text and len(text.strip()) > 50:
                encoded = text.encode("utf-8", errors="ignore")
                return calculate_entropy_from_counter(Counter(encoded), len(encoded))
        except Exception:
            pass
    try:
        with open(filepath, "rb") as f:
            data = f.read(8192)
        filtered = bytes(b for b in data if 32 <= b < 127 or b in (9, 10, 13))
        if len(filtered) > 50:
            counter = Counter(filtered)
            return calculate_entropy_from_counter(counter, len(filtered))
    except Exception:
        pass
    return None


def calculate_zip_entropy(filepath):
    """
    Calculate entropy from ZIP archive contents.
    
    Opens a ZIP file and calculates entropy from the decompressed contents
    of files inside. This reveals the true entropy of archived data rather
    than the compressed bytes. Prioritizes text content when available.
    
    Args:
        filepath: Path to the ZIP archive
    
    Returns:
        Entropy value (0.0 to 8.0) or None if calculation fails
    """
    try:
        import zipfile
        text_content, binary_entropy_sum, file_count = [], 0.0, 0
        with zipfile.ZipFile(filepath, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                try:
                    data = zf.read(info)
                    if not data:
                        continue
                    file_count += 1
                    text_exts = (".txt", ".csv", ".json", ".xml", ".html",
                                 ".md", ".log", ".py", ".js", ".java")
                    if any(info.filename.endswith(e) for e in text_exts):
                        try:
                            text_content.append(data.decode("utf-8", errors="ignore"))
                        except Exception:
                            pass
                    sample  = data[:min(1000, len(data))]
                    counter = Counter(sample)
                    binary_entropy_sum += calculate_entropy_from_counter(counter, len(sample))
                except Exception:
                    pass
        if text_content:
            combined = "\n".join(text_content)
            if len(combined) > 50:
                encoded  = combined.encode("utf-8", errors="ignore")
                text_ent = calculate_entropy_from_counter(Counter(encoded), len(encoded))
                if file_count > 1 and binary_entropy_sum > 0:
                    return round(0.7 * text_ent + 0.3 * (binary_entropy_sum / file_count), 4)
                return text_ent
        if file_count > 0 and binary_entropy_sum > 0:
            return round(binary_entropy_sum / file_count, 4)
    except Exception:
        pass
    return None


def calculate_ooxml_entropy(filepath):
    """
    Calculate entropy from Office Open XML documents (DOCX, XLSX, PPTX).
    
    These files are actually ZIP archives containing XML files. This function
    extracts the text content from the document.xml or sharedStrings.xml files
    inside and calculates entropy from the actual document content.
    
    Args:
        filepath: Path to the Office document
    
    Returns:
        Entropy value (0.0 to 8.0) or None if extraction fails
    """
    try:
        import zipfile, re
        text_parts = []
        with zipfile.ZipFile(filepath, "r") as zf:
            for name in zf.namelist():
                if name.endswith(".xml") and any(k in name for k in
                        ("word/", "xl/", "ppt/", "content", "document", "sheet", "slide")):
                    try:
                        raw   = zf.read(name).decode("utf-8", errors="ignore")
                        plain = re.sub(r"<[^>]+>", " ", raw)
                        plain = re.sub(r"\s+", " ", plain).strip()
                        text_parts.append(plain)
                    except Exception:
                        pass
        text = " ".join(text_parts)
        if text and len(text) > 50:
            encoded = text.encode("utf-8", errors="ignore")
            return calculate_entropy_from_counter(Counter(encoded), len(encoded))
    except Exception:
        pass
    return None


def calculate_ole_entropy(filepath):
    """
    Calculate entropy from legacy Office documents (DOC, XLS, PPT).
    
    Legacy Office files use the OLE2 format. This function uses the olefile
    library to extract text content and calculate entropy from the actual
    document data, not the binary OLE structure.
    
    Args:
        filepath: Path to the legacy Office document
    
    Returns:
        Entropy value (0.0 to 8.0) or None if extraction fails
    """
    try:
        import olefile
        ole = olefile.OleFileIO(filepath)
        text_parts = []
        for entry in ole.listdir():
            try:
                data      = ole.openstream("/".join(entry)).read()
                printable = bytes(b for b in data if 32 <= b < 127 or b in (9, 10, 13))
                if len(printable) > 20:
                    text_parts.append(printable)
            except Exception:
                pass
        ole.close()
        if text_parts:
            combined = b"".join(text_parts)
            return calculate_entropy_from_counter(Counter(combined), len(combined))
    except Exception:
        pass
    return None


def _get_entropy(filepath, file_type, real_ext, permission_readable,
                 byte_counter, total_bytes_read, first_chunk: bytes = b""):
    """
    Choose and execute the best entropy calculation method for a file type.
    
    This function routes to specialized entropy calculators based on file type:
    - Images: pixel-based entropy
    - PDFs: text content entropy  
    - Office/ZIP files: extracted content entropy
    - Other files: raw byte entropy
    
    Args:
        filepath: Path to the file
        file_type: File extension from filename
        real_ext: Actual file type from magic bytes
        permission_readable: Whether file can be read
        byte_counter: Counter of byte frequencies
        total_bytes_read: Total bytes read from file
        first_chunk: First bytes already read from file
    
    Returns:
        Entropy value (0.0 to 8.0)
    """
    if not permission_readable or total_bytes_read == 0:
        return 0.0

    ext = (real_ext or file_type or "").lower().strip().lstrip(".")

    if ext in ("jpg", "jpeg", "png", "bmp", "gif", "tif", "tiff", "webp"):
        result = calculate_pixel_entropy(filepath)
        if result is not None:
            return result

    # For PDFs, OOXML and ZIP-based formats, do content-aware extraction
    if ext == "pdf":
        result = calculate_pdf_entropy(filepath)
        if result is not None:
            return result

    if ext in ("docx", "xlsx", "pptx", "odt", "ods", "odp", "odg",
               "jar", "apk", "epub"):
        result = calculate_ooxml_entropy(filepath)
        if result is not None:
            return result

    if ext == "zip":
        result = calculate_zip_entropy(filepath)
        if result is not None:
            return result

    # Fallback: use the already-read first_chunk (up to 1 MB) if available
    if first_chunk:
        return calculate_entropy(first_chunk)

    # Last resort: re-open (should almost never happen)
    try:
        with open(filepath, "rb") as fh:
            raw = fh.read(1_048_576)
        if raw:
            return calculate_entropy(raw)
    except Exception:
        pass

    return calculate_entropy_from_counter(byte_counter, total_bytes_read)


# ─────────────────────────────────────────────────────────────────────────────
# METADATA HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _extract_author_windows(filepath):
    """
    Extract author metadata from a file using Windows shell properties.
    
    Uses Windows COM interface to read extended file properties like
    Author, Authors, or Creator. Only works on Windows systems.
    
    Args:
        filepath: Path to the file
    
    Returns:
        Author name string, or None if not found or not on Windows
    """
    if os.name != "nt":
        return None
    try:
        import win32com.client
        sh     = win32com.client.Dispatch("Shell.Application")
        folder = sh.NameSpace(os.path.dirname(os.path.abspath(filepath)))
        item   = folder.ParseName(os.path.basename(filepath))
        for i in range(300):
            name = folder.GetDetailsOf(None, i)
            if name in ("Authors", "Author", "Creator"):
                val = folder.GetDetailsOf(item, i)
                if val:
                    return val
        return folder.GetDetailsOf(item, 20)
    except Exception:
        return None


def _extract_author_pdf(file_bytes):
    """
    Extract author information from PDF file header.
    
    Searches the first 8KB of a PDF file for the /Author field which
    is part of the PDF document metadata dictionary.
    
    Args:
        file_bytes: First bytes of the PDF file
    
    Returns:
        Author name string, or None if not found
    """
    if file_bytes and b"/Author" in file_bytes[:8192]:
        try:
            idx   = file_bytes.find(b"/Author")
            start = file_bytes.find(b"(", idx)
            end   = file_bytes.find(b")", start)
            if start != -1 and end != -1:
                return file_bytes[start + 1:end].decode("utf-8", errors="ignore")
        except Exception:
            pass
    return None


def _extract_author_office(file_bytes):
    """
    Extract author from Office document XML metadata.
    
    Searches for the dc:creator XML tag in the first 8KB of Office
    documents (DOCX, XLSX, etc.) which stores the document author.
    
    Args:
        file_bytes: First bytes of the Office file
    
    Returns:
        Author name string, or None if not found
    """
    if file_bytes and b"dc:creator>" in file_bytes[:8192]:
        try:
            idx   = file_bytes.find(b"dc:creator>")
            start = idx + 11
            end   = file_bytes.find(b"</", start)
            if start != -1 and end != -1:
                return file_bytes[start:end].decode("utf-8", errors="ignore")
        except Exception:
            pass
    return None


def _extract_author_zip_office(filepath):
    """
    Extract author from Office document by reading core.xml from ZIP.
    
    Modern Office files are ZIP archives. This function extracts the
    core.xml file from inside which contains author and other metadata.
    
    Args:
        filepath: Path to the Office document (DOCX, XLSX, etc.)
    
    Returns:
        Author name string, or None if extraction fails
    """
    try:
        import zipfile, re
        with zipfile.ZipFile(filepath) as zf:
            if "docProps/core.xml" in zf.namelist():
                content = zf.read("docProps/core.xml").decode("utf-8", errors="ignore")
                m = re.search(r"<dc:creator[^>]*>(.*?)</dc:creator>", content, re.IGNORECASE)
                if m and m.group(1).strip():
                    return m.group(1).strip()
                m = re.search(r"<cp:lastModifiedBy[^>]*>(.*?)</cp:lastModifiedBy>",
                              content, re.IGNORECASE)
                if m and m.group(1).strip():
                    return m.group(1).strip()
            if "meta.xml" in zf.namelist():
                content = zf.read("meta.xml").decode("utf-8", errors="ignore")
                m = re.search(r"<meta:initial-creator[^>]*>(.*?)</meta:initial-creator>",
                              content, re.IGNORECASE)
                if m and m.group(1).strip():
                    return m.group(1).strip()
    except Exception:
        pass
    return None


def extract_author(filepath, file_bytes=b""):
    """
    Extract the author/creator of a file using multiple methods.
    
    Tries various methods in order: Windows properties, Office metadata,
    PDF metadata, and XML metadata. Returns the first author found.
    
    Args:
        filepath: Path to the file
        file_bytes: First bytes of the file for format detection
    
    Returns:
        Author name string, or "Unknown" if not found
    """
    author = _extract_author_windows(filepath)
    if not author:
        if file_bytes.startswith(b"PK\x03\x04"):
            author = _extract_author_zip_office(filepath)
        if not author:
            author = _extract_author_pdf(file_bytes) or _extract_author_office(file_bytes)
    return author.strip() if author else "Unknown"


def get_file_owner(filepath):
    """
    Get the file system owner of a file.
    
    Retrieves the user who owns the file according to the operating system.
    On Windows, uses security descriptors; on Unix/Linux, uses pwd module.
    
    Args:
        filepath: Path to the file
    
    Returns:
        Owner name string (format depends on OS), or "Unknown" on error
    """
    if os.name == "nt":
        try:
            import win32security
            sd        = win32security.GetFileSecurity(filepath, win32security.OWNER_SECURITY_INFORMATION)
            owner_sid = sd.GetSecurityDescriptorOwner()
            name, domain, _ = win32security.LookupAccountSid(None, owner_sid)
            return f"{domain}\\{name}"
        except Exception:
            return "Unknown"
    else:
        try:
            import pwd
            return pwd.getpwuid(os.stat(filepath).st_uid).pw_name
        except Exception:
            return "Unknown"


def get_source_and_url(filepath):
    """
    Determine where a file came from and its download URL.
    
    On Windows, checks the Zone.Identifier alternate data stream which
    Windows adds to files downloaded from the internet. Returns the source
    (Local or Internet) and the original download URL if available.
    
    Args:
        filepath: Path to the file
    
    Returns:
        Tuple of (source, url) where source is "Local" or "Internet"
    """
    source, url = "Local", "N/A"
    if os.name == "nt":
        zone_path = filepath + ":Zone.Identifier"
        if os.path.exists(zone_path):
            source = "Internet"
            try:
                with open(zone_path, "r", encoding="utf-8") as f:
                    for line in f.read().splitlines():
                        if line.startswith("HostUrl="):
                            url = line.split("=", 1)[1].strip() or url
            except Exception:
                pass
    return source, url


def get_permissions_string(filepath):
    """
    Get a human-readable string of file permissions.
    
    Checks if the current user has read, write, and execute permissions
    on the file and returns them in a readable format like "Read/Write".
    
    Args:
        filepath: Path to the file
    
    Returns:
        String like "Read/Write/Execute" or "None" or "Unknown"
    """
    try:
        perms = []

        # ── Read: try to actually open the file for reading ──────────────
        # Using actual file open is more reliable than os.access() for
        # detecting ACL-based "Deny" entries set via Windows Security tab.
        try:
            with open(filepath, "rb"):
                pass
            perms.append("Read")
        except (PermissionError, OSError):
            pass

        # ── Write: try to open for writing without changing content ──────
        # os.access(W_OK) is unreliable on Windows for ACL-based "Deny"
        # entries, especially when the process runs as Administrator.
        # Actually attempting to open the file is the only reliable check.
        try:
            with open(filepath, "r+b"):
                pass
            perms.append("Write")
        except (PermissionError, OSError):
            pass

        # ── Execute: use os.access(X_OK) ─────────────────────────────────
        # On Windows, os.access(X_OK) correctly reflects whether the current
        # user has execute rights on the file (e.g. full-control / owner).
        # Unlike Read/Write, ACL "Deny Execute" is rare and os.access is
        # sufficient here — it avoids incorrectly hiding Execute from
        # normal non-executable files like .txt or .jpg that the owner
        # has full control over.
        if os.access(filepath, os.X_OK):
            perms.append("Execute")

        return "/".join(perms) if perms else "None"
    except Exception:
        return "Unknown"


def update_permissions_in_db(db_path, filepath):
    """
    Re-read the live file permissions and update the database record.

    Because Windows does not update a file's 'Date Modified' when only the
    permissions are changed, the tool's cache (check_if_analyzed) can return
    a stale 'Read/Write/Execute' value even after the file was made read-only.
    This function bypasses the cache: it reads the actual current permissions
    from disk and writes them directly into every matching database row.

    Args:
        db_path:  Path to the forensic SQLite database.
        filepath: Absolute path to the file whose permissions to refresh.

    Returns:
        The freshly-read permissions string (e.g. "Read/Execute").
    """
    live_perms = get_permissions_string(filepath)
    abs_path   = os.path.abspath(filepath)
    try:
        conn   = get_db_connection(db_path)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE forensic_files SET permissions = ? WHERE filepath = ?",
            (live_perms, abs_path)
        )
        conn.commit()
        conn.close()
    except Exception:
        pass
    return live_perms


def is_hidden_file(filepath):
    """
    Check if a file is hidden.
    
    On Windows, checks the FILE_ATTRIBUTE_HIDDEN flag.
    On Unix/Linux, checks if filename starts with a dot.
    
    Args:
        filepath: Path to the file
    
    Returns:
        True if the file is hidden, False otherwise
    """
    if os.name == "nt":
        try:
            return bool(os.stat(filepath).st_file_attributes & stat.FILE_ATTRIBUTE_HIDDEN)
        except Exception:
            return False
    return os.path.basename(filepath).startswith(".")


def format_time(ts):
    """
    Convert a Unix timestamp to a formatted time string.
    
    Formats the timestamp showing both local time and UTC time.
    Returns an empty string if timestamp is None.
    
    Args:
        ts: Unix timestamp (seconds since epoch) or None
    
    Returns:
        Formatted string like "Local: 2024-01-15 10:30:00 | UTC: 2024-01-15 15:30:00"
    """
    if ts is None:
        return ""
    dt_utc   = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
    dt_local = dt_utc.astimezone()
    return (f"Local: {dt_local.strftime('%Y-%m-%d %H:%M:%S')} | "
            f"UTC: {dt_utc.strftime('%Y-%m-%d %H:%M:%S')}")


def check_virustotal(sha256_hash, api_key):
    """
    Query VirusTotal API for a file's reputation.
    
    Sends the SHA-256 hash to VirusTotal's API and retrieves how many
    antivirus engines flagged the file as malicious or suspicious.
    
    Args:
        sha256_hash: SHA-256 hash of the file to check
        api_key: VirusTotal API key
    
    Returns:
        String like "5/72" (5 detections out of 72 engines),
        or error message like "Not Found", "Rate Limited", "Invalid API Key"
    """
    if not api_key:
        return "N/A"
    # Also support env variable override
    api_key = os.environ.get("VT_API_KEY") or api_key
    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    try:
        req = urllib.request.Request(url, headers={"x-apikey": api_key})
        with urllib.request.urlopen(req, timeout=15) as response:
            stats      = json.loads(response.read().decode()).get(
                "data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious  = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            undetected = stats.get("undetected", 0)
            harmless   = stats.get("harmless", 0)
            total      = malicious + suspicious + undetected + harmless
            return f"{malicious}/{total}"
    except urllib.error.HTTPError as e:
        return {404: "Not Found", 401: "Invalid API Key", 429: "Rate Limited"}.get(
            e.code, f"Error {e.code}")
    except Exception:
        return "Error"


# ─────────────────────────────────────────────────────────────────────────────
# FILE TYPE DETECTION
# ─────────────────────────────────────────────────────────────────────────────

_PE_EXTENSIONS = {
    "exe", "dll", "sys", "scr", "ocx", "cpl",
    "ax", "acm", "drv", "mui", "efi",
}
_ELF_EXTENSIONS = {"elf", "so", "ko", "axf", "prx"}
_MACHO_EXTENSIONS = {"macho", "dylib", "bundle", "o", "kext"}


def _check_zip_contents(filepath, default_ext="zip", default_desc="ZIP Archive"):
    """
    Determine the actual content type of a ZIP archive.
    
    ZIP files can contain many types of data. This function checks for
    specific file signatures inside the ZIP to identify Office documents,
    Android APKs, JAR files, EPUBs, and LibreOffice formats.
    
    Args:
        filepath: Path to the ZIP file
        default_ext: Default extension if type can't be determined
        default_desc: Default description if type can't be determined
    
    Returns:
        Tuple of (extension, description) for the actual content type
    """
    try:
        import zipfile
        with zipfile.ZipFile(filepath, "r") as zf:
            names = set(zf.namelist())

            if ("ppt/presentation.xml" in names or
                    any(n.startswith("ppt/") for n in names)):
                return "pptx", "Microsoft PowerPoint Presentation (PPTX)"

            if ("xl/workbook.xml" in names or
                    any(n.startswith("xl/") for n in names)):
                return "xlsx", "Microsoft Excel Spreadsheet (XLSX)"

            if ("word/document.xml" in names or
                    any(n.startswith("word/") for n in names)):
                return "docx", "Microsoft Word Document (DOCX)"

            if "AndroidManifest.xml" in names and "classes.dex" in names:
                return "apk", "Android Package (APK)"

            if ("BundleConfig.pb" in names or
                    "base/manifest/AndroidManifest.xml" in names):
                return "aab", "Android App Bundle (AAB)"

            if "META-INF/MANIFEST.MF" in names:
                return "jar", "Java Archive (JAR)"

            if ("OEBPS/content.opf" in names or
                    "META-INF/container.xml" in names):
                return "epub", "EPUB Electronic Book"

            if "content.xml" in names and "meta.xml" in names:
                try:
                    import re
                    content = zf.read("content.xml").decode("utf-8", errors="ignore")
                    if "office:document" in content:
                        if "presentation" in content or "draw:page" in content:
                            return "odp", "LibreOffice Impress Presentation"
                        if "table:"  in content:
                            return "ods", "LibreOffice Calc Spreadsheet"
                        if "draw:"   in content:
                            return "odg", "LibreOffice Draw Document"
                        if "text:"   in content:
                            return "odt", "LibreOffice Writer Document"
                except Exception:
                    pass

    except Exception:
        pass

    return default_ext, default_desc


def _refine_ole(head):
    """
    Identify the specific Office document type from OLE file header.
    
    Legacy Office files (DOC, XLS, PPT, MSG) all use the same OLE2 format
    header but have different internal signatures. This function reads the
    bytes at offset 512 to determine the specific document type.
    
    Args:
        head: First bytes of the file (at least 516 bytes)
    
    Returns:
        Tuple of (extension, description) for the specific Office type
    """
    if len(head) >= 516:
        sub = head[512:516]
        if sub[:2] == b"\xec\xa5":
            return "doc", "Microsoft Word Document"
        if sub[:4] == b"\x09\x08":
            return "xls", "Microsoft Excel Spreadsheet"
        if sub[:4] in (b"\x00\x6e", b"\xa0\x46"):
            return "ppt", "Microsoft PowerPoint Presentation"
        if sub[:4] == b"\xfd\xff":
            return "msg", "Microsoft Outlook Message"
    return "ole", "MS Office OLE2 Document"


def _determine_file_type(permission_readable, file_size, file_head,
                          magic_bits, file_type, filepath, signatures,
                          known_binary_exts=None):
    """
    Determine the true file type using magic bytes and content analysis.
    
    This is the main file type identification function. It uses magic byte
    signatures, file headers, and content analysis to determine what a file
    actually is, regardless of its extension.
    
    Args:
        permission_readable: Whether file can be read
        file_size: Size of the file in bytes
        file_head: First bytes of the file
        magic_bits: Hex string of first 4 bytes
        file_type: Claimed file extension
        filepath: Full path to the file
        signatures: List of file signature definitions
        known_binary_exts: Dictionary of known binary extensions
    
    Returns:
        Tuple of (extension, description) for the actual file type
    """
    if known_binary_exts is None:
        known_binary_exts = {}

    if not permission_readable:
        return "unknown", "Cannot read file (Permission Denied)"
    if file_size == 0:
        return "empty", "Empty File"

    head = file_head

    declared = (file_type or "").lower().strip().lstrip(".")

    if len(head) >= 12 and head[4:8] == b"ftyp":
        brand = head[8:12]
        FTYP_MAP = {
            b"isom": ("mp4",  "MP4 Video (ISO Base Media)"),
            b"MSNV": ("mp4",  "MP4 Video (MSNV)"),
            b"mp42": ("m4v",  "MPEG-4 Video (mp42)"),
            b"M4V ": ("m4v",  "Apple M4V Video"),
            b"M4A ": ("m4a",  "Apple M4A Lossless Audio"),
            b"qt  ": ("mov",  "QuickTime Movie"),
            b"3gp5": ("3gp",  "3GPP Media"),
            b"3gp6": ("3gp",  "3GPP Media"),
            b"3g2a": ("3g2",  "3GPP2 Media"),
            b"heic": ("heic", "High Efficiency Image (HEIC)"),
            b"heix": ("heic", "High Efficiency Image (HEIC)"),
            b"avif": ("avif", "AV1 Image (AVIF)"),
            b"mif1": ("heic", "Multi-Image HEIF"),
            b"f4v ": ("f4v",  "Adobe Flash Video (F4V)"),
            b"f4a ": ("m4a",  "Adobe Flash Audio"),
        }
        for key, val in FTYP_MAP.items():
            if brand[:len(key)] == key:
                return val
        return "mp4", "MP4/MOV/M4A Media (ftyp)"

    if len(head) >= 12 and head[:4] == b"RIFF":
        sub = head[8:12]
        RIFF_MAP = {
            b"WAVE": ("wav",  "WAV Audio"),
            b"AVI ": ("avi",  "AVI Video"),
            b"WEBP": ("webp", "WebP Image"),
            b"ANI ": ("ani",  "Windows Animated Cursor"),
            b"CDDA": ("cda",  "CD Digital Audio"),
            b"QLCM": ("qcp",  "Qualcomm PureVoice Audio"),
            b"RMID": ("rmi",  "RIFF MIDI Audio"),
        }
        if sub in RIFF_MAP:
            return RIFF_MAP[sub]
        return "riff", "RIFF Container"

    if len(head) >= 132 and head[128:132] == b"DICM":
        return "dcm", "DICOM Medical Image"

    if len(head) >= 262 and head[257:262] == b"ustar":
        return "tar", "TAR Archive"

    for sig in signatures:
        b   = sig["bytes"]
        off = sig["offset"]
        if not (len(head) >= off + len(b) and head[off:off + len(b)] == b):
            continue

        sig_ext  = sig["ext"]
        sig_desc = sig["desc"]

        sig_len = len(sig["bytes"])
        if sig_len < 4 and sig_ext != declared:
            continue

        if sig_ext == "exe" and head[:2] == b"MZ":
            if declared in _PE_EXTENSIONS:
                desc_map = {
                    "exe":  "Windows Executable (PE)",
                    "dll":  "Dynamic Link Library (PE)",
                    "sys":  "Windows System Driver (PE)",
                    "scr":  "Windows Screensaver (PE)",
                    "ocx":  "OLE Control Extension (PE)",
                    "cpl":  "Windows Control Panel Applet (PE)",
                    "ax":   "DirectShow Filter (PE)",
                    "acm":  "Audio Compression Manager Driver (PE)",
                    "drv":  "Windows Device Driver (PE)",
                    "mui":  "Multilingual UI Resource (PE)",
                    "efi":  "Extensible Firmware Interface Binary (PE)",
                }
                return declared, desc_map.get(declared, f"{declared.upper()} PE Binary")
            return "exe", "Windows/DOS Executable (MZ)"

        if sig_ext == "elf" and head[:4] == b"\x7fELF":
            if declared in _ELF_EXTENSIONS:
                desc_map = {
                    "elf": "ELF Executable (Linux/Unix)",
                    "so":  "Shared Library (ELF)",
                    "ko":  "Linux Kernel Module (ELF)",
                    "axf": "ARM Executable (ELF)",
                    "prx": "PlayStation Portable Module (ELF)",
                }
                return declared, desc_map.get(declared, f"{declared.upper()} ELF Binary")
            return "elf", "ELF Executable (Linux/Unix)"

        if sig_ext == "macho" and head[:4] in (
                b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
            if declared in _MACHO_EXTENSIONS:
                desc_map = {
                    "macho":  "Mach-O Binary",
                    "dylib":  "Dynamic Library (Mach-O)",
                    "bundle": "macOS Bundle (Mach-O)",
                    "o":      "Object File (Mach-O)",
                    "kext":   "macOS Kernel Extension (Mach-O)",
                }
                return declared, desc_map.get(declared, f"{declared.upper()} Mach-O Binary")
            return "macho", "Mach-O Binary (macOS)"

        _ZIP_MAGIC  = b"PK\x03\x04"
        _ZIP_FAMILY = {"zip", "docx", "xlsx", "pptx", "odt", "ods", "odp",
                       "odg", "jar", "apk", "epub", "aab", "war", "aar", "xpi"}
        if (sig_ext in _ZIP_FAMILY or b[:4] == _ZIP_MAGIC) and filepath:
            return _check_zip_contents(filepath, "zip", "ZIP Archive")

        if sig_ext == "ole":
            return _refine_ole(head)

        return sig_ext, sig_desc

    try:
        sample   = head[:1024]
        sample.decode("utf-8", errors="strict")
        stripped = sample.lstrip(b"\xef\xbb\xbf")
        if stripped.startswith(b"<?xml") or \
           (stripped.strip().startswith(b"<") and b">" in stripped[:200]):
            return "xml", "XML Document"
        if stripped.strip()[:9].lower() == b"<!doctype" or \
           stripped.strip().lower().startswith(b"<html"):
            return "html", "HTML Document"
        TEXT_EXTS = {"txt", "json", "csv", "log", "md", "css", "js", "py",
                     "ini", "bat", "ps1", "sh", "c", "cpp", "h", "java",
                     "sql", "rb", "go", "yaml", "toml", "cfg", "conf"}
        if declared in TEXT_EXTS:
            return declared, f"{declared.upper()} Text Document"
        return "txt", "ASCII/UTF-8 Text Document"
    except (UnicodeDecodeError, AttributeError):
        pass

    if declared and declared in known_binary_exts:
        return declared, known_binary_exts[declared]

    return "unknown", "Unknown Binary Format"


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ANALYSIS FUNCTION  (single-pass hashing + no double file-read)
# ─────────────────────────────────────────────────────────────────────────────

def analyze_file(filepath, signatures, progress_callback=None,
                 vt_api_key=None, known_binary_exts=None, db_path=None, **kwargs):
    """
    Analyze a single file and extract all forensic metadata.
    
    This is the main analysis function that performs comprehensive forensic
    analysis on a file. It reads the file once and extracts:
    - File hashes (SHA-256)
    - File type identification using magic bytes
    - Entropy analysis
    - Metadata (author, owner, timestamps, permissions)
    - Internet source information
    - VirusTotal reputation (if API key provided)
    
    The function is optimized to read the file only once for all operations.
    
    Args:
        filepath: Path to the file to analyze
        signatures: List of file signature definitions for type detection
        progress_callback: Optional function called with (bytes_read, total_bytes)
        vt_api_key: Optional VirusTotal API key for reputation check
        known_binary_exts: Dictionary of known binary file extensions
        db_path: Database path for checking previous records
    
    Returns:
        Dictionary containing all forensic metadata for the file
    """
    if known_binary_exts is None:
        known_binary_exts = {}

    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    stat_info = os.stat(filepath)
    filename  = os.path.basename(filepath)
    file_size = stat_info.st_size
    _, ext    = os.path.splitext(filename)
    file_type = ext.lstrip(".").lower() if ext else "unknown"

    # ── Single-pass: hash SHA-256 + byte frequency + first chunk ──
    sha256_h         = hashlib.sha256()
    byte_counter     = Counter()
    total_bytes_read = 0
    file_head        = b""
    magic_bits       = ""
    permission_readable = False

    CHUNK_SIZE = 65536
    HEAD_SIZE  = 8192

    try:
        with open(filepath, "rb") as f:
            permission_readable = True
            first_chunk_done    = False
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                sha256_h.update(chunk)
                byte_counter.update(chunk)
                total_bytes_read += len(chunk)
                if not first_chunk_done:
                    file_head  = chunk[:HEAD_SIZE]
                    magic_bits = (chunk[:4].hex().upper()
                                  if len(chunk) >= 4 else chunk.hex().upper())
                    first_chunk_done = True
                if progress_callback and file_size > 0:
                    progress_callback(total_bytes_read, file_size)
    except PermissionError:
        magic_bits = "ACCESS_DENIED"

    sha256_hash = sha256_h.hexdigest() if permission_readable else ""

    real_ext, real_desc = _determine_file_type(
        permission_readable, file_size, file_head,
        magic_bits, file_type, filepath, signatures,
        known_binary_exts=known_binary_exts
    )

    # Pass file_head to avoid second file open
    entropy = _get_entropy(filepath, file_type, real_ext,
                           permission_readable, byte_counter, total_bytes_read,
                           first_chunk=file_head)

    entropy_class = classify_entropy(entropy, real_ext)

    source_of_file, download_url = get_source_and_url(filepath)

    # ── Preserve Internet provenance across re-analyses ──────────────────────
    # Windows Zone.Identifier ADS is stripped by most editors when a file is
    # saved after modification. If a previous scan recorded source="Internet"
    # but the current file no longer has a Zone.Identifier (source=="Local"),
    # we inherit the original provenance so the forensic record stays accurate.
    if source_of_file == "Local":
        try:
            prev = get_latest_record_by_filename(db_path, filename)
            if prev and prev.get("source_of_file") == "Internet":
                source_of_file = "Internet"
                # Keep the stored download URL if we don't have a new one
                stored_url = prev.get("download_url") or "N/A"
                if download_url in ("N/A", "", None):
                    download_url = stored_url
        except Exception:
            pass


    vt_score = "N/A"
    if sha256_hash and vt_api_key:
        vt_score = check_virustotal(sha256_hash, vt_api_key)

    return {
        "filename":               filename,
        "filepath":               os.path.abspath(filepath),
        "file_size":              file_size,
        "file_type":              file_type,
        "created_time":           format_time(stat_info.st_ctime),
        "modified_time":          format_time(stat_info.st_mtime),
        "accessed_time":          format_time(stat_info.st_atime),
        "sha256_hash":            sha256_hash,
        "author":                 extract_author(filepath, file_head),
        "owner":                  get_file_owner(filepath),
        "source_of_file":         source_of_file,
        "download_url":           download_url,
        "permissions":            get_permissions_string(filepath),
        "is_hidden":              is_hidden_file(filepath),
        "entropy":                entropy,
        "entropy_classification": entropy_class,
        "magic_bits":             magic_bits,
        "real_file_extension":    real_ext,
        "real_file_description":  real_desc,
        "analyzed_at":            format_time(
            datetime.datetime.now(datetime.timezone.utc).timestamp()),
        "vt_score":               vt_score,
    }


# ─────────────────────────────────────────────────────────────────────────────
# DATABASE OPERATIONS
# ─────────────────────────────────────────────────────────────────────────────

def save_analysis(db_path, data):
    """
    Save a file analysis result to the forensic database.
    
    Inserts a new record into the forensic_files table with all metadata
    extracted from a file analysis. This includes file info, hashes, 
    entropy, metadata, and VirusTotal score.
    
    Args:
        db_path: Path to the forensic database
        data: Dictionary containing all file analysis data
    """
    conn   = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO forensic_files (
            filename, filepath, file_size, file_type,
            created_time, modified_time, accessed_time,
            sha256_hash,
            author, owner, source_of_file, download_url,
            permissions, is_hidden, entropy,
            magic_bits, real_file_extension, real_file_description,
            analyzed_at, vt_score
        ) VALUES (
            :filename, :filepath, :file_size, :file_type,
            :created_time, :modified_time, :accessed_time,
            :sha256_hash,
            :author, :owner, :source_of_file, :download_url,
            :permissions, :is_hidden, :entropy,
            :magic_bits, :real_file_extension, :real_file_description,
            :analyzed_at, :vt_score
        )
    ''', data)
    conn.commit()
    conn.close()


def update_vt_score(db_path, record_id, score):
    """
    Update the VirusTotal score for an existing record.
    
    After fetching a VirusTotal score for a file, this function updates
    the vt_score field in the database for the specified record.
    
    Args:
        db_path: Path to the forensic database
        record_id: Database ID of the record to update
        score: VirusTotal score string (e.g., "5/72")
    """
    conn   = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("UPDATE forensic_files SET vt_score = ? WHERE id = ?",
                   (score, record_id))
    conn.commit()
    conn.close()


def check_if_analyzed(db_path, filepath):
    """
    Check if a file has already been analyzed with current modification time.
    
    Used to determine if a file needs re-analysis. Checks if the file exists
    in the database with the same modification timestamp.
    
    Args:
        db_path: Path to the forensic database
        filepath: Path to the file to check
    
    Returns:
        Database row if file was analyzed with same mtime, None otherwise
    """
    mtime  = format_time(os.path.getmtime(filepath))
    conn   = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, vt_score FROM forensic_files WHERE filepath = ? AND modified_time = ?",
        (os.path.abspath(filepath), mtime)
    )
    result = cursor.fetchone()
    conn.close()
    return result


def clear_database(db_path="forensic_data.db"):
    """
    Delete all records from the forensic database.
    
    Completely clears all analysis records and integrity checks from the
    database. Use with caution - this cannot be undone.
    
    Args:
        db_path: Path to the forensic database
    """
    conn   = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM forensic_files")
    cursor.execute("DELETE FROM sqlite_sequence WHERE name='forensic_files'")
    cursor.execute("DELETE FROM integrity_checks")
    cursor.execute("DELETE FROM sqlite_sequence WHERE name='integrity_checks'")
    conn.commit()
    conn.close()


def get_latest_record_by_filename(db_path: str, filename: str) -> dict:
    """
    Get the most recent analysis record for a specific filename.
    
    Retrieves the latest forensic analysis record for a given filename,
    ordered by database ID (newest first). Used to check file history
    and detect changes.
    
    Args:
        db_path: Path to the forensic database
        filename: Name of the file to look up
    
    Returns:
        Dictionary with record data, or None if no record exists
    """
    conn   = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM forensic_files WHERE filename = ? ORDER BY id DESC LIMIT 1",
        (filename,)
    )
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_records(db_path="forensic_data.db"):
    """
    Retrieve all file analysis records from the database.
    
    Gets all forensic analysis records ordered by ID descending (newest first).
    Used to populate the main file list in the UI.
    
    Args:
        db_path: Path to the forensic database
    
    Returns:
        List of dictionaries containing all analysis records
    """
    conn   = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM forensic_files ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def log_activity(action, details="", db_path="activity_logs.db"):
    """
    Log an action to the activity logs database.
    
    Records an audit trail entry with timestamp, action type, and details.
    Used to track all operations performed in the application.
    
    Args:
        action: Type of action performed (e.g., "ANALYZE_FILE", "EXPORT_PDF")
        details: Additional details about the action
        db_path: Path to the activity logs database
    """
    conn      = get_db_connection(db_path)
    cursor    = conn.cursor()
    timestamp = datetime.datetime.now(datetime.timezone.utc).astimezone().strftime(
        "%Y-%m-%d %H:%M:%S")
    cursor.execute(
        "INSERT INTO activity_logs (timestamp, action, details) VALUES (?, ?, ?)",
        (timestamp, action, details)
    )
    conn.commit()
    conn.close()


def get_activity_logs(db_path="activity_logs.db"):
    """
    Retrieve all activity log records.
    
    Gets all audit trail entries ordered by ID descending (newest first).
    Used to display the activity history in the UI.
    
    Args:
        db_path: Path to the activity logs database
    
    Returns:
        List of dictionaries containing all activity log entries
    """
    conn   = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM activity_logs ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def clear_activity_logs(db_path="activity_logs.db"):
    """
    Clear all activity logs while maintaining an audit trail.
    
    Deletes all records from the activity_logs table but inserts a new
    record documenting that the logs were cleared. This maintains an
    audit trail even after clearing.
    
    Args:
        db_path: Path to the activity logs database
    """
    conn   = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM activity_logs")
    cursor.execute("DELETE FROM sqlite_sequence WHERE name='activity_logs'")
    # Re-insert a record that the logs were cleared (audit trail)
    timestamp = datetime.datetime.now(datetime.timezone.utc).astimezone().strftime(
        "%Y-%m-%d %H:%M:%S")
    cursor.execute(
        "INSERT INTO activity_logs (timestamp, action, details) VALUES (?, ?, ?)",
        (timestamp, "LOGS_CLEARED", "All previous activity logs were deleted by user")
    )
    conn.commit()
    conn.close()
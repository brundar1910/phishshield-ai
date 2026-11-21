"""Database connection and query handling for scan logs and security analytics."""

import sqlite3
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
DB_PATH = ROOT_DIR / "phishing_detector.db"


def init_db(db_path: Path = DB_PATH):
    """Initializes and migrates the SQLite database schema if necessary."""
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL DEFAULT '',
            is_phishing INTEGER NOT NULL DEFAULT 0,
            threat_level TEXT NOT NULL DEFAULT 'LOW',
            confidence REAL NOT NULL DEFAULT 0.0,
            heuristic_flags TEXT DEFAULT '',
            scan_timestamp TEXT NOT NULL,
            scan_type TEXT NOT NULL DEFAULT 'url',
            target TEXT NOT NULL DEFAULT '',
            risk_score INTEGER NOT NULL DEFAULT 0,
            verdict TEXT NOT NULL DEFAULT 'LOW',
            explanation TEXT DEFAULT ''
        )
    """)

    cursor.execute("PRAGMA table_info(scan_logs)")
    columns = [row[1] for row in cursor.fetchall()]

    if "url" not in columns:
        cursor.execute("ALTER TABLE scan_logs ADD COLUMN url TEXT NOT NULL DEFAULT ''")
    if "is_phishing" not in columns:
        cursor.execute("ALTER TABLE scan_logs ADD COLUMN is_phishing INTEGER NOT NULL DEFAULT 0")
    if "threat_level" not in columns:
        cursor.execute("ALTER TABLE scan_logs ADD COLUMN threat_level TEXT NOT NULL DEFAULT 'LOW'")
    if "scan_type" not in columns:
        cursor.execute("ALTER TABLE scan_logs ADD COLUMN scan_type TEXT NOT NULL DEFAULT 'url'")
    if "target" not in columns:
        cursor.execute("ALTER TABLE scan_logs ADD COLUMN target TEXT NOT NULL DEFAULT ''")
    if "risk_score" not in columns:
        cursor.execute("ALTER TABLE scan_logs ADD COLUMN risk_score INTEGER NOT NULL DEFAULT 0")
    if "verdict" not in columns:
        cursor.execute("ALTER TABLE scan_logs ADD COLUMN verdict TEXT NOT NULL DEFAULT 'LOW'")
    if "explanation" not in columns:
        cursor.execute("ALTER TABLE scan_logs ADD COLUMN explanation TEXT DEFAULT ''")

    conn.commit()
    conn.close()


def log_scan(
    scan_type: str,
    target: str,
    risk_score: int,
    verdict: str,
    confidence: float,
    explanation: str,
    heuristic_flags: List[str],
    db_path: Path = DB_PATH,
) -> int:
    """Logs a completed scan result to the database."""
    init_db(db_path)
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    flags_str = "; ".join(heuristic_flags) if isinstance(heuristic_flags, list) else str(heuristic_flags or "")
    now_str = datetime.utcnow().isoformat()
    clean_target = str(target or "")
    is_phish = 1 if str(verdict).upper() in ["HIGH", "CRITICAL", "PHISHING"] else 0

    cursor.execute(
        """
        INSERT INTO scan_logs (url, scan_type, target, is_phishing, threat_level, risk_score, verdict, confidence, explanation, heuristic_flags, scan_timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (clean_target, scan_type, clean_target, is_phish, verdict, int(risk_score), verdict, float(confidence), explanation, flags_str, now_str),
    )
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def get_recent_scans(limit: int = 50, scan_type: Optional[str] = None, db_path: Path = DB_PATH) -> List[Dict[str, Any]]:
    """Retrieves recent scan records, optionally filtered by scan_type."""
    init_db(db_path)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    if scan_type:
        cursor.execute(
            """
            SELECT id, url, scan_type, target, risk_score, verdict, confidence, explanation, heuristic_flags, scan_timestamp
            FROM scan_logs
            WHERE scan_type = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (scan_type, limit),
        )
    else:
        cursor.execute(
            """
            SELECT id, url, scan_type, target, risk_score, verdict, confidence, explanation, heuristic_flags, scan_timestamp
            FROM scan_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )

    rows = cursor.fetchall()
    results = [dict(row) for row in rows]
    conn.close()
    return results


def get_scan_stats(db_path: Path = DB_PATH) -> Dict[str, Any]:
    """Computes aggregated metrics and security statistics from database logs."""
    init_db(db_path)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*), AVG(risk_score) FROM scan_logs")
    count_row = cursor.fetchone()
    total_scans = count_row[0] or 0
    avg_score = round(float(count_row[1] or 0.0), 1)

    # Verdict breakdown
    cursor.execute("SELECT verdict, COUNT(*) FROM scan_logs GROUP BY verdict")
    verdict_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for row in cursor.fetchall():
        v = (row[0] or "").upper()
        if v in verdict_counts:
            verdict_counts[v] += row[1]
        elif v == "SAFE":
            verdict_counts["LOW"] += row[1]
        elif v == "SUSPICIOUS":
            verdict_counts["MEDIUM"] += row[1]
        elif v == "PHISHING":
            verdict_counts["CRITICAL"] += row[1]

    # Scan types breakdown
    cursor.execute("SELECT scan_type, COUNT(*) FROM scan_logs GROUP BY scan_type")
    scan_type_counts = {"url": 0, "email": 0, "html": 0, "image": 0}
    for row in cursor.fetchall():
        t = (row[0] or "").lower()
        if t in scan_type_counts:
            scan_type_counts[t] += row[1]

    # Top heuristic flags
    cursor.execute("SELECT heuristic_flags FROM scan_logs WHERE heuristic_flags != ''")
    flag_counter = Counter()
    for row in cursor.fetchall():
        flags = [f.strip() for f in (row[0] or "").split(";") if f.strip()]
        flag_counter.update(flags)

    top_flags = [{"flag": flag, "count": count} for flag, count in flag_counter.most_common(5)]

    conn.close()
    return {
        "total_scans": total_scans,
        "verdicts": verdict_counts,
        "scan_types": scan_type_counts,
        "average_risk_score": avg_score,
        "top_heuristic_flags": top_flags,
    }


# Auto-initialize
init_db()

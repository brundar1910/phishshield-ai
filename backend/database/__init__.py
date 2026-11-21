"""Database persistence layer."""
from .db import init_db, log_scan, get_recent_scans

__all__ = ["init_db", "log_scan", "get_recent_scans"]

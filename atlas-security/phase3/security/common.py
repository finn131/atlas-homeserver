"""
Shared utilities for Atlas Security Observatory.
Database helpers, logging setup, graceful shutdown.
"""
import sqlite3
import signal
import logging
from contextlib import contextmanager
from typing import Generator


def setup_logging(name: str, level: str = "INFO", log_file: str = None) -> logging.Logger:
    """Configure structured logging for a daemon."""
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))
    fmt = logging.Formatter(
        "%(asctime)s [%(name)s] %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler = logging.StreamHandler()
    handler.setFormatter(fmt)
    logger.addHandler(handler)
    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    return logger


@contextmanager
def get_db(
    db_path: str,
    wal_mode: bool = True,
    busy_timeout_ms: int = 5000,
    read_only: bool = False,
) -> Generator[sqlite3.Connection, None, None]:
    """
    Context manager for SQLite connections.
    Enables WAL mode, sets busy timeout, ensures clean close.
    """
    uri = f"file:{db_path}"
    if read_only:
        uri += "?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=busy_timeout_ms / 1000)
    conn.row_factory = sqlite3.Row
    if wal_mode and not read_only:
        conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
    try:
        yield conn
        if not read_only:
            conn.commit()
    except Exception:
        if not read_only:
            conn.rollback()
        raise
    finally:
        conn.close()


class GracefulShutdown:
    """Handle SIGTERM/SIGINT for clean daemon shutdown."""

    def __init__(self):
        self.should_stop = False
        signal.signal(signal.SIGTERM, self._handler)
        signal.signal(signal.SIGINT, self._handler)

    def _handler(self, signum, frame):
        self.should_stop = True

#!/usr/bin/env python3
"""
Atlas Security Observatory — Phase 7 Schema Migration

Adds notification_queue and incident_notes tables.
Non-destructive: only creates tables if they don't exist.
"""
import sqlite3
import sys

DB_PATH = "/opt/atlas/security.db"

MIGRATION_SQL = """
-- Notification queue: decouples alert creation from notification delivery
CREATE TABLE IF NOT EXISTS notification_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER REFERENCES alerts(id),
    channel TEXT NOT NULL DEFAULT 'ntfy',
    status TEXT NOT NULL DEFAULT 'pending',
    payload TEXT NOT NULL,
    error_message TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    sent_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_notif_queue_status ON notification_queue(status);
CREATE INDEX IF NOT EXISTS idx_notif_queue_created ON notification_queue(created_at);

-- Incident notes: analyst notes attached to incidents
CREATE TABLE IF NOT EXISTS incident_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES incidents(id),
    note TEXT NOT NULL,
    author TEXT NOT NULL DEFAULT 'system',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_incident_notes_incident ON incident_notes(incident_id);
"""


def migrate(db_path: str = DB_PATH) -> bool:
    """Run migration. Returns True if tables were created."""
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row

        existing = {
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }

        if "notification_queue" in existing and "incident_notes" in existing:
            print("Phase 7 tables already exist, skipping migration.")
            conn.close()
            return False

        conn.executescript(MIGRATION_SQL)
        conn.close()
        print("Phase 7 migration complete: notification_queue + incident_notes created.")
        return True

    except Exception as e:
        print(f"Migration failed: {e}", file=sys.stderr)
        return False


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else DB_PATH
    success = migrate(path)
    sys.exit(0 if success else 1)

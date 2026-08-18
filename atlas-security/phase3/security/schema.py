"""
SQLite schema definitions for Atlas Security Observatory.
Includes events, detections, incidents, alerts, and remediation log.
"""
import sqlite3

SCHEMA_VERSION = 1

SCHEMA_DDL = """
-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Normalized security events
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    hostname TEXT NOT NULL,
    source TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info',
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    username TEXT,
    process TEXT,
    message TEXT,
    raw_log TEXT,
    correlation_id TEXT,
    metadata_json TEXT,
    collected_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Detection findings (rule-based, each detection references events)
CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 0.0,
    hostname TEXT NOT NULL,
    src_ip TEXT,
    explanation TEXT NOT NULL,
    related_event_ids TEXT,
    evidence TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Incidents: first-class model aggregating detections + related events
-- This becomes the primary input for the future AI Analyst
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    summary TEXT,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    src_ip TEXT,
    started_at TEXT NOT NULL,
    last_updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    detection_ids TEXT NOT NULL DEFAULT '[]',
    event_ids TEXT NOT NULL DEFAULT '[]',
    evidence_summary TEXT NOT NULL DEFAULT '{}',
    explanation TEXT,
    confidence REAL NOT NULL DEFAULT 0.0,
    resolution TEXT,
    resolved_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Alert lifecycle management (alerts reference incidents or detections)
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER REFERENCES incidents(id),
    detection_id INTEGER REFERENCES detections(id),
    status TEXT NOT NULL DEFAULT 'new',
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    src_ip TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    acknowledged_at TEXT,
    resolved_at TEXT
);

-- Remediation actions log (future use, human-approved)
CREATE TABLE IF NOT EXISTS remediation_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER REFERENCES incidents(id),
    alert_id INTEGER REFERENCES alerts(id),
    action_type TEXT NOT NULL,
    action_details TEXT,
    result TEXT,
    performed_at TEXT NOT NULL DEFAULT (datetime('now')),
    performed_by TEXT NOT NULL DEFAULT 'system'
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_collected_at ON events(collected_at);

CREATE INDEX IF NOT EXISTS idx_detections_timestamp ON detections(timestamp);
CREATE INDEX IF NOT EXISTS idx_detections_rule_name ON detections(rule_name);
CREATE INDEX IF NOT EXISTS idx_detections_severity ON detections(severity);
CREATE INDEX IF NOT EXISTS idx_detections_src_ip ON detections(src_ip);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_started_at ON incidents(started_at);
CREATE INDEX IF NOT EXISTS idx_incidents_src_ip ON incidents(src_ip);

CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_incident_id ON alerts(incident_id);

CREATE INDEX IF NOT EXISTS idx_remediation_log_incident_id ON remediation_log(incident_id);

-- Event types reference
CREATE TABLE IF NOT EXISTS event_types (
    event_type TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    description TEXT NOT NULL
);

INSERT OR IGNORE INTO event_types VALUES
    ('ssh_auth_fail',       'journald',    'SSH authentication failure'),
    ('ssh_auth_success',    'journald',    'SSH authentication success'),
    ('ssh_session_open',    'journald',    'SSH session opened'),
    ('ssh_session_close',   'journald',    'SSH session closed'),
    ('nginx_4xx',           'nginx',       'NGINX 4xx response'),
    ('nginx_5xx',           'nginx',       'NGINX 5xx response'),
    ('nginx_error',         'nginx',       'NGINX error log entry'),
    ('nft_drop',            'nftables',    'nftables packet drop'),
    ('fail2ban_ban',        'fail2ban',    'Fail2Ban IP ban'),
    ('fail2ban_unban',      'fail2ban',    'Fail2Ban IP unban'),
    ('fail2ban_jail',       'fail2ban',    'Fail2Ban jail activation'),
    ('service_start',       'journald',    'Systemd service started'),
    ('service_stop',        'journald',    'Systemd service stopped'),
    ('service_failed',      'journald',    'Systemd service failed'),
    ('service_restart',     'journald',    'Systemd service restarted'),
    ('kernel_security',     'kernel',      'Kernel security message');
"""


def init_schema(conn: sqlite3.Connection) -> None:
    """Apply schema DDL to a fresh database."""
    conn.executescript(SCHEMA_DDL)
    conn.execute(
        "INSERT OR IGNORE INTO schema_version (version) VALUES (?)",
        (SCHEMA_VERSION,),
    )
    conn.commit()


def ensure_schema(db_path: str) -> None:
    """Create database and schema if they don't exist."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='events'"
    )
    if cursor.fetchone() is None:
        init_schema(conn)
    conn.close()

"""
Atlas Security Observatory — Detection Engine

Runs as an internal polling loop within the collector process.
Reads new events from SQLite, applies rule-based detection,
writes detections, incidents, and alerts.
Enqueues notifications for new alerts.
"""
import json
import time
import logging
import sqlite3
from abc import ABC, abstractmethod
from datetime import datetime, timezone, timedelta
from typing import Optional

from .common import get_db
from .models import Detection, Severity

logger = logging.getLogger("atlas-detector")

SEVERITY_WEIGHT = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


class DetectionRule(ABC):
    """Base class for detection rules."""

    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @property
    @abstractmethod
    def cooldown_sec(self) -> int:
        ...

    @abstractmethod
    def evaluate(self, conn: sqlite3.Connection, since_id: int) -> list:
        """Evaluate rule against events since since_id. Returns list of Detection."""
        ...


class SSHBruteForceRule(DetectionRule):
    name = "ssh_brute_force"
    cooldown_sec = 3600

    def evaluate(self, conn, since_id) -> list:
        """Count SSH auth failures per source IP in rolling 10-min window."""
        rows = conn.execute("""
            SELECT src_ip, COUNT(*) as cnt,
                   GROUP_CONCAT(id) as event_ids,
                   MIN(timestamp) as first_seen,
                   MAX(timestamp) as last_seen
            FROM events
            WHERE event_type = 'ssh_auth_fail'
              AND timestamp >= datetime('now', '-10 minutes')
            GROUP BY src_ip
            HAVING cnt >= 5
        """).fetchall()

        detections = []
        for row in rows:
            evidence = {
                "failure_count": row["cnt"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "window_minutes": 10,
                "threshold": 5,
            }
            detections.append(Detection(
                timestamp=datetime.now(timezone.utc),
                rule_name=self.name,
                severity=Severity.HIGH,
                confidence=min(0.5 + (row["cnt"] - 5) * 0.05, 0.95),
                hostname="",
                src_ip=row["src_ip"],
                explanation=(
                    f"{row['cnt']} failed SSH authentication attempts from "
                    f"{row['src_ip']} within 10 minutes"
                ),
                related_event_ids=[int(i) for i in row["event_ids"].split(",") if i],
                evidence=evidence,
            ))
        return detections


class RepeatedFirewallBlocksRule(DetectionRule):
    name = "repeated_firewall_blocks"
    cooldown_sec = 1800

    def evaluate(self, conn, since_id) -> list:
        rows = conn.execute("""
            SELECT src_ip, COUNT(*) as cnt,
                   GROUP_CONCAT(id) as event_ids,
                   MIN(timestamp) as first_seen,
                   MAX(timestamp) as last_seen
            FROM events
            WHERE event_type = 'nft_drop'
              AND timestamp >= datetime('now', '-5 minutes')
            GROUP BY src_ip
            HAVING cnt >= 10
        """).fetchall()

        detections = []
        for row in rows:
            evidence = {
                "drop_count": row["cnt"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "window_minutes": 5,
                "threshold": 10,
            }
            detections.append(Detection(
                timestamp=datetime.now(timezone.utc),
                rule_name=self.name,
                severity=Severity.MEDIUM,
                confidence=min(0.4 + (row["cnt"] - 10) * 0.03, 0.85),
                hostname="",
                src_ip=row["src_ip"],
                explanation=(
                    f"{row['cnt']} nftables packet drops from "
                    f"{row['src_ip']} within 5 minutes"
                ),
                related_event_ids=[int(i) for i in row["event_ids"].split(",") if i],
                evidence=evidence,
            ))
        return detections


class PortScanningRule(DetectionRule):
    name = "port_scanning"
    cooldown_sec = 3600

    def evaluate(self, conn, since_id) -> list:
        rows = conn.execute("""
            SELECT src_ip,
                   COUNT(DISTINCT dst_port) as port_count,
                   GROUP_CONCAT(DISTINCT dst_port) as ports,
                   GROUP_CONCAT(id) as event_ids,
                   MIN(timestamp) as first_seen,
                   MAX(timestamp) as last_seen
            FROM events
            WHERE event_type = 'nft_drop'
              AND dst_port IS NOT NULL
              AND timestamp >= datetime('now', '-2 minutes')
            GROUP BY src_ip
            HAVING port_count >= 5
        """).fetchall()

        detections = []
        for row in rows:
            evidence = {
                "distinct_ports": row["port_count"],
                "ports_scanned": row["ports"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "window_minutes": 2,
                "threshold": 5,
            }
            detections.append(Detection(
                timestamp=datetime.now(timezone.utc),
                rule_name=self.name,
                severity=Severity.HIGH,
                confidence=min(0.6 + (row["port_count"] - 5) * 0.05, 0.95),
                hostname="",
                src_ip=row["src_ip"],
                explanation=(
                    f"{row['src_ip']} attempted connections to "
                    f"{row['port_count']} distinct ports within 2 minutes "
                    f"(ports: {row['ports']})"
                ),
                related_event_ids=[int(i) for i in row["event_ids"].split(",") if i],
                evidence=evidence,
            ))
        return detections


class ServiceAnomalyRule(DetectionRule):
    name = "service_anomaly"
    cooldown_sec = 900

    def evaluate(self, conn, since_id) -> list:
        rows = conn.execute("""
            SELECT id, timestamp, event_type, process, message, metadata_json
            FROM events
            WHERE event_type IN ('service_failed', 'service_stop')
              AND id > ?
              AND timestamp >= datetime('now', '-5 minutes')
        """, (since_id,)).fetchall()

        detections = []
        for row in rows:
            severity = Severity.HIGH if row["event_type"] == "service_failed" else Severity.MEDIUM
            evidence = {
                "event_type": row["event_type"],
                "process": row["process"],
                "raw_message": row["message"],
            }
            detections.append(Detection(
                timestamp=datetime.now(timezone.utc),
                rule_name=self.name,
                severity=severity,
                confidence=0.8,
                hostname="",
                src_ip=None,
                explanation=f"Service {row['process']} {row['event_type']}: {row['message']}",
                related_event_ids=[row["id"]],
                evidence=evidence,
            ))
        return detections


class SuspiciousNGINXRule(DetectionRule):
    name = "suspicious_nginx"
    cooldown_sec = 1800

    def evaluate(self, conn, since_id) -> list:
        rows = conn.execute("""
            SELECT src_ip, COUNT(*) as cnt,
                   GROUP_CONCAT(id) as event_ids,
                   MIN(timestamp) as first_seen,
                   MAX(timestamp) as last_seen
            FROM events
            WHERE event_type = 'nginx_4xx'
              AND timestamp >= datetime('now', '-5 minutes')
            GROUP BY src_ip
            HAVING cnt >= 20
        """).fetchall()

        detections = []
        for row in rows:
            evidence = {
                "error_count": row["cnt"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "window_minutes": 5,
                "threshold": 20,
            }
            detections.append(Detection(
                timestamp=datetime.now(timezone.utc),
                rule_name=self.name,
                severity=Severity.LOW,
                confidence=min(0.3 + (row["cnt"] - 20) * 0.02, 0.8),
                hostname="",
                src_ip=row["src_ip"],
                explanation=(
                    f"{row['cnt']} 4xx responses from "
                    f"{row['src_ip']} within 5 minutes"
                ),
                related_event_ids=[int(i) for i in row["event_ids"].split(",") if i],
                evidence=evidence,
            ))
        return detections


class AuthCorrelationRule(DetectionRule):
    """
    Evidence-based correlation: SSH auth success followed by nft_drop
    from same IP within 1 minute. NOT automatically high-severity —
    classified as medium with evidence of correlation only.
    """
    name = "auth_correlation"
    cooldown_sec = 7200

    def evaluate(self, conn, since_id) -> list:
        rows = conn.execute("""
            SELECT
                s.id as success_id,
                s.src_ip,
                s.timestamp as success_time,
                s.username,
                d.id as drop_id,
                d.timestamp as drop_time,
                d.dst_port,
                d.message as drop_message
            FROM events s
            JOIN events d ON d.src_ip = s.src_ip
                AND d.event_type = 'nft_drop'
                AND d.id > s.id
                AND d.id > ?
                AND d.timestamp <= datetime(s.timestamp, '+1 minute')
            WHERE s.event_type = 'ssh_auth_success'
              AND s.id > ?
              AND s.timestamp >= datetime('now', '-5 minutes')
            GROUP BY s.id
        """, (since_id, since_id)).fetchall()

        detections = []
        for row in rows:
            evidence = {
                "ssh_success_id": row["success_id"],
                "ssh_success_time": row["success_time"],
                "ssh_username": row["username"],
                "nft_drop_id": row["drop_id"],
                "nft_drop_time": row["drop_time"],
                "nft_drop_port": row["dst_port"],
                "correlation_window": "1 minute",
            }
            detections.append(Detection(
                timestamp=datetime.now(timezone.utc),
                rule_name=self.name,
                severity=Severity.MEDIUM,
                confidence=0.5,
                hostname="",
                src_ip=row["src_ip"],
                explanation=(
                    f"SSH authentication success for user '{row['username']}' "
                    f"from {row['src_ip']} was followed by a firewall drop "
                    f"to port {row['dst_port']} within 1 minute. "
                    f"This is evidence of correlation, not confirmed compromise."
                ),
                related_event_ids=[row["success_id"], row["drop_id"]],
                evidence=evidence,
            ))
        return detections


# --- Cooldown / Deduplication ---

class AlertDeduplicator:
    """
    Prevents alert spam by tracking cooldowns.
    Stores last alert time per (rule_name, src_ip) pair.
    """

    def __init__(self):
        self._cooldowns: dict = {}

    def should_alert(self, rule_name: str, src_ip: Optional[str], cooldown_sec: int) -> bool:
        key = (rule_name, src_ip or "__none__")
        last = self._cooldowns.get(key)
        now = datetime.now(timezone.utc)
        if last and (now - last).total_seconds() < cooldown_sec:
            return False
        self._cooldowns[key] = now
        return True


# --- Detection Engine ---

class DetectionEngine:
    """
    Internal detection engine, runs as a polling loop within the collector.
    Polls for new events every N seconds, runs all rules, writes results.
    """

    def __init__(self, db_path: str, poll_interval_sec: int = 10, cursor_file: str = None):
        self.db_path = db_path
        self.poll_interval = poll_interval_sec
        self.cursor_file = cursor_file or "/opt/atlas/security/detector_cursor.json"
        self.rules = [
            SSHBruteForceRule(),
            RepeatedFirewallBlocksRule(),
            PortScanningRule(),
            ServiceAnomalyRule(),
            SuspiciousNGINXRule(),
            AuthCorrelationRule(),
        ]
        self.deduplicator = AlertDeduplicator()
        self.last_event_id = 0
        self._load_cursor()

    def _load_cursor(self):
        import os
        if os.path.exists(self.cursor_file):
            try:
                with open(self.cursor_file) as f:
                    data = json.load(f)
                    self.last_event_id = data.get("last_event_id", 0)
            except (json.JSONDecodeError, OSError):
                self.last_event_id = 0

    def _save_cursor(self):
        try:
            with open(self.cursor_file, "w") as f:
                json.dump({"last_event_id": self.last_event_id}, f)
        except OSError as e:
            logger.error(f"Failed to save detector cursor: {e}")

    def run_cycle(self) -> int:
        """
        Run one detection cycle. Returns number of new detections.
        Called periodically by the collector's main loop.
        """
        detections_written = 0

        try:
            with get_db(self.db_path) as conn:
                rows = conn.execute(
                    "SELECT MAX(id) as max_id FROM events WHERE id > ?",
                    (self.last_event_id,),
                ).fetchone()

                if not rows or rows["max_id"] is None:
                    return 0

                new_max_id = rows["max_id"]
                if new_max_id == self.last_event_id:
                    return 0

                logger.debug(f"Processing events {self.last_event_id + 1} to {new_max_id}")

                for rule in self.rules:
                    try:
                        detections = rule.evaluate(conn, self.last_event_id)
                    except Exception as e:
                        logger.error(f"Rule {rule.name} error: {e}")
                        continue

                    for detection in detections:
                        if not self.deduplicator.should_alert(
                            rule.name, detection.src_ip, rule.cooldown_sec
                        ):
                            logger.debug(
                                f"Cooldown active for {rule.name} from {detection.src_ip}"
                            )
                            continue

                        hostname = ""
                        if detection.related_event_ids:
                            ev_row = conn.execute(
                                "SELECT hostname FROM events WHERE id = ?",
                                (detection.related_event_ids[0],),
                            ).fetchone()
                            if ev_row:
                                hostname = ev_row["hostname"]
                        detection.hostname = hostname

                        det_id = self._write_detection(conn, detection)
                        alert_id = self._write_alert(conn, det_id, detection)
                        self._enqueue_notification(conn, alert_id, detection)
                        self._handle_incident(conn, detection)

                        detections_written += 1
                        logger.warning(
                            f"DETECTION: {rule.name} | severity={detection.severity.value} | "
                            f"src={detection.src_ip} | confidence={detection.confidence:.2f} | "
                            f"{detection.explanation}"
                        )

                self.last_event_id = new_max_id
                conn.commit()

        except Exception as e:
            logger.error(f"Detection cycle error: {e}", exc_info=True)

        if detections_written > 0:
            self._save_cursor()

        return detections_written

    def _write_detection(self, conn, detection) -> int:
        cursor = conn.execute(
            """INSERT INTO detections (
                timestamp, rule_name, severity, confidence, hostname,
                src_ip, explanation, related_event_ids, evidence
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                detection.timestamp.isoformat(),
                detection.rule_name,
                detection.severity.value,
                detection.confidence,
                detection.hostname,
                detection.src_ip,
                detection.explanation,
                json.dumps(detection.related_event_ids),
                json.dumps(detection.evidence),
            ),
        )
        return cursor.lastrowid

    def _write_alert(self, conn, detection_id: int, detection) -> int:
        title = f"[{detection.severity.value.upper()}] {detection.rule_name.replace('_', ' ').title()}"
        cursor = conn.execute(
            """INSERT INTO alerts (
                detection_id, status, severity, title, description, src_ip
            ) VALUES (?, ?, ?, ?, ?, ?)""",
            (
                detection_id,
                "new",
                detection.severity.value,
                title,
                detection.explanation,
                detection.src_ip,
            ),
        )
        return cursor.lastrowid

    def _enqueue_notification(self, conn, alert_id: int, detection):
        """Insert a notification into the queue for the notifier daemon."""
        try:
            payload = json.dumps({
                "title": f"[{detection.severity.value.upper()}] {detection.rule_name.replace('_', ' ').title()}",
                "body": detection.explanation,
                "severity": detection.severity.value,
                "src_ip": detection.src_ip,
                "rule": detection.rule_name,
                "alert_id": alert_id,
            })
            conn.execute(
                """INSERT INTO notification_queue (alert_id, channel, payload)
                   VALUES (?, 'ntfy', ?)""",
                (alert_id, payload),
            )
            logger.debug(f"Enqueued notification for alert {alert_id}")
        except Exception as e:
            logger.error(f"Failed to enqueue notification for alert {alert_id}: {e}")

    def _handle_incident(self, conn, detection):
        """Create or update an incident."""
        existing = conn.execute(
            """SELECT id, detection_ids, event_ids, confidence
               FROM incidents
               WHERE status = 'open'
                 AND src_ip = ?
                 AND json_extract(detection_ids, '$[0]') IS NOT NULL
               ORDER BY last_updated_at DESC LIMIT 1""",
            (detection.src_ip,),
        ).fetchone()

        if existing:
            det_ids = json.loads(existing["detection_ids"])
            ev_ids = json.loads(existing["event_ids"])
            det_ids.append(detection.related_event_ids[0] if detection.related_event_ids else 0)
            ev_ids.extend(detection.related_event_ids)

            new_confidence = max(existing["confidence"], detection.confidence)

            conn.execute(
                """UPDATE incidents
                   SET detection_ids = ?,
                       event_ids = ?,
                       last_updated_at = ?,
                       confidence = ?,
                       severity = ?
                   WHERE id = ?""",
                (
                    json.dumps(det_ids),
                    json.dumps(ev_ids),
                    datetime.now(timezone.utc).isoformat(),
                    new_confidence,
                    detection.severity.value,
                    existing["id"],
                ),
            )
        else:
            conn.execute(
                """INSERT INTO incidents (
                    title, summary, severity, status, src_ip,
                    started_at, detection_ids, event_ids,
                    evidence_summary, explanation, confidence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    f"[{detection.severity.value.upper()}] {detection.rule_name.replace('_', ' ').title()}",
                    detection.explanation,
                    detection.severity.value,
                    "open",
                    detection.src_ip,
                    detection.timestamp.isoformat(),
                    json.dumps(detection.related_event_ids),
                    json.dumps(detection.related_event_ids),
                    json.dumps(detection.evidence),
                    detection.explanation,
                    detection.confidence,
                ),
            )

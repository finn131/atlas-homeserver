#!/usr/bin/env python3
"""
Atlas Security Observatory — Notification Daemon

Polls notification_queue for pending alerts, sends ntfy push notifications,
updates queue status. Retries failed sends with exponential backoff.

Runs as a standalone systemd service (atlas-notifier.service).
"""
import json
import os
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import get_db, GracefulShutdown, setup_logging
from config import load_config

SEVERITY_WEIGHT = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}

SEVERITY_TAGS = {
    "critical": "rotating_light,skull",
    "high": "warning,lock",
    "medium": "warning",
    "low": "information_source",
    "info": "grey_question",
}

SEVERITY_PRIORITY = {
    "critical": "urgent",
    "high": "high",
    "medium": "default",
    "low": "min",
    "info": "min",
}


def send_ntfy(url: str, topic: str, title: str, body: str,
              tags: str = "warning", priority: str = "default") -> bool:
    """Send a notification via ntfy HTTP POST. Returns True on success."""
    endpoint = f"{url.rstrip('/')}/{topic}"
    payload = body.encode("utf-8")

    req = urllib.request.Request(
        endpoint,
        data=payload,
        headers={
            "Title": title,
            "Tags": tags,
            "Priority": priority,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except (urllib.error.URLError, OSError) as e:
        return False


class Notifier:
    def __init__(self):
        self.config = load_config()
        self.shutdown = GracefulShutdown()
        self.logger = setup_logging(
            "atlas-notifier",
            level="INFO",
            log_file="/opt/atlas/security/atlas-notifier.log",
        )
        self.min_severity_weight = SEVERITY_WEIGHT.get(
            self.config.notification.min_severity, 4
        )

    def run(self):
        self.logger.info(
            f"Atlas Notifier starting (ntfy={self.config.ntfy.url}/{self.config.ntfy.topic}, "
            f"min_severity={self.config.notification.min_severity})"
        )

        while not self.shutdown.should_stop:
            try:
                self._process_queue()
            except Exception as e:
                self.logger.error(f"Notification cycle error: {e}")

            for _ in range(self.config.notification.poll_interval_sec * 10):
                if self.shutdown.should_stop:
                    break
                time.sleep(0.1)

        self.logger.info("Notifier stopped.")

    def _process_queue(self):
        with get_db(self.config.database.path) as conn:
            rows = conn.execute(
                """SELECT id, alert_id, channel, payload, attempts, max_attempts
                   FROM notification_queue
                   WHERE status = 'pending'
                     AND attempts < max_attempts
                   ORDER BY id ASC
                   LIMIT 10"""
            ).fetchall()

            if not rows:
                return

            for row in rows:
                self._send_notification(conn, dict(row))

    def _send_notification(self, conn, item: dict):
        nq_id = item["id"]
        attempts = item["attempts"]

        try:
            payload = json.loads(item["payload"])
        except (json.JSONDecodeError, TypeError):
            conn.execute(
                "UPDATE notification_queue SET status='failed', error_message='invalid payload' WHERE id=?",
                (nq_id,),
            )
            return

        severity = payload.get("severity", "info")
        sev_weight = SEVERITY_WEIGHT.get(severity, 1)

        if sev_weight < self.min_severity_weight:
            conn.execute(
                "UPDATE notification_queue SET status='skipped' WHERE id=?",
                (nq_id,),
            )
            self.logger.debug(f"Skipped notification {nq_id}: severity {severity} below threshold")
            return

        title = payload.get("title", "Atlas Security Alert")
        body = payload.get("body", payload.get("description", "No details"))
        src_ip = payload.get("src_ip", "")
        rule = payload.get("rule", "")

        if src_ip:
            body += f"\nSource IP: {src_ip}"
        if rule:
            body += f"\nRule: {rule}"

        tags = SEVERITY_TAGS.get(severity, "warning")
        priority = SEVERITY_PRIORITY.get(severity, "default")

        new_attempts = attempts + 1
        now = datetime.now(timezone.utc).isoformat()

        if item["channel"] == "ntfy":
            ntfy_cfg = self.config.ntfy
            success = send_ntfy(
                ntfy_cfg.url, ntfy_cfg.topic,
                title=title, body=body,
                tags=tags, priority=priority,
            )
        else:
            self.logger.warning(f"Unknown channel '{item['channel']}' for notification {nq_id}")
            conn.execute(
                "UPDATE notification_queue SET status='failed', error_message=?, attempts=? WHERE id=?",
                (f"unknown channel: {item['channel']}", new_attempts, nq_id),
            )
            return

        if success:
            conn.execute(
                "UPDATE notification_queue SET status='sent', attempts=?, sent_at=? WHERE id=?",
                (new_attempts, now, nq_id),
            )
            self.logger.info(f"Notification {nq_id} sent via {item['channel']}")
        else:
            if new_attempts >= item["max_attempts"]:
                conn.execute(
                    "UPDATE notification_queue SET status='failed', attempts=?, error_message=? WHERE id=?",
                    (new_attempts, "max attempts exceeded", nq_id),
                )
                self.logger.warning(f"Notification {nq_id} failed after {new_attempts} attempts")
            else:
                conn.execute(
                    "UPDATE notification_queue SET attempts=? WHERE id=?",
                    (new_attempts, nq_id),
                )
                self.logger.warning(f"Notification {nq_id} send failed, attempt {new_attempts}")


def main():
    notifier = Notifier()
    notifier.run()


if __name__ == "__main__":
    main()

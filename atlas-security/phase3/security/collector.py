#!/usr/bin/env python3
"""
Atlas Security Observatory — Event Collector Daemon

Reads security-relevant events from:
1. systemd journal (SSH, Fail2Ban, kernel/nftables, service lifecycle)
2. NGINX access log files
3. Fail2Ban log file

Normalizes all events to a common schema, writes to SQLite in batches.
Embeds the detection engine as an internal polling loop.

Architecture:
- Event-driven journal follow (near-zero idle CPU)
- File-tail with byte offset cursor for flat logs
- Bounded in-memory queue (drops with counter if full)
- Batch writes (every N events or every M seconds)
- Graceful restart via signal handlers and cursor persistence
"""
import os
import sys
import time
import json
import socket
import signal
import subprocess
import logging
from collections import deque
from pathlib import Path

# Ensure the package is importable
sys.path.insert(0, "/opt/atlas")

from security.config import load_config, Config
from security.common import get_db, GracefulShutdown, setup_logging
from security.schema import ensure_schema
from security.models import SecurityEvent
from security.parsers.nginx import parse_nginx_access_line
from security.parsers.fail2ban import parse_fail2ban_line
from security.parsers.journald import parse_journald_entry
from security.detector import DetectionEngine

logger = logging.getLogger("atlas-collector")

BATCH_INSERT_SQL = """
INSERT INTO events (
    timestamp, hostname, source, event_type, severity,
    src_ip, dst_ip, src_port, dst_port, username,
    process, message, raw_log, correlation_id, metadata_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


class EventCollector:
    """Main collector daemon."""

    def __init__(self, config: Config):
        self.config = config
        self.hostname = socket.gethostname()
        self.shutdown = GracefulShutdown()
        self.queue: deque = deque(maxlen=config.collector.queue_max_size)
        self.events_dropped = 0
        self.events_collected = 0
        self.last_flush = time.time()
        self.detector = None

        # File tail state: {path: {"handle": file, "offset": int}}
        self._file_handles = {}

        # Journal processes
        self._journal_procs = []
        self._journal_bufs = []

    def run(self):
        """Main daemon loop."""
        logger.info("Atlas Collector starting...")

        # Ensure database exists
        ensure_schema(self.config.database.path)

        # Initialize detection engine
        if self.config.detector.enabled:
            self.detector = DetectionEngine(
                db_path=self.config.database.path,
                poll_interval_sec=self.config.detector.poll_interval_sec,
                cursor_file=self.config.detector.cursor_file,
            )
            logger.info("Detection engine initialized")

        # Start journal follower
        self._start_journal()

        # Open file handles for log tailing
        self._open_log_file(
            os.path.join(self.config.collector.log_dir, "atlas_access.log"),
            "nginx",
        )
        self._open_log_file(
            self.config.collector.fail2ban_log,
            "fail2ban",
        )

        logger.info("Collector running. Waiting for events...")

        last_detect_cycle = time.time()

        while not self.shutdown.should_stop:
            # 1. Read from journal (non-blocking drain)
            self._drain_journal()

            # 2. Read new lines from NGINX log
            self._drain_file(
                os.path.join(self.config.collector.log_dir, "atlas_access.log"),
                parse_nginx_access_line,
            )

            # 3. Read new lines from fail2ban log
            self._drain_file(
                self.config.collector.fail2ban_log,
                parse_fail2ban_line,
            )

            # 4. Flush events if batch ready
            self._maybe_flush()

            # 5. Run detection cycle periodically
            now = time.time()
            if (
                self.detector
                and (now - last_detect_cycle) >= self.config.detector.poll_interval_sec
            ):
                try:
                    count = self.detector.run_cycle()
                    if count > 0:
                        logger.info(f"Detection cycle: {count} new detections")
                except Exception as e:
                    logger.error(f"Detection cycle error: {e}")
                last_detect_cycle = now

            # Brief sleep to avoid spinning
            time.sleep(0.5)

        # Final flush before exit
        self._flush()
        self._save_cursors()
        self._stop_journal()
        logger.info(
            f"Collector stopped. Collected: {self.events_collected}, "
            f"Dropped: {self.events_dropped}"
        )

    def _start_journal(self):
        """Start journalctl --follow --output=json as subprocess(es).

        Uses two separate processes because -k (kernel) is incompatible
        with -u (unit) filters in journalctl.
        """
        if not self.config.collector.journald_follow:
            return

        self._journal_procs = []
        self._journal_bufs = []

        # Process 1: unit-filtered events (SSH, fail2ban, nginx, etc.)
        cmd_units = ["journalctl", "--follow", "--output=json", "--no-pager", "-q"]
        units = self.config.journald.units
        for unit in units:
            cmd_units.extend(["-u", unit])

        try:
            proc = subprocess.Popen(
                cmd_units,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                bufsize=0,
            )
            self._journal_procs.append(proc)
            self._journal_bufs.append("")
            logger.info(f"Journal unit follower started (pid={proc.pid})")
        except Exception as e:
            logger.error(f"Failed to start journal unit follower: {e}")

        # Process 2: kernel messages (nftables drops)
        if self.config.journald.include_kernel:
            cmd_kernel = ["journalctl", "--follow", "--output=json", "--no-pager", "-q", "-k"]
            try:
                proc = subprocess.Popen(
                    cmd_kernel,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    bufsize=0,
                )
                self._journal_procs.append(proc)
                self._journal_bufs.append("")
                logger.info(f"Journal kernel follower started (pid={proc.pid})")
            except Exception as e:
                logger.error(f"Failed to start journal kernel follower: {e}")

    def _stop_journal(self):
        """Stop all journal follower subprocesses."""
        for proc in getattr(self, "_journal_procs", []):
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            self._journal_proc = None

    def _drain_journal(self):
        """Read all pending journal entries from the subprocess(es)."""
        procs = getattr(self, "_journal_procs", [])
        bufs = getattr(self, "_journal_bufs", [])

        for idx, proc in enumerate(procs):
            if proc.poll() is not None:
                logger.warning(f"Journal process {proc.pid} exited, restarting...")
                procs.pop(idx)
                bufs.pop(idx)
                self._start_journal()
                return

            fd = proc.stdout.fileno()
            os.set_blocking(fd, False)
            buf = bufs[idx] if idx < len(bufs) else ""
            while not self.shutdown.should_stop:
                import select
                readable, _, _ = select.select([fd], [], [], 0.1)
                if not readable:
                    break

                try:
                    chunk = os.read(fd, 8192)
                except BlockingIOError:
                    break
                if not chunk:
                    break

                buf += chunk.decode("utf-8", errors="replace")
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    events = parse_journald_entry(entry, self.hostname)
                    for ev in events:
                        self._enqueue(ev)
            if idx < len(bufs):
                bufs[idx] = buf

    def _open_log_file(self, path: str, source: str):
        """Open a log file for tailing, seek to end initially."""
        try:
            if not os.path.exists(path):
                logger.warning(f"Log file not found: {path}")
                return

            handle = open(path, "r")
            # Seek to end to avoid reprocessing old logs on first start
            handle.seek(0, 2)
            self._file_handles[path] = {
                "handle": handle,
                "offset": handle.tell(),
                "source": source,
            }
            logger.info(f"Tailing {path} from offset {self._file_handles[path]['offset']}")
        except Exception as e:
            logger.error(f"Failed to open {path}: {e}")

    def _drain_file(self, path: str, parser_func):
        """Read new lines from a tailed file."""
        state = self._file_handles.get(path)
        if not state:
            # Try to open if it now exists
            if os.path.exists(path):
                source = "nginx" if "nginx" in path else "fail2ban"
                self._open_log_file(path, source)
                state = self._file_handles.get(path)
            if not state:
                return

        handle = state["handle"]
        source = state["source"]

        # Check if file was rotated (inode change)
        try:
            current_stat = os.fstat(handle.fileno())
            path_stat = os.stat(path)
            if current_stat.st_ino != path_stat.st_ino:
                logger.info(f"Log file rotated: {path}")
                handle.close()
                self._open_log_file(path, source)
                state = self._file_handles.get(path)
                if not state:
                    return
                handle = state["handle"]
        except OSError:
            pass

        while not self.shutdown.should_stop:
            line = handle.readline()
            if not line:
                break

            state["offset"] = handle.tell()
            line = line.strip()
            if not line:
                continue

            # Parse the line
            try:
                if source == "nginx":
                    events = parse_nginx_access_line(line, self.hostname)
                    for ev in events:
                        self._enqueue(ev)
                elif source == "fail2ban":
                    ev = parse_fail2ban_line(line, self.hostname)
                    if ev:
                        self._enqueue(ev)
            except Exception as e:
                logger.debug(f"Parse error ({source}): {e}")

    def _enqueue(self, event: SecurityEvent):
        """Add event to bounded queue."""
        try:
            self.queue.append(event)
            self.events_collected += 1
        except IndexError:
            self.events_dropped += 1
            if self.events_dropped % 100 == 1:
                logger.warning(
                    f"Queue full, {self.events_dropped} events dropped total"
                )

    def _maybe_flush(self):
        """Flush queue to SQLite if batch size or time threshold reached."""
        now = time.time()
        db = self.config.database
        if (
            len(self.queue) >= db.batch_size
            or (now - self.last_flush) >= db.flush_interval_sec
        ):
            self._flush()

    def _flush(self):
        """Write all queued events to SQLite in a single transaction."""
        if not self.queue:
            return

        events_to_write = list(self.queue)
        self.queue.clear()

        try:
            with get_db(self.config.database.path) as conn:
                conn.executemany(
                    BATCH_INSERT_SQL,
                    [e.to_db_tuple() for e in events_to_write],
                )
            self.last_flush = time.time()
            logger.debug(f"Flushed {len(events_to_write)} events to database")
        except Exception as e:
            logger.error(f"Failed to flush events: {e}")
            # Re-queue events (they'll be tried again)
            for ev in reversed(events_to_write):
                self.queue.appendleft(ev)

    def _save_cursors(self):
        """Persist current file positions for resume on restart."""
        cursor = {}
        for path, state in self._file_handles.items():
            cursor[path] = {
                "offset": state["offset"],
                "source": state["source"],
            }

        cursor_file = self.config.collector.log_resume_file
        try:
            os.makedirs(os.path.dirname(cursor_file), exist_ok=True)
            with open(cursor_file, "w") as f:
                json.dump(cursor, f)
        except Exception as e:
            logger.error(f"Failed to save cursors: {e}")


def main():
    config = load_config()
    setup_logging("atlas-collector", log_file="/var/log/atlas-collector.log")
    collector = EventCollector(config)
    collector.run()


if __name__ == "__main__":
    main()

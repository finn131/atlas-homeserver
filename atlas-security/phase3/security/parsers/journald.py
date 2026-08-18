"""
Parse journald entries for security-relevant events.
Uses journalctl --follow --output=json subprocess.
"""
import json
import re
from datetime import datetime, timezone
from typing import Optional

from ..models import SecurityEvent, Severity

# SSH log patterns
SSH_FAIL_PASSWORD_RE = re.compile(
    r'Failed password for (?:invalid user )?(?P<username>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+)'
)
SSH_FAIL_PUBLICKEY_RE = re.compile(
    r'Failed publickey for (?:invalid user )?(?P<username>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+)'
)
SSH_ACCEPTED_RE = re.compile(
    r'Accepted (?:password|publickey) for (?P<username>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+)'
)
SSH_DISCONNECTED_RE = re.compile(
    r'Disconnected from (?:authenticating )?(?:invalid )?user \S+ (?P<src_ip>\S+) port (?P<src_port>\d+)'
)
SSH_DISCONNECTED_GENERIC_RE = re.compile(
    r'Disconnected from (?P<src_ip>\S+) port (?P<src_port>\d+)'
)

# nftables log pattern from kernel
NFT_DROP_RE = re.compile(
    r'NFT DROP:\s+'
    r'(?:IN=(?P<in>\S+)\s+)?'
    r'(?:OUT=(?P<out>\S+)\s+)?'
    r'(?:MAC=(?P<mac>\S+)\s+)?'
    r'SRC=(?P<src_ip>\S+)\s+'
    r'DST=(?P<dst_ip>\S+)\s+'
    r'.*?'
    r'(?:SPT=(?P<src_port>\d+)\s+)?'
    r'(?:DPT=(?P<dst_port>\d+)\s+)?'
    r'(?:PROTO=(?P<proto>\S+)\s+)?'
)

# Systemd service state patterns
SERVICE_STATE_RE = re.compile(
    r'(?P<unit>\S+)\.service: (?:Main process exited with|Succeeded|Failed with result)'
)


def _microseconds_to_datetime(us_str: str) -> Optional[datetime]:
    """Convert journald __REALTIME_TIMESTAMP (microseconds since epoch) to datetime."""
    try:
        us = int(us_str)
        return datetime.fromtimestamp(us / 1_000_000, tz=timezone.utc)
    except (ValueError, TypeError, OSError):
        return None


def _parse_ssh_events(entry: dict, hostname: str) -> list:
    """Extract SSH authentication events from journald."""
    message = entry.get("MESSAGE", "")
    timestamp_us = entry.get("__REALTIME_TIMESTAMP", "")
    ts = _microseconds_to_datetime(timestamp_us)
    if ts is None:
        return []

    events = []

    # Failed password
    m = SSH_FAIL_PASSWORD_RE.search(message)
    if m:
        events.append(SecurityEvent(
            timestamp=ts,
            hostname=hostname,
            source="journald",
            event_type="ssh_auth_fail",
            severity=Severity.MEDIUM,
            src_ip=m.group("src_ip"),
            src_port=int(m.group("src_port")),
            username=m.group("username"),
            process="sshd",
            message=message,
            raw_log=message,
        ))
        return events

    # Failed publickey
    m = SSH_FAIL_PUBLICKEY_RE.search(message)
    if m:
        events.append(SecurityEvent(
            timestamp=ts,
            hostname=hostname,
            source="journald",
            event_type="ssh_auth_fail",
            severity=Severity.MEDIUM,
            src_ip=m.group("src_ip"),
            src_port=int(m.group("src_port")),
            username=m.group("username"),
            process="sshd",
            message=message,
            raw_log=message,
        ))
        return events

    # Accepted auth
    m = SSH_ACCEPTED_RE.search(message)
    if m:
        events.append(SecurityEvent(
            timestamp=ts,
            hostname=hostname,
            source="journald",
            event_type="ssh_auth_success",
            severity=Severity.INFO,
            src_ip=m.group("src_ip"),
            src_port=int(m.group("src_port")),
            username=m.group("username"),
            process="sshd",
            message=message,
            raw_log=message,
        ))
        return events

    # Session open (Accepted ...)
    if "Accepted" in message:
        return events  # Already handled above

    return events


def _parse_nftables_event(entry: dict, hostname: str) -> Optional[SecurityEvent]:
    """Extract nftables DROP events from kernel log."""
    message = entry.get("MESSAGE", "")
    timestamp_us = entry.get("__REALTIME_TIMESTAMP", "")
    ts = _microseconds_to_datetime(timestamp_us)
    if ts is None:
        return None

    m = NFT_DROP_RE.search(message)
    if not m:
        return None

    metadata = {}
    if m.group("in"):
        metadata["in_interface"] = m.group("in")
    if m.group("out"):
        metadata["out_interface"] = m.group("out")
    if m.group("proto"):
        metadata["protocol"] = m.group("proto")
    if m.group("mac"):
        metadata["mac"] = m.group("mac")

    return SecurityEvent(
        timestamp=ts,
        hostname=hostname,
        source="nftables",
        event_type="nft_drop",
        severity=Severity.LOW,
        src_ip=m.group("src_ip"),
        dst_ip=m.group("dst_ip"),
        src_port=int(m.group("src_port")) if m.group("src_port") else None,
        dst_port=int(m.group("dst_port")) if m.group("dst_port") else None,
        process="kernel",
        message=message,
        raw_log=message,
        metadata=metadata,
    )


def _parse_service_event(entry: dict, hostname: str) -> Optional[SecurityEvent]:
    """Parse service lifecycle events from systemd."""
    message = entry.get("MESSAGE", "")
    unit = entry.get("_SYSTEMD_UNIT", "")
    timestamp_us = entry.get("__REALTIME_TIMESTAMP", "")
    ts = _microseconds_to_datetime(timestamp_us)
    if ts is None:
        return None

    # Only track security-relevant services
    tracked = {"ssh.service", "sshd.service", "sshd-session.service", "nginx.service", "prometheus.service",
               "grafana-server.service", "fail2ban.service"}
    if unit not in tracked:
        return None

    if "Failed with result" in message or "Main process exited with" in message:
        event_type = "service_failed"
        severity = Severity.HIGH
    elif "Succeeded" in message:
        event_type = "service_stop"
        severity = Severity.LOW
    elif "Started" in message:
        event_type = "service_start"
        severity = Severity.INFO
    elif "Stopping" in message:
        event_type = "service_stop"
        severity = Severity.INFO
    else:
        return None

    return SecurityEvent(
        timestamp=ts,
        hostname=hostname,
        source="journald",
        event_type=event_type,
        severity=severity,
        process=unit,
        message=message,
        raw_log=message,
        metadata={"unit": unit},
    )


def parse_journald_entry(entry: dict, hostname: str) -> list:
    """
    Parse a journald JSON entry into zero or more SecurityEvents.

    Handles:
    - sshd.service → SSH auth events
    - kernel → nftables DROP events (via "NFT DROP" prefix)
    - Any tracked service → start/stop/failed lifecycle events
    """
    unit = entry.get("_SYSTEMD_UNIT", "")
    comm = entry.get("_COMM", "")
    message = entry.get("MESSAGE", "")

    events = []

    if unit in ("sshd.service", "sshd-session.service", "ssh.service"):
        events.extend(_parse_ssh_events(entry, hostname))
    elif comm == "kernel" and message and "NFT DROP" in message:
        ev = _parse_nftables_event(entry, hostname)
        if ev:
            events.append(ev)
    elif unit and ".service" in unit:
        ev = _parse_service_event(entry, hostname)
        if ev:
            events.append(ev)

    return events

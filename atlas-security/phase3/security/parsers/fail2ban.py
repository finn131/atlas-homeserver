"""
Parse Fail2Ban log entries.

Format examples:
2026-08-18 14:32:05,123 fail2ban.actions[1234]: NOTICE  [sshd] Ban 192.168.1.50
2026-08-18 14:32:05,123 fail2ban.actions[1234]: NOTICE  [sshd] Unban 192.168.1.50
2026-08-18 14:32:05,123 fail2ban.filter[1234]: INFO    [sshd] Found 192.168.1.50 - 2026-08-18 14:32:05
"""
import re
from datetime import datetime
from typing import Optional

from ..models import SecurityEvent, Severity

F2B_TIME_FMT = "%Y-%m-%d %H:%M:%S,%f"

F2B_BAN_RE = re.compile(
    r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2},\d{3})\s+'
    r'fail2ban\.actions\[\d+\]:\s+'
    r'(?P<level>\w+)\s+'
    r'\[(?P<jail>\w+)\]\s+'
    r'(?P<action>Ban|Unban)\s+'
    r'(?P<ip>\S+)'
)

F2B_FILTER_RE = re.compile(
    r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2},\d{3})\s+'
    r'fail2ban\.filter\[\d+\]:\s+'
    r'(?P<level>\w+)\s+'
    r'\[(?P<jail>\w+)\]\s+'
    r'Found\s+'
    r'(?P<ip>\S+)'
)


def _parse_f2b_time(time_str: str) -> Optional[datetime]:
    try:
        return datetime.strptime(time_str, F2B_TIME_FMT)
    except (ValueError, TypeError):
        return None


def parse_fail2ban_line(line: str, hostname: str) -> Optional[SecurityEvent]:
    """
    Parse a single fail2ban log line into a SecurityEvent.
    Returns SecurityEvent for Ban/Unban actions, None otherwise.
    """
    line = line.rstrip("\n")

    # Try ban/unban pattern first
    m = F2B_BAN_RE.match(line)
    if m:
        ts = _parse_f2b_time(m.group("timestamp"))
        if ts is None:
            return None

        action = m.group("action")
        jail = m.group("jail")
        ip = m.group("ip")

        if action == "Ban":
            event_type = "fail2ban_ban"
            severity = Severity.MEDIUM
        else:
            event_type = "fail2ban_unban"
            severity = Severity.INFO

        return SecurityEvent(
            timestamp=ts,
            hostname=hostname,
            source="fail2ban",
            event_type=event_type,
            severity=severity,
            src_ip=ip,
            process="fail2ban",
            message=f"[{jail}] {action} {ip}",
            raw_log=line,
            metadata={"jail": jail, "action": action},
        )

    # Try filter/found pattern (lower severity, still useful)
    m = F2B_FILTER_RE.match(line)
    if m:
        ts = _parse_f2b_time(m.group("timestamp"))
        if ts is None:
            return None

        jail = m.group("jail")
        ip = m.group("ip")

        return SecurityEvent(
            timestamp=ts,
            hostname=hostname,
            source="fail2ban",
            event_type="fail2ban_match",
            severity=Severity.LOW,
            src_ip=ip,
            process="fail2ban",
            message=f"[{jail}] Found match for {ip}",
            raw_log=line,
            metadata={"jail": jail},
        )

    return None

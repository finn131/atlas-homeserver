"""
Parse NGINX access log lines in atlas_security format.

Format:
$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
"$http_referer" "$http_user_agent" rt=$request_time ...
"""
import re
from datetime import datetime
from typing import Optional

from ..models import SecurityEvent, Severity

# Main pattern: captures up to user_agent
NGINX_ACCESS_RE = re.compile(
    r'(?P<src_ip>\S+) - (?P<remote_user>\S+) '
    r'\[(?P<time_local>[^\]]+)\] '
    r'"(?P<request>[^"]*)" '
    r'(?P<status>\d{3}) '
    r'(?P<body_bytes>\d+) '
    r'"(?P<referer>[^"]*)" '
    r'"(?P<user_agent>[^"]*)"'
)

REQUEST_RE = re.compile(r'^(?P<method>\S+)\s+(?P<path>\S+)')

# NGINX time format: 18/Aug/2026:14:32:05 +0700
NGINX_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"


def _parse_nginx_time(time_str: str) -> Optional[datetime]:
    """Parse NGINX time_local format to datetime."""
    try:
        return datetime.strptime(time_str, NGINX_TIME_FMT)
    except (ValueError, TypeError):
        return None


def parse_nginx_access_line(line: str, hostname: str) -> list:
    """
    Parse a single NGINX access log line into SecurityEvent(s).
    Only emits events for security-relevant status codes (4xx, 5xx).
    Returns empty list for 2xx/3xx.
    """
    line = line.rstrip("\n")
    m = NGINX_ACCESS_RE.match(line)
    if not m:
        return []

    status = int(m.group("status"))
    src_ip = m.group("src_ip")
    time_local = m.group("time_local")

    ts = _parse_nginx_time(time_local)
    if ts is None:
        return []

    # Only emit events for security-relevant status codes
    if 400 <= status < 500:
        severity = Severity.LOW
        event_type = "nginx_4xx"
    elif 500 <= status < 600:
        severity = Severity.MEDIUM
        event_type = "nginx_5xx"
    else:
        return []

    # Extract method and path from request
    request = m.group("request")
    req_match = REQUEST_RE.match(request)
    method = req_match.group("method") if req_match else None
    path = req_match.group("path") if req_match else None

    metadata = {
        "status": status,
        "method": method,
        "path": path,
        "body_bytes": int(m.group("body_bytes")),
        "user_agent": m.group("user_agent"),
    }

    return [SecurityEvent(
        timestamp=ts,
        hostname=hostname,
        source="nginx",
        event_type=event_type,
        severity=severity,
        src_ip=src_ip,
        process="nginx",
        message=f"{method or '?'} {path or '?'} {status}",
        raw_log=line,
        metadata=metadata,
    )]

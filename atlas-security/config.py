"""
Configuration loader for Atlas Security Observatory.
Reads /etc/atlas/security.ini, provides typed access with safe defaults.
"""
import configparser
from pathlib import Path
from dataclasses import dataclass, field

CONFIG_PATH = Path("/etc/atlas/security.ini")


@dataclass(frozen=True)
class DatabaseConfig:
    path: str = "/opt/atlas/security.db"
    wal_mode: bool = True
    busy_timeout_ms: int = 5000
    batch_size: int = 50
    flush_interval_sec: int = 5


@dataclass(frozen=True)
class CollectorConfig:
    queue_max_size: int = 10000
    log_resume_file: str = "/opt/atlas/security/collector_cursor.json"
    log_dir: str = "/var/log/nginx"
    fail2ban_log: str = "/var/log/fail2ban.log"
    journald_follow: bool = True


@dataclass(frozen=True)
class JournaldConfig:
    units: list = field(default_factory=lambda: [
        "sshd.service", "fail2ban.service", "nginx.service",
        "atlas-collector.service",
    ])
    include_kernel: bool = True
    kernel_prefix: str = "NFT DROP"


@dataclass(frozen=True)
class DetectorConfig:
    poll_interval_sec: int = 10
    cursor_file: str = "/opt/atlas/security/detector_cursor.json"
    enabled: bool = True


@dataclass(frozen=True)
class NotificationConfig:
    enabled: bool = True
    poll_interval_sec: int = 5
    min_severity: str = "high"


@dataclass(frozen=True)
class NtfyConfig:
    url: str = "http://127.0.0.1:8088"
    topic: str = "atlas-alerts"


@dataclass(frozen=True)
class Config:
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    collector: CollectorConfig = field(default_factory=CollectorConfig)
    journald: JournaldConfig = field(default_factory=JournaldConfig)
    detector: DetectorConfig = field(default_factory=DetectorConfig)
    notification: NotificationConfig = field(default_factory=NotificationConfig)
    ntfy: NtfyConfig = field(default_factory=NtfyConfig)


def load_config(path: Path = CONFIG_PATH) -> Config:
    """Load configuration from INI file, falling back to defaults."""
    if not path.exists():
        return Config()

    parser = configparser.ConfigParser()
    parser.read(str(path))

    db = DatabaseConfig(
        path=parser.get("database", "path", fallback="/opt/atlas/security.db"),
        wal_mode=parser.getboolean("database", "wal_mode", fallback=True),
        busy_timeout_ms=parser.getint("database", "busy_timeout_ms", fallback=5000),
        batch_size=parser.getint("database", "batch_size", fallback=50),
        flush_interval_sec=parser.getint("database", "flush_interval_sec", fallback=5),
    )

    collector = CollectorConfig(
        queue_max_size=parser.getint("collector", "queue_max_size", fallback=10000),
        log_resume_file=parser.get("collector", "log_resume_file",
                                   fallback="/opt/atlas/security/collector_cursor.json"),
        log_dir=parser.get("collector", "log_dir", fallback="/var/log/nginx"),
        fail2ban_log=parser.get("collector", "fail2ban_log",
                                fallback="/var/log/fail2ban.log"),
        journald_follow=parser.getboolean("collector", "journald_follow", fallback=True),
    )

    units_str = parser.get("journald", "units",
                           fallback="sshd.service,fail2ban.service,nginx.service,atlas-collector.service")
    units = [u.strip() for u in units_str.split(",") if u.strip()]

    journald = JournaldConfig(
        units=units,
        include_kernel=parser.getboolean("journald", "include_kernel", fallback=True),
        kernel_prefix=parser.get("journald", "kernel_prefix", fallback="NFT DROP"),
    )

    detector = DetectorConfig(
        poll_interval_sec=parser.getint("detector", "poll_interval_sec", fallback=10),
        cursor_file=parser.get("detector", "cursor_file",
                               fallback="/opt/atlas/security/detector_cursor.json"),
        enabled=parser.getboolean("detector", "enabled", fallback=True),
    )

    notification = NotificationConfig(
        enabled=parser.getboolean("notification", "enabled", fallback=True),
        poll_interval_sec=parser.getint("notification", "poll_interval_sec", fallback=5),
        min_severity=parser.get("notification", "min_severity", fallback="high"),
    )

    ntfy = NtfyConfig(
        url=parser.get("ntfy", "url", fallback="http://127.0.0.1:8088"),
        topic=parser.get("ntfy", "topic", fallback="atlas-alerts"),
    )

    return Config(
        database=db, collector=collector, journald=journald,
        detector=detector, notification=notification, ntfy=ntfy,
    )

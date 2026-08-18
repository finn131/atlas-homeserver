# Atlas Security Observatory - Implementation Plan

> **Version:** 1.0  
> **Status:** Proposed  
> **Date:** 2026-08-18  
> **Project:** Atlas Homelab  
> **Scope:** Phases 0-6 (No AI/ML)

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Directory Layout](#directory-layout)
3. [Phase 0: Security Hardening](#phase-0-security-hardening)
4. [Phase 1: Infrastructure Monitoring Documentation](#phase-1-infrastructure-monitoring-documentation)
5. [Phase 2: Centralized Logging](#phase-2-centralized-logging)
6. [Phase 3: Security Event Collection](#phase-3-security-event-collection)
7. [Phase 4: Detection Engine](#phase-4-detection-engine)
8. [Phase 5: Alerting & Security API](#phase-5-alerting--security-api)
9. [Phase 6: Security Dashboard](#phase-6-security-dashboard)
10. [ADR: SQLite for Security Store](#adr-sqlite-for-security-store)
11. [ADR: Event Pipeline Architecture](#adr-event-pipeline-architecture)
12. [Resource Budget](#resource-budget)
13. [Dependency Map](#dependency-map)

---

## Architecture Overview

### Current State

```
                    Internet
                        │
                  Tailscale VPN
                        │
                Debian 13 Home Server
                        │
    ┌───────────────────┼───────────────────┐
    │                   │                   │
  nginx             prometheus            ssh
    │                   │
    ├── /grafana        ├── node-exporter
    ├── /files          └── nginx-exporter
    ├── /prometheus
    ├── /api/status
    └── /ws
```

### Target State — Atlas Security Observatory

```
                    Internet
                        │
                  Tailscale VPN
                        │
                Debian 13 Home Server
                        │
    ┌───────────────────┼───────────────────────────────────┐
    │                   │                                   │
  nginx             prometheus            ssh               │
    │                   │                 (hardened)         │
    ├── /grafana        ├── node-exporter (localhost)       │
    ├── /files          └── nginx-exporter (localhost)      │
    ├── /prometheus                                     ┌────┴────┐
    ├── /api/status                                     │  auditd │
    ├── /api/security/*                                 └─────────┘
    ├── /ws
    └── landing page

    ┌──────────────────────────────────────────────────────────┐
    │                  Security Observatory                     │
    │                                                          │
    │   systemd-journald ──→ collector.py ──→ security.db     │
    │   nginx.log ──────────→     │          (SQLite)          │
    │   nftables.log ───────→     │               │            │
    │   fail2ban.log ───────→     │               ▼            │
    │                         normalizer    detector.py        │
    │                                            │            │
    │                              ┌─────────────┼────────┐   │
    │                              ▼             ▼        ▼   │
    │                         detections     alerts    API    │
    │                                          │        │    │
    │                              ┌───────────┴────────┘    │
    │                              ▼                         │
    │                    Grafana Security Dashboard           │
    │                    Atlas Landing Page Section            │
    └──────────────────────────────────────────────────────────┘
```

### Data Flow

```
[Sources]              [Collection]         [Storage]       [Detection]      [Presentation]

journald ─────┐
  ssh.auth    │
  nftables    ├──→ collector.py ──→ security.db ──→ detector.py ──→ Grafana
  systemd     │     (daemon)        (SQLite)        (daemon)        dashboard
  kernel      │         │
              │         ├──→ events table
nginx.log ────┤         ├──→ detections table
  access      │         ├──→ alerts table
  error       │         └──→ remediation_log table
              │
nftables.log ─┤
  DROP prefix │
              │
fail2ban.log ─┘
```

---

## Directory Layout

All security components live under `/opt/atlas/security/` and `/etc/atlas/`:

```
/opt/atlas/
├── backend.py                  # Existing FastAPI app (modified in Phase 5)
├── status.db                   # Existing service status DB (untouched)
├── security.db                 # New: security events/detections/alerts
└── security/
    ├── __init__.py
    ├── collector.py             # Phase 3: Event collection daemon
    ├── detector.py              # Phase 4: Detection engine daemon
    ├── schema.py                # Shared DB schema definitions
    ├── config.py                # Shared configuration constants
    ├── models.py                # Shared data models (Pydantic)
    ├── common.py                # Shared utilities (logging, DB helpers)
    └── tests/
        ├── __init__.py
        ├── test_schema.py       # Schema validation tests
        ├── test_collector.py    # Collector unit tests
        ├── test_detector.py     # Detector unit tests
        ├── test_normalizer.py   # Normalizer unit tests
        └── fixtures/            # Test fixture data
            ├── sample_nginx_access.log
            ├── sample_fail2ban.log
            ├── sample_nftables.json
            └── sample_journald.json

/etc/atlas/
├── security.ini                 # Phase 3: Central config file
├── grafana/
│   └── provisioning/
│       ├── datasources/
│       │   └── prometheus.yaml  # Phase 1
│       └── dashboards/
│           ├── dashboard.yml    # Phase 1 (provider config)
│           ├── infrastructure.json  # Phase 1
│           └── security.json    # Phase 6

/etc/systemd/system/
├── atlas-collector.service      # Phase 3
├── atlas-detector.service       # Phase 4

/etc/nginx/
├── conf.d/
│   └── atlas-security.conf     # Phase 5: /api/security/* routes

/etc/audit/
├── auditd.conf                 # Phase 0: auditd config
└── rules.d/
    └── atlas-security.rules    # Phase 0: audit rules
```

---

## Phase 0: Security Hardening

### Goal

Close known security exposure before building the observatory on top of the system. This is prerequisite work — no new features, just fixing what's exposed.

### ADR-001: Bind Monitoring Exporters to Localhost

**Status:** Proposed

**Context:** Prometheus (9090), Node Exporter (9100), and NGINX Exporter (9113) currently listen on `0.0.0.0`. The nftables DROP policy blocks most inbound, but Tailscale peers and any compromised host on the LAN can reach these endpoints directly, bypassing nginx auth.

**Decision:** Bind all three services to `127.0.0.1` only. Scrape from localhost. No remote exporter access.

**Consequences:**
- Easier: Prometheus scrapes work identically (same host)
- Harder: Cannot debug exporter from another machine (acceptable — use SSH tunnel)
- Trade-off: Slight operational inconvenience for significant security improvement

### Files to Create/Modify

#### 1. Prometheus — Bind to Localhost

**File:** `/etc/prometheus/prometheus.yml`  
**Action:** No changes needed to prometheus.yml itself (scrape targets already use localhost). The change is in the systemd unit or flags.

**File:** `/etc/default/prometheus` (or override via systemd drop-in)  
**Action:** Add `--web.listen-address=127.0.0.1:9090`

Create systemd override:
```
/etc/systemd/system/prometheus.service.d/override.conf
```
```ini
[Service]
ExecStart=
ExecStart=/usr/bin/prometheus \
  --config.file=/etc/prometheus/prometheus.yml \
  --storage.tsdb.path=/var/lib/prometheus \
  --web.listen-address=127.0.0.1:9090 \
  --web.console.libraries=/etc/prometheus/console_libraries \
  --web.console.templates=/etc/prometheus/consoles \
  --web.enable-lifecycle
```

#### 2. Node Exporter — Bind to Localhost

**File:** `/etc/systemd/system/prometheus-node-exporter.service.d/override.conf`  
**Action:**
```ini
[Service]
ExecStart=
ExecStart=/usr/bin/prometheus-node-exporter \
  --web.listen-address=127.0.0.1:9100
```

#### 3. NGINX Exporter — Bind to Localhost

**File:** `/etc/systemd/system/prometheus-nginx-exporter.service.d/override.conf` (or wherever the nginx exporter service is defined)  
**Action:**
```ini
[Service]
ExecStart=
ExecStart=/usr/bin/nginx-prometheus-exporter \
  --nginx.scrape-uri=http://127.0.0.1/stub_status \
  --web.listen-address=127.0.0.1:9113
```

#### 4. SSH Hardening

**File:** `/etc/ssh/sshd_config`  
**Changes:**
```
PermitRootLogin no
PasswordAuthentication no          # Key-only (verify key exists first!)
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
AllowGroups ssh-users              # Create this group first
```

**Prerequisite steps (run in order):**
```bash
# 1. Verify SSH key auth works for non-root user
ssh -i <key> <user>@<server> "echo ok"

# 2. Add user to ssh-users group
groupadd ssh-users
usermod -aG ssh-users <your-user>

# 3. Test SSH access in a SEPARATE terminal
# 4. ONLY THEN restart sshd
systemctl restart sshd
```

#### 5. Install auditd

```bash
apt-get install -y auditd audispd-plugins
```

**File:** `/etc/audit/rules.d/atlas-security.rules`
```bash
# Atlas Security Observatory — audit rules

# Monitor authentication events
-w /var/log/auth.log -p wa -k auth_log
-w /var/log/fail2ban.log -p wa -k fail2ban_log

# Monitor SSH config changes
-w /etc/ssh/sshd_config -p wa -k sshd_config

# Monitor nftables/firewall changes
-w /etc/nftables.conf -p wa -k nftables_config

# Monitor user/group changes
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k sudoers

# Monitor privilege escalation
-w /usr/bin/sudo -p x -k privilege_escalation
-w /usr/bin/su -p x -k privilege_escalation

# Monitor system startup scripts
-w /etc/systemd/ -p wa -k systemd_config

# Monitor ATLAS security database
-w /opt/atlas/security.db -p wa -k atlas_security_db

# Monitor atlas security directory
-w /opt/atlas/security/ -p wa -k atlas_security_code

# Make rules immutable (requires reboot to change)
-e 2
```

Enable and start:
```bash
systemctl enable auditd
systemctl start auditd
augenrules --load
```

#### 6. Configure journald for Persistent Storage

**File:** `/etc/systemd/journald.conf`
```ini
[Journal]
Storage=persistent
SystemMaxUse=200M
SystemMaxFileSize=20M
MaxRetentionSec=30day
MaxFileSec=1day
ForwardToSyslog=no
Compress=yes
```

```bash
mkdir -p /var/log/journal
systemctl restart systemd-journald
```

#### 7. Install sqlite3 CLI

```bash
apt-get install -y sqlite3
```

#### 8. nftables Logging Enhancement

Verify existing nftables rules log dropped packets. The current setup has `log prefix "NFT DROP: "`. This is sufficient — the collector (Phase 3) will read from journald where these kernel messages land.

**Verify current nft rules include logging:**
```bash
nft list ruleset | grep -A2 "log"
```

### Files Summary — Phase 0

| File | Action | Purpose |
|------|--------|---------|
| `/etc/systemd/system/prometheus.service.d/override.conf` | Create | Bind Prometheus to localhost:9090 |
| `/etc/systemd/system/prometheus-node-exporter.service.d/override.conf` | Create | Bind Node Exporter to localhost:9100 |
| `/etc/systemd/system/prometheus-nginx-exporter.service.d/override.conf` | Create | Bind NGINX Exporter to localhost:9113 |
| `/etc/ssh/sshd_config` | Modify | Disable root login, harden SSH |
| `/etc/audit/rules.d/atlas-security.rules` | Create | Audit rules for security events |
| `/etc/systemd/journald.conf` | Modify | Enable persistent storage |

### Testing — Phase 0

```bash
# 1. Verify exporters only bind to localhost
ss -tlnp | grep -E '9090|9100|9113'
# Expected: All show 127.0.0.1:port, NOT 0.0.0.0:port

# 2. Verify Prometheus still scrapes correctly
curl -s http://127.0.0.1:9090/api/v1/targets | python3 -m json.tool
# Expected: All targets UP

# 3. Verify SSH root login is denied
ssh root@<server-ip> "echo test"
# Expected: Permission denied

# 4. Verify SSH key auth still works
ssh -i <key> <user>@<server-ip> "echo test"
# Expected: "test"

# 5. Verify auditd is running
auditctl -l
# Expected: List of rules matches atlas-security.rules

# 6. Verify journald persists
journalctl --list-boots
ls -la /var/log/journal/

# 7. Verify Grafana still works through nginx proxy
curl -s -o /dev/null -w "%{http_code}" http://localhost/grafana/
# Expected: 200 or 302 (redirect to login)
```

### Rollback — Phase 0

```bash
# Remove exporter overrides
rm /etc/systemd/system/prometheus.service.d/override.conf
rm /etc/systemd/system/prometheus-node-exporter.service.d/override.conf
rm /etc/systemd/system/prometheus-nginx-exporter.service.d/override.conf
systemctl daemon-reload
systemctl restart prometheus prometheus-node-exporter prometheus-nginx-exporter

# Restore SSH root login (CAUTION: ensure password or key auth works first)
sed -i 's/^PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config
systemctl restart sshd

# Remove auditd rules
rm /etc/audit/rules.d/atlas-security.rules
augenrules --load

# Restore journald defaults
sed -i 's/^Storage=persistent/Storage=auto/' /etc/systemd/journald.conf
systemctl restart systemd-journald
```

---

## Phase 1: Infrastructure Monitoring Documentation

### Goal

Document the existing monitoring stack, provision Grafana datasources and dashboards, and establish a working baseline before adding security components.

### Files to Create/Modify

#### 1. Grafana Datasource Provisioning

**File:** `/etc/atlas/grafana/provisioning/datasources/prometheus.yaml`
```yaml
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://127.0.0.1:9090
    isDefault: true
    editable: false
    jsonData:
      timeInterval: "15s"
```

#### 2. Grafana Dashboard Provider

**File:** `/etc/atlas/grafana/provisioning/dashboards/dashboard.yml`
```yaml
apiVersion: 1

providers:
  - name: Atlas Dashboards
    orgId: 1
    folder: Atlas
    type: file
    disableDeletion: false
    editable: true
    updateIntervalSeconds: 30
    allowUiUpdates: true
    options:
      path: /etc/atlas/grafana/provisioning/dashboards
      foldersFromFilesStructure: false
```

#### 3. Infrastructure Dashboard

**File:** `/etc/atlas/grafana/provisioning/dashboards/infrastructure.json`

This is a Grafana dashboard JSON with the following panels:

| Panel | Type | Query |
|-------|------|-------|
| CPU Usage | Gauge + Time Series | `100 - (avg(rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)` |
| Memory Usage | Gauge + Time Series | `(1 - node_memory_MemAvailable_bytes/node_memory_MemTotal_bytes) * 100` |
| Disk Usage | Gauge | `(1 - node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"}) * 100` |
| Network RX/TX | Time Series | `rate(node_network_receive_bytes_total[5m])`, `rate(node_network_transmit_bytes_total[5m])` |
| Uptime | Stat | `time() - node_boot_time_seconds` |
| NGINX Active Connections | Stat | `nginx_connections_active` |
| NGINX Request Rate | Time Series | `rate(nginx_http_requests_total[5m])` |
| NGINX 4xx/5xx Rate | Time Series | `rate(nginx_http_responses_total{code=~"4.."}[5m])`, `rate(nginx_http_responses_total{code=~"5.."}[5m])` |
| System Load | Time Series | `node_load1`, `node_load5`, `node_load15` |
| Open File Descriptors | Time Series | `node_filefd_allocated` |

Dashboard JSON should include:
- `uid`: `atlas-infrastructure`
- `title`: `Atlas Infrastructure`
- `tags`: `["atlas", "infrastructure"]`
- Refresh: 15s
- Time range: last 1 hour default
- Templating variable for hostname if multi-host ever needed

#### 4. NGINX Stub Status Config

**Verify** or create the NGINX stub_status endpoint that the NGINX exporter scrapes:

**File:** `/etc/nginx/conf.d/stub_status.conf`
```nginx
server {
    listen 127.0.0.1:8088;
    server_name _;

    location /stub_status {
        stub_status;
        allow 127.0.0.1;
        deny all;
    }
}
```

#### 5. Documentation

**File:** `/opt/atlas/docs/monitoring-stack.md`

Document:
- All scrape targets and their endpoints
- Grafana admin credentials (where stored)
- How to add new dashboards
- How to verify scraping is healthy
- Prometheus retention and storage paths
- Backup strategy for Prometheus data

### Testing — Phase 1

```bash
# 1. Verify Grafana datasource is provisioned
curl -s -u admin:admin http://127.0.0.1:3000/api/datasources
# Expected: Prometheus datasource listed

# 2. Verify Grafana dashboard is provisioned
curl -s -u admin:admin http://127.0.0.1:3000/api/search?query=Atlas
# Expected: "Atlas Infrastructure" dashboard listed

# 3. Verify Prometheus targets are all UP
curl -s http://127.0.0.1:9090/api/v1/targets | python3 -c "
import sys, json
data = json.load(sys.stdin)
for t in data['data']['activeTargets']:
    print(f\"{t['labels']['job']}: {t['health']}\")
"
# Expected: all "up"

# 4. Verify nginx stub_status
curl -s http://127.0.0.1:8088/stub_status
# Expected: nginx status output with active connections
```

### Rollback — Phase 1

```bash
# Remove provisioned files
rm /etc/atlas/grafana/provisioning/datasources/prometheus.yaml
rm /etc/atlas/grafana/provisioning/dashboards/dashboard.yml
rm /etc/atlas/grafana/provisioning/dashboards/infrastructure.json
rm /etc/nginx/conf.d/stub_status.conf

# Restart services
systemctl restart grafana-server nginx
```

---

## Phase 2: Centralized Logging

### Goal

Audit what the system already logs, configure log sources for security relevance, and establish the log feeds that Phase 3 will consume.

### What Journald Already Captures

| Source | Unit/Tag | What It Contains |
|--------|----------|------------------|
| SSH | `_SYSTEMD_UNIT=sshd.service` | Login attempts, key auth, session opens/closes |
| NGINX | stdout/stderr via systemd | Access logs (if started via systemd) |
| Fail2Ban | `_SYSTEMD_UNIT=fail2ban.service` | Ban/unban actions, jail activations |
| nftables | kernel (prefix `NFT DROP:`) | Dropped packet log lines in kern.log/journal |
| Systemd | `MESSAGE_ID=...` | Service start/stop/restart, failures |
| Kernel | kernel subsystem | Security messages, OOM, module loads |

### What Needs Supplementary Collection

NGINX access/error logs are best parsed from their flat files (`/var/log/nginx/access.log`, `/var/log/nginx/error.log`) because journald stdout capture may lose structure. The collector will tail both journald AND flat log files.

### NGINX Log Format Enhancement

**File:** `/etc/nginx/conf.d/log-format-security.conf`
```nginx
# Security-enhanced log format for atlas
# Existing main format is preserved; this adds a second log

log_format atlas_security
    '$remote_addr - $remote_user [$time_local] '
    '"$request" $status $body_bytes_sent '
    '"$http_referer" "$http_user_agent" '
    'rt=$request_time '
    'uct=$upstream_connect_time '
    'uht=$upstream_header_time '
    'urt=$upstream_response_time '
    'ssl_protocol=$ssl_protocol '
    'ssl_cipher=$ssl_cipher';

# Apply to access log (add alongside existing log)
# The existing access_log directive stays; this adds a second file
access_log /var/log/nginx/atlas_access.log atlas_security;
```

**Important:** Do NOT replace the existing log format. Add the new format as a secondary log. Both the original `/var/log/nginx/access.log` and the new `/var/log/nginx/atlas_access.log` will exist. The collector reads from `atlas_access.log`.

### Log File Map for the Collector

| Log File / Source | Format | Collection Method |
|-------------------|--------|-------------------|
| `/var/log/nginx/atlas_access.log` | atlas_security format | File tail (inotify-like) |
| `/var/log/nginx/error.log` | nginx error format | File tail |
| `/var/log/fail2ban.log` | fail2ban log format | File tail |
| `journald` (all units) | JSON | `systemd.journal` module or `journalctl --follow --output=json` |
| `kernel` (nftables) | message with prefix `NFT DROP:` | journald filter `_COMM=kernel` |

### Journald Filters for Security-Relevant Entries

The collector will use these journald match strings:

```
_SYSTEMD_UNIT=sshd.service                    # SSH events
_SYSTEMD_UNIT=fail2ban.service                # Fail2Ban events
_SYSTEMD_UNIT=nginx.service                   # NGINX lifecycle
_COMM=kernel                                   # Kernel messages (nftables)
_SYSTEMD_UNIT=atlas-collector.service          # Self-monitoring
_SYSTEMD_UNIT=atlas-detector.service           # Self-monitoring
```

### Logrotate for Security Logs

**File:** `/etc/logrotate.d/atlas-security`
```
/var/log/nginx/atlas_access.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 www-data adm
    sharedscripts
    postrotate
        [ -f /var/run/nginx.pid ] && kill -USR1 $(cat /var/run/nginx.pid) || true
    endscript
}

/opt/atlas/security.db {
    # SQLite doesn't need rotation, but we backup
    # Handled by a separate cron script, not logrotate
    daily
    rotate 7
    copy
    compress
}
```

### SQLite Database Backup Script

**File:** `/opt/atlas/security/backup.sh`
```bash
#!/bin/bash
# Backup security.db daily
# Called by cron, not logrotate

DB="/opt/atlas/security.db"
BACKUP_DIR="/opt/atlas/backups/security"
DATE=$(date +%Y%m%d)
MAX_BACKUPS=7

mkdir -p "$BACKUP_DIR"

# Use sqlite3 .backup for consistent snapshot
sqlite3 "$DB" ".backup '$BACKUP_DIR/security-$DATE.db'"

# Cleanup old backups
find "$BACKUP_DIR" -name "security-*.db" -mtime +$MAX_BACKUPS -delete
```

### Files Summary — Phase 2

| File | Action | Purpose |
|------|--------|---------|
| `/etc/nginx/conf.d/log-format-security.conf` | Create | Security-enhanced NGINX log format |
| `/etc/logrotate.d/atlas-security` | Create | Log rotation for security logs and DB backup |
| `/opt/atlas/security/backup.sh` | Create | SQLite backup script |
| `/var/log/nginx/atlas_access.log` | Auto-created by NGINX | New log file (after NGINX reload) |

### Testing — Phase 2

```bash
# 1. Reload nginx to pick up new log format
nginx -t && systemctl reload nginx

# 2. Make a request to generate a log entry
curl -s http://localhost/ > /dev/null

# 3. Verify atlas_access.log has entries with security fields
tail -1 /var/log/nginx/atlas_access.log
# Expected: Log line with ssl_protocol, ssl_cipher, etc.

# 4. Verify fail2ban log exists
ls -la /var/log/fail2ban.log

# 5. Verify journald captures SSH events
journalctl -u sshd.service --since "1 hour ago" --no-pager | head -5

# 6. Verify nftables drops appear in journal
journalctl -k --since "1 hour ago" | grep "NFT DROP" | head -5

# 7. Verify logrotate config is valid
logrotate -d /etc/logrotate.d/atlas-security 2>&1 | head -20

# 8. Test backup script
bash /opt/atlas/security/backup.sh
ls -la /opt/atlas/backups/security/
```

### Rollback — Phase 2

```bash
# Remove NGINX security log format
rm /etc/nginx/conf.d/log-format-security.conf
# Remove the atlas_security access_log line from main nginx config if added there
systemctl reload nginx

# Remove logrotate config
rm /etc/logrotate.d/atlas-security

# Remove backup script
rm /opt/atlas/security/backup.sh
rm -rf /opt/atlas/backups/security/
```

---

## Phase 3: Security Event Collection

### Goal

Build and deploy the event collection daemon that ingests security-relevant events from all sources into a unified SQLite database.

### Shared Infrastructure

#### Configuration

**File:** `/etc/atlas/security.ini`
```ini
[database]
path = /opt/atlas/security.db
wal_mode = true
busy_timeout_ms = 5000
batch_size = 50
flush_interval_sec = 5

[collector]
queue_max_size = 10000
log_resume_file = /opt/atlas/security/collector_cursor.json
log_dir = /var/log/nginx
fail2ban_log = /var/log/fail2ban.log
journald_follow = true

[journald]
# Unit filters (pipe-separated for journalctl)
units = sshd.service,fail2ban.service,nginx.service,atlas-collector.service,atlas-detector.service
# Kernel messages (for nftables log prefix)
include_kernel = true
kernel_prefix = NFT DROP

[nginx]
access_log = /var/log/nginx/atlas_access.log
error_log = /var/log/nginx/error.log
# Log format fields (order matters for parsing)
# Format: $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" rt=...
log_format = atlas_security
```

#### Configuration Loader

**File:** `/opt/atlas/security/config.py`
```python
"""
Configuration loader for Atlas Security Observatory.
Reads /etc/atlas/security.ini, provides typed access.
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
    units: list[str] = field(default_factory=lambda: [
        "sshd.service", "fail2ban.service", "nginx.service",
        "atlas-collector.service", "atlas-detector.service"
    ])
    include_kernel: bool = True
    kernel_prefix: str = "NFT DROP"

@dataclass(frozen=True)
class Config:
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    collector: CollectorConfig = field(default_factory=CollectorConfig)
    journald: JournaldConfig = field(default_factory=JournaldConfig)

def load_config(path: Path = CONFIG_PATH) -> Config:
    """Load configuration from INI file, falling back to defaults."""
    # ... implementation reads INI, maps to dataclasses ...
    pass
```

#### Shared Database Helpers

**File:** `/opt/atlas/security/common.py`
```python
"""
Shared utilities for Atlas Security Observatory.
Database helpers, logging setup, graceful shutdown.
"""
import sqlite3
import signal
import logging
from pathlib import Path
from contextlib import contextmanager
from typing import Generator

logger = logging.getLogger("atlas-security")

@contextmanager
def get_db(db_path: str, wal_mode: bool = True, busy_timeout_ms: int = 5000) -> Generator[sqlite3.Connection, None, None]:
    """
    Context manager for SQLite connections.
    Enables WAL mode, sets busy timeout, ensures clean close.
    """
    conn = sqlite3.connect(db_path, timeout=busy_timeout_ms / 1000)
    conn.row_factory = sqlite3.Row
    if wal_mode:
        conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
    try:
        yield conn
        conn.commit()
    except Exception:
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
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        self.should_stop = True

def setup_logging(name: str, level: str = "INFO", log_file: str | None = None) -> logging.Logger:
    """Configure structured logging for a daemon."""
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))
    fmt = logging.Formatter(
        "%(asctime)s [%(name)s] %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    handler = logging.StreamHandler()
    handler.setFormatter(fmt)
    logger.addHandler(handler)
    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    return logger
```

### SQLite Schema

**File:** `/opt/atlas/security/schema.py`
```python
"""
SQLite schema definitions for Atlas Security Observatory.
All DDL and migration logic lives here.
"""
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
    timestamp TEXT NOT NULL,              -- ISO 8601: '2026-08-18T14:32:05Z'
    hostname TEXT NOT NULL,               -- 'atlas' (from socket.gethostname())
    source TEXT NOT NULL,                 -- 'journald', 'nginx', 'fail2ban', 'nftables', 'kernel'
    event_type TEXT NOT NULL,             -- 'ssh_auth_fail', 'nginx_4xx', 'nft_drop', etc.
    severity TEXT NOT NULL DEFAULT 'info', -- 'info', 'low', 'medium', 'high', 'critical'
    src_ip TEXT,                          -- Source IP address
    dst_ip TEXT,                          -- Destination IP address
    src_port INTEGER,                     -- Source port
    dst_port INTEGER,                     -- Destination port
    username TEXT,                        -- Auth username attempted
    process TEXT,                         -- Generating process name
    message TEXT,                         -- Raw or formatted message
    raw_log TEXT,                         -- Original unparsed log line
    correlation_id TEXT,                  -- For grouping related events
    metadata_json TEXT,                   -- Extensible JSON blob for source-specific data
    collected_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Detection findings
CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,              -- When detection fired
    rule_name TEXT NOT NULL,              -- 'ssh_brute_force', 'port_scan', etc.
    severity TEXT NOT NULL,               -- 'low', 'medium', 'high', 'critical'
    confidence REAL NOT NULL DEFAULT 0.0, -- 0.0 to 1.0
    hostname TEXT NOT NULL,
    src_ip TEXT,                          -- Primary source IP (if applicable)
    explanation TEXT,                     -- Human-readable explanation
    related_event_ids TEXT,               -- JSON array of event IDs
    evidence TEXT,                        -- JSON object with supporting data
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Alert lifecycle management
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    detection_id INTEGER NOT NULL REFERENCES detections(id),
    status TEXT NOT NULL DEFAULT 'new',   -- 'new','acknowledged','investigating','resolved','dismissed'
    severity TEXT NOT NULL,               -- Copied from detection at creation time
    title TEXT NOT NULL,                  -- Short human-readable title
    description TEXT,                     -- Detailed description
    src_ip TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    acknowledged_at TEXT,
    resolved_at TEXT
);

-- Future: remediation actions log
CREATE TABLE IF NOT EXISTS remediation_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER REFERENCES alerts(id),
    action_type TEXT NOT NULL,            -- 'block_ip', 'ban_user', 'notify', etc.
    action_details TEXT,                  -- JSON details of action taken
    result TEXT,                          -- 'success', 'failure', 'pending'
    performed_at TEXT NOT NULL DEFAULT (datetime('now')),
    performed_by TEXT NOT NULL DEFAULT 'system' -- 'system', 'api', 'manual'
);

-- Indexes for query performance
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_correlation_id ON events(correlation_id);
CREATE INDEX IF NOT EXISTS idx_events_collected_at ON events(collected_at);

CREATE INDEX IF NOT EXISTS idx_detections_timestamp ON detections(timestamp);
CREATE INDEX IF NOT EXISTS idx_detections_rule_name ON detections(rule_name);
CREATE INDEX IF NOT EXISTS idx_detections_severity ON detections(severity);
CREATE INDEX IF NOT EXISTS idx_detections_src_ip ON detections(src_ip);

CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_detection_id ON alerts(detection_id);

CREATE INDEX IF NOT EXISTS idx_remediation_log_alert_id ON remediation_log(alert_id);

-- Event types reference (for documentation and validation)
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
    ('nft_drop_invalid',    'nftables',    'nftables invalid packet drop'),
    ('fail2ban_ban',        'fail2ban',    'Fail2Ban IP ban'),
    ('fail2ban_unban',      'fail2ban',    'Fail2Ban IP unban'),
    ('fail2ban_jail',       'fail2ban',    'Fail2Ban jail activation'),
    ('service_start',       'journald',    'Systemd service started'),
    ('service_stop',        'journald',    'Systemd service stopped'),
    ('service_failed',      'journald',    'Systemd service failed'),
    ('service_restart',     'journald',    'Systemd service restarted'),
    ('kernel_security',     'kernel',      'Kernel security message'),
    ('audit_event',         'auditd',      'Audit daemon event');
"""

def init_schema(conn: sqlite3.Connection) -> None:
    """Apply schema DDL to a fresh database."""
    conn.executescript(SCHEMA_DDL)
    conn.execute(
        "INSERT OR IGNORE INTO schema_version (version) VALUES (?)",
        (SCHEMA_VERSION,)
    )
    conn.commit()

def ensure_schema(db_path: str) -> None:
    """Create database and schema if they don't exist."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    # Check if tables exist
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='events'"
    )
    if cursor.fetchone() is None:
        init_schema(conn)
    conn.close()
```

### Event Type Definitions

**File:** `/opt/atlas/security/models.py`
```python
"""
Pydantic models for security events, detections, and alerts.
"""
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional
from enum import Enum

class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AlertStatus(str, Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"

class SecurityEvent(BaseModel):
    timestamp: datetime
    hostname: str
    source: str                      # 'journald', 'nginx', 'fail2ban', 'nftables', 'kernel'
    event_type: str                  # from event_types table
    severity: Severity = Severity.INFO
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    username: Optional[str] = None
    process: Optional[str] = None
    message: Optional[str] = None
    raw_log: Optional[str] = None
    correlation_id: Optional[str] = None
    metadata: dict = Field(default_factory=dict)

    def to_db_tuple(self) -> tuple:
        """Convert to tuple for SQLite INSERT."""
        import json
        return (
            self.timestamp.isoformat(),
            self.hostname,
            self.source,
            self.event_type,
            self.severity.value,
            self.src_ip,
            self.dst_ip,
            self.src_port,
            self.dst_port,
            self.username,
            self.process,
            self.message,
            self.raw_log,
            self.correlation_id,
            json.dumps(self.metadata) if self.metadata else None,
        )

class Detection(BaseModel):
    timestamp: datetime
    rule_name: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    hostname: str
    src_ip: Optional[str] = None
    explanation: str
    related_event_ids: list[int] = Field(default_factory=list)
    evidence: dict = Field(default_factory=dict)

class Alert(BaseModel):
    detection_id: int
    status: AlertStatus = AlertStatus.NEW
    severity: Severity
    title: str
    description: Optional[str] = None
    src_ip: Optional[str] = None
```

### Event Parsers

#### NGINX Access Log Parser

```python
"""
Parse NGINX access log lines in atlas_security format.

Format:
$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
"$http_referer" "$http_user_agent" rt=$request_time uct=$upstream_connect_time
uht=$upstream_header_time urt=$upstream_response_time
ssl_protocol=$ssl_protocol ssl_cipher=$ssl_cipher

Example:
192.168.1.50 - - [18/Aug/2026:14:32:05 +0700] "GET /api/status HTTP/1.1" 200 1234
"-" "Mozilla/5.0" rt=0.003 uct=0.001 uht=0.002 urt=0.002
ssl_protocol=TLSv1.3 ssl_cipher=TLS_AES_256_GCM_SHA384
"""
import re
from typing import Optional
from ..models import SecurityEvent, Severity
from datetime import datetime

NGINX_ACCESS_PATTERN = re.compile(
    r'(?P<src_ip>\S+) - (?P<remote_user>\S+) '
    r'\[(?P<time_local>[^\]]+)\] '
    r'"(?P<request>[^"]*)" '
    r'(?P<status>\d{3}) '
    r'(?P<body_bytes>\d+) '
    r'"(?P<referer>[^"]*)" '
    r'"(?P<user_agent>[^"]*)"'
)

# Enriched format (optional trailing fields)
NGINX_ENRICHED_PATTERN = re.compile(
    r'rt=(?P<request_time>[\d.]+)'
    r'(?:\s+uct=(?P<upstream_connect>[\d.]+))?'
    r'(?:\s+uht=(?P<upstream_header>[\d.]+))?'
    r'(?:\s+urt=(?P<upstream_response>[\d.]+))?'
    r'(?:\s+ssl_protocol=(?P<ssl_protocol>\S+))?'
    r'(?:\s+ssl_cipher=(?P<ssl_cipher>\S+))?'
)

REQUEST_METHOD_PATTERN = re.compile(r'^(?P<method>\S+)\s+(?P<path>\S+)')

def parse_nginx_access_line(line: str, hostname: str) -> list[SecurityEvent]:
    """Parse a single NGINX access log line into SecurityEvent(s)."""
    # Returns 0 or 1 events (only 4xx/5xx are security-relevant, or all if needed)
    # Implementation details...
    pass

def classify_nginx_status(status_code: int) -> tuple[Optional[SecurityEvent], Optional[str]]:
    """Determine if a status code warrants a security event."""
    if 400 <= status_code < 500:
        return Severity.LOW, "nginx_4xx"
    elif 500 <= status_code < 600:
        return Severity.MEDIUM, "nginx_5xx"
    return None, None
```

#### Fail2Ban Log Parser

```python
"""
Parse Fail2Ban log entries.

Format examples:
2026-08-18 14:32:05,123 fail2ban.actions[1234]: NOTICE  [sshd] Ban 192.168.1.50
2026-08-18 14:32:05,123 fail2ban.actions[1234]: NOTICE  [sshd] Unban 192.168.1.50
2026-08-18 14:32:05,123 fail2ban.filter[1234]: INFO    [sshd] Found 192.168.1.50 - 2026-08-18 14:32:05
"""
import re
from typing import Optional
from ..models import SecurityEvent, Severity

F2B_BAN_PATTERN = re.compile(
    r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2},\d{3})\s+'
    r'fail2ban\.actions\[\d+\]:\s+'
    r'(?P<level>\w+)\s+'
    r'\[(?P<jail>\w+)\]\s+'
    r'(?P<action>Ban|Unban)\s+'
    r'(?P<ip>\S+)'
)

F2B_FILTER_PATTERN = re.compile(
    r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2},\d{3})\s+'
    r'fail2ban\.filter\[\d+\]:\s+'
    r'(?P<level>\w+)\s+'
    r'\[(?P<jail>\w+)\]\s+'
    r'Found\s+'
    r'(?P<ip>\S+)'
)

def parse_fail2ban_line(line: str, hostname: str) -> Optional[SecurityEvent]:
    """Parse a single fail2ban log line into a SecurityEvent."""
    # Implementation details...
    pass
```

#### Journald Parser

```python
"""
Parse journald JSON entries for security-relevant events.
Uses systemd.journal module or journalctl --follow --output=json.
"""
import json
from typing import Optional, Generator
from ..models import SecurityEvent, Severity

# For direct journal reading (preferred if systemd.journal is available):
# import systemd.journal

# Fallback: subprocess journalctl --follow --output=json

def parse_journald_entry(entry: dict, hostname: str) -> list[SecurityEvent]:
    """
    Parse a journald JSON entry into zero or more SecurityEvents.
    
    Handles:
    - sshd.service → SSH auth events
    - fail2ban.service → Fail2Ban events
    - nginx.service → NGINX lifecycle events
    - kernel → nftables DROP events (via "NFT DROP" prefix)
    - Any service → start/stop/failed lifecycle events
    """
    unit = entry.get("_SYSTEMD_UNIT", "")
    comm = entry.get("_COMM", "")
    message = entry.get("MESSAGE", "")
    timestamp = entry.get("__REALTIME_TIMESTAMP", "")
    
    events = []
    
    if unit == "sshd.service":
        events.extend(_parse_ssh_event(entry, hostname))
    elif comm == "kernel" and "NFT DROP" in message:
        events.append(_parse_nftables_event(entry, hostname))
    elif unit.startswith("atlas-"):
        pass  # Skip own service logs to avoid feedback loop
    elif message:
        events.append(_parse_generic_systemd_event(entry, hostname))
    
    return events

def _parse_ssh_event(entry: dict, hostname: str) -> list[SecurityEvent]:
    """Extract SSH authentication events from journald."""
    # Matches patterns like:
    # "Failed password for root from 192.168.1.50 port 22 ssh2"
    # "Accepted publickey for user from 192.168.1.50 port 22 ssh2"
    # "Disconnected from authenticating user root 192.168.1.50 port 22"
    pass

def _parse_nftables_event(entry: dict, hostname: str) -> SecurityEvent:
    """
    Extract nftables DROP events from kernel log.
    Message format: "NFT DROP: IN=eth0 OUT= MAC=... SRC=1.2.3.4 DST=5.6.7.8 
                     LEN=... TTL=... ID=... PROTO=TCP SPT=... DPT=443 ..."
    """
    pass

def _parse_generic_systemd_event(entry: dict, hostname: str) -> Optional[SecurityEvent]:
    """
    Parse service lifecycle events (start/stop/failed).
    Only creates events for state changes, not every log line.
    """
    pass
```

### Cursor Management (Resume from Last Position)

```python
"""
Track file read positions for graceful restart.
Stores byte offset for each tailed file.
"""
import json
from pathlib import Path
from typing import Optional

class CursorStore:
    """Persist and restore read positions for log tailing."""
    
    def __init__(self, path: str):
        self.path = Path(path)
        self._positions: dict[str, int] = {}
        self._load()
    
    def _load(self) -> None:
        if self.path.exists():
            with open(self.path) as f:
                self._positions = json.load(f)
    
    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, 'w') as f:
            json.dump(self._positions, f)
    
    def get(self, source: str) -> Optional[int]:
        return self._positions.get(source)
    
    def set(self, source: str, position: int) -> None:
        self._positions[source] = position
```

### Collector Daemon

**File:** `/opt/atlas/security/collector.py`
```python
#!/usr/bin/env python3
"""
Atlas Security Observatory — Event Collector Daemon

Reads security-relevant events from:
1. systemd journal (SSH, Fail2Ban, kernel/nftables, service lifecycle)
2. NGINX access/error log files
3. Fail2Ban log file

Writes normalized events to SQLite in batches.

Architecture:
- Event-driven, not polling
- Bounded in-memory queue (drops with counter if full)
- Batch writes (every N events or every M seconds)
- Graceful restart via signal handlers and cursor persistence
"""
import os
import sys
import time
import json
import socket
import logging
import subprocess
from pathlib import Path
from typing import Optional
from collections import deque

from .config import load_config, Config
from .common import get_db, GracefulShutdown, setup_logging
from .schema import ensure_schema
from .models import SecurityEvent

# Parsers (from parser modules above)
from .parsers.nginx import parse_nginx_access_line
from .parsers.fail2ban import parse_fail2ban_line
from .parsers.journald import parse_journald_entry, create_journal_reader

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
        self.queue: deque[SecurityEvent] = deque(
            maxlen=config.collector.queue_max_size
        )
        self.events_dropped = 0
        self.events_collected = 0
        self.last_flush = time.time()
    
    def run(self) -> None:
        """Main daemon loop."""
        logger.info("Atlas Collector starting...")
        
        # Ensure database exists
        ensure_schema(self.config.database.path)
        
        # Initialize log readers
        journal_reader = None
        if self.config.collector.journald_follow:
            journal_reader = create_journal_reader(self.config)
        
        # Open file handles for log tailing
        nginx_handle = self._open_log_tailed(
            self.config.collector.log_dir + "/atlas_access.log"
        )
        fail2ban_handle = self._open_log_tailed(
            self.config.collector.fail2ban_log
        )
        
        logger.info("Collector running. Waiting for events...")
        
        while not self.shutdown.should_stop:
            # 1. Read from journal (blocks until new entry)
            if journal_reader:
                self._drain_journal(journal_reader)
            
            # 2. Read new lines from NGINX log
            self._drain_file(nginx_handle, "nginx", parse_nginx_access_line)
            
            # 3. Read new lines from fail2ban log
            self._drain_file(fail2ban_handle, "fail2ban", parse_fail2ban_line)
            
            # 4. Flush if batch ready
            self._maybe_flush()
        
        # Final flush before exit
        self._flush()
        self._save_cursors()
        logger.info(
            f"Collector stopped. Collected: {self.events_collected}, "
            f"Dropped: {self.events_dropped}"
        )
    
    def _drain_journal(self, reader) -> None:
        """Read all pending journal entries, non-blocking after initial drain."""
        # Implementation: use journal.next() with timeout
        pass
    
    def _drain_file(self, handle, source: str, parser) -> None:
        """Read new lines from a tailed file."""
        # Use saved cursor position, read new bytes, parse lines
        pass
    
    def _enqueue(self, event: SecurityEvent) -> None:
        """Add event to bounded queue."""
        try:
            self.queue.append(event)
            self.events_collected += 1
        except IndexError:
            self.events_dropped += 1
    
    def _maybe_flush(self) -> None:
        """Flush queue to SQLite if batch size or time threshold reached."""
        now = time.time()
        db_config = self.config.database
        if (
            len(self.queue) >= db_config.batch_size
            or (now - self.last_flush) >= db_config.flush_interval_sec
        ):
            self._flush()
    
    def _flush(self) -> None:
        """Write all queued events to SQLite in a single transaction."""
        if not self.queue:
            return
        
        events_to_write = list(self.queue)
        self.queue.clear()
        
        with get_db(self.config.database.path) as conn:
            conn.executemany(
                BATCH_INSERT_SQL,
                [e.to_db_tuple() for e in events_to_write]
            )
        
        self.last_flush = time.time()
        logger.debug(f"Flushed {len(events_to_write)} events to database")
    
    def _open_log_tailed(self, path: str) -> Optional[dict]:
        """Open a log file for tailing, seek to last known position."""
        # Returns handle dict with file object and metadata
        pass
    
    def _save_cursors(self) -> None:
        """Persist current file positions for resume on restart."""
        pass

def main():
    config = load_config()
    setup_logging("atlas-collector", log_file="/var/log/atlas-collector.log")
    collector = EventCollector(config)
    collector.run()

if __name__ == "__main__":
    main()
```

### Parser Subpackage

**Files to create:**
```
/opt/atlas/security/parsers/
├── __init__.py
├── nginx.py       # NGINX access log parser (from above)
├── fail2ban.py    # Fail2Ban log parser (from above)
└── journald.py    # Journald parser (from above)
```

### Systemd Service

**File:** `/etc/systemd/system/atlas-collector.service`
```ini
[Unit]
Description=Atlas Security Observatory - Event Collector
After=network.target systemd-journald.service
Wants=systemd-journald.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/atlas/security/collector.py
WorkingDirectory=/opt/atlas/security
Restart=always
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=5

# Security hardening
User=atlas-security
Group=atlas-security
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/opt/atlas/security.db /opt/atlas/security/ /var/log/ /opt/atlas/backups
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
MemoryMax=50M
CPUQuota=10%

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=atlas-collector

[Install]
WantedBy=multi-user.target
```

### Service User

```bash
# Create dedicated service user
useradd --system --no-create-home --shell /usr/sbin/nologin atlas-security

# Grant read access to log files
usermod -aG adm atlas-security
# adm group owns /var/log/ files on Debian

# Grant ownership of security database and directory
chown atlas-security:atlas-security /opt/atlas/security.db
chown -R atlas-security:atlas-security /opt/atlas/security/
```

### Files Summary — Phase 3

| File | Action | Purpose |
|------|--------|---------|
| `/etc/atlas/security.ini` | Create | Central configuration |
| `/opt/atlas/security/__init__.py` | Create | Python package |
| `/opt/atlas/security/config.py` | Create | Configuration loader |
| `/opt/atlas/security/common.py` | Create | Shared utilities |
| `/opt/atlas/security/schema.py` | Create | Database schema DDL |
| `/opt/atlas/security/models.py` | Create | Pydantic data models |
| `/opt/atlas/security/collector.py` | Create | Event collector daemon |
| `/opt/atlas/security/parsers/__init__.py` | Create | Parser package |
| `/opt/atlas/security/parsers/nginx.py` | Create | NGINX log parser |
| `/opt/atlas/security/parsers/fail2ban.py` | Create | Fail2Ban log parser |
| `/opt/atlas/security/parsers/journald.py` | Create | Journald parser |
| `/etc/systemd/system/atlas-collector.service` | Create | Systemd unit file |

### Testing — Phase 3

```bash
# 1. Verify database schema was created
sqlite3 /opt/atlas/security.db ".tables"
# Expected: alerts detections events event_types remediation_log schema_version

sqlite3 /opt/atlas/security.db "SELECT * FROM event_types LIMIT 5;"
# Expected: rows with event types

# 2. Generate test events
# SSH auth failure (from another terminal):
ssh baduser@localhost
# NGINX 404:
curl http://localhost/nonexistent
# Fail2Ban ban (may need to trigger with enough failures):
for i in $(seq 1 10); do ssh baduser@localhost 2>/dev/null; done

# 3. Wait for flush interval (5 seconds max) then check
sleep 10
sqlite3 /opt/atlas/security.db "SELECT COUNT(*) FROM events;"
# Expected: > 0

sqlite3 /opt/atlas/security.db "SELECT source, event_type, COUNT(*) FROM events GROUP BY source, event_type;"
# Expected: counts for each source/event_type combination

# 4. Verify collector is running
systemctl status atlas-collector
# Expected: active (running)

# 5. Verify service restarts cleanly
systemctl restart atlas-collector
sleep 5
systemctl status atlas-collector
# Expected: active (running), journal shows "Collector starting..." and "Collector running"

# 6. Verify resource usage
systemctl show atlas-collector -p MemoryCurrent
# Expected: < 50M

# 7. Test graceful shutdown
systemctl stop atlas-collector
journalctl -u atlas-collector --since "1 min ago" --no-pager
# Expected: "shutting down gracefully", "Flushed N events", "Collector stopped"
```

### Rollback — Phase 3

```bash
# Stop and disable service
systemctl stop atlas-collector
systemctl disable atlas-collector

# Remove all files
rm /etc/systemd/system/atlas-collector.service
rm /etc/atlas/security.ini
rm -rf /opt/atlas/security/
rm /opt/atlas/security.db

# Remove service user
userdel atlas-security

# Reload systemd
systemctl daemon-reload
```

---

## Phase 4: Detection Engine

### Goal

Build a daemon that reads new events from SQLite, applies rule-based detection logic, and writes detections and alerts to the database.

### Detection Rules

| Rule | Logic | Severity | Cooldown |
|------|-------|----------|----------|
| `ssh_brute_force` | N (>=5) failed SSH auth from same IP within T (10) minutes | high | 1 hour |
| `repeated_firewall_blocks` | N (>=10) nft_drop events from same IP within T (5) minutes | medium | 30 minutes |
| `port_scanning` | Connection attempts to >= N (5) distinct destination ports from same IP within T (2) minutes | high | 1 hour |
| `service_anomaly` | service_stop or service_failed event | medium | 15 minutes |
| `suspicious_nginx` | >= N (20) 4xx errors from same IP within T (5) minutes | low | 30 minutes |
| `auth_correlation` | SSH auth success followed by nft_drop from same IP within T (1) minute | high | 2 hours |

### Detector Daemon

**File:** `/opt/atlas/security/detector.py`
```python
#!/usr/bin/env python3
"""
Atlas Security Observatory — Detection Engine Daemon

Polls the events table for new events (via incremental ID cursor),
applies rule-based detection, writes detections and alerts.

Architecture:
- Polls every N seconds (configurable, default 10s)
- Tracks last processed event ID (cursor in DB or file)
- Each rule is a class implementing the detection interface
- Deduplication via cooldown: same rule + same source IP within cooldown → skip
- Writes to detections and alerts tables in single transaction
"""
import time
import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Optional
from collections import defaultdict

from .config import load_config
from .common import get_db, GracefulShutdown, setup_logging
from .models import Detection, Alert, Severity, AlertStatus

logger = logging.getLogger("atlas-detector")

# --- Detection Rule Interface ---

class DetectionRule(ABC):
    """Base class for detection rules."""
    
    @property
    @abstractmethod
    def name(self) -> str: ...
    
    @property
    @abstractmethod
    def cooldown_sec(self) -> int: ...
    
    @abstractmethod
    def evaluate(self, events: list[dict], conn) -> list[Detection]:
        """
        Evaluate events against this rule.
        Returns zero or more Detection objects.
        """
        pass

# --- Concrete Rules ---

class SSHBruteForceRule(DetectionRule):
    name = "ssh_brute_force"
    cooldown_sec = 3600  # 1 hour
    
    def evaluate(self, events: list[dict], conn) -> list[Detection]:
        """
        Count SSH auth failures per source IP in rolling 10-minute window.
        If count >= 5, generate detection.
        """
        # Query: SELECT src_ip, COUNT(*) as cnt
        #        FROM events
        #        WHERE event_type = 'ssh_auth_fail'
        #        AND timestamp >= datetime('now', '-10 minutes')
        #        GROUP BY src_ip
        #        HAVING cnt >= 5
        pass

class RepeatedFirewallBlocksRule(DetectionRule):
    name = "repeated_firewall_blocks"
    cooldown_sec = 1800  # 30 minutes
    
    def evaluate(self, events: list[dict], conn) -> list[Detection]:
        """
        Count nft_drop events per source IP in rolling 5-minute window.
        If count >= 10, generate detection.
        """
        pass

class PortScanningRule(DetectionRule):
    name = "port_scanning"
    cooldown_sec = 3600  # 1 hour
    
    def evaluate(self, events: list[dict], conn) -> list[Detection]:
        """
        Count distinct destination ports per source IP in rolling 2-minute window.
        If count >= 5, generate detection.
        """
        pass

class ServiceAnomalyRule(DetectionRule):
    name = "service_anomaly"
    cooldown_sec = 900  # 15 minutes
    
    def evaluate(self, events: list[dict], conn) -> list[Detection]:
        """
        Detect service_stop or service_failed events.
        """
        pass

class SuspiciousNGINXRule(DetectionRule):
    name = "suspicious_nginx"
    cooldown_sec = 1800  # 30 minutes
    
    def evaluate(self, events: list[dict], conn) -> list[Detection]:
        """
        Count 4xx responses per source IP in rolling 5-minute window.
        If count >= 20, generate detection.
        """
        pass

class AuthCorrelationRule(DetectionRule):
    name = "auth_correlation"
    cooldown_sec = 7200  # 2 hours
    
    def evaluate(self, events: list[dict], conn) -> list[Detection]:
        """
        Detect SSH auth success followed by nft_drop from same IP within 1 minute.
        This indicates a legitimate login that's then triggering firewall drops
        (possible lateral movement or compromised host).
        """
        pass

# --- Alert Deduplication ---

class AlertDeduplicator:
    """
    Prevents alert spam by tracking cooldowns.
    Stores last alert time per (rule_name, src_ip) pair.
    """
    
    def __init__(self):
        self._cooldowns: dict[tuple[str, str], datetime] = {}
    
    def should_alert(self, rule_name: str, src_ip: Optional[str], cooldown_sec: int) -> bool:
        """Check if enough time has passed since last alert for this rule+source."""
        key = (rule_name, src_ip or "__none__")
        last = self._cooldowns.get(key)
        now = datetime.utcnow()
        
        if last and (now - last).total_seconds() < cooldown_sec:
            return False
        
        self._cooldowns[key] = now
        return True

# --- Main Detector ---

class DetectionEngine:
    """Main detection engine daemon."""
    
    POLL_INTERVAL = 10  # seconds
    
    def __init__(self):
        self.shutdown = GracefulShutdown()
        self.rules: list[DetectionRule] = [
            SSHBruteForceRule(),
            RepeatedFirewallBlocksRule(),
            PortScanningRule(),
            ServiceAnomalyRule(),
            SuspiciousNGINXRule(),
            AuthCorrelationRule(),
        ]
        self.deduplicator = AlertDeduplicator()
        self.last_event_id = 0  # Cursor: last processed event ID
    
    def run(self) -> None:
        """Main daemon loop."""
        logger.info("Atlas Detector starting...")
        
        # Load cursor
        self._load_cursor()
        
        while not self.shutdown.should_stop:
            try:
                self._run_detection_cycle()
            except Exception as e:
                logger.error(f"Detection cycle error: {e}", exc_info=True)
            
            # Sleep in small increments to respond to shutdown quickly
            for _ in range(self.POLL_INTERVAL * 10):
                if self.shutdown.should_stop:
                    break
                time.sleep(0.1)
        
        self._save_cursor()
        logger.info("Detector stopped.")
    
    def _run_detection_cycle(self) -> None:
        """One pass: fetch new events, run all rules, write results."""
        with get_db(DB_PATH) as conn:
            # Fetch new events since last processed ID
            cursor = conn.execute(
                "SELECT * FROM events WHERE id > ? ORDER BY id",
                (self.last_event_id,)
            )
            new_events = [dict(row) for row in cursor.fetchall()]
            
            if not new_events:
                return
            
            logger.debug(f"Processing {len(new_events)} new events")
            
            # Run each rule
            for rule in self.rules:
                detections = rule.evaluate(new_events, conn)
                
                for detection in detections:
                    # Check cooldown
                    if not self.deduplicator.should_alert(
                        rule.name, detection.src_ip, rule.cooldown_sec
                    ):
                        logger.debug(
                            f"Cooldown active for {rule.name} from {detection.src_ip}, skipping"
                        )
                        continue
                    
                    # Write detection
                    det_id = self._write_detection(conn, detection)
                    
                    # Write alert
                    self._write_alert(conn, det_id, detection)
                    
                    logger.warning(
                        f"DETECTION: {rule.name} | severity={detection.severity.value} | "
                        f"src={detection.src_ip} | {detection.explanation}"
                    )
            
            # Update cursor
            self.last_event_id = max(e["id"] for e in new_events)
            conn.commit()
        
        self._save_cursor()
    
    def _write_detection(self, conn, detection: Detection) -> int:
        """Insert detection into database, return the new ID."""
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
            )
        )
        return cursor.lastrowid
    
    def _write_alert(self, conn, detection_id: int, detection: Detection) -> int:
        """Insert alert into database, return the new ID."""
        title = f"[{detection.severity.value.upper()}] {detection.rule_name.replace('_', ' ').title()}"
        cursor = conn.execute(
            """INSERT INTO alerts (
                detection_id, status, severity, title, description, src_ip
            ) VALUES (?, ?, ?, ?, ?, ?)""",
            (
                detection_id,
                AlertStatus.NEW.value,
                detection.severity.value,
                title,
                detection.explanation,
                detection.src_ip,
            )
        )
        return cursor.lastrowid
    
    def _load_cursor(self) -> None:
        """Load last processed event ID from cursor file."""
        cursor_file = Path("/opt/atlas/security/detector_cursor.json")
        if cursor_file.exists():
            with open(cursor_file) as f:
                data = json.load(f)
                self.last_event_id = data.get("last_event_id", 0)
    
    def _save_cursor(self) -> None:
        """Persist last processed event ID."""
        cursor_file = Path("/opt/atlas/security/detector_cursor.json")
        with open(cursor_file, 'w') as f:
            json.dump({"last_event_id": self.last_event_id}, f)

def main():
    setup_logging("atlas-detector", log_file="/var/log/atlas-detector.log")
    engine = DetectionEngine()
    engine.run()

if __name__ == "__main__":
    main()
```

### Systemd Service

**File:** `/etc/systemd/system/atlas-detector.service`
```ini
[Unit]
Description=Atlas Security Observatory - Detection Engine
After=atlas-collector.service
Wants=atlas-collector.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/atlas/security/detector.py
WorkingDirectory=/opt/atlas/security
Restart=always
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=5

# Security hardening
User=atlas-security
Group=atlas-security
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/opt/atlas/security.db /opt/atlas/security/ /opt/atlas/backups
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
MemoryMax=50M
CPUQuota=10%

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=atlas-detector

[Install]
WantedBy=multi-user.target
```

### Files Summary — Phase 4

| File | Action | Purpose |
|------|--------|---------|
| `/opt/atlas/security/detector.py` | Create | Detection engine daemon |
| `/etc/systemd/system/atlas-detector.service` | Create | Systemd unit file |
| `/opt/atlas/security/detector_cursor.json` | Auto-created | Resume cursor |

### Testing — Phase 4

```bash
# 1. Start detector
systemctl start atlas-detector
systemctl status atlas-detector
# Expected: active (running)

# 2. Generate enough SSH auth failures to trigger brute force rule
# From another machine or locally:
for i in $(seq 1 8); do
    ssh -o BatchMode=yes baduser@localhost 2>/dev/null
done

# 3. Wait for collector flush + detector cycle
sleep 15

# 4. Check detections
sqlite3 /opt/atlas/security.db "SELECT * FROM detections;"
# Expected: ssh_brute_force detection with severity=high

# 5. Check alerts
sqlite3 /opt/atlas/security.db "SELECT * FROM alerts;"
# Expected: Alert with status=new, severity=high

# 6. Verify cooldown (run same test again within 1 hour)
for i in $(seq 1 8); do
    ssh -o BatchMode=yes baduser@localhost 2>/dev/null
done
sleep 15
sqlite3 /opt/atlas/security.db "SELECT COUNT(*) FROM detections WHERE rule_name='ssh_brute_force';"
# Expected: still 1 (cooldown prevented second alert)

# 7. Verify resource usage
systemctl show atlas-detector -p MemoryCurrent
# Expected: < 50M

# 8. Verify nft_drop detection with port scan simulation
# From another machine, scan multiple ports:
# nmap -p 22,80,443,3306,5432 <server-ip>
# Then wait and check:
# sqlite3 /opt/atlas/security.db "SELECT * FROM detections WHERE rule_name='port_scanning';"
```

### Rollback — Phase 4

```bash
systemctl stop atlas-detector
systemctl disable atlas-detector
rm /etc/systemd/system/atlas-detector.service
rm /opt/atlas/security/detector_cursor.json
# Note: detection and alert data stays in security.db (shared)
# To fully remove: rm /opt/atlas/security.db (also removes collector data)
systemctl daemon-reload
```

---

## Phase 5: Alerting & Security API

### Goal

Expose security data through REST API endpoints, add alert lifecycle management, and integrate with the existing atlas-backend.

### Architecture Decision

**Extend existing atlas-backend** rather than creating a new service. Rationale:
- Atlas backend is already a FastAPI app on port 8000 behind nginx
- Sharing the codebase avoids an extra process, port, and nginx route
- The security API is lightweight (just SQLite queries)
- Single deployment unit simplifies operations on a resource-constrained host

### API Endpoints

| Method | Path | Description | Query Params |
|--------|------|-------------|--------------|
| `GET` | `/api/security/status` | Security overview summary | — |
| `GET` | `/api/security/alerts` | List alerts | `?status=new&severity=high&limit=50&offset=0` |
| `GET` | `/api/security/alerts/{id}` | Single alert detail | — |
| `PUT` | `/api/security/alerts/{id}` | Update alert status | Body: `{"status": "acknowledged"}` |
| `GET` | `/api/security/detections` | List detections | `?rule_name=ssh_brute_force&limit=50&offset=0` |
| `GET` | `/api/security/events` | Search events | `?source=nginx&event_type=nginx_4xx&src_ip=1.2.3.4&since=2026-08-18T00:00:00&limit=100&offset=0` |
| `GET` | `/api/security/stats` | Aggregate statistics | `?period=24h` |

### Response Schemas

```python
# /api/security/status
{
    "status": "ok",
    "events_today": 1234,
    "active_alerts": 3,
    "high_severity_alerts": 1,
    "last_event_at": "2026-08-18T14:32:05Z",
    "detection_rules_active": 6,
    "collector_healthy": true,
    "detector_healthy": true,
    "database_size_bytes": 1048576
}

# /api/security/alerts
{
    "alerts": [
        {
            "id": 1,
            "detection_id": 1,
            "status": "new",
            "severity": "high",
            "title": "[HIGH] Ssh Brute Force",
            "description": "8 failed SSH login attempts from 192.168.1.50 in 10 minutes",
            "src_ip": "192.168.1.50",
            "created_at": "2026-08-18T14:35:00Z",
            "updated_at": "2026-08-18T14:35:00Z",
            "detection": {
                "rule_name": "ssh_brute_force",
                "confidence": 0.95,
                "evidence": { ... }
            }
        }
    ],
    "total": 3,
    "limit": 50,
    "offset": 0
}

# /api/security/events
{
    "events": [ ... ],
    "total": 456,
    "limit": 100,
    "offset": 0
}
```

### Backend Modifications

**File:** `/opt/atlas/backend.py` (modified)

Add security router:

```python
# In backend.py, add import and include:
from security_api import router as security_router
app.include_router(security_router, prefix="/api/security", tags=["security"])
```

**File:** `/opt/atlas/security_api.py` (new)

```python
"""
Atlas Security Observatory — REST API Router

Thin query layer over the security.db SQLite database.
All endpoints are read-only except alert status updates.
"""
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

from security.common import get_db

router = APIRouter()

DB_PATH = "/opt/atlas/security.db"

class AlertStatusUpdate(BaseModel):
    status: str  # validated against AlertStatus enum

@router.get("/status")
async def security_status():
    """Overview of security posture."""
    with get_db(DB_PATH) as conn:
        # Aggregate queries...
        pass

@router.get("/alerts")
async def list_alerts(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """List alerts with optional filtering."""
    pass

@router.get("/alerts/{alert_id}")
async def get_alert(alert_id: int):
    """Get a single alert with its detection details."""
    pass

@router.put("/alerts/{alert_id}")
async def update_alert(alert_id: int, update: AlertStatusUpdate):
    """Update alert status (new → acknowledged → investigating → resolved/dismissed)."""
    valid_statuses = {"new", "acknowledged", "investigating", "resolved", "dismissed"}
    if update.status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid_statuses}")
    pass

@router.get("/detections")
async def list_detections(
    rule_name: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    src_ip: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """List detections with optional filtering."""
    pass

@router.get("/events")
async def list_events(
    source: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    src_ip: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    since: Optional[str] = Query(None),  # ISO 8601
    until: Optional[str] = Query(None),  # ISO 8601
    search: Optional[str] = Query(None),  # Free text in message field
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """Search security events with filtering."""
    pass

@router.get("/stats")
async def security_stats(
    period: str = Query("24h"),  # 1h, 6h, 24h, 7d, 30d
):
    """Aggregate security statistics."""
    pass
```

### NGINX Route Addition

**File:** `/etc/nginx/conf.d/atlas-security.conf`
```nginx
# Security API routes — proxied to atlas-backend
# These are added to the existing nginx configuration

# If atlas-backend nginx config is in a single server block,
# add these location blocks to that server block:

# location /api/security/ {
#     proxy_pass http://127.0.0.1:8000;
#     proxy_set_header Host $host;
#     proxy_set_header X-Real-IP $remote_addr;
#     proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
#     proxy_set_header X-Forwarded-Proto $scheme;
# }
```

**Note:** Since the atlas-backend is already proxied at `/api/status` and `/ws`, the security API endpoints at `/api/security/*` should be added to the same nginx server block. Check existing nginx config for the atlas-backend proxy and add the location block there.

### Health Check Integration

The `/api/security/status` endpoint checks:
1. `atlas-collector.service` active status (via `systemctl is-active`)
2. `atlas-detector.service` active status
3. `security.db` file size
4. Last event timestamp in database
5. Active alert count

### Files Summary — Phase 5

| File | Action | Purpose |
|------|--------|---------|
| `/opt/atlas/security_api.py` | Create | FastAPI router for security endpoints |
| `/opt/atlas/backend.py` | Modify | Import and include security router |
| `/etc/nginx/conf.d/atlas-backend.conf` (or equivalent) | Modify | Add `/api/security/` proxy location |

### Testing — Phase 5

```bash
# 1. Restart atlas-backend to pick up new code
systemctl restart atlas-backend

# 2. Test status endpoint
curl -s http://localhost:8000/api/security/status | python3 -m json.tool
# Expected: JSON with events_today, active_alerts, etc.

# 3. Test alerts endpoint
curl -s http://localhost:8000/api/security/alerts | python3 -m json.tool
# Expected: JSON with alerts array

# 4. Test events endpoint
curl -s "http://localhost:8000/api/security/events?source=journald&limit=10" | python3 -m json.tool
# Expected: JSON with events array

# 5. Test alert status update
curl -s -X PUT http://localhost:8000/api/security/alerts/1 \
  -H "Content-Type: application/json" \
  -d '{"status": "acknowledged"}'
# Expected: Updated alert

# 6. Test via nginx proxy
curl -s http://localhost/api/security/status | python3 -m json.tool
# Expected: Same response as direct

# 7. Verify existing endpoints still work
curl -s http://localhost/api/status | python3 -m json.tool
# Expected: Existing service status response
```

### Rollback — Phase 5

```bash
# Revert backend.py changes (remove security router import)
# Restart backend
systemctl restart atlas-backend

# Remove new files
rm /opt/atlas/security_api.py

# Remove nginx route additions
# Restart nginx
systemctl reload nginx
```

---

## Phase 6: Security Dashboard

### Goal

Create visual dashboards in Grafana and extend the Atlas landing page with security information.

### A. Grafana Security Dashboard

**File:** `/etc/atlas/grafana/provisioning/dashboards/security.json`

Dashboard panels:

| Row | Panel | Type | Data Source | Query / Notes |
|-----|-------|------|-------------|---------------|
| **Overview** | Active Alerts | Stat | SQLite API | Color thresholds: green(0), yellow(1-2), red(3+) |
| **Overview** | Events (24h) | Stat | SQLite API | Total events in last 24h |
| **Overview** | Security Score | Gauge | Derived | 100 - (active_high * 20 + active_medium * 10 + active_low * 2) |
| **Overview** | Collector Status | Stat | SQLite API | Healthy/Stale |
| **Auth Activity** | SSH Auth Failures (24h) | Time Series | SQLite API | Line chart, hourly buckets |
| **Auth Activity** | SSH Auth Successes (24h) | Time Series | SQLite API | Line chart, hourly buckets |
| **Auth Activity** | Top Source IPs (by failure count) | Table | SQLite API | Sorted by failure count desc |
| **Firewall** | nftables Drops (24h) | Time Series | SQLite API | Line chart, hourly buckets |
| **Firewall** | Drops by Source IP | Table | SQLite API | Top 10 IPs by drop count |
| **Firewall** | Drops by Destination Port | Bar Chart | SQLite API | Port distribution |
| **NGINX Security** | 4xx Responses (24h) | Time Series | SQLite API | Line chart |
| **NGINX Security** | 5xx Responses (24h) | Time Series | SQLite API | Line chart |
| **NGINX Security** | Top 4xx URLs | Table | SQLite API | Path + count |
| **Detections** | Detections Timeline | Time Series | SQLite API | Detections over time, colored by severity |
| **Detections** | Detections by Rule | Pie Chart | SQLite API | Rule distribution |
| **Detections** | Active Detections Table | Table | SQLite API | Latest detections with details |
| **Alerts** | Alerts by Status | Pie Chart | SQLite API | new/acknowledged/investigating/resolved/dismissed |
| **Alerts** | Alerts Table | Table | SQLite API | All non-resolved alerts, sortable |

#### SQLite Data Source Strategy

Grafana does not have a native SQLite datasource. Two options:

**Option A (Recommended): SQLite JSON API Endpoint**

Add a thin query endpoint to the security API:

```python
@router.get("/grafana/query")
async def grafana_query(
    q: str = Query(..., description="SQL query (SELECT only)"),
    params: str = Query("[]", description="JSON array of query parameters"),
):
    """
    Execute a read-only SQL query against security.db.
    Used by Grafana JSON API datasource plugin.
    
    Security: Only SELECT queries allowed. No INSERT/UPDATE/DELETE.
    Query timeout: 5 seconds.
    """
    import json as _json
    
    # Security: validate it's a SELECT
    q_stripped = q.strip().upper()
    if not q_stripped.startswith("SELECT"):
        raise HTTPException(400, "Only SELECT queries allowed")
    if any(keyword in q_stripped for keyword in ["INSERT", "UPDATE", "DELETE", "DROP", "ALTER"]):
        raise HTTPException(400, "Disallowed SQL keyword")
    
    params_list = _json.loads(params)
    # Execute with timeout, return results
    pass
```

Grafana datasource config for this:

**File:** `/etc/atlas/grafana/provisioning/datasources/security-api.yaml`
```yaml
apiVersion: 1
datasources:
  - name: Security API
    type: grafana-infinity-datasource
    # Or use JSON API datasource with custom queries
    url: http://127.0.0.1:8000/api/security/grafana/query
    isDefault: false
    editable: false
```

**Option B: Prometheus Adapter**

Write a small exporter that queries SQLite and exposes metrics as Prometheus gauges. Grafana already has Prometheus as a datasource.

```python
# Metrics to expose:
# atlas_security_events_total{source, event_type, severity}
# atlas_security_alerts_total{status, severity}
# atlas_security_detections_total{rule_name, severity}
# atlas_security_last_event_timestamp
```

**Recommendation:** Use Option B (Prometheus adapter) for time-series panels (charts over time) and Option A (SQLite API) for table panels. This avoids installing additional Grafana plugins.

#### Dashboard Provisioning Config

**File:** `/etc/atlas/grafana/provisioning/dashboards/dashboard.yml` (modify Phase 1 version)

```yaml
apiVersion: 1

providers:
  - name: Atlas Dashboards
    orgId: 1
    folder: Atlas
    type: file
    disableDeletion: false
    editable: true
    updateIntervalSeconds: 30
    allowUiUpdates: true
    options:
      path: /etc/atlas/grafana/provisioning/dashboards
      foldersFromFilesStructure: false
```

This already points to the dashboard directory where `infrastructure.json` (Phase 1) and `security.json` (Phase 6) both live.

### B. Atlas Landing Page — Security Section

**File to modify:** The existing Atlas landing page HTML/JS (served at `/`)

Add a new section after the existing service status section:

```
┌──────────────────────────────────────────────────────────┐
│                    SECURITY STATUS                        │
│                                                          │
│  🟢 SECURE    Active Alerts: 0    Events Today: 342     │
│                                                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │
│  │ 🔴 HIGH  │ │ 🟡 MED   │ │ 🔵 LOW   │ │ ⚪ INFO  │   │
│  │    0     │ │    1     │ │    3     │ │   298    │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘   │
│                                                          │
│  Recent Detections                                       │
│  ┌─────────────────────────────────────────────────────┐ │
│  │ 14:35  SSH Brute Force     HIGH    192.168.1.50    │ │
│  │ 14:22  Port Scanning       HIGH    10.0.0.5        │ │
│  │ 14:10  Suspicious NGINX    LOW     192.168.1.50    │ │
│  └─────────────────────────────────────────────────────┘ │
│                                                          │
│  [View Full Security Dashboard →]                        │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

**Implementation approach:**
- The existing landing page uses WebSocket for real-time data
- Add security data to the WebSocket payload (new field: `security`)
- Backend collects security summary on each WebSocket broadcast cycle
- JavaScript renders the security section using existing card/badge CSS classes

**Backend modification** (in `/opt/atlas/backend.py`):

Add a security summary function to the WebSocket broadcast payload:

```python
async def get_security_summary() -> dict:
    """Fetch security summary for WebSocket broadcast."""
    with get_db("/opt/atlas/security.db") as conn:
        # Active alerts by severity
        # Event count today
        # Last 5 detections
        pass
```

Add to WebSocket payload:
```python
{
    # ... existing fields ...
    "security": {
        "status": "ok",           # "ok", "warning", "critical"
        "active_alerts": 3,
        "high_severity": 1,
        "medium_severity": 1,
        "low_severity": 1,
        "events_today": 342,
        "last_event_at": "2026-08-18T14:32:05Z",
        "recent_detections": [
            {
                "time": "14:35",
                "rule": "SSH Brute Force",
                "severity": "high",
                "src_ip": "192.168.1.50"
            }
        ]
    }
}
```

**Frontend modification** (in the landing page HTML/JS):
- Add a "Security Status" section to the dashboard layout
- Render security data from WebSocket payload
- Add CSS for alert severity badges (reuse existing color palette)
- Add link to `/grafana/d/atlas-security/security-dashboard`

### Files Summary — Phase 6

| File | Action | Purpose |
|------|--------|---------|
| `/etc/atlas/grafana/provisioning/dashboards/security.json` | Create | Grafana security dashboard |
| `/etc/atlas/grafana/provisioning/datasources/security-api.yaml` | Create (optional) | SQLite API datasource |
| `/opt/atlas/security_api.py` | Modify | Add `/grafana/query` endpoint |
| `/opt/atlas/backend.py` | Modify | Add security summary to WebSocket |
| Landing page HTML/JS | Modify | Add security section |

### Testing — Phase 6

```bash
# 1. Verify Grafana dashboard is provisioned
curl -s -u admin:admin http://127.0.0.1:3000/api/search?query=Security
# Expected: "Atlas Security" dashboard listed

# 2. Open Grafana in browser
# Navigate to /grafana/d/atlas-security/security-dashboard
# Verify panels load (some may show "No data" if no events yet)

# 3. Generate test events and verify dashboard updates
# (trigger some SSH failures, check dashboard panels)

# 4. Verify Atlas landing page security section
curl -s http://localhost/ | grep -i "security"
# Expected: Security Status section in HTML

# 5. Verify WebSocket includes security data
# (Open browser dev tools, check WebSocket messages for "security" field)

# 6. Test alert management via UI
# Navigate to alerts, acknowledge one, verify status change via API
```

### Rollback — Phase 6

```bash
# Remove Grafana dashboard
rm /etc/atlas/grafana/provisioning/dashboards/security.json

# Remove security-api datasource (if created)
rm /etc/atlas/grafana/provisioning/datasources/security-api.yaml

# Revert backend.py changes (remove security WebSocket additions)

# Revert landing page changes

# Restart grafana and atlas-backend
systemctl restart grafana-server atlas-backend
```

---

## ADR: SQLite for Security Store

### ADR-001: Single SQLite Database for Security Events

**Status:** Accepted

**Context:**  
The security observatory needs to store time-series-like event data, detection findings, and alert lifecycle on a Debian VM with 1 vCPU and 1.9 GB RAM. Options considered: SQLite, PostgreSQL, Prometheus TSDB (via custom metrics), In-memory with periodic flush.

**Decision:**  
Use a single SQLite database at `/opt/atlas/security.db` with WAL mode enabled.

**Rationale:**
- Zero additional services to install, configure, or maintain
- WAL mode allows concurrent reads (API) and writes (collector) without locking
- Single file is trivial to backup, move, and inspect with `sqlite3` CLI
- Sufficient for homelab-scale event volumes (hundreds to low thousands of events per day)
- Python stdlib `sqlite3` — no additional dependencies

**Trade-offs Accepted:**
- No concurrent writers (acceptable: only collector writes events, only detector writes detections/alerts)
- No built-in replication (acceptable: single host)
- Manual schema migration (acceptable: simple schema, low change frequency)
- No built-in full-text search (acceptable: LIKE queries sufficient at this scale)

**Reversibility:** High — can migrate to PostgreSQL by changing the connection string and schema DDL.

---

## ADR: Event Pipeline Architecture

### ADR-002: File-Tail + Journal-Follow Collection Pattern

**Status:** Accepted

**Context:**  
Security events come from multiple heterogeneous sources (journald, flat log files, kernel messages). The system has very limited resources.

**Decision:**  
Use a single Python daemon that:
1. Follows journald via `journalctl --follow --output=json` subprocess (or `systemd.journal` module if available)
2. Tails flat log files (NGINX, fail2ban) by tracking byte offsets in a cursor file
3. Normalizes all events to a common schema
4. Batch-writes to SQLite

**Rationale:**
- Event-driven following (not polling) means near-zero CPU when idle
- Single daemon is simpler to manage, monitor, and debug than multiple collectors
- Cursor persistence allows clean restarts without duplicate or lost events
- Bounded queue prevents memory exhaustion under burst load

**Trade-offs Accepted:**
- `journalctl --follow` subprocess is slightly less efficient than direct `sd_journal` API via ctypes (acceptable: Python `systemd.journal` module may be available; subprocess is fallback)
- File-tail requires correct byte offset tracking (handled by cursor store)
- Single daemon is a single point of failure for collection (acceptable: auto-restart via systemd)

---

## Resource Budget

All security components must fit within a strict resource budget on the 1 vCPU / 1.9 GB RAM host:

| Component | RAM Target | CPU Behavior | Disk |
|-----------|-----------|--------------|------|
| auditd | ~5 MB | Event-driven, near-zero idle | ~1 MB/day audit log |
| journald (persistent) | Shared with existing | Existing overhead | 200 MB cap (configured) |
| atlas-collector | <20 MB | Event-driven, near-zero idle | Cursor file: 1 KB |
| atlas-detector | <15 MB | Poll every 10s, near-zero idle | Cursor file: 1 KB |
| security.db (SQLite) | Shared page cache | On-demand reads/writes | ~1 MB/day, ~30 MB/month |
| Atlas security API (in backend.py) | <5 MB additional | On-demand (request only) | — |
| **Total additional** | **<45 MB** | **Near-zero when idle** | **~35 MB/month** |

### Bounded Queue Behavior

When the event queue fills (10,000 events max in memory):
- Events are dropped with an incrementing counter
- `events_dropped` counter is exposed via the `/api/security/status` endpoint
- Collector logs a warning every 100 dropped events
- No crash, no data corruption — graceful degradation

### Batch Write Strategy

- Flush to SQLite every 50 events OR every 5 seconds (whichever first)
- Single transaction per batch for atomicity and WAL efficiency
- `PRAGMA busy_timeout=5000` prevents SQLITE_BUSY errors under concurrent reads

---

## Dependency Map

```
Phase 0 ─────────────────────────────────── (no code dependencies)
  │
  ├──→ Phase 1 ──────────────────────────── (Grafana provisioning only)
  │       │
  │       └──→ Phase 6 (Grafana dashboard) ─── depends on Phase 1 datasource
  │
  ├──→ Phase 2 ──────────────────────────── (log files, journald config)
  │       │
  │       └──→ Phase 3 ──────────────────── (reads logs configured in Phase 2)
  │               │
  │               └──→ Phase 4 ──────────── (reads events written by Phase 3)
  │                       │
  │                       └──→ Phase 5 ──── (reads detections/alerts from Phase 4)
  │                               │
  │                               └──→ Phase 6 (landing page + API)
  │
  └──→ Phase 2 (can run in parallel with Phase 1)
```

**Parallelization opportunities:**
- Phase 1 and Phase 2 can be done in parallel (no code dependencies)
- Phase 3 and Phase 4 can be developed and tested independently (Phase 4 uses SQLite as contract)
- Phase 5 API can be developed in parallel with Phase 4 (schema is known)

---

## Implementation Order (Recommended)

| Step | Phase | Estimated Effort | Prerequisites |
|------|-------|-----------------|---------------|
| 1 | Phase 0 | 30 minutes | None |
| 2 | Phase 1 | 45 minutes | Phase 0 (Grafana access) |
| 3 | Phase 2 | 30 minutes | Phase 0 (journald config) |
| 4 | Phase 3 | 3-4 hours | Phase 2 (log feeds) |
| 5 | Phase 4 | 2-3 hours | Phase 3 (event schema) |
| 6 | Phase 5 | 2-3 hours | Phase 4 (detection/alert schema) |
| 7 | Phase 6 | 2-3 hours | Phase 5 (API endpoints) |

**Total estimated effort:** 10-14 hours of focused implementation.

---

## Verification Checklist (End-to-End)

After all phases are complete:

```bash
# 1. All exporters bound to localhost
ss -tlnp | grep -E '9090|9100|9113' | grep -v '127.0.0.1' | wc -l
# Expected: 0

# 2. SSH hardened
grep PermitRootLogin /etc/ssh/sshd_config
# Expected: PermitRootLogin no

# 3. Auditd running
systemctl is-active auditd
# Expected: active

# 4. Journald persistent
ls /var/log/journal/
# Expected: directory exists with machine ID subfolder

# 5. Grafana datasources provisioned
curl -s -u admin:admin http://127.0.0.1:3000/api/datasources | python3 -c "
import sys, json
ds = json.load(sys.stdin)
print([d['name'] for d in ds])
"
# Expected: ['Prometheus']

# 6. Grafana dashboards provisioned
curl -s -u admin:admin http://127.0.0.1:3000/api/search | python3 -c "
import sys, json
dashboards = json.load(sys.stdin)
print([d['title'] for d in dashboards])
"
# Expected: ['Atlas Infrastructure', 'Atlas Security']

# 7. Collector running and collecting events
systemctl is-active atlas-collector
sqlite3 /opt/atlas/security.db "SELECT COUNT(*) FROM events;"
# Expected: active + count > 0

# 8. Detector running and generating detections
systemctl is-active atlas-detector
# (May have 0 detections if no attacks have occurred — that's good)

# 9. Security API responding
curl -s http://localhost:8000/api/security/status | python3 -m json.tool
# Expected: JSON with status, event counts, alert counts

# 10. Security dashboard in Grafana accessible via nginx
curl -s -o /dev/null -w "%{http_code}" http://localhost/grafana/d/atlas-security/security-dashboard
# Expected: 200 or 302

# 11. Atlas landing page shows security section
curl -s http://localhost/ | grep -c "security"
# Expected: > 0

# 12. Resource usage within budget
systemctl show atlas-collector -p MemoryCurrent
systemctl show atlas-detector -p MemoryCurrent
# Expected: Both < 50M

# 13. Database backup works
bash /opt/atlas/security/backup.sh
ls /opt/atlas/backups/security/
# Expected: security-YYYYMMDD.db file

# 14. Existing services unaffected
curl -s http://localhost/api/status | python3 -m json.tool
curl -s http://localhost/grafana/ -o /dev/null -w "%{http_code}"
curl -s http://localhost/files/ -o /dev/null -w "%{http_code}"
# Expected: All return正常 responses
```

---

*End of Plan*

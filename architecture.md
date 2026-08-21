# 🏗️ Atlas Enterprise Home Server Architecture

## Project Overview

Project ini membangun sebuah Home Server berbasis Debian 13 yang menyediakan beberapa layanan dalam satu mesin virtual, yaitu:

- Web Server
- Reverse Proxy
- NAS
- Monitoring
- Remote Access
- Security
- Status Page & Uptime Monitoring
- Security Observatory

---

# High Level Architecture

                                    Internet
                                        │
                                 Tailscale VPN
                                        │
                         ┌──────────────┴──────────────┐
                         │                             │
                       Laptop                         HP
                         │                             │
                         └──────────────┬──────────────┘
                                        │
                               Debian 13 Home Server
                                        │
                     ┌──────────────────┼──────────────────┐
                     │                  │                  │
                     ▼                  ▼                  ▼
                 Nginx            Prometheus          OpenSSH
                     │                  │
                     │                  ▼
                     │           Node Exporter
                     │
        ┌────────────┼───────────────┐
        │            │               │
        ▼            ▼               ▼
     Landing Page   File Browser      Grafana
        │            │               │
        │            ▼               │
        │      /srv/storage          │
        │                            │
        └──────────────┬─────────────┘
                       │
                 Samba File Share

---

# Virtual Machine Layout

VirtualBox
```
┌──────────────────────────────────────┐
│ Debian 13 VM                         │
├──────────────────────────────────────┤
│ CPU : 2 Core                         │
│ RAM : 3 - 4 GB                       │
├──────────────────────────────────────┤
│ Disk 1                               │
│ 20-30 GB                             │
│ Debian Operating System              │
├──────────────────────────────────────┤
│ Disk 2                               │
│ 100 GB (atau sesuai kebutuhan)       │
│ NAS Storage                          │
└──────────────────────────────────────┘
```
---

# Storage Architecture

Disk 1

/dev/sda

```
/
├── /boot
├── /home
├── /etc
└── /var
```

Disk 2

/dev/sdb

```
/srv/storage

├── Public
├── Private
├── Documents
├── Projects
├── ISO
├── Backup
├── Media
└── Downloads
```

---

# Network Architecture

```
                    Internet
                        │
                  Tailscale VPN
                        │
               100.x.x.x Address
                        │
                 Debian Home Server
                        │
              192.168.1.xxx (LAN)
                        │
        ┌───────────────┼────────────────┐
        │               │                │
     Laptop          Smartphone      Windows PC
```

---

# Reverse Proxy Flow

    Browser

    ↓

    Nginx

    ↓

```
/                → Landing Page

/files           → File Browser

/grafana         → Grafana

/status          → Status Page (statis)

/api/status      → Backend FastAPI (JSON)

/api/security/*  → Security API (JSON)
```

---

# Status Monitoring Flow

    Browser

    ↓

    Nginx (/status)

    ↓

    Statis: /var/www/atlas/status/index.html

    ↓

    fetch /api/status & /api/status/history (tiap 10 detik)

    ↓

    Nginx (/api/status)

    ↓

    Backend FastAPI (uvicorn :8000)

    ↓

    systemctl is-active (tiap 30 detik) → SQLite /opt/atlas/status.db

    ↓

    Status Page: kartu service + uptime 24h/7d + sparkline

---

# Monitoring Flow

    Node Exporter

    ↓

    Prometheus

    ↓

    Grafana

    ↓

    Dashboard

Grafana Dashboard

- CPU Usage
- RAM Usage
- Disk Usage
- Storage NAS
- Network Traffic
- Active Connections
- Uptime
- Nginx Metrics

---

# NAS Flow

    Browser

    ↓

    Nginx

    ↓

    File Browser

    ↓

    /srv/storage

    ↓

    Disk 2

---

# Samba Flow

    Windows Explorer

    ↓

    \\SERVER\Public

    ↓

    Samba

    ↓

    /srv/storage/Public

---

# Remote Access

    HP

    ↓

    Internet

    ↓

    Tailscale

    ↓

    Debian Home Server

    ↓

    Nginx

    ↓

    Landing Page

---

# Security Layer

    Internet

    ↓

    Tailscale

    ↓

    Firewall

    ↓

    Fail2Ban

    ↓

    Nginx

    ↓

    Application

    ↓

    Storage

Security Components

- SSH Key Authentication
- Disable Root Login
- UFW / nftables
- Fail2Ban
- HTTPS
- Security Headers

---

# Security Observatory

    Journal + NGINX Logs
         │
         ▼
    atlas-collector (Python)
         │
         ├── journald parser → SSH, kernel/nftables, fail2ban, nginx
         │
         └── NGINX access log parser → 4xx/5xx events
                  │
                  ▼
         security.db (SQLite WAL)
                  │
         ┌────────┴────────┐
         ▼                 ▼
    Detection Engine    REST API (19+ endpoints)
    (internal poll)     Grafana Security Dashboard (15 panels)
         │
         ▼
    Detections → Incidents → Alerts
                                    │
                                    ▼
                            Notification Queue
                                    │
                                    ▼
                            atlas-notifier
                                    │
                                    ▼
                               ntfy (push)
                                    │
                                    ▼
                                  Phone

Deployment

- User: atlas-security (dedicated, member of systemd-journal)
- Services: atlas-collector, atlas-notifier (systemd, auto-restart, 50M memory cap)
- DB: /opt/atlas/security.db (WAL mode, ~23 MB RSS)
- Logs: /opt/atlas/security/atlas-notifier.log + journald
- Backups: /opt/atlas/security/backup.sh → /opt/atlas/backups/security/
- Config: /etc/atlas/security.ini
- ntfy: 127.0.0.1:8088 (local only)

Key Decisions

- No Docker, no rsyslog — native systemd services only
- Split journalctl subprocesses: unit-filtered (-u) + kernel (-k) are incompatible
- Raw fd os.read() instead of select.select() on TextIOWrapper for subprocess polling
- ProtectSystem=strict with ReadWritePaths=/opt/atlas/ for SQLite WAL/journal creation
- NGINX parser only emits events for 4xx/5xx (2xx/3xx filtered out)
- ntfy installed via apt (not Docker), listening on localhost only

---

# URL Structure

```
http://server/

Home Dashboard

-----------------------

http://server/files

NAS

-----------------------

http://server/grafana

Grafana Dashboard

-----------------------

http://server/status

Status Page & Uptime Monitoring

-----------------------

http://server/api/status

API Status (JSON)
```

---

# Service Architecture

| Service | Function |
|----------|----------|
| Debian 13 | Operating System |
| Nginx | Web Server & Reverse Proxy |
| File Browser | NAS Web Interface |
| Samba | Windows File Sharing |
| Prometheus | Metrics Collection |
| Grafana | Monitoring Dashboard |
| Node Exporter | System Metrics |
| Nginx Exporter | Nginx Metrics |
| Tailscale | Remote Access VPN |
| OpenSSH | Remote Administration |
| Fail2Ban | Brute Force Protection |
| UFW / nftables | Firewall |
| FastAPI (atlas-backend) | Status API & Uptime Monitoring |
| SQLite | Riwayat uptime status |
| atlas-collector | Security event collection & detection |
| atlas-notifier | Notification daemon (ntfy push alerts) |
| ntfy | Push notification server (127.0.0.1:8088) |
| security.db | Security events, detections, incidents, alerts, notifications |

---

# Boot Sequence

    Server Boot

    ↓

    Debian

    ↓

    Networking

    ↓

    SSH

    ↓

    Firewall

    ↓

    Nginx

    ↓

    Prometheus

    ↓

    Node Exporter

    ↓

    Grafana
  
    ↓

    File Browser
  
    ↓

    Samba

    ↓

    Atlas Backend (status API)

    ↓

    Atlas Collector (security events)

    ↓

    Atlas Notifier (ntfy alerts)

    ↓

    Tailscale

    ↓

    Ready

---

# Future Expansion

Jika RAM ditambah menjadi 16 GB

```
                   Nginx Gateway
                         │
           ┌─────────────┴─────────────┐
           ▼                           ▼
     Home Server                Web Server 2
     NAS + Grafana               Backend
```

Nantinya:

- Multiple Backend
- Docker
- Kubernetes 

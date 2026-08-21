# 🏠 Atlas Enterprise Home Server

> A self-hosted Home Server built with **Debian 13** and **NGINX**, combining a Web Server, NAS, Monitoring Stack, Security Observatory, and Secure Remote Access in a single environment.

![Debian](https://img.shields.io/badge/Debian-13-A81D33?style=flat\&logo=debian)
![NGINX](https://img.shields.io/badge/NGINX-Reverse%20Proxy-009639?style=flat\&logo=nginx)
![Grafana](https://img.shields.io/badge/Grafana-Monitoring-F46800?style=flat\&logo=grafana)
![Prometheus](https://img.shields.io/badge/Prometheus-Metrics-E6522C?style=flat\&logo=prometheus)
![Tailscale](https://img.shields.io/badge/Tailscale-Remote%20Access-242424?style=flat\&logo=tailscale)
![License](https://img.shields.io/badge/License-MIT-blue)

---

## 📖 Overview

Most beginner server projects stop after serving a simple web page.

This project takes a different approach by transforming a Debian server into a **multi-purpose Home Server** that combines several infrastructure services into one platform.

Instead of acting as a traditional web server, this project also functions as:

* 🌐 Web Server
* 📁 NAS (Network Attached Storage)
* 📊 Monitoring Server
* 🔒 Secure Remote Access
* 🛡️ Hardened Linux Server
* 🔍 Security Observatory (event collection, detection, alerting, dashboards)

The goal is to simulate a small-scale enterprise infrastructure while remaining lightweight enough to run inside VirtualBox.

---

# ✨ Features

## 🌐 Web Server

* NGINX Web Server
* Reverse Proxy
* Custom Landing Page
* Custom Error Pages
* Virtual Host Configuration

---

## 📁 NAS

* Web-based File Manager
* Upload & Download Files
* Folder Management
* Public & Private Storage
* Samba File Sharing
* Dedicated Storage Disk

---

## 📊 Monitoring Stack

Powered by:

* Prometheus
* Grafana
* Node Exporter
* NGINX Prometheus Exporter

Available Metrics:

* CPU Usage
* RAM Usage
* Disk Usage
* NAS Storage
* Network Traffic
* Uptime
* NGINX Metrics
* System Health

---

## 🟢 Status Page & Uptime Monitoring

* Live status page at `/status`
* Realtime service health (Nginx, Grafana, Prometheus, File Browser, Samba, SSH, Tailscale, Fail2Ban)
* Uptime percentage over 24h & 7d
* Sparkline of recent health checks per service
* Auto-refresh every 10 seconds
* History persisted in SQLite (`/opt/atlas/status.db`)
* JSON API for status & uptime history

---

## 🔍 Security Observatory

A self-hosted security observability platform built with **zero containers** — all native systemd services.

* **Event Collection**: Journald (SSH, kernel/nftables, fail2ban, nginx) + NGINX access logs (4xx/5xx)
* **Detection Engine**: 6 rule-based detections with severity scoring, confidence, and cooldown deduplication
* **SQLite Storage**: WAL-mode database (`/opt/atlas/security.db`) — events, detections, incidents, alerts, notifications
* **REST API**: 19+ endpoints for status, events, detections, alerts, incidents, notifications, and Grafana metrics
* **Grafana Dashboard**: 15-panel security dashboard with Prometheus queries
* **Alerting**: ntfy push notifications via `atlas-notifier.service` with retry/backoff
* **Incident Management**: Notes, timeline, and lifecycle tracking per incident
* **Lightweight**: ~23 MB RAM for the collector daemon (target <50 MB)
* **Boot-enabled**: `atlas-collector.service` and `atlas-notifier.service` start automatically on boot

Full implementation plan: [SECURITY-OBSERVATORY-PLAN.md](SECURITY-OBSERVATORY-PLAN.md)

---

## 🔐 Security

* SSH Key Authentication
* Disable Root Login
* UFW / nftables
* Fail2Ban
* HTTPS
* Security Headers

---

## 🌍 Remote Access

Using **Tailscale** to securely access the server from:

* Laptop
* Smartphone
* Tablet

without exposing ports directly to the Internet.

---

# 🏗 Architecture

```text
                     Internet
                         │
                   Tailscale VPN
                         │
         ┌────────────────┴────────────────┐
         │                                 │
     Laptop                           Smartphone
         │                                 │
         └───────────────┬─────────────────┘
                         │
                 Debian 13 Home Server
                         │
       ┌─────────────────┼──────────────────┐
       │                 │                  │
       ▼                 ▼                  ▼
    NGINX           Prometheus          OpenSSH
       │                 │
       │                 ▼
       │          Node Exporter
       │
  ┌────┼─────────────┐
  │    │             │
  ▼    ▼             ▼
Home  NAS        Grafana
Page Interface
  │
  ▼
/srv/storage
  │
  ▼
Dedicated Storage Disk

Security Observatory:
  Journal + NGINX Logs → atlas-collector → security.db
      → Detection Engine → Alerts → atlas-notifier → ntfy → Phone
```

---

# 💾 Storage Layout

```text
Disk 1

Operating System

Debian 13

-------------------------

Disk 2

NAS Storage

/srv/storage

├── Public
├── Private
├── Backup
├── Documents
├── Projects
├── ISO
└── Media
```

Separating the operating system and storage makes maintenance easier and helps preserve data if the OS needs to be reinstalled.

---

# 🌐 Service Endpoints

| Endpoint   | Description          |
| ---------- | -------------------- |
| `/`        | Home Dashboard       |
| `/files`   | NAS Web Interface    |
| `/grafana` | Monitoring Dashboard |
| `/status`  | Status Page & Uptime Monitoring |
| `/api/status` | Status API (JSON) |
| `/api/status/history` | Uptime History API (JSON) |
| `/api/security/status` | Security overview (JSON) |
| `/api/security/events` | Security events search (JSON) |
| `/api/security/detections` | Detection findings (JSON) |
| `/api/security/incidents` | Security incidents (JSON) |
| `/api/security/alerts` | Alert management (JSON) |
| `/api/security/stats` | Aggregate statistics (JSON) |
| `/api/security/metrics` | Prometheus metrics (text format) |
| `/api/security/notifications` | Notification history (JSON) |
| `/api/security/notifications/test` | Send test notification (POST) |
| `/api/security/notifications/queue` | Notification queue status (JSON) |
| `/api/security/incidents/{id}/notes` | Incident notes (GET/POST) |
| `/api/security/incidents/{id}/timeline` | Incident timeline (JSON) |
| `/api/security/remediation` | Remediation actions (JSON) |

---

# 🛠 Technology Stack

| Category         | Technology                |
| ---------------- | ------------------------- |
| Operating System | Debian 13                 |
| Web Server       | NGINX                     |
| Reverse Proxy    | NGINX                     |
| NAS              | File Browser + Samba      |
| Monitoring       | Prometheus                |
| Dashboard        | Grafana                   |
| Metrics          | Node Exporter             |
| NGINX Metrics    | NGINX Prometheus Exporter |
| VPN              | Tailscale                 |
| Firewall         | nftables                  |
| Security         | Fail2Ban                  |
| Remote Access    | OpenSSH                   |
| Status Page      | Python FastAPI + SQLite   |
| Security Observatory | Python collector + SQLite (WAL) |
| Notifications    | ntfy (push notifications) |
| Notification Daemon | Python (atlas-notifier) |

---

# 📂 Project Structure

```text
enterprise-home-server/
│
├── README.md
├── architecture.md
├── roadmap.md
├── Design.md
├── SECURITY-OBSERVATORY-PLAN.md
├── atlas-landing-index.html
├── grafana-dashboard-atlas-infrastructure.json
│
└── atlas-security/
    ├── config.py              # Configuration loader
    ├── detector.py            # Detection engine
    ├── notifier.py            # Notification daemon
    ├── security_api.py        # REST API (19+ endpoints)
    ├── migrate_phase7.py      # Schema migration
    ├── atlas-notifier.service # Systemd unit
    ├── ntfy-server.yml        # ntfy config
    ├── security.json          # Grafana dashboard
    ├── security-api.yaml      # Grafana datasource
    ├── deploy.sh              # Deployment script
    ├── phase0/                # Hardening configs
    ├── phase1/                # Grafana provisioning
    ├── phase2/                # Logging configs
    └── phase3/                # Collector files
```

---

# 🚀 Development Roadmap

* [x] Project Planning
* [x] Debian Installation
* [x] Static Network Configuration
* [x] NGINX Setup
* [x] Reverse Proxy
* [x] NAS Storage
* [x] File Browser
* [x] Samba File Sharing
* [x] Prometheus
* [x] Grafana
* [x] Node Exporter
* [x] Tailscale
* [x] Security Hardening
* [x] HTTPS
* [x] Status Page & Uptime Monitoring
* [x] Security Observatory (event collection & detection)
* [x] Security Observatory API & Dashboards
* [x] Security Observatory Alerting (ntfy)
* [x] Documentation

---

# 🎯 Learning Objectives

This project focuses on learning practical Linux infrastructure, including:

* Linux Server Administration
* NGINX Configuration
* Reverse Proxy
* NAS Deployment
* Monitoring & Observability
* Network Security
* VPN Connectivity
* Security Observability
* Infrastructure Documentation

---

# 📸 Screenshots

> Screenshots will be added after deployment.

---

# 📄 License

This project is released under the MIT License.

---

⭐ If you find this project interesting, feel free to star the repository and follow its progress as new infrastructure features are added.

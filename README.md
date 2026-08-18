# 🏠 Atlas Enterprise Home Server

> A self-hosted Home Server built with **Debian 13** and **NGINX**, combining a Web Server, NAS, Monitoring Stack, Security Observatory, Secure Remote Access, and a foundation for High Availability in a single environment.

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
* 🔍 Security Observatory (event collection & detection)
* ⚖️ Foundation for Load Balancing

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
* **Detection Engine**: Internal polling loop with configurable rules, severity, and confidence scoring
* **SQLite Storage**: WAL-mode database (`/opt/atlas/security.db`) — events, detections, incidents, alerts
* **Lightweight**: ~23 MB RAM for the collector daemon (target <50 MB)
* **Boot-enabled**: `atlas-collector.service` starts automatically on boot

Planned: REST API, Grafana security dashboards, webhook/ntfy alerting, auto-remediation, incident management.

Full roadmap: [SECURITY-OBSERVATORY-PLAN.md](SECURITY-OBSERVATORY-PLAN.md)

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

## ⚖️ High Availability (Planned)

* NGINX Load Balancer
* Round Robin
* Backend Health Check
* Failover Demonstration

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

---

# 📂 Project Structure

```text
enterprise-home-server/
│
├── docs/
│   ├── ARCHITECTURE.md
│   ├── ROADMAP.md
│   ├── INSTALLATION.md
│   ├── SECURITY.md
│   ├── MONITORING.md
│   └── TROUBLESHOOTING.md
│
├── nginx/
├── prometheus/
├── grafana/
├── filebrowser/
├── samba/
├── scripts/
├── screenshots/
│
└── README.md
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
* [ ] Security Observatory API & Dashboards
* [ ] Security Observatory Alerting
* [ ] Documentation
* [ ] Load Balancing

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
* Infrastructure Documentation
* High Availability Concepts

---

# 📸 Screenshots

Screenshots will be added after implementation.

```text
screenshots/

├── landing-page.png
├── grafana-dashboard.png
├── nas-interface.png
├── nginx-config.png
└── architecture.png
```

---

# 📄 License

This project is released under the MIT License.

---

⭐ If you find this project interesting, feel free to star the repository and follow its progress as new infrastructure features are added.

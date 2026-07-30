# 🏗️ Atlas Enterprise Home Server Architecture

## Project Overview

Project ini membangun sebuah Home Server berbasis Debian 13 yang menyediakan beberapa layanan dalam satu mesin virtual, yaitu:

- Web Server
- Reverse Proxy
- NAS
- Monitoring
- Remote Access
- Security
- (Bonus) Load Balancing

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

/status          → Status Page
```

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

# Load Balancing (Bonus)

```
                Browser
                   │
                   ▼
           Nginx Load Balancer
                   │
         ┌─────────┴─────────┐
         ▼                   ▼
 Backend A (8081)      Backend B (8082)
```

Round Robin
```
Request 1

↓

Backend A

Request 2

↓

Backend B

Request 3

↓

Backend A

---
```

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

Server Status
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

- True Load Balancing
- Multiple Backend
- Docker
- Kubernetes 

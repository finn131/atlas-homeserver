# Atlas Realtime Dashboard Design

> **Version:** 1.0
> **Status:** Draft
> **Project:** Atlas Homelab
> **Author:** Finn

---

# Overview

Atlas Dashboard adalah landing page utama Home Server yang menampilkan kondisi server secara **realtime**.

Dashboard ini bukan pengganti Grafana.

Grafana tetap digunakan untuk observability dan analisis mendalam, sedangkan Atlas Dashboard berfungsi sebagai **Network Operations Center (NOC)** sederhana yang memberikan gambaran kesehatan server dalam satu halaman.

Semua data diperbarui secara realtime menggunakan **WebSocket** tanpa refresh browser.

---

# Hero Section

Landing page Atlas harus memberikan kesan seperti **Network Operations Center (NOC)** modern, bukan sekadar halaman berisi kumpulan tautan.

Saat pengguna membuka halaman, informasi terpenting harus langsung terlihat dalam beberapa detik tanpa perlu membuka Grafana.

Hero section menjadi identitas visual utama Atlas.

---

## Hero Layout

```
┌──────────────────────────────────────────────────────────────────────────────┐

                               A T L A S

                     Self Hosted Infrastructure Dashboard

            Debian 13 • Nginx • Prometheus • Grafana

                               🟢 ONLINE

                   Uptime 12 Days 14 Hours 32 Minutes

───────────────────────────────────────────────────────────────────────────────

CPU 18%      RAM 39%      Disk 42%      NAS 81%      Network Active

└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Hero Goals

Memberikan informasi penting hanya dalam sekali lihat.

Pengguna langsung mengetahui:

- Status server
- Lama uptime
- Sistem operasi
- Service utama
- Ringkasan penggunaan resource

tanpa perlu melakukan scrolling.

---

## Hero Components

### Atlas Logo

Logo sederhana dengan teks besar.

```
ATLAS
```

Subtitle

```
Self Hosted Infrastructure Dashboard
```

---

### Server Identity

```
Debian 13

Kernel 6.x

Hostname

debian
```

---

### Server Status

Status ditampilkan menggunakan badge.

```
🟢 ONLINE

atau

🔴 OFFLINE
```

Badge menggunakan animasi pulse halus.

---

### Quick Metrics

Menampilkan metric utama.

```
CPU

18%

RAM

39%

Disk

42%

NAS

81%

Network

Active
```

Seluruh nilai diperbarui melalui WebSocket.

---

### Uptime

```
12 Days

14 Hours

32 Minutes

18 Seconds
```

Timer berjalan realtime setiap detik.

---

## Hero Animation

Saat halaman dibuka:

- Logo melakukan fade in
- Subtitle muncul setelah logo
- Badge ONLINE muncul dengan efek glow hijau
- Metric card muncul satu per satu
- Progress bar melakukan animasi dari 0% menuju nilai aktual

Durasi keseluruhan sekitar 700–1000 ms agar terasa halus namun tetap responsif.

---

## Visual Style

Hero menggunakan perpaduan gaya:

- CasaOS → layout yang bersih dan ramah
- Grafana → metric card dan nuansa monitoring
- Ubuntu Server → minimalis dan fokus pada informasi

Tujuannya agar Atlas terlihat modern, profesional, dan tetap ringan dijalankan.

# Design Philosophy

Atlas mengambil inspirasi dari beberapa dashboard modern.

## CasaOS

Diambil dari CasaOS:

- Card layout
- Clean spacing
- Friendly UI
- Quick Access
- Service Launcher

---

## Grafana

Diambil dari Grafana:

- Dark theme
- Metric cards
- Live charts
- System monitoring
- Status indicators

---

## Ubuntu Server

Diambil dari Ubuntu:

- Minimalis
- Fokus pada informasi
- Tidak banyak dekorasi
- Cepat dibaca
- Efisien

---

# Design Goals

- Modern
- Clean
- Realtime
- Responsive
- Lightweight
- Fast
- Self Hosted

---

# Color Palette

Background

```
#0D1117
```

Secondary

```
#161B22
```

Card

```
#1F2937
```

Border

```
#30363D
```

Primary

```
#3B82F6
```

Success

```
#22C55E
```

Warning

```
#FACC15
```

Danger

```
#EF4444
```

Text

```
#F8FAFC
```

Muted

```
#94A3B8
```

---

# Typography

Font

```
Inter
```

Alternative

```
Geist
```

Icons

```
Lucide Icons
```

---

# Layout

```
+------------------------------------------------------+

                Atlas Home Server

--------------------------------------------------------

CPU            RAM            Network

Disk           NAS            Uptime

--------------------------------------------------------

Services

Nginx
Grafana
Prometheus
File Browser
Samba
SSH
Tailscale

--------------------------------------------------------

Quick Access

Grafana
Prometheus
NAS
Portfolio

--------------------------------------------------------

Realtime Logs

--------------------------------------------------------

Footer

```

---

# Dashboard Sections

## Header

```
Atlas

Debian 13

Kernel 6.x

Hostname

debian

Current Time

09:31:24

Server Status

🟢 ONLINE
```

---

# System Overview

Card:

CPU

```
18%

███████░░░
```

---

RAM

```
3.1 GB / 8 GB

█████░░░░
```

---

Disk

```
42%

████░░░░░
```

---

NAS

```
81 GB / 100 GB

████████░
```

---

Network

```
↑ 182 KB/s

↓

2.1 MB/s
```

---

Uptime

```
12 Days

13 Hours

42 Minutes
```

---

# Live Charts

Mini Sparkline

CPU

```
▁▁▂▃▄▅▆▇▆▅▄▃
```

RAM

```
▂▃▄▄▅▆▇▇▆▅▄
```

Network

```
▁▂▄▆▇▆▅▄▂▁
```

---

# Service Status

```
🟢 Nginx

🟢 Grafana

🟢 Prometheus

🟢 File Browser

🟢 Samba

🟢 SSH

🟢 Tailscale
```

Status diperbarui otomatis setiap ada perubahan.

---

# Quick Access

```
Grafana

Prometheus

NAS

Portfolio
```

Semua card dapat diklik.

---

# Realtime Events

Menampilkan event terbaru.

Contoh

```
09:30

SSH Login

-----------------------

09:27

Grafana Started

-----------------------

09:22

Prometheus Reloaded

-----------------------

09:20

NAS Mounted
```

---

# Footer

```
Atlas

Version 1.0

Realtime Connected

Last Update

09:31:28
```

---

# Animations

Semua perubahan menggunakan animasi halus.

CPU

- Smooth Progress

RAM

- Smooth Progress

Charts

- Live Update

Status

- Fade Transition

Hover

- Scale 1.02

---

# Responsive Layout

Desktop

```
3 Columns
```

Tablet

```
2 Columns
```

Mobile

```
1 Column
```

---

# Backend Architecture

```
Browser

        │

        ▼

WebSocket

        │

        ▼

FastAPI

        │

 ┌──────┴───────────────┐

 │                      │

Prometheus API     System Metrics

 │                      │

Node Exporter      systemctl

 │                      │

Nginx Exporter     psutil
```

---

# WebSocket Flow

```
Client Connect

↓

Server Accept

↓

Every 1 Second

↓

Collect Metrics

↓

Create JSON

↓

Broadcast

↓

Update Dashboard
```

---

# Example Payload

```json
{
  "cpu": 18,
  "ram": 39,
  "disk": 42,
  "nas": 81,
  "uptime": "12d 4h 20m",

  "network": {
    "rx": "2.1 MB/s",
    "tx": "184 KB/s"
  },

  "services": {
    "nginx": "online",
    "grafana": "online",
    "prometheus": "online",
    "filebrowser": "online",
    "tailscale": "online",
    "samba": "online"
  }
}
```

---

# Technology Stack

Frontend

- HTML
- TailwindCSS
- Vanilla JavaScript
- Chart.js

Backend

- FastAPI
- WebSocket
- Uvicorn
- psutil
- httpx

Monitoring

- Prometheus
- Node Exporter
- Nginx Exporter

Server

- Debian 13
- Nginx
- Systemd

---

# Future Features

- Weather Widget
- Docker Status
- Temperature Monitoring
- UPS Monitoring
- Multi Node Monitoring
- Notification Center
- User Authentication
- Theme Switching
- Mobile PWA
- Historical Charts
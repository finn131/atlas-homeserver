# 🏠 Atlas Enterprise Home Server Roadmap

## Tujuan
Membangun **Home Server** berbasis Debian 13 yang menggabungkan Web Server, NAS, Monitoring, dan akses jarak jauh dalam satu sistem.

## Arsitektur
- Debian 13 (VM)
- Disk 1: OS Debian
- Disk 2: NAS (`/srv/storage`)
- Nginx (reverse proxy & landing page)
- File Browser (web interface NAS)
- Samba (akses dari Windows)
- Prometheus
- Grafana
- Node Exporter
- Nginx Prometheus Exporter
- Tailscale
- UFW / nftables
- Fail2Ban
- OpenSSH
- Status Page (FastAPI + SQLite)
- Security Observatory (journal + NGINX log collection, detection engine)

---

## Phase 1 — Persiapan
- [x] Install Debian 13
- [x] Static IP
- [x] SSH
- [x] User non-root
- [x] Update sistem

## Phase 2 — Storage
- [x] Tambahkan VDI kedua
- [x] Format filesystem
- [x] Mount ke `/srv/storage`
- [x] Auto mount via `/etc/fstab`

## Phase 3 — Nginx
- [x] Landing page Home Server
- [x] Reverse Proxy
- [x] Custom error page

## Phase 4 — NAS
- [x] Install File Browser
- [x] Reverse proxy `/files`
- [x] Upload/Download
- [x] Folder management
- [x] Login admin
- [x] Preview gambar/PDF
- [x] Install Samba untuk share LAN

## Phase 5 — Security
- [x] nftables
- [x] SSH Key
- [x] Disable root login
- [x] Fail2Ban
- [x] HTTPS (self-signed)

## Phase 6 — Monitoring
- [x] Prometheus
- [x] Grafana
- [x] Node Exporter
- [x] Nginx Exporter

Dashboard:
- CPU
- RAM
- Disk
- Storage NAS
- Network
- Nginx
- Uptime

## Phase 7 — Tailscale
- [x] Install Tailscale
- [x] Akses dari HP
- [x] Uji akses dashboard
- [x] Uji akses NAS

## Phase 8 — Status Page & Uptime Monitoring
- [x] Backend `/api/status` (status service real-time)
- [x] Backend `/api/status/history` (riwayat uptime 24h / 7d via SQLite)
- [x] Halaman `/status` live dengan auto-refresh
- [x] Sparkline & persentase uptime per service
- [x] Notifikasi down/up (direncanakan: ntfy / Telegram)

## Phase 9 — Dokumentasi
- [ ] README
- [ ] Diagram arsitektur
- [ ] Screenshot dashboard
- [ ] Hasil pengujian

## Phase 10 — Atlas Security Observatory

Observability platform untuk keamanan: event collection, detection, alerting, dan dashboards — semua berjalan sebagai native systemd services (tanpa Docker/rsyslog/Kubernetes).

Rencana lengkap: [SECURITY-OBSERVATORY-PLAN.md](SECURITY-OBSERVATORY-PLAN.md)

### Phase 0 — Security Hardening & Infrastructure ✅
- [x] Prometheus, Node Exporter, NGINX Exporter bind ke 127.0.0.1
- [x] SSH: `PermitRootLogin no`
- [x] Journald persistent storage (200M max, 30 hari retention)
- [x] `sqlite3` CLI terinstall

### Phase 1 — Grafana Provisioning ✅
- [x] Prometheus datasource (uid: prometheus) via provisioning
- [x] Infrastructure dashboard (`atlas-infrastructure`) via provisioning
- [x] Dashboard provider untuk auto-load JSON dashboards

### Phase 2 — Centralized Logging ✅
- [x] NGINX log format `atlas_security` (request_time, ssl_protocol, ssl_cipher)
- [x] Logrotate: 30 hari daily rotation untuk `/var/log/nginx/atlas_access.log`
- [x] Backup script: `/opt/atlas/security/backup.sh` → `/opt/atlas/backups/security/`
- [x] `atlas-security` user & group

### Phase 3 — Security Event Collection ✅
- [x] `atlas-collector.service` — daemon Python (systemd, auto-restart)
- [x] Collector: journald parser (sshd, sshd-session, fail2ban, nginx, kernel/nftables)
- [x] Collector: NGINX access log parser (4xx/5xx events)
- [x] SQLite database: `/opt/atlas/security.db` (WAL mode)
- [x] Schema: events, detections, incidents, alerts, remediation_log
- [x] Detection engine: polling loop internal (setiap 10 detik)
- [x] Memory: ~23 MB RSS (target <50 MB)
- [x] Events terverifikasi: SSH auth success & NGINX 4xx

### Phase 4 — Detection Rules (Mendatang)
- [ ] Brute force SSH detection
- [ ] Port scan / nftables correlation
- [ ] NGINX anomaly (4xx spike, suspicious paths)
- [ ] Service auth failure patterns
- [ ] Confidence scoring & severity levels

### Phase 5 — API & Dashboard (Mendatang)
- [ ] REST API endpoints (events, detections, incidents)
- [ ] Grafana security dashboards
- [ ] NGINX reverse proxy `/security` → API

### Phase 6 — Alerting & Response (Mendatang)
- [ ] Webhook / ntfy / Telegram alerts
- [ ] Auto-remediation rules
- [ ] Incident management

### Phase 7 — Advanced Analysis (Mendatang)
- [ ] Historical trend analysis
- [ ] Threat intelligence integration
- [ ] Compliance reporting

---

## Struktur URL

- `/` → Home Dashboard
- `/files` → NAS Web Interface
- `/grafana` → Monitoring
- `/metrics` → Prometheus metrics (internal)
- `/status` → Status Page live + uptime monitoring
- `/api/status` → API status service (JSON)
- `/api/status/history?range=24h|7d` → API riwayat uptime (JSON)

---

## Target Demo

1. Landing page Home Server.
2. Login ke NAS dan upload file.
3. Akses file dari Windows (Samba).
4. Monitoring server di Grafana.
5. Status Page `/status` menunjukkan semua service online + uptime 24h/7d.
6. Security Observatory: event collection & detection engine berjalan.
7. Akses server dari HP menggunakan Tailscale.


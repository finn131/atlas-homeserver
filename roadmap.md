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
- Security Observatory (journal + NGINX log collection, detection engine, REST API, Grafana dashboard)
- Notification Daemon (atlas-notifier — ntfy alerts)
- ntfy (push notification server)

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

### Phase 4 — Detection Rules ✅
- [x] Brute force SSH detection (>=5 failures / 10 min, HIGH)
- [x] Port scan / nftables correlation (>=5 ports / 2 min, HIGH)
- [x] NGINX anomaly (>=20 4xx / 5 min, LOW)
- [x] Service anomaly (service_stop/failed, MEDIUM/HIGH)
- [x] Firewall blocks correlation (>=10 drops / 5 min, MEDIUM)
- [x] Auth correlation (SSH success + nft_drop, MEDIUM)
- [x] Confidence scoring & severity levels
- [x] Alert deduplication with cooldown
- [x] Incident grouping by source IP

### Phase 5 — Security API & Alert Management ✅
- [x] REST API router (`security_api.py`) — 12 endpoints
- [x] `/api/security/status` — dashboard overview
- [x] `/api/security/events` — search & filter events
- [x] `/api/security/detections` — list/get detections
- [x] `/api/security/incidents` — list/get/update incidents
- [x] `/api/security/alerts` — list/get/update alerts (status lifecycle)
- [x] `/api/security/stats` — aggregate statistics
- [x] `/api/security/security-summary` — lightweight WebSocket payload
- [x] NGINX proxy `/api/security/` → backend
- [x] Security review: parameterized SQL, bounded limits, no detection logic duplicated

### Phase 6 — Grafana Security Dashboard ✅
- [x] `/api/security/metrics` endpoint (Prometheus text format)
- [x] Prometheus scrape config for security-api
- [x] Grafana Security Dashboard (15 panels, 4 rows — Prometheus queries)
- [x] Backend WebSocket security summary (5s cache)
- [x] Landing page Security Status card
- [x] Status page English translation

### Phase 7 — Alerting & Response ✅
- [x] ntfy installed and configured (listening on 127.0.0.1:8088)
- [x] Notification daemon (`atlas-notifier.service`) with retry/backoff
- [x] Notification queue in SQLite (`notification_queue` table)
- [x] Incident notes API (GET + POST `/incidents/{id}/notes`)
- [x] Incident timeline API (`/incidents/{id}/timeline`)
- [x] Auto-remediation placeholder (`/remediation`)

### Phase 8 — Advanced Analysis (Cancelled)
> Cancelled — GeoIP, threat intel, auto-remediation, and analytics are overkill for a homelab only accessible via Tailscale. fail2Ban + nftables already handle blocking.

---

## Struktur URL

- `/` → Home Dashboard
- `/files` → NAS Web Interface
- `/grafana` → Monitoring
- `/metrics` → Prometheus metrics (internal)
- `/status` → Status Page live + uptime monitoring
- `/api/status` → API status service (JSON)
- `/api/status/history?range=24h|7d` → API riwayat uptime (JSON)
- `/api/security/status` → Security overview (JSON)
- `/api/security/events` → Security events search (JSON)
- `/api/security/detections` → Detection findings (JSON)
- `/api/security/incidents` → Security incidents (JSON)
- `/api/security/alerts` → Alert management (JSON)
- `/api/security/stats` → Aggregate statistics (JSON)
- `/api/security/metrics` → Prometheus metrics (Prometheus text format)
- `/api/security/notifications` → Notification history (JSON)
- `/api/security/notifications/test` → Send test notification (POST)
- `/api/security/notifications/queue` → Notification queue status (JSON)
- `/api/security/incidents/{id}/notes` → Incident notes (GET/POST)
- `/api/security/incidents/{id}/timeline` → Incident timeline (JSON)
- `/api/security/remediation` → Remediation actions (JSON)

---

## Target Demo

1. Landing page Home Server.
2. Login ke NAS dan upload file.
3. Akses file dari Windows (Samba).
4. Monitoring server di Grafana.
5. Status Page `/status` menunjukkan semua service online + uptime 24h/7d.
6. Security Observatory: event collection, detection engine, & REST API berjalan.
7. Security API: `/api/security/status` menunjukkan ringkasan keamanan real-time.
8. Akses server dari HP menggunakan Tailscale.
9. ntfy notifications: alert dikirim ke HP saat ada high/critical detection.


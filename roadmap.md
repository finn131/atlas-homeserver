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
- [ ] Nginx Exporter

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

## Phase 8 — Load Balancing (Bonus)
- [ ] Simulasi dua backend Nginx
- [ ] Round Robin
- [ ] Dokumentasi konsep failover

## Phase 9 — Dokumentasi
- [ ] README
- [ ] Diagram arsitektur
- [ ] Screenshot dashboard
- [ ] Hasil pengujian

---

## Struktur URL

- `/` → Home Dashboard
- `/files` → NAS Web Interface
- `/grafana` → Monitoring
- `/metrics` → Prometheus metrics (internal)
- `/status` → Status layanan

---

## Target Demo

1. Landing page Home Server.
2. Login ke NAS dan upload file.
3. Akses file dari Windows (Samba).
4. Monitoring server di Grafana.
5. Akses server dari HP menggunakan Tailscale.
6. (Bonus) Tunjukkan simulasi load balancing.


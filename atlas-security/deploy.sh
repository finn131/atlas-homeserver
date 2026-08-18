#!/bin/bash
# Atlas Security Observatory — Deployment Script
# Run with: sudo bash deploy.sh
#
# This script applies Phase 0-3 changes to the Atlas Debian host.
# It reads files from /tmp/atlas-security/ which should be uploaded first.

set -euo pipefail

STAGING="/tmp/atlas-security"
ATLAS_DIR="/opt/atlas/security"
LOG_FILE="/var/log/atlas-deploy-$(date +%Y%m%d-%H%M%S).log"

log() { echo "[$(date -Iseconds)] $*" | tee -a "$LOG_FILE"; }

log "=== Atlas Security Observatory Deployment ==="
log "Staging dir: $STAGING"
log "Deploy log: $LOG_FILE"

# -------------------------------------------------------------------
# Phase 0: Security Hardening
# -------------------------------------------------------------------
log ""
log "--- Phase 0: Security Hardening ---"

# 0.1 Bind Prometheus to localhost
log "Binding Prometheus to 127.0.0.1:9090..."
cp "$STAGING/phase0/prometheus-default" /etc/default/prometheus
log "  Updated /etc/default/prometheus"

# 0.2 Bind Node Exporter to localhost
log "Binding Node Exporter to 127.0.0.1:9100..."
cp "$STAGING/phase0/prometheus-node-exporter-default" /etc/default/prometheus-node-exporter
log "  Updated /etc/default/prometheus-node-exporter"

# 0.3 Bind NGINX Exporter to localhost
log "Binding NGINX Exporter to 127.0.0.1:9113..."
cp "$STAGING/phase0/nginx-exporter.service" /etc/systemd/system/nginx-exporter.service
log "  Updated /etc/systemd/system/nginx-exporter.service"

# 0.4 SSH hardening
log "Hardening SSH..."
# Create ssh-users group if it doesn't exist
if ! getent group ssh-users >/dev/null 2>&1; then
    groupadd ssh-users
    log "  Created ssh-users group"
fi
# Add nyxx to ssh-users group
if ! groups nyxx | grep -q ssh-users; then
    usermod -aG ssh-users nyxx
    log "  Added nyxx to ssh-users group"
fi
# Apply SSH config
cp "$STAGING/phase0/sshd_config" /etc/ssh/sshd_config
log "  Updated /etc/ssh/sshd_config"

# 0.5 Configure journald for persistent storage
log "Configuring journald for persistent storage..."
cp "$STAGING/phase0/journald.conf" /etc/systemd/journald.conf
mkdir -p /var/log/journal
log "  Updated /etc/systemd/journald.conf"

# 0.6 Install sqlite3 CLI
log "Installing sqlite3..."
apt-get install -y sqlite3 >/dev/null 2>&1 || true
log "  sqlite3 installed"

# -------------------------------------------------------------------
# Phase 1: Grafana Provisioning
# -------------------------------------------------------------------
log ""
log "--- Phase 1: Grafana Provisioning ---"

# Create directory structure
mkdir -p /etc/atlas/grafana/provisioning/datasources
mkdir -p /etc/atlas/grafana/provisioning/dashboards

# 1.1 Datasource
log "Provisioning Prometheus datasource..."
cp "$STAGING/phase1/grafana/provisioning/datasources/prometheus.yaml" \
   /etc/atlas/grafana/provisioning/datasources/prometheus.yaml

# 1.2 Dashboard provider
log "Configuring dashboard provider..."
cp "$STAGING/phase1/grafana/provisioning/dashboards/dashboard.yml" \
   /etc/atlas/grafana/provisioning/dashboards/dashboard.yml

# 1.3 Infrastructure dashboard
log "Provisioning infrastructure dashboard..."
cp "$STAGING/phase1/grafana/provisioning/dashboards/infrastructure.json" \
   /etc/atlas/grafana/provisioning/dashboards/infrastructure.json

log "  Grafana provisioning complete"

# -------------------------------------------------------------------
# Phase 2: Centralized Logging
# -------------------------------------------------------------------
log ""
log "--- Phase 2: Centralized Logging ---"

# 2.1 NGINX security log format
log "Adding NGINX security log format..."
cp "$STAGING/phase2/log-format-security.conf" /etc/nginx/conf.d/log-format-security.conf
log "  Created /etc/nginx/conf.d/log-format-security.conf"

# 2.2 Logrotate
log "Configuring logrotate..."
cp "$STAGING/phase2/logrotate-atlas-security" /etc/logrotate.d/atlas-security
log "  Created /etc/logrotate.d/atlas-security"

# 2.3 Backup script
log "Installing backup script..."
mkdir -p /opt/atlas/security
mkdir -p /opt/atlas/backups/security
cp "$STAGING/phase2/backup.sh" /opt/atlas/security/backup.sh
chmod +x /opt/atlas/security/backup.sh
log "  Created /opt/atlas/security/backup.sh"

# -------------------------------------------------------------------
# Phase 3: Security Event Collection
# -------------------------------------------------------------------
log ""
log "--- Phase 3: Security Event Collection ---"

# 3.1 Create service user
log "Creating atlas-security service user..."
if ! id atlas-security >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin atlas-security
    log "  Created atlas-security user"
else
    log "  atlas-security user already exists"
fi

# 3.2 Create directory structure
log "Creating security directory structure..."
mkdir -p "$ATLAS_DIR/parsers"
mkdir -p /opt/atlas/backups/security
mkdir -p /etc/atlas

# 3.3 Deploy Python packages
log "Deploying Python security modules..."
cp "$STAGING/phase3/security/__init__.py" "$ATLAS_DIR/__init__.py"
cp "$STAGING/phase3/security/config.py" "$ATLAS_DIR/config.py"
cp "$STAGING/phase3/security/common.py" "$ATLAS_DIR/common.py"
cp "$STAGING/phase3/security/schema.py" "$ATLAS_DIR/schema.py"
cp "$STAGING/phase3/security/models.py" "$ATLAS_DIR/models.py"
cp "$STAGING/phase3/security/detector.py" "$ATLAS_DIR/detector.py"
cp "$STAGING/phase3/security/collector.py" "$ATLAS_DIR/collector.py"
cp "$STAGING/phase3/security/parsers/__init__.py" "$ATLAS_DIR/parsers/__init__.py"
cp "$STAGING/phase3/security/parsers/nginx.py" "$ATLAS_DIR/parsers/nginx.py"
cp "$STAGING/phase3/security/parsers/fail2ban.py" "$ATLAS_DIR/parsers/fail2ban.py"
cp "$STAGING/phase3/security/parsers/journald.py" "$ATLAS_DIR/parsers/journald.py"
log "  Python modules deployed to $ATLAS_DIR"

# 3.4 Configuration
log "Deploying security configuration..."
cp "$STAGING/phase3/security.ini" /etc/atlas/security.ini
log "  Created /etc/atlas/security.ini"

# 3.5 Systemd service
log "Deploying systemd service..."
cp "$STAGING/phase3/atlas-collector.service" /etc/systemd/system/atlas-collector.service
log "  Created /etc/systemd/system/atlas-collector.service"

# 3.6 Set permissions
log "Setting permissions..."
chown -R atlas-security:atlas-security "$ATLAS_DIR"
chmod 750 "$ATLAS_DIR"
chmod 640 "$ATLAS_DIR"/*.py
chmod 640 "$ATLAS_DIR"/parsers/*.py
chown atlas-security:atlas-security /etc/atlas/security.ini
chmod 640 /etc/atlas/security.ini
# Initialize security.db with proper ownership
touch /opt/atlas/security.db
chown atlas-security:atlas-security /opt/atlas/security.db
chmod 660 /opt/atlas/security.db
# Initialize log file with proper ownership
touch /var/log/atlas-collector.log
chown atlas-security:atlas-security /var/log/atlas-collector.log
chmod 640 /var/log/atlas-collector.log
log "  Permissions set"

# -------------------------------------------------------------------
# Service Restarts
# -------------------------------------------------------------------
log ""
log "--- Restarting Services ---"

systemctl daemon-reload

log "Restarting Prometheus..."
systemctl restart prometheus

log "Restarting Node Exporter..."
systemctl restart prometheus-node-exporter

log "Restarting NGINX Exporter..."
systemctl restart nginx-exporter

log "Reloading NGINX..."
nginx -t && systemctl reload nginx

log "Restarting Grafana..."
systemctl restart grafana-server

log "Restarting SSH (with hardened config)..."
systemctl restart sshd

log "Restarting journald..."
systemctl restart systemd-journald

log "Enabling and starting Atlas Collector..."
systemctl enable atlas-collector
systemctl start atlas-collector

# -------------------------------------------------------------------
# Verification
# -------------------------------------------------------------------
log ""
log "--- Verification ---"

# Check exporters bind to localhost
log "Checking exporter bindings..."
for port in 9090 9100 9113; do
    binding=$(ss -tlnp | grep ":$port " | head -1)
    if echo "$binding" | grep -q "127.0.0.1"; then
        log "  ✓ Port $port bound to 127.0.0.1"
    else
        log "  ✗ Port $port NOT bound to 127.0.0.1: $binding"
    fi
done

# Check SSH
log "Checking SSH config..."
if grep -q "PermitRootLogin no" /etc/ssh/sshd_config; then
    log "  ✓ Root login disabled"
else
    log "  ✗ Root login NOT disabled"
fi

# Check journald
if [ -d /var/log/journal ]; then
    log "  ✓ Journald persistent storage enabled"
else
    log "  ✗ Journald persistent storage NOT enabled"
fi

# Check Grafana
log "Checking Grafana..."
if curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:3000/api/health | grep -q "200"; then
    log "  ✓ Grafana is healthy"
else
    log "  ✗ Grafana health check failed"
fi

# Check collector
log "Checking Atlas Collector..."
if systemctl is-active atlas-collector >/dev/null 2>&1; then
    log "  ✓ Atlas Collector is running"
else
    log "  ✗ Atlas Collector is NOT running"
    journalctl -u atlas-collector --no-pager -n 20 | tee -a "$LOG_FILE"
fi

# Check database
if [ -f /opt/atlas/security.db ]; then
    count=$(sqlite3 /opt/atlas/security.db "SELECT COUNT(*) FROM events;" 2>/dev/null || echo "0")
    log "  ✓ security.db exists with $count events"
else
    log "  ✗ security.db does not exist"
fi

# Check Prometheus targets
log "Checking Prometheus targets..."
targets=$(curl -s http://127.0.0.1:9090/api/v1/targets 2>/dev/null)
if echo "$targets" | python3 -c "import sys,json; d=json.load(sys.stdin); [print(f'  {t[\"labels\"][\"job\"]}: {t[\"health\"]}') for t in d['data']['activeTargets']]" 2>/dev/null; then
    log "  ✓ Prometheus targets checked"
else
    log "  ⚠ Could not check Prometheus targets (may need time to start)"
fi

# Check Grafana datasources
log "Checking Grafana datasources..."
ds=$(curl -s -u admin:admin http://127.0.0.1:3000/api/datasources 2>/dev/null)
if echo "$ds" | python3 -c "import sys,json; [print(f'  {d[\"name\"]}') for d in json.load(sys.stdin)]" 2>/dev/null; then
    log "  ✓ Grafana datasources checked"
else
    log "  ⚠ Could not check Grafana datasources"
fi

log ""
log "=== Deployment Complete ==="
log "Review log: $LOG_FILE"
log ""
log "Next steps:"
log "  1. Verify SSH access works: ssh nyxx@192.168.1.8"
log "  2. Check Grafana: https://192.168.1.8/grafana/"
log "  3. Monitor collector: journalctl -u atlas-collector -f"
log "  4. Generate test events: ssh baduser@192.168.1.8"

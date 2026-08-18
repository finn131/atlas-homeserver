#!/bin/bash
# Atlas Security Observatory — SQLite Database Backup
# Called by cron daily. Uses sqlite3 .backup for consistent snapshot.

set -euo pipefail

DB="/opt/atlas/security.db"
BACKUP_DIR="/opt/atlas/backups/security"
DATE=$(date +%Y%m%d)
MAX_BACKUPS=7

mkdir -p "$BACKUP_DIR"

# Skip if database doesn't exist yet
if [ ! -f "$DB" ]; then
    echo "[$(date -Iseconds)] security.db not found, skipping backup"
    exit 0
fi

# Use sqlite3 .backup for consistent snapshot (safe even if DB is in use)
sqlite3 "$DB" ".backup '$BACKUP_DIR/security-$DATE.db'"

# Cleanup old backups
find "$BACKUP_DIR" -name "security-*.db" -mtime +$MAX_BACKUPS -delete 2>/dev/null || true

echo "[$(date -Iseconds)] Backup completed: $BACKUP_DIR/security-$DATE.db"

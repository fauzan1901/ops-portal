#!/usr/bin/env bash
# Daily backup of the portal database (SQLite online backup, safe while the portal runs); old backups are removed after
# BACKUP_KEEP_DAYS. Restoring a backup also needs /etc/ops-portal/credentials.key (service account passwords).
set -euo pipefail
DB="${PORTAL_DATA:-/var/lib/ops-portal}/portal.db"
DEST="$(dirname "$DB")/backup"
[ -f "$DB" ] || { echo "$DB does not exist yet, nothing to back up."; exit 0; }
mkdir -p "$DEST"
sqlite3 "$DB" ".backup '$DEST/portal-$(date +%F).db'"
find "$DEST" -name 'portal-*.db' -mtime +"${BACKUP_KEEP_DAYS:-180}" -delete
echo "Backup: $DEST/portal-$(date +%F).db"

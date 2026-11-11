#!/usr/bin/env bash
# Back to Fabric Manager (8480) and Snapshot Restore Web UI (8481) after the Ops Portal cutover (run with sudo).
# Their code, settings and databases were not changed by the cutover; changes made in the portal since then stay only
# in the portal database (/var/lib/ops-portal/portal.db).
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo." >&2; exit 1; }
echo "==> Stop the portal"
systemctl disable --now ops-portal.service ops-portal-backup.timer 2>/dev/null || true
echo "==> nginx: the old sites again"
rm -f /etc/nginx/sites-enabled/ops-portal /etc/nginx/sites-enabled/ops-portal-oldport
for site in fabric-ui snapshot-restore; do
  [ -f "/etc/nginx/sites-available/$site" ] && ln -sf "/etc/nginx/sites-available/$site" "/etc/nginx/sites-enabled/$site"
done
nginx -t && systemctl reload nginx
echo "==> Start the old applications"
systemctl enable --now fabric-ui.service snapshot-restore.service fabric-ui-backup.timer snapshot-restore-backup.timer
sleep 3
for p in 8480 8481; do printf '   https://127.0.0.1:%s/healthz  %s\n' "$p" "$(curl -sk --noproxy '*' -o /dev/null -w '%{http_code}' "https://127.0.0.1:$p/healthz" || true)"; done
echo "Rolled back. The portal can be installed again later (its database is kept)."

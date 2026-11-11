#!/usr/bin/env bash
# Cutover on the bastion (WSL): Fabric Manager (8480) + Snapshot Restore Web UI (8481) -> Ops Portal on 8480.
# Run from the unpacked package:  sudo bash portal/deploy/cutover.sh
#   1/8 nothing running in the old apps   2/8 backups   3/8 portal settings from the old apps   4/8 portal installed on
#   127.0.0.1:18400 (not yet reachable)   5/8 old apps stopped, data moved   6/8 portal started   7/8 nginx: 8480 =
#   portal, 8481 -> portal /restore/   8/8 old services disabled (their files and databases stay; rollback-cutover.sh).
# If a step after 5/8 fails, the old applications are started again automatically.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo: sudo bash $0" >&2; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
NAME="${WEB_HOSTNAME:-aci.example.internal}"
ALT="${WEB_ALT_NAMES:-ops-portal.example.internal,aci.example.internal,restore.example.internal}"
ADMINS="${MIGRATE_ADMINS:-admin1}"
OLDPY=/opt/snapshot_restore/.venv/bin/python
stamp="$(date +%Y%m%d-%H%M%S)"
BK="/var/backups/acme-cloud-cutover-$stamp"
step() { printf '\n== %s\n' "$*"; }

step "1/8 Nothing may be running in the old applications"
for s in fabric-ui snapshot-restore; do systemctl cat "$s" >/dev/null 2>&1 || { echo "Service $s not found." >&2; exit 1; }; done
busy() {
  "$OLDPY" - <<'PY'
import datetime, sqlite3
a = sqlite3.connect("file:/var/lib/fabric_ui/audit.db?mode=ro", uri=True)
now = datetime.datetime.now().astimezone()
aci = 0
for (ts,) in a.execute("SELECT ts FROM audit WHERE status = 'pending'"):
    t = datetime.datetime.fromisoformat(ts)
    aci += (now - (t if t.tzinfo else t.astimezone())).total_seconds() < 600
o = sqlite3.connect("file:/var/lib/snapshot_restore/restore.db?mode=ro", uri=True)
ontap = o.execute("SELECT (SELECT COUNT(*) FROM restores WHERE status='running') + (SELECT COUNT(*) FROM deletions WHERE status='deleting')").fetchone()[0]
print(aci + ontap)
PY
}
n="$(busy)"
[ "$n" = 0 ] || { echo "   $n ACI change(s) or ONTAP restore/deletion job(s) are running. Wait until they finish, then run again." >&2; exit 1; }
echo "   Nothing running."
if [ -f /var/lib/ops-portal/portal.db ] && [ "$(sqlite3 /var/lib/ops-portal/portal.db 'SELECT COUNT(*) FROM portal_users' 2>/dev/null || echo 0)" != 0 ]; then
  echo "   The portal database already holds users: the cutover was done before. Nothing changed." >&2
  echo "   (A new attempt: sudo bash $SRC/deploy/rollback-cutover.sh, move /var/lib/ops-portal/portal.db away, run again.)" >&2
  exit 1
fi

step "2/8 Backups in $BK"
install -d -m 700 "$BK"
sqlite3 /var/lib/fabric_ui/audit.db ".backup '$BK/audit.db'"
sqlite3 /var/lib/snapshot_restore/restore.db ".backup '$BK/restore.db'"
tar -czf "$BK/settings.tgz" /etc/fabric_ui /etc/snapshot_restore /etc/nginx/sites-available /etc/nginx/sites-enabled 2>/dev/null
ls -la "$BK" | tail -n +2 | awk '{print "   " $NF " " $5}'

step "3/8 Portal settings from the old applications (/etc/ops-portal)"
id opsportal >/dev/null 2>&1 || useradd --system --home-dir /var/lib/ops-portal --shell /usr/sbin/nologin opsportal
install -d -o opsportal -g opsportal -m 750 /var/lib/ops-portal /var/lib/ops-portal/backup
install -d -m 755 /etc/ops-portal
if [ ! -s /etc/ops-portal/credentials.key ]; then
  (umask 077 && "$OLDPY" -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())' > /etc/ops-portal/credentials.key)
  chown root:opsportal /etc/ops-portal/credentials.key; chmod 640 /etc/ops-portal/credentials.key
  echo "   New key /etc/ops-portal/credentials.key (service accounts are encrypted again with it in 5/8)"
fi
"$OLDPY" "$SRC/deploy/migrate-from-apps.py" config --hostname "$NAME" --port 8480

step "4/8 Install the portal (127.0.0.1:18400, not reachable from outside yet)"
WEB_HOSTNAME="$NAME" WEB_ALT_NAMES="$ALT" SKIP_NGINX=1 bash "$SRC/deploy/install.sh"

rollback() {
  echo >&2
  echo "!! The cutover failed: starting the old applications again." >&2
  bash /opt/ops-portal/deploy/rollback-cutover.sh >&2 || true
  echo "!! Old applications are back. Backups: $BK" >&2
}

step "5/8 Stop the old applications, move the data"
n="$(busy)"
[ "$n" = 0 ] || { echo "   Something started meanwhile ($n). Run again later; nothing was switched." >&2; exit 1; }
trap rollback ERR
systemctl stop fabric-ui.service snapshot-restore.service
systemctl stop ops-portal.service
"$OLDPY" "$SRC/deploy/migrate-from-apps.py" data --wi-for-all $(for a in ${ADMINS//,/ }; do printf -- '--admin %s ' "$a"; done)

step "6/8 Start the portal"
systemctl start ops-portal.service
for _ in $(seq 1 30); do curl -fs --noproxy '*' http://127.0.0.1:18400/healthz >/dev/null 2>&1 && break; sleep 1; done
curl -fs --noproxy '*' http://127.0.0.1:18400/healthz >/dev/null
"$OLDPY" "$SRC/deploy/migrate-from-apps.py" check

step "7/8 nginx: 8480 = portal, 8481 -> portal /restore/"
bash /opt/ops-portal/deploy/nginx-portal.sh
sleep 1
code="$(curl -sk --noproxy '*' -o /dev/null -w '%{http_code}' -H "Host: $NAME" https://127.0.0.1:8480/)"
loc="$(curl -sk --noproxy '*' -o /dev/null -w '%{redirect_url}' https://127.0.0.1:8481/)"
client="$(curl -sk --noproxy '*' --haproxy-protocol -H "Host: $NAME" https://127.0.0.1:28080/api/session | "$OLDPY" -c 'import json,sys; print(json.load(sys.stdin).get("client","?"))' || echo '?')"
printf '   %-55s %s\n' "https://$NAME:8480/" "$code" "https://...:8481/ redirects to" "$loc" "PROXY port 28080 (PortalProxy), client seen" "$client"
[ "$code" = 200 ]
trap - ERR

step "8/8 Old services off (files and databases stay for rollback)"
systemctl disable --quiet fabric-ui.service snapshot-restore.service fabric-ui-backup.timer snapshot-restore-backup.timer
systemctl stop fabric-ui-backup.timer snapshot-restore-backup.timer 2>/dev/null || true
printf '   %-30s %s\n' ops-portal "$(systemctl is-active ops-portal)" fabric-ui "$(systemctl is-active fabric-ui || true)" \
  snapshot-restore "$(systemctl is-active snapshot-restore || true)"

cat <<EOF

Done. The Ops Portal answers on https://$NAME:8480 (and https://<any old name>:8481 -> /restore/).
  Backups of the old databases and settings: $BK
  Rollback to the two old applications:     sudo bash /opt/ops-portal/deploy/rollback-cutover.sh
  When ops-portal.example.internal resolves and is registered in Duo:
                                             sudo bash /opt/ops-portal/deploy/set-hostname.sh ops-portal.example.internal
EOF

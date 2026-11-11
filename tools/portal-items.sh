#!/usr/bin/env bash
# Read-only: the items of OpenStack fixes on the director of a site (each runs in the background there, in its own folder
# /tmp/wi-live.*, and goes on by itself when the portal restarts): running or ended, since when, and their last lines
# (instance, attempt, waiting for another migration, progress of the memory copy, time, RESULT). After a restart of the portal, start a new run only when none is running.
# Same path as the portal: portal service account -> management host -> director.
# Run on the bastion:  sudo bash ~/portal-items.sh <SITE>
set -u
SITE="${1:-}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
SVC=opsportal
PY=/opt/ops-portal/.venv/bin/python

read -r MGMT_HOST MGMT_PORT MGMT_USER MGMT_KEY DIR_HOST DIR_USER DIR_PORT < <("$PY" - "$SITE" <<'EOF'
import sys, yaml
c = yaml.safe_load(open("/etc/ops-portal/sites.yml"))["sites"][sys.argv[1]]
m, d = c.get("mgmt") or {}, c.get("director") or {}
print(m.get("host", "-"), m.get("port", 22), m.get("user") or "-", m.get("private_key") or "-",
      d.get("host", "-"), d.get("user") or "stack", d.get("port", 22))
EOF
)
OPTS=(-o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new -p "$MGMT_PORT")
[ "$MGMT_KEY" != "-" ] && OPTS+=(-i "$MGMT_KEY")
TARGET="$MGMT_HOST"
[ "$MGMT_USER" != "-" ] && TARGET="$MGMT_USER@$MGMT_HOST"

REMOTE=$(cat <<'EOF'
n=0; r=0
for d in /tmp/wi-live.*; do
  [ -d "$d" ] && [ -f "$d/out" ] || continue
  n=$((n + 1))
  if [ -f "$d/rc" ]; then st="ended (exit $(cat "$d/rc"))"; else st="RUNNING"; r=$((r + 1)); fi
  echo "== $d: $st, started $(stat -c %y "$d/script" 2>/dev/null | cut -c1-19), last output $(stat -c %y "$d/out" | cut -c1-19)"
  grep -E '^(== Item|[^ ].*: status |Attempt [0-9]|Time: |RESULT |Waiting: |The other live|Automatic fix|Skip |Note: |  The incoming copy|  Nova refused|  [0-9]+ (min|s)[^:]*: migration )' "$d/out" \
    | tail -n 10 | cut -c1-300 | sed 's/^/   /'
done
echo "== $n item folder(s) on the director, $r running"
pgrep -fa 'wi_ops\.[A-Za-z0-9]+ ' | grep -v pgrep | cut -c1-200 | sed 's/^/   process: /'
EOF
)

echo "Read-only, $(date -Is), site $SITE, director $DIR_USER@$DIR_HOST"
printf '%s\n' "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
  "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1 | grep -v '^\*\* '

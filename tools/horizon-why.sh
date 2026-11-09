#!/usr/bin/env bash
# Read-only: why a Horizon page answers "Something went wrong!" (HTTP 500), e.g. the detail page of one instance. On every
# controller: the requests of the last <hours> naming <text> that got HTTP 500 (Horizon's access logs), and the errors
# Django and Apache logged for them, traceback included ("Internal Server Error: <path>"). Then, for an instance ID, what
# that page reads: the instance, its volume attachments in Nova and each volume in Cinder BY ID (a volume missing in Cinder
# while Nova still has it is a known cause: vm-c3, 2026-11-02). Same path as the portal: portal service account ->
# management host -> director -> controllers. Only show / list / grep of logs.
# Run on the bastion:  sudo bash ~/horizon-why.sh <SITE> <instance ID or other text of the URL> [hours, default 6]
set -u
SITE="${1:-}"
TEXT="${2:-}"
HOURS="${3:-6}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$TEXT" =~ ^[A-Za-z0-9_.-]{4,64}$ ]] || { echo "Text: an instance ID or a word of the URL (letters, digits, _ . -)"; exit 1; }
[[ "$HOURS" =~ ^[0-9]{1,3}$ ]] || { echo "Hours: a number"; exit 1; }
OUT="/home/deploy/horizon-why-$(date +%Y%m%d-%H%M%S).txt"
SVC=opsportal
PY=/opt/ops-portal/.venv/bin/python

read -r MGMT_HOST MGMT_PORT MGMT_USER MGMT_KEY DIR_HOST DIR_USER DIR_PORT RC < <("$PY" - "$SITE" <<'EOF'
import sys, yaml
c = yaml.safe_load(open("/etc/ops-portal/sites.yml"))["sites"][sys.argv[1]]
m, d = c.get("mgmt") or {}, c.get("director") or {}
print(m.get("host", "-"), m.get("port", 22), m.get("user") or "-", m.get("private_key") or "-",
      d.get("host", "-"), d.get("user") or "stack", d.get("port", 22), d.get("overcloudrc") or "~/overcloudrc")
EOF
)
OPTS=(-o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new -p "$MGMT_PORT")
[ "$MGMT_KEY" != "-" ] && OPTS+=(-i "$MGMT_KEY")
TARGET="$MGMT_HOST"
[ "$MGMT_USER" != "-" ] && TARGET="$MGMT_USER@$MGMT_HOST"

REMOTE=$(cat <<'EOF'
set -u
source $RC >/dev/null 2>&1 || { echo "source $RC failed"; exit 1; }
INV=$(ls ~/overcloud-deploy/*/tripleo-ansible-inventory.yaml ~/config-download/*/tripleo-ansible-inventory.yaml \
  ~/tripleo-ansible-inventory.yaml 2>/dev/null | head -1)
nodes() {   # "<short name> <ctlplane ip> <ssh user>" of the nodes whose name or group matches $1
  python3 - "$1" "$INV" <<'PY'
import sys, yaml
want, path = sys.argv[1].lower(), sys.argv[2]
try:
    inv = yaml.safe_load(open(path)) or {}
except Exception:
    inv = {}
seen = set()
for group, body in inv.items():
    for host, hv in ((body or {}).get("hosts") or {}).items() if isinstance(body, dict) else []:
        name = host.split(".")[0].lower()
        if isinstance(hv, dict) and (want == name or (want == "controller" and "controller" in (group + name).lower())) and name not in seen:
            seen.add(name)
            print(name, hv.get("ctlplane_ip") or hv.get("ansible_host") or "-", hv.get("ansible_ssh_user") or "-")
PY
}
DEFUSR=$(grep -q '17\.' /etc/rhosp-release && echo tripleo-admin || echo heat-admin)
on() {   # on <ip> <user> <command>
  local u="$2"; [ "$u" = "-" ] && u=$DEFUSR
  ssh -n -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$u@$1" "$3"
}
nodes controller | while read -r N IP USR; do
  [ "$IP" = "-" ] && continue
  echo "== $N: requests naming $TEXT that got HTTP 500 (Horizon access logs, last 10)"
  on "$IP" "$USR" "sudo sh -c 'zgrep -h \"$TEXT\" /var/log/containers/httpd/horizon/*access*log* 2>/dev/null' | grep -E '\" 500 ' | tail -10" | cut -c1-400
  echo "== $N: Django / Horizon errors for $TEXT, traceback included (last 2)"
  on "$IP" "$USR" "sudo sh -c 'zgrep -h -A70 \"Internal Server Error: .*$TEXT\" /var/log/containers/horizon/horizon.log* 2>/dev/null' | tail -150" | cut -c1-400
  echo "== $N: Apache (mod_wsgi) error lines for $TEXT or a traceback, last $HOURS hours (last 60)"
  on "$IP" "$USR" "sudo sh -c 'find /var/log/containers/httpd/horizon -name \"*error*\" -mmin -$((HOURS * 60)) -exec cat {} + 2>/dev/null' | grep -E \"$TEXT|Traceback|Error|Exception|  File \" | tail -60" | cut -c1-400
done
if [[ "$TEXT" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
  echo "== Instance $TEXT"
  openstack server show "$TEXT" -f value -c name -c status -c OS-EXT-STS:task_state -c OS-EXT-SRV-ATTR:host -c flavor 2>&1 | head -8
  echo "== Its volume attachments in Nova, and each volume in Cinder by ID (show by ID only: a name match is no answer)"
  for v in $(openstack server show "$TEXT" -f json -c volumes_attached 2>/dev/null | python3 -c '
import json, sys
try:
    print(" ".join(v.get("id", "") for v in json.load(sys.stdin).get("volumes_attached") or []))
except Exception:
    pass'); do
    got=$(openstack volume show "$v" -f value -c id 2>&1 | head -1)
    if [ "$got" = "$v" ]; then
      echo "$v: in Cinder ($(openstack volume show "$v" -f value -c status 2>&1 | head -1))"
    else
      echo "$v: NOT in Cinder by its ID (openstack volume show answers: $got)"
      openstack volume list --all-projects --name "$v" -f value -c ID -c Status -c Size 2>&1 | sed 's/^/   a volume NAMED like it: /' | head -5
    fi
  done
fi
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, text $TEXT, last $HOURS hours; management host $MGMT_HOST, director $DIR_USER@$DIR_HOST (keys are not printed)"
  printf 'TEXT=%q\nHOURS=%q\nRC=%s\n%s\n' "$TEXT" "$HOURS" "$RC" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1
  echo "== exit $?"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

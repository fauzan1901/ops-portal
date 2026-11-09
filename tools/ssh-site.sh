#!/usr/bin/env bash
# An interactive shell along the portal's path: bastion -> management host -> director -> compute, with the portal
# service account's key (the same hops every script here uses). Only opens the shell; nothing runs by itself. The hosts
# and users of each hop are printed first (never the key itself). Leave each hop with exit or Ctrl-D.
# Run on the bastion:  sudo bash ~/ssh-site.sh <SITE> [director | <compute name>]
#   e.g. sudo bash ~/ssh-site.sh DCA                                 (the management host)
#        sudo bash ~/ssh-site.sh DCA director                        (the director, as stack)
#        sudo bash ~/ssh-site.sh DCA overcloud-novacomputeiha-0      (a compute, as heat-admin / tripleo-admin)
set -u
SITE="${1:-}"
NODE="${2:-}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$NODE" =~ ^[A-Za-z0-9.-]*$ ]] || { echo "Second argument: director or a compute name, e.g. overcloud-novacomputeiha-0"; exit 1; }
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
[ "${MGMT_HOST:-"-"}" != "-" ] || { echo "No management host for $SITE in /etc/ops-portal/sites.yml (run with sudo)"; exit 1; }
OPTS=(-o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=30 -p "$MGMT_PORT")
[ "$MGMT_KEY" != "-" ] && OPTS+=(-i "$MGMT_KEY")
TARGET="$MGMT_HOST"
[ "$MGMT_USER" != "-" ] && TARGET="$MGMT_USER@$MGMT_HOST"
echo "1. management host: $TARGET port $MGMT_PORT (key of $SVC: $MGMT_KEY)"
if [ -z "$NODE" ]; then
  exec sudo -u "$SVC" -H ssh -t "${OPTS[@]}" "$TARGET"
fi
echo "2. director: $DIR_USER@$DIR_HOST port $DIR_PORT"
if [ "$NODE" = director ]; then
  exec sudo -u "$SVC" -H ssh -t "${OPTS[@]}" "$TARGET" "ssh -t -o ServerAliveInterval=30 -p $DIR_PORT $DIR_USER@$DIR_HOST"
fi
# the compute's ctlplane address and user, from the director's inventory (as the scripts read them)
read -r IP USR < <(sudo -u "$SVC" -H ssh -o BatchMode=yes "${OPTS[@]}" "$TARGET" \
  "ssh -o BatchMode=yes -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s -- $NODE" <<'EOF'
INV=$(ls ~/overcloud-deploy/*/tripleo-ansible-inventory.yaml ~/config-download/*/tripleo-ansible-inventory.yaml \
  ~/tripleo-ansible-inventory.yaml 2>/dev/null | head -1)
DEFUSR=$(grep -q '17\.' /etc/rhosp-release && echo tripleo-admin || echo heat-admin)
python3 - "$1" "$INV" "$DEFUSR" <<'PY'
import sys, yaml
want, path, default = sys.argv[1].split(".")[0].lower(), sys.argv[2], sys.argv[3]
try:
    inv = yaml.safe_load(open(path)) or {}
except Exception:
    inv = {}
for group, body in inv.items():
    for host, hv in ((body or {}).get("hosts") or {}).items() if isinstance(body, dict) else []:
        if host.split(".")[0].lower() == want and isinstance(hv, dict) and (hv.get("ctlplane_ip") or hv.get("ansible_host")):
            print(hv.get("ctlplane_ip") or hv.get("ansible_host"), hv.get("ansible_ssh_user") or default)
            raise SystemExit
print("-", "-")
PY
EOF
)
[ "${IP:-"-"}" != "-" ] || { echo "$NODE is not in the director's inventory (a name such as overcloud-novacomputeiha-0)"; exit 1; }
echo "3. compute $NODE: $USR@$IP"
exec sudo -u "$SVC" -H ssh -t "${OPTS[@]}" "$TARGET" \
  "ssh -t -o ServerAliveInterval=30 -p $DIR_PORT $DIR_USER@$DIR_HOST ssh -t -o ServerAliveInterval=30 $USR@$IP"

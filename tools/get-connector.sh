#!/usr/bin/env bash
# Read-only: the host connector of a compute as nova-manage gives it (volume_attachment get_connector --json): the input
# of nova-manage volume_attachment refresh. Shows stdout and stderr apart, as the container user and as root, so a
# failure (privsep, logging on stdout) is visible. A connector holds the host name, IP, iSCSI initiator, multipath flag:
# no secret.
# Same path as the portal: portal service account -> management host -> director -> the compute.
# Run on the bastion:  sudo bash ~/get-connector.sh <SITE> <compute short name>
set -u
SITE="${1:-}"
NODE="${2:-}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$NODE" =~ ^[a-z0-9-]{1,63}$ ]] || { echo "Compute: its short name, e.g. dcbrhosp-az1-compute-2"; exit 1; }
OUT="/home/deploy/get-connector-$(date +%Y%m%d-%H%M%S).txt"
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

ONNODE=$(cat <<'EOF'
for u in "" "-u root"; do
  echo "== podman exec ${u:-(container user)} nova_compute nova-manage volume_attachment get_connector --json"
  podman exec $u nova_compute nova-manage volume_attachment get_connector --json > /tmp/gc.out 2> /tmp/gc.err
  echo "exit $?"
  echo "-- stdout (first 1500 characters)"; head -c 1500 /tmp/gc.out; echo
  echo "-- stderr (last 15 lines)"; tail -15 /tmp/gc.err | cut -c1-300
  rm -f /tmp/gc.out /tmp/gc.err
done
echo "== container user of nova_compute: $(podman exec nova_compute id 2>&1)"
EOF
)

REMOTE=$(cat <<'EOF'
INV=$(ls ~/overcloud-deploy/*/tripleo-ansible-inventory.yaml ~/config-download/*/tripleo-ansible-inventory.yaml \
  ~/tripleo-ansible-inventory.yaml 2>/dev/null | head -1)
read -r IP USR < <(python3 - "$NODE" "$INV" <<'PY'
import sys, yaml
want, path = sys.argv[1].lower(), sys.argv[2]
try:
    inv = yaml.safe_load(open(path)) or {}
except Exception:
    inv = {}
for group, body in inv.items():
    for host, hv in ((body or {}).get("hosts") or {}).items() if isinstance(body, dict) else []:
        if host.split(".")[0].lower() == want and isinstance(hv, dict):
            print(hv.get("ctlplane_ip") or hv.get("ansible_host") or "-", hv.get("ansible_ssh_user") or "-")
            raise SystemExit
print("- -")
PY
)
[ "$IP" = "-" ] && { echo "$NODE: not in the inventory $INV"; exit 1; }
[ "$USR" = "-" ] && USR=$(grep -q '17\.' /etc/rhosp-release && echo tripleo-admin || echo heat-admin)
echo "######## $NODE ($USR@$IP)"
printf '%s\n' "$ONNODE" | ssh -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o LogLevel=ERROR "$USR@$IP" "sudo -n bash -s"
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, compute $NODE; management host $MGMT_HOST, director $DIR_USER@$DIR_HOST (keys are not printed)"
  printf 'NODE=%q\nONNODE=%q\n%s\n' "$NODE" "$ONNODE" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1
  echo "== exit $?"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

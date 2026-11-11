#!/usr/bin/env bash
# Read-only: did a disconnect aimed at another instance's stale LUN hurt the instance that really owns that disk? For
# the instance that owns the multipath device: who it is (project, host, created), when it came to its compute
# (migrations, actions), its disk errors seen by libvirt (domblkerror), the qemu log, and the I/O / filesystem errors its
# guest printed on its console. Also whether `nova-manage volume_attachment` (refresh the connection info of an
# attachment, upstream Xena+) exists in this deployment.
# Same path as the portal: portal service account -> management host -> director -> controller / compute.
# Run on the bastion:  sudo bash ~/neighbour-disk-check.sh <SITE> <server ID of the owner> <its compute short name>
set -u
SITE="${1:-}"
SID="${2:-}"
NODE="${3:-}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$SID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || { echo "Server ID: an OpenStack UUID"; exit 1; }
[[ "$NODE" =~ ^[a-z0-9-]{1,63}$ ]] || { echo "Compute: its short name, e.g. dcbrhosp-az1-compute-2"; exit 1; }
OUT="/home/deploy/neighbour-disk-check-$(date +%Y%m%d-%H%M%S).txt"
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
echo "== The instance that owns the disk"
openstack server show "$SID" -f json 2>&1 | python3 -c '
import json, sys
try:
    s = json.load(sys.stdin)
except Exception:
    print("not readable"); raise SystemExit
for k in ("name", "project_id", "status", "OS-EXT-STS:power_state", "OS-EXT-STS:task_state", "OS-EXT-SRV-ATTR:host",
          "OS-EXT-SRV-ATTR:instance_name", "volumes_attached", "created", "updated"):
    print(f"{k}: {s.get(k)}"[:400])'
echo "== Its migrations (newest first, UTC)"
openstack --os-compute-api-version 2.59 server migration list --server "$SID" -f value \
  -c Id -c Status -c "Source Compute" -c "Dest Compute" -c "Created At" -c "Updated At" 2>&1 | sort -rn | head -5
echo "== Its actions (newest first, UTC)"
openstack server event list "$SID" -f value -c Action -c "Start Time" 2>&1 | head -6
echo "== Its console log: I/O, block device and filesystem errors (last 25 of the last 2000 lines)"
openstack console log show --lines 2000 "$SID" 2>&1 | grep -iE "I/O error|blk_update_request|Buffer I/O|EXT4-fs error|XFS.*(error|shutdown)|remount.*read-only|Remounting filesystem read-only|end_request|critical medium|journal" | tail -25
echo "== nova-manage volume_attachment on a controller (refresh of an attachment's connection info)"
INV=$(ls ~/overcloud-deploy/*/tripleo-ansible-inventory.yaml ~/config-download/*/tripleo-ansible-inventory.yaml \
  ~/tripleo-ansible-inventory.yaml 2>/dev/null | head -1)
nodes() {
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
on() {
  local u="$2"; [ "$u" = "-" ] && u=$DEFUSR
  ssh -n -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$u@$1" "$3"
}
read -r CN CIP CUSR < <(nodes controller | head -1)
on "$CIP" "$CUSR" "sudo podman exec nova_api rpm -q openstack-nova-common 2>&1; sudo podman exec nova_api nova-manage volume_attachment --help 2>&1 | head -12"
read -r N IP USR < <(nodes "$NODE")
[ -z "${IP:-}" ] || [ "$IP" = "-" ] && { echo "$NODE: not in the inventory $INV"; exit 1; }
INST=$(openstack server show "$SID" -f value -c OS-EXT-SRV-ATTR:instance_name 2>/dev/null)
echo "== $NODE: $INST seen by libvirt (state, disk errors) and its qemu log"
on "$IP" "$USR" "sudo sh -c 'c=\$(podman ps --format \"{{.Names}}\" | grep -m1 -E \"^(nova_virtqemud|nova_libvirt)\$\"); podman exec \$c virsh -c qemu:///system domstate $INST --reason; podman exec \$c virsh -c qemu:///system domblkerror $INST; tail -15 /var/log/containers/libvirt/qemu/$INST.log'" 2>&1 | cut -c1-300
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, instance $SID, compute $NODE; management host $MGMT_HOST, director $DIR_USER@$DIR_HOST (keys are not printed)"
  printf 'SID=%q\nNODE=%q\nRC=%s\n%s\n' "$SID" "$NODE" "$RC" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1
  echo "== exit $?"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

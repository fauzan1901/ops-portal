#!/usr/bin/env bash
# Read-only: "duplicate connectors detected on volume" (a migration fails in Cinder attachment_update). Cinder refuses
# to connect an attachment while another attachment of the same (not multiattach) volume is still connected: usually
# one left over by an earlier failed migration. Before any attachment is deleted it must be clear which one Nova uses
# (block_device_mapping.attachment_id), the host each one is connected to (connector host), and where the instance
# runs now (virsh on the computes): deleting a connected attachment disconnects the volume from that host.
# Shows: the instance (state, host), its last migrations and actions, every volume of it with its Cinder attachments,
# the Nova BDM rows and the Cinder volume_attachment rows (database, SELECT only), and the domain on the computes.
# Same path as the portal: portal service account -> management host -> director -> controller / computes.
# Run on the bastion:  sudo bash ~/volume-attachments.sh <SITE> <server ID>
set -u
SITE="${1:-}"
SID="${2:-}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$SID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || { echo "Server ID: an OpenStack UUID"; exit 1; }
OUT="/home/deploy/volume-attachments-$(date +%Y%m%d-%H%M%S).txt"
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
echo "== Instance"
SRV=$(openstack server show "$SID" -f json 2>&1)
SRV="$SRV" python3 - <<'PY'
import json, os
try:
    s = json.loads(os.environ["SRV"])
except Exception:
    print(os.environ["SRV"][:1500]); raise SystemExit
for k in ("name", "status", "OS-EXT-STS:vm_state", "OS-EXT-STS:power_state", "OS-EXT-STS:task_state", "OS-EXT-SRV-ATTR:host",
          "OS-EXT-SRV-ATTR:instance_name", "volumes_attached", "fault", "updated"):
    print(f"{k}: {s.get(k)}"[:600])
PY
HOST=$(SRV="$SRV" python3 -c 'import json,os; print(json.loads(os.environ["SRV"]).get("OS-EXT-SRV-ATTR:host") or "")' 2>/dev/null)
INST=$(SRV="$SRV" python3 -c 'import json,os; print(json.loads(os.environ["SRV"]).get("OS-EXT-SRV-ATTR:instance_name") or "")' 2>/dev/null)
VOLS=$(SRV="$SRV" python3 -c '
import json, os, re
v = json.loads(os.environ["SRV"]).get("volumes_attached")
print(" ".join(re.findall(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", str(v))))' 2>/dev/null)
echo "== Migrations of the instance (newest first)"
openstack --os-compute-api-version 2.59 server migration list --server "$SID" -f value \
  -c Id -c Type -c Status -c "Source Compute" -c "Dest Compute" -c "Created At" -c "Updated At" 2>&1 | sort -rn | head -6
SRC=$(openstack --os-compute-api-version 2.59 server migration list --server "$SID" -f value -c Id -c "Source Compute" 2>/dev/null | sort -rn | head -1 | awk '{print $2}')
echo "== Actions of the instance (newest first)"
openstack server event list "$SID" -f value -c "Request ID" -c Action -c "Start Time" 2>&1 | head -6
for V in $VOLS; do
  echo "== Volume $V"
  openstack volume show "$V" -f json -c status -c attach_status -c multiattach -c bootable -c type -c attachments 2>&1 | tr -d '\n' | cut -c1-900; echo
  cinder --os-volume-api-version 3.27 attachment-list --all-tenants --volume-id "$V" 2>&1
done
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
read -r CN CIP CUSR < <(nodes controller | head -1)
if [ -n "${CIP:-}" ] && [ "$CIP" != "-" ]; then
  Q="SELECT id, device_name, volume_id, attachment_id, updated_at FROM nova.block_device_mapping WHERE instance_uuid='$SID' AND deleted=0 AND destination_type='volume';"
  for V in $VOLS; do
    Q="$Q SELECT id, attach_status, attached_host, JSON_VALUE(connector, '\$.host') AS connector_host, connection_info IS NOT NULL AS connected, instance_uuid, attach_time, updated_at FROM cinder.volume_attachment WHERE volume_id='$V' AND deleted=0;"
  done
  echo "== Database on $CN (SELECT only): Nova block device mappings (attachment_id = the attachment Nova uses), Cinder attachments (connector host = where it is connected)"
  on "$CIP" "$CUSR" "sudo podman exec \$(sudo podman ps -q -f name=galera-bundle | head -1) mysql -t -e \"$Q\"" 2>&1 | cut -c1-260
else
  echo "== no controller in the inventory $INV: database not read"
fi
for h in ${HOST:-} ${SRC:-}; do
  read -r N IP USR < <(nodes "${h%%.*}")
  [ -z "${IP:-}" ] || [ "$IP" = "-" ] && { echo "== $h: no address in the inventory"; continue; }
  echo "== $h: the domain $INST and its disks"
  on "$IP" "$USR" "sudo sh -c 'c=\$(podman ps --format \"{{.Names}}\" | grep -m1 -E \"^(nova_virtqemud|nova_libvirt)\$\"); podman exec \$c virsh -c qemu:///system domstate $INST --reason 2>&1; podman exec \$c virsh -c qemu:///system domblklist $INST 2>&1 | head -6'"
done
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, server $SID; management host $MGMT_HOST, director $DIR_USER@$DIR_HOST (keys are not printed)"
  printf 'SID=%q\nRC=%s\n%s\n' "$SID" "$RC" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1
  echo "== exit $?"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

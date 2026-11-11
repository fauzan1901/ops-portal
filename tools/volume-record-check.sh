#!/usr/bin/env bash
# Read-only: the volume records of an instance, as Nova and Cinder keep them, side by side: Nova's block device mappings
# (volume, attachment, LUN and target of the stored connection; never the whole connection info, it holds the CHAP
# secret), and for each of their volumes every Cinder row that names it (its ID, its name_id, its display name, a
# migration target:<ID>), deleted rows included, with their attachments and metadata keys; the volumes by ID through the
# API; on the compute: the disk of the running domain (device, WWID, the NetApp serial to look up with lun show -serial,
# the serial the guest sees). For a record left by a Cinder volume migration that never completed (vm-c3, 2026-11-02:
# Nova's volume 7a3c9e01 gone from Cinder, the target 8b4d0f12 named "7a3c9e01-..."). SELECT / show / list only.
# Same path as the portal: portal service account -> management host -> director -> controller (galera) / compute.
# Run on the bastion:  sudo bash ~/volume-record-check.sh <SITE> <server ID or exact name>
set -u
SITE="${1:-}"
SID="${2:-}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$SID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ || "$SID" =~ ^[A-Za-z0-9_.-]{1,64}$ ]] \
  || { echo "Server: an OpenStack UUID or an exact instance name"; exit 1; }
OUT="/home/deploy/volume-record-check-$(date +%Y%m%d-%H%M%S).txt"
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
if ! [[ "$SID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
  IDS=$(openstack server list --all-projects --name "^${SID//./\\.}\$" -f value -c ID 2>&1)
  n=$(printf '%s\n' "$IDS" | grep -cE '^[0-9a-f-]{36}$')
  [ "$n" = 1 ] || { echo "Instance name $SID: $n instance(s) with exactly that name (give its ID):"; printf '%s\n' "$IDS" | head -10; exit 1; }
  echo "Instance name $SID = $IDS"
  SID=$IDS
fi
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
onin() {   # onin <ip> <user> <arg> < script: the script runs as root on the node, with <arg> as $1
  local u="$2"; [ "$u" = "-" ] && u=$DEFUSR
  ssh -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$u@$1" "sudo bash -s -- $3"
}
echo "== Instance (Nova)"
openstack server show "$SID" -f value -c name -c status -c OS-EXT-STS:task_state -c OS-EXT-SRV-ATTR:host \
  -c OS-EXT-SRV-ATTR:instance_name -c project_id -c volumes_attached 2>&1 | head -12
HOST=$(openstack server show "$SID" -f value -c OS-EXT-SRV-ATTR:host 2>/dev/null)
INST=$(openstack server show "$SID" -f value -c OS-EXT-SRV-ATTR:instance_name 2>/dev/null)
read -r CN CIP CUSR < <(nodes controller | head -1)
[ -z "${CIP:-}" ] || [ "$CIP" = "-" ] && { echo "no controller in the inventory"; exit 1; }
SQLQ() {   # one SELECT on the galera of the first controller, tab separated
  on "$CIP" "$CUSR" "sudo podman exec \$(sudo podman ps -q --filter name=galera-bundle | head -n 1) mysql -B -e \"$1\"" 2>&1
}
echo "== Nova block device mappings of the instance (deleted ones too; LUN / target of the stored connection only)"
SQLQ "SELECT id, deleted, boot_index, device_name, volume_id, attachment_id, volume_size, created_at, updated_at, \
IFNULL(JSON_VALUE(connection_info,'$.serial'),'') AS conn_serial, IFNULL(JSON_VALUE(connection_info,'$.volume_id'),'') AS conn_volume, \
IFNULL(JSON_VALUE(connection_info,'$.data.volume_id'),'') AS data_volume, IFNULL(JSON_VALUE(connection_info,'$.data.target_iqn'),'') AS iqn, \
IFNULL(JSON_VALUE(connection_info,'$.data.target_lun'),'') AS lun, IFNULL(JSON_EXTRACT(connection_info,'$.data.target_luns'),'') AS luns \
FROM nova.block_device_mapping WHERE instance_uuid='$SID' AND destination_type='volume' ORDER BY deleted, boot_index"
VOLS=$(SQLQ "SELECT DISTINCT volume_id FROM nova.block_device_mapping WHERE instance_uuid='$SID' AND destination_type='volume' AND deleted=0" \
  | grep -oE '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$')
for V in $VOLS; do
  echo "== Volume $V: every Cinder row naming it (by ID, name_id, display name, migration target), deleted ones too"
  SQLQ "SELECT id, deleted, deleted_at, _name_id, display_name, status, attach_status, migration_status, host, project_id, size, \
bootable, volume_type_id, created_at, updated_at FROM cinder.volumes WHERE id='$V' OR _name_id='$V' OR display_name='$V' \
OR migration_status='target:$V' ORDER BY created_at"
  IDS=$(SQLQ "SELECT id FROM cinder.volumes WHERE id='$V' OR _name_id='$V' OR display_name='$V' OR migration_status='target:$V'" \
    | grep -oE '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$' | sort -u)
  LIST=$(printf "'%s'," $IDS $V | sed 's/,$//')
  echo "-- their attachments (deleted ones too; connector host, whether a connection is stored)"
  SQLQ "SELECT id, volume_id, deleted, instance_uuid, attach_status, attached_host, mountpoint, attach_time, detach_time, \
IFNULL(JSON_VALUE(connector,'$.host'),'') AS connector_host, IF(connection_info IS NULL,0,1) AS has_connection, updated_at \
FROM cinder.volume_attachment WHERE volume_id IN ($LIST) ORDER BY created_at"
  echo "-- metadata keys (glance metadata: what a boot volume carries for Nova; admin metadata; user metadata)"
  SQLQ "SELECT 'glance', volume_id, deleted, COUNT(*) FROM cinder.volume_glance_metadata WHERE volume_id IN ($LIST) GROUP BY volume_id, deleted \
UNION ALL SELECT 'admin', volume_id, deleted, GROUP_CONCAT(\\\`key\\\`) FROM cinder.volume_admin_metadata WHERE volume_id IN ($LIST) GROUP BY volume_id, deleted \
UNION ALL SELECT 'user', volume_id, deleted, GROUP_CONCAT(\\\`key\\\`) FROM cinder.volume_metadata WHERE volume_id IN ($LIST) GROUP BY volume_id, deleted"
  echo "-- the API, by ID (a show that answers another ID found the volume by its NAME, not by this ID)"
  for X in $IDS $V; do
    printf '%s: ' "$X"; openstack volume show "$X" -f value -c id -c status -c migration_status 2>&1 | tr '\n' ' ' | cut -c1-200; echo
  done
  echo "-- Cinder attachment records (API 3.27, the list only)"
  for X in $IDS $V; do cinder --os-volume-api-version 3.27 attachment-list --all-tenants --volume-id "$X" 2>&1 | grep -E '^\| [0-9a-f]' | sed "s/^/   $X: /"; done
done
if [ -n "${HOST:-}" ] && [ -n "${INST:-}" ]; then
  read -r N IP USR < <(nodes "${HOST%%.*}")
  if [ -n "${IP:-}" ] && [ "$IP" != "-" ]; then
    echo "== $HOST: the disks of $INST (target, source, device-mapper map, WWID, NetApp serial, LUN of its paths, serial the guest sees)"
    onin "$IP" "$USR" "$INST" <<'NODE' | cut -c1-300
I=$1
c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$')
[ -z "$c" ] && { echo "no libvirt container running"; exit 0; }
V="timeout 30 podman exec $c virsh -c qemu:///system"
$V domstate --reason "$I" 2>&1 | head -1
$V dumpxml "$I" 2>/dev/null | awk '/<disk /{d=1; s=""; t=""; ser=""} d && /<source dev=/{match($0, /dev=.[^"\x27]*/); s=substr($0, RSTART+5, RLENGTH-5)} d && /<target dev=/{match($0, /dev=.[^"\x27]*/); t=substr($0, RSTART+5, RLENGTH-5)} d && /<serial>/{gsub(/.*<serial>|<\/serial>.*/, ""); ser=$0} /<\/disk>/{if (d) print t, s, ser; d=0}' |
while read -r t s ser; do
  m=$(basename "$(readlink -f "$s")")
  w=$(cat /sys/block/$m/dm/name 2>/dev/null)
  hex=${w#3600a0980}
  sn=$(python3 -c 'import sys; print(bytes.fromhex(sys.argv[1]).decode("ascii", "replace"))' "$hex" 2>/dev/null)
  luns=$(for p in $(ls /sys/block/$m/slaves 2>/dev/null); do basename "$(readlink -f /sys/block/$p/device)"; done | tr '\n' ' ')
  echo "$t: $s -> $m, WWID ${w:-?}, NetApp serial ${sn:-?}, paths (H:C:T:L) ${luns:-none}; serial in the guest: ${ser:-none}"
done
NODE
  fi
fi
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, server $SID; management host $MGMT_HOST, director $DIR_USER@$DIR_HOST (keys are not printed)"
  printf 'SID=%q\nRC=%s\n%s\n' "$SID" "$RC" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1 \
    | grep -v 'post-quantum\|store now, decrypt\|openssh.com/pq\|server may need to be upgraded'
  echo "== exit $?"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

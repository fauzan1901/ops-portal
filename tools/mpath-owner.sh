#!/usr/bin/env bash
# Read-only: whose disk is a multipath device on a compute? For a hard reboot (or delete) that failed at "Flushing
# <wwid> failed" (os-brick disconnect_volume): Nova disconnects the volumes of the instance with the connection info
# saved in its block device mapping. When that info is stale (target LUN of another host), the LUN number it names can
# be ANOTHER volume on this compute. Shows the connection info Nova keeps for the instance (no password: only target,
# LUN, device path, serial), the multipath device (paths, open count), which device that LUN number is on this compute,
# which running domain uses the multipath device (its name, UUID, state, the volume serial of that disk), and the
# kernel / qemu messages of that time.
# Same path as the portal: portal service account -> management host -> director -> controller / compute.
# Run on the bastion:  sudo bash ~/mpath-owner.sh <SITE> <compute short name> <multipath WWID> <server ID>
set -u
SITE="${1:-}"
NODE="${2:-}"
WWID="${3:-}"
SID="${4:-}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$NODE" =~ ^[a-z0-9-]{1,63}$ ]] || { echo "Compute: its short name, e.g. dcbrhosp-az1-compute-2"; exit 1; }
[[ "$WWID" =~ ^3[0-9a-f]{32}$ ]] || { echo "WWID: 3 and 32 hex digits, e.g. 3600a09803831384c712b557361544945"; exit 1; }
[[ "$SID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || { echo "Server ID: an OpenStack UUID"; exit 1; }
OUT="/home/deploy/mpath-owner-$(date +%Y%m%d-%H%M%S).txt"
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

# runs on the compute as root; WWID and LUN are set before it
ONNODE=$(cat <<'EOF'
set -u
MP=$(command -v multipath >/dev/null && echo multipath || echo "podman exec multipathd multipath")
V="podman exec $(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$') virsh -c qemu:///system"
echo "== $(hostname -s), now $(date '+%F %T %Z')"
echo "-- multipath device $WWID: paths and state"
$MP -ll "$WWID" 2>&1 | head -14
DM=$(basename "$(readlink -f /dev/mapper/$WWID 2>/dev/null)")
echo "-- /dev/mapper/$WWID -> ${DM:-not present}; open count (0 = nothing uses it):"
dmsetup info -c --noheadings -o name,open,attr "$WWID" 2>&1 | head -2
if [ -n "${LUN:-}" ]; then
  echo "-- the device LUN $LUN of target ${IQN:-?} is on this compute (the LUN Nova would disconnect for the instance)"
  ls -l /dev/disk/by-path/ 2>/dev/null | grep -E "${IQN:-iscsi}-lun-$LUN( |$)" | awk '{print $9, $10, $11}' | head -8
fi
echo "-- running domains that use $WWID (${DM:-?}): name, UUID, state, the volume serial of that disk"
for d in $($V list --name 2>/dev/null); do
  [ -z "$d" ] && continue
  X=$($V dumpxml "$d" 2>/dev/null)
  if printf '%s' "$X" | grep -qE "/dev/(${DM:-none}|mapper/$WWID|disk/by-id/dm-uuid-mpath-$WWID)[^0-9a-f]"; then
    echo "$d uuid $($V domuuid "$d" 2>/dev/null) state $($V domstate "$d" --reason 2>/dev/null | head -1)"
    printf '%s\n' "$X" | awk -v dev="${DM:-none}" -v w="$WWID" '/<disk /{b=""} {b=b $0 "\n"} /<\/disk>/{if (b ~ ("/dev/" dev "[^0-9]") || b ~ w) print b}' \
      | grep -E "<source |<target |<serial>" | sed 's/^ */   /'
    grep -hE "I/O error|error|paused" /var/log/containers/libvirt/qemu/$d.log 2>/dev/null | tail -5 | sed 's/^/   qemu log: /'
  fi
done
echo "-- kernel messages of today about ${DM:-?} or its paths (I/O errors, path failures), last 25"
SDS=$($MP -ll "$WWID" 2>/dev/null | grep -oE ' sd[a-z]+ ' | tr -d ' ' | tr '\n' '|' | sed 's/|$//')
journalctl -k --since today --no-pager 2>/dev/null | grep -E "(${DM:-none}|$WWID${SDS:+|$SDS})[^0-9a-z]" | tail -25
EOF
)

REMOTE=$(cat <<'EOF'
set -u
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
read -r CN CIP CUSR < <(nodes controller | head -1)
[ "$CUSR" = "-" ] && CUSR=$DEFUSR
Q="SELECT volume_id, attachment_id, JSON_VALUE(connection_info,'\$.driver_volume_type') AS type, JSON_VALUE(connection_info,'\$.data.target_iqn') AS iqn, JSON_VALUE(connection_info,'\$.data.target_lun') AS lun, JSON_EXTRACT(connection_info,'\$.data.target_luns') AS luns, JSON_VALUE(connection_info,'\$.data.device_path') AS device_path, JSON_VALUE(connection_info,'\$.serial') AS serial, updated_at FROM nova.block_device_mapping WHERE instance_uuid='$SID' AND deleted=0 AND destination_type='volume'"
echo "== Connection info Nova keeps for $SID (block_device_mapping; no password), read on $CN"
ROWS=$(ssh -n -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$CUSR@$CIP" \
  "sudo podman exec \$(sudo podman ps -q -f name=galera-bundle | head -1) mysql -N -B -e \"$Q\"" 2>&1)
printf '%s\n' "$ROWS" | awk -F'\t' '{printf "volume %s attachment %s type %s\n   iqn %s lun %s luns %s\n   device_path %s serial %s updated %s\n", $1,$2,$3,$4,$5,$6,$7,$8,$9}'
IQN=$(printf '%s\n' "$ROWS" | head -1 | cut -f4)
LUN=$(printf '%s\n' "$ROWS" | head -1 | cut -f5)
[[ "$LUN" =~ ^[0-9]+$ ]] || LUN=""
read -r N IP USR < <(nodes "$NODE")
[ -z "${IP:-}" ] || [ "$IP" = "-" ] && { echo "$NODE: not in the inventory $INV"; exit 1; }
[ "$USR" = "-" ] && USR=$DEFUSR
echo
echo "######## $NODE ($USR@$IP)"
printf 'WWID=%q\nLUN=%q\nIQN=%q\n%s\n' "$WWID" "$LUN" "$IQN" "$ONNODE" | ssh -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$USR@$IP" "sudo -n bash -s"
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, compute $NODE, multipath $WWID, instance $SID; management host $MGMT_HOST, director $DIR_USER@$DIR_HOST (keys are not printed)"
  printf 'SID=%q\nNODE=%q\nWWID=%q\nONNODE=%q\n%s\n' "$SID" "$NODE" "$WWID" "$ONNODE" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1
  echo "== exit $?"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

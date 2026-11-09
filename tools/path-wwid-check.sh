#!/usr/bin/env bash
# Read-only: does every path of an instance's disks present the LUN of its multipath map? For a migration the portal
# did not start on "stale connection info" while Nova's LUN is a path of the instance's own map (a real case,
# tenant-staging-3: LUN 294 is a path of dm-221, but that path reports WWID ...484b4d and the map is
# ...24e73). Per disk of the domain: the map (name = WWID), its paths with the WWID each one reports now (sysfs and
# udev), its SCSI address, state and iSCSI target; per volume Nova's target and LUN (no secret) and every device at that
# LUN on the sessions of that target, its map and the domain using it; multipathd's own view of those paths; the maps of
# any other WWID seen, the domain using them; the kernel / multipathd lines of those devices (14 days); and on the
# controller the other Nova connections on this compute with the same LUN numbers.
# Same path as the portal: portal service account -> management host -> director -> controller / compute.
# Only show / list / grep / SELECT.   Run on the bastion:  sudo bash ~/path-wwid-check.sh <SITE> <server ID or name>
set -u
SITE="${1:-}"
SID="${2:-}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$SID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || { echo "Server: its ID or its exact name"; exit 1; }
OUT="/home/deploy/path-wwid-check-$(date +%Y%m%d-%H%M%S).txt"
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

ONNODE=$(cat <<'NODE'
c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$')
V="podman exec $c virsh -c qemu:///system"
MPD=$(podman ps --format '{{.Names}}' | grep -m1 -x multipathd)
MP() { if [ -n "$MPD" ]; then podman exec "$MPD" multipath "$@"; else multipath "$@"; fi; }
MPDC() { if [ -n "$MPD" ]; then podman exec "$MPD" multipathd "$@"; else multipathd "$@"; fi; }
ww() { sed -E 's/^naa\./3/' /sys/block/$1/device/wwid 2>/dev/null; }
hcil() { basename "$(readlink -f /sys/block/$1/device)"; }
tgt() {   # the iSCSI target and portal of the session a SCSI device is on
  local h s
  h=$(readlink -f /sys/block/$1/device | grep -oE '/host[0-9]+/' | head -1 | tr -dc 0-9)
  s=$(ls -d /sys/class/iscsi_host/host$h/device/session* 2>/dev/null | head -1)
  s=$(basename "${s:-none}")
  echo "$(cat /sys/class/iscsi_session/$s/targetname 2>/dev/null || echo '?') $(cat /sys/class/iscsi_connection/connection${s#session}:0/persistent_address 2>/dev/null || echo '?')"
}
udevid() { udevadm info --query=property --name=/dev/$1 2>/dev/null | grep -E '^(ID_SERIAL|ID_WWN|ID_SCSI_SERIAL)=' | tr '\n' ' '; }
# which running domain uses which device (dm-N or sdX)
U=$(podman exec "$c" sh -c 'for x in $(virsh -c qemu:///system list --name); do virsh -c qemu:///system domblklist $x 2>/dev/null | awk -v x=$x "\$2 ~ /^\/dev\// {print \$2, x}"; done' |
    while read -r s x; do echo "$(basename "$(readlink -f "$s")") $x"; done)
users() { printf '%s\n' "$U" | awk -v d="$1" '$1 == d {print $2}' | paste -sd, -; }
SEEN=""
OTHER=""
echo "domain $INST: $($V domstate $INST 2>&1 | head -1)"
echo "-- the disks of $INST: each path with the WWID it reports now (MISMATCH: not the WWID of its map)"
for pair in $($V domblklist $INST 2>/dev/null | awk '$2 ~ /^\/dev\// {print $1 "=" $2}'); do
  t=${pair%%=*}; src=${pair#*=}
  dm=$(basename "$(readlink -f "$src")")
  if [ ! -e /sys/block/$dm/dm ]; then echo "DISK $t $src $dm: not a device-mapper device (wwid $(ww $dm))"; continue; fi
  w=$(cat /sys/block/$dm/dm/name 2>/dev/null)
  echo "DISK $t $src $dm map $w uuid $(cat /sys/block/$dm/dm/uuid 2>/dev/null) holders: $(ls /sys/block/$dm/holders 2>/dev/null | paste -sd, -) used by: $(users $dm)"
  MP -ll /dev/$dm 2>/dev/null | sed 's/^/     /'
  for sd in $(ls /sys/block/$dm/slaves 2>/dev/null); do
    pw=$(ww $sd)
    [ "$pw" = "$w" ] && m=ok || { m=MISMATCH; OTHER="$OTHER $pw"; }
    SEEN="$SEEN $sd"
    echo "   path $sd $(hcil $sd) state=$(cat /sys/block/$sd/device/state 2>/dev/null) wwid=$pw $m target $(tgt $sd) | udev: $(udevid $sd)"
  done
done
echo "-- the devices at Nova's LUN of each volume, on the sessions of its target"
printf '%s\n' "$PAIRS" | while read -r q l; do
  [ -n "$q" ] || continue
  for ss in /sys/class/iscsi_session/session*; do
    [ "$(cat $ss/targetname 2>/dev/null)" = "$q" ] || continue
    h=$(ls -d $ss/device/target* 2>/dev/null | head -1 | sed -E 's/.*target([0-9]+):.*/\1/')
    for a in /sys/class/scsi_device/$h:*:*:$l; do
      [ -e "$a" ] || continue
      sd=$(ls $a/device/block 2>/dev/null | head -1); [ -n "$sd" ] || continue
      hd=$(ls /sys/block/$sd/holders 2>/dev/null | head -1)
      echo "LUN $l of $q: $sd $(basename $a) state=$(cat /sys/block/$sd/device/state 2>/dev/null) wwid=$(ww $sd) in map ${hd:-none} ($(cat /sys/block/${hd:-x}/dm/name 2>/dev/null || echo -)) used by: $(users ${hd:-$sd})"
    done
  done
done
echo "-- multipathd's view of those paths: dev, address, wwid it keeps, map, dm state, checker, dev state"
MPDC show paths format "%d %i %w %m %t %T %o" 2>/dev/null | awk -v s=" $SEEN " 'NR == 1 || index(s, " " $1 " ")'
for o in $(printf '%s\n' $OTHER | sort -u); do
  echo "-- WWID $o (reported by a path of the instance): its map on this compute and who uses it"
  x=$(MP -ll "$o" 2>/dev/null)
  [ -n "$x" ] && printf '%s\n' "$x" | sed 's/^/     /' || echo "     no map named $o"
  d=$(printf '%s\n' "$x" | grep -oE ' dm-[0-9]+ ' | head -1 | tr -d ' ')
  [ -n "$d" ] && echo "     $d used by: $(users $d)"
  for sd in $(ls /sys/block | grep -E '^sd'); do [ "$(ww $sd)" = "$o" ] && echo "     $sd $(hcil $sd) holder $(ls /sys/block/$sd/holders 2>/dev/null | paste -sd, -) target $(tgt $sd)"; done | head -12
done
P=$(printf '%s\n' $SEEN | sort -u | paste -sd'|' -)
if [ -n "$P" ]; then
  echo "-- kernel and multipathd lines of those devices, last 14 days (journal, /var/log/messages, multipathd container log)"
  { journalctl -k --since '-14 days' --no-pager -o short-iso 2>/dev/null
    zgrep -h -E 'kernel:|multipathd' /var/log/messages* 2>/dev/null
    zcat -f /var/log/containers/stdouts/multipathd.log* 2>/dev/null; } |
    grep -E "\b($P)\b" | grep -iE 'wwid|changed|inquiry|lun|attached|add|remov|fail|reinstat|offline|error|reset|uuid' | sort -u | tail -40
fi
NODE
)

REMOTE=$(cat <<'EOF'
set -u
source $RC >/dev/null 2>&1 || { echo "source $RC failed"; exit 1; }
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
asroot() {
  local N IP USR
  read -r N IP USR < <(nodes "$1")
  [ -z "${IP:-}" ] || [ "$IP" = "-" ] && { echo "$1: not in the inventory"; return 1; }
  [ "$USR" = "-" ] && USR=$DEFUSR
  ssh -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$USR@$IP" "sudo -n bash -s"
}
if ! [[ "$SID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
  IDS=$(openstack server list --all-projects --name "^${SID}\$" -f value -c ID 2>&1)
  [ "$(printf '%s\n' "$IDS" | grep -c .)" = 1 ] || { echo "name $SID: $(printf '%s\n' "$IDS" | paste -sd' ') (one instance needed: give its ID)"; exit 1; }
  SID=$IDS
fi
CTL=$(nodes controller | head -1 | cut -d' ' -f1)
echo "== Instance $SID: $(openstack server show "$SID" -f value -c name -c status -c OS-EXT-STS:task_state -c OS-EXT-SRV-ATTR:host -c OS-EXT-SRV-ATTR:instance_name 2>&1 | paste -sd' ')"
HOST=$(openstack server show "$SID" -f value -c OS-EXT-SRV-ATTR:host 2>/dev/null)
INST=$(openstack server show "$SID" -f value -c OS-EXT-SRV-ATTR:instance_name 2>/dev/null)
echo "== Nova's connection of each volume (device, volume, target, LUN; no secret)"
Q="SELECT b.device_name, b.volume_id, JSON_VALUE(b.connection_info,'\$.data.target_iqn') iqn, JSON_VALUE(b.connection_info,'\$.data.target_lun') lun, JSON_VALUE(b.connection_info,'\$.serial') serial FROM nova.block_device_mapping b WHERE b.instance_uuid='$SID' AND b.deleted=0 AND b.destination_type='volume' ORDER BY b.device_name"
ROWS=$(printf 'podman exec $(podman ps -q -f name=galera-bundle | head -1) mysql -N -B -e %q\n' "$Q" | asroot "$CTL")
printf '%s\n' "$ROWS" | column -t
PAIRS=$(printf '%s\n' "$ROWS" | awk 'NF >= 4 && $3 ~ /^iqn\./ && $4 ~ /^[0-9]+$/ {print $3, $4}' | sort -u)
LUNS=$(printf '%s\n' "$PAIRS" | awk '{print $2}' | sort -u | paste -sd, -)
echo "== On ${HOST%%.*}"
printf 'INST=%q\nPAIRS=%q\n%s\n' "$INST" "$PAIRS" "$ONNODE" | asroot "${HOST%%.*}" | cut -c1-400
if [ -n "$LUNS" ]; then
  echo "== Nova connections of instances on ${HOST%%.*} with the same LUN number(s) $LUNS (other instances = stale info)"
  Q="SELECT i.display_name, b.instance_uuid, i.vm_state, b.volume_id, JSON_VALUE(b.connection_info,'\$.data.target_iqn') iqn, JSON_VALUE(b.connection_info,'\$.data.target_lun') lun, b.updated_at FROM nova.block_device_mapping b JOIN nova.instances i ON i.uuid = b.instance_uuid AND i.deleted = 0 WHERE b.deleted = 0 AND b.destination_type = 'volume' AND i.host = '$HOST' AND JSON_VALUE(b.connection_info,'\$.data.target_lun') IN ($LUNS)"
  printf 'podman exec $(podman ps -q -f name=galera-bundle | head -1) mysql -t -e %q\n' "$Q" | asroot "$CTL"
fi
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, instance $SID; management host $MGMT_HOST, director $DIR_USER@$DIR_HOST (keys are not printed)"
  printf 'SID=%q\nONNODE=%q\nRC=%s\n%s\n' "$SID" "$ONNODE" "$RC" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1 | grep -v 'post-quantum\|store now, decrypt\|openssh.com/pq'
  echo "== exit ${PIPESTATUS[1]}"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

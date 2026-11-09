#!/usr/bin/env bash
# Bring back the paths of a VM disk whose SCSI devices a migration rollback removed on its compute (the multipath map
# is left with no path: "dm-N ##,##", the guest gets I/O errors). Scans ONLY the one LUN of that disk on the iSCSI
# sessions of its target, and keeps the new devices only when their WWID is the WWID of the existing map.
#   0. read-only checks: the instance (on this compute, ACTIVE), its block device mapping for the disk (target, LUN; no
#      secret), the domain disk on that dm device, the map (WWID, no path), the iSCSI sessions of that target (host
#      numbers), devices of that LUN now;
#   1. typed RESCAN: echo "0 0 <LUN>" into /sys/class/scsi_host/host<N>/scan for each session host of the target where
#      no device is at that address now (a device there is never scanned nor deleted: Nova's LUN may be stale); a new
#      device whose WWID is not the map's is deleted again at once; multipathd adds the right ones to the map; the map is
#      shown after. Nothing in the guest is touched: its filesystem (XFS shut down / ext4 read-only) needs the owner.
# Same path as the portal: portal service account -> management host -> director -> controller / compute.
# Run on the bastion:  sudo bash ~/lun-rescan.sh <SITE> <server ID> <compute short name> <dm-N>
set -u
SITE="${1:-}"
SID="${2:-}"
NODE="${3:-}"
DM="${4:-}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$SID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || { echo "Server ID: a UUID"; exit 1; }
[[ "$NODE" =~ ^[a-z0-9-]{1,63}$ ]] || { echo "Compute: its short name"; exit 1; }
[[ "$DM" =~ ^dm-[0-9]+$ ]] || { echo "Device: dm-N"; exit 1; }
STAMP=$(date +%Y%m%d-%H%M%S)
OUT="/home/deploy/lun-rescan-$STAMP.txt"
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

# on the compute as root; MODE check | rescan; DM, INST, IQN, LUN set before
ONNODE=$(cat <<'NODE'
set -u
c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$')
V="podman exec $c virsh -c qemu:///system"
MPD=$(podman ps --format '{{.Names}}' | grep -m1 -x multipathd)
MP() { if [ -n "$MPD" ]; then podman exec "$MPD" multipath "$@"; else multipath "$@"; fi; }
WWID=$(cat /sys/block/$DM/dm/name 2>/dev/null)
echo "map $DM: ${WWID:-none}"
MP -ll /dev/$DM 2>&1 | head -6
echo "domain $INST disk on $DM: $($V domblklist $INST 2>/dev/null | awk -v d="/dev/$DM" '$2 == d {print $1}')"
ISCSIADM() { if command -v iscsiadm >/dev/null; then iscsiadm "$@"; else podman exec iscsid iscsiadm "$@"; fi; }
HOSTS=$(ISCSIADM -m session -P 3 2>/dev/null | awk -v t="$IQN" '/^Target: /{on=($2 == t)} on && /Host Number:/{print $3}' | sort -u | tr '\n' ' ')
echo "iSCSI session hosts of target $IQN: ${HOSTS:-none}"
echo "devices of LUN $LUN on those hosts now: $(for h in $HOSTS; do ls -d /sys/class/scsi_host/host$h/device/session*/target$h:0:0/$h:0:0:$LUN 2>/dev/null; done | wc -l)"
OK=1
[[ "$(cat /sys/block/$DM/dm/uuid 2>/dev/null)" == mpath-* ]] || { echo "CHECK FAILED: $DM is not a multipath map (uuid $(cat /sys/block/$DM/dm/uuid 2>/dev/null); an LVM- uuid = a guest LV the host activated)"; OK=0; }
[ -n "$($V domblklist $INST 2>/dev/null | awk -v d="/dev/$DM" '$2 == d')" ] || { echo "CHECK FAILED: $DM is not a disk of $INST"; OK=0; }
[ -n "$HOSTS" ] || { echo "CHECK FAILED: no iSCSI session of the target"; OK=0; }
if [ "$MODE" = "check" ]; then [ $OK = 1 ] && echo "READY"; exit 0; fi
[ $OK = 1 ] || { echo "NOT DONE: a check failed"; exit 1; }
SCANNED=""
for h in $HOSTS; do
  if ls -d /sys/class/scsi_host/host$h/device/session*/target$h:0:0/$h:0:0:$LUN >/dev/null 2>&1; then
    echo "== host$h: a device is at $h:0:0:$LUN already: not scanned, never touched"
    continue
  fi
  echo "== scan LUN $LUN on host$h"
  echo "0 0 $LUN" > /sys/class/scsi_host/host$h/scan
  SCANNED="$SCANNED $h"
done
sleep 5
for h in $SCANNED; do
  for d in /sys/class/scsi_host/host$h/device/session*/target$h:0:0/$h:0:0:$LUN/block/*; do
    [ -e "$d" ] || continue
    sd=$(basename "$d"); w="3$(cat /sys/block/$sd/device/wwid 2>/dev/null | sed -E 's/^naa\.//')"
    if [ "$w" = "$WWID" ]; then
      echo "$h:0:0:$LUN $sd: WWID $w = the map, kept"
      [ -n "$MPD" ] && podman exec "$MPD" multipathd add path $sd >/dev/null 2>&1
    else
      echo "$h:0:0:$LUN $sd: WWID $w is NOT the map ($WWID): deleted again"
      echo 1 > /sys/block/$sd/device/delete
    fi
  done
done
sleep 3
echo "== map after"
MP -ll /dev/$DM 2>&1 | head -8
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
CTL=$(nodes controller | head -1 | cut -d' ' -f1)
S=$(openstack server show "$SID" -f value -c name -c status -c OS-EXT-STS:power_state -c OS-EXT-SRV-ATTR:host -c OS-EXT-SRV-ATTR:instance_name 2>&1 | paste -sd' ')
echo "== Instance: $S"
INST=$(openstack server show "$SID" -f value -c OS-EXT-SRV-ATTR:instance_name 2>/dev/null)
HOST=$(openstack server show "$SID" -f value -c OS-EXT-SRV-ATTR:host 2>/dev/null)
[ "${HOST%%.*}" = "$NODE" ] || { echo "the instance is on $HOST, not on $NODE: stop"; exit 1; }
DISK=$(printf 'c=$(podman ps --format "{{.Names}}" | grep -m1 -E "^(nova_virtqemud|nova_libvirt)$"); podman exec $c virsh -c qemu:///system domblklist %s | awk -v d=/dev/%s '"'"'$2 == d {print $1}'"'"'\n' "$INST" "$DM" | asroot "$NODE")
echo "== Its disk on $DM: ${DISK:-none}"
ROW=$(printf 'podman exec $(podman ps -q -f name=galera-bundle | head -1) mysql -N -B -e %q\n' \
  "SELECT volume_id, JSON_VALUE(connection_info,'\$.data.target_iqn'), JSON_VALUE(connection_info,'\$.data.target_lun') FROM nova.block_device_mapping WHERE instance_uuid='$SID' AND deleted=0 AND destination_type='volume' AND device_name='/dev/$DISK'" | asroot "$CTL" | head -1)
VOLID=$(printf '%s' "$ROW" | cut -f1); IQN=$(printf '%s' "$ROW" | cut -f2); LUN=$(printf '%s' "$ROW" | cut -f3)
echo "== Nova's connection of /dev/$DISK: volume ${VOLID:-?}, target ${IQN:-?}, LUN ${LUN:-?}"
[[ "$LUN" =~ ^[0-9]+$ ]] && [ -n "$IQN" ] || { echo "no target / LUN for that disk: stop"; exit 1; }
printf 'MODE=%q\nDM=%q\nINST=%q\nIQN=%q\nLUN=%q\n%s\n' "$MODE" "$DM" "$INST" "$IQN" "$LUN" "$ONNODE" | asroot "$NODE"
EOF
)

remote() {
  printf 'MODE=%q\nSID=%q\nNODE=%q\nDM=%q\nONNODE=%q\nRC=%s\n%s\n' "$1" "$SID" "$NODE" "$DM" "$ONNODE" "$RC" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1 | grep -v 'post-quantum\|store now, decrypt\|openssh.com/pq'
}

exec > >(tee "$OUT") 2>&1
echo "$(date -Is) site $SITE, instance $SID, compute $NODE, device $DM"
echo "######## 0. Checks (read-only)"
R0=$(remote check)
printf '%s\n' "$R0"
printf '%s\n' "$R0" | grep -qx "READY" || { echo "Not going on: a check failed."; chown deploy: "$OUT" 2>/dev/null; exit 1; }
echo
read -r -p ">>> Scan only that LUN on the target's session hosts (devices with another WWID are deleted again)? Type RESCAN to go on: " ans </dev/tty
[ "$ans" = "RESCAN" ] || { echo "Stopped, nothing was changed."; chown deploy: "$OUT" 2>/dev/null; exit 0; }
echo "######## 1. Rescan"
remote rescan
chown deploy: "$OUT" 2>/dev/null
echo "Saved: $OUT"

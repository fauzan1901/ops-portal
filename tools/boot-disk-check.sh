#!/usr/bin/env bash
# Read-only: why does an instance say "Boot failed: not a bootable disk"? Compares how its domain boots now with how
# it booted before (the old domain definition kept on its former compute, if any): firmware (BIOS / UEFI loader),
# machine type, disk bus and source of every disk. Shows the image properties it was created with (hw_firmware_type,
# hw_disk_bus, hw_machine_type...), and on its compute the disk it boots from: multipath WWID, size, partition table
# (GPT / MBR, partition types) and the boot signature of sector 0. Nothing is written: dd reads one sector, fdisk -l /
# blkid -p only read.
# Same path as the portal: portal service account -> management host -> director -> controller / computes.
# Run on the bastion:  sudo bash ~/boot-disk-check.sh <SITE> <server ID> <volume ID> [former compute short name]
set -u
SITE="${1:-}"
SID="${2:-}"
VOL="${3:-}"
OLD="${4:-}"
UUID_RE='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
for x in "$SID" "$VOL"; do [[ "$x" =~ $UUID_RE ]] || { echo "Usage: <SITE> <server ID> <volume ID> [former compute]"; exit 1; }; done
[ -z "$OLD" ] || [[ "$OLD" =~ ^[a-z0-9-]{1,63}$ ]] || { echo "Former compute: its short name"; exit 1; }
OUT="/home/deploy/boot-disk-check-$(date +%Y%m%d-%H%M%S).txt"
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

# on a compute: the boot related parts of the domain XML; with DISK=1 also the disk it boots from
ONNODE=$(cat <<'NODE'
c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$')
V="podman exec $c virsh -c qemu:///system"
echo "-- domain $INST: $($V domstate $INST 2>&1 | head -1)"
X=$($V dumpxml --inactive $INST 2>/dev/null)
[ -z "$X" ] && { echo "not defined here"; exit 0; }
printf '%s\n' "$X" | sed -n '/<os/,/<\/os>/p'
printf '%s\n' "$X" | grep -E "<loader|<nvram|<smbios|machine=" | sort -u
printf '%s\n' "$X" | awk '/<disk /{b=""; on=1} on{b=b $0 "\n"} /<\/disk>/{on=0; print b}' | grep -E "<disk |<driver |<source |<target |<boot |<serial>|<address " | sed 's/^ */   /'
[ "${DISK:-0}" = "1" ] || exit 0
SRC=$(printf '%s\n' "$X" | awk '/<disk /{b=""; on=1} on{b=b $0 "\n"} /<\/disk>/{on=0; if (b ~ /device=.disk./) {print b; exit}}' | grep -oE "<source dev='[^']+'" | head -1 | cut -d"'" -f2)
echo "-- the first disk of the domain: ${SRC:-none}"
[ -n "$SRC" ] || exit 0
MP=$(command -v multipath >/dev/null && echo multipath || echo "podman exec multipathd multipath")
$MP -ll "$SRC" 2>&1 | head -4
echo "size: $(blockdev --getsize64 "$SRC" 2>/dev/null) bytes"
echo "-- partition table (fdisk -l, read-only)"
fdisk -l "$SRC" 2>&1 | grep -vE "^$" | head -20
echo "-- sector 0: last 32 bytes (a BIOS boot sector ends with 55 aa) and whether it is all zero"
dd if="$SRC" bs=512 count=1 iflag=direct status=none | od -A d -t x1 | tail -3
Z=$(dd if="$SRC" bs=512 count=1 iflag=direct status=none | tr -d '\000' | wc -c)
echo "non-zero bytes in sector 0: $Z"
echo "-- first 1 MiB all zero? $( [ "$(dd if="$SRC" bs=1M count=1 iflag=direct status=none | tr -d '\000' | wc -c)" = "0" ] && echo yes || echo no )"
echo "-- signatures (blkid -p)"
blkid -p "$SRC" 2>&1 | head -3
DMN=$(cat /sys/block/$(basename $(readlink -f $SRC))/dm/name 2>/dev/null)
for p in $(ls /dev/mapper/${DMN}p[0-9]* /dev/mapper/${DMN}-part[0-9]* 2>/dev/null | head -6); do blkid -p "$p" 2>&1 | head -1; done   # its partitions only
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
HOST=$(openstack server show "$SID" -f value -c OS-EXT-SRV-ATTR:host 2>/dev/null)
INST=$(openstack server show "$SID" -f value -c OS-EXT-SRV-ATTR:instance_name 2>/dev/null)
echo "== Instance: $(openstack server show "$SID" -f value -c status -c OS-EXT-STS:power_state -c OS-EXT-SRV-ATTR:host 2>&1 | paste -sd' ')"
echo "== Image properties of the volume (volume_image_metadata)"
openstack volume show "$VOL" -f json -c volume_image_metadata -c bootable -c size 2>&1 | python3 -c '
import json, sys
v = json.load(sys.stdin)
print("bootable", v.get("bootable"), "size", v.get("size"))
for k, val in sorted((v.get("volume_image_metadata") or {}).items()):
    if k.startswith(("hw_", "os_", "image_name", "disk_format", "img_")):
        print("  ", k, "=", val)' 2>&1
echo "== Image properties Nova keeps for the instance (instance_system_metadata image_hw_* / image_os_*)"
printf 'podman exec $(podman ps -q -f name=galera-bundle | head -1) mysql -N -B -e %q\n' \
  "SELECT \`key\`, value FROM nova.instance_system_metadata WHERE instance_uuid='$SID' AND deleted=0 AND (\`key\` LIKE 'image_hw_%' OR \`key\` LIKE 'image_os_%' OR \`key\` LIKE 'image_img_%' OR \`key\` = 'image_disk_format')" | asroot "$CTL"
echo "== BDM of the instance (device, bus, boot index)"
printf 'podman exec $(podman ps -q -f name=galera-bundle | head -1) mysql -N -B -e %q\n' \
  "SELECT device_name, disk_bus, device_type, boot_index, source_type, destination_type, volume_id FROM nova.block_device_mapping WHERE instance_uuid='$SID' AND deleted=0" | asroot "$CTL"
echo
echo "######## now: ${HOST%%.*}"
printf 'INST=%q\nDISK=1\n%s\n' "$INST" "$ONNODE" | asroot "${HOST%%.*}"
if [ -n "$OLD" ]; then
  echo
  echo "######## before: $OLD (the domain definition left there)"
  printf 'INST=%q\nDISK=0\n%s\n' "$INST" "$ONNODE" | asroot "$OLD"
fi
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, instance $SID, volume $VOL, former compute ${OLD:--}; management host $MGMT_HOST, director $DIR_USER@$DIR_HOST (keys are not printed)"
  printf 'SID=%q\nVOL=%q\nOLD=%q\nONNODE=%q\nRC=%s\n%s\n' "$SID" "$VOL" "$OLD" "$ONNODE" "$RC" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1 | grep -v 'post-quantum\|store now, decrypt\|openssh.com/pq'
  echo "== exit $?"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

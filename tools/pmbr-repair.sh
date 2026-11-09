#!/usr/bin/env bash
# Write back sector 0 (the protective MBR with the FreeBSD BIOS boot code, pmbr) of a pfSense boot volume whose sector 0
# was found damaged (SeaBIOS: "Boot failed: not a bootable disk"; the GPT header and gptzfsboot after it intact). The
# sector written is the one of 5 other volumes made from the same, since deleted, Glance image 41909d33 (all 5
# identical, SHA-256 893f21d3...; their GPT header identical to this volume's, so the same origin): 512 bytes, nothing else.
#   0. read-only checks: the instance, the disk of its domain (the BDM LUN, used by no other domain), its sector 0 now,
#      its GPT header (sector 1: EFI PART), the sector to write (SHA-256);
#   1. typed STOP: openstack server stop (power off only; the volume stays connected), wait for SHUTOFF;
#   2. typed WRITE: on its compute, with its domain shut off: backup of the first 1 MiB (root-only file there), write the
#      512 bytes to sector 0 (O_DIRECT, fsync), read back and compare;
#   3. typed START: openstack server start, its state, then a console screenshot (PNG on the bastion).
# Same path as the portal: portal service account -> management host -> director -> controller / compute.
# Run on the bastion:  sudo bash ~/pmbr-repair.sh <SITE> <server ID> <volume ID>
set -u
SITE="${1:-}"
SID="${2:-}"
VOL="${3:-}"
UUID_RE='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
for x in "$SID" "$VOL"; do [[ "$x" =~ $UUID_RE ]] || { echo "Usage: <SITE> <server ID> <volume ID>"; exit 1; }; done
S0B64="/DHAjsCO2I7QvAAOvhp8vxoGueYB86TpAIqA+oByC4o2dQSAxoA48nICsoDo0QC2AbsADr6RB+isAGaBPgAORUZJIHUNZoE+BA5QQVJUdQLrH4D+AQ+FuwC2AL4QEr+RB2aDLAFmg1wEALkEAPOl68C+SA67ABDobACJ3r+ZB7kQAPOmdUCJ3411ILvAB47DMdtW6FAAXmaLRShmOwR1D2aLRSxmO0QEdQWOw+lRdWaDBAFmg1QEAIzAg8AgPQCQc02OwOvMZv8OUA50UaFUDgHDgfsAEnKiZoMGSA4BZoMWTA4A64tm/3QEZv80BlNqAWoQiea4AELNE4PEEHIaw74AEscEHgC4AEjNE3ILw74xB+sWvkcH6xG+XwfrDL59B+sHuwcAtA7NEKyEwHX06/5Cb290IGxvYWRlciB0b28gbGFyZ2UASW52YWxpZCBwYXJ0aXRpb24gdGFibGUASS9PIGVycm9yIGxvYWRpbmcgYm9vdCBsb2FkZXIATWlzc2luZyBib290IGxvYWRlcgABAAAAAAAAAJ1rvYNBf9wRvgsAFWC4Tw+QkJCQkJCQkJCQkJCQkJAAAAAAAAAAAAIA7v///wEAAAD//z8BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVao="
S0SHA=893f21d3e738ce35680c858ac7d71b7143516739d8cb494be2fa506f7b169ae1
[ "$(printf '%s' "$S0B64" | base64 -d | sha256sum | cut -d' ' -f1)" = "$S0SHA" ] || { echo "the sector to write is not the expected one"; exit 1; }
STAMP=$(date +%Y%m%d-%H%M%S)
OUT="/home/deploy/pmbr-repair-$STAMP.txt"
SHOT="/home/deploy/console-$SID-$STAMP.png"
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

LIB=$(cat <<'EOF'
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
asroot() {   # asroot <node short name>: runs stdin as root on the node
  local N IP USR
  read -r N IP USR < <(nodes "$1")
  [ -z "${IP:-}" ] || [ "$IP" = "-" ] && { echo "$1: not in the inventory"; return 1; }
  [ "$USR" = "-" ] && USR=$DEFUSR
  ssh -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$USR@$IP" "sudo -n bash -s"
}
CTL=$(nodes controller | head -1 | cut -d' ' -f1)
sql() {
  printf 'podman exec $(podman ps -q -f name=galera-bundle | head -1) mysql -N -B -e %q\n' "$1" | asroot "$CTL"
}
HOST=$(openstack server show "$SID" -f value -c OS-EXT-SRV-ATTR:host 2>/dev/null)
NODE=${HOST%%.*}
INST=$(openstack server show "$SID" -f value -c OS-EXT-SRV-ATTR:instance_name 2>/dev/null)
ROW=$(sql "SELECT attachment_id, JSON_VALUE(connection_info,'\$.driver_volume_type'), JSON_VALUE(connection_info,'\$.data.target_iqn'), JSON_VALUE(connection_info,'\$.data.target_lun') FROM nova.block_device_mapping WHERE instance_uuid='$SID' AND volume_id='$VOL' AND deleted=0" | head -1)
BATT=$(printf '%s' "$ROW" | cut -f1); BTYPE=$(printf '%s' "$ROW" | cut -f2); IQN=$(printf '%s' "$ROW" | cut -f3); LUN=$(printf '%s' "$ROW" | cut -f4)
# on the compute: the devices of LUN $LUN of target $IQN, the multipath above them, and the domains that use it
LUNCHECK=$(cat <<'NODE'
c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$')
DMS=""
for p in $(ls /dev/disk/by-path/ 2>/dev/null | grep -E -- "-$IQN-lun-$LUN\$"); do
  d=$(basename "$(readlink -f /dev/disk/by-path/$p)")
  m=$(ls /sys/block/$d/holders 2>/dev/null | head -1)
  echo "path $p -> $d${m:+ -> $m ($(cat /sys/block/$m/dm/name 2>/dev/null))}"
  DMS="$DMS $d ${m:-}"
done
[ -z "$DMS" ] && echo "no device of LUN $LUN on this compute"
for x in $(podman exec $c virsh -c qemu:///system list --name); do
  for s in $(podman exec $c virsh -c qemu:///system domblklist $x | awk '$2 ~ /^\/dev\// {print $2}'); do
    for dv in $DMS; do [ "$s" = "/dev/$dv" ] && echo "USED BY $x ($s)"; done
  done
done
NODE
)
EOF
)

DISKDEF=$(cat <<'DEFEOF'
# on the compute, as root: the disk of the domain (by its volume serial), checked against the BDM LUN; MODE check | write
DISK=$(cat <<'NODE'
set -u
c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$')
V="podman exec $c virsh -c qemu:///system"
STATE=$($V domstate $INST 2>&1 | head -1)
SRC=$($V dumpxml --inactive $INST 2>/dev/null | awk -v v="$VOL" '/<disk /{b=""; on=1} on{b=b $0 "\n"} /<\/disk>/{on=0; if (index(b, "<serial>" v "</serial>")) print b}' | grep -oE "<source dev='[^']+'" | head -1 | cut -d"'" -f2)
DM=$(basename "$(readlink -f "${SRC:-/nonexistent}")")
NAME=$(cat /sys/block/$DM/dm/name 2>/dev/null)
LUNDM=""
for p in $(ls /dev/disk/by-path/ 2>/dev/null | grep -E -- "-$IQN-lun-$LUN\$"); do
  d=$(basename "$(readlink -f /dev/disk/by-path/$p)"); LUNDM=$(ls /sys/block/$d/holders 2>/dev/null | head -1)
done
USERS=""
for x in $($V list --name); do
  [ "$x" = "$INST" ] && continue
  $V domblklist $x | awk '$2 ~ /^\/dev\// {print $2}' | grep -qx "/dev/$DM" && USERS="$USERS $x"
done
echo "domain $INST: $STATE; its disk $SRC = $DM ($NAME); LUN $LUN of the BDM = ${LUNDM:-no device}; other domains on it:${USERS:- none}"
OK=1
[ -n "$SRC" ] && [ -b "$SRC" ] && [ "$DM" = "$LUNDM" ] || { echo "CHECK FAILED: the disk of the domain is not the LUN of the BDM"; OK=0; }
[ -z "$USERS" ] || { echo "CHECK FAILED: another domain uses the disk"; OK=0; }
echo "size $(blockdev --getsize64 "$SRC" 2>/dev/null) bytes; sector 0 now: sha256 $(dd if="$SRC" bs=512 count=1 iflag=direct status=none | sha256sum | cut -c1-16), ends with $(dd if="$SRC" bs=1 skip=510 count=2 iflag=direct status=none | od -A n -t x1 | tr -d ' \n'); sector 1: $(dd if="$SRC" bs=512 skip=1 count=1 iflag=direct status=none | head -c 8)"
if [ "$MODE" = "write" ]; then
  [ "$STATE" = "shut off" ] || { echo "NOT WRITTEN: the domain is '$STATE', it must be shut off"; exit 1; }
  [ $OK = 1 ] || { echo "NOT WRITTEN: a check failed"; exit 1; }
  umask 077
  B=/root/pmbr-backup-$VOL-$STAMP.bin
  dd if="$SRC" of="$B" bs=1M count=1 iflag=direct status=none && echo "backup of the first 1 MiB: $B ($(stat -c %s "$B") bytes)"
  printf '%s' "$S0B64" | base64 -d > /root/pmbr-new-$VOL.bin
  [ "$(sha256sum < /root/pmbr-new-$VOL.bin | cut -d' ' -f1)" = "$S0SHA" ] || { echo "NOT WRITTEN: the sector to write is not the expected one"; exit 1; }
  dd if=/root/pmbr-new-$VOL.bin of="$SRC" bs=512 count=1 oflag=direct conv=fsync status=none && echo "sector 0 written"
  R=$(dd if="$SRC" bs=512 count=1 iflag=direct status=none | sha256sum | cut -d' ' -f1)
  [ "$R" = "$S0SHA" ] && echo "VERIFIED: sector 0 read back is the written one (sha256 ${R:0:16})" || echo "VERIFY FAILED: sector 0 read back is ${R:0:16}"
  rm -f /root/pmbr-new-$VOL.bin
else
  [ $OK = 1 ] && echo "DISK OK"
fi
NODE
)

ondisk() {   # ondisk <check|write>, on the director
  printf 'MODE=%q\nINST=%q\nVOL=%q\nIQN=%q\nLUN=%q\nSTAMP=%q\nS0B64=%q\nS0SHA=%q\n%s\n' "$1" "$INST" "$VOL" "$IQN" "$LUN" "$STAMP" "$S0B64" "$S0SHA" "$DISK" | asroot "$NODE"
}
DEFEOF
)

PHASE0=$(cat <<'EOF'
echo "== Instance: $(openstack server show "$SID" -f value -c status -c OS-EXT-STS:power_state -c OS-EXT-STS:task_state -c OS-EXT-SRV-ATTR:host 2>&1 | paste -sd' ')"
echo "== BDM: attachment $BATT, type $BTYPE, lun $LUN"
echo "== The disk on $NODE"
ondisk check
EOF
)

PHASE1=$(cat <<'EOF'
echo "== openstack server stop $SID"
openstack server stop "$SID" && echo "stop requested at $(date '+%T')"
for i in $(seq 1 30); do
  sleep 10
  V=$(openstack server show "$SID" -f value -c status -c OS-EXT-STS:task_state 2>/dev/null | paste -sd' ')
  echo "  $(date '+%T') task_state status: $V"
  [[ "$V" == "None SHUTOFF" ]] && break
done
ondisk check
EOF
)

PHASE2=$(cat <<'EOF'
echo "== Write sector 0 on $NODE"
ondisk write
EOF
)

PHASE3=$(cat <<'EOF'
echo "== openstack server start $SID"
openstack server start "$SID" && echo "start requested at $(date '+%T')"
for i in $(seq 1 40); do
  sleep 15
  V=$(openstack server show "$SID" -f value -c status -c OS-EXT-STS:power_state -c OS-EXT-STS:task_state 2>/dev/null | paste -sd' ')
  echo "  $(date '+%T') power_state task_state status: $V"
  [[ "$V" == *" None "* && ( "$V" == *ACTIVE || ( "$V" == *SHUTOFF && $i -gt 2 ) ) ]] && break
done
echo "== Console screenshot (90 s after the start)"
sleep 90
printf '%s\n' "c=\$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)\$'); podman exec \$c virsh -c qemu:///system screenshot $INST /tmp/shot-$SID >/dev/null 2>&1 && podman exec \$c cat /tmp/shot-$SID | base64 -w0; podman exec \$c rm -f /tmp/shot-$SID" | asroot "$NODE" | sed 's/^/SHOT /'
EOF
)

remote() {
  printf 'SID=%q\nVOL=%q\nSTAMP=%q\nS0B64=%q\nS0SHA=%q\nRC=%s\n%s\n%s\n%s\n' "$SID" "$VOL" "$STAMP" "$S0B64" "$S0SHA" "$RC" "$LIB" "$DISKDEF" "$1" \
    | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
      "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1 \
    | grep -v 'post-quantum\|store now, decrypt\|openssh.com/pq'
}
confirm() {
  echo
  read -r -p ">>> $2 Type $1 to go on (anything else stops): " ans </dev/tty
  [ "$ans" = "$1" ] || { echo "Stopped here."; chown deploy: "$OUT" 2>/dev/null; exit 0; }
}

exec > >(tee "$OUT") 2>&1
echo "$(date -Is) site $SITE, instance $SID, volume $VOL; sector to write: sha256 ${S0SHA:0:16}"
echo "######## 0. Checks (read-only)"
R0=$(remote "$PHASE0")
printf '%s\n' "$R0"
printf '%s\n' "$R0" | grep -q "^DISK OK" || { echo "Not going on: a check failed."; chown deploy: "$OUT" 2>/dev/null; exit 1; }
confirm STOP "Step 1: stop the instance (power off; the volume stays connected)."
remote "$PHASE1"
confirm WRITE "Step 2: back up the first 1 MiB of the disk and write the 512 bytes of sector 0."
R2=$(remote "$PHASE2")
printf '%s\n' "$R2"
printf '%s\n' "$R2" | grep -q "^VERIFIED" || { echo "Not starting: the write was not verified."; chown deploy: "$OUT" 2>/dev/null; exit 1; }
confirm START "Step 3: start the instance."
R3=$(remote "$PHASE3")
printf '%s\n' "$R3" | grep -v '^SHOT '
B64=$(printf '%s\n' "$R3" | grep '^SHOT ' | cut -c6- | tr -d '\n')
if [ -n "$B64" ]; then
  B64="$B64" "$PY" - "$SHOT" <<'PY'
import base64, os, sys
sys.path.insert(0, "/opt/ops-portal/modules/wi/wi_analysis")
data = base64.b64decode(os.environ["B64"])
try:
    import wi_ops
    data = wi_ops.to_png(data) or data
except Exception as exc:
    print("PNG conversion failed (%s): the raw screenshot is saved" % exc)
open(sys.argv[1], "wb").write(data)
print("console screenshot saved: " + sys.argv[1])
PY
  chown deploy: "$SHOT" 2>/dev/null
fi
chown deploy: "$OUT" 2>/dev/null
echo "Saved: $OUT"

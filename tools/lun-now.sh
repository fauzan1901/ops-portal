#!/usr/bin/env bash
# Read-only: which LUN does the storage present NOW behind the multipath disks of a compute, and who uses it? For a path
# whose LUN number came to present another LUN (a real case, tenant-staging-3 on ha-7: map dm-221 kept WWID
# ...24e73, a 60 GiB volume, while its paths at LUN 294 reported ...484b4d and 100 GiB; the volume itself never changed).
# The kernel keeps a path's WWID and size from its last scan; a fresh SCSI INQUIRY (scsi_id, VPD pages 0x83 / 0x80) and
# READ CAPACITY (sg_readcap, when installed) show what the LUN number gives now. INQUIRY and READ CAPACITY change nothing.
# Prints the compute's iSCSI initiator name first (to find its igroup on the storage). Three ways to call it:
#   dm-N     one map: each path in full, the I/O of the map in 10 s, the domain using it;
#   lun-N    the devices at LUN number N on every session of the compute: each in full, the map holding it, its user;
#   all      every multipath map: only the maps with a path whose WWID (kernel or INQUIRY now) or size is not the map's.
# Same path as the portal: portal service account -> management host -> director -> the compute.
# Run on the bastion:  sudo bash ~/lun-now.sh <SITE> <compute short name> <dm-N | lun-N | all>
set -u
SITE="${1:-}"
NODE="${2:-}"
WHAT="${3:-}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$NODE" =~ ^[a-z0-9-]{1,63}$ ]] || { echo "Compute: its short name, e.g. overcloud-novacomputeha-7"; exit 1; }
[[ "$WHAT" =~ ^(dm-[0-9]{1,5}|lun-[0-9]{1,5}|all)$ ]] || { echo "Third argument: dm-N, lun-N or all"; exit 1; }
OUT="/home/deploy/lun-now-$NODE-$WHAT-$(date +%Y%m%d-%H%M%S).txt"
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
SCSI_ID=$(ls /usr/lib/udev/scsi_id /lib/udev/scsi_id 2>/dev/null | head -1)
READCAP=$(command -v sg_readcap)
MPD=$(podman ps --format '{{.Names}}' | grep -m1 -x multipathd)
c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$')
echo "$(hostname -s): iSCSI initiator $(sed -n 's/^InitiatorName=//p' /etc/iscsi/initiatorname.iscsi 2>/dev/null)"
# block device (dm-N or sdX) -> domain and its disk target, for every running domain
USERS=$(podman exec "$c" sh -c 'for x in $(virsh -c qemu:///system list --name); do u=$(virsh -c qemu:///system domuuid $x 2>/dev/null); virsh -c qemu:///system domblklist $x 2>/dev/null | awk -v x=$x -v u=$u "\$2 ~ /^\/dev\// {print \$1, \$2, x, u}"; done' |
  while read -r t s x u; do echo "$(basename "$(readlink -f "$s")") $x $t $u"; done)
# the domain, its disk and the instance ID (the domain UUID is the Nova instance ID)
user_of() { echo "$USERS" | awk -v d="$1" '$1 == d {printf "%s%s %s (instance %s)", (n++ ? ", " : ""), $2, $3, $4} END {if (!n) printf "none"}'; }
wwid_of() { sed -E 's/^naa\./3/' /sys/block/$1/device/wwid 2>/dev/null; }
# a fresh INQUIRY only on a running path (a blocked one would wait for the session)
now83() { [ -n "$SCSI_ID" ] && [ "$(cat /sys/block/$1/device/state)" = running ] && timeout 10 $SCSI_ID --whitelisted --page=0x83 --device=/dev/$1 2>/dev/null | head -1; }
where() {
  local s; s=$(readlink -f /sys/block/$1/device | grep -o 'session[0-9]*' | head -1)
  [ -n "$s" ] && echo "$(cat /sys/class/iscsi_session/$s/targetname 2>/dev/null) $(cat /sys/class/iscsi_connection/connection${s#session}:0/persistent_address 2>/dev/null)"
}
detail() {
  local sd=$1 st
  st=$(cat /sys/block/$sd/device/state)
  echo "path $sd $(basename "$(readlink -f /sys/block/$sd/device)") state $st holder $(ls /sys/block/$sd/holders | paste -sd, -) target $(where $sd)"
  echo "   kernel keeps: wwid $(wwid_of $sd), size $(blockdev --getsize64 /dev/$sd) bytes"
  if [ -z "$SCSI_ID" ]; then
    echo "   INQUIRY now: scsi_id not found"
  elif [ "$st" != running ]; then
    echo "   INQUIRY now: not sent (path $st)"
  else
    echo "   INQUIRY now: page 0x83 $(timeout 10 $SCSI_ID --whitelisted --page=0x83 --device=/dev/$sd 2>&1 | head -1), page 0x80 $(timeout 10 $SCSI_ID --whitelisted --page=0x80 --device=/dev/$sd 2>&1 | head -1)"
  fi
  if [ "$st" != running ]; then
    echo "   READ CAPACITY now: not sent (path $st)"
  elif [ -n "$READCAP" ]; then
    echo "   READ CAPACITY now: $(timeout 10 $READCAP --long /dev/$sd 2>&1 | grep -E 'Last LBA|Logical block length|Device size' | tr -s ' ' | paste -sd' ' -)"
  elif [ -n "$MPD" ] && podman exec "$MPD" sh -c 'command -v sg_readcap' >/dev/null 2>&1; then
    echo "   READ CAPACITY now: $(timeout 10 podman exec "$MPD" sg_readcap --long /dev/$sd 2>&1 | grep -E 'Last LBA|Logical block length|Device size' | tr -s ' ' | paste -sd' ' -)"
  else
    echo "   READ CAPACITY now: sg_readcap not installed"
  fi
}
io10() {
  local a b r1 rs1 w1 ws1
  a=$(cat /sys/block/$1/stat); sleep 10; b=$(cat /sys/block/$1/stat)
  set -- $a; r1=$1 rs1=$3 w1=$5 ws1=$7
  set -- $b; echo "I/O in 10 s: $(( $1 - r1 )) reads ($(( ($3 - rs1) / 2 )) KiB), $(( $5 - w1 )) writes ($(( ($7 - ws1) / 2 )) KiB); since boot: $5 writes"
}
map_line() { echo "map $1: name $(cat /sys/block/$1/dm/name), uuid $(cat /sys/block/$1/dm/uuid), size $(blockdev --getsize64 /dev/$1) bytes, used by: $(user_of $1)"; }
case "$WHAT" in
(dm-*)
  [ -e /sys/block/$WHAT/dm ] || { echo "$WHAT: no such device-mapper device"; exit 1; }
  map_line $WHAT
  # what else holds the map open (a host LV on it: "map in use" without a domain), and how many paths it has
  echo "holders: $(for h in $(ls /sys/block/$WHAT/holders); do printf '%s (%s) ' $h "$(cat /sys/block/$h/dm/name 2>/dev/null)"; done)"
  echo "open count: $(dmsetup info -c --noheadings -o open $(cat /sys/block/$WHAT/dm/name) 2>/dev/null); path devices: $(ls /sys/block/$WHAT/slaves | wc -l)"
  for sd in $(ls /sys/block/$WHAT/slaves); do detail $sd; done
  echo "$WHAT $(io10 $WHAT)"
  ;;
(lun-*)
  L=${WHAT#lun-}; n=0
  for h in /sys/class/scsi_device/*:*:*:$L; do
    [ -e "$h/device/block" ] || continue
    for sd in $(ls $h/device/block); do
      n=$((n + 1)); detail $sd
      for dm in $(ls /sys/block/$sd/holders); do echo "   in $(map_line $dm)"; done
      [ -z "$(ls /sys/block/$sd/holders)" ] && echo "   in no map; used directly by: $(user_of $sd)"
    done
  done
  [ "$n" -eq 0 ] && echo "LUN $L: no device on any session of this compute"
  ;;
(all)
  maps=0; paths=0; bad=0; asked=0
  for m in /sys/block/dm-*; do
    u=$(cat $m/dm/uuid 2>/dev/null)
    case "$u" in (mpath-*) ;; (*) continue;; esac
    dm=$(basename $m); w=${u#mpath-}; msz=$(blockdev --getsize64 /dev/$dm 2>/dev/null); maps=$((maps + 1)); hit=; out=
    for sd in $(ls $m/slaves); do
      paths=$((paths + 1)); kw=$(wwid_of $sd); nw=$(now83 $sd); psz=$(blockdev --getsize64 /dev/$sd 2>/dev/null); flag=
      [ "$kw" != "$w" ] && flag="$flag kernel-wwid"
      [ -n "$nw" ] && asked=$((asked + 1))
      [ -n "$nw" ] && [ "$nw" != "$w" ] && flag="$flag inquiry-wwid"
      [ "$psz" != "$msz" ] && flag="$flag size"
      [ -n "$flag" ] && hit=1
      out="$out
   path $sd $(basename "$(readlink -f /sys/block/$sd/device)") $(cat /sys/block/$sd/device/state) target $(where $sd): kernel wwid $kw, INQUIRY now ${nw:-not sent}, size $psz${flag:+   <== differs:$flag}"
    done
    [ -n "$hit" ] && { bad=$((bad + 1)); echo "MAP $dm $w size $msz used by: $(user_of $dm)$out"; }
  done
  echo "checked: $maps multipath maps, $paths paths ($asked answered a fresh INQUIRY); $bad map(s) with a path whose WWID or size is not the map's"
  ;;
esac
NODE
)

REMOTE=$(cat <<'EOF'
set -u
INV=$(ls ~/overcloud-deploy/*/tripleo-ansible-inventory.yaml ~/config-download/*/tripleo-ansible-inventory.yaml \
  ~/tripleo-ansible-inventory.yaml 2>/dev/null | head -1)
read -r N IP USR < <(python3 - "$NODE" "$INV" <<'PY'
import sys, yaml
want, path = sys.argv[1].lower(), sys.argv[2]
try:
    inv = yaml.safe_load(open(path)) or {}
except Exception:
    inv = {}
for group, body in inv.items():
    for host, hv in ((body or {}).get("hosts") or {}).items() if isinstance(body, dict) else []:
        if host.split(".")[0].lower() == want and isinstance(hv, dict):
            print(want, hv.get("ctlplane_ip") or hv.get("ansible_host") or "-", hv.get("ansible_ssh_user") or "-")
            sys.exit()
PY
)
[ -n "${IP:-}" ] && [ "$IP" != "-" ] || { echo "$NODE: not in the inventory"; exit 1; }
[ "$USR" = "-" ] && USR=$(grep -q '17\.' /etc/rhosp-release && echo tripleo-admin || echo heat-admin)
printf 'WHAT=%q\n%s\n' "$WHAT" "$ONNODE" | ssh -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$USR@$IP" "sudo -n bash -s"
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, $NODE $WHAT; management host $MGMT_HOST, director $DIR_USER@$DIR_HOST (keys are not printed)"
  printf 'NODE=%q\nWHAT=%q\nONNODE=%q\n%s\n' "$NODE" "$WHAT" "$ONNODE" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1 | grep -v 'post-quantum\|store now, decrypt\|openssh.com/pq'
  echo "== exit ${PIPESTATUS[1]}"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

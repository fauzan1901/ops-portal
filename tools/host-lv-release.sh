#!/usr/bin/env bash
# Release guest LVM LVs that a compute HOST activated on Cinder iSCSI devices (see host-lvm-check.sh), and leftover
# multipath maps without any path. While such an LV sits on a path or on a map, os-brick takes it for the volume's
# multipath device: Nova detach / start / hard reboot fail at "multipath -f <LV name>: not a multipath device"
# (a real case), and a reconnect can hand the domain the LV instead of the map.
#   0. read-only checks per given dm device:
#      - an LV: uuid LVM-*, open 0, no holder, not a disk of a running domain, every device under it an iSCSI path / its partition /
#        a multipath map (never a disk of the host itself), or gone;
#      - a map: uuid mpath-*, no working path, open 0, not a disk of a running domain;
#   1. typed RELEASE: dmsetup remove of each LV (only the host's mapping; nothing is written to the volume), the freed
#      path added back to the map of its WWID (multipathd add path) when that map exists; multipath -f of each map.
# Same path as the portal: portal service account -> management host -> director -> the compute.
# Run on the bastion:  sudo bash ~/host-lv-release.sh <SITE> <compute short name> <dm-N> [<dm-N>...]
set -u
SITE="${1:-}"
CMP="${2:-}"
shift 2 2>/dev/null
DMS="$*"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$CMP" =~ ^[a-z0-9-]{1,63}$ ]] || { echo "Compute: its short name"; exit 1; }
[[ "$DMS" =~ ^dm-[0-9]+( dm-[0-9]+)*$ ]] || { echo "Devices: dm-N, one or more"; exit 1; }
OUT="/home/deploy/host-lv-release-$(date +%Y%m%d-%H%M%S).txt"
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

# on the compute as root; MODE check | release, DMS set before
ONNODE=$(cat <<'NODE'
set -u
c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$')
V="podman exec $c virsh -c qemu:///system"
MPD=$(podman ps --format '{{.Names}}' | grep -m1 -x multipathd)
MP() { if [ -n "$MPD" ]; then podman exec "$MPD" multipath "$@"; else multipath "$@"; fi; }
MPDC() { if [ -n "$MPD" ]; then podman exec "$MPD" multipathd "$@"; else multipathd "$@"; fi; }
wwid_sd() { sed 's/^naa\./3/' /sys/block/$1/device/wwid 2>/dev/null; }
opn() { dmsetup info -c --noheadings -o open "$1" 2>/dev/null | tr -d ' '; }
paths() { MP -ll "/dev/$1" 2>/dev/null | grep -cE ' sd[a-z]+ .*active ready'; }   # $1 = dm-N
mapof() { for x in /sys/block/dm-*; do [ "$(cat $x/dm/uuid 2>/dev/null)" = "mpath-$1" ] && { echo ${x##*/}; return; }; done; }
# disks of running domains block a release; a shut-off domain only keeps an old path in its XML (Nova start rebuilds it)
USERS=$(for x in $($V list --name); do $V domblklist $x 2>/dev/null | awk -v x=$x '$2 ~ /^\/dev\// {print $2, x}'; done |
  while read -r s x; do echo "$(basename "$(readlink -f "$s")") $x"; done)
OFF=$(for x in $($V list --inactive --name); do $V domblklist $x 2>/dev/null | awk -v x=$x '$2 ~ /^\/dev\// {print $2, x}'; done |
  while read -r s x; do echo "$(basename "$(readlink -f "$s")") $x"; done)
who() { printf '%s\n' "$USERS" | awk -v d="$1" '$1 == d {print $2}' | paste -sd, -; }
whooff() { printf '%s\n' "$OFF" | awk -v d="$1" '$1 == d {print $2}' | paste -sd, -; }
OK=1; PLAN=""
for d in $DMS; do
  if [ ! -e /sys/block/$d/dm ]; then echo "$d: no such device-mapper device (already gone)"; continue; fi
  u=$(cat /sys/block/$d/dm/uuid 2>/dev/null); n=$(cat /sys/block/$d/dm/name)
  o=$(opn "$n"); usedby=$(who $d); h=$(ls /sys/block/$d/holders 2>/dev/null | paste -sd, -)
  off=$(whooff $d)
  echo "== $d name=$n uuid=${u:0:12}... open=$o holders=${h:-none} disk-of-running-domain=${usedby:-none}${off:+ (named in the XML of shut-off domain $off: its next Nova start rebuilds the disk from the volume)} table=[$(dmsetup table "$n" 2>/dev/null | head -2 | paste -sd';' -)]"
  [ "$o" = 0 ] || { echo "CHECK FAILED $d: open $o (in use)"; OK=0; }
  [ -z "$h" ] || { echo "CHECK FAILED $d: device-mapper holders $h"; OK=0; }
  [ -z "$usedby" ] || { echo "CHECK FAILED $d: a disk of running domain $usedby"; OK=0; }
  if [[ "$u" == LVM-* ]]; then
    for s in $(ls /sys/block/$d/slaves 2>/dev/null); do
      p=$s; [ -e /sys/class/block/$s/partition ] && p=$(basename "$(dirname "$(readlink -f /sys/class/block/$s)")")
      if [[ "$p" == sd* ]] && [ ! -e /sys/block/$p/device ]; then
        echo "   under it: $s (its SCSI device is already removed from the host)"
        PLAN+="$d $n - - -"$'\n'
      elif [[ "$p" == sd* ]]; then
        a=$(basename "$(readlink -f /sys/block/$p/device)")
        if [ ! -e /sys/class/iscsi_host/host${a%%:*} ]; then echo "CHECK FAILED $d: $s is not an iSCSI device (a disk of the host?)"; OK=0; continue; fi
        w=$(wwid_sd $p); m=$(mapof $w)
        echo "   under it: $s (iSCSI $a wwid=$w); map of this WWID: ${m:-none}${m:+, paths $(paths $m)}"
        PLAN+="$d $n $p $w ${m:--}"$'\n'
      elif [[ "$p" == dm-* ]] && [[ "$(cat /sys/block/$p/dm/uuid 2>/dev/null)" == mpath-* ]]; then
        echo "   under it: multipath map $p $(cat /sys/block/$p/dm/name) (paths $(paths $p), disk of domain: $(who $p | grep . || echo none))"
        PLAN+="$d $n - - -"$'\n'
      else
        echo "CHECK FAILED $d: $s is neither an iSCSI path nor a multipath map"; OK=0
      fi
    done
    [ -n "$(ls /sys/block/$d/slaves 2>/dev/null)" ] || { echo "   under it: nothing left (its device was removed)"; PLAN+="$d $n - - -"$'\n'; }
  elif [[ "$u" == mpath-* ]]; then
    np=$(paths $d)
    echo "   multipath map with $np working path(s)"
    [ "$np" = 0 ] || { echo "CHECK FAILED $d: the map still has working paths (not a leftover)"; OK=0; }
    PLAN+="MAP $n - - -"$'\n'
  else
    echo "CHECK FAILED $d: neither an LVM LV nor a multipath map (uuid ${u:-none})"; OK=0
  fi
done
if [ "$MODE" = "check" ]; then [ $OK = 1 ] && echo "READY"; exit 0; fi
[ $OK = 1 ] || { echo "NOT DONE: a check failed"; exit 1; }
printf '%s' "$PLAN" | while read -r d n p w m; do
  [ -n "$d" ] || continue
  if [ "$d" = MAP ]; then
    MP -f "$n" >/dev/null 2>&1 && echo "map $n flushed" || echo "map $n: flush FAILED"
    continue
  fi
  if dmsetup info "$n" >/dev/null 2>&1; then
    dmsetup remove "$n" && echo "LV $n ($d) removed from the host (the volume is not written)" || { echo "LV $n: remove FAILED"; continue; }
  fi
  if [ "$p" != "-" ] && [ "$m" != "-" ]; then
    MPDC add path "$p" >/dev/null 2>&1; sleep 2
    echo "path $p added back to map $m: now $(paths $m) working path(s)"
  elif [ "$p" != "-" ]; then
    echo "path $p (wwid $w): no map of that WWID here; left as it is"
  fi
done
echo "== after"
for d in $DMS; do [ -e /sys/block/$d/dm ] && echo "$d still present: $(cat /sys/block/$d/dm/name)" || echo "$d: gone"; done
NODE
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
        if isinstance(hv, dict) and want == name and name not in seen:
            seen.add(name)
            print(name, hv.get("ctlplane_ip") or hv.get("ansible_host") or "-", hv.get("ansible_ssh_user") or "-")
PY
}
DEFUSR=$(grep -q '17\.' /etc/rhosp-release && echo tripleo-admin || echo heat-admin)
read -r N IP USR < <(nodes "$CMP")
[ -z "${IP:-}" ] || [ "$IP" = "-" ] && { echo "$CMP: not in the inventory"; exit 1; }
[ "$USR" = "-" ] && USR=$DEFUSR
printf 'MODE=%q\nDMS=%q\n%s\n' "$MODE" "$DMS" "$ONNODE" | ssh -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$USR@$IP" "sudo -n bash -s"
EOF
)

run() {
  printf 'MODE=%q\nCMP=%q\nDMS=%q\nONNODE=%q\n%s\n' "$1" "$CMP" "$DMS" "$ONNODE" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1 | grep -v 'post-quantum\|store now, decrypt\|openssh.com/pq'
}
{
  echo "$(date -Is) site $SITE, compute $CMP, devices: $DMS"
  echo "######## 0. Checks (read-only)"
  run check
} | tee "$OUT"
if grep -q '^READY$' "$OUT"; then
  read -r -p ">>> Remove these host LVs / leftover maps on $CMP (the volumes are not written)? Type RELEASE to go on: " ans </dev/tty
  if [ "$ans" = "RELEASE" ]; then
    { echo "######## 1. Release"; run release; } | tee -a "$OUT"
  else
    echo "Not changed." | tee -a "$OUT"
  fi
else
  echo "Not changed: a check failed." | tee -a "$OUT"
fi
chown deploy: "$OUT"
echo "Saved: $OUT"

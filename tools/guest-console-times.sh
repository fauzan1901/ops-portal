#!/usr/bin/env bash
# Read-only: the kernel lines an instance printed on its serial console (soft lockups, RCU stalls, hung tasks, OOM,
# I/O and link errors) with the wall clock (WIB) of each, and a summary per minute. The guest stamps its lines with
# seconds since it booted; the console log file on the compute is written as the lines come, so its last line is
# anchored to the file's modification time and every other line is placed relative to it (paused time of a migration,
# milliseconds, is the only error). After a live migration the file on the destination holds only what the guest
# printed there; the source keeps its file when Nova left it (pass the source compute to read it too).
# Same path as the portal: portal service account -> management host -> director -> computes. Only reads.
# With raw: every line of the console log as it is (escape codes and carriage returns left out), each with its time
# (WIB; a line the guest printed without a stamp gets the time of the line before it, marked "~").
# Run on the bastion:  sudo bash ~/guest-console-times.sh <SITE> <server ID> [other compute,...] [raw]
#   e.g. sudo bash ~/guest-console-times.sh DCA e08b726b-9dcd-48a3-9b3e-62ea0c52e692 overcloud-novacomputeiha-13
#        sudo bash ~/guest-console-times.sh DCA e08b726b-9dcd-48a3-9b3e-62ea0c52e692 raw
set -u
SITE="${1:-}"
SID="${2:-}"
MORE=""
RAW=0
for x in "${@:3}"; do [ "$x" = raw ] && RAW=1 || MORE="$x"; done
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$SID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || { echo "Server ID: an OpenStack UUID"; exit 1; }
[[ "$MORE" =~ ^[A-Za-z0-9.,-]*$ ]] || { echo "Other computes: names, comma separated"; exit 1; }
OUT="/home/deploy/guest-console-times-$SITE-${SID:0:8}$([ $RAW = 1 ] && echo -raw)-$(date +%Y%m%d-%H%M%S).txt"
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
HOST=$(openstack server show "$SID" -f value -c OS-EXT-SRV-ATTR:host)
INST=$(openstack server show "$SID" -f value -c OS-EXT-SRV-ATTR:instance_name)
echo "== $(openstack server show "$SID" -f value -c name) ($INST) now on $HOST"
FL=$(openstack server show "$SID" -f value -c flavor | sed -E 's/.*\(([0-9a-f-]{36})\).*/\1/')
echo "   flavor: $(openstack flavor show "$FL" -f value -c name -c ram -c vcpus -c properties 2>/dev/null | paste -sd' ' -)"
INV=$(ls ~/overcloud-deploy/*/tripleo-ansible-inventory.yaml ~/config-download/*/tripleo-ansible-inventory.yaml \
  ~/tripleo-ansible-inventory.yaml 2>/dev/null | head -1)
DEFUSR=$(grep -q '17\.' /etc/rhosp-release && echo tripleo-admin || echo heat-admin)
for h in ${MORE//,/ } ${HOST%%.*}; do
  read -r N IP USR < <(python3 - "$h" "$INV" <<'PY'
import sys, yaml
want, path = sys.argv[1].split(".")[0].lower(), sys.argv[2]
try:
    inv = yaml.safe_load(open(path)) or {}
except Exception:
    inv = {}
for group, body in inv.items():
    for host, hv in ((body or {}).get("hosts") or {}).items() if isinstance(body, dict) else []:
        if host.split(".")[0].lower() == want and isinstance(hv, dict) and (hv.get("ctlplane_ip") or hv.get("ansible_host")):
            print(want, hv.get("ctlplane_ip") or hv.get("ansible_host"), hv.get("ansible_ssh_user") or "-")
            raise SystemExit
print(want, "-", "-")
PY
)
  [ "${IP:-}" = "-" ] && { echo "######## $h: no address in the inventory"; continue; }
  [ "$USR" = "-" ] && USR=$DEFUSR
  echo
  echo "######## compute $h"
  ssh -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
    "$USR@$IP" "sudo bash -s -- $SID $INST $RAW" <<'NODE' | cut -c1-$([ $RAW = 1 ] && echo 4000 || echo 260)
SID=$1 INST=$2 RAW=${3:-0}
c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$')
echo "-- memory and CPU settings of this compute (what can stop every vCPU of a large guest at once)"
echo "   $(nproc) CPUs; tuned $(tuned-adm active 2>/dev/null | sed 's/.*: //'); THP $(cat /sys/kernel/mm/transparent_hugepage/enabled) defrag $(cat /sys/kernel/mm/transparent_hugepage/defrag) khugepaged defrag $(cat /sys/kernel/mm/transparent_hugepage/khugepaged/defrag 2>/dev/null)"
echo "   ksm run $(cat /sys/kernel/mm/ksm/run 2>/dev/null) (pages shared $(cat /sys/kernel/mm/ksm/pages_shared 2>/dev/null)); $(sysctl -n kernel.numa_balancing 2>/dev/null | sed 's/^/numa_balancing /'); $(sysctl vm.zone_reclaim_mode vm.min_free_kbytes vm.watermark_scale_factor vm.swappiness 2>/dev/null | paste -sd';' -)"
for n in /sys/devices/system/node/node[0-9]*; do
  echo "   $(basename $n): CPUs $(cat $n/cpulist); $(awk '/MemTotal|MemFree|AnonHugePages/ {printf "%s %d GiB ", $3, $4 / 1048576}' $n/meminfo)"
done
echo "   large guests here (RSS 64 GiB or more): memory per NUMA node, vCPUs, pinning"
ps -eo pid=,rss=,args= | awk '$2 >= 67108864 && /qemu-kvm/' | while read -r pid rss args; do
  g=$(printf '%s' "$args" | grep -oE 'guest=[^, ]+' | head -1 | cut -d= -f2)
  v=$(printf '%s' "$args" | grep -oE '\-smp [0-9]+' | head -1 | awk '{print $2}')
  per=$(awk '{for (i = 2; i <= NF; i++) if ($i ~ /^N[0-9]+=/) {split($i, a, "="); k = a[1]; ps = 4; if (match($0, /kernelpagesize_kB=[0-9]+/)) ps = substr($0, RSTART + 18, RLENGTH - 18); s[k] += a[2] * ps}} END {for (k in s) printf "%s %d GiB ", k, s[k] / 1048576}' /proc/$pid/numa_maps 2>/dev/null)
  aff=$(taskset -pc $pid 2>/dev/null | sed 's/.*: //')
  echo "     $g: RSS $((rss / 1048576)) GiB, $v vCPUs, memory $per, CPUs allowed $aff$([ "$g" = "$INST" ] && echo '  <- this instance')"
done
if [ -n "$c" ] && timeout 30 podman exec $c virsh -c qemu:///system domstate $INST >/dev/null 2>&1; then
  echo "   this instance: numatune $(timeout 30 podman exec $c virsh -c qemu:///system numatune $INST 2>/dev/null | paste -sd' ' - | tr -s ' ');" \
       "vCPU 0 pinned to $(timeout 30 podman exec $c virsh -c qemu:///system vcpupin $INST --vcpu 0 2>/dev/null | awk 'NR > 2 && NF {print $2}')"
fi
P=""
[ -n "$c" ] && P=$(timeout 30 podman exec $c virsh -c qemu:///system dumpxml $INST 2>/dev/null \
  | grep -oE "<log file='[^']+'" | head -1 | sed -E "s/^<log file='//; s/'$//")
[ -n "$P" ] && [ -f "$P" ] || P=/var/lib/nova/instances/$SID/console.log
if [ ! -f "$P" ]; then
  echo "   no console log of the instance here ($P)"
  exit 0
fi
M=$(stat -c %Y "$P")
LAST=$(grep -aoE '^\[ *[0-9]+\.[0-9]+\]' "$P" | tail -1 | tr -d '[] ')
echo "   console log $P: $(wc -l < "$P") line(s), last written $(date -d @$M '+%Y-%m-%d %H:%M:%S %Z') (the anchor of its last stamped line, ${LAST:-none} s since the guest booted)"
[ -n "$LAST" ] || exit 0
echo "   the guest booted about $(date -d @$(awk -v m=$M -v l=$LAST 'BEGIN {printf "%d", m - l}') '+%Y-%m-%d %H:%M:%S %Z')"
echo "   first stamped line: $(date -d @$(awk -v m=$M -v l=$LAST -v f=$(grep -aoE '^\[ *[0-9]+\.[0-9]+\]' "$P" | head -1 | tr -d '[] ') 'BEGIN {printf "%d", m - (l - f)}') '+%H:%M:%S') $(grep -aE '^\[ *[0-9]+\.[0-9]+\]' "$P" | head -1 | cut -c1-160)"
if [ "$RAW" = 1 ]; then
  echo "-- the console log as it is, each line with its time (WIB)"
  sed -e 's/\r//g' -e 's/\x1b\[[0-9;?]*[A-Za-z]//g' "$P" | awk -v m=$M -v l=$LAST '
    match($0, /^\[ *[0-9]+\.[0-9]+\]/) { t = strftime("%Y-%m-%d %H:%M:%S", m - (l - (substr($0, RSTART + 1, RLENGTH - 2) + 0))); print t "   " $0; next }
    { print (t ? t : "-------------------") " ~ " $0 }'
  exit 0
fi
PAT='soft lockup|hard LOCKUP|rcu.*(stall|detected)|blocked for more than|Out of memory|oom-kill|clocksource|I/O error|Link is|link is|NETDEV|nfs: server|connection[0-9:]* error|EXT4-fs error|XFS .*(error|metadata)|watchdog|time jump|virtio'
echo "-- per minute (WIB): soft lockups (vCPUs that did not run for 20 s or more; the longest), hung tasks, other kernel lines"
awk -v m=$M -v l=$LAST -v pat="$PAT" '
  match($0, /^\[ *[0-9]+\.[0-9]+\]/) {
    ts = substr($0, RSTART + 1, RLENGTH - 2) + 0
    if ($0 !~ pat) next
    k = strftime("%Y-%m-%d %H:%M", m - (l - ts))
    if (!(k in seen)) { seen[k] = 1; keys[++n] = k }
    if ($0 ~ /soft lockup/) { lock[k]++; if (match($0, /stuck for [0-9]+s/)) { s = substr($0, RSTART + 10, RLENGTH - 11) + 0; if (s > top[k]) top[k] = s } }
    else if ($0 ~ /blocked for more than/) hung[k]++
    else other[k]++
  }
  END { for (i = 1; i <= n; i++) { k = keys[i]; printf "   %s  soft lockups %3d (longest %2ds)  hung tasks %3d  other %3d\n", k, lock[k], top[k], hung[k], other[k] } }' "$P"
echo "-- the lines (WIB, guest seconds, text; the last 300)"
awk -v m=$M -v l=$LAST -v pat="$PAT" '
  match($0, /^\[ *[0-9]+\.[0-9]+\]/) && $0 ~ pat { ts = substr($0, RSTART + 1, RLENGTH - 2) + 0; print "   " strftime("%H:%M:%S", m - (l - ts)) " " $0 }' "$P" | tail -300
NODE
done
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, server $SID; director $DIR_USER@$DIR_HOST (keys are not printed)"
  printf 'SID=%q\nMORE=%q\nRAW=%q\nRC=%s\n%s\n' "$SID" "$MORE" "$RAW" "$RC" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1 | grep -v '^\*\* '
  echo "== exit ${PIPESTATUS[1]}"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

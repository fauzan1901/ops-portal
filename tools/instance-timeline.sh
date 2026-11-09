#!/usr/bin/env bash
# Read-only: what happened around one instance in a time window (a customer reports its node NotReady at given times),
# and how it is now. The instance (flavor, ports and their networks: provider VLAN or geneve), its own actions in the
# window, every migration of the site in the window (name and RAM of the instance moved, who asked, marked when it
# touched a compute the instance ran on), the instances of its project and their migrations, the migrations still
# running, Nova's and Placement's memory view of its computes; on each such compute: the nova-compute lines of the
# instance's migration (progress, downtime, post-copy) and the migration errors of any instance, the migration settings,
# kernel link / bond / lockup / OOM / memory lines, ovn-controller slow loops and reconnects, sysstat history (CPU, load,
# memory, direct reclaim, traffic and drops per bond and link) when sysstat keeps it, its network layout, and now: memory,
# load, vmstat, drops over 10 s, the domain and its memory, and a ping of the instance from the OVN metadata namespace.
# Last, the items of the portal's fixes that moved the instances of these migrations (usage read, attempts, result).
# Same path as the portal: portal service account -> management host -> director -> computes. Only show / list / grep.
# Run on the bastion:  sudo bash ~/instance-timeline.sh <SITE> <server ID> "<from YYYY-MM-DD HH:MM>" "<to YYYY-MM-DD HH:MM>"
#   (times in WIB), e.g. sudo bash ~/instance-timeline.sh DCA 3a915e67-6f07-4c2f-9196-eabdc165276e "2026-10-31 01:30" "2026-10-31 05:30"
set -u
SITE="${1:-}"
SID="${2:-}"
FROM="${3:-}"
TO="${4:-}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$SID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || { echo "Server ID: an OpenStack UUID"; exit 1; }
[[ "$FROM" =~ ^20[0-9]{2}-[0-9]{2}-[0-9]{2}\ [0-9]{2}:[0-9]{2}$ ]] && [[ "$TO" =~ ^20[0-9]{2}-[0-9]{2}-[0-9]{2}\ [0-9]{2}:[0-9]{2}$ ]] \
  || { echo "From / to: \"YYYY-MM-DD HH:MM\" (WIB)"; exit 1; }
F=$(TZ=Asia/Jakarta date -d "$FROM" +%s) && T=$(TZ=Asia/Jakarta date -d "$TO" +%s) && [ "$T" -gt "$F" ] && [ $((T - F)) -le 86400 ] \
  || { echo "The window must be at most 24 hours, from before to"; exit 1; }
OUT="/home/deploy/instance-timeline-$SITE-${SID:0:8}-$(date +%Y%m%d-%H%M%S).txt"
SVC=opsportal
PY=/opt/ops-portal/.venv/bin/python
DB=/var/lib/ops-portal/portal.db

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
wib() { TZ=Asia/Jakarta date -d "@$1" '+%Y-%m-%d %H:%M:%S'; }
echo "Window: $(wib $F) .. $(wib $T) WIB; now $(wib $(date +%s)) WIB"
echo "== Instance (now)"
openstack server show "$SID" -f json -c name -c status -c OS-EXT-STS:task_state -c OS-EXT-STS:vm_state -c OS-EXT-STS:power_state \
  -c OS-EXT-SRV-ATTR:host -c OS-EXT-SRV-ATTR:instance_name -c flavor -c updated 2>&1 | tr -d '\n' | sed 's/  */ /g'; echo
HOST=$(openstack server show "$SID" -f value -c OS-EXT-SRV-ATTR:host)
INST=$(openstack server show "$SID" -f value -c OS-EXT-SRV-ATTR:instance_name)
PROJ=$(openstack server show "$SID" -f value -c project_id)
echo "== Its ports and networks (provider VLAN networks share the compute's provider bond; geneve goes over the tunnel interface)"
NETIP=""
for p in $(openstack port list --server "$SID" -f value -c ID 2>/dev/null); do
  PJ=$(openstack port show "$p" -f json -c id -c network_id -c fixed_ips -c status -c binding_host_id 2>/dev/null)
  NET=$(printf '%s' "$PJ" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("network_id",""))' 2>/dev/null)
  NJ=$(openstack network show "$NET" -f json -c name -c provider:network_type -c provider:physical_network -c provider:segmentation_id 2>/dev/null)
  LINE=$(PJ="$PJ" NJ="$NJ" python3 -c '
import json, os
p, n = json.loads(os.environ["PJ"] or "{}"), json.loads(os.environ["NJ"] or "{}")
ips = [str(x.get("ip_address")) for x in p.get("fixed_ips") or [] if isinstance(x, dict)]
print("%s=%s" % (p.get("network_id"), ips[0] if ips else "-"))
print("   port %s %s on %s: %s; network %s (%s, physnet %s, segment %s)" % (p.get("id"), p.get("status"), p.get("binding_host_id"),
      ", ".join(ips) or str(p.get("fixed_ips")), n.get("name"), n.get("provider:network_type"), n.get("provider:physical_network"),
      n.get("provider:segmentation_id")))' 2>/dev/null)
  NETIP="$NETIP${NETIP:+,}$(printf '%s\n' "$LINE" | head -1)"
  printf '%s\n' "$LINE" | tail -n +2
done
echo "== Its actions in the window (UTC; WIB = UTC+7)"
openstack server event list "$SID" -f value -c "Request ID" -c Action -c "Start Time" 2>/dev/null | while read -r req act st; do
  e=$(date -u -d "${st%.*}Z" +%s 2>/dev/null) || continue
  [ "$e" -ge $((F - 3600)) ] && [ "$e" -le "$T" ] && echo "   $st ($(wib $e) WIB) $act $req"
done
echo "== Migrations of the site in the window (times WIB); >> = it touched a compute this instance ran on"
MIG=$(openstack --os-compute-api-version 2.59 server migration list --changes-since "$(date -u -d @$((F - 7200)) +%Y-%m-%dT%H:%M:%S)" -f json 2>&1)
REP=$(MIG="$MIG" SID="$SID" HOST="$HOST" F="$F" T="$T" PROJ="$PROJ" python3 - <<'PY'
import datetime, json, os, re, subprocess
from concurrent.futures import ThreadPoolExecutor

def osc(args, timeout=180):
    try:
        p = subprocess.Popen(["openstack"] + args + ["-f", "json"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             universal_newlines=True)
        out, _err = p.communicate(timeout=timeout)
        return json.loads(out) if p.returncode == 0 else None
    except Exception:
        return None

try:
    rows = json.loads(os.environ["MIG"])
except ValueError:
    print(os.environ["MIG"][:600]); rows = []
sid, f, t, proj = os.environ["SID"], int(os.environ["F"]), int(os.environ["T"]), os.environ["PROJ"]
short = lambda v: str(v).split(".")[0]
def uuid(r):
    """The instance of a migration row, whatever the client calls the column (Server UUID, Instance UUID, server_id)."""
    for k, v in r.items():
        key = k.strip().lower()
        if v and key not in ("uuid", "migration uuid", "id") and ("uuid" in key or key in ("server", "server id", "server_id")):
            return str(v)
    return ""
if rows and not any(uuid(r) for r in rows):
    print("   (no instance column in the migration list; its columns: " + ", ".join(sorted(rows[0])) + ")")
def ep(v):
    try:
        return int(datetime.datetime.strptime(str(v)[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc).timestamp())
    except ValueError:
        return None
def wib(e):
    return datetime.datetime.fromtimestamp(e, datetime.timezone(datetime.timedelta(hours=7))).strftime("%H:%M:%S") if e else "?"
full = {short(os.environ["HOST"]): os.environ["HOST"]}
hosts = {short(os.environ["HOST"])}
for r in rows:
    for k in ("Source Compute", "Dest Compute"):
        if r.get(k):
            full.setdefault(short(r[k]), str(r[k]))
    if uuid(r) == sid:
        hosts |= {short(r.get("Source Compute")), short(r.get("Dest Compute"))}
hosts = {h for h in hosts if h and h != "None"}
near = [r for r in rows if ep(r.get("Created At")) and ep(r.get("Updated At"))
        and ep(r.get("Updated At")) >= f - 1800 and ep(r.get("Created At")) <= t]
FINAL = {"completed", "error", "failed", "cancelled", "done", "confirmed", "reverted", "finished"}
running = [r for r in rows if str(r.get("Status")).lower() not in FINAL]
uuids = sorted({uuid(r) for r in near + running if uuid(r)})

def info(u):
    s = osc(["--os-compute-api-version", "2.47", "server", "show", u]) or {}
    ev = osc(["server", "event", "list", "--long", u]) or []
    return u, s, ev
with ThreadPoolExecutor(6) as ex:
    infos = {u: (s, ev) for u, s, ev in ex.map(info, uuids)}

def ram_gib(s):
    m = re.search(r"\bram'?\"?\s*[:=]\s*'?(\d+)", str(s.get("flavor")))
    return int(m.group(1)) // 1024 if m else None
def who(r):
    s, ev = infos.get(uuid(r), ({}, []))
    c = ep(r.get("Created At")) or 0
    for e in ev:
        st = ep(str(e.get("Start Time") or "").replace(" ", "T"))
        if "migrat" in str(e.get("Action")) and st and abs(st - c) <= 300:
            return str(e.get("User ID") or "?"), str(e.get("Request ID") or "")
    return "?", ""
mine = [who(r)[0] for r in near if uuid(r) == sid]
portal_user = mine[0] if mine else ""
def line(r):
    c, u = ep(r.get("Created At")), ep(r.get("Updated At"))
    s, d = short(r.get("Source Compute")), short(r.get("Dest Compute"))
    srv = infos.get(uuid(r), ({}, []))[0]
    mark = ">>" if (s in hosts or d in hosts) else "  "
    user, _req = who(r)
    tags = []
    if uuid(r) == sid:
        tags.append("THIS INSTANCE")
    elif srv.get("project_id") == proj:
        tags.append("SAME PROJECT")
    g = ram_gib(srv)
    return (f"{mark} {wib(c)} - {wib(u)} ({(u - c) // 60} min) migration {r.get('Id')} {r.get('Status')} {s} -> {d}: "
            f"{srv.get('name') or uuid(r)} ({g if g is not None else '?'} GiB RAM)"
            f" by {'the same account as its own migration' if portal_user and user == portal_user else 'user ' + user[:8]}"
            + (f" [{', '.join(tags)}]" if tags else ""))
print(f"   computes of the instance: {' '.join(sorted(hosts))}")
for r in sorted(near, key=lambda r: ep(r.get("Created At"))):
    print("   " + line(r))
print(f"   {len(near)} migration(s) in or around the window, "
      f"{sum(1 for r in near if short(r.get('Source Compute')) in hosts or short(r.get('Dest Compute')) in hosts)} touching "
      f"{', '.join(sorted(hosts))}")
for r in near:
    if short(r.get("Source Compute")) in hosts or short(r.get("Dest Compute")) in hosts:
        print(f"@@touch {uuid(r)} {r.get('Id')} {infos.get(uuid(r), ({}, []))[0].get('name') or '-'}")
print("== Migrations of the site still running now")
for r in running:
    print("   " + line(r))
if not running:
    print("   none (every migration of the last hours has ended)")
print("== Instances of its project now, and their migrations in the window")
vms = osc(["server", "list", "--all-projects", "--project", proj, "--long"]) or []
for v in sorted(vms, key=lambda v: str(v.get("Name")))[:60]:
    moved = [f"{wib(ep(r.get('Created At')))}-{wib(ep(r.get('Updated At')))} {short(r.get('Source Compute'))}->"
             f"{short(r.get('Dest Compute'))} {r.get('Status')}" for r in near if uuid(r) == v.get("ID")]
    print(f"   {v.get('Name')}: {v.get('Status')}, task {v.get('Task State') or '-'}, power {v.get('Power State')}, "
          f"on {short(v.get('Host'))}" + (f"; migrated {'; '.join(moved)}" if moved else ""))
if not vms:
    print("   (the list could not be read)")
print("== Memory of its computes as Nova and Placement count it (flavors, not the real use)")
for h in sorted(hosts):
    hv = osc(["hypervisor", "show", full.get(h, h)]) or {}
    print(f"   {h}: memory_mb {hv.get('memory_mb')}, used by flavors {hv.get('memory_mb_used')}, free {hv.get('free_ram_mb')}, "
          f"running VMs {hv.get('running_vms')}, vCPUs {hv.get('vcpus_used')}/{hv.get('vcpus')}")
    rp = osc(["resource", "provider", "list", "--name", full.get(h, h)]) or []
    if rp:
        inv = osc(["resource", "provider", "inventory", "list", rp[0].get("uuid")]) or []
        for i in inv:
            if i.get("resource_class") in ("MEMORY_MB", "VCPU"):
                print(f"      placement {i.get('resource_class')}: total {i.get('total')}, reserved {i.get('reserved')}, "
                      f"allocation ratio {i.get('allocation_ratio')}")
print("@@hosts " + " ".join(sorted(hosts)))
PY
)
printf '%s\n' "$REP" | grep -v '^@@hosts '
HOSTS=$(printf '%s\n' "$REP" | sed -n 's/^@@hosts //p')
echo "== Guest console: stalls, lockups, clock, network lines (the last 1500 lines read; seconds since the guest booted)"
CL=$(openstack console log show --lines 1500 "$SID" 2>/dev/null)
echo "   $(printf '%s\n' "$CL" | grep -c .) line(s) in the console log"
printf '%s\n' "$CL" | grep -aiE 'lockup|stall|rcu|clocksource|watchdog|hung|blocked for|NETDEV|link is|virtio|kubelet|NotReady|time jump|Out of memory|oom' | tail -40 | cut -c1-220
INV=$(ls ~/overcloud-deploy/*/tripleo-ansible-inventory.yaml ~/config-download/*/tripleo-ansible-inventory.yaml \
  ~/tripleo-ansible-inventory.yaml 2>/dev/null | head -1)
DEFUSR=$(grep -q '17\.' /etc/rhosp-release && echo tripleo-admin || echo heat-admin)
for h in $HOSTS; do
  read -r N IP USR < <(python3 - "$h" "$INV" <<'PY'
import sys, yaml
want, path = sys.argv[1].lower(), sys.argv[2]
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
    "$USR@$IP" "sudo bash -s -- $SID $F $T ${INST:-none} ${NETIP:-none}" <<'NODE' | cut -c1-300
SID=$1 F=$2 T=$3 INST=$4 NETIP=$5
export LC_ALL=C S_TIME_FORMAT=ISO
A=$(date -d @$F '+%Y-%m-%d %H:%M:%S'); B=$(date -d @$T '+%Y-%m-%d %H:%M:%S')
AU=$(date -u -d @$F '+%Y-%m-%dT%H:%M:%S'); BU=$(date -u -d @$T '+%Y-%m-%dT%H:%M:%S')
CONF=/var/lib/config-data/puppet-generated/nova_libvirt/etc/nova/nova.conf
QUIET='ADDRCONF|promiscuous|scsi |sd [0-9]|alua|device-mapper|multipath'
KERN='Link is|link status|NETDEV WATCHDOG|bond|lockup|stall|Out of memory|oom-kill|invoked oom|blocked for more than|page allocation failure|hung_task|mlx5|i40e|ice |bnxt|kvm'
echo "(local time here: $(date +%Z); window $A .. $B)"
echo "-- network layout: bonds and their links, addresses, OVN encap and bridge mappings"
SLAVES=""
for b in /proc/net/bonding/*; do
  [ -e "$b" ] || continue
  echo "   $(basename $b): $(grep -E '^(Bonding Mode|MII Status)' $b | head -2 | tr '\n' ' ')$(grep -E '^Slave Interface|^Speed' $b | paste -sd' ' -)"
  SLAVES="$SLAVES $(basename $b) $(awk '/^Slave Interface/ {print $3}' $b | paste -sd' ' -)"
done
ip -br addr 2>/dev/null | grep -vE '^(tap|lo|ovs-system|genev_sys|br-int)' | head -20 | sed 's/^/   /'
echo "   ovn: $(ovs-vsctl get open_vswitch . external_ids:ovn-encap-ip 2>/dev/null) encap; $(ovs-vsctl get open_vswitch . external_ids:ovn-bridge-mappings 2>/dev/null)"
echo "   nova settings: $(grep -hE '^(live_migration_[a-z_]+|ram_allocation_ratio|initial_ram_allocation_ratio|cpu_allocation_ratio|reserved_host_memory_mb|max_concurrent_live_migrations)[[:space:]]*=' $CONF 2>/dev/null | sed 's/[[:space:]]//g' | sort -u | paste -sd';' -)"
echo "-- nova-compute lines of the instance in the window (migration start / progress / downtime / post-copy / end; every 6th progress line)"
zcat -f /var/log/containers/nova/nova-compute.log* 2>/dev/null | grep -F "$SID" | awk -v a="$A" -v b="$B" '($1 " " $2) >= a && ($1 " " $2) <= b' \
  | grep -E 'Migration running for|Increasing downtime|post.copy|Migration operation has|pre_live_migration|post_live_migration|Live Migration failure|Took|Starting monitoring|Instance spawned|Migrating instance' \
  | sort -s -k1,2 | awk '/Migration running for/ {n++; if (n % 6 != 1) next} {print}' | cut -c1-260 | tail -60
echo "-- nova-compute migration errors in the window (any instance; no tracebacks)"
zcat -f /var/log/containers/nova/nova-compute.log* 2>/dev/null | awk -v a="$A" -v b="$B" '($1 " " $2) >= a && ($1 " " $2) <= b' \
  | grep -E 'Live Migration failure|Migration operation has aborted|Error from libvirt|ERROR nova\.(virt|compute)' \
  | grep -vE 'Traceback|File "|connection_info|password|auth_' | sort -s -k1,2 | cut -c1-400 | tail -25
echo "-- kernel in the window: links, bonds, NIC, lockups, OOM, memory, hung tasks (tap and SCSI noise left out)"
journalctl _TRANSPORT=kernel --since "$A" --until "$B" --no-pager -q 2>/dev/null | grep -E "$KERN" | grep -vE "$QUIET" | tail -40
echo "-- qemu log of the instance in the window (UTC)"
for q in /var/log/containers/libvirt/qemu/$INST.log /var/log/libvirt/qemu/$INST.log; do
  # libvirt writes "2026-10-30 19:28:30.123+0000: ...", QEMU itself "2026-10-30T19:28:30.123456Z ..."
  [ -f "$q" ] && awk -v a="$AU" -v b="$BU" '{k = ($1 ~ /T/) ? substr($1, 1, 19) : ($1 "T" substr($2, 1, 8))} k >= a && k <= b' "$q" \
    | cut -c1-240 | tail -20
done
echo "-- ovn-controller in the window (UTC): slow loops, reconnects, errors"
for g in $(ls /var/log/containers/openvswitch/ovn-controller.log* 2>/dev/null); do zcat -f "$g"; done \
  | awk -v a="$AU" -v b="$BU" 'substr($1, 1, 19) >= a && substr($1, 1, 19) <= b' \
  | grep -E 'Unreasonably long|connection|reconnect|ERR|dropped|TIMEOUT|commit failed' | sort | tail -40
echo "-- sysstat history in the window (10-minute averages: a spike of seconds does not show)"
D=$(date -d @$F +%d); S=$(date -d @$F +%H:%M:%S); E=$(date -d @$T +%H:%M:%S)
IFRE="^($(echo $SLAVES | tr ' ' '|'))\$"
if command -v sar >/dev/null 2>&1 && [ -f /var/log/sa/sa$D ]; then
  SA="-s $S -e $E -f /var/log/sa/sa$D"
  echo "   CPU:"; sar -u $SA 2>/dev/null | tail -n +3 | head -40
  echo "   load:"; sar -q $SA 2>/dev/null | tail -n +3 | head -40
  echo "   memory:"; sar -r $SA 2>/dev/null | tail -n +3 | head -40
  echo "   paging (pgscand/s > 0 = direct reclaim: processes, QEMU too, wait for free memory):"; sar -B $SA 2>/dev/null | tail -n +3 | head -40
  echo "   swap:"; sar -W $SA 2>/dev/null | tail -n +3 | head -40
  echo "   traffic per bond and link (MiB/s; util = % of the link speed):"
  sar -n DEV $SA 2>/dev/null | awk -v re="$IFRE" '$2 ~ re && $1 ~ /^[0-9]/ {printf "   %s %-14s rx %8.1f tx %8.1f util %s%%\n", $1, $2, $5/1024, $6/1024, $10}' | head -200
  echo "   errors / drops per bond and link (only intervals with any):"
  sar -n EDEV $SA 2>/dev/null | awk -v re="$IFRE" '$2 ~ re && $1 ~ /^[0-9]/ {s = 0; for (i = 3; i <= NF; i++) s += $i; if (s > 0) print "   " $0}' | head -40
else
  echo "   no sysstat history (sar or /var/log/sa/sa$D missing)"
fi
echo "-- now ($(date '+%Y-%m-%d %H:%M:%S %Z'))"
echo "   $(uptime)"
echo "   $(awk '/^(MemTotal|MemAvailable|Committed_AS|CommitLimit|AnonHugePages|HugePages_Total|HugePages_Free):/ {printf "%s %d GiB; ", $1, $2 / 1048576}' /proc/meminfo)"
echo "   vmstat 1 5 (si/so = swap, wa = waiting for disk, st = stolen):"; vmstat -w 1 5 | sed 's/^/   /'
TD=$(date +%d)
if command -v sar >/dev/null 2>&1 && [ -f /var/log/sa/sa$TD ]; then
  SN="-f /var/log/sa/sa$TD"; [ "$TD" = "$D" ] && SN="-s $E $SN"
  echo "   since the window, load:"; sar -q $SN 2>/dev/null | tail -n +3 | head -40
  echo "   since the window, memory:"; sar -r $SN 2>/dev/null | tail -n +3 | head -40
  echo "   since the window, direct reclaim:"; sar -B $SN 2>/dev/null | tail -n +3 | awk '{print "   " $1, "pgscand/s", $8, "%vmeff", $10}' | head -40
fi
echo "   kernel since the window:"; journalctl _TRANSPORT=kernel --since "$B" --no-pager -q 2>/dev/null | grep -E "$KERN" | grep -vE "$QUIET" | tail -20
echo "   ovn-controller since the window: $(for g in $(ls /var/log/containers/openvswitch/ovn-controller.log* 2>/dev/null); do zcat -f "$g"; done \
  | awk -v b="$BU" 'substr($1, 1, 19) > b' | grep -c 'Unreasonably long') slow loop(s); the last ones:"
for g in $(ls /var/log/containers/openvswitch/ovn-controller.log* 2>/dev/null); do zcat -f "$g"; done \
  | awk -v b="$BU" 'substr($1, 1, 19) > b' | grep -E 'Unreasonably long|reconnect|ERR' | sort | tail -4 | sed 's/^/   /'
echo "   bond links (link failures since boot):"
for b in /proc/net/bonding/*; do [ -e "$b" ] && awk -v n=$(basename $b) '/^Slave Interface/ {s=$3} /^MII Status/ && s {m=$3} /^Link Failure Count/ && s {print "     " n " " s ": " m ", failures " $4; s=""}' $b; done
echo "   drops over 10 s now (increase of rx_dropped / rx_missed_errors / tx_dropped):"
declare -A r1
for i in $SLAVES; do r1[$i]=$(cat /sys/class/net/$i/statistics/{rx_dropped,rx_missed_errors,tx_dropped} 2>/dev/null | paste -sd' ' -); done
sleep 10
for i in $SLAVES; do
  read -r a1 b1 c1 <<< "${r1[$i]:-0 0 0}"
  read -r a2 b2 c2 < <(cat /sys/class/net/$i/statistics/{rx_dropped,rx_missed_errors,tx_dropped} 2>/dev/null | paste -sd' ' -)
  echo "     $i: +$(( ${a2:-0} - ${a1:-0} )) / +$(( ${b2:-0} - ${b1:-0} )) / +$(( ${c2:-0} - ${c1:-0} ))"
done
echo "-- the domain of the instance here now"
c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$')
if [ -n "$c" ] && [ "$INST" != none ]; then
  V="timeout 30 podman exec $c virsh -c qemu:///system"
  echo "   $($V domstate --reason $INST 2>&1 | head -1)"
  if $V domstate $INST >/dev/null 2>&1; then
    echo "   memory (KiB; rss = what the host gives it now):"; $V dommemstat $INST 2>&1 | paste -sd' ' - | sed 's/^/     /'
    echo "   job now: $($V domjobinfo $INST 2>&1 | head -1)"
    echo "   the last migration job here:"; $V domjobinfo --completed $INST 2>&1 | grep -E 'Job type|Operation|Time elapsed|Downtime|Memory processed|Memory bandwidth|Dirty rate|Iteration|Postcopy|Auto converge' | sed 's/^/     /'
  fi
fi
if [ "$NETIP" != none ]; then
  echo "   ping of the instance from the OVN metadata namespace here (20 x 0.2 s; no answer can be its security group):"
  for x in ${NETIP//,/ }; do
    n=${x%%=*}; ip=${x#*=}
    if ip netns list 2>/dev/null | grep -q "^ovnmeta-$n"; then
      echo "     $ip: $(ip netns exec ovnmeta-$n ping -c 20 -i 0.2 -W 1 -q $ip 2>&1 | tail -2 | paste -sd' ' -)"
    else
      echo "     $ip: no metadata namespace of its network here"
    fi
  done
fi
NODE
done
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, server $SID, window $FROM .. $TO WIB; director $DIR_USER@$DIR_HOST (keys are not printed)"
  printf 'SID=%q\nF=%q\nT=%q\nRC=%s\n%s\n' "$SID" "$F" "$T" "$RC" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1 | grep -v '^\*\* '
  echo "== exit ${PIPESTATUS[1]}"
} | tee "$OUT"

# the portal's fix items that moved the instances of the migrations touching its computes
if [ -r "$DB" ]; then
  "$PY" - "$DB" "$OUT" "$FROM" <<'PY' | tee -a "$OUT"
import datetime, json, re, sqlite3, sys
db, out, frm = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(out).read()
touch = {}
for l in text.splitlines():
    m = re.match(r"^@@touch (\S+) (\S+) (.*)$", l.strip())
    if m:
        touch[m.group(1)] = (m.group(2), m.group(3))
m = re.search(r"computes of the instance: (.*)", text)
hosts = m.group(1).split() if m else []
print("\n== Portal fix items that moved these instances (usage read before the move, attempts, result)")
if not touch:
    print("   no migration touched its computes"); raise SystemExit
con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
con.row_factory = sqlite3.Row
since = (datetime.datetime.strptime(frm, "%Y-%m-%d %H:%M") - datetime.timedelta(days=1)).strftime("%Y-%m-%d")
KEEP = re.compile(r"Usage of|Attempt \d|RESULT|^Time:|Why it takes long|not converging|stuck|abort|refus|wait|took ")
found = 0
for a in con.execute("SELECT * FROM wi_actions WHERE ts >= ? ORDER BY id", (since,)):
    try:
        steps = json.loads(a["output"] or "[]")
    except ValueError:
        continue
    for i, st in enumerate(steps, 1):
        label, out_text = str(st.get("command") or ""), str(st.get("out") or "")
        hit = [u for u in touch if u in label or u in out_text]
        if not hit:
            continue
        found += 1
        mid, name = touch[hit[0]]
        print(f"   Fix #{a['id']} item {i} ({name}, migration {mid}), fix started {a['ts']} by {a['username']}, exit {st.get('rc')}")
        lines = [l.strip() for l in out_text.splitlines() if l.strip() and not l.startswith("@@WI@@") and not l.lstrip().startswith("$ ")]
        keep = [l for l in lines if KEEP.search(l) or (": CPU " in l and any(h in l for h in hosts))]
        for l in keep[:18]:
            print(f"     | {l[:260]}")
print(f"   {found} item(s) of the portal's fixes moved these instances; the other migrations came from elsewhere "
      "(Horizon, the CLI, another tool)")
PY
fi
chown deploy: "$OUT"
echo "Saved: $OUT"

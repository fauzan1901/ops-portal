#!/usr/bin/env bash
# Read-only: is it safe to live-migrate the instances of a source compute to the destination compute(s), with respect
# to what made VMs get I/O errors?
# Per running instance of the source:
#   - Nova's connection of each volume (BDM target + LUN) names the device the domain really uses on the source (a stale
#     LUN number = a rollback, hard reboot or delete would disconnect another VM's disk);
#   - each volume has exactly one Cinder attachment (more = "duplicate connectors" halfway through a migration);
#   - every disk has active paths; libvirt answers a job on the domain (no stuck "state change lock");
#   - no port still carries a migrating_to binding profile;
#   - each disk the domain runs on is a multipath map, not a guest LV the host activated; the first 4 KiB of each disk
#     with a working path are read (O_DIRECT, read-only) for an LVM label on the WHOLE disk: such a volume can be
#     activated by the destination host's LVM during a live migration (a real case, storage-vm / mdt01).
# Per destination: multipath maps used by running VMs without any path, leftover instance directories of the source's
# instances (DestinationDiskExists, whose rollback disconnects LUNs), kernel disk errors of the last 24 h.
# Same path as the portal: portal service account -> management host -> director -> controller / computes.
# Run on the bastion:  sudo bash ~/migration-readiness.sh <SITE> <source compute> <destination compute>...
#                  or:  sudo bash ~/migration-readiness.sh <SITE> all   (every nova-compute that is up, enabled or disabled
#                       (a disabled one is usually the compute being drained), each as
#                       source and as destination, read in parallel)
set -u
SITE="${1:-}"
SRC="${2:-}"
shift 2 2>/dev/null
DESTS="$*"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$SRC" =~ ^[a-z0-9-]{1,63}$ ]] || { echo "Source compute: its short name, or all"; exit 1; }
if [ "$SRC" = "all" ]; then DESTS="all"; else
  [[ "$DESTS" =~ ^[a-z0-9-]+( [a-z0-9-]+)*$ ]] || { echo "Destination computes: short names"; exit 1; }
fi
OUT="/home/deploy/migration-readiness-$(date +%Y%m%d-%H%M%S).txt"
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

# on a compute, read-only: running domains and their disks (dm, WWID, active paths), the by-path map iqn+lun -> dm,
# multipath maps without a path, instance directories without a domain, kernel disk errors of 24 h; JOB=1: domjobinfo
ONNODE=$(cat <<'NODE'
c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$')
V="podman exec $c virsh -c qemu:///system"
MPD=$(podman ps --format '{{.Names}}' | grep -m1 -x multipathd)
MP() { if [ -n "$MPD" ]; then podman exec "$MPD" multipath "$@"; else multipath "$@"; fi; }
MPLL=$(MP -ll 2>/dev/null)
paths() { printf '%s\n' "$MPLL" | awk -v d="$1" '$2 == d {on=1; next} /^[0-9a-f]{33} dm-/ {on=0} on && / sd[a-z]+ / && /active ready/ {n++} END {print n+0}'; }
for ss in /sys/class/iscsi_session/session*; do
  [ -e "$ss/targetname" ] || continue
  h=$(ls -d $ss/device/target* 2>/dev/null | head -1 | sed -E 's/.*target([0-9]+):.*/\1/')
  echo "SESS ${h:-?} $(cat $ss/targetname)"
done
for b in /sys/block/sd*; do
  [ -e "$b/device" ] || continue
  echo "SD $(basename $b) $(basename "$(readlink -f $b/device)") $(ls $b/holders 2>/dev/null | head -1 | grep . || echo none) $(cat $b/device/state 2>/dev/null)"
done
for x in $($V list --name); do
  u=$($V domuuid $x 2>/dev/null)
  if [ "$JOB" = 1 ]; then j=$(timeout 12 $V domjobinfo $x 2>&1 | head -1); echo "JOB $u ${j:-timeout}"; fi
  $V domblklist $x 2>/dev/null | awk '$2 ~ /^\/dev\// {print $1, $2}' | while read -r t s; do
    dm=$(basename "$(readlink -f "$s")"); w=$(cat /sys/block/$dm/dm/name 2>/dev/null)
    if [[ "$dm" == dm-* ]]; then a=$(paths $dm); else a=$([ "$(cat /sys/block/$dm/device/state 2>/dev/null)" = running ] && echo 1 || echo 0); fi
    k=sd; if [[ "$dm" == dm-* ]]; then k=$(cut -d- -f1 /sys/block/$dm/dm/uuid 2>/dev/null); k=${k:-dm}; fi
    pv=-   # read only from a disk with a working path (a read on a map without path could hang)
    if [ "$a" -gt 0 ] && [ "$k" != LVM ]; then
      pv=$(timeout 10 dd if=/dev/$dm bs=4096 count=1 iflag=direct 2>/dev/null | grep -abo LABELONE | head -1 | cut -d: -f1)
      pv=${pv:+pv@$pv}; pv=${pv:-no}
    fi
    echo "DISK $u $x $t $dm ${w:-none} $a $k $pv"
  done
done
printf '%s\n' "$MPLL" | awk '/^[0-9a-f]{33} dm-/ {if (m != "" && n == 0) print "NOPATH", m; m=$2" "$1; n=0; next} / sd[a-z]+ / {n++} END {if (m != "" && n == 0) print "NOPATH", m}'
for d in /var/lib/nova/instances/*; do
  u=$(basename "$d"); [[ "$u" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || continue
  $V dominfo "$u" >/dev/null 2>&1 || echo "ORPHAN $u"
done
echo "KERNEL $(journalctl -k --since '-24 hours' --no-pager 2>/dev/null | grep -cE 'alua: Detached|I/O error, dev dm-') line(s) with removed SCSI devices / dm I/O errors in 24 h"
journalctl -k --since '-24 hours' --no-pager 2>/dev/null | grep -E 'alua: Detached|I/O error, dev dm-' | tail -5 | sed 's/^/KLINE /'
journalctl -k --since '-24 hours' --no-pager -o short-iso 2>/dev/null | grep -E 'I/O error, dev (dm-[0-9]+|sd[a-z]+)' |
  awk '{match($0, /dev (dm-[0-9]+|sd[a-z]+)/); d = substr($0, RSTART + 4, RLENGTH - 4); n[d]++; if (!(d in f)) f[d] = $1; l[d] = $1}
       END {for (d in n) print "IOERR", d, n[d], f[d], l[d]}'
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
sql() { printf 'podman exec $(podman ps -q -f name=galera-bundle | head -1) mysql -N -B -e %q\n' "$1" | asroot "$CTL"; }
W=$(mktemp -d /tmp/mr-XXXXXX); trap 'rm -rf "$W"' EXIT
if [ "$SRC" = "all" ]; then
  SVCS=$(openstack compute service list --service nova-compute -f value -c Host -c Status -c State 2>/dev/null | sed 's/^\([^. ]*\)[^ ]*/\1/')
  ALL=$(printf '%s\n' "$SVCS" | awk '$3 == "up" {print $1}' | sort -u)
  echo "== Every nova-compute that is up: $(echo $ALL | wc -w) compute(s), read in parallel (6 at a time); disabled among them: $(printf '%s\n' "$SVCS" | awk '$3 == "up" && $2 == "disabled" {print $1}' | sort -u | paste -sd' ' - | grep . || echo none)"
  DOWN=$(printf '%s\n' "$SVCS" | awk '$3 != "up" {print $1 " (" $2 ")"}' | sort -u | paste -sd' ' -)
  [ -n "$DOWN" ] && echo "== nova-compute DOWN, not read: $DOWN"
  export ONNODE INV DEFUSR W
  export -f nodes asroot
  printf '%s\n' $ALL | xargs -P 6 -I{} bash -c 'printf "JOB=1\n%s\n" "$ONNODE" | asroot {} > "$W/node-{}" 2>&1'
  sql "SELECT i.uuid, i.display_name, SUBSTRING_INDEX(i.host, '.', 1) FROM nova.instances i WHERE i.deleted = 0" > "$W/inst"
  sql "SELECT b.instance_uuid, b.device_name, b.volume_id, b.attachment_id, JSON_VALUE(b.connection_info,'\$.data.target_iqn'), JSON_VALUE(b.connection_info,'\$.data.target_lun') FROM nova.block_device_mapping b JOIN nova.instances i ON i.uuid = b.instance_uuid WHERE i.deleted = 0 AND b.deleted = 0 AND b.destination_type = 'volume'" > "$W/bdm"
  sql "SELECT a.volume_id, COUNT(*), GROUP_CONCAT(a.attach_status), GROUP_CONCAT(a.id) FROM cinder.volume_attachment a WHERE a.deleted = 0 GROUP BY a.volume_id HAVING COUNT(*) > 1" > "$W/att"
  sql "SELECT p.device_id, b.port_id, b.host, b.profile FROM ovs_neutron.ml2_port_bindings b JOIN ovs_neutron.ports p ON p.id = b.port_id WHERE b.profile LIKE '%migrating_to%'" > "$W/mig" 2>/dev/null
  python3 - "$W" $ALL <<'PY'
import sys, os, collections
def device_map(t):
    sess = {}
    for l in t:
        if l.startswith("SESS "):
            p = l.split(" ", 2)
            if len(p) == 3:
                sess[p[1]] = p[2]
    out = {}
    for l in t:
        if l.startswith("SD "):
            p = l.split(" ")
            if len(p) < 4:
                continue
            sd, addr, holder = p[1], p[2], p[3]
            a = addr.split(":")
            if len(a) != 4 or a[0] not in sess:
                continue
            lun = int(a[3])
            dev = holder if holder != "none" else sd
            for n in {lun, lun - 0x4000 if lun >= 0x4000 else lun}:
                out.setdefault((sess[a[0]], str(n)), set()).add(dev)   # one device per path when there is no map
    return out
w, computes = sys.argv[1], sys.argv[2:]
def lines(p):
    f = os.path.join(w, p)
    return [l.rstrip("\n") for l in open(f, errors="replace")] if os.path.exists(f) else []
inst = {}
for l in lines("inst"):
    p = l.split("\t")
    if len(p) >= 3:
        inst[p[0]] = (p[1], p[2])
vols = collections.defaultdict(list)
for l in lines("bdm"):
    p = l.split("\t")
    if len(p) >= 6:
        vols[p[0]].append(p[1:])
att = {}
for l in lines("att"):
    p = l.split("\t")
    if len(p) >= 4:
        att[p[0]] = (int(p[1]), p[2])
mig = collections.defaultdict(list)
for l in lines("mig"):
    p = l.split("\t")
    if len(p) >= 2:
        mig[p[0]].append(p[1])
total_risk, total_ok, total_nop, total_left, total_wlvm, total_disks, total_unread = 0, 0, 0, 0, 0, 0, 0
total_single, total_ioerr, total_ioerr_vm = 0, 0, 0
for c in computes:
    t = lines(f"node-{c}")
    if not any(x.startswith(("DISK ", "KERNEL ")) for x in t):
        print(f"######## {c}: NOT READ ({(t[0] if t else 'no answer')[:150]})")
        continue
    bypath, disks, users, jobs = device_map(t), {}, collections.defaultdict(list), {}
    for l in t:
        if l.startswith("DISK "):
            p = l.split(" ")
            u, dom, tgt, dm, wwid, act = p[1:7]
            disks[(u, "/dev/" + tgt)] = (dm, int(act), p[7] if len(p) > 7 else "?", p[8] if len(p) > 8 else "-")
            users[dm].append(u)
        elif l.startswith("JOB "):
            p = l.split(" ", 2)
            jobs[p[1]] = p[2] if len(p) > 2 else ""
    here = [u for u, (n, h) in inst.items() if h == c and vols.get(u)]
    risk, wlvm = [], []
    for u in here:
        why, wd = [], []
        for dev, vol, attid, iqn, lun in vols[u]:
            d = disks.get((u, dev))
            if not d:
                continue   # not running here now (shut off / being moved): nothing to compare
            dm, act, kind, pv = d
            bdm_dm = bypath.get((iqn, lun))
            if pv.startswith("pv@"):
                wd.append(dev)
            if kind == "LVM":
                why.append(f"{dev} {dm}: the domain runs on a guest LV the HOST activated, not on the multipath map "
                           "(the guest sees the inner LV as its disk; its LVM is not found after a reboot)")
                continue
            if act == 0:
                why.append(f"{dev} {dm}: NO PATH (the guest gets I/O errors)")
            if bdm_dm is None:
                why.append(f"{dev}: Nova's LUN {lun} has no device here (stale connection info)")
            elif dm not in bdm_dm:
                other = sorted({x for b in bdm_dm for x in users.get(b, []) if x != u})
                why.append(f"{dev}: Nova's LUN {lun} is {'/'.join(sorted(bdm_dm))} here, not the domain's {dm}"
                           + (f" = disk of {','.join(other)}" if other else "") + " (STALE)")
            if vol in att:
                why.append(f"{dev} volume {vol}: {att[vol][0]} Cinder attachments ({att[vol][1]})")
        j = jobs.get(u, "")
        if "state change lock" in j or j == "timeout":
            why.append(f"libvirt job: {j[:100]}")
        if mig.get(u):
            why.append(f"port(s) {','.join(mig[u])} still carry migrating_to")
        if why:
            risk.append((u, why))
        if wd:
            wlvm.append((u, wd))
    nop = [l for l in t if l.startswith("NOPATH ")]
    orph = [l.split()[1] for l in t if l.startswith("ORPHAN ")]
    left = [x for x in orph if x in inst and inst[x][1] != c]
    unread = sum(1 for v in disks.values() if v[3] == "-" and v[2] != "LVM")
    total_risk += len(risk); total_ok += len(here) - len(risk); total_nop += len(nop); total_left += len(left)
    total_wlvm += len(wlvm); total_disks += len(disks); total_unread += unread
    print(f"######## {c}: instances with volumes {len(here)}, at RISK {len(risk)}; maps without any path {len(nop)}; "
          f"leftover directories of instances elsewhere {len(left)} (of deleted ones {len([x for x in orph if x not in inst])}); "
          f"running disks {len(disks)} (label not read: {unread}); instances with LVM on a whole disk {len(wlvm)}")
    for u, why in risk:
        print(f"  RISK {u} {inst[u][0]}")
        for x in why:
            print(f"       - {x}")
    single = [(u, dev, v[0]) for (u, dev), v in disks.items() if v[1] == 1 and v[2] != "LVM"]
    for u, dev, dm in sorted(single):
        print(f"  ONE PATH {u} {inst.get(u, ('?', ''))[0]}: {dev} {dm} has 1 working path"
              + (" (a single SCSI device, no multipath map)" if dm.startswith("sd") else "") + ": one more path failure = I/O errors")
    total_single += len(single)
    byd = collections.defaultdict(list)
    for (u, dev), v in disks.items():
        byd[v[0]].append((u, dev, v[1]))
    for l in t:
        if l.startswith("IOERR "):
            _, dm, cnt, first, last = (l.split(" ") + ["", "", "", ""])[:5]
            now = byd.get(dm, [])
            who = ", ".join(f"{dev} of {u} {inst.get(u, ('?', ''))[0]} (working paths now {a})" for u, dev, a in now) or "no running domain disk now"
            total_ioerr += 1; total_ioerr_vm += len({u for u, _, _ in now})
            print(f"  I/O ERRORS 24h {dm}: {cnt} error line(s), first {first}, last {last}; {who}")
    for u, wd in wlvm:
        print(f"  WHOLE-DISK LVM {u} {inst.get(u, ('?', ''))[0]}: {','.join(wd)} (a live migration to a host that has not seen "
              "the WWID yet can make that host activate the guest LVs, and the domain there would run on the inner LV)")
    for l in nop:
        dm = l.split()[1]
        who = ",".join(x + " " + inst.get(x, ("?", ""))[0] for x in users.get(dm, [])) or "nothing"
        print(f"  NO PATH {l[7:]} used by {who}")
    for x in left:
        print(f"  LEFTOVER {x} ({inst[x][0]}, now on {inst[x][1]}): a live migration of it to {c} is refused -> move it aside first")
    k = next((l[7:] for l in t if l.startswith("KERNEL ")), "")
    if k and not k.startswith("0 "):
        print(f"  kernel: {k}")
        for l in [l for l in t if l.startswith("KLINE ")]:
            print("    " + l[6:][:180])
print(f"== SITE TOTAL: instances OK {total_ok}, at RISK {total_risk}; maps without any path {total_nop}; "
      f"leftover directories of instances elsewhere {total_left}; running disks {total_disks} (label not read: "
      f"{total_unread}); instances with LVM on a whole disk {total_wlvm}; disks with one working path {total_single}; "
      f"devices with I/O errors in 24 h {total_ioerr} (disks of {total_ioerr_vm} running instance(s))")
PY
  exit 0
fi
echo "== Source $SRC: domains, disks, paths, libvirt jobs"
printf 'JOB=1\n%s\n' "$ONNODE" | asroot "$SRC" > "$W/src"
HOSTQ=$(grep -m1 . "$W/src" >/dev/null; echo "$SRC")
sql "SELECT i.uuid, i.display_name, b.device_name, b.volume_id, b.attachment_id, JSON_VALUE(b.connection_info,'\$.data.target_iqn'), JSON_VALUE(b.connection_info,'\$.data.target_lun') FROM nova.instances i JOIN nova.block_device_mapping b ON b.instance_uuid = i.uuid AND b.deleted = 0 AND b.destination_type = 'volume' WHERE i.deleted = 0 AND i.host LIKE '$SRC.%'" > "$W/bdm"
sql "SELECT a.volume_id, COUNT(*), GROUP_CONCAT(a.attach_status), GROUP_CONCAT(a.id) FROM cinder.volume_attachment a WHERE a.deleted = 0 AND a.volume_id IN (SELECT b.volume_id FROM nova.block_device_mapping b JOIN nova.instances i ON i.uuid = b.instance_uuid WHERE i.deleted = 0 AND b.deleted = 0 AND i.host LIKE '$SRC.%') GROUP BY a.volume_id" > "$W/att"
sql "SELECT p.device_id, b.port_id, b.host, b.profile FROM ovs_neutron.ml2_port_bindings b JOIN ovs_neutron.ports p ON p.id = b.port_id WHERE b.profile LIKE '%migrating_to%'" > "$W/mig" 2>/dev/null
for D in $DESTS; do
  printf 'JOB=0\n%s\n' "$ONNODE" | asroot "$D" > "$W/dst-$D"
done
python3 - "$W" "$SRC" $DESTS <<'PY'
import sys, os, collections
def device_map(t):
    sess = {}
    for l in t:
        if l.startswith("SESS "):
            p = l.split(" ", 2)
            if len(p) == 3:
                sess[p[1]] = p[2]
    out = {}
    for l in t:
        if l.startswith("SD "):
            p = l.split(" ")
            if len(p) < 4:
                continue
            sd, addr, holder = p[1], p[2], p[3]
            a = addr.split(":")
            if len(a) != 4 or a[0] not in sess:
                continue
            lun = int(a[3])
            dev = holder if holder != "none" else sd
            for n in {lun, lun - 0x4000 if lun >= 0x4000 else lun}:
                out.setdefault((sess[a[0]], str(n)), set()).add(dev)   # one device per path when there is no map
    return out
w, src, dests = sys.argv[1], sys.argv[2], sys.argv[3:]
def lines(p):
    return [l.rstrip("\n") for l in open(os.path.join(w, p))] if os.path.exists(os.path.join(w, p)) else []
s = lines("src")
bypath = device_map(s)
disks, users, jobs = {}, collections.defaultdict(list), {}
for l in s:
    if l.startswith("DISK "):
        p = l.split(" ")
        u, dom, tgt, dm, wwid, act = p[1:7]
        disks[(u, "/dev/" + tgt)] = (dm, wwid, int(act), dom, p[7] if len(p) > 7 else "?", p[8] if len(p) > 8 else "-")
        users[dm].append(u)
    elif l.startswith("JOB "):
        _, u, rest = (l.split(" ", 2) + [""])[:3]
        jobs[u] = rest
att = {}
for l in lines("att"):
    p = l.split("\t")
    if len(p) >= 4:
        att[p[0]] = (int(p[1]), p[2], p[3])
mig = collections.defaultdict(list)
for l in lines("mig"):
    p = l.split("\t")
    if len(p) >= 4:
        mig[p[0]].append(p[1])
inst = collections.OrderedDict()
for l in lines("bdm"):
    p = l.split("\t")
    if len(p) >= 7:
        inst.setdefault(p[0], {"name": p[1], "vols": []})["vols"].append(p[2:])
risk, ok = [], 0
for u, it in inst.items():
    why = []
    for dev, vol, attid, iqn, lun in it["vols"]:
        d = disks.get((u, dev))
        if not d:
            why.append(f"{dev}: no disk of the domain here (instance not running on {src}?)")
            continue
        dm, wwid, act, dom, kind, pv = d
        bdm_dm = bypath.get((iqn, lun))
        if pv.startswith("pv@"):
            why.append(f"{dev}: LVM on the whole disk (a destination that has not seen the WWID can activate the guest LVs; "
                       "the domain there would run on the inner LV)")
        if kind == "LVM":
            why.append(f"{dev} {dm}: the domain runs on a guest LV the HOST activated, not on the multipath map")
            continue
        if act == 0:
            why.append(f"{dev} {dm}: NO PATH (the guest gets I/O errors)")
        if bdm_dm is None:
            why.append(f"{dev}: Nova's LUN {lun} has no device here (stale connection info)")
        elif dm not in bdm_dm:
            other = sorted({x for b in bdm_dm for x in users.get(b, []) if x != u})
            why.append(f"{dev}: Nova's LUN {lun} is {'/'.join(sorted(bdm_dm))} here, not the domain's {dm}" + (f" = disk of {','.join(other)}" if other else "") + " (STALE: a rollback / hard reboot would hit it)")
        n = att.get(vol)
        if n and n[0] > 1:
            why.append(f"{dev} volume {vol}: {n[0]} Cinder attachments ({n[1]})")
    j = jobs.get(u, "")
    if "state change lock" in j or j == "timeout":
        why.append(f"libvirt job: {j[:100]}")
    if mig.get(u):
        why.append(f"port(s) {','.join(mig[u])} still carry migrating_to")
    if why:
        risk.append((u, it["name"], why))
    else:
        ok += 1
print(f"Instances with volumes on {src}: {len(inst)}; OK {ok}; at RISK {len(risk)}")
for u, name, why in risk:
    print(f"RISK {u} {name}")
    for x in why:
        print(f"     - {x}")
nop = [l for l in s if l.startswith("NOPATH ")]
print(f"{src}: maps without any path: {len(nop)}" + "".join(f"\n     {l[7:]} used by {','.join(users.get(l.split()[1], [])) or 'nothing'}" for l in nop))
print(next((l[7:] for l in s if l.startswith("KERNEL ")), ""))
for d in dests:
    t = lines(f"dst-{d}")
    nop = [l for l in t if l.startswith("NOPATH ")]
    dusers = collections.defaultdict(list)
    for l in t:
        if l.startswith("DISK "):
            dusers[l.split(" ")[4]].append(l.split(" ")[1])
    orph = [l.split()[1] for l in t if l.startswith("ORPHAN ")]
    mine = [x for x in orph if x in inst]
    print(f"== Destination {d}: running disks {sum(1 for l in t if l.startswith('DISK '))}; maps without any path: {len(nop)}; "
          f"leftover directories: {len(orph)} (of {src}'s instances: {len(mine)})")
    for l in nop:
        print(f"     NO PATH {l[7:]} used by {','.join(dusers.get(l.split()[1], [])) or 'nothing'}")
    for x in mine:
        print(f"     LEFTOVER {x} ({inst[x]['name']}): its migration here would be refused (DestinationDiskExists) -> move it aside first")
    print("     " + next((l[7:] for l in t if l.startswith("KERNEL ")), ""))
    for l in [l for l in t if l.startswith("KLINE ")]:
        print("       " + l[6:][:200])
PY
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, source $SRC, destinations $DESTS; management host $MGMT_HOST, director $DIR_USER@$DIR_HOST (keys are not printed)"
  printf 'SRC=%q\nDESTS=%q\nONNODE=%q\nRC=%s\n%s\n' "$SRC" "$DESTS" "$ONNODE" "$RC" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1 | grep -v 'post-quantum\|store now, decrypt\|openssh.com/pq'
  echo "== exit $?"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

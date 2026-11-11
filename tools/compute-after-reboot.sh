#!/usr/bin/env bash
# Read-only: a compute after an unexpected reboot. Nothing is changed anywhere.
#   compute   boot time and how the previous boot ended (last lines, panic / hardware / watchdog), failed units, containers
#             not up, NICs and bonds, OVS bridges and ovn-bridge-mappings, ovn-controller connection and its errors, iSCSI
#             sessions, multipath maps without a working path, kernel I/O errors since boot, state and disk errors of
#             every domain;
#   OVN       the VM ports Neutron put on this compute (NB, requested-chassis) against what is bound and up on its chassis
#             (SB), per network with its type, physical network and VLAN: which networks (e.g. MPLS VLANs) are cut, and
#             whether their physical network is mapped to a bridge with a NIC that is up on this compute;
#   OpenStack the network agents of this compute, its instances that are not ACTIVE / running;
#   guests    the console log of each instance: read-only remounts, EXT4 / XFS errors, I/O errors;
#   services  containers not up or unhealthy, errors of nova-compute and of the OVN metadata agent since the boot;
#   instance  (optional third argument) one instance end to end: Nova (status, fault), its Neutron ports and networks,
#             their OVN NB / SB state (up, chassis), the tap on the compute (ofport, OVS error), the domain and its
#             disks, the error lines of its console log.
# Same path as the portal: portal service account -> management host -> director -> compute / controller.
# Run on the bastion:  sudo bash ~/compute-after-reboot.sh <SITE> <compute short name> [instance ID]
set -u
SITE="${1:-}"
NODE="${2:-}"
SID="${3:--}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$NODE" =~ ^[a-z0-9-]{1,63}$ ]] || { echo "Compute: short name, e.g. dccrhosp-compute-1"; exit 1; }
[[ "$SID" =~ ^(-|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$ ]] || { echo "Instance ID: a UUID"; exit 1; }
OUT="/home/deploy/compute-after-reboot-$SITE-$NODE-$(date +%Y%m%d-%H%M%S).txt"
SVC=opsportal
PY=/opt/ops-portal/.venv/bin/python
OPS=/opt/ops-portal/modules/wi/wi_analysis/wi_ops.py
[ -r "$OPS" ] || { echo "$OPS not readable (run with sudo)"; exit 1; }

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
HOP="ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST"

HARNESS=$(cat <<'PY'
import concurrent.futures, functools, json, os, re, shlex, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wi_ops

print = functools.partial(print, flush=True)
node, sid = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] != "-" else "")
MASK = "sed -E \"s/(auth_password|password|secret|target_secret|chap_secret)(['\\\"]?[[:space:]]*[:=][[:space:]]*['\\\"]?)[^'\\\",} ]+/\\1\\2***/g\""
d = wi_ops.Director(write=lambda line: None)


def sh(argv, timeout=180):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, f"(no answer after {timeout} s)"


def os_json(args, timeout=180):
    rc, out = sh(["openstack"] + args + ["-f", "json"], timeout)
    try:
        return json.loads(out) if rc == 0 else None
    except ValueError:
        return None


def on(host, script, timeout=300):
    ip, user = d.node(host)
    if not ip:
        return f"(no address for {host} in the inventory)"
    rc, out = d.run(wi_ops.SSH + [f"{user}@{ip}", "sudo -n sh -c " + shlex.quote(script)], show=False, timeout=timeout)
    return str(out or "").rstrip() + ("" if rc == 0 else f"\n(exit {rc})")


def rows(text):
    """Rows of `ovn-?bctl --format=json` as dicts (uuid / set / map unwrapped)."""
    m = re.search(r'\{"data".*\}', str(text or ""), re.S)
    try:
        v = json.loads(m.group(0)) if m else None
    except ValueError:
        v = None
    if not isinstance(v, dict):
        return None
    def un(x):
        if isinstance(x, list) and len(x) == 2 and x[0] in ("uuid", "set", "map"):
            if x[0] == "uuid":
                return x[1]
            if x[0] == "set":
                return [un(y) for y in x[1]]
            return {k: un(w) for k, w in x[1]}
        return x
    return [dict(zip(v["headings"], [un(c) for c in r])) for r in v.get("data", [])]


svc = os_json(["compute", "service", "list", "--service", "nova-compute"]) or []
fqdn = next((s["Host"] for s in svc if wi_ops.short(s.get("Host")) == node), None)
if not fqdn:
    print(f"{node} is not a nova-compute of this site")
    raise SystemExit(1)
st = next(s for s in svc if s["Host"] == fqdn)
print(f"== {fqdn}: nova-compute {st.get('Status')}/{st.get('State')}, updated {st.get('Updated At')}")

# ---------------------------------------------------------------- the compute itself
COMPUTE = r"""
echo "@@ boot"; echo "up since $(uptime -s)"; journalctl --list-boots --no-pager 2>/dev/null | tail -n 3
echo "@@ previous boot: its last lines (an abrupt end = power loss / reset / crash)"
journalctl -b -1 -n 12 --no-pager -o short-iso 2>&1 | cut -c1-220
echo "@@ previous boot: panic / hardware / watchdog / lockups"
journalctl -b -1 -k --no-pager -o short-iso 2>/dev/null | grep -iE 'panic|oops|watchdog|hard lockup|soft lockup|mce|machine check|hardware error|nmi|hung_task|blocked for more than|out of memory' | tail -n 15 | cut -c1-220
echo "@@ crash dumps"; ls -la /var/crash 2>&1 | tail -n 5
for f in /var/crash/*/vmcore-dmesg.txt; do [ -e "$f" ] || continue; echo "== $f: panic / oops / hardware lines"
  grep -E 'Kernel panic|BUG:|Oops|RIP:|watchdog|[Hh]ard LOCKUP|soft lockup|MCE|[Mm]achine [Cc]heck|Hardware Error|GHES|NMI|hung_task|blocked for more than|Comm:' "$f" | tail -n 30 | cut -c1-220
  echo "== $f: its last 40 lines"; tail -n 40 "$f" | cut -c1-220; done
echo "@@ failed units"; systemctl --failed --no-legend --no-pager 2>&1 | head -n 20
echo "@@ containers not up or unhealthy"; podman ps -a --format '{{.Names}} {{.Status}}' | grep -vE ' Up [^(]*$| Up .*\(healthy\)' | head -n 30
echo "@@ nova-compute: errors since the boot (last 25)"
b=$(date -d "$(uptime -s)" '+%Y-%m-%d %H:%M'); grep -hE ' (ERROR|CRITICAL) ' /var/log/containers/nova/nova-compute.log 2>/dev/null | awk -v b="$b" 'substr($0, 1, 16) >= b' | tail -n 25 | cut -c1-300 | MASK_HERE
echo "@@ OVN metadata agent: errors since the boot (last 15)"
grep -hE ' (ERROR|CRITICAL) ' /var/log/containers/neutron/ovn-metadata-agent.log 2>/dev/null | awk -v b="$b" 'substr($0, 1, 16) >= b' | tail -n 15 | cut -c1-300 | MASK_HERE
echo "@@ links (no VM taps)"; ip -br link | grep -vE '^(tap|qvo|qvb|qbr|vnet|genev_sys|o-hm)' | head -n 60
echo "@@ bonds"
for b in /proc/net/bonding/*; do [ -e "$b" ] || continue; echo "== $b"; grep -E 'Bonding Mode|MII Status|Slave Interface|Currently Active|Aggregator ID' "$b"; done
ovs-appctl bond/show 2>/dev/null | grep -E '^---|bond_mode|lacp_status|member .*:|slave .*:' | head -n 40
echo "@@ OVS external_ids (ovn-bridge-mappings, encap)"; ovs-vsctl get open_vswitch . external_ids 2>&1
echo "@@ OVS bridges: their ports other than VM taps"
for br in $(ovs-vsctl list-br); do echo "== $br: $(ovs-vsctl list-ports $br | grep -vE '^(tap|vnet)' | tr '\n' ' ')($(ovs-vsctl list-ports $br | grep -cE '^(tap|vnet)') VM ports)"; done
echo "@@ OVS interfaces with an error"; ovs-vsctl --columns=name,error --format=csv --no-headings find interface 'error!=[]' 2>&1 | head -n 20
echo "@@ ovn-controller"; podman ps -a --filter name=ovn_controller --format '{{.Names}} {{.Status}}'
podman exec ovn_controller ovn-appctl -t ovn-controller connection-status 2>&1 | head -n 3
echo "@@ ovn-controller log: last errors / warnings"
tail -n 5000 /var/log/containers/openvswitch/ovn-controller.log 2>/dev/null | grep -E '\|(ERR|WARN|EMER)\|' | tail -n 25 | cut -c1-250
echo "@@ ovs-vswitchd log: last errors"
tail -n 5000 /var/log/openvswitch/ovs-vswitchd.log 2>/dev/null | grep -E '\|(ERR|EMER)\|' | tail -n 20 | cut -c1-250
echo "@@ storage"
i=$(podman ps --format '{{.Names}}' | grep -m1 -x iscsid); echo "iSCSI sessions: $(podman exec $i iscsiadm -m session 2>/dev/null | wc -l)"
dmsetup status --target multipath 2>/dev/null | awk '$4 == "multipath" {a = 0; t = 0; for (i = 2; i < NF; i++) if ($i ~ /^[0-9]+:[0-9]+$/) {t++; if ($(i+1) == "A") a++} m++; if (a == 0) z++; else if (a < t) h++} END {printf "multipath maps: %d, without a working path: %d, with a failed path: %d\n", m, z, h}'
echo "@@ kernel since boot: disk / path errors"
echo "I/O error lines since boot: $(journalctl -k -b --no-pager 2>/dev/null | grep -cE 'I/O error|Buffer I/O|blk_update_request')"
journalctl -k -b --no-pager -o short-iso 2>/dev/null | grep -E 'I/O error|conn error|session recovery|Failing path|remaining active paths: 0|reinstated|EXT4-fs error|XFS .*error' | tail -n 15 | cut -c1-220
echo "@@ domains: state and disk errors"
c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$')
timeout 240 podman exec "$c" sh -c 'for x in $(virsh -c qemu:///system list --all --name); do s=$(virsh -c qemu:///system domstate --reason $x 2>&1); e=$(virsh -c qemu:///system domblkerror $x 2>&1 | grep -v "No errors found" | tr "\n" " "); echo "$x | $(virsh -c qemu:///system domuuid $x) | $s | ${e:-no disk errors}"; done'
"""
print(on(node, COMPUTE.replace("MASK_HERE", MASK), timeout=420))

# ---------------------------------------------------------------- OpenStack: agents, instances
print("@@ network agents of this compute")
for a in os_json(["network", "agent", "list", "--host", fqdn]) or []:
    print(f"   {a.get('Agent Type')}: alive {a.get('Alive')}, state {a.get('State')}, binary {a.get('Binary')}")
servers = os_json(["server", "list", "--all-projects", "--host", fqdn, "--long", "--limit", "-1"]) or []
print(f"@@ instances on this compute: {len(servers)}")
bad = [s for s in servers if s.get("Status") != "ACTIVE" or str(s.get("Power State")).lower() not in ("running", "1")]
for s in bad:
    print(f"   NOT ACTIVE/running: {s.get('Name')} ({s.get('ID')}) status {s.get('Status')}, power {s.get('Power State')}, task {s.get('Task State')}")

# ---------------------------------------------------------------- OVN: ports Neutron put here vs bound and up on this chassis
print("@@ OVN: ports of this compute, per network")
ctrl, _u = d.controller()
nb = on(d._inventory and next((h for h in sorted(d._inventory) if "controller" in h), "") or "",
        "c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^ovn_cluster_north_db_server$|^ovn-dbs-bundle'); "
        f"podman exec \"$c\" ovn-nbctl --no-leader-only --format=json --columns=name,external_ids,up,type,options "
        f"find logical_switch_port options:requested-chassis={fqdn} 2>&1") if ctrl else "(no controller in the inventory)"
lsps = rows(nb)
SBC = "c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^ovn_cluster_south_db_server$|^ovn-dbs-bundle'); "
ctl_name = next((h for h in sorted(d._inventory or {}) if "controller" in h), "")
sb = on(ctl_name, SBC + f"podman exec \"$c\" ovn-sbctl --no-leader-only --format=json --columns=_uuid,name,hostname,other_config,external_ids "
                  f"find chassis hostname={fqdn} 2>&1; echo @@SPLIT; "
                  f"ch=$(podman exec \"$c\" ovn-sbctl --no-leader-only --bare --columns=_uuid find chassis hostname={fqdn}); "
                  f"[ -n \"$ch\" ] && podman exec \"$c\" ovn-sbctl --no-leader-only --format=json --columns=logical_port,up "
                  f"find port_binding chassis=$ch 2>&1") if ctl_name else "@@SPLIT"
sb_ch, _, sb_pb = sb.partition("@@SPLIT")
sb_ok = rows(sb_ch.strip()) is not None
chassis, bindings = rows(sb_ch.strip()) or [], rows(sb_pb.strip()) or []
if lsps is None:
    print(f"   the Northbound DB could not be read: {nb[:300]}")
else:
    maps = ""
    for c in chassis:
        print(f"   chassis {c.get('name')} ({c.get('hostname')})")
        maps = (c.get("other_config") or {}).get("ovn-bridge-mappings") or (c.get("external_ids") or {}).get("ovn-bridge-mappings") or ""
        print(f"   ovn-bridge-mappings: {maps or '(none)'}")
    if not sb_ok:
        print(f"   the Southbound DB could not be read on {ctl_name or 'a controller'}: {sb_ch.strip()[:300]} (the 'bound' column is not known)")
    elif not chassis:
        print(f"   NO CHASSIS of {fqdn} in the Southbound DB: ovn-controller of this compute is not registered")
    physnets = {m.split(':')[0] for m in maps.split(',') if ':' in m}
    bound = {b.get("logical_port"): b for b in bindings}
    nets = {}
    for p in lsps:
        if p.get("type") not in ("", None):
            continue
        net = str((p.get("external_ids") or {}).get("neutron:network_name") or "").replace("neutron-", "")
        nets.setdefault(net, []).append(p)
    def netinfo(nid):
        rc, out = sh(["openstack", "network", "show", nid, "-f", "json", "-c", "name", "-c", "provider:network_type",
                      "-c", "provider:physical_network", "-c", "provider:segmentation_id"], 120)
        try:
            return nid, json.loads(out) if rc == 0 else {}
        except ValueError:
            return nid, {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        info = dict(ex.map(netinfo, list(nets)))
    print(f"   {len(lsps)} port(s) requested on this compute, {len(bindings)} bound to its chassis")
    print("   %-30s %-7s %-14s %-6s %6s %6s %6s  %s" % ("network", "type", "physnet", "vlan", "ports", "bound", "up", "problem"))
    for nid, ports in sorted(nets.items(), key=lambda x: str(info.get(x[0], {}).get("name"))):
        i = info.get(nid) or {}
        typ, phys = str(i.get("provider:network_type") or "?"), str(i.get("provider:physical_network") or "-")
        nb_up = sum(1 for p in ports if p.get("up") is True)
        on_ch = sum(1 for p in ports if p.get("name") in bound)
        sb_up = sum(1 for p in ports if (bound.get(p.get("name")) or {}).get("up") in (True, [True]))
        why = []
        if sb_ok and on_ch < len(ports):
            why.append(f"{len(ports) - on_ch} not bound here")
        if nb_up < len(ports):
            why.append(f"{len(ports) - nb_up} down in NB")
        if typ in ("vlan", "flat") and phys != "-" and physnets and phys not in physnets:
            why.append(f"physnet {phys} NOT in ovn-bridge-mappings")
        print("   %-30s %-7s %-14s %-6s %6d %6d %6d  %s" % (str(i.get("name") or nid)[:30], typ, phys[:14],
              str(i.get("provider:segmentation_id") or "-"), len(ports), on_ch, nb_up, "; ".join(why) or "-"))

# ---------------------------------------------------------------- one instance end to end
if sid:
    print(f"@@ instance {sid}")
    s = os_json(["server", "show", sid]) or {}
    if not s:
        print("   not found")
    else:
        inst = s.get("OS-EXT-SRV-ATTR:instance_name") or ""
        host = s.get("OS-EXT-SRV-ATTR:host") or ""
        print(f"   {s.get('name')}: status {s.get('status')}, power {s.get('OS-EXT-STS:power_state')}, task {s.get('OS-EXT-STS:task_state')}, "
              f"vm_state {s.get('OS-EXT-STS:vm_state')}, host {host}, {inst}, updated {s.get('updated')}")
        if s.get("fault"):
            print(f"   fault: {str(s.get('fault'))[:400]}")
        print(f"   addresses: {s.get('addresses')}")
        for e in (os_json(["server", "event", "list", sid, "--long"]) or [])[:8]:
            print(f"   event {e.get('Start Time')}: {e.get('Action')} ({e.get('Request ID')}), user {e.get('User ID')}, message {e.get('Message') or '-'}")
        print(f"   volumes: {s.get('volumes_attached')}")
        ports = os_json(["port", "list", "--server", sid, "--long"]) or []
        nb_all, taps = [], []
        for p in ports:
            pid = p.get("ID")
            ps = os_json(["port", "show", pid]) or {}
            nid = ps.get("network_id") or ""
            n = os_json(["network", "show", nid, "-c", "name", "-c", "provider:network_type", "-c", "provider:physical_network",
                         "-c", "provider:segmentation_id", "-c", "status", "-c", "admin_state_up"]) or {}
            print(f"   port {pid} {ps.get('mac_address')} {ps.get('fixed_ips')}: status {ps.get('status')}, admin {ps.get('admin_state_up')}, "
                  f"binding host {ps.get('binding_host_id')}, vif {ps.get('binding_vif_type')}, port security {ps.get('port_security_enabled')}, "
                  f"security groups {ps.get('security_group_ids')}")
            print(f"      network {n.get('name')} ({nid}): {n.get('provider:network_type')}, physnet {n.get('provider:physical_network')}, "
                  f"VLAN {n.get('provider:segmentation_id')}, status {n.get('status')}, admin {n.get('admin_state_up')}")
            taps.append("tap" + pid[:11])
            nb_all.append(pid)
        ctl = next((h for h in sorted(d._inventory or {}) if "controller" in h), "")
        if nb_all and ctl:
            q = "; ".join(f"podman exec \"$c\" ovn-nbctl --no-leader-only --format=json --columns=name,up,enabled,addresses,port_security,options "
                          f"find logical_switch_port name={pid}" for pid in nb_all)
            out = on(ctl, "c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^ovn_cluster_north_db_server$|^ovn-dbs-bundle'); " + q)
            for chunk in re.findall(r'\{"data".*?"headings":\[[^\]]*\]\}', out, re.S):
                for r in rows(chunk) or []:
                    print(f"   OVN NB {r.get('name')}: up {r.get('up')}, enabled {r.get('enabled')}, requested-chassis "
                          f"{(r.get('options') or {}).get('requested-chassis')}, addresses {r.get('addresses')}, port_security {r.get('port_security')}")
        if nb_all:
            q = "; ".join(f"podman exec ovn_controller ovn-sbctl --no-leader-only --format=json --columns=logical_port,chassis,up,mac "
                          f"find port_binding logical_port={pid}" for pid in nb_all)
            q = q.replace("podman exec ovn_controller ovn-sbctl", "podman exec \"$c\" ovn-sbctl")
            out = on(ctl_name, SBC + q + "; podman exec \"$c\" ovn-sbctl --no-leader-only --format=json --columns=_uuid,hostname list chassis") if ctl_name else ""
            parts = re.findall(r'\{"data".*?"headings":\[[^\]]*\]\}', out, re.S)
            names = {r.get("_uuid"): r.get("hostname") for r in (rows(parts[-1]) or [])} if parts else {}
            for chunk in parts[:-1]:
                for r in rows(chunk) or []:
                    print(f"   OVN SB {r.get('logical_port')}: chassis {names.get(r.get('chassis'), r.get('chassis') or 'NONE')}, up {r.get('up')}")
        if host and wi_ops.INSTANCE_RE.match(inst):
            print(f"   on its compute {wi_ops.short(host)}:")
            script = ("c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$'); "
                      + "".join(f"echo \"tap {t}: $(ip -br link show {t} 2>&1 | head -1)\"; "
                                f"ovs-vsctl --columns=name,ofport,error --format=csv --no-headings find interface name={t} 2>&1; " for t in taps)
                      + f"echo \"domain: $(podman exec \"$c\" virsh -c qemu:///system domstate --reason {inst} 2>&1)\"; "
                      + f"podman exec \"$c\" virsh -c qemu:///system domiflist {inst} 2>&1; "
                      + f"podman exec \"$c\" virsh -c qemu:///system domblklist {inst} 2>&1; "
                      + f"podman exec \"$c\" virsh -c qemu:///system domblkerror {inst} 2>&1")
            print("\n".join("      " + l for l in on(wi_ops.short(host), script).splitlines()))
        rc, out = sh(["openstack", "console", "log", "show", "--lines", "600", sid], 120)
        GUEST1 = re.compile(r"[Rr]emounting filesystem read-only|read-only file ?system|EXT4-fs (error|warning)|XFS \(\S+\): .*(error|[Cc]orrupt|shutdown)|"
                            r"I/O error|Buffer I/O|blk_update_request|journal (aborted|has aborted)|Aborting journal|link is not ready|NIC Link is Down|"
                            r"dhcp|DHCP|cloud-init.*(error|failed)|Failed to start", re.I)
        lines = [l.rstrip() for l in out.splitlines()] if rc == 0 else []
        hits = [l for l in lines if GUEST1.search(l)]
        print(f"   console log: {len(lines)} line(s) read, {len(hits)} about disks / filesystems / network / failed services; the last ones:")
        for l in hits[-15:]:
            print(f"      {l[:220]}")

# ---------------------------------------------------------------- guests: console logs
print("@@ guests: read-only remounts, filesystem and I/O errors in the console log (last 400 lines of each)")
GUEST = re.compile(r"[Rr]emounting filesystem read-only|read-only file ?system|EXT4-fs (error|warning)|XFS \(\S+\): .*(error|[Cc]orrupt|shutdown|Shutting down)|"
                   r"I/O error|Buffer I/O|blk_update_request|journal (aborted|has aborted)|Aborting journal")
def console(s):
    rc, out = sh(["openstack", "console", "log", "show", "--lines", "400", s["ID"]], 120)
    return s, rc, out
hit, empty = 0, 0
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
    for s, rc, out in ex.map(console, servers):
        lines = [l.strip() for l in out.splitlines() if GUEST.search(l)] if rc == 0 else []
        if rc == 0 and not out.strip():
            empty += 1
        if lines:
            hit += 1
            print(f"   !! {s.get('Name')} ({s.get('ID')}): {len(lines)} line(s), last: {lines[-1][:220]}")
print(f"   {hit} instance(s) with such lines, {empty} with an empty console log (Windows / no serial console: look at the console), "
      f"{len(servers) - hit - empty} without")
wi_ops.SSH_POOL.close()
PY
)

REMOTE=$(cat <<'EOF'
set -u
source $RC >/dev/null 2>&1 || { echo "source $RC failed"; exit 1; }
W=$(mktemp -d /tmp/wi-reboot.XXXXXXXX) || exit 1
trap 'rm -rf "$W"' EXIT
printf %s "$OPSB" | base64 -d | gunzip > "$W/wi_ops.py"
printf %s "$HB" | base64 -d > "$W/harness.py"
python3 -u "$W/harness.py" "$NODE" "$SID"
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, compute $NODE; director $DIR_USER@$DIR_HOST"
  OPSB=$(gzip -c "$OPS" | base64 -w0)
  HB=$(printf '%s\n' "$HARNESS" | base64 -w0)
  printf 'RC=%s\nNODE=%q\nSID=%q\nOPSB=%q\nHB=%q\n%s\n' "$RC" "$NODE" "$SID" "$OPSB" "$HB" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "$HOP bash -s" 2>&1 | grep -v '^\*\* '
  echo "== exit ${PIPESTATUS[1]}"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

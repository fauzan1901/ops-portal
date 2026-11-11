#!/usr/bin/env bash
# Read-only: the instances a compute crash restarted, and the NICs of each in the order of its domain. After an
# unexpected reboot Nova starts the instances of the compute again with a domain built anew from its ports; an instance
# whose interfaces were attached / detached while it ran (attach_interface / detach_interface) can then see its NICs in
# another order or with other names in the guest (ens5 <-> ens6): an IP or a route (e.g. to an MPLS network) sits on the
# wrong NIC, while Neutron, OVN and the switch are fine. Also the routes / IPs added by hand in the guest are gone.
# For each instance restarted by the crash (still on the compute, domain "running (booted)", or moved away since its
# boot): its NICs in domain order with tap, MAC, network, type / physical network / VLAN, IPs and OVN state, and its
# interface attach / detach history. Instances with a NIC on the physical network named (e.g. osp-provider) and such a
# history come first: check in their guest that each MAC carries the IPs and routes shown here. Nothing is changed.
# Same path as the portal: portal service account -> management host -> director -> controller / computes.
# Run on the bastion:  sudo bash ~/vm-nic-map.sh <SITE> <crashed compute short name> [physical network, default osp-provider]
set -u
SITE="${1:-}"
NODE="${2:-}"
PHYS="${3:-osp-provider}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$NODE" =~ ^[a-z0-9-]{1,63}$ ]] || { echo "Compute: short name, e.g. dccrhosp-compute-1"; exit 1; }
[[ "$PHYS" =~ ^[A-Za-z0-9_.-]{1,64}$ ]] || { echo "Physical network: e.g. osp-provider"; exit 1; }
OUT="/home/deploy/vm-nic-map-$SITE-$NODE-$(date +%Y%m%d-%H%M%S).txt"
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
import concurrent.futures, datetime, functools, json, os, re, shlex, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wi_ops

print = functools.partial(print, flush=True)
node, phys = sys.argv[1], sys.argv[2]
d = wi_ops.Director(write=lambda line: None)


def sh(argv, timeout=180):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, ""


def os_json(args, timeout=180):
    rc, out = sh(["openstack"] + args + ["-f", "json"], timeout)
    try:
        return json.loads(out) if rc == 0 else None
    except ValueError:
        return None


def on(host, script, timeout=300):
    ip, user = d.node(host)
    if not ip:
        return ""
    rc, out = d.run(wi_ops.SSH + [f"{user}@{ip}", "sudo -n sh -c " + shlex.quote(script)], show=False, timeout=timeout)
    return str(out or "")


def rows(text):
    m = re.search(r'\{"data".*\}', str(text or ""), re.S)
    try:
        v = json.loads(m.group(0)) if m else None
    except ValueError:
        return []
    if not isinstance(v, dict):
        return []
    def un(x):
        if isinstance(x, list) and len(x) == 2 and x[0] in ("uuid", "set", "map"):
            return x[1] if x[0] == "uuid" else [un(y) for y in x[1]] if x[0] == "set" else {k: un(w) for k, w in x[1]}
        return x
    return [dict(zip(v["headings"], [un(c) for c in r])) for r in v.get("data", [])]


svc = os_json(["compute", "service", "list", "--service", "nova-compute"]) or []
fqdn_of = {wi_ops.short(s["Host"]): s["Host"] for s in svc}
fqdn = fqdn_of.get(node)
if not fqdn:
    print(f"{node} is not a nova-compute of this site")
    raise SystemExit(1)
boot = on(node, "uptime -s").strip()
boot_utc = datetime.datetime.strptime(boot, "%Y-%m-%d %H:%M:%S").astimezone().astimezone(datetime.timezone.utc) if boot else None
print(f"{fqdn} up since {boot} (local); physical network of interest: {phys}")

# instances restarted by the crash: still on the compute, or moved away since its boot
vms = {}   # uuid -> current host
for s in os_json(["server", "list", "--all-projects", "--host", fqdn, "--limit", "-1"]) or []:
    vms[s["ID"]] = fqdn
moved = 0
if boot_utc:
    for m in os_json(["--os-compute-api-version", "2.59", "server", "migration", "list", "--host", fqdn,
                      "--changes-since", boot_utc.strftime("%Y-%m-%dT%H:%M:%SZ")]) or []:
        if wi_ops.short(m.get("Source Compute")) == node and str(m.get("Status")).lower() in ("completed", "confirmed", "finished"):
            u = next((v for k, v in m.items() if re.search(r"(server|instance).*(uuid|id)", k, re.I) and
                      re.match(r"^[0-9a-f-]{36}$", str(v or ""))), None)
            if u:
                vms[u] = m.get("Dest Compute") or m.get("dest_compute")
            elif moved == 0:
                print(f"   (a migration without an instance UUID I can read: Server UUID {m.get('Server UUID')!r}, type {m.get('Type')!r})")
            moved += 1
hosts = sorted({h for h in vms.values() if h})
print(f"{len(vms)} instance(s): {sum(1 for h in vms.values() if h == fqdn)} still on {node}, {moved} moved away since its boot "
      f"(to {', '.join(wi_ops.short(h) for h in hosts if h != fqdn) or 'nowhere'})")

# per host: the domains (state, order of their NICs) and the OVN NB ports requested there
DOMS = r"""c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$')
timeout 600 podman exec -i "$c" sh -s <<'EOS'
V="virsh -c qemu:///system"
for x in $($V list --name); do
  echo "@@dom $($V domuuid $x) $x $($V domstate --reason $x | tr -d ' ')"
  $V domiflist $x | awk 'NR > 2 && NF >= 5 {print $1, $5}' | while read t m; do
    echo "@@if $t $m $($V domifstat $x $t 2>/dev/null | awk '{printf "%s=%s ", $2, $3}')"
  done
done
EOS"""
ctl = next((h for h in sorted(d._inventory or {}) if "controller" in h), "")
NB = "c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^ovn_cluster_north_db_server$|^ovn-dbs-bundle'); "
dom, ports = {}, {}
for h in hosts:
    cur = None
    for line in on(wi_ops.short(h), DOMS, timeout=700).splitlines():
        p = line.split()
        if p and p[0] == "@@dom" and len(p) >= 4:
            cur = p[1]
            dom[cur] = {"name": p[2], "state": p[3], "ifs": [], "host": h}
        elif p and p[0] == "@@if" and len(p) >= 3 and cur:
            stats = dict(x.split("=", 1) for x in p[3:] if "=" in x)
            dom[cur]["ifs"].append((p[1], p[2].lower(), stats))
    if ctl:
        for r in rows(on(ctl, NB + f"podman exec \"$c\" ovn-nbctl --no-leader-only --format=json --columns=name,addresses,up,external_ids "
                                   f"find logical_switch_port options:requested-chassis={h}")):
            ports[r.get("name")] = r

nets = {}
for r in ports.values():
    n = str((r.get("external_ids") or {}).get("neutron:network_name") or "").replace("neutron-", "")
    if n:
        nets[n] = None
def netinfo(nid):
    i = os_json(["network", "show", nid, "-c", "name", "-c", "provider:network_type", "-c", "provider:physical_network",
                 "-c", "provider:segmentation_id"], 120) or {}
    return nid, i
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
    nets = dict(ex.map(netinfo, list(nets)))
def history(uuid):
    ev = os_json(["server", "event", "list", uuid], 120) or []
    s = os_json(["server", "show", uuid, "-c", "name", "-c", "status", "-c", "OS-EXT-SRV-ATTR:host"], 120) or {}
    return uuid, [e for e in ev if e.get("Action") in ("attach_interface", "detach_interface")], s
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
    hist = {u: (e, s) for u, e, s in ex.map(history, list(vms))}

by_mac = {}
for pid, r in ports.items():
    addrs = r.get("addresses") or []
    for a in [addrs] if isinstance(addrs, str) else addrs:   # one address: a string, several: a list
        a = a if isinstance(a, str) else ""
        f = a.split()
        if f and re.match(r"^[0-9a-f:]{17}$", f[0]):
            by_mac[f[0]] = (pid, f[1:], r)
report = []
for uuid, host in vms.items():
    events, s = hist.get(uuid, ([], {}))
    dm = dom.get(uuid) or {}
    nics = []
    for k, (tap, mac, st) in enumerate(dm.get("ifs") or [], 1):
        pid, ips, r = by_mac.get(mac, ("?", [], {}))
        nid = str((r.get("external_ids") or {}).get("neutron:network_name") or "").replace("neutron-", "")
        i = nets.get(nid) or {}
        nics.append({"n": k, "tap": tap, "mac": mac, "ips": " ".join(x for x in ips if x != "unknown") or "-",
                     "net": i.get("name") or nid or "?", "type": i.get("provider:network_type") or "?",
                     "phys": i.get("provider:physical_network") or "-", "vlan": i.get("provider:segmentation_id") or "-",
                     "up": r.get("up"), "tx": int(st.get("tx_packets") or 0), "rx": int(st.get("rx_packets") or 0)})
    on_phys = [x for x in nics if x["phys"] == phys]
    risk = bool(on_phys) and (bool(events) or len(nics) > 1)
    report.append((not risk, not on_phys, s.get("name") or dm.get("name") or uuid, uuid, host, dm, events, nics, on_phys))
report.sort(key=lambda x: (x[0], x[1], str(x[2]).lower()))
first = [r for r in report if not r[0]]
print(f"\n{len(first)} instance(s) with a NIC on {phys} and several NICs or an interface attach / detach in their history "
      "(check these in their guest first):")
for _risk, _nophys, name, uuid, host, dm, events, nics, on_phys in first:
    print(f"   {name} ({uuid}) on {wi_ops.short(host)}, {len(nics)} NIC(s), {len(events)} attach/detach")
print()
for risk_sort, _nophys, name, uuid, host, dm, events, nics, on_phys in report:
    mark = "!!" if not risk_sort else "  "
    print(f"{mark} {name} ({uuid}) on {wi_ops.short(host)}: domain {dm.get('state', 'not running there')}"
          + (f"; interface attach/detach: " + ", ".join(f"{e.get('Action')} {str(e.get('Start Time'))[:16]}" for e in events[:6]) if events else ""))
    for x in nics:
        print(f"      NIC {x['n']} {x['tap']} {x['mac']}  {x['net'][:34]} ({x['type']}"
              + (f", {x['phys']} VLAN {x['vlan']}" if x['phys'] != '-' else "") + f")  IP {x['ips']}  OVN up {x['up']}  guest sent {x['tx']} / received {x['rx']} packets"
              + ("  << the guest sends (almost) nothing on this NIC" if x['phys'] == phys and x['tx'] < 50 and
                 any(y['tx'] >= 500 for y in nics if y is not x) else ""))
silent = [(r[2], x) for r in report for x in r[7] if x["phys"] == phys and x["tx"] < 50 and any(y["tx"] >= 500 for y in r[7] if y is not x)]
quiet = [(r[2], x) for r in report for x in r[7] if x["phys"] == phys and x["tx"] < 50 and not any(y["tx"] >= 500 for y in r[7] if y is not x)]
print(f"\n{len(silent)} NIC(s) on {phys} where the guest sends (almost) nothing while another NIC of it is busy "
      "(the guest has no IP / route on it, e.g. its name changed after the restart):")
for name, x in silent:
    print(f"   {name}: NIC {x['n']} {x['mac']} {x['net']} VLAN {x['vlan']} IP {x['ips']} (sent {x['tx']}, received {x['rx']})")
print(f"\n{len(quiet)} other NIC(s) on {phys} where the guest sent fewer than 50 packets since its domain started (idle, or "
      "no IP / route in the guest: check these too):")
for name, x in quiet:
    print(f"   {name}: NIC {x['n']} {x['mac']} {x['net']} VLAN {x['vlan']} IP {x['ips']} (sent {x['tx']}, received {x['rx']})")
print(f"\n!! = a NIC on {phys} and several NICs or an attach / detach in the history. In the guest (console): "
      "`ip -br link` and `ip -br addr` (each MAC above with its IPs), `ip route` (the routes to the MPLS networks), and the "
      "interface config (by name or by MAC). A name / order change or a route added by hand is fixed in the guest by its owner.")
wi_ops.SSH_POOL.close()
PY
)

REMOTE=$(cat <<'EOF'
set -u
source $RC >/dev/null 2>&1 || { echo "source $RC failed"; exit 1; }
W=$(mktemp -d /tmp/wi-nics.XXXXXXXX) || exit 1
trap 'rm -rf "$W"' EXIT
printf %s "$OPSB" | base64 -d | gunzip > "$W/wi_ops.py"
printf %s "$HB" | base64 -d > "$W/harness.py"
python3 -u "$W/harness.py" "$NODE" "$PHYS"
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, crashed compute $NODE, physical network $PHYS; director $DIR_USER@$DIR_HOST"
  OPSB=$(gzip -c "$OPS" | base64 -w0)
  HB=$(printf '%s\n' "$HARNESS" | base64 -w0)
  printf 'RC=%s\nNODE=%q\nPHYS=%q\nOPSB=%q\nHB=%q\n%s\n' "$RC" "$NODE" "$PHYS" "$OPSB" "$HB" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "$HOP bash -s" 2>&1 | grep -v '^\*\* '
  echo "== exit ${PIPESTATUS[1]}"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

#!/usr/bin/env bash
# Read-only: do the VLANs of a physical network (e.g. osp-provider, the MPLS networks) reach the computes from the switch?
# For each compute named: the MAC table of the OVS bridge of that physical network (ovs-appctl fdb/show), per VLAN, the
# MACs learned from the uplink (the bond to the switch: the gateways / PE routers and hosts behind it) and from the
# instances (the patch ports to br-int), next to the Neutron networks of that physical network and their VLAN. A VLAN with
# instances on a compute but no MAC from the uplink there gets no traffic from the switch (VLAN not on that trunk, the
# PE / gateway down) or is idle: compare with another compute that has the same VLAN. Nothing is changed.
# Same path as the portal: portal service account -> management host -> director -> computes.
# Run on the bastion:  sudo bash ~/provider-vlan-check.sh <SITE> <physnet> <compute short>[,<compute short>...]
#   e.g. sudo bash ~/provider-vlan-check.sh DCC osp-provider dccrhosp-compute-0,dccrhosp-compute-1
set -u
SITE="${1:-}"
PHYS="${2:-}"
NODES="${3:-}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$PHYS" =~ ^[A-Za-z0-9_.-]{1,64}$ ]] || { echo "Physical network: e.g. osp-provider"; exit 1; }
[[ "$NODES" =~ ^[a-z0-9-]{1,63}(,[a-z0-9-]{1,63}){0,15}$ ]] || { echo "Computes: short names, comma separated"; exit 1; }
OUT="/home/deploy/provider-vlan-check-$SITE-$PHYS-$(date +%Y%m%d-%H%M%S).txt"
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
phys, nodes = sys.argv[1], sys.argv[2].split(",")
d = wi_ops.Director(write=lambda line: None)


def sh(argv, timeout=180):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, ""


rc, out = sh(["openstack", "network", "list", "--provider-physical-network", phys, "-f", "json"])
nets = json.loads(out) if rc == 0 else []
def show(n):
    rc, out = sh(["openstack", "network", "show", n["ID"], "-f", "json", "-c", "name", "-c", "provider:segmentation_id",
                  "-c", "provider:network_type", "-c", "status", "-c", "admin_state_up"], 120)
    try:
        return json.loads(out) if rc == 0 else {}
    except ValueError:
        return {}
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
    infos = list(ex.map(show, nets))
by_vlan = {}
for n, i in zip(nets, infos):
    v = str(i.get("provider:segmentation_id") or "")
    if v.isdigit():
        by_vlan.setdefault(int(v), []).append(f"{i.get('name') or n.get('Name')}{'' if i.get('admin_state_up') in (True, None) else ' (admin down)'}")
print(f"{len(nets)} Neutron network(s) on {phys}: {len(by_vlan)} VLAN(s)")

SCRIPT = (f"br=$(ovs-vsctl get open_vswitch . external_ids:ovn-bridge-mappings | tr -d '\"' | tr ',' '\\n' | "
          f"awk -F: '$1 == \"{phys}\" {{print $2}}'); [ -n \"$br\" ] || {{ echo '@@nobridge'; exit 0; }}; echo \"@@bridge $br\"; "
          "ovs-ofctl show \"$br\" | grep -oE '^ *[0-9]+\\([^)]+\\)' | tr -d ' ' | sed -E 's/^([0-9]+)\\((.*)\\)$/@@port \\1 \\2/'; "
          "for p in $(ovs-vsctl list-ports \"$br\" | grep -v '^patch-'); do echo \"@@uplink $p $(cat /sys/class/net/$p/operstate 2>/dev/null)\"; done; "
          "ovs-appctl fdb/show \"$br\" | awk 'NR > 1 {print \"@@fdb\", $1, $2, $3, $4}'")


def read(node):
    ip, user = d.node(node)
    if not ip:
        return node, f"(no address for {node})"
    rc, out = d.run(wi_ops.SSH + [f"{user}@{ip}", "sudo -n sh -c " + shlex.quote(SCRIPT)], show=False, timeout=180)
    return node, str(out or "")


with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
    results = list(ex.map(read, nodes))
seen = {}
for node, out in results:
    print(f"\n== {node}")
    if "@@nobridge" in out:
        print(f"   {phys} is not in ovn-bridge-mappings of this compute")
        continue
    br = re.search(r"^@@bridge (\S+)", out, re.M)
    names = dict(re.findall(r"^@@port (\d+) (\S+)", out, re.M))
    uplinks = re.findall(r"^@@uplink (\S+) ?(\S*)", out, re.M)
    print(f"   bridge {br.group(1) if br else '?'}; uplink(s): " + (", ".join(f"{p} {s or '?'}" for p, s in uplinks) or "NONE"))
    up = {p for p, _s in uplinks}
    per = {}
    for port, vlan, mac, age in re.findall(r"^@@fdb (\S+) (\S+) (\S+) (\S+)", out, re.M):
        name = names.get(port, port)
        if port == "LOCAL" or name == "LOCAL":   # the bridge itself
            continue
        side = "uplink" if name in up else "local"
        v = int(vlan) if vlan.isdigit() else -1
        per.setdefault(v, {"uplink": 0, "local": 0})[side] += 1
    seen[node] = per
    print("   %-6s %-8s %-8s %-10s %s" % ("VLAN", "uplink", "local", "check", "Neutron network(s)"))
    for v in sorted(set(per) | {v for v in by_vlan if v in per}):
        c = per.get(v, {"uplink": 0, "local": 0})
        flag = "NO UPLINK" if c["local"] and not c["uplink"] else "-"
        print("   %-6s %-8d %-8d %-10s %s" % (v, c["uplink"], c["local"], flag, ", ".join(by_vlan.get(v, ["(not a Neutron network)"]))[:120]))
print("\nuplink = MACs learned from the switch side (gateway / PE / other hosts), local = MACs of the instances on this "
      "compute. NO UPLINK: instances here, nothing from the switch on that VLAN in the last 5 minutes (MACs age out after "
      "300 s of silence): compare with the other compute(s) above and check that VLAN on the trunk / PE.")
wi_ops.SSH_POOL.close()
PY
)

REMOTE=$(cat <<'EOF'
set -u
source $RC >/dev/null 2>&1 || { echo "source $RC failed"; exit 1; }
W=$(mktemp -d /tmp/wi-vlan.XXXXXXXX) || exit 1
trap 'rm -rf "$W"' EXIT
printf %s "$OPSB" | base64 -d | gunzip > "$W/wi_ops.py"
printf %s "$HB" | base64 -d > "$W/harness.py"
python3 -u "$W/harness.py" "$PHYS" "$NODES"
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, physical network $PHYS, computes $NODES; director $DIR_USER@$DIR_HOST"
  OPSB=$(gzip -c "$OPS" | base64 -w0)
  HB=$(printf '%s\n' "$HARNESS" | base64 -w0)
  printf 'RC=%s\nPHYS=%q\nNODES=%q\nOPSB=%q\nHB=%q\n%s\n' "$RC" "$PHYS" "$NODES" "$OPSB" "$HB" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "$HOP bash -s" 2>&1 | grep -v '^\*\* '
  echo "== exit ${PIPESTATUS[1]}"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

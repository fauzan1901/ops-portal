#!/usr/bin/env bash
# Read-only: why did Nova answer "No valid host was found" to a live migration with a destination named (microversion
# 2.30: the scheduler checks the host)? The instance (flavor as it has it, with its extra specs, image properties, server
# groups and where their members run), its live-migration requests of the last 2 days with every event and the end of
# each traceback (a destination whose pre-check failed is skipped by nova-conductor, and the scheduler then answers No
# valid host), the scheduler settings and every nova-scheduler / nova-conductor / nova-api line of those requests on the
# controllers ("Got no allocation candidates" = Placement has no room; "Filtering removed all hosts" = a filter, named;
# "ignoring hosts" = the destination was skipped after its pre-check), the zones and aggregates of the computes, and the
# room left in Placement on every compute (allocation ratio and reserved included) against the flavor of the instance.
# Same path as the portal: portal service account -> management host -> director -> controllers. Only show / list /
# grep of logs and GET requests.
# Run on the bastion:  sudo bash ~/no-valid-host-why.sh <SITE> <server ID> [<request ID>[,<request ID>...]]
set -u
SITE="${1:-}"
SID="${2:-}"
REQARG="${3:-}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$SID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || { echo "Server ID: an OpenStack UUID"; exit 1; }
[ -z "$REQARG" ] || [[ "$REQARG" =~ ^req-[0-9a-f-]{36}(,req-[0-9a-f-]{36})*$ ]] || { echo "Request ID(s): req-<uuid>[,req-<uuid>...]"; exit 1; }
OUT="/home/deploy/no-valid-host-why-$(date +%Y%m%d-%H%M%S).txt"
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
SJ=$(openstack --os-compute-api-version 2.79 server show "$SID" -f json 2>&1)
echo "== Instance (the flavor as the instance has it, with its extra specs)"
printf '%s' "$SJ" | python3 -c '
import json, sys
t = sys.stdin.read()
try:
    s = json.loads(t)
except ValueError:
    print(t[:800]); sys.exit()
for k in ("name", "status", "OS-EXT-STS:task_state", "OS-EXT-SRV-ATTR:host", "OS-EXT-AZ:availability_zone", "project_id",
          "config_drive", "image", "volumes_attached", "created", "locked"):
    print(f"{k}: {s.get(k)}")
print("flavor:", json.dumps(s.get("flavor")))'
# vcpus ram disk(root+ephemeral+swap GiB, 0 when booted from volume) image-id volume-ids
read -r VCPUS RAM DISK IMG VOLS < <(printf '%s' "$SJ" | python3 -c '
import json, math, re, sys
try:
    s = json.loads(sys.stdin.read())
except ValueError:
    print("0 0 0 - -"); sys.exit()
f = s.get("flavor")
img = re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", str(s.get("image") or ""))
vols = re.findall(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", str(s.get("volumes_attached") or ""))
def n(k):   # the embedded flavor: a dict, or the "key=\x27value\x27, ..." text of older clients
    v = f.get(k) if isinstance(f, dict) else (re.search(r"\b%s=\x27?(\d+)" % k, str(f or "")) or [None, None])[1]
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0
disk = (n("disk") if img else 0) + n("ephemeral") + int(math.ceil(n("swap") / 1024.0))
print(n("vcpus"), n("ram"), disk, img.group(0) if img else "-", ",".join(vols[:4]) or "-")')
echo "(placement needs: VCPU $VCPUS, MEMORY_MB $RAM, DISK_GB $DISK$( [ "$IMG" = "-" ] && echo ', booted from volume'))"
if [ "$IMG" != "-" ]; then
  echo "== Image $IMG: properties that steer scheduling (hw_*, traits, img_*)"
  openstack image show "$IMG" -f json -c name -c properties 2>&1 | python3 -c '
import json, sys
t = sys.stdin.read()
try:
    i = json.loads(t)
except ValueError:
    print(t[:400]); sys.exit()
p = i.get("properties") or {}
hit = {k: v for k, v in p.items() if k.startswith(("hw_", "trait", "img_", "os_", "hypervisor", "architecture"))}
print(i.get("name"), json.dumps(hit) if hit else "(none of those)")'
fi
if [ "$VOLS" != "-" ]; then
  echo "== Volumes: boot flag and the image properties they carry"
  for v in ${VOLS//,/ }; do
    echo "$v $(openstack volume show "$v" -f json -c bootable -c volume_image_metadata -c volume_type -c size 2>&1 | python3 -c '
import json, sys
t = sys.stdin.read()
try:
    v = json.loads(t)
except ValueError:
    print(t[:300]); sys.exit()
m = v.get("volume_image_metadata") or {}
hit = {k: x for k, x in m.items() if str(k).startswith(("hw_", "trait", "img_"))} if isinstance(m, dict) else m
print("bootable", v.get("bootable"), "type", v.get("volume_type"), "size", v.get("size"), "props", json.dumps(hit))')"
  done
fi
echo "== Server groups with this instance (affinity / anti-affinity) and the computes of their members"
openstack server group list --all-projects --long -f json 2>&1 | SID=$SID python3 -c '
import json, os, subprocess, sys
t = sys.stdin.read()
try:
    rows = json.loads(t)
except ValueError:
    print(t[:400]); sys.exit()
sid, hit = os.environ["SID"], 0
for g in rows:
    if sid not in str(g.get("Members")):
        continue
    hit += 1
    members = [m.strip() for m in str(g.get("Members")).replace("[", "").replace("]", "").replace("\x27", "").split(",") if m.strip()]
    hosts = []
    for m in members[:30]:
        p = subprocess.run(["openstack", "server", "show", m, "-f", "value", "-c", "OS-EXT-SRV-ATTR:host"], capture_output=True, text=True)
        hosts.append((p.stdout.strip() or "?").split(".")[0])
    print(g.get("Name"), g.get("ID"), "policy", g.get("Policies") or g.get("Policy"), "rules", g.get("Rules", "-"),
          f"{len(members)} member(s) on", ", ".join(sorted(set(hosts))))
print(f"{hit} group(s)")'
echo "== Live-migration requests of the instance (last 2 days, and any given), every event with the end of its traceback"
CUT=$(date -u -d '-2 days' +%Y-%m-%dT%H:%M:%S)
REQS=$({ openstack server event list "$SID" -f value -c "Request ID" -c Action -c "Start Time" 2>/dev/null |
         awk -v c="$CUT" '$3 >= c && $2 ~ /live.migration/ {print $1}'; printf '%s\n' ${REQARG//,/ }; } | awk 'NF && !s[$0]++' | head -12)
for req in $REQS; do
  openstack server event show "$SID" "$req" -f json 2>&1
  echo "@@@"
done | python3 -c '
import json, sys
for chunk in sys.stdin.read().split("@@@"):
    try:
        a = json.loads(chunk)
    except ValueError:
        if chunk.strip():
            print("  " + chunk.strip()[:300])
        continue
    ev = a.get("events") or []
    print("%s %s %s message: %s" % (a.get("start_time"), a.get("action"), a.get("request_id"), a.get("message") or "-"))
    for e in sorted(ev, key=lambda e: e.get("start_time") or ""):
        print("     %s %s %s on %s" % (e.get("event"), e.get("result"), e.get("start_time"), e.get("host") or "-"))
        tb = [l for l in (e.get("traceback") or "").strip().splitlines() if l.strip()]
        for l in tb[-4:]:
            print("       | " + l.strip()[:400])
    if not ev:
        print("     (no event: refused before any compute worked on it)")
'
echo "== Migrations of the instance (newest 8)"
openstack --os-compute-api-version 2.59 server migration list --server "$SID" --limit 8 -f value -c Id -c Type -c Status \
  -c "Source Compute" -c "Dest Compute" -c "Created At" 2>&1 | head -8
echo "== nova-compute services: zone, status, state"
openstack compute service list --service nova-compute -f json 2>&1 | python3 -c '
import json, sys
t = sys.stdin.read()
try:
    rows = json.loads(t)
except ValueError:
    print(t[:400]); sys.exit()
for r in sorted(rows, key=lambda r: str(r.get("Host"))):
    print(str(r.get("Host")).split(".")[0], r.get("Zone"), r.get("Status"), r.get("State"))'
echo "== Aggregates: zone, properties (filter_tenant_id, flavor keys), hosts"
for a in $(openstack aggregate list -f value -c ID 2>/dev/null); do
  openstack aggregate show "$a" -f json 2>&1 | python3 -c '
import json, sys
t = sys.stdin.read()
try:
    g = json.loads(t)
except ValueError:
    print(t[:300]); sys.exit()
hosts = g.get("hosts") or []
hosts = hosts if isinstance(hosts, list) else str(hosts).split(",")
print("%s zone %s properties %s\n   %d host(s): %s" % (g.get("name"), g.get("availability_zone") or "-", g.get("properties") or "-",
      len(hosts), ", ".join(sorted(str(h).strip().split(".")[0] for h in hosts))))'
done
echo "== Placement: room left on every compute ((total - reserved) x allocation ratio - used) against this instance"
TOKEN=$(openstack token issue -f value -c id 2>/dev/null)
PURL=$(openstack endpoint list --service placement --interface public -f value -c URL 2>/dev/null | head -1)
[ -n "$PURL" ] || PURL=$(openstack endpoint list --service placement --interface internal -f value -c URL 2>/dev/null | head -1)
TOKEN=$TOKEN PURL=$PURL NEED="$VCPUS $RAM $DISK" SRC="$(printf '%s' "$SJ" | python3 -c 'import json,sys
try: print(str(json.loads(sys.stdin.read()).get("OS-EXT-SRV-ATTR:host") or "").split(".")[0])
except ValueError: print("")')" python3 -c '
import json, os, ssl, sys, urllib.request
tok, url = os.environ.get("TOKEN", ""), os.environ.get("PURL", "").rstrip("/")
if not tok or not url:
    print("no token or no placement endpoint: skipped"); sys.exit()
need = dict(zip(("VCPU", "MEMORY_MB", "DISK_GB"), map(int, os.environ["NEED"].split())))
ctx = ssl.create_default_context(cafile=os.environ.get("OS_CACERT") or None)
if str(os.environ.get("OS_INSECURE", "")).lower() in ("1", "true", "yes"):
    ctx = ssl._create_unverified_context()
def get(path):
    r = urllib.request.Request(url + path, headers={"X-Auth-Token": tok, "OpenStack-API-Version": "placement 1.10",
                                                    "Accept": "application/json"})
    with urllib.request.urlopen(r, timeout=60, context=ctx) as f:
        return json.load(f)
try:
    rps = get("/resource_providers")["resource_providers"]
except Exception as e:
    print(f"placement not readable ({e}): skipped"); sys.exit()
src = os.environ.get("SRC", "")
print("%-34s %-26s %-30s %-24s %s" % ("compute", "VCPU used/cap (ratio)", "RAM GiB used/cap (ratio, rsvd)", "DISK GiB used/cap", "this instance fits?"))
for rp in sorted(rps, key=lambda r: r["name"]):
    name = rp["name"].split(".")[0]
    if "compute" not in name:
        continue
    try:
        inv = get("/resource_providers/%s/inventories" % rp["uuid"])["inventories"]
        use = get("/resource_providers/%s/usages" % rp["uuid"])["usages"]
    except Exception as e:
        print(name, "not readable:", e); continue
    cols, short = [], []
    for rc in ("VCPU", "MEMORY_MB", "DISK_GB"):
        i = inv.get(rc)
        if not i:
            cols.append("-"); continue
        cap = int((i["total"] - i.get("reserved", 0)) * i.get("allocation_ratio", 1.0))
        used = use.get(rc, 0)
        free = cap - used
        d = 1024.0 if rc == "MEMORY_MB" else 1
        cols.append("%g/%g (x%g%s)" % (round(used / d, 1), round(cap / d, 1), i.get("allocation_ratio", 1.0),
                                       ", %g" % round(i.get("reserved", 0) / d, 1) if rc == "MEMORY_MB" else ""))
        if need.get(rc) and (need[rc] > free or need[rc] > i.get("max_unit", need[rc])):
            short.append("%s needs %g, free %g" % (rc, round(need[rc] / d, 1), round(free / d, 1)))
    mark = "(the source)" if name == src else ("NO: " + "; ".join(short)) if short else "yes"
    print("%-34s %-26s %-30s %-24s %s" % (name, cols[0], cols[1], cols[2], mark))
'
INV=$(ls ~/overcloud-deploy/*/tripleo-ansible-inventory.yaml ~/config-download/*/tripleo-ansible-inventory.yaml \
  ~/tripleo-ansible-inventory.yaml 2>/dev/null | head -1)
DEFUSR=$(grep -q '17\.' /etc/rhosp-release && echo tripleo-admin || echo heat-admin)
CTL=$(python3 - "$INV" <<'PY'
import sys, yaml
try:
    inv = yaml.safe_load(open(sys.argv[1])) or {}
except Exception:
    inv = {}
seen = set()
for group, body in inv.items():
    for host, hv in ((body or {}).get("hosts") or {}).items() if isinstance(body, dict) else []:
        name = host.split(".")[0].lower()
        if isinstance(hv, dict) and "controller" in (group + name).lower() and name not in seen:
            seen.add(name)
            print(name, hv.get("ctlplane_ip") or hv.get("ansible_host") or "-", hv.get("ansible_ssh_user") or "-")
PY
)
first=1
while read -r N IP USR; do
  [ -n "${IP:-}" ] && [ "$IP" != "-" ] || continue
  [ "$USR" = "-" ] && USR=$DEFUSR
  echo
  echo "######## controller $N"
  ssh -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
    "$USR@$IP" "sudo bash -s -- $SID $first $(echo $REQS | tr ' ' ',')" <<'NODE' 2>&1 | cut -c1-700
SID=$1 FIRST=$2 REQS=${3:-}
L=/var/log/containers/nova
echo "(times here are $(date +%Z))"
if [ "$FIRST" = 1 ]; then
  echo "-- scheduler settings (nova.conf of the controller; a key not shown has its default)"
  grep -hE '^\s*(enabled_filters|available_filters|query_placement_for_availability_zone|query_placement_for_image_type_support|limit_tenants_to_placement_aggregate|placement_aggregate_required_for_tenants|enable_isolated_aggregate_filtering|max_attempts|host_subset_size|max_placement_results|migrate_max_retries)\s*=' \
    /var/lib/config-data/puppet-generated/nova*/etc/nova/nova.conf 2>/dev/null | sort -u
fi
for r in ${REQS//,/ }; do
  for f in nova-scheduler nova-conductor nova-api; do
    x=$(zgrep -h "$r" $L/$f.log* 2>/dev/null | sort -s -k1,2)
    [ -n "$x" ] || continue
    echo "[$f] $r: $(printf '%s\n' "$x" | grep -c .) line(s)"
    printf '%s\n' "$x" | grep -v ' DEBUG ' | head -25
  done
done
echo "-- scheduler lines naming the instance (filter results, Placement, hosts ignored)"
zgrep -h "$SID" $L/nova-scheduler.log* 2>/dev/null | grep -E 'Filtering removed|allocation candidates|ignoring hosts|NoValidHost' | sort -s -k1,2 | tail -10
NODE
  first=0
done <<< "$CTL"
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, server $SID${REQARG:+, request(s) $REQARG}; management host $MGMT_HOST, director $DIR_USER@$DIR_HOST (keys are not printed)"
  printf 'SID=%q\nREQARG=%q\nRC=%s\n%s\n' "$SID" "$REQARG" "$RC" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1 | grep -v '^\*\* '
  echo "== exit ${PIPESTATUS[1]}"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

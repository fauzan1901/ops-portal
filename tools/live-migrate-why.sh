#!/usr/bin/env bash
# Read-only: why did a live migration fail, hang or need an abort (instance left in ERROR, rolled back, stuck in
# migrating)? The instance, its migrations and live-migration actions incl. aborts (events with traceback), the zones and
# CPUs of the source and destination computes, other migrations of that destination, the ports of the instance, the
# nova-compute / nova-conductor / qemu log lines of the instance (start and end of the migration request, progress lines),
# and on both computes: the domain now, its last migration job (domjobinfo --completed), its QEMU process, multipath maps
# with no active path and kernel I/O errors.
# Same path as the portal: portal service account -> management host -> director -> overcloud nodes (tripleo-admin /
# heat-admin). Only show / list / grep of logs.   Run on the bastion:  sudo bash ~/live-migrate-why.sh <SITE> <server ID or exact name>
# Also the volumes of the instance in Cinder and the cinder-api / cinder-volume lines of the migration request (a failed
# attachment for the destination in pre_live_migration).
set -u
SITE="${1:-}"
SID="${2:-}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
# an exact instance name is looked up on the director (all projects); it must name one instance
[[ "$SID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ || "$SID" =~ ^[A-Za-z0-9_.-]{1,64}$ ]] \
  || { echo "Server: an OpenStack UUID or an exact instance name"; exit 1; }
OUT="/home/deploy/live-migrate-why-$(date +%Y%m%d-%H%M%S).txt"
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
if ! [[ "$SID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
  IDS=$(openstack server list --all-projects --name "^${SID//./\\.}\$" -f value -c ID 2>&1)
  n=$(printf '%s\n' "$IDS" | grep -cE '^[0-9a-f-]{36}$')
  [ "$n" = 1 ] || { echo "Instance name $SID: $n instance(s) with exactly that name (give its ID):"; printf '%s\n' "$IDS" | head -10; exit 1; }
  echo "Instance name $SID = $IDS"
  SID=$IDS
fi
echo "== Instance"
openstack server show "$SID" -f json -c name -c status -c OS-EXT-STS:vm_state -c OS-EXT-STS:power_state \
  -c OS-EXT-STS:task_state -c OS-EXT-SRV-ATTR:host -c OS-EXT-SRV-ATTR:instance_name -c OS-EXT-AZ:availability_zone \
  -c flavor -c image -c config_drive -c volumes_attached -c fault -c updated
HOST=$(openstack server show "$SID" -f value -c OS-EXT-SRV-ATTR:host)
INST=$(openstack server show "$SID" -f value -c OS-EXT-SRV-ATTR:instance_name)
IMG=$(openstack server show "$SID" -f json -c image | python3 -c 'import json,sys; v=json.load(sys.stdin).get("image"); print(v.get("id","") if isinstance(v,dict) else "")' 2>/dev/null)
if [ -n "$IMG" ]; then
  echo "== Image $IMG (hw_* properties change what libvirt needs on the destination)"
  openstack image show "$IMG" -f json -c name -c disk_format -c properties 2>&1 | head -40
fi
echo "== Migrations of the instance (newest first)"
MIG=$(openstack --os-compute-api-version 2.59 server migration list --server "$SID" -f json 2>&1)
MIG="$MIG" python3 - <<'PY'
import json, os
try:
    rows = json.loads(os.environ["MIG"])
except Exception:
    print(os.environ["MIG"][:2000]); rows = []
for r in sorted(rows, key=lambda r: -int(r.get("Id") or 0))[:8]:
    print(r.get("Id"), r.get("Type"), r.get("Status"), r.get("Source Compute"), "->", r.get("Dest Compute"),
          "created", r.get("Created At"), "updated", r.get("Updated At"))
PY
DEST=$(MIG="$MIG" python3 -c '
import json, os
try:
    rows = [r for r in json.loads(os.environ["MIG"]) if "live" in str(r.get("Type") or "") or not r.get("Type")]
except Exception:
    rows = []
rows.sort(key=lambda r: -int(r.get("Id") or 0))
print((rows[0].get("Source Compute") or "-") + " " + (rows[0].get("Dest Compute") or "-") if rows else "- -")' 2>/dev/null)
# the computes of the last live migration (its source ran the copy and logged its progress), and where it is now
MSRC=${DEST%% *}; DEST=${DEST#* }
[ "$MSRC" = "-" ] && MSRC=""; [ "$DEST" = "-" ] && DEST=""
echo "Now on (where Nova records it): ${HOST:-?}; last live migration: ${MSRC:-?} -> ${DEST:-?}"
echo "== live-migration actions of the instance, aborts included (newest first), and the events of the last 3 (admins see the traceback)"
EV=$(openstack server event list "$SID" -f value -c "Request ID" -c Action -c "Start Time" 2>&1 | awk '$2 ~ /live.migration/ {print $3, $1, $2}' | sort -r)
printf '%s\n' "$EV" | head -6
for req in $(printf '%s\n' "$EV" | head -3 | awk '{print $2}'); do
  echo "-- $req"; openstack server event show "$SID" "$req" -f json 2>&1 | head -80
done
# the last live migration itself, and the aborts / force-completes asked for after it
REQ=$(printf '%s\n' "$EV" | awk '$3 == "live-migration" {print $2; exit}')
AFTER=$(printf '%s\n' "$EV" | awk '$3 == "live-migration" {exit} {print $2}' | head -3)
echo "== nova-compute services (zone, status, state)"
openstack compute service list --service nova-compute -f value -c Host -c Zone -c Status -c State 2>&1 | sort
echo "== Aggregates (availability zone, properties)"
openstack aggregate list --long -f value 2>&1 | head -20
echo "== CPU of the source and the destination (libvirt refuses a destination missing a CPU feature of the source)"
CS=$(openstack hypervisor show "${MSRC:-$HOST}" -f json -c cpu_info 2>&1)
CD=$( [ -n "$DEST" ] && openstack hypervisor show "$DEST" -f json -c cpu_info 2>&1)
CS="$CS" CD="$CD" python3 - <<'PY'
import json, os, ast
def cpu(text):
    try:
        v = json.loads(text).get("cpu_info")
        if isinstance(v, str):
            try:
                v = json.loads(v)
            except ValueError:
                v = ast.literal_eval(v)
        return v if isinstance(v, dict) else {}
    except Exception:
        return {}
s, d = cpu(os.environ.get("CS", "")), cpu(os.environ.get("CD", ""))
for role, c in (("source", s), ("destination", d)):
    print(f"{role}: model {c.get('model')}, vendor {c.get('vendor')}, {len(c.get('features') or [])} features, topology {c.get('topology')}")
if s and d:
    print("features of the source missing on the destination:", sorted(set(s.get("features") or []) - set(d.get("features") or [])) or "none")
PY
echo "== Other migrations from or to the destination ${DEST:-?} (newest first; did it accept others in this run?)"
if [ -n "$DEST" ]; then
  openstack --os-compute-api-version 2.59 server migration list --host "$DEST" --limit 15 -f json 2>&1 | python3 -c '
import json, sys
text = sys.stdin.read()
try:
    rows = json.loads(text)
except ValueError:
    print(text[:1500]); rows = []
for r in rows:
    print(r.get("Id"), r.get("Type"), r.get("Status"), r.get("Source Compute"), "->", r.get("Dest Compute"), "server", r.get("Server UUID"), r.get("Created At"))'
fi
echo "== Ports of the instance (binding host, vif type, binding profile)"
for p in $(openstack port list --server "$SID" -f value -c ID 2>/dev/null); do
  openstack port show "$p" -f json -c id -c status -c binding_host_id -c binding_vif_type -c binding_profile 2>&1 | tr -d '\n'; echo
done
INV=$(ls ~/overcloud-deploy/*/tripleo-ansible-inventory.yaml ~/config-download/*/tripleo-ansible-inventory.yaml \
  ~/tripleo-ansible-inventory.yaml 2>/dev/null | head -1)
nodes() {   # "<short name> <ctlplane ip> <ssh user>" of the nodes whose name or group matches $1
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
on() {   # on <ip> <user> <command>
  local u="$2"; [ "$u" = "-" ] && u=$DEFUSR
  ssh -n -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$u@$1" "$3"
}
onin() {   # onin <ip> <user> <arg> < script: the script runs as root on the node, with <arg> as $1
  local u="$2"; [ "$u" = "-" ] && u=$DEFUSR
  ssh -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$u@$1" "sudo bash -s -- $3"
}
PAIRS=("source ${MSRC:-${HOST:-}}" "destination ${DEST:-}")
[ -n "$HOST" ] && [ "$HOST" != "${MSRC:-$HOST}" ] && [ "$HOST" != "$DEST" ] && PAIRS+=("now ${HOST}")
for pair in "${PAIRS[@]}"; do
  set -- $pair
  role=$1; h=${2:-}
  [ -z "$h" ] && { echo "== $role: unknown"; continue; }
  N= IP= USR=
  read -r N IP USR < <(nodes "${h%%.*}")
  [ -z "${IP:-}" ] || [ "$IP" = "-" ] && { echo "== $role $h: no address in the inventory"; continue; }
  echo "== nova-compute on $h ($role): ERROR / WARNING lines of the instance (traceback included, also rotated logs), last 80"
  on "$IP" "$USR" "sudo sh -c 'zgrep -hE \"$SID\" /var/log/containers/nova/nova-compute.log* 2>/dev/null' | grep -E ' (ERROR|WARNING|CRITICAL) ' | sort -s -k1,2 | tail -80" | cut -c1-500
  if [ -n "$REQ" ]; then
    # the start (pre_live_migration, volume connections) and the end (progress, abort, rollback) of that request
    echo "== nova-compute on $h ($role): the last live migration request $REQ, first 20 and last 45 lines"
    L=$(on "$IP" "$USR" "sudo sh -c 'zgrep -hE \"$REQ\" /var/log/containers/nova/nova-compute.log* 2>/dev/null' | sort -s -k1,2" | cut -c1-500)
    n=$(printf '%s\n' "$L" | grep -c .)
    printf '%s\n' "$L" | head -20
    [ "$n" -gt 65 ] && echo "   ... $((n - 65)) line(s) left out ..."
    [ "$n" -gt 20 ] && printf '%s\n' "$L" | tail -n $(( n - 20 < 45 ? n - 20 : 45 ))
  fi
  for a in $AFTER; do
    echo "== nova-compute on $h ($role): request $a (abort / force complete), last 15 lines"
    on "$IP" "$USR" "sudo sh -c 'zgrep -hE \"$a\" /var/log/containers/nova/nova-compute.log* 2>/dev/null' | sort -s -k1,2 | tail -15" | cut -c1-500
  done
  echo "== nova-compute on $h ($role): progress lines of the instance (memory left, downtime steps), last 25"
  on "$IP" "$USR" "sudo sh -c 'zgrep -hE \"$SID\" /var/log/containers/nova/nova-compute.log* 2>/dev/null' | grep -E 'Migration running for|Increasing downtime|Migration operation has|[Pp]ost.copy|Live Migration failure|aborted' | sort -s -k1,2 | tail -25" | cut -c1-400
  echo "== nova.conf on $h: CPU and live migration settings"
  on "$IP" "$USR" "sudo grep -hE '^(cpu_mode|cpu_models?|cpu_model_extra_flags|live_migration_[a-z_]+|images_type)\s*=' /var/lib/config-data/puppet-generated/nova_libvirt/etc/nova/nova.conf 2>/dev/null | sort -u"
  if [ -n "$INST" ]; then
    echo "== qemu log of $INST on $h, last 25"
    on "$IP" "$USR" "sudo tail -25 /var/log/containers/libvirt/qemu/$INST.log 2>/dev/null || echo 'no qemu log'" | cut -c1-400
    echo "== $h ($role): domain $INST now, its last migration job, its QEMU process, dead multipath maps, kernel errors"
    onin "$IP" "$USR" "$INST" <<'NODE' | cut -c1-400
I=$1
c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$')
if [ -z "$c" ]; then echo "no libvirt container running"; else
  V="timeout 30 podman exec $c virsh -c qemu:///system"
  echo "domstate: $($V domstate --reason "$I" 2>&1 | head -1)"
  if $V dominfo "$I" >/dev/null 2>&1; then
    $V dominfo "$I" 2>&1 | grep -E '^(State|CPU\(s\)|Max memory|Used memory|Persistent)'
    echo "-- domjobinfo (a job running now?)"
    $V domjobinfo "$I" 2>&1 | grep -v '^$' | head -30
    echo "-- domjobinfo --completed (the last job that ended, aborted ones included; the stats are kept)"
    $V domjobinfo "$I" --completed --keep-completed 2>&1 | grep -v '^$' | head -40
    echo "-- passthrough devices (hostdev) in the domain: $($V dumpxml "$I" 2>/dev/null | grep -c '<hostdev ')"
    echo "-- disks"
    $V domblklist "$I" 2>&1 | grep -v '^$'
  fi
  for p in $(pgrep -f "guest=$I," | head -3); do
    echo "-- qemu pid $p: state $(awk '{print $3}' /proc/$p/stat 2>/dev/null), started $(ps -o lstart= -p $p), wchan $(cat /proc/$p/wchan 2>/dev/null)"
  done
fi
echo "-- multipath maps with no active path (map, path devices)"
Z=$(dmsetup status --target multipath 2>/dev/null | awk '$4 == "multipath" {n = $1; sub(/:$/, "", n); a = 0; t = 0
  for (i = 2; i < NF; i++) if ($i ~ /^[0-9]+:[0-9]+$/) {t++; if ($(i+1) == "A") a++}
  if (a == 0) print n, t}')
echo "${Z:-none}"
echo "-- kernel, last 8 hours: I/O errors, path failures, hung tasks, lockups (last 25)"
journalctl -k --since '-8 hours' --no-pager 2>/dev/null | grep -E 'I/O error|Illegal Request|Logical unit not supported|failing path|remaining active paths: 0|blocked for more than|soft lockup|[Hh]ard LOCKUP' | tail -25
NODE
  fi
done
echo "== nova-conductor on the controllers: ERROR / WARNING lines of the instance (also rotated logs), last 30"
nodes controller | while read -r N IP USR; do
  [ "$IP" = "-" ] && continue
  L=$(on "$IP" "$USR" "sudo sh -c 'zgrep -hE \"$SID\" /var/log/containers/nova/nova-conductor.log* 2>/dev/null' | grep -E ' (ERROR|WARNING|CRITICAL) ' | sort -s -k1,2 | tail -30" | cut -c1-500)
  [ -n "$L" ] && { echo "-- $N"; printf '%s\n' "$L"; }
done
# pre_live_migration makes a new attachment of each volume for the destination (Cinder: initialize_connection = the LUN
# mapped to the destination's initiator); when that fails, only Cinder's logs say why (Nova passes its request ID on)
VOLS=$(openstack server show "$SID" -f json -c volumes_attached 2>/dev/null | python3 -c '
import json, sys
try:
    print(" ".join(v.get("id", "") for v in json.load(sys.stdin).get("volumes_attached") or []))
except Exception:
    pass')
echo "== Volumes of the instance in Cinder (status, host, attachments: server and host; no connection info)"
for v in $VOLS; do
  openstack volume show "$v" -f json -c id -c name -c status -c size -c os-vol-host-attr:host -c migration_status \
    -c multiattach -c attachments -c updated_at 2>&1 | V="$v" python3 -c '
import json, os, sys
text = sys.stdin.read()
try:
    v = json.loads(text)
except ValueError:
    print(text[:600]); raise SystemExit
if v.get("id") != os.environ["V"]:   # openstack volume show falls back to a NAME (vm-c3, 2026-11-02)
    print("!! NO volume with ID", os.environ["V"], "in Cinder: this is the volume NAMED so (a Cinder volume migration that",
          "never completed?); Nova cannot attach it for a destination (HTTP 404)")
print(v.get("id"), v.get("name"), v.get("status"), str(v.get("size")) + " GiB", v.get("os-vol-host-attr:host"),
      "migration", v.get("migration_status"), "multiattach", v.get("multiattach"), "updated", v.get("updated_at"))
for a in v.get("attachments") or []:
    print("   attachment", a.get("attachment_id") or a.get("id"), "server", a.get("server_id"), "host", a.get("host_name"),
          a.get("device"), "since", a.get("attached_at"))'
  echo "   attachment records (API 3.27; the list only, never attachment-show: it prints the connection info)"
  cinder --os-volume-api-version 3.27 attachment-list --all-tenants --volume-id "$v" 2>&1 | head -12 | sed 's/^/     /'
done
PAT=$(printf '%s\n' $VOLS | paste -sd'|')
nodes controller | while read -r N IP USR; do
  [ "$IP" = "-" ] && continue
  for svc in cinder-api cinder-volume; do
    if [ -n "$REQ" ]; then
      L=$(on "$IP" "$USR" "sudo sh -c 'zgrep -hE \"$REQ\" /var/log/containers/cinder/$svc.log* 2>/dev/null' | sort -s -k1,2" | cut -c1-500)
      n=$(printf '%s\n' "$L" | grep -c .)
      if [ "$n" -gt 0 ]; then
        echo "== $svc on $N: lines of the live migration request $REQ ($n; first 10 and last 30)"
        printf '%s\n' "$L" | head -10
        [ "$n" -gt 40 ] && echo "   ... $((n - 40)) line(s) left out ..."
        [ "$n" -gt 10 ] && printf '%s\n' "$L" | tail -n $(( n - 10 < 30 ? n - 10 : 30 ))
      fi
    fi
    [ -z "$PAT" ] && continue
    L=$(on "$IP" "$USR" "sudo sh -c 'zgrep -hE \"$PAT\" /var/log/containers/cinder/$svc.log* 2>/dev/null' | grep -E ' (ERROR|WARNING|CRITICAL) ' | sort -s -k1,2 | tail -30" | cut -c1-500)
    [ -n "$L" ] && { echo "== $svc on $N: ERROR / WARNING lines of the volumes (also rotated logs), last 30"; printf '%s\n' "$L"; }
  done
done
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, server $SID; management host $MGMT_HOST, director $DIR_USER@$DIR_HOST (keys are not printed)"
  printf 'SID=%q\nRC=%s\n%s\n' "$SID" "$RC" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1
  echo "== exit $?"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

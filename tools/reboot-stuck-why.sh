#!/usr/bin/env bash
# Read-only: why did an action on an instance (hard reboot, migration, reset) fail or hang? The actions of the instance
# with their events and tracebacks, the nova-compute lines of those requests on its compute, the cinder-api /
# cinder-volume lines of its volumes on the controllers, and on its compute and on the source of its last migration:
# the domain, its disks and the multipath state of each (a volume still connected, or a path left over).
# Same path as the portal: portal service account -> management host -> director -> controllers / computes.
# Run on the bastion:  sudo bash ~/reboot-stuck-why.sh <SITE> <server ID>
set -u
SITE="${1:-}"
SID="${2:-}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$SID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || { echo "Server ID: an OpenStack UUID"; exit 1; }
OUT="/home/deploy/reboot-stuck-why-$(date +%Y%m%d-%H%M%S).txt"
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
echo "== Instance"
SRV=$(openstack server show "$SID" -f json 2>&1)
SRV="$SRV" python3 - <<'PY'
import json, os
try:
    s = json.loads(os.environ["SRV"])
except Exception:
    print(os.environ["SRV"][:1500]); raise SystemExit
for k in ("name", "status", "OS-EXT-STS:vm_state", "OS-EXT-STS:power_state", "OS-EXT-STS:task_state", "OS-EXT-SRV-ATTR:host",
          "OS-EXT-SRV-ATTR:instance_name", "locked", "volumes_attached", "fault", "updated"):
    print(f"{k}: {s.get(k)}"[:600])
PY
HOST=$(SRV="$SRV" python3 -c 'import json,os; print(json.loads(os.environ["SRV"]).get("OS-EXT-SRV-ATTR:host") or "")' 2>/dev/null)
INST=$(SRV="$SRV" python3 -c 'import json,os; print(json.loads(os.environ["SRV"]).get("OS-EXT-SRV-ATTR:instance_name") or "")' 2>/dev/null)
VOLS=$(SRV="$SRV" python3 -c '
import json, os, re
v = json.loads(os.environ["SRV"]).get("volumes_attached")
print(" ".join(re.findall(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", str(v))))' 2>/dev/null)
SRC=$(openstack --os-compute-api-version 2.59 server migration list --server "$SID" -f value -c Id -c "Source Compute" 2>/dev/null | sort -rn | head -1 | awk '{print $2}')
echo "== Actions of the instance (newest first, times UTC) and the events of the last 8 (result, traceback)"
EV=$(openstack server event list "$SID" -f value -c "Request ID" -c Action -c "Start Time" 2>&1 | head -12)
printf '%s\n' "$EV"
REQS=$(printf '%s\n' "$EV" | awk '$1 ~ /^req-/ {print $1}' | head -8)
for R in $REQS; do
  openstack server event show "$SID" "$R" -f json 2>/dev/null | python3 -c '
import json, sys
a = json.load(sys.stdin)
print("--", a.get("action"), a.get("request_id"), "start", a.get("start_time"), "message", a.get("message"))
for e in a.get("events") or []:
    print("   ", e.get("event"), e.get("result"), e.get("start_time"), "->", e.get("finish_time"), "host", e.get("host"))
    tb = (e.get("traceback") or "").strip().splitlines()
    for line in tb[-4:]:
        print("      ", line[:300])'
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
onin() {   # onin <ip> <user>: runs its stdin on the node as root
  local u="$2"; [ "$u" = "-" ] && u=$DEFUSR
  ssh -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$u@$1" "sudo -n bash -s"
}
PAT=$(echo "$REQS" | tr '\n' '|' | sed 's/|$//')
if [ -n "${HOST:-}" ]; then
  read -r N IP USR < <(nodes "${HOST%%.*}")
  if [ -n "${IP:-}" ] && [ "$IP" != "-" ]; then
    echo "== nova-compute on $HOST: the lines of these requests (traceback cut), last 60"
    on "$IP" "$USR" "sudo sh -c 'zgrep -hE \"$PAT\" /var/log/containers/nova/nova-compute.log* 2>/dev/null' | grep -vE '\]  ' | sort -s -k1,2 | tail -60" | cut -c1-400
    echo "== nova-compute on $HOST: os-brick / volume connection lines of the last 3 hours (connect, iSCSI, multipath, timeouts), last 30"
    on "$IP" "$USR" "sudo sh -c 'c=\$(date -d \"-3 hours\" \"+%Y-%m-%d %H:%M:%S\"); grep -hiE \"os_brick|connect_volume|iscsiadm|multipath|Volume device not found|timed out|Lock .*held\" /var/log/containers/nova/nova-compute.log | awk -v c=\"\$c\" \"(\\\$1 \\\" \\\" \\\$2) >= c\"' | tail -30" | cut -c1-400
  fi
fi
echo "== cinder-api / cinder-volume on the controllers: ERROR / WARNING lines of the volumes, last 25 each"
nodes controller | while read -r N IP USR; do
  [ "$IP" = "-" ] && continue
  for V in $VOLS; do
    L=$(on "$IP" "$USR" "sudo sh -c 'zgrep -hE \"$V\" /var/log/containers/cinder/cinder-api.log* /var/log/containers/cinder/cinder-volume.log* 2>/dev/null' | grep -E ' (ERROR|WARNING) ' | grep -vE '\]  ' | sort -s -k1,2 | tail -25" | cut -c1-400)
    [ -n "$L" ] && { echo "-- $N"; printf '%s\n' "$L"; }
  done
done
for h in ${HOST:-} ${SRC:-}; do
  read -r N IP USR < <(nodes "${h%%.*}")
  [ -z "${IP:-}" ] || [ "$IP" = "-" ] && { echo "== $h: no address in the inventory"; continue; }
  echo "== $h: the domain $INST, its disks and their multipath state (failed / faulty paths = the LUN is gone from this host)"
  onin "$IP" "$USR" <<NODE
c=\$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)\$')
podman exec \$c virsh -c qemu:///system domstate $INST --reason 2>&1
for d in \$(podman exec \$c virsh -c qemu:///system domblklist $INST 2>/dev/null | awk '\$2 ~ /^\/dev\// {print \$2}'); do
  echo "-- \$d"
  m=\$(command -v multipath >/dev/null && echo multipath || echo "podman exec multipathd multipath")
  \$m -ll \$d 2>&1 | head -12
  dmsetup info -c --noheadings -o name,open,attr \$d 2>&1 | head -2
done
echo "-- iSCSI / multipath messages of the kernel in the last 3 hours, last 10"
journalctl -k --since '-3 hours' --no-pager 2>/dev/null | grep -iE 'iscsi|multipath|blk_update_request|I/O error|remaining active paths' | tail -10
NODE
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

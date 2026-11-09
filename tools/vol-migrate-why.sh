#!/usr/bin/env bash
# Read-only: why does a Cinder volume migration fail (migration_status error)? The volume and the instance it is attached
# to, the swap_volume actions Nova recorded (with their events and traceback), and the lines of cinder-volume (on the
# controllers) and nova-compute (on the compute of the instance) that name the volume.
# Same path as the portal: portal service account -> management host -> director -> overcloud nodes (tripleo-admin /
# heat-admin). Only show / list / grep of logs.   Run on the bastion:  sudo bash ~/vol-migrate-why.sh <SITE> <volume ID>
set -u
SITE="${1:-}"
VID="${2:-}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$VID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || { echo "Volume ID: an OpenStack UUID"; exit 1; }
OUT="/home/deploy/vol-migrate-why-$(date +%Y%m%d-%H%M%S).txt"
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
echo "== Volume"
openstack volume show "$VID" -f json -c name -c size -c status -c migration_status -c os-vol-host-attr:host -c volume_type \
  -c bootable -c multiattach -c attachments -c os-vol-mig-status-attr:name_id -c updated_at
ATT=$(openstack volume show "$VID" -f value -c attachments)
SID=$(printf '%s' "$ATT" | grep -oE "'server_id': '[0-9a-f-]{36}'" | head -1 | grep -oE '[0-9a-f-]{36}')
echo "== Temporary copies left (migration_status target:$VID)"
cinder list --all-tenants --fields id,name,status,migration_status 2>/dev/null | grep -i "target:$VID" || echo "none"
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
if [ -n "$SID" ]; then
  echo "== Instance $SID (a volume attached to an instance is swapped by Nova: the instance must be ACTIVE, PAUSED or RESIZED)"
  openstack server show "$SID" -f json -c name -c status -c OS-EXT-STS:vm_state -c OS-EXT-STS:power_state -c OS-EXT-STS:task_state \
    -c OS-EXT-SRV-ATTR:host -c OS-EXT-SRV-ATTR:instance_name -c fault
  echo "== swap_volume actions of the instance (newest first) and the events of the last 3"
  EV=$(openstack server event list "$SID" -f value -c "Request ID" -c Action -c "Start Time" 2>&1 | awk '$2 == "swap_volume" {print $3, $1}' | sort -r)
  printf '%s\n' "$EV" | head -6
  for req in $(printf '%s\n' "$EV" | head -3 | awk '{print $2}'); do
    echo "-- $req"; openstack server event show "$SID" "$req" -f json 2>&1 | head -60
  done
  HOST=$(openstack server show "$SID" -f value -c OS-EXT-SRV-ATTR:host)
  read -r N IP USR < <(nodes "${HOST%%.*}")
  if [ -n "${IP:-}" ] && [ "$IP" != "-" ]; then
    echo "== nova-compute on $HOST: lines of the volume and errors (also the rotated logs), last 40"
    on "$IP" "$USR" "sudo sh -c 'zgrep -hE \"$VID|$SID\" /var/log/containers/nova/nova-compute.log* 2>/dev/null' | grep -E 'ERROR|WARNING|Exception|swap|Swapping|rror' | sort | tail -40" | cut -c1-500
  fi
fi
echo "== cinder-volume on the controllers: lines of the volume (also the rotated logs), last 50"
nodes controller | while read -r N IP USR; do
  [ "$IP" = "-" ] && continue
  L=$(on "$IP" "$USR" "sudo sh -c 'zgrep -hE \"$VID\" /var/log/containers/cinder/cinder-volume.log* 2>/dev/null' | sort | tail -50" | cut -c1-600)
  [ -n "$L" ] && { echo "-- $N"; printf '%s\n' "$L"; }
done
echo "== cinder-scheduler / cinder-api errors of the volume on the controllers, last 20"
nodes controller | while read -r N IP USR; do
  [ "$IP" = "-" ] && continue
  L=$(on "$IP" "$USR" "sudo sh -c 'zgrep -hE \"$VID\" /var/log/containers/cinder/cinder-scheduler.log* /var/log/containers/cinder/cinder-api.log* 2>/dev/null' | grep -E 'ERROR|WARNING|Exception|rror' | sort | tail -20" | cut -c1-600)
  [ -n "$L" ] && { echo "-- $N"; printf '%s\n' "$L"; }
done
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, volume $VID; management host $MGMT_HOST, director $DIR_USER@$DIR_HOST (keys are not printed)"
  printf 'VID=%q\nRC=%s\n%s\n' "$VID" "$RC" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1
  echo "== exit $?"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

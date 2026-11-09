#!/usr/bin/env bash
# Start a STOPPED volume-backed instance after its volume connection was repointed (bdm-refresh-safe.sh), checking first
# that the start cannot touch another instance's disk and that its ports can come up:
#   0. read-only checks (any failed one stops the script, nothing is started):
#      - the instance is stopped, no task;
#      - its BDM is iSCSI with a LUN number, and its attachment is the attached one in Cinder;
#      - its domain is not defined on its compute;
#      - the device of that LUN on the compute is used by no domain (Nova disconnects it before the start);
#      - every port is bound to its compute, without "migrating_to", and its VIF type is not unbound / failed.
#   1. after a typed START: openstack server start, then its state every 15 s (at most 10 minutes). A failed start
#      leaves it SHUTOFF (Nova sets no ERROR on start).
#   2. read-only checks after: the instance (status, power, host, fault), its ports, its domain on the compute, the
#      multipath device the domain uses (it must be the LUN of the BDM, used by no other domain), and a screenshot of
#      its console (saved on the bastion as PNG).
# Same path as the portal: portal service account -> management host -> director -> controller / compute.
# Run on the bastion:  sudo bash ~/start-after-refresh.sh <SITE> <server ID> <volume ID>
set -u
SITE="${1:-}"
SID="${2:-}"
VOL="${3:-}"
UUID_RE='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
for x in "$SID" "$VOL"; do [[ "$x" =~ $UUID_RE ]] || { echo "Usage: <SITE> <server ID> <volume ID> (UUIDs)"; exit 1; }; done
STAMP=$(date +%Y%m%d-%H%M%S)
OUT="/home/deploy/start-after-refresh-$STAMP.txt"
SHOT="/home/deploy/console-$SID-$STAMP.png"
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

LIB=$(cat <<'EOF'
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
asroot() {   # asroot <node short name>: runs stdin as root on the node
  local N IP USR
  read -r N IP USR < <(nodes "$1")
  [ -z "${IP:-}" ] || [ "$IP" = "-" ] && { echo "$1: not in the inventory"; return 1; }
  [ "$USR" = "-" ] && USR=$DEFUSR
  ssh -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$USR@$IP" "sudo -n bash -s"
}
CTL=$(nodes controller | head -1 | cut -d' ' -f1)
sql() {
  printf 'podman exec $(podman ps -q -f name=galera-bundle | head -1) mysql -N -B -e %q\n' "$1" | asroot "$CTL"
}
HOST=$(openstack server show "$SID" -f value -c OS-EXT-SRV-ATTR:host 2>/dev/null)
NODE=${HOST%%.*}
INST=$(openstack server show "$SID" -f value -c OS-EXT-SRV-ATTR:instance_name 2>/dev/null)
ROW=$(sql "SELECT attachment_id, JSON_VALUE(connection_info,'\$.driver_volume_type'), JSON_VALUE(connection_info,'\$.data.target_iqn'), JSON_VALUE(connection_info,'\$.data.target_lun') FROM nova.block_device_mapping WHERE instance_uuid='$SID' AND volume_id='$VOL' AND deleted=0" | head -1)
BATT=$(printf '%s' "$ROW" | cut -f1); BTYPE=$(printf '%s' "$ROW" | cut -f2); IQN=$(printf '%s' "$ROW" | cut -f3); LUN=$(printf '%s' "$ROW" | cut -f4)
# on the compute: the devices of LUN $LUN of target $IQN, the multipath above them, and the domains that use it
LUNCHECK=$(cat <<'NODE'
c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$')
DMS=""
for p in $(ls /dev/disk/by-path/ 2>/dev/null | grep -E -- "-$IQN-lun-$LUN\$"); do
  d=$(basename "$(readlink -f /dev/disk/by-path/$p)")
  m=$(ls /sys/block/$d/holders 2>/dev/null | head -1)
  echo "path $p -> $d${m:+ -> $m ($(cat /sys/block/$m/dm/name 2>/dev/null))}"
  DMS="$DMS $d ${m:-}"
done
[ -z "$DMS" ] && echo "no device of LUN $LUN on this compute"
for x in $(podman exec $c virsh -c qemu:///system list --name); do
  for s in $(podman exec $c virsh -c qemu:///system domblklist $x | awk '$2 ~ /^\/dev\// {print $2}'); do
    for dv in $DMS; do [ "$s" = "/dev/$dv" ] && echo "USED BY $x ($s)"; done
  done
done
NODE
)
EOF
)

PHASE0=$(cat <<'EOF'
BAD=""
echo "== Instance"
S=$(openstack --os-compute-api-version 2.9 server show "$SID" -f json 2>&1)
printf '%s' "$S" | python3 -c '
import json, sys
s = json.load(sys.stdin)
print(" ".join(f"{k}={s.get(k)}" for k in ("name", "status", "OS-EXT-STS:vm_state", "OS-EXT-STS:power_state", "OS-EXT-STS:task_state", "OS-EXT-SRV-ATTR:host", "locked")))'
VM=$(printf '%s' "$S" | python3 -c 'import json,sys; s=json.load(sys.stdin); print(s.get("OS-EXT-STS:vm_state"), s.get("OS-EXT-STS:task_state"))')
[ "$VM" = "stopped None" ] || BAD="$BAD; the instance is not stopped without a task ($VM)"
echo "== BDM: attachment $BATT, type $BTYPE, iqn $IQN, lun $LUN"
[ "$BTYPE" = "iscsi" ] && [[ "$LUN" =~ ^[0-9]+$ ]] || BAD="$BAD; the BDM is not iSCSI with a LUN number"
echo "== Cinder attachments of the volume"
CA=$(cinder --os-volume-api-version 3.27 attachment-list --all-tenants --volume-id "$VOL" 2>&1 | grep -E '^\| [0-9a-f]')
printf '%s\n' "$CA"
[ "$(printf '%s\n' "$CA" | grep -c .)" = "1" ] && printf '%s' "$CA" | grep -q "$BATT .*| attached " || BAD="$BAD; Cinder does not have exactly one attachment, the BDM one, attached"
echo "== Domain $INST on $NODE (must be absent)"
D=$(printf '%s\n' "c=\$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)\$'); podman exec \$c virsh -c qemu:///system list --all --name | grep -qx '$INST' && echo PRESENT || echo absent" | asroot "$NODE")
echo "$D"
[ "$D" = "absent" ] || BAD="$BAD; its domain is defined on $NODE"
echo "== $NODE: devices of LUN $LUN (Nova disconnects them before the start; no domain may use them)"
L=$(printf 'IQN=%q\nLUN=%q\n%s\n' "$IQN" "$LUN" "$LUNCHECK" | asroot "$NODE")
printf '%s\n' "$L"
printf '%s' "$L" | grep -q "^USED BY" && BAD="$BAD; a domain uses the device of LUN $LUN"
echo "== Ports (status, binding host, VIF type, binding profile, admin up)"
for p in $(openstack port list --server "$SID" -f value -c ID 2>/dev/null); do
  J=$(openstack port show "$p" -f json -c id -c status -c binding_host_id -c binding_vif_type -c binding_profile -c admin_state_up 2>&1)
  R=$(printf '%s' "$J" | HOST="$HOST" python3 -c '
import json, os, sys
p = json.load(sys.stdin)
prof = p.get("binding_profile") or {}
print(p.get("id"), p.get("status"), p.get("binding_host_id"), p.get("binding_vif_type"), json.dumps(prof), "admin", p.get("admin_state_up"))
bad = []
if p.get("binding_host_id") != os.environ["HOST"]: bad.append("bound to %s" % p.get("binding_host_id"))
if isinstance(prof, dict) and prof.get("migrating_to"): bad.append("migrating_to %s" % prof.get("migrating_to"))
if str(p.get("binding_vif_type")) in ("unbound", "binding_failed"): bad.append("vif %s" % p.get("binding_vif_type"))
print("PORTBAD " + ", ".join(bad) if bad else "PORTOK")')
  printf '%s\n' "$R" | head -1
  printf '%s' "$R" | grep -q "^PORTBAD" && BAD="$BAD; port $p: $(printf '%s' "$R" | grep '^PORTBAD' | cut -c9-)"
done
if [ -n "$BAD" ]; then echo; echo "NOT READY${BAD}"; else echo; echo "READY"; fi
EOF
)

PHASE1=$(cat <<'EOF'
echo "== openstack server start $SID"
openstack server start "$SID" && echo "start requested at $(date '+%T')"
for i in $(seq 1 40); do
  sleep 15
  V=$(openstack server show "$SID" -f value -c status -c OS-EXT-STS:power_state -c OS-EXT-STS:task_state 2>/dev/null | paste -sd' ')
  echo "  $(date '+%T') power_state task_state status: $V"   # -f value prints the columns sorted by name
  [[ "$V" == *" None "* && ( "$V" == *ACTIVE || ( "$V" == *SHUTOFF && $i -gt 2 ) ) ]] && break
done
EOF
)

PHASE2=$(cat <<'EOF'
echo "== Instance"
openstack server show "$SID" -f value -c status -c OS-EXT-STS:power_state -c OS-EXT-STS:task_state -c OS-EXT-SRV-ATTR:host -c fault 2>&1 | paste -sd' ' | cut -c1-600
echo "== Ports (ACTIVE expected; up to 2 minutes)"
for i in 1 2 3 4 5 6 7 8; do
  P=$(for p in $(openstack port list --server "$SID" -f value -c ID 2>/dev/null); do openstack port show "$p" -f value -c id -c status -c binding_host_id | paste -sd' '; done)
  printf '%s\n' "$P" | grep -q " DOWN " || break
  sleep 15
done
printf '%s\n' "$P"
echo "== Domain $INST on $NODE and its disks"
printf '%s\n' "c=\$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)\$'); podman exec \$c virsh -c qemu:///system domstate $INST --reason; podman exec \$c virsh -c qemu:///system domblklist $INST" | asroot "$NODE"
echo "== $NODE: devices of LUN $LUN and the domains that use them (only $INST expected)"
printf 'IQN=%q\nLUN=%q\n%s\n' "$IQN" "$LUN" "$LUNCHECK" | asroot "$NODE"
echo "== Console screenshot (60 s after the start)"
sleep 60
printf '%s\n' "c=\$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)\$'); podman exec \$c virsh -c qemu:///system screenshot $INST /tmp/shot-$SID >/dev/null 2>&1 && podman exec \$c cat /tmp/shot-$SID | base64 -w0; podman exec \$c rm -f /tmp/shot-$SID" | asroot "$NODE" | sed 's/^/SHOT /'
EOF
)

remote() {
  printf 'SID=%q\nVOL=%q\nRC=%s\n%s\n%s\n' "$SID" "$VOL" "$RC" "$LIB" "$1" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1 \
    | grep -v 'post-quantum\|store now, decrypt\|openssh.com/pq'
}

exec > >(tee "$OUT") 2>&1
echo "$(date -Is) site $SITE, instance $SID, volume $VOL"
echo "######## 0. Checks (read-only)"
R0=$(remote "$PHASE0")
printf '%s\n' "$R0"
if ! printf '%s\n' "$R0" | grep -qx "READY"; then
  echo "Not started: fix what NOT READY lists first."
  chown deploy: "$OUT" 2>/dev/null; exit 1
fi
echo
read -r -p ">>> Start the instance now? Type START to go on (anything else stops): " ans </dev/tty
[ "$ans" = "START" ] || { echo "Stopped, nothing was changed."; chown deploy: "$OUT" 2>/dev/null; exit 0; }
echo "######## 1. Start"
remote "$PHASE1"
echo "######## 2. Checks after (read-only)"
R2=$(remote "$PHASE2")
printf '%s\n' "$R2" | grep -v '^SHOT '
B64=$(printf '%s\n' "$R2" | grep '^SHOT ' | cut -c6- | tr -d '\n')
if [ -n "$B64" ]; then
  B64="$B64" "$PY" - "$SHOT" <<'PY'
import base64, os, sys
sys.path.insert(0, "/opt/ops-portal/modules/wi/wi_analysis")
data = base64.b64decode(os.environ["B64"])
try:
    import wi_ops
    data = wi_ops.to_png(data) or data
except Exception as exc:
    print("PNG conversion failed (%s): the raw screenshot is saved" % exc)
open(sys.argv[1], "wb").write(data)
print("console screenshot saved: " + sys.argv[1])
PY
  chown deploy: "$SHOT" 2>/dev/null
else
  echo "no console screenshot"
fi
chown deploy: "$OUT" 2>/dev/null
echo "Saved: $OUT"

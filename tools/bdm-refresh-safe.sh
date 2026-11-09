#!/usr/bin/env bash
# Repoint the volume connection of a STOPPED-to-be instance whose block device mapping (BDM) keeps a stale
# connection_info (a LUN number of another host), without ever disconnecting a device on its compute:
#   0. read-only checks: the instance (host, state, lock), the BDM row (must still be the stale one the operator names),
#      the Cinder attachments, no domain of it on its compute, the nova-manage refresh code installed, the connector;
#   1. backup of the BDM connection_info on the controller (root-only file, never printed: it holds the CHAP secret);
#   2. unlock + stop the instance (power off only: no volume operation; its domain does not exist on the compute);
#   3. neutralize the BDM connection_info (exactly 1 row): driver_volume_type "local", whose disconnect_volume is a no-op,
#      so the remove_volume_connection that nova-manage refresh runs first disconnects nothing on the compute;
#   4. nova-manage volume_attachment refresh with the connector of its compute: a new Cinder attachment, the LUN mapped
#      to that compute, the new connection_info saved in the BDM;
#   5. read-only checks after: the new connection_info (target, LUN; no secret), the Cinder attachments, and that the new
#      LUN number is not used by any domain on the compute. The instance is NOT started: the operator starts it.
# Every change asks for a typed confirmation first. Same path as the portal: portal service account -> management host
# -> director -> controller / compute.
# Run on the bastion:  sudo bash ~/bdm-refresh-safe.sh <SITE> <server ID> <volume ID> <stale attachment ID>
set -u
SITE="${1:-}"
SID="${2:-}"
VOL="${3:-}"
ATT="${4:-}"
UUID_RE='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
for x in "$SID" "$VOL" "$ATT"; do [[ "$x" =~ $UUID_RE ]] || { echo "Usage: <SITE> <server ID> <volume ID> <stale attachment ID> (UUIDs)"; exit 1; }; done
STAMP=$(date +%Y%m%d-%H%M%S)
OUT="/home/deploy/bdm-refresh-safe-$STAMP.txt"
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

# shared by every phase on the director: node lookup, run as root on a node, SQL on the galera container
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
sql() {   # sql "<statement>": on the galera container of the first controller, tab separated, no header
  printf 'podman exec $(podman ps -q -f name=galera-bundle | head -1) mysql -N -B -e %q\n' "$1" | asroot "$CTL"
}
HOST=$(openstack server show "$SID" -f value -c OS-EXT-SRV-ATTR:host 2>/dev/null)
NODE=${HOST%%.*}
INST=$(openstack server show "$SID" -f value -c OS-EXT-SRV-ATTR:instance_name 2>/dev/null)
BDMQ="SELECT id, attachment_id, JSON_VALUE(connection_info,'\$.driver_volume_type'), JSON_VALUE(connection_info,'\$.data.target_iqn'), JSON_VALUE(connection_info,'\$.data.target_lun'), JSON_VALUE(connection_info,'\$.data.device_path') FROM nova.block_device_mapping WHERE instance_uuid='$SID' AND volume_id='$VOL' AND deleted=0"
EOF
)

PHASE0=$(cat <<'EOF'
echo "== Instance"
openstack --os-compute-api-version 2.9 server show "$SID" -f value -c name -c status -c OS-EXT-STS:vm_state -c OS-EXT-STS:power_state -c OS-EXT-STS:task_state -c OS-EXT-SRV-ATTR:host -c locked 2>&1 | paste -sd' '
echo "== BDM row (id, attachment, type, iqn, lun, device_path; no secret)"
sql "$BDMQ"
echo "== Cinder attachments of the volume"
cinder --os-volume-api-version 3.27 attachment-list --all-tenants --volume-id "$VOL" 2>&1 | grep -E '^\| [0-9a-f]'
echo "== Domain $INST on $NODE (must not exist)"
printf '%s\n' "c=\$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)\$'); if podman exec \$c virsh -c qemu:///system list --all --name | grep -qx '$INST'; then echo \"PRESENT: \$(podman exec \$c virsh -c qemu:///system domstate $INST)\"; else echo 'absent (not defined on this compute)'; fi" | asroot "$NODE"
echo "== nova-manage volume_attachment refresh as installed on $CTL (the calls it makes, in order)"
printf '%s\n' 'P=$(podman exec nova_api python3 -c "import nova, os; print(os.path.dirname(nova.__file__))"); podman exec nova_api awk "/class VolumeAttachmentCommands/,/def refresh\\(/" $P/cmd/manage.py | grep -nE "def _|vm_state|STOPPED|locked_instance|attachment_create|remove_volume_connection|connector\\[.host.\\]|HostConflict|attachment_delete|attachment_update|bdm.connection_info =|attachment_complete"' | asroot "$CTL"
echo "== Stop and start on $NODE when the domain does not exist (installed code): handled, and no ERROR state set?"
printf '%s\n' 'podman exec nova_compute python3 -c "
import inspect, re
import nova.virt.libvirt.driver as d, nova.compute.manager as m
src = inspect.getsource(d.LibvirtDriver._clean_shutdown)
print(\"-- libvirt _clean_shutdown returns when the domain is not found:\", bool(re.search(r\"except exception.InstanceNotFound:[^\\n]*\\n(\\s*#[^\\n]*\\n)*\\s*return True\", src)))
src = inspect.getsource(d.LibvirtDriver._destroy)
print(\"-- libvirt _destroy handles a missing domain:\", \"except exception.InstanceNotFound\" in src)
for f in (\"stop_instance\", \"start_instance\", \"_power_on\"):
    src = inspect.getsource(getattr(m.ComputeManager, f))
    print(\"-- compute manager\", f, \"lines that set the ERROR state (0 expected):\", len(re.findall(r\"_set_instance_obj_error_state|vm_states.ERROR\", src)))
"' | asroot "$NODE"
echo "== Connector of $NODE (nova-manage volume_attachment get_connector; host and initiator only)"
printf '%s\n' 'podman exec -u root nova_compute nova-manage volume_attachment get_connector --json 2>/dev/null | python3 -c "import json,sys; c=json.load(sys.stdin); print(\"host\", c.get(\"host\"), \"initiator\", c.get(\"initiator\"), \"multipath\", c.get(\"multipath\"))"' | asroot "$NODE"
EOF
)

PHASE1=$(cat <<'EOF'
echo "== Backup of the BDM connection_info on $CTL: /root/bdm-$SID-$STAMP.json (root only, not printed)"
printf '%s\n' "umask 077; podman exec \$(podman ps -q -f name=galera-bundle | head -1) mysql -N -B -e \"SELECT id, attachment_id, connection_info FROM nova.block_device_mapping WHERE instance_uuid='$SID' AND volume_id='$VOL' AND deleted=0\" > /root/bdm-$SID-$STAMP.json && chmod 600 /root/bdm-$SID-$STAMP.json && wc -c /root/bdm-$SID-$STAMP.json" | asroot "$CTL"
echo "== Unlock and stop $SID"
openstack server unlock "$SID" && echo "unlocked"
openstack server stop "$SID" && echo "stop requested"
for i in $(seq 1 30); do
  S=$(openstack server show "$SID" -f value -c OS-EXT-STS:vm_state -c OS-EXT-STS:task_state 2>/dev/null | paste -sd' ')
  echo "  vm_state task_state: $S"
  [[ "$S" == *stopped* && "$S" == *None* ]] && break   # -f value prints the columns sorted by name
  sleep 10
done
EOF
)

PHASE2=$(cat <<'EOF'
echo "== Neutralize the BDM connection_info (exactly 1 row: this instance, this volume, attachment $ATT)"
NEW="{\"driver_volume_type\": \"local\", \"data\": {}, \"serial\": \"$VOL\"}"
sql "UPDATE nova.block_device_mapping SET connection_info='$NEW' WHERE instance_uuid='$SID' AND volume_id='$VOL' AND attachment_id='$ATT' AND deleted=0 LIMIT 1; SELECT ROW_COUNT();"
sql "$BDMQ"
EOF
)

PHASE3=$(cat <<'EOF'
echo "== nova-manage volume_attachment refresh $SID $VOL with the connector of $NODE"
S=$(openstack --os-compute-api-version 2.9 server show "$SID" -f value -c OS-EXT-STS:vm_state -c locked 2>/dev/null | paste -sd' ')
if [[ "$S" == *stopped* && "$S" == *True* ]]; then
  openstack server unlock "$SID" && echo "unlocked (a lock left by an earlier refresh attempt)"
  S=$(openstack --os-compute-api-version 2.9 server show "$SID" -f value -c OS-EXT-STS:vm_state -c locked 2>/dev/null | paste -sd' ')
fi
[[ "$S" == *stopped* && "$S" == *False* ]] || { echo "the instance must be stopped and unlocked (now: $S): stop"; exit 1; }
CONN=$(printf '%s\n' "podman exec -u root nova_compute nova-manage volume_attachment get_connector --json 2>/dev/null" | asroot "$NODE")
CHOST=$(printf '%s' "$CONN" | python3 -c "import json,sys; print(json.load(sys.stdin).get('host') or '')" 2>/dev/null)
[ -n "$CHOST" ] && [ "$CHOST" = "$HOST" ] || { echo "connector host '$CHOST' is not the instance host '$HOST': stop"; exit 1; }
echo "connector host $CHOST"
D=$(printf '%s\n' "c=\$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)\$'); if podman exec \$c virsh -c qemu:///system list --all --name | grep -qx '$INST'; then echo \"PRESENT: \$(podman exec \$c virsh -c qemu:///system domstate $INST)\"; else echo 'absent (not defined on this compute)'; fi" | asroot "$NODE")
echo "domain $INST on $NODE: $D"
[[ "$D" == absent* ]] || { echo "the domain exists on $NODE: stop"; exit 1; }
# nova-manage runs with an admin context without a token: its Cinder calls need [cinder] auth options, which nova.conf
# of nova_api does not have ("Unknown auth type: None"). They are taken from its [keystone_authtoken] (the nova service
# user) into a root-only file inside the container for this one command, then deleted; the password is never printed.
ONCTL=$(cat <<'NODE'
umask 077
printf '%s\n' "$CONN" > /tmp/connector-$SID.json
podman cp /tmp/connector-$SID.json nova_api:/tmp/connector-$SID.json
podman exec -i -u root -e SID="$SID" nova_api python3 - <<'PY'
import configparser, os
c = configparser.RawConfigParser(strict=False, interpolation=None)
c.read("/etc/nova/nova.conf")
keys = [k for k in ("auth_url", "username", "password", "project_name", "user_domain_name", "project_domain_name")
        if c.has_option("keystone_authtoken", k)]
os.umask(0o077)
with open("/tmp/cinder-auth-%s.conf" % os.environ["SID"], "w") as f:
    f.write("[cinder]\nauth_type = password\n")
    for k in keys:
        f.write("%s = %s\n" % (k, c.get("keystone_authtoken", k)))
print("[cinder] auth for this command from [keystone_authtoken]:", ", ".join(keys))
PY
podman exec -u root nova_api nova-manage --config-file /etc/nova/nova.conf --config-file /tmp/cinder-auth-$SID.conf \
  volume_attachment refresh "$SID" "$VOL" /tmp/connector-$SID.json
echo "refresh exit $?"
podman exec -u root nova_api rm -f /tmp/cinder-auth-$SID.conf /tmp/connector-$SID.json
rm -f /tmp/connector-$SID.json
echo "temporary files removed"
NODE
)
printf 'SID=%q\nVOL=%q\nCONN=%q\n%s\n' "$SID" "$VOL" "$CONN" "$ONCTL" | asroot "$CTL"
EOF
)

PHASE4=$(cat <<'EOF'
echo "== After: BDM row (id, attachment, type, iqn, lun, device_path; no secret)"
ROW=$(sql "$BDMQ")
printf '%s\n' "$ROW"
IQN=$(printf '%s\n' "$ROW" | head -1 | cut -f4)
LUN=$(printf '%s\n' "$ROW" | head -1 | cut -f5)
echo "== Cinder attachments of the volume"
cinder --os-volume-api-version 3.27 attachment-list --all-tenants --volume-id "$VOL" 2>&1 | grep -E '^\| [0-9a-f]'
if [[ "$LUN" =~ ^[0-9]+$ ]]; then
  echo "== $NODE: LUN $LUN of the target, and any running domain that uses it (must be none before the start)"
  printf '%s\n' "ls -l /dev/disk/by-path/ 2>/dev/null | grep -E '$IQN-lun-$LUN( |\$)' | awk '{print \$9, \$11}'
c=\$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)\$')
for p in \$(ls /dev/disk/by-path/ 2>/dev/null | grep -E '$IQN-lun-$LUN\$'); do
  d=\$(readlink -f /dev/disk/by-path/\$p); m=\$(ls /sys/block/\$(basename \$d)/holders 2>/dev/null)
  for x in \$(podman exec \$c virsh -c qemu:///system list --name); do
    podman exec \$c virsh -c qemu:///system domblklist \$x | grep -qE \"(\$d|/dev/\${m:-none})\\\$\" && echo \"USED BY \$x\"
  done
done
echo 'domain check done'" | asroot "$NODE"
else
  echo "the BDM has no LUN number: look at the refresh output above"
fi
echo
echo "Not started. When the above is right: openstack server start $SID"
EOF
)

STATEQ=$(cat <<'EOF'
T=$(sql "SELECT JSON_VALUE(connection_info,'\$.driver_volume_type') FROM nova.block_device_mapping WHERE instance_uuid='$SID' AND volume_id='$VOL' AND deleted=0" | head -1)
S=$(openstack server show "$SID" -f value -c OS-EXT-STS:vm_state 2>/dev/null)
echo "STATE $T $S"
EOF
)

remote() {   # remote <phase script>: runs LIB + the phase on the director
  printf 'SID=%q\nVOL=%q\nATT=%q\nSTAMP=%q\nRC=%s\n%s\n%s\n' "$SID" "$VOL" "$ATT" "$STAMP" "$RC" "$LIB" "$1" \
    | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
      "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1 | grep -v 'post-quantum\|store now, decrypt\|openssh.com/pq'
}
confirm() {   # confirm <word> <what>
  echo
  read -r -p ">>> $2 Type $1 to go on (anything else stops): " ans </dev/tty
  [ "$ans" = "$1" ] || { echo "Stopped, nothing more was changed."; exit 0; }
}

exec > >(tee "$OUT") 2>&1
echo "$(date -Is) site $SITE, instance $SID, volume $VOL, stale attachment $ATT"
echo "######## 0. Checks (read-only)"
remote "$PHASE0"
ST=$(remote "$STATEQ" | grep '^STATE ' | tail -1)
if [ "$ST" = "STATE local stopped" ]; then
  echo
  echo "Steps 1 and 2 were done before: the instance is stopped and its BDM connection_info is neutral (local). Going on with step 3."
else
  confirm BACKUP "Step 1: backup the BDM connection_info (root-only file on the controller), unlock and STOP the instance (power off only)."
  remote "$PHASE1"
  confirm NEUTRALIZE "Step 2: set the BDM connection_info of this instance/volume/attachment to driver_volume_type local (1 row)."
  remote "$PHASE2"
fi
confirm REFRESH "Step 3: nova-manage volume_attachment refresh (new attachment and LUN mapping for its compute)."
remote "$PHASE3"
echo "######## 4. Checks after (read-only)"
remote "$PHASE4"
chown deploy: "$OUT" 2>/dev/null
echo "Saved: $OUT"

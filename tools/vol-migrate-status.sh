#!/usr/bin/env bash
# Read-only: how far a Cinder volume migration is (Operation Automation fix "Migrate volumes"), on one site.
# Same path as the portal: portal service account -> management host -> director (overcloudrc / stackrc) -> the compute
# of the instance (tripleo-admin / heat-admin, as TripleO; ssh -n so it never reads the rest of the script). Only show / list / grep / virsh info commands.
# Run on the bastion:  sudo bash ~/vol-migrate-status.sh <SITE> <volume ID>
set -u
SITE="${1:-}"
VID="${2:-}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$VID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || { echo "Volume ID: an OpenStack UUID"; exit 1; }
OUT="/home/deploy/vol-migrate-$(date +%Y%m%d-%H%M%S).txt"
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

# The script that runs on the director (quoted: nothing is expanded here; VID and RC come first).
REMOTE=$(cat <<'EOF'
set -u
source $RC >/dev/null 2>&1 || { echo "source $RC failed"; exit 1; }
echo "== RHOSP release"; cat /etc/rhosp-release 2>/dev/null
echo "== Volume (status, migration_status, host now)"
openstack volume show "$VID" -f json -c id -c name -c size -c status -c migration_status -c os-vol-host-attr:host \
  -c os-vol-mig-status-attr:name_id -c attachments -c updated_at
ATT=$(openstack volume show "$VID" -f value -c attachments)
SID=$(printf '%s' "$ATT" | grep -oE "'server_id': '[0-9a-f-]{36}'" | head -1 | grep -oE '[0-9a-f-]{36}')
DEV=$(printf '%s' "$ATT" | grep -oE "'device': '/dev/[a-z]+'" | head -1 | grep -oE '/dev/[a-z]+')
echo "== Volumes being migrated now (the temporary copy has migration_status target:<source>)"
cinder list --all-tenants --fields id,name,status,migration_status,host 2>/dev/null | grep -iE "migrat|target:" | head -20
echo "== Cinder messages of the volume"
cinder --os-volume-api-version 3.3 message-list --resource_uuid "$VID" 2>/dev/null | grep -E "^\+|Resource UUID|$VID" | head -12
[ -n "$SID" ] || { echo "== The volume is not attached: no compute copies it"; exit 0; }
echo "== Instance $SID (device ${DEV:-?})"
openstack server show "$SID" -f json -c id -c name -c status -c OS-EXT-STS:vm_state -c OS-EXT-STS:power_state \
  -c OS-EXT-STS:task_state -c OS-EXT-SRV-ATTR:host -c OS-EXT-SRV-ATTR:instance_name -c fault -c updated
echo "== Console log of the instance: errors in the last 400 lines (I/O, filesystem, hung tasks, panic)"
LOG=$(openstack console log show "$SID" --lines 400 2>&1)
if [ -z "$LOG" ]; then echo "(empty: the guest writes nothing to the serial console, e.g. Windows; see the screenshot)"
else
  printf '%s\n' "$LOG" | grep -inE 'i/o error|blk_update_request|buffer i/o|ext4-fs error|xfs .*(error|corrupt)|read-only file system|blocked for more than|soft lockup|hung_task|kernel panic|call trace|oops|out of memory|segfault' | tail -20 || true
  [ -n "$(printf '%s\n' "$LOG" | grep -icE 'i/o error|blk_update_request|ext4-fs error|blocked for more than|soft lockup|kernel panic|call trace')" ] || echo "no error lines"
  echo "-- last 25 lines of the console log:"; printf '%s\n' "$LOG" | tail -25
fi
HOST=$(openstack server show "$SID" -f value -c OS-EXT-SRV-ATTR:host)
INST=$(openstack server show "$SID" -f value -c OS-EXT-SRV-ATTR:instance_name)
SHORT=${HOST%%.*}
# The ctlplane address and the SSH user of the compute, from the TripleO Ansible inventory (only these two values).
INV=$(ls ~/overcloud-deploy/*/tripleo-ansible-inventory.yaml ~/config-download/*/tripleo-ansible-inventory.yaml \
  ~/tripleo-ansible-inventory.yaml 2>/dev/null | head -1)
read -r IP USR < <(python3 - "$SHORT" "$INV" <<'PY'
import sys, yaml
want, path = sys.argv[1].lower(), sys.argv[2]
try:
    inv = yaml.safe_load(open(path)) or {}
except Exception:
    inv = {}
for body in inv.values():
    for host, hv in ((body or {}).get("hosts") or {}).items() if isinstance(body, dict) else []:
        if host.split(".")[0].lower() == want and isinstance(hv, dict):
            print(hv.get("ctlplane_ip") or hv.get("ansible_host") or "-", hv.get("ansible_ssh_user") or "-")
            sys.exit()
print("- -")
PY
)
if [ "${IP:--}" = "-" ]; then echo "== Compute $HOST: its ctlplane address is not in the TripleO inventory ($INV)"; exit 0; fi
[ "${USR:--}" = "-" ] && { grep -q '17\.' /etc/rhosp-release && USR=tripleo-admin || USR=heat-admin; }
NODE=(ssh -n -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$USR@$IP")
echo "== Compute $HOST ($IP, $USR): the copy of an attached volume runs here (Nova swap volume = libvirt block copy)"
C=$("${NODE[@]}" "sudo podman ps --format '{{.Names}}'" 2>/dev/null | grep -E '^nova_(virtqemud|libvirt)$' | head -1)
echo "libvirt container: ${C:-not found}"
if [ -n "$C" ]; then
  "${NODE[@]}" "sudo podman exec $C virsh domblklist $INST" 2>&1
  for d in $("${NODE[@]}" "sudo podman exec $C virsh domblklist $INST" 2>/dev/null | awk 'NR>2 && $1 ~ /^[sv]d[a-z]+$/ {print $1}'); do
    echo "-- block job on $d:"; "${NODE[@]}" "sudo podman exec $C virsh blockjob $INST $d --info" 2>&1
  done
  echo "-- domain state and disk errors:"
  "${NODE[@]}" "sudo podman exec $C virsh domstate $INST --reason; sudo podman exec $C virsh domblkerror $INST" 2>&1
  # What the console (VNC / Horizon) shows now: a screenshot of the display, copied out as base64 (nothing changes in the VM)
  echo "@@SHOT-BEGIN $INST"
  "${NODE[@]}" "sudo podman exec $C virsh screenshot $INST /tmp/wi-shot-$INST.ppm >/dev/null && sudo podman exec $C cat /tmp/wi-shot-$INST.ppm | base64; sudo podman exec $C rm -f /tmp/wi-shot-$INST.ppm" 2>/dev/null
  echo "@@SHOT-END"
fi
echo "== nova-compute log lines of the volume (last 15)"
"${NODE[@]}" "sudo grep -h $VID /var/log/containers/nova/nova-compute.log | tail -15" 2>&1
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, volume $VID; management host $MGMT_HOST, director $DIR_USER@$DIR_HOST (keys are not printed)"
  printf 'VID=%q\nRC=%s\n%s\n' "$VID" "$RC" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1
  echo "== exit $?"
} | awk -v shot="/home/deploy/vm-console-$(date +%Y%m%d-%H%M%S)" '
  /^@@SHOT-BEGIN / {f = shot "-" $2 ".ppm.b64"; on = 1; next}
  /^@@SHOT-END/ {if (on) {close(f); print "console screenshot: " f}; on = 0; next}
  on {print > f; next}
  {print}' | tee "$OUT"
chown deploy: "$OUT"
for b in /home/deploy/vm-console-*.ppm.b64; do
  [ -s "$b" ] && base64 -d "$b" > "${b%.b64}" 2>/dev/null && chown deploy: "${b%.b64}" && echo "Screenshot: ${b%.b64}"
  rm -f "$b"
done
echo "Saved: $OUT"

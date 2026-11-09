#!/usr/bin/env bash
# Read-only: when did an instance last boot, and did anything happen to it around a change (volume swap, migration)?
# Same path as the portal: portal service account -> management host -> director (overcloudrc) -> its compute
# (tripleo-admin / heat-admin). Only show / list / ps / virsh info / grep of logs.
# Run on the bastion:  sudo bash ~/vm-boot-evidence.sh <SITE> <server ID>
set -u
SITE="${1:-}"
SID="${2:-}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$SID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || { echo "Server ID: an OpenStack UUID"; exit 1; }
OUT="/home/deploy/vm-boot-$(date +%Y%m%d-%H%M%S).txt"
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
openstack server show "$SID" -f json -c name -c status -c OS-EXT-STS:power_state -c OS-EXT-SRV-ATTR:host \
  -c OS-EXT-SRV-ATTR:instance_name -c created -c updated -c OS-SRV-USG:launched_at
echo "== Actions Nova recorded for it (newest first: reboot, stop / start, migration, swap volume...)"
EV=$(openstack server event list "$SID" -f value -c "Request ID" -c Action -c "Start Time" 2>&1 | awk '{print $3, $2, $1}' | sort -r)
echo "$(printf '%s\n' "$EV" | grep -c ' createImage ') createImage (backups); the other actions, newest first:"
printf '%s\n' "$EV" | grep -v ' createImage ' | head -20
HOST=$(openstack server show "$SID" -f value -c OS-EXT-SRV-ATTR:host)
INST=$(openstack server show "$SID" -f value -c OS-EXT-SRV-ATTR:instance_name)
VOLS=$(openstack server show "$SID" -f value -c volumes_attached | grep -oE '[0-9a-f-]{36}' | tr '\n' ' ')
echo "volumes: $VOLS"
SHORT=${HOST%%.*}
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
[ "${IP:--}" = "-" ] && { echo "== $HOST: not in the TripleO inventory"; exit 0; }
[ "${USR:--}" = "-" ] && { grep -q '17\.' /etc/rhosp-release && USR=tripleo-admin || USR=heat-admin; }
NODE=(ssh -n -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$USR@$IP")
echo "== Compute $HOST ($IP): the QEMU process of $INST (started = when the domain started or came in by live migration)"
"${NODE[@]}" "P=\$(pgrep -f 'guest=$INST,' | head -1); [ -n \"\$P\" ] && ps -o pid,lstart,etime,time,pcpu -p \$P || echo 'no QEMU process'"
C=$("${NODE[@]}" "sudo podman ps --format '{{.Names}}'" | grep -E '^nova_(virtqemud|libvirt)$' | head -1)
echo "== CPU time, disk and network since the QEMU process started (a server at an emergency prompt does almost nothing)"
"${NODE[@]}" "sudo podman exec $C virsh domstats $INST --state --cpu-total --block --interface" 2>&1 \
  | grep -E 'state\.|cpu\.time|block\.[0-9]+\.(name|rd\.bytes|wr\.bytes|errors)|net\.[0-9]+\.(rx|tx)\.bytes'
echo "== libvirt log of the domain (starts, stops, block jobs)"
"${NODE[@]}" "sudo tail -n 25 /var/log/containers/libvirt/qemu/$INST.log 2>/dev/null || sudo tail -n 25 /var/log/libvirt/qemu/$INST.log" 2>&1 | cut -c1-300
echo "== nova-compute log lines of the instance and its volumes (also the rotated logs), last 40"
PAT="$SID"; for v in $VOLS; do PAT="$PAT|$v"; done
"${NODE[@]}" "sudo sh -c 'zgrep -hE \"$PAT\" /var/log/containers/nova/nova-compute.log* 2>/dev/null' | grep -vE 'DEBUG' | sort | tail -40" 2>&1 | cut -c1-400
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

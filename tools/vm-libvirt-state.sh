#!/usr/bin/env bash
# Read-only: does libvirt still control the QEMU of an instance on its compute? For "cannot acquire state change lock
# (held by monitor=init-<instance>)": the init-<instance> thread is the one virtqemud starts to reconnect to a running
# QEMU after it (re)starts; it holds the lock until QEMU answers. Shows when the libvirt containers started, the state of
# the QEMU process and its threads (D = waiting on I/O), its qemu log, the libvirt log lines of the instance, the kernel
# messages about blocked tasks or storage, and the other running domains of the compute (does the same happen to them?).
# Same path as the portal: portal service account -> management host -> director -> the compute (tripleo-admin /
# heat-admin). Only ps / ls / tail / grep / virsh domstate / virsh list.
# Run on the bastion:  sudo bash ~/vm-libvirt-state.sh <SITE> <compute short name> <instance-xxxxxxxx>
set -u
SITE="${1:-}"
NODE="${2:-}"
INST="${3:-}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$NODE" =~ ^[a-z0-9-]{1,63}$ ]] || { echo "Compute: its short name, e.g. dcbrhosp-compute-0"; exit 1; }
[[ "$INST" =~ ^instance-[0-9a-f]{8}$ ]] || { echo "Instance: instance-xxxxxxxx (OS-EXT-SRV-ATTR:instance_name)"; exit 1; }
OUT="/home/deploy/vm-libvirt-state-$(date +%Y%m%d-%H%M%S).txt"
SVC=opsportal
PY=/opt/ops-portal/.venv/bin/python

read -r MGMT_HOST MGMT_PORT MGMT_USER MGMT_KEY DIR_HOST DIR_USER DIR_PORT < <("$PY" - "$SITE" <<'EOF'
import sys, yaml
c = yaml.safe_load(open("/etc/ops-portal/sites.yml"))["sites"][sys.argv[1]]
m, d = c.get("mgmt") or {}, c.get("director") or {}
print(m.get("host", "-"), m.get("port", 22), m.get("user") or "-", m.get("private_key") or "-",
      d.get("host", "-"), d.get("user") or "stack", d.get("port", 22))
EOF
)
OPTS=(-o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new -p "$MGMT_PORT")
[ "$MGMT_KEY" != "-" ] && OPTS+=(-i "$MGMT_KEY")
TARGET="$MGMT_HOST"
[ "$MGMT_USER" != "-" ] && TARGET="$MGMT_USER@$MGMT_HOST"

# runs on the compute (as root through sudo); $INST is set before it
ONNODE=$(cat <<'EOF'
set -u
V="podman exec $(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$') virsh -c qemu:///system"
echo "== now on the node: $(date '+%F %T %Z')"
echo "== libvirt / nova containers: status and start time (a restart of virtqemud reconnects to every running QEMU)"
podman ps -a --format '{{.Names}}' | grep -E '^nova_(virt|libvirt|compute)' | while read -r c; do
  echo "$c $(podman inspect -f '{{.State.Status}} started {{.State.StartedAt}} restarts {{.RestartCount}}' "$c")"
done
echo "== virsh domstate --reason $INST (no lock needed)"
$V domstate "$INST" --reason 2>&1
echo "== QEMU process of $INST: state, run time, where it waits"
PID=$(pgrep -f "guest=$INST," | head -1)
if [ -n "$PID" ]; then
  ps -o pid,stat,lstart,etime,pcpu,rss,wchan:32 -p "$PID"
  echo "-- its threads not running or sleeping normally (D = waiting on I/O, uninterruptible)"
  ps -L -o tid,stat,wchan:32,comm -p "$PID" | awk 'NR == 1 || $2 ~ /D|Z|T/'
  echo "-- threads: $(ls /proc/$PID/task | wc -l); kernel stack of the main thread:"
  cat /proc/$PID/stack 2>/dev/null | head -12
else
  echo "no QEMU process for $INST"
fi
echo "== qemu log of $INST"
ls -l /var/log/containers/libvirt/qemu/$INST.log* 2>&1
tail -30 /var/log/containers/libvirt/qemu/$INST.log 2>/dev/null
echo "== libvirt logs: files, then lines of $INST (last 40)"
ls -l /var/log/containers/libvirt/ 2>&1 | head -20
zgrep -h "$INST" /var/log/containers/libvirt/virtqemud.log* /var/log/containers/libvirt/libvirtd.log* 2>/dev/null | tail -40 | cut -c1-400
echo "== kernel: blocked tasks, I/O errors, iSCSI / multipath / NFS (last 25)"
dmesg -T 2>/dev/null | grep -iE "blocked for more than|hung_task|I/O error|blk_update_request|multipath|iscsi|connection.*(failed|timed out)|nfs: server" | tail -25
echo "== other running domains of this compute and the state of their QEMU (D = waiting on I/O)"
$V list --name 2>&1 | while read -r d; do
  [ -z "$d" ] && continue
  p=$(pgrep -f "guest=$d," | head -1)
  echo "$d pid ${p:--} $( [ -n "$p" ] && ps -o stat=,etime= -p "$p") D-threads $( [ -n "$p" ] && ps -L -o stat= -p "$p" | grep -c D)"
done
EOF
)

REMOTE=$(cat <<'EOF'
set -u
INV=$(ls ~/overcloud-deploy/*/tripleo-ansible-inventory.yaml ~/config-download/*/tripleo-ansible-inventory.yaml \
  ~/tripleo-ansible-inventory.yaml 2>/dev/null | head -1)
read -r IP USR < <(python3 - "$NODE" "$INV" <<'PY'
import sys, yaml
want, path = sys.argv[1].lower(), sys.argv[2]
try:
    inv = yaml.safe_load(open(path)) or {}
except Exception:
    inv = {}
for group, body in inv.items():
    for host, hv in ((body or {}).get("hosts") or {}).items() if isinstance(body, dict) else []:
        if host.split(".")[0].lower() == want and isinstance(hv, dict):
            print(hv.get("ctlplane_ip") or hv.get("ansible_host") or "-", hv.get("ansible_ssh_user") or "-")
            raise SystemExit
print("- -")
PY
)
[ "$IP" = "-" ] && { echo "$NODE: not in the inventory $INV"; exit 1; }
[ "$USR" = "-" ] && USR=$(grep -q '17\.' /etc/rhosp-release && echo tripleo-admin || echo heat-admin)
echo "Compute $NODE: $USR@$IP"
printf 'INST=%q\n%s\n' "$INST" "$ONNODE" | ssh -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$USR@$IP" "sudo -n bash -s"
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, compute $NODE, $INST; management host $MGMT_HOST, director $DIR_USER@$DIR_HOST (keys are not printed)"
  printf 'NODE=%q\nINST=%q\nONNODE=%q\n%s\n' "$NODE" "$INST" "$ONNODE" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1
  echo "== exit $?"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

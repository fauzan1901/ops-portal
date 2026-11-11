#!/usr/bin/env bash
# Read-only: did a migration rollback (or any volume disconnect) touch a disk on a compute in a time window? The
# kernel messages of the window about SCSI / multipath / block I/O (devices removed, paths failed, I/O errors), the
# multipath devices that have failed or faulty paths now, and for every dm device named in those messages the domain
# that uses it now (a running VM whose disk lost paths or got I/O errors).
# Same path as the portal: portal service account -> management host -> director -> the computes.
# Run on the bastion:  sudo bash ~/kernel-window.sh <SITE> "<from YYYY-MM-DD HH:MM>" "<to YYYY-MM-DD HH:MM>" <compute>...
set -u
SITE="${1:-}"
FROM="${2:-}"
TO="${3:-}"
shift 3 2>/dev/null
NODES="$*"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
TS_RE='^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}$'
[[ "$FROM" =~ $TS_RE && "$TO" =~ $TS_RE ]] || { echo "Times: \"YYYY-MM-DD HH:MM\" (WIB, the compute's time)"; exit 1; }
[[ "$NODES" =~ ^[a-z0-9-]+( [a-z0-9-]+)*$ ]] || { echo "Computes: short names, e.g. dccrhosp-compute-1"; exit 1; }
OUT="/home/deploy/kernel-window-$(date +%Y%m%d-%H%M%S).txt"
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

ONNODE=$(cat <<'NODE'
c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$')
V="podman exec $c virsh -c qemu:///system"
echo "== $(hostname -s), now $(date '+%F %T %Z'); window $FROM .. $TO"
K=$(journalctl -k --since "$FROM" --until "$TO" --no-pager 2>/dev/null | grep -iE "I/O error|blk_update_request|Buffer I/O|Synchronizing SCSI cache|detach|remaining active paths|Fail(ing)? (all )?path|failed path|queue_if_no_path|multipath|device-mapper|sd [0-9:]+: \[sd[a-z]+\] (Attached|Stopping|Synchronizing)|EXT4-fs|XFS")
echo "-- kernel messages about disks in the window: $(printf '%s' "$K" | grep -c .) line(s), last 40"
printf '%s\n' "$K" | tail -40 | cut -c1-220
echo "-- dm devices named in them, and the running domain that uses each now"
for dm in $(printf '%s\n' "$K" | grep -oE "dm-[0-9]+" | sort -u); do
  users=""
  for x in $($V list --name); do $V domblklist $x 2>/dev/null | awk '{print $2}' | grep -qx "/dev/$dm" && users="$users $x"; done
  echo "$dm ($(cat /sys/block/$dm/dm/name 2>/dev/null || echo 'gone')): used by${users:- nothing}"
done
echo "-- multipath devices with failed / faulty paths now"
MP=$(command -v multipath >/dev/null && echo multipath || echo "podman exec multipathd multipath")
$MP -ll 2>/dev/null | awk '/^[0-9a-f]{33} dm-/{m=$1" "$2} /failed|faulty|offline/{print m": "$0}' | head -20
echo "-- running domains: $($V list --name | grep -c .)"
NODE
)

REMOTE=$(cat <<'EOF'
INV=$(ls ~/overcloud-deploy/*/tripleo-ansible-inventory.yaml ~/config-download/*/tripleo-ansible-inventory.yaml \
  ~/tripleo-ansible-inventory.yaml 2>/dev/null | head -1)
for NODE in $NODES; do
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
  echo
  [ "$IP" = "-" ] && { echo "$NODE: not in the inventory $INV"; continue; }
  [ "$USR" = "-" ] && USR=$(grep -q '17\.' /etc/rhosp-release && echo tripleo-admin || echo heat-admin)
  echo "######## $NODE ($USR@$IP)"
  printf 'FROM=%q\nTO=%q\n%s\n' "$FROM" "$TO" "$ONNODE" | ssh -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$USR@$IP" "sudo -n bash -s"
done
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, window $FROM .. $TO, computes $NODES; management host $MGMT_HOST, director $DIR_USER@$DIR_HOST (keys are not printed)"
  printf 'FROM=%q\nTO=%q\nNODES=%q\nONNODE=%q\n%s\n' "$FROM" "$TO" "$NODES" "$ONNODE" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1 | grep -v 'post-quantum\|store now, decrypt\|openssh.com/pq'
  echo "== exit $?"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

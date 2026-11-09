#!/usr/bin/env bash
# Read-only: why a live migration fails with "DestinationDiskExists(path=instance_dir)". Nova (libvirt driver,
# pre_live_migration) refuses when /var/lib/nova/instances/<uuid> already exists on the destination and the instances
# path is not shared: usually a directory left over by an earlier migration of the instance. Before such a directory is
# moved aside, it must be sure that it is NOT the live directory of the instance (shared storage between the computes)
# and that no domain of the instance runs there. Shows, per compute given (the source first): the mount of the
# instances path, the directory of the instance (inode, files, times), a domain with its UUID in libvirt, and the
# nova-compute lines of the instance about directories and migrations.
# Same path as the portal: portal service account -> management host -> director -> the computes.
# Run on the bastion:  sudo bash ~/dest-disk-exists.sh <SITE> <server ID> <source compute> <destination compute>... [req-...]
# (request IDs of the failed attempts, optional: all their nova-compute lines are shown)
set -u
SITE="${1:-}"
SID="${2:-}"
shift 2 2>/dev/null
NODES=""
REQ=""
for x in "$@"; do
  if [[ "$x" =~ ^req-[0-9a-f-]{36}$ ]]; then REQ="${REQ:+$REQ }$x"; else NODES="${NODES:+$NODES }$x"; fi
done
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$SID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || { echo "Server ID: the UUID of the instance"; exit 1; }
[[ "$NODES" =~ ^[a-z0-9-]+( [a-z0-9-]+)*$ ]] || { echo "Computes: short names, the source first, e.g. dccrhosp-compute-2 dccrhosp-compute-1"; exit 1; }
OUT="/home/deploy/dest-disk-exists-$(date +%Y%m%d-%H%M%S).txt"
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

# runs on each compute (as root through sudo); $SID is set before it
ONNODE=$(cat <<'EOF'
set -u
D=/var/lib/nova/instances/$SID
V="podman exec $(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$') virsh -c qemu:///system"
echo "== $(hostname -s), now $(date '+%F %T %Z')"
echo "-- instances_path in nova.conf (empty: the default /var/lib/nova/instances)"
grep -hE '^\s*instances_path\s*=' /var/lib/config-data/puppet-generated/nova_libvirt/etc/nova/nova.conf \
  /var/lib/config-data/puppet-generated/nova/etc/nova/nova.conf 2>/dev/null | sort -u
echo "-- mount of /var/lib/nova/instances (nfs / ceph / gluster: shared between the computes)"
findmnt -T /var/lib/nova/instances -o TARGET,SOURCE,FSTYPE,OPTIONS 2>&1 | cut -c1-200
echo "-- the directory of the instance"
if [ -e "$D" ]; then
  stat -c '%n  inode %i  device %d  owner %U:%G  changed %z' "$D"
  ls -la --time-style=+%F_%T "$D" 2>&1 | head -20
  echo "size: $(du -sh "$D" 2>/dev/null | cut -f1)"
else
  echo "$D does not exist"
fi
ls -d /var/lib/nova/instances/${SID}_* 2>/dev/null | sed 's/^/also: /'
echo "-- what nova-compute itself sees (inside its container; it checks the directory there)"
podman inspect nova_compute --format '{{range .Mounts}}{{.Source}} -> {{.Destination}}{{println}}{{end}}' 2>&1 | grep -E 'nova' | head -5
podman exec nova_compute sh -c "ls -ld --time-style=+%F_%T /var/lib/nova/instances/$SID* 2>&1; echo \"entries: \$(ls /var/lib/nova/instances | wc -l)\"" 2>&1
echo "entries on the node: $(ls /var/lib/nova/instances | wc -l)"
echo "-- a libvirt domain with this UUID here (none: it does not run here)"
$V dominfo "$SID" 2>&1 | grep -E '^(Name|UUID|State)|error' | head -4
echo "-- nova-compute about this instance: directories, migrations, cleanup (last 25)"
zgrep -h "$SID" /var/log/containers/nova/nova-compute.log* 2>/dev/null \
  | grep -iE "DestinationDiskExists|instance directory|Deleting instance files|Deletion of .* complete|live.?migrat|pre_live|rollback|post_live|cleanup|Migrating instance" \
  | sort -s -k1,2 | tail -25 | cut -c1-330
if [ -n "${REQ:-}" ]; then
  echo "-- every nova-compute line of the requests $REQ (no traceback, last 30)"
  zgrep -hE "$(echo "$REQ" | tr ' ' '|')" /var/log/containers/nova/nova-compute.log* 2>/dev/null | grep -vE '\]  ' \
    | sort -s -k1,2 | tail -30 | cut -c1-330
fi
EOF
)

REMOTE=$(cat <<'EOF'
set -u
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
  printf 'SID=%q\nREQ=%q\n%s\n' "$SID" "$REQ" "$ONNODE" | ssh -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$USR@$IP" "sudo -n bash -s"
done
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, instance $SID, computes $NODES; management host $MGMT_HOST, director $DIR_USER@$DIR_HOST (keys are not printed)"
  printf 'SID=%q\nNODES=%q\nREQ=%q\nONNODE=%q\n%s\n' "$SID" "$NODES" "$REQ" "$ONNODE" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1
  echo "== exit $?"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

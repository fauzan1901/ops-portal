#!/usr/bin/env bash
# Read-only: which instances got the I/O errors that a migration rollback caused on a compute, and is their guest hurt?
# For each <compute>:<dm device> pair: the multipath device (WWID, paths with their SCSI address H:C:T:LUN, state), the
# running domain that uses it (instance name, UUID), that instance in Nova (name, project, status, host) and the I/O /
# filesystem errors its guest printed on its console. With a migrated instance (optional): the LUN number Nova keeps
# for its volumes (target, LUN; no secret), to compare with the LUN of the removed devices.
# Same path as the portal: portal service account -> management host -> director -> controller / computes.
# Run on the bastion:  sudo bash ~/rollback-victims.sh <SITE> <migrated server ID or -> <compute>:<dm-N>...
set -u
SITE="${1:-}"
MIG="${2:-}"
shift 2 2>/dev/null
PAIRS="$*"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[ "$MIG" = "-" ] || [[ "$MIG" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || { echo "Migrated server: a UUID or -"; exit 1; }
[[ "$PAIRS" =~ ^[a-z0-9-]+:dm-[0-9]+( [a-z0-9-]+:dm-[0-9]+)*$ ]] || { echo "Pairs: <compute short name>:dm-N, e.g. dccrhosp-compute-1:dm-7"; exit 1; }
OUT="/home/deploy/rollback-victims-$(date +%Y%m%d-%H%M%S).txt"
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

ONNODE=$(cat <<'NODE'
c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$')
V="podman exec $c virsh -c qemu:///system"
MP=$(command -v multipath >/dev/null && echo multipath || echo "podman exec multipathd multipath")
echo "-- $DM on $(hostname -s): $(cat /sys/block/$DM/dm/name 2>/dev/null)"
$MP -ll /dev/$DM 2>&1 | head -8
for x in $($V list --name); do
  if $V domblklist $x 2>/dev/null | awk '{print $2}' | grep -qx "/dev/$DM"; then
    echo "USER $x $($V domuuid $x 2>/dev/null)"
    $V domblklist $x 2>/dev/null | grep -E "/dev/$DM\$" | sed 's/^/   disk: /'
  fi
done
NODE
)

REMOTE=$(cat <<'EOF'
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
asroot() {
  local N IP USR
  read -r N IP USR < <(nodes "$1")
  [ -z "${IP:-}" ] || [ "$IP" = "-" ] && { echo "$1: not in the inventory"; return 1; }
  [ "$USR" = "-" ] && USR=$DEFUSR
  ssh -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$USR@$IP" "sudo -n bash -s"
}
if [ "$MIG" != "-" ]; then
  CTL=$(nodes controller | head -1 | cut -d' ' -f1)
  echo "== The migrated instance $MIG: host now, and the LUN Nova keeps for each volume (no secret)"
  openstack server show "$MIG" -f value -c name -c OS-EXT-SRV-ATTR:host 2>&1 | paste -sd' '
  printf 'podman exec $(podman ps -q -f name=galera-bundle | head -1) mysql -t -e %q\n' \
    "SELECT volume_id, device_name, JSON_VALUE(connection_info,'\$.data.target_iqn') iqn, JSON_VALUE(connection_info,'\$.data.target_lun') lun FROM nova.block_device_mapping WHERE instance_uuid='$MIG' AND deleted=0 AND destination_type='volume'" | asroot "$CTL"
fi
for pair in $PAIRS; do
  NODE=${pair%%:*}; DM=${pair##*:}
  echo
  echo "######## $NODE $DM"
  R=$(printf 'DM=%q\n%s\n' "$DM" "$ONNODE" | asroot "$NODE")
  printf '%s\n' "$R"
  for U in $(printf '%s\n' "$R" | awk '/^USER /{print $3}'); do
    echo "-- instance $U in Nova"
    openstack server show "$U" -f value -c name -c project_id -c status -c OS-EXT-STS:power_state -c OS-EXT-SRV-ATTR:host 2>&1 | paste -sd' '
    echo "-- its console log: I/O and filesystem errors (last 15 of the last 3000 lines)"
    openstack console log show --lines 3000 "$U" 2>&1 | grep -iE "I/O error|blk_update_request|Buffer I/O|EXT4-fs error|EXT4-fs .*read-only|Remounting filesystem read-only|XFS.*(error|shutdown|corrupt)|journal|Aborting journal" | tail -15
  done
done
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, migrated instance $MIG, devices $PAIRS; management host $MGMT_HOST, director $DIR_USER@$DIR_HOST (keys are not printed)"
  printf 'MIG=%q\nPAIRS=%q\nONNODE=%q\nRC=%s\n%s\n' "$MIG" "$PAIRS" "$ONNODE" "$RC" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1 | grep -v 'post-quantum\|store now, decrypt\|openssh.com/pq'
  echo "== exit $?"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

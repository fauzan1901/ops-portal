#!/usr/bin/env bash
# Read-only: every disk of an instance on its compute and whether it still has paths. Per disk of the domain
# (domblklist): target (vda, vdb...), source (dm-N), multipath WWID, size, vendor, number of active / failed paths and
# their SCSI addresses; and Nova's connection of each volume (device, volume, target, LUN; no secret). A disk with no
# path is the one a guest reports I/O errors on; lun-rescan.sh <SITE> <server> <compute> <dm-N> brings it back.
# Same path as the portal: portal service account -> management host -> director -> controller / compute.
# Run on the bastion:  sudo bash ~/instance-disks.sh <SITE> <server ID>
set -u
SITE="${1:-}"
SID="${2:-}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$SID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || { echo "Server ID: a UUID"; exit 1; }
OUT="/home/deploy/instance-disks-$(date +%Y%m%d-%H%M%S).txt"
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
MPD=$(podman ps --format '{{.Names}}' | grep -m1 -x multipathd)
MP() { if [ -n "$MPD" ]; then podman exec "$MPD" multipath "$@"; else multipath "$@"; fi; }
echo "domain $INST: $($V domstate $INST 2>&1 | head -1)"
$V domblklist $INST 2>/dev/null | awk '$2 ~ /^\/dev\// {print $1, $2}' | while read -r tgt src; do
  dm=$(basename "$(readlink -f "$src")")
  w=$(cat /sys/block/$dm/dm/name 2>/dev/null)
  L=$(MP -ll /dev/$dm 2>/dev/null)
  act=$(printf '%s\n' "$L" | grep -cE '[0-9]+:[0-9]+:[0-9]+:[0-9]+ +sd[a-z]+ .*active ready')
  bad=$(printf '%s\n' "$L" | grep -cE '[0-9]+:[0-9]+:[0-9]+:[0-9]+ +sd[a-z]+ .*(failed|faulty|offline)')
  addrs=$(printf '%s\n' "$L" | grep -oE '[0-9]+:[0-9]+:[0-9]+:[0-9]+ +sd[a-z]+' | tr -s ' ' '=' | tr '\n' ' ')
  vend=$(printf '%s\n' "$L" | head -1 | awk '{print $3}')
  size=$(printf '%s\n' "$L" | sed -n 's/^size=\([^ ]*\).*/\1/p' | head -1)
  echo "DISK $tgt $src $dm wwid=${w:-?} size=${size:-?} vendor=${vend:-?} active=$act failed=$bad paths: ${addrs:-none}"
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
CTL=$(nodes controller | head -1 | cut -d' ' -f1)
echo "== Instance: $(openstack server show "$SID" -f value -c name -c status -c OS-EXT-STS:power_state -c OS-EXT-SRV-ATTR:host 2>&1 | paste -sd' ')"
HOST=$(openstack server show "$SID" -f value -c OS-EXT-SRV-ATTR:host 2>/dev/null)
INST=$(openstack server show "$SID" -f value -c OS-EXT-SRV-ATTR:instance_name 2>/dev/null)
echo "== Nova's connection of each volume (device, volume, size, target, LUN; no secret)"
printf 'podman exec $(podman ps -q -f name=galera-bundle | head -1) mysql -t -e %q\n' \
  "SELECT b.device_name, b.volume_id, v.size, JSON_VALUE(b.connection_info,'\$.data.target_iqn') iqn, JSON_VALUE(b.connection_info,'\$.data.target_lun') lun FROM nova.block_device_mapping b LEFT JOIN cinder.volumes v ON v.id = b.volume_id WHERE b.instance_uuid='$SID' AND b.deleted=0 AND b.destination_type='volume' ORDER BY b.device_name" | asroot "$CTL"
echo "== The disks of $INST on ${HOST%%.*} (active = paths that work; a disk with 0 active has no path)"
printf 'INST=%q\n%s\n' "$INST" "$ONNODE" | asroot "${HOST%%.*}"
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, instance $SID; management host $MGMT_HOST, director $DIR_USER@$DIR_HOST (keys are not printed)"
  printf 'SID=%q\nONNODE=%q\nRC=%s\n%s\n' "$SID" "$ONNODE" "$RC" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1 | grep -v 'post-quantum\|store now, decrypt\|openssh.com/pq'
  echo "== exit $?"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

#!/usr/bin/env bash
# Guided repair of an instance whose block device mapping (BDM) keeps a volume Cinder no longer has by its ID, while its
# domain runs on another Cinder volume: the target of a Cinder volume migration that never completed (vm-c3,
# 2026-11-02: Nova keeps 7a3c9e01, deleted in Cinder; the domain runs on 8b4d0f12, named 7a3c9e01, migration
# target:7a3c9e01, NetApp LUN volume-8b4d0f12, LUN 103 on its compute; Nova's stored connection names LUN 33). Every Nova
# action on the volume fails (HTTP 404), Horizon cannot open the instance, and a start or migration would connect the LUN
# Nova keeps, not the disk. The steps:
#   0. read-only checks, any mismatch stops before a change: the instance; Nova's BDM (the missing volume, its stale
#      attachment); Cinder (the missing volume has no live row; the real one is in-use, migration none or target:<missing>,
#      the same size, ONE attachment, to this instance on its compute); the domain (its vda runs on the multipath map of
#      the NetApp serial the operator read on ONTAP, and the path of Cinder's attachment at its LUN number is a path of
#      that map: the disk is the real volume); the connector of the compute; nova-manage refresh as installed;
#   1. backup of the BDM, the Cinder rows and attachments on the controller (root-only directory, never printed: the rows
#      hold the CHAP secret), then stop the instance (power off only: no volume operation);
#   2. repoint: cinder reset-state --state in-use --reset-migration-status <real> (only its migration status changes);
#      the BDM -> the real volume, its attachment, connection_info driver_volume_type "local" (a no-op disconnect),
#      exactly 1 row;
#   3. remove the disk's devices on the compute (flush its multipath map, delete its SCSI paths) as os-brick does on a
#      disconnect, only while the domain is shut off and nothing holds the map: the refresh then unmaps the LUN on NetApp
#      and maps it again, possibly at another LUN number; old paths left behind would point at whatever LUN NetApp maps
#      at that number later;
#   4. nova-manage volume_attachment refresh with the connector of its compute (as bdm-refresh-safe.sh, a real case):
#      a new attachment, the LUN mapped for the compute, the new connection_info saved in the BDM;
#   5. read-only checks after: the BDM, ONE attachment, no device of ANOTHER LUN at the new LUN number on the compute;
#   6. start, then: running, vda on the map of the same serial at the new LUN number, the console opens.
# Every change asks for a typed confirmation first. Run it again after a stop: it goes on from the step reached (state
# read from the BDM: the missing volume = from step 1, the real one neutral = from step 3, iscsi = from step 5).
# Same path as the portal: portal service account -> management host -> director -> controller / compute.
# Run on the bastion:
#   sudo bash ~/missing-volume-repair.sh <SITE> <server ID> <Nova's missing volume ID> <real volume ID> '<NetApp serial>'
#   (the serial of the real volume's LUN on ONTAP: lun show -path /vol/<flexvol>/volume-<real volume ID> -fields serial)
set -u
SITE="${1:-}"
SID="${2:-}"
V="${3:-}"
X="${4:-}"
SER="${5:-}"
UUID_RE='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
USAGE="Usage: <SITE> <server ID> <Nova's missing volume ID> <real volume ID> '<NetApp serial of the real volume's LUN>'"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
for x in "$SID" "$V" "$X"; do [[ "$x" =~ $UUID_RE ]] || { echo "$USAGE"; exit 1; }; done
[ "$V" != "$X" ] || { echo "The missing and the real volume are the same ID"; exit 1; }
[[ ${#SER} -eq 12 && "$SER" =~ ^[[:graph:]]+$ && "$SER" != *"'"* && "$SER" != *'"'* && "$SER" != *'\'* ]] \
  || { echo "NetApp serial: the 12 characters lun show gives (in single quotes)"; exit 1; }
WWID="3600a0980$(printf '%s' "$SER" | od -An -tx1 | tr -d ' \n')"
[[ "$WWID" =~ ^3600a0980[0-9a-f]{24}$ ]] || { echo "Serial $SER does not give a NetApp WWID"; exit 1; }
STAMP=$(date +%Y%m%d-%H%M%S)
OUT="/home/deploy/missing-volume-repair-$STAMP.txt"
SVC=opsportal
PY=/opt/ops-portal/.venv/bin/python
TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT

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

# ---- shared by every phase on the director: node lookup, root on a node, SQL on the galera container, compute scripts
IFS= read -r -d '' LIB <<'EOF' || true
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
vmshow() {
  openstack --os-compute-api-version 2.9 server show "$SID" -f json 2>&1 | python3 -c '
import json, sys
try:
    s = json.load(sys.stdin)
except Exception:
    print("@@vm ? ? ? ?")
    sys.exit()
print("@@vm", s.get("OS-EXT-STS:vm_state") or "?", s.get("OS-EXT-STS:task_state") or "None", s.get("locked"),
      s.get("OS-EXT-SRV-ATTR:host") or "?")
print("   ", s.get("name"), s.get("status"), "power", s.get("OS-EXT-STS:power_state"), "on", s.get("OS-EXT-SRV-ATTR:host"))'
}
BDMQ="SELECT volume_id, IFNULL(attachment_id,'-'), IFNULL(device_name,'-'), IFNULL(JSON_VALUE(connection_info,'\$.driver_volume_type'),'NULL'), IFNULL(JSON_VALUE(connection_info,'\$.data.target_iqn'),'-'), IFNULL(JSON_VALUE(connection_info,'\$.data.target_lun'),'-'), IFNULL(JSON_VALUE(connection_info,'\$.data.device_path'),'-') FROM nova.block_device_mapping WHERE instance_uuid='$SID' AND deleted=0 AND volume_id IN ('$V','$X')"
VOLQ="SELECT id, deleted, IFNULL(deleted_at,'-'), IFNULL(_name_id,'-'), IFNULL(display_name,'-'), status, IFNULL(attach_status,'-'), IFNULL(migration_status,'-'), IFNULL(host,'-'), size FROM cinder.volumes WHERE id IN ('$V','$X')"
ATTQ="SELECT id, volume_id, IFNULL(instance_uuid,'-'), IFNULL(attached_host,'-'), IFNULL(attach_status,'-'), IFNULL(JSON_VALUE(connector,'\$.host'),'-'), IFNULL(JSON_VALUE(connection_info,'\$.target_iqn'),IFNULL(JSON_VALUE(connection_info,'\$.data.target_iqn'),'-')), IFNULL(JSON_VALUE(connection_info,'\$.target_lun'),IFNULL(JSON_VALUE(connection_info,'\$.data.target_lun'),'-')) FROM cinder.volume_attachment WHERE volume_id IN ('$V','$X') AND deleted=0"
# the compute scripts (run as root on the instance's compute; INST, WWID, IQN, LUN set before them)
IFS= read -r -d '' COMMON_C <<'C' || true
set -u
c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$')
v() { podman exec "$c" virsh -c qemu:///system "$@"; }
MPD=$(podman ps --format '{{.Names}}' | grep -m1 -x multipathd)
MP() { if [ -n "$MPD" ]; then podman exec "$MPD" multipath "$@"; else multipath "$@"; fi; }
lunof() { readlink "/sys/block/$1/device" 2>/dev/null | awk -F: '{print $NF}'; }
mapof() { for d in /sys/block/dm-*; do [ "$(cat "$d/dm/uuid" 2>/dev/null)" = "mpath-$1" ] && basename "$d"; done; }
pathsof() { for s in /sys/block/sd*; do [ "$(cat "$s/device/wwid" 2>/dev/null)" = "naa.${1#3}" ] && basename "$s"; done; }
C
IFS= read -r -d '' DOMREAD <<'C' || true
echo "@@state $(v domstate "$INST" 2>&1 | head -1)"
src=$(v domblklist "$INST" --details 2>/dev/null | awk '$3=="vda"{print $4}')
echo "@@src ${src:--}"
dm=$(basename "$(readlink -f "${src:-/nonexistent}")")
if [ -n "$src" ] && [ -r "/sys/block/$dm/dm/uuid" ]; then
  name=$(cat "/sys/block/$dm/dm/name")
  holders=$(ls "/sys/block/$dm/holders" | paste -sd, -)
  echo "@@dm $dm $name $(cat "/sys/block/$dm/dm/uuid") $(dmsetup info -c --noheadings -o open "$name" 2>/dev/null | tr -d ' ') ${holders:--}"
  for s in $(ls "/sys/block/$dm/slaves"); do echo "@@slave $s $(lunof "$s") $(cat "/sys/block/$s/device/state" 2>/dev/null)"; done
  for x in $(v list --name); do
    [ "$x" = "$INST" ] && continue
    for p in $(v domblklist "$x" --details 2>/dev/null | awk '$1=="block"{print $4}'); do
      [ "$(readlink -f "$p")" = "/dev/$dm" ] && echo "@@usedby $x"
    done
  done
fi
v dumpxml "$INST" 2>/dev/null | python3 -c '
import sys, xml.etree.ElementTree as E
try:
    r = E.fromstring(sys.stdin.read())
except Exception:
    r = None
s = "-"
for d in (r.iter("disk") if r is not None else []):
    t = d.find("target")
    if t is not None and t.get("dev") == "vda":
        s = (d.findtext("serial") or "-").strip()
print("@@serial", s)'
if [ -n "$IQN" ] && [ -n "$LUN" ]; then
  ls /dev/disk/by-path/ 2>/dev/null | while read -r p; do
    case "$p" in *"-iscsi-$IQN-lun-$LUN") echo "@@bypath $p $(basename "$(readlink -f "/dev/disk/by-path/$p")")";; esac
  done
fi
C
IFS= read -r -d '' PREFLIGHT <<'C' || true
echo "@@mpd ${MPD:-none} $(command -v multipath >/dev/null && echo host || echo -)"
echo "@@mpmap $(MP -ll "$WWID" 2>/dev/null | head -1 | awk '{print $1}')"
echo "@@tools $(for t in dmsetup blockdev; do command -v "$t" >/dev/null && printf '%s,' "$t"; done)"
ls /dev/disk/by-path/ 2>/dev/null | while read -r p; do
  case "$p" in *"-iscsi-$IQN-lun-"*) ;; *) continue;; esac
  n=${p##*-lun-}
  [[ "$n" =~ ^[0-9]+$ ]] || continue
  s=$(basename "$(readlink -f "/dev/disk/by-path/$p")")
  h=$(ls "/sys/block/$s/holders" 2>/dev/null | head -1)
  echo "@@tdev $n $s $(cat "/sys/block/$s/device/wwid" 2>/dev/null || echo -) $(cat "/sys/block/$s/device/state" 2>/dev/null || echo -) ${h:--}"
done
C
IFS= read -r -d '' CLEAN <<'C' || true
st=$(v domstate "$INST" 2>&1 | head -1)
case "$st" in "shut off"|*"failed to get domain"*|*"Domain not found"*) ;; *) echo "@@stop domain $INST is '$st', not shut off: nothing removed"; exit 1;; esac
maps=$(mapof "$WWID")
for dm in $maps; do
  name=$(cat "/sys/block/$dm/dm/name")
  for i in 1 2 3 4 5 6; do
    open=$(dmsetup info -c --noheadings -o open "$name" | tr -d ' ')
    [ "$open" = 0 ] && break
    sleep 5
  done
  holders=$(ls "/sys/block/$dm/holders" | paste -sd, -)
  [ "$open" = 0 ] && [ -z "$holders" ] || { echo "@@stop $dm ($name) is in use (open $open, holders ${holders:-none}): nothing removed"; exit 1; }
done
for x in $(v list --name); do
  for p in $(v domblklist "$x" --details 2>/dev/null | awk '$1=="block"{print $4}'); do
    for dm in $maps; do [ "$(readlink -f "$p")" = "/dev/$dm" ] && { echo "@@stop $dm is a disk of the running domain $x: nothing removed"; exit 1; }; done
  done
done
for dm in $maps; do
  name=$(cat "/sys/block/$dm/dm/name")
  slaves=$(ls "/sys/block/$dm/slaves" | paste -sd' ' -)
  echo "flush $name ($dm), paths $slaves (LUN $(for s in $slaves; do lunof "$s"; done | sort -un | paste -sd, -))"
  MP -f "$name" || { echo "@@stop multipath -f $name failed: its paths were not removed"; exit 1; }
  for s in $slaves; do blockdev --flushbufs "/dev/$s" 2>/dev/null; echo 1 > "/sys/block/$s/device/delete" && echo "  removed $s"; done
done
for s in $(pathsof "$WWID"); do   # a path of the disk in no map
  [ -z "$(ls "/sys/block/$s/holders")" ] || { echo "@@stop path $s of WWID $WWID is held: not removed"; exit 1; }
  blockdev --flushbufs "/dev/$s" 2>/dev/null; echo 1 > "/sys/block/$s/device/delete" && echo "  removed $s (in no map, LUN $(lunof "$s"))"
done
sleep 3
left="$(mapof "$WWID") $(pathsof "$WWID")"
if [ -z "${left// /}" ]; then echo "@@clean done: no device of WWID $WWID left on this compute"; else echo "@@stop still there: $left"; exit 1; fi
C
IFS= read -r -d '' AFTER <<'C' || true
echo "@@state $(v domstate "$INST" 2>&1 | head -1)"
for dm in $(mapof "$WWID"); do
  echo "@@map $dm LUN $(for s in $(ls "/sys/block/$dm/slaves"); do lunof "$s"; done | sort -un | paste -sd, -) open $(dmsetup info -c --noheadings -o open "$(cat "/sys/block/$dm/dm/name")" | tr -d ' ')"
done
for s in $(pathsof "$WWID"); do echo "@@path $s LUN $(lunof "$s")"; done
if [ -n "$IQN" ] && [ -n "$LUN" ]; then
  ls /dev/disk/by-path/ 2>/dev/null | while read -r p; do
    case "$p" in *"-iscsi-$IQN-lun-$LUN")
      s=$(basename "$(readlink -f "/dev/disk/by-path/$p")")
      echo "@@atlun $s $(cat "/sys/block/$s/device/wwid" 2>/dev/null || echo -) $(ls "/sys/block/$s/holders" | paste -sd, -)";;
    esac
  done
fi
C
oncompute() {   # oncompute <script>: as root on the instance's compute, with INST, WWID, IQN, LUN
  { printf 'INST=%q\nWWID=%q\nIQN=%q\nLUN=%q\n' "$INST" "${WWID:-}" "${IQN:-}" "${LUN:-}"; printf '%s\n' "$COMMON_C" "$1"; } | asroot "$NODE"
}
EOF

# ---- 0. read-only checks
IFS= read -r -d '' PHASE0 <<'EOF' || true
echo "== Instance"
vmshow
echo "== Nova's block device mapping of both volumes (volume, attachment, device, type, target, LUN, device path; no secret)"
sql "$BDMQ" | sed 's/^/@@bdm\t/'
echo "== Cinder rows of both volumes (id, deleted, deleted at, name_id, name, status, attach, migration, host, size)"
sql "$VOLQ" | sed 's/^/@@vol\t/'
echo "== Cinder attachments (id, volume, instance, attached host, status, connector host, target, LUN; no secret)"
ATT=$(sql "$ATTQ")
printf '%s\n' "$ATT" | sed '/^$/d; s/^/@@att\t/'
read -r IQN LUN < <(printf '%s\n' "$ATT" | awk -F'\t' -v x="$X" -v s="$SID" '$2==x && $3==s {print $7, $8; exit}')
echo "== Domain $INST on $NODE: its vda, the paths of its map, the path of Cinder's attachment (LUN ${LUN:-?})"
oncompute "$DOMREAD"
echo "== $NODE: multipath tools, and every device of target ${IQN:-?} (LUN, device, WWID, state, holder)"
oncompute "$PREFLIGHT"
echo "== Live Cinder attachments of this compute on that target (LUN, volume, instance)"
sql "SELECT IFNULL(JSON_VALUE(connection_info,'\$.target_lun'),JSON_VALUE(connection_info,'\$.data.target_lun')), volume_id, IFNULL(instance_uuid,'-') FROM cinder.volume_attachment WHERE deleted=0 AND attach_status='attached' AND JSON_VALUE(connector,'\$.host')='$HOST' AND IFNULL(JSON_VALUE(connection_info,'\$.target_iqn'),JSON_VALUE(connection_info,'\$.data.target_iqn'))='$IQN'" | sed 's/^/@@hostatt\t/'
echo "== Services the refresh and the start need"
openstack compute service list --service nova-compute --host "$HOST" -f json 2>&1 | python3 -c '
import json, sys
try:
    r = json.load(sys.stdin)
except Exception:
    r = []
for x in r:
    print("@@novacompute", x.get("Host"), x.get("Status"), x.get("State"))'
VH=$(sql "SELECT host FROM cinder.volumes WHERE id='$X'" | head -1)
openstack volume service list --service cinder-volume -f json 2>&1 | python3 -c '
import json, sys
try:
    r = json.load(sys.stdin)
except Exception:
    r = []
for x in r:
    if x.get("Host") == sys.argv[1]:
        print("@@cindervolume", x.get("Host"), x.get("Status"), x.get("State"))' "${VH%%#*}"
echo "@@dbwrite $(sql 'SHOW GRANTS' | grep -c 'GRANT ALL PRIVILEGES ON \*\.\*')"
echo "== The service role Cinder takes from a service token, and the roles of nova's [service_user]"
printf '%s\n' 'podman exec cinder_api python3 -c "
import configparser
c = configparser.RawConfigParser(strict=False, interpolation=None)
c.read(\"/etc/cinder/cinder.conf\")
print(\"@@cinderroles\", c.get(\"keystone_authtoken\", \"service_token_roles\", fallback=\"service\").replace(\" \", \"\") or \"service\")
"' | asroot "$CTL"
read -r SU SD SP < <(printf '%s\n' 'podman exec nova_api python3 -c "
import configparser
c = configparser.RawConfigParser(strict=False, interpolation=None)
c.read(\"/etc/nova/nova.conf\")
print(c.get(\"service_user\", \"username\", fallback=\"-\"), c.get(\"service_user\", \"user_domain_name\", fallback=\"Default\"),
      c.get(\"service_user\", \"project_name\", fallback=\"service\"))
"' | asroot "$CTL")
# the roles of that user in the project its token is scoped to (with --names the project reads <name>@<domain>)
echo "@@svcroles ${SU:--}@${SP:--} $(openstack role assignment list --effective --user "${SU:--}" --user-domain "${SD:-Default}" --names -f value -c Role -c Project 2>/dev/null | awk -v p="${SP:--}" '$2==p || index($2, p"@")==1 {print $1}' | sort -u | paste -sd, -)"
openstack console url show "$SID" -f value -c url >/dev/null 2>&1 && echo "@@console ok" || echo "@@console failed"
echo "== Image metadata rows in Cinder (volume, deleted, rows; the start uses Nova's own copy of the image properties)"
sql "SELECT volume_id, deleted, COUNT(*) FROM cinder.volume_glance_metadata WHERE volume_id IN ('$V','$X') GROUP BY volume_id, deleted"
echo "== Connector of $NODE (nova-manage volume_attachment get_connector; host and initiator only)"
printf '%s\n' 'podman exec -u root nova_compute nova-manage volume_attachment get_connector --json 2>/dev/null | python3 -c "import json,sys; c=json.load(sys.stdin); print(\"@@connector\", c.get(\"host\"), c.get(\"initiator\"), \"multipath\", c.get(\"multipath\"))"' | asroot "$NODE"
echo "== nova-manage volume_attachment refresh as installed on $CTL (the calls it makes, in order)"
printf '%s\n' 'P=$(podman exec nova_api python3 -c "import nova, os; print(os.path.dirname(nova.__file__))"); podman exec nova_api awk "/class VolumeAttachmentCommands/,/def refresh\\(/" $P/cmd/manage.py | grep -nE "vm_state|STOPPED|locked_instance|attachment_create|remove_volume_connection|attachment_delete|attachment_update|bdm.connection_info =|attachment_complete" | tee /dev/stderr | grep -oE "attachment_create|remove_volume_connection|attachment_delete|attachment_update|attachment_complete" | sort -u | paste -sd, - | sed "s/^/@@refreshcalls /"' | asroot "$CTL" 2>&1
echo "== nova.conf of nova_api: does nova-manage send a service token (Cinder refuses to delete an attachment Nova uses"
echo "   without one, CVE-2023-2088), and the [keystone_authtoken] option names the [cinder] auth is built from (no value)"
printf '%s\n' 'podman exec nova_api python3 -c "
import configparser
c = configparser.RawConfigParser(strict=False, interpolation=None)
c.read(\"/etc/nova/nova.conf\")
print(\"@@serviceuser\", c.get(\"service_user\", \"send_service_user_token\", fallback=\"-\").strip().lower(),
      \",\".join(k for k in (\"auth_url\", \"username\", \"password\") if c.has_option(\"service_user\", k)) or \"-\")
print(\"@@authkeys\", \",\".join(k for k in (\"auth_url\", \"username\", \"password\", \"project_name\", \"user_domain_name\",
      \"project_domain_name\") if c.has_option(\"keystone_authtoken\", k)) or \"-\")
"' | asroot "$CTL"
EOF

# ---- 1. backup, stop
IFS= read -r -d '' PHASE1 <<'EOF' || true
D=/root/missing-volume-repair-$SID-$STAMP
echo "== Backup on $CTL: $D (root only, not printed: the rows hold the CHAP secret)"
printf '%s\n' "umask 077; mkdir -p $D; G=\$(podman ps -q -f name=galera-bundle | head -1)
podman exec \$G mysql -B -e \"SELECT * FROM nova.block_device_mapping WHERE instance_uuid='$SID' AND deleted=0\" > $D/bdm.tsv
podman exec \$G mysql -B -e \"SELECT * FROM cinder.volumes WHERE id IN ('$V','$X')\" > $D/volumes.tsv
podman exec \$G mysql -B -e \"SELECT * FROM cinder.volume_attachment WHERE volume_id IN ('$V','$X')\" > $D/attachments.tsv
chmod -R go-rwx $D; wc -l $D/*" | asroot "$CTL"
S=$(openstack server show "$SID" -f value -c OS-EXT-STS:vm_state 2>/dev/null)
if [ "$S" = active ]; then
  echo "== Stop $SID (power off only)"
  openstack server stop "$SID" && echo "stop requested"
fi
for i in $(seq 1 30); do
  S=$(openstack server show "$SID" -f value -c OS-EXT-STS:vm_state -c OS-EXT-STS:task_state 2>/dev/null | paste -sd' ')
  echo "  vm_state task_state: $S"
  [[ "$S" == *stopped* && "$S" == *None* ]] && { echo "@@stopped"; break; }
  sleep 10
done
EOF

# ---- 2. repoint the BDM onto the real volume
IFS= read -r -d '' PHASE2 <<'EOF' || true
MS=$(sql "SELECT IFNULL(migration_status,'-') FROM cinder.volumes WHERE id='$X' AND deleted=0" | head -1)
if [ "$MS" != "-" ]; then
  echo "== Clear the migration status of $X ($MS); its status stays in-use"
  cinder reset-state --state in-use --reset-migration-status "$X" && echo "reset-state done"
fi
R=$(sql "SELECT status, IFNULL(attach_status,'-'), IFNULL(migration_status,'-') FROM cinder.volumes WHERE id='$X' AND deleted=0" | head -1)
echo "$X: $R"
[ "$R" = "$(printf 'in-use\tattached\t-')" ] || { echo "@@stop $X is not in-use, attached, without migration status: the BDM is not changed"; exit 1; }
echo "== Nova's BDM: $V -> $X, attachment $STALE -> $A, connection_info neutral (exactly 1 row)"
NEW="{\"driver_volume_type\": \"local\", \"data\": {}, \"serial\": \"$X\"}"
if [ "$STALE" = "-" ]; then W="attachment_id IS NULL"; else W="attachment_id='$STALE'"; fi
N=$(sql "UPDATE nova.block_device_mapping SET volume_id='$X', attachment_id='$A', connection_info='$NEW' WHERE instance_uuid='$SID' AND volume_id='$V' AND $W AND deleted=0 LIMIT 1; SELECT ROW_COUNT();" | tail -1)
echo "rows changed: $N"
sql "$BDMQ" | sed 's/^/@@bdm\t/'
[ "$N" = 1 ] && echo "@@repointed" || echo "@@stop the UPDATE changed ${N:-no} row(s), not 1"
EOF

# ---- 3. remove the disk's devices on the compute
IFS= read -r -d '' PHASE3 <<'EOF' || true
echo "== $NODE: the devices of WWID $WWID (domain $INST shut off, nothing holding them)"
oncompute "$CLEAN"
EOF

# ---- 4. nova-manage volume_attachment refresh (as bdm-refresh-safe.sh)
IFS= read -r -d '' PHASE4 <<'EOF' || true
echo "== nova-manage volume_attachment refresh $SID $X with the connector of $NODE"
T=$(sql "SELECT IFNULL(JSON_VALUE(connection_info,'\$.driver_volume_type'),'NULL') FROM nova.block_device_mapping WHERE instance_uuid='$SID' AND volume_id='$X' AND deleted=0" | head -1)
if [ "$T" = NULL ]; then   # a refresh that failed after deleting the attachment leaves connection_info NULL
  NEW="{\"driver_volume_type\": \"local\", \"data\": {}, \"serial\": \"$X\"}"
  sql "UPDATE nova.block_device_mapping SET connection_info='$NEW' WHERE instance_uuid='$SID' AND volume_id='$X' AND connection_info IS NULL AND deleted=0 LIMIT 1; SELECT ROW_COUNT();"
  T=local
fi
[ "$T" = local ] || { echo "@@stop the BDM of $X is '$T', not neutral (local): no refresh"; exit 1; }
S=$(openstack --os-compute-api-version 2.9 server show "$SID" -f value -c OS-EXT-STS:vm_state -c locked 2>/dev/null | paste -sd' ')
if [[ "$S" == *stopped* && "$S" == *True* ]]; then
  openstack server unlock "$SID" && echo "unlocked (a lock left by an earlier refresh attempt)"
  S=$(openstack --os-compute-api-version 2.9 server show "$SID" -f value -c OS-EXT-STS:vm_state -c locked 2>/dev/null | paste -sd' ')
fi
[[ "$S" == *stopped* && "$S" == *False* ]] || { echo "@@stop the instance must be stopped and unlocked (now: $S)"; exit 1; }
CONN=$(printf '%s\n' "podman exec -u root nova_compute nova-manage volume_attachment get_connector --json 2>/dev/null" | asroot "$NODE")
CHOST=$(printf '%s' "$CONN" | python3 -c "import json,sys; print(json.load(sys.stdin).get('host') or '')" 2>/dev/null)
[ -n "$CHOST" ] && [ "$CHOST" = "$HOST" ] || { echo "@@stop connector host '$CHOST' is not the instance host '$HOST'"; exit 1; }
echo "connector host $CHOST"
D=$(oncompute 'v domstate "$INST" 2>&1 | head -1')
echo "domain $INST on $NODE: $D"
[[ "$D" == "shut off" || "$D" == *"failed to get domain"* || "$D" == *"Domain not found"* ]] || { echo "@@stop the domain is '$D' on $NODE"; exit 1; }
# nova-manage runs with an admin context without a token: its Cinder calls need [cinder] auth options, which nova.conf
# of nova_api does not have ("Unknown auth type: None"). They are taken from its [keystone_authtoken] (the nova service
# user) into a root-only file inside the container for this one command, then deleted; the password is never printed.
IFS= read -r -d '' ONCTL <<'NODE' || true
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
  volume_attachment refresh "$SID" "$X" /tmp/connector-$SID.json
echo "refresh exit $?"
podman exec -u root nova_api rm -f /tmp/cinder-auth-$SID.conf /tmp/connector-$SID.json
rm -f /tmp/connector-$SID.json
echo "temporary files removed"
NODE
printf 'SID=%q\nX=%q\nCONN=%q\n%s\n' "$SID" "$X" "$CONN" "$ONCTL" | asroot "$CTL"
EOF

# ---- 5. read-only checks after the refresh (and after the start)
IFS= read -r -d '' PHASE5 <<'EOF' || true
vmshow
ROW=$(sql "$BDMQ")
printf '%s\n' "$ROW" | sed '/^$/d; s/^/@@bdm\t/'
read -r IQN LUN < <(printf '%s\n' "$ROW" | awk -F'\t' -v x="$X" '$1==x {print $5, $6; exit}')
sql "$VOLQ" | sed 's/^/@@vol\t/'
sql "$ATTQ" | sed 's/^/@@att\t/'
echo "== $NODE: the devices of WWID $WWID and what is at LUN ${LUN:-?} of the target"
oncompute "$AFTER"
oncompute "$DOMREAD" | grep -E '^@@(dm|slave|usedby|serial) '
openstack console url show "$SID" -f value -c url >/dev/null 2>&1 && echo "@@console ok" || echo "@@console failed"
EOF

# ---- 6. start
IFS= read -r -d '' PHASE6 <<'EOF' || true
openstack server start "$SID" && echo "start requested"
for i in $(seq 1 60); do
  S=$(openstack server show "$SID" -f value -c OS-EXT-STS:vm_state -c OS-EXT-STS:task_state 2>/dev/null | paste -sd' ')
  echo "  vm_state task_state: $S"
  [[ "$S" == *active* && "$S" == *None* ]] && break
  [[ "$S" == *error* ]] && { openstack server show "$SID" -f json -c fault 2>/dev/null | python3 -c "import json,sys; print('fault:', (json.load(sys.stdin).get('fault') or {}).get('message'))"; break; }
  sleep 10
done
EOF

# ---- the verdicts on what a phase read: [OK] / [STOP] lines, VERDICT, VARS
IFS= read -r -d '' VERDICT_PY <<'EOF' || true
import sys
mode, path, V, X, SID, SER, WWID = sys.argv[1:8]
NEWLUN = sys.argv[8] if len(sys.argv) > 8 else ""
lines = open(path, errors="replace").read().splitlines()
tab = lambda tag: [l.split("\t")[1:] for l in lines if l.startswith(tag + "\t")]
sp = lambda tag: [l.split()[1:] for l in lines if l.startswith(tag + " ")]
short = lambda h: str(h or "").split(".")[0].lower()
oks, stops = [], []

def check(cond, good, bad):
    (oks if cond else stops).append(good if cond else bad)
    return bool(cond)

vm = (sp("@@vm") or [["?", "?", "?", "?"]])[0] + ["?"] * 4
vm_state, task, locked, host = vm[:4]
bdm, vols, atts = tab("@@bdm"), {r[0]: r for r in tab("@@vol") if r}, [a for a in tab("@@att") if len(a) >= 8]
bV, bX = [r for r in bdm if r[0] == V], [r for r in bdm if r[0] == X]
xr, vr = vols.get(X), vols.get(V)
dstate = " ".join((sp("@@state") or [["?"]])[0])
dm = (sp("@@dm") or [[]])[0]
slaves = sp("@@slave")
serial = ((sp("@@serial") or [["-"]])[0] or ["-"])[0]
used = [u[0] for u in sp("@@usedby") if u]
out = []
if mode == "before":
    state = ("start" if len(bV) == 1 and not bX else
             "repointed" if len(bX) == 1 and not bV and bX[0][3] in ("local", "NULL") else
             "refreshed" if len(bX) == 1 and not bV and bX[0][3] == "iscsi" else "")
    check(state, f"Nova's block device mapping: {'the missing volume ' + V + ', attachment ' + bV[0][1] + ', ' + bV[0][3] + ' LUN ' + bV[0][5] if state == 'start' else X + ' (' + bX[0][3] + '): an earlier run reached this'}",
          f"Nova's block device mapping is not one this script knows ({len(bV)} row(s) of {V}, {len(bX)} of {X})")
    check(task in ("None", "-", ""), f"no task runs on the instance ({vm_state})", f"a task runs on the instance: {task}")
    conn = (sp("@@connector") or [["?"]])[0]
    check(short(conn[0]) == short(host), f"the connector of the compute is of {conn[0]}", f"the connector of the compute is of {conn[0]}, not {host}")
    check(xr and xr[1] == "0", f"{X} is a live Cinder volume ({xr[5] if xr else '?'}, {xr[6] if xr else '?'}, migration {xr[7] if xr else '?'}, {xr[9] if xr else '?'} GiB, named {xr[4] if xr else '?'})",
          f"{X} is not a live Cinder volume")
    A = "-"
    calls = set(((sp("@@refreshcalls") or [[""]])[0] or [""])[0].split(","))
    need = {"attachment_create", "remove_volume_connection", "attachment_delete", "attachment_update", "attachment_complete"}
    check(need <= calls, "nova-manage volume_attachment refresh is installed (attachment_create, remove_volume_connection, attachment_delete, attachment_update, attachment_complete)",
          f"nova-manage volume_attachment refresh as installed does not make the calls expected (found: {', '.join(sorted(calls - {''})) or 'none'})")
    su = (sp("@@serviceuser") or [["-", "-"]])[0] + ["-"]
    check(su[0] == "true" and set(su[1].split(",")) >= {"auth_url", "username", "password"},
          "nova_api sends a service token ([service_user] send_service_user_token = true, with its credentials): Cinder lets the refresh delete the attachment Nova uses",
          f"[service_user] of nova_api: send_service_user_token = {su[0]}, options {su[1]}: without a service token Cinder refuses to delete the attachment Nova uses (409, CVE-2023-2088) and the refresh stops halfway, with the instance stopped")
    ak = set(((sp("@@authkeys") or [["-"]])[0] or ["-"])[0].split(","))
    check(ak >= {"auth_url", "username", "password", "project_name"}, f"[keystone_authtoken] of nova_api has {', '.join(sorted(ak))} (the [cinder] auth of the refresh)",
          f"[keystone_authtoken] of nova_api lacks options for the [cinder] auth of the refresh (has: {', '.join(sorted(ak - {'-'})) or 'none'})")
    nc = (sp("@@novacompute") or [[]])[0]
    check(len(nc) >= 3 and nc[2] == "up", f"nova-compute of {short(nc[0]) if nc else '?'} is up ({nc[1] if len(nc) > 1 else '?'}): the refresh and the start reach it",
          f"nova-compute of the instance's compute is not up ({' '.join(nc) or 'not read'}): the refresh and the start need it")
    cv = (sp("@@cindervolume") or [[]])[0]
    check(len(cv) >= 3 and cv[1] == "enabled" and cv[2] == "up", f"cinder-volume {cv[0] if cv else '?'} (the backend of {X}) is enabled and up",
          f"cinder-volume of the backend of {X} is not enabled and up ({' '.join(cv) or 'not read'}): the refresh needs it to map the LUN")
    dbw = ((sp("@@dbwrite") or [["0"]])[0] or ["0"])[0]
    check(dbw.isdigit() and int(dbw) > 0, "the database account of the script has ALL PRIVILEGES (step 2 can write)", "the database account of the script cannot be shown to write (step 2 updates the BDM)")
    want = set((((sp("@@cinderroles") or [["service"]])[0] or ["service"])[0]).split(","))
    sr = (sp("@@svcroles") or [["-"]])[0] + [""]
    have = set(sr[1].split(",")) - {""}
    check(bool(want & have), f"nova's service user {sr[0]} has the role {', '.join(sorted(want & have))}: Cinder takes its service token, the refresh may delete the attachment Nova uses",
          f"nova's service user {sr[0]} has the roles {', '.join(sorted(have)) or 'none'}, not {', '.join(sorted(want))} that Cinder takes from a service token: Cinder would refuse to delete the attachment (409) and the refresh would stop halfway")
    mpd = (sp("@@mpd") or [["none", "-"]])[0] + ["-"]
    tools = ((sp("@@tools") or [[""]])[0] or [""])[0]
    check((mpd[0] != "none" or mpd[1] == "host") and "dmsetup" in tools and "blockdev" in tools,
          f"step 3 has its tools on the compute (multipath in {'the container ' + mpd[0] if mpd[0] != 'none' else 'the host'}, dmsetup, blockdev)",
          f"step 3 lacks a tool on the compute (multipath: {mpd[0]}/{mpd[1]}, others: {tools or 'none'})")
    mpmap = ((sp("@@mpmap") or [[""]])[0] or [""])[0]
    check(mpmap == WWID, f"multipath shows the map of {WWID}", f"multipath does not show the map of {WWID} ({mpmap or 'nothing'})")
    tdev, hatt = sp("@@tdev"), [a for a in tab("@@hostatt") if a and a[0]]
    taken = {a[0] for a in hatt}
    loose = [d for d in tdev if d and d[0] not in taken]
    check(not loose, f"each of the {len(tdev)} paths of the target on the compute is at a LUN number with a live Cinder attachment of this compute ({len(taken)} numbers): wherever NetApp maps {X} next, no old device is there",
          f"paths of the target on the compute at LUN numbers without a Cinder attachment of this compute (old, or mapped outside Cinder): "
          + "; ".join(f"LUN {d[0]} {d[1]} {d[2] if len(d) > 2 else '?'} {d[3] if len(d) > 3 else '?'} holder {d[4] if len(d) > 4 else '?'}" for d in loose[:8])
          + f": NetApp may map {X} at such a number and step 5 would stop; clear them first")
    own = {a[7] for a in atts if a[1] == X and a[2] == SID}   # deleted by the refresh before the new mapping
    free = next(n for n in range(0, 4096) if str(n) not in taken - own)
    oks.append(f"(note) NetApp gives the lowest free LUN number of the igroup: likely LUN {free} (no live Cinder attachment of this compute there)")
    check(any(l.strip() == "@@console ok" for l in lines), "Nova gives the console URL of the instance (checked again after the start)", "Nova gives no console URL now: the check after the start would report it")
    if state == "start":
        check(locked == "False", "the instance is not locked", "the lock state of the instance was not read" if locked in ("None", "?") else
              "the instance is locked (by its owner?): unlock it with the owner's approval, then run again")
        check(vm_state in ("active", "stopped"), f"the instance is {vm_state}", f"the instance is {vm_state}, not active or stopped")
        check(not vr or vr[1] != "0", f"{V} has no live row in Cinder" + (f" (deleted {vr[2]})" if vr else ""), f"{V} is a live Cinder volume: this is not the case this script repairs")
        check(xr and xr[5] == "in-use" and xr[6] == "attached" and xr[7] in ("-", f"target:{V}"),
              f"{X} is in-use, attached, migration {xr[7] if xr else '?'}", f"{X} is not in-use / attached / migration none or target:{V}")
        if vr and xr:
            check(vr[9] == xr[9], f"both are {xr[9]} GiB", f"the sizes differ: {V} {vr[9]} GiB, {X} {xr[9]} GiB")
        live = [a for a in atts if a[1] == X]
        mine = [a for a in live if a[2] == SID and a[4] == "attached" and short(a[5] if a[5] != "-" else a[3]) == short(host)]
        if check(len(live) == 1 and len(mine) == 1, f"{X} has one attachment, {mine[0][0] if mine else '?'}, attached to the instance on {short(host)} (LUN {mine[0][7] if mine else '?'})",
                 f"{X} has {len(live)} live attachment(s), {len(mine)} attached to this instance on {short(host)}: one is expected"):
            A, alun = mine[0][0], mine[0][7]
            want = "running" if vm_state == "active" else "shut off"
            check(dstate == want, f"its domain is {dstate}", f"its domain is '{dstate}', not {want}")
            check(len(dm) >= 3 and dm[2] == f"mpath-{WWID}", f"vda of the domain runs on {dm[0] if dm else '?'} ({dm[1] if len(dm) > 1 else '?'}), WWID {WWID} = NetApp serial {SER}",
                  f"vda of the domain is not on the map of NetApp serial {SER} ({' '.join(dm) or 'no multipath map found'})")
            luns = {s[1] for s in slaves if len(s) > 1}
            bypath = {b[1] for b in sp("@@bypath") if len(b) > 1}
            check(alun in luns and bypath & {s[0] for s in slaves},
                  f"Cinder's attachment {A} is that disk: its path at LUN {alun} ({', '.join(sorted(bypath))}) is a path of {dm[0] if dm else '?'} (LUN {','.join(sorted(luns))})",
                  f"Cinder's attachment {A} (LUN {alun}) is not shown to be the disk of the domain (paths of the map at LUN {','.join(sorted(luns)) or '?'}, path at LUN {alun}: {', '.join(sorted(bypath)) or 'none'})")
            check(not used, "no other domain uses that disk", f"another domain uses that disk: {', '.join(used)}")
    elif state == "repointed":
        check(vm_state == "stopped", "the instance is stopped", f"the instance is {vm_state}, not stopped (a start with a neutral connection fails)")
        check(xr and xr[7] == "-", "its migration status is cleared", f"its migration status is {xr[7] if xr else '?'}")
    elif state == "refreshed":
        check(vm_state in ("active", "stopped"), f"the instance is {vm_state}", f"the instance is {vm_state}")
    out.append(f"VARS {state or '-'} {bV[0][1] if bV else '-'} {A} {vm_state} {serial}")
else:   # after (the refresh, instance stopped) / started
    x = bX[0] if len(bX) == 1 and not bV else []
    lun = x[5] if x else "-"
    check(x and x[3] == "iscsi" and lun.isdigit(), f"Nova's block device mapping: {X}, attachment {x[1] if x else '?'}, iscsi LUN {lun} of {x[4] if x else '?'}",
          f"Nova's block device mapping of {X} is not a fresh iscsi connection ({' '.join(x) or 'no row'})")
    live = [a for a in atts if a[1] == X]
    check(x and len(live) == 1 and live[0][0] == x[1] and live[0][4] == "attached" and short(live[0][5] if live[0][5] != "-" else live[0][3]) == short(host),
          f"Cinder: one attachment of {X}, the BDM's, attached on {short(host)}", f"Cinder: {len(live)} live attachment(s) of {X}: " + "; ".join(f"{a[0]} {a[4]} {a[5]}" for a in live))
    check(xr and xr[5] == "in-use" and xr[7] == "-", f"{X} is in-use, no migration status", f"{X}: {xr[5] if xr else '?'}, migration {xr[7] if xr else '?'}")
    naa = "naa." + WWID[1:]
    other = [s for s in sp("@@atlun") if len(s) > 1 and s[1] != naa]
    check(not other, f"no device of another LUN at LUN {lun} on the compute",
          "devices of ANOTHER LUN at LUN " + lun + " on the compute (os-brick would take them): " + ", ".join(f"{s[0]} {s[1]}" for s in other))
    maps, paths = sp("@@map"), sp("@@path")
    if mode == "after":
        check(vm_state == "stopped" and (dstate == "shut off" or "failed to get domain" in dstate or "not found" in dstate), f"the instance is stopped, its domain {dstate}", f"the instance is {vm_state}, its domain {dstate}")
        check(all(m[-1] == "0" for m in maps), "no device of the disk is open on the compute", "a device of the disk is open on the compute: " + " ".join(" ".join(m) for m in maps))
        out.append(f"VARS {lun} {'1' if maps or paths else '0'}")
    else:
        check(vm_state == "active" and dstate == "running", f"the instance is active, its domain running", f"the instance is {vm_state}, its domain {dstate}")
        check(len(dm) >= 3 and dm[2] == f"mpath-{WWID}", f"vda runs on {dm[0] if dm else '?'}, the map of NetApp serial {SER}", f"vda is not on the map of serial {SER}: {' '.join(dm) or 'none'}")
        luns = {s[1] for s in slaves if len(s) > 1}
        check(luns == {NEWLUN or lun}, f"its paths are LUN {','.join(sorted(luns))}, the BDM's", f"its paths are LUN {','.join(sorted(luns)) or '?'}, the BDM's is {NEWLUN or lun}")
        check(not used, "no other domain uses that disk", f"another domain uses that disk: {', '.join(used)}")
        check(any(l.strip() == "@@console ok" for l in lines), "the console opens (Nova gives its URL)", "Nova gives no console URL")
        out.append(f"VARS {lun} -")
for t in oks:
    print("[OK]  ", t)
for t in stops:
    print("[STOP]", t)
print("VERDICT", "STOP" if stops else "OK")
print("\n".join(out))
EOF

remote() {   # remote <phase script>: runs LIB + the phase on the director
  printf 'SID=%q\nV=%q\nX=%q\nSER=%q\nWWID=%q\nSTAMP=%q\nSTALE=%q\nA=%q\nRC=%s\n%s\n%s\n' \
    "$SID" "$V" "$X" "$SER" "$WWID" "$STAMP" "${STALE:--}" "${A:--}" "$RC" "$LIB" "$1" \
    | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
      "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1 \
    | grep -v 'post-quantum\|store now, decrypt\|openssh.com/pq'
}
run() {   # run <name> <phase script>: shows its output, keeps it in $TMP/<name>
  remote "$2" | tee "$TMP/$1"
}
verdict() {   # verdict <mode> <name> [new LUN]: prints the checks; returns 1 on a STOP
  "$PY" -c "$VERDICT_PY" "$1" "$TMP/$2" "$V" "$X" "$SID" "$SER" "$WWID" "${3:-}" | tee "$TMP/$2.verdict" | grep -v '^VARS '
  grep -q '^VERDICT OK$' "$TMP/$2.verdict"
}
vars() { awk '$1=="VARS"{$1=""; print substr($0, 2); exit}' "$TMP/$1.verdict"; }
stopped_here() { echo; echo "Stopped at a check: nothing more was changed. $1"; chown deploy: "$OUT" 2>/dev/null; echo "Saved: $OUT"; exit 1; }
confirm() {   # confirm <word> <what>
  echo
  read -r -p ">>> $2 Type $1 to go on (anything else stops): " ans </dev/tty
  [ "$ans" = "$1" ] || { echo "Stopped, nothing more was changed."; chown deploy: "$OUT" 2>/dev/null; echo "Saved: $OUT"; exit 0; }
}
failed() { grep -q '^@@stop' "$TMP/$1"; }

exec > >(tee "$OUT") 2>&1
echo "$(date -Is) site $SITE, instance $SID, Nova's volume $V -> real volume $X, NetApp serial $SER (WWID $WWID)"
echo "######## 0. Checks (read-only)"
run p0 "$PHASE0" >/dev/null
grep -v '^@@\(slave\|bypath\|tdev\|hostatt\) ' "$TMP/p0"
echo
verdict before p0 || stopped_here "Read the [STOP] lines above."
read -r STATE STALE A VMSTATE GSERIAL <<<"$(vars p0)"
[[ "$STATE" =~ ^(start|repointed|refreshed)$ ]] || stopped_here "Unknown state '$STATE'."
for x in "$STALE" "$A"; do [[ "$x" = - || "$x" =~ $UUID_RE ]] || stopped_here "Unexpected attachment ID '$x'."; done
echo
echo "The guest sees its disk serial as '$GSERIAL' now; after the repair it is $X. Only /dev/disk/by-id/virtio-… names in the"
echo "guest change: ask the owner whether its fstab or applications use them (UUID= and /dev/vda are not affected)."

if [ "$STATE" = start ]; then
  [ "$A" != - ] || stopped_here "No attachment of $X to repoint onto."
  if [ "$VMSTATE" = active ]; then
    confirm STOP "Step 1: back up the BDM and Cinder rows (root-only directory on the controller), then STOP the instance (power off only; customer downtime starts)."
  else
    confirm BACKUP "Step 1: back up the BDM and Cinder rows (root-only directory on the controller); the instance is already stopped."
  fi
  echo "######## 1. Backup, stop"
  run p1 "$PHASE1" >/dev/null; cat "$TMP/p1"
  grep -q '^@@stopped' "$TMP/p1" || stopped_here "The instance did not reach stopped in 5 minutes: look at it, then run again (it goes on from here)."
  confirm REPOINT "Step 2: clear the migration status of $X and point Nova's BDM at $X, attachment $A, neutral connection (1 row)."
  echo "######## 2. Repoint"
  run p2 "$PHASE2" >/dev/null; cat "$TMP/p2"
  grep -q '^@@repointed' "$TMP/p2" || stopped_here "The BDM was not repointed (see above); the instance is stopped."
  STATE=repointed
fi
if [ "$STATE" = repointed ]; then
  confirm CLEAN "Step 3: remove the devices of WWID $WWID on the compute (flush its multipath map, delete its paths; the domain is shut off)."
  echo "######## 3. Devices of the disk on the compute"
  run p3 "$PHASE3" >/dev/null; cat "$TMP/p3"
  failed p3 && stopped_here "The devices were not removed (see @@stop); the instance is stopped, its BDM neutral: run again after the cause is fixed."
  confirm REFRESH "Step 4: nova-manage volume_attachment refresh (Cinder: new attachment, $X mapped again for the compute, maybe at another LUN number)."
  echo "######## 4. Refresh"
  run p4 "$PHASE4" >/dev/null; cat "$TMP/p4"
  failed p4 && stopped_here "No refresh (see @@stop)."
fi
echo "######## 5. Checks after (read-only)"
run p5 "$PHASE5" >/dev/null; grep -v '^@@' "$TMP/p5"
VMNOW=$(awk '$1=="@@vm"{print $2; exit}' "$TMP/p5")
if [ "$VMNOW" = active ]; then
  verdict started p5 || stopped_here "The instance runs; read the [STOP] lines above."
  echo; echo "The instance already runs on $X. Run the portal check \"Volume connections of an instance\" again."
  chown deploy: "$OUT" 2>/dev/null; echo "Saved: $OUT"; exit 0
fi
verdict after p5 || stopped_here "The instance stays stopped; read the [STOP] lines above. Run again when it is fixed."
read -r NEWLUN CLEANUP <<<"$(vars p5)"
[[ "$NEWLUN" =~ ^[0-9]+$ ]] || stopped_here "No LUN number in the BDM."
if [ "$CLEANUP" = 1 ]; then   # devices of the disk from before the refresh: os-brick connects it fresh at the start
  confirm CLEAN "Devices of WWID $WWID are on the compute again (a rescan): remove them before the start (the domain is shut off)."
  run p3b "$PHASE3" >/dev/null; cat "$TMP/p3b"
  failed p3b && stopped_here "The devices were not removed (see @@stop)."
fi
confirm START "Step 6: START the instance (Nova connects $X at LUN $NEWLUN; guest disk serial $X)."
echo "######## 6. Start"
run p6 "$PHASE6" >/dev/null; cat "$TMP/p6"
run p7 "$PHASE5" >/dev/null; grep -v '^@@' "$TMP/p7"
verdict started p7 "$NEWLUN" || stopped_here "Read the [STOP] lines above (fault, domain, console)."
echo
echo "Repaired: $SID runs on $X (LUN $NEWLUN). Next: the owner checks the guest, then run the portal check"
echo "\"Volume connections of an instance\" again (it should show $X in Cinder by its ID and its LUN as the disk)."
chown deploy: "$OUT" 2>/dev/null
echo "Saved: $OUT"

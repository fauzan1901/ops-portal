#!/usr/bin/env bash
# Read-only: who could have removed the disk of an instance that lost its paths without any action of its own (a real case). The LUN stayed mapped (a rescan brought the
# same WWID back), so a disconnect on the compute named that LUN number: a stale Nova connection of another instance,
# or a live-migration rollback that disconnects the source LUN number on the destination. The database keeps what the
# logs (1-2 days on DCA) lost. Per disk of each instance (no secret is printed; times WIB = UTC + 7):
#   - the compute's journal: oldest kernel line kept, first I/O error of the disk, removals / attaches of the LUN;
#     /var/log/messages (weeks): the removals of the LUN's devices on the target's sessions and the host around the first;
#   - A. every Cinder attachment ever made on this compute with this LUN number of this target;
#   - B. other instances that got this LUN number of this target (Cinder, any compute, any time) or whose Nova
#        connection names it (also deleted rows): the ones a wrong disconnect could come from;
#   - C. migrations touching this compute in <days>: those of the instances in B, and every one that did not complete;
#   - D. actions of the instances in B with an event on this compute in <days>;
#   - E. when /var/log/messages has the removal: every Nova event, migration and Cinder attachment on this compute from
#        30 min before to 5 min after it.
# Per instance also V: its own migrations and actions in <days>, and every Cinder attachment of it (deleted ones too).
# First line: how far back the database still goes (TripleO purges deleted Cinder rows after some weeks).
# --db-only: the database only, the compute's logs are not read (fast; for a window older than the logs).
# Same path as the portal: portal service account -> management host -> director -> controller / compute.
# Run on the bastion:  sudo bash ~/lun-history.sh <SITE> <days> [--db-only] <server ID> [<server ID>...]
set -u
SITE="${1:-}"
DAYS="${2:-}"
shift 2 2>/dev/null
DBONLY=0
[ "${1:-}" = "--db-only" ] && { DBONLY=1; shift; }
SIDS="$*"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$DAYS" =~ ^[0-9]{1,3}$ ]] && [ "$DAYS" -ge 1 ] || { echo "Days: 1 to 999"; exit 1; }
[ -n "$SIDS" ] || { echo "Server ID(s): one or more UUIDs"; exit 1; }
for s in $SIDS; do
  [[ "$s" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || { echo "Not a UUID: $s"; exit 1; }
done
OUT="/home/deploy/lun-history-$(date +%Y%m%d-%H%M%S).txt"
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

# on the compute, read-only. Input: SID, DEV, LUN
ONNODE=$(cat <<'NODE'
c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$')
V="podman exec $c virsh -c qemu:///system"
s=$($V domblklist $SID 2>/dev/null | awk -v d="$DEV" '$1 == d {print $2}')
dm=$(basename "$(readlink -f "$s" 2>/dev/null)" 2>/dev/null)
echo "  journal of $(hostname -s): up since $(uptime -s); oldest kernel line kept: $(journalctl -k -o short-iso --no-pager 2>/dev/null | grep -m1 -v '^--' | cut -c1-24)"
K=$(journalctl -k -o short-iso --no-pager 2>/dev/null | grep -E "I/O error, dev ${dm:-none},|[0-9]+:0:0:$LUN: alua: Detached|[0-9]+:0:0:$LUN: \[sd[a-z]+\] Attached")
F=$(printf '%s\n' "$K" | grep -m1 'I/O error' | cut -c1-24)
echo "  $DEV is ${dm:-not found} now; first I/O error of it kept: ${F:-none}"
echo "  removals / attaches of LUN $LUN (any target) kept in the journal: $(printf '%s\n' "$K" | grep -cE 'Detached|Attached')"
printf '%s\n' "$K" | grep -E 'Detached|Attached' | head -8 | sed 's/^/    /'
# rsyslog keeps weeks where the journal keeps 1-2 days: the removal of the LUN's devices on this target's sessions
ts() { awk '{print ($1 ~ /^[0-9][0-9][0-9][0-9]-/ ? $1 : $1" "$2" "$3); exit}'; }
ISCSIADM() { if command -v iscsiadm >/dev/null; then iscsiadm "$@"; else podman exec iscsid iscsiadm "$@"; fi; }
HOSTS=$(ISCSIADM -m session -P 3 2>/dev/null | awk -v t="$IQN" '/^Target: /{on=($2 == t)} on && /Host Number:/{print $3}' | sort -un | paste -sd'|' -)
M=$(ls -tr /var/log/messages* 2>/dev/null | tr '\n' ' ')
if [ -z "$M" ] || [ -z "$HOSTS" ]; then
  echo "  /var/log/messages: ${M:-none}; session hosts of the target: ${HOSTS:-none}: not searched"
else
  echo "  /var/log/messages: $(echo $M | wc -w) file(s), oldest line: $(zcat -f $(echo $M | cut -d' ' -f1) 2>/dev/null | ts)"
  RM=":0:0:$LUN: (alua: Detached|\[sd[a-z]+\] Synchronizing SCSI cache)"
  L=$(zcat -f $M 2>/dev/null | LC_ALL=C grep -E " ($HOSTS)$RM| ($HOSTS):0:0:$LUN: .*(offline|rejecting I/O|FAILED Result|Sense Key|Add\. Sense)|I/O error, dev ${dm:-none},")
  echo "  in it, removals of LUN $LUN on the target's sessions (hosts ${HOSTS//|/ }): $(printf '%s\n' "$L" | grep -cE "$RM")"
  printf '%s\n' "$L" | grep -vE 'I/O error' | head -10 | cut -c1-200 | sed 's/^/    /'
  echo "  first I/O error of ${dm:-the disk} in it: $(printf '%s\n' "$L" | grep 'I/O error' | ts)"
  R=$(printf '%s\n' "$L" | grep -E " ($HOSTS)$RM" | ts)
  if [ -n "$R" ]; then
    echo "  the whole host around the first removal ($R): 12 lines before, 6 after"
    zcat -f $M 2>/dev/null | LC_ALL=C grep -m1 -B12 -A6 -E " ($HOSTS)$RM" | cut -c1-200 | sed 's/^/    | /'
    echo "@@removal $(date -d "$R" +%s)"
  fi
fi
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
sql() { printf 'podman exec $(podman ps -q -f name=galera-bundle | head -1) mysql -N -B -e %q\n' "$1" | asroot "$CTL"; }
LUNQ="COALESCE(JSON_VALUE(a.connection_info,'\$.target_lun'), JSON_VALUE(a.connection_info,'\$.data.target_lun'))"
IQNQ="COALESCE(JSON_VALUE(a.connection_info,'\$.target_iqn'), JSON_VALUE(a.connection_info,'\$.data.target_iqn'))"
W=$(mktemp -d /tmp/lh-XXXXXX); trap 'rm -rf "$W"' EXIT
IFS=$'\t' read -r OLDM OLDA OLDC < <(sql "SELECT IFNULL((SELECT DATE_ADD(MIN(created_at), INTERVAL 7 HOUR) FROM nova.migrations),'-'), IFNULL((SELECT DATE_ADD(MIN(start_time), INTERVAL 7 HOUR) FROM nova.instance_actions),'-'), IFNULL((SELECT DATE_ADD(MIN(deleted_at), INTERVAL 7 HOUR) FROM cinder.volume_attachment WHERE deleted = 1),'-')")
echo "== The database still has: Nova migrations since ${OLDM:-?}, instance actions since ${OLDA:-?}, deleted Cinder attachments since ${OLDC:-?} (older deleted ones were purged)"
for SID in $SIDS; do
  IFS=$'\t' read -r name host < <(sql "SELECT display_name, SUBSTRING_INDEX(IFNULL(host,'-'), '.', 1) FROM nova.instances WHERE deleted = 0 AND uuid = '$SID'")
  echo
  echo "################ $SID ${name:-?} on ${host:-?}"
  [ -n "${host:-}" ] || { echo "  not found in nova.instances"; continue; }
  echo "  V. Its own migrations in the last $DAYS days:"
  sql "SELECT m.id, m.migration_type, m.status, SUBSTRING_INDEX(IFNULL(m.source_compute,'-'), '.', 1), SUBSTRING_INDEX(IFNULL(m.dest_compute,'-'), '.', 1), DATE_ADD(m.created_at, INTERVAL 7 HOUR), IFNULL(DATE_ADD(m.updated_at, INTERVAL 7 HOUR),'-') FROM nova.migrations m WHERE m.instance_uuid = '$SID' AND m.created_at > NOW() - INTERVAL $DAYS DAY ORDER BY m.created_at" |
    awk -F'\t' '{printf "      #%s %s %s -> %s, %s %s .. %s\n", $1, $2, $4, $5, $3, $6, $7}'
  echo "     its own actions in the last $DAYS days (event=result@host):"
  sql "SELECT DATE_ADD(ia.start_time, INTERVAL 7 HOUR), ia.action, IFNULL(ia.message,'-'), IFNULL(GROUP_CONCAT(CONCAT(e.event, '=', IFNULL(e.result,'?'), '@', SUBSTRING_INDEX(IFNULL(e.host,'-'), '.', 1)) ORDER BY e.id SEPARATOR ' '),'-') FROM nova.instance_actions ia LEFT JOIN nova.instance_actions_events e ON e.action_id = ia.id WHERE ia.instance_uuid = '$SID' AND ia.start_time > NOW() - INTERVAL $DAYS DAY GROUP BY ia.id ORDER BY ia.start_time" |
    awk -F'\t' '{printf "      %s %s %s  %s\n", $1, $2, $3, $4}'
  echo "     every Cinder attachment of it still in the database (deleted ones too):"
  sql "SELECT a.id, a.volume_id, a.attach_status, a.deleted, SUBSTRING_INDEX(IFNULL(JSON_VALUE(a.connector,'\$.host'),'-'), '.', 1), IFNULL($LUNQ,'-'), DATE_ADD(a.created_at, INTERVAL 7 HOUR), IFNULL(DATE_ADD(a.deleted_at, INTERVAL 7 HOUR),'-') FROM cinder.volume_attachment a WHERE a.instance_uuid = '$SID' ORDER BY a.created_at" |
    awk -F'\t' '{printf "      %s%s attachment %s volume %s on %s LUN %s, created %s, deleted %s\n", $3, ($4 == "0" ? "" : " (deleted)"), $1, $2, $5, $6, $7, $8}'
  sql "SELECT b.device_name, b.volume_id, IFNULL(JSON_VALUE(b.connection_info,'\$.data.target_iqn'),'-'), IFNULL(JSON_VALUE(b.connection_info,'\$.data.target_lun'),'-') FROM nova.block_device_mapping b WHERE b.deleted = 0 AND b.destination_type = 'volume' AND b.instance_uuid = '$SID' ORDER BY b.device_name" > "$W/bdm"
  while IFS=$'\t' read -r dev vol iqn lun; do
    echo "---- $dev volume $vol: LUN $lun of $iqn"
    [[ "$iqn" =~ ^iqn\.[0-9a-z.:-]+$ ]] && [[ "$lun" =~ ^[0-9]+$ ]] || { echo "  no iSCSI target / LUN in Nova's connection: skipped"; continue; }
    if [ "$DBONLY" = 1 ]; then
      echo "  (the logs of $host are not read: --db-only)" > "$W/node"
    else
      printf 'SID=%q\nDEV=%q\nLUN=%q\nIQN=%q\n%s\n' "$SID" "${dev##*/}" "$lun" "$iqn" "$ONNODE" | asroot "$host" > "$W/node" 2>&1
    fi
    grep -v '^@@' "$W/node"
    T=$(awk '$1 == "@@removal" && $2 ~ /^[0-9]+$/ {print $2; exit}' "$W/node")
    echo "  A. Cinder attachments ever made on $host with LUN $lun of this target (deleted ones too):"
    sql "SELECT a.id, a.volume_id, IFNULL(a.instance_uuid,'-'), IFNULL(i.display_name,'-'), a.attach_status, a.deleted, DATE_ADD(a.created_at, INTERVAL 7 HOUR), IFNULL(DATE_ADD(a.deleted_at, INTERVAL 7 HOUR),'-') FROM cinder.volume_attachment a LEFT JOIN nova.instances i ON i.uuid = a.instance_uuid WHERE SUBSTRING_INDEX(IFNULL(JSON_VALUE(a.connector,'\$.host'),''), '.', 1) = '$host' AND $LUNQ = '$lun' AND $IQNQ = '$iqn' ORDER BY a.created_at" |
      awk -F'\t' -v s="$SID" '{printf "      %s %s attachment %s volume %s instance %s %s, created %s, deleted %s%s\n", $5, ($6 == "0" ? "" : "(deleted)"), $1, $2, $3, $4, $7, $8, ($3 == s ? "  <= this disk" : "  <= another volume with this LUN number here (compare the dates)")}'
    sql "SELECT IFNULL(a.instance_uuid,'-'), IFNULL(i.display_name,'-'), SUBSTRING_INDEX(IFNULL(i.host,'-'), '.', 1), IFNULL(i.deleted,'-'), SUBSTRING_INDEX(IFNULL(JSON_VALUE(a.connector,'\$.host'),'-'), '.', 1), a.volume_id, a.attach_status, DATE_ADD(a.created_at, INTERVAL 7 HOUR), IFNULL(DATE_ADD(a.deleted_at, INTERVAL 7 HOUR),'-') FROM cinder.volume_attachment a LEFT JOIN nova.instances i ON i.uuid = a.instance_uuid WHERE $LUNQ = '$lun' AND $IQNQ = '$iqn' AND IFNULL(a.instance_uuid,'') NOT IN ('', '$SID') ORDER BY a.created_at" > "$W/b1"
    sql "SELECT b.instance_uuid, IFNULL(i.display_name,'-'), SUBSTRING_INDEX(IFNULL(i.host,'-'), '.', 1), IFNULL(i.deleted,'-'), b.device_name, b.volume_id, b.deleted, IFNULL(DATE_ADD(b.updated_at, INTERVAL 7 HOUR),'-') FROM nova.block_device_mapping b LEFT JOIN nova.instances i ON i.uuid = b.instance_uuid WHERE b.destination_type = 'volume' AND JSON_VALUE(b.connection_info,'\$.data.target_lun') = '$lun' AND JSON_VALUE(b.connection_info,'\$.data.target_iqn') = '$iqn' AND b.instance_uuid <> '$SID'" > "$W/b2"
    echo "  B. Other instances given LUN $lun of this target by Cinder ($(cut -f1 "$W/b1" | sort -u | grep -c .) instance(s), any compute, any time; the last 15 attachments):"
    tail -15 "$W/b1" | awk -F'\t' '{printf "      %s %s (now on %s%s): attachment on %s, volume %s, %s, created %s, deleted %s\n", $1, $2, $3, ($4 == "0" ? "" : ($4 == "-" ? ", not in Nova" : ", instance deleted")), $5, $6, $7, $8, $9}'
    echo "     Nova connections of other instances that name LUN $lun of this target ($(grep -c . "$W/b2")):"
    awk -F'\t' -v h="$host" '{printf "      %s %s (now on %s%s): %s volume %s, bdm %s, updated %s%s\n", $1, $2, $3, ($4 == "0" ? "" : ($4 == "-" ? ", not in Nova" : ", instance deleted")), $5, $6, ($7 == "0" ? "live" : "deleted"), $8, ($7 == "0" && $3 == h ? "  <= LIVE on the same compute: a disconnect of it removes this disk" : "")}' "$W/b2"
    HOLD=$(cut -f1 "$W/b1" "$W/b2" | sort -u | grep -E '^[0-9a-f-]{36}$' | sed "s/.*/'&'/" | paste -sd, -)
    HOLD=${HOLD:-"''"}
    echo "  C. Migrations touching $host in the last $DAYS days: of the instances in B (<=), and every one that did not complete:"
    sql "SELECT m.id, m.instance_uuid, IFNULL(i.display_name,'-'), m.migration_type, m.status, SUBSTRING_INDEX(IFNULL(m.source_compute,'-'), '.', 1), SUBSTRING_INDEX(IFNULL(m.dest_compute,'-'), '.', 1), DATE_ADD(m.created_at, INTERVAL 7 HOUR), IFNULL(DATE_ADD(m.updated_at, INTERVAL 7 HOUR),'-'), IF(m.instance_uuid IN ($HOLD), 1, 0) FROM nova.migrations m LEFT JOIN nova.instances i ON i.uuid = m.instance_uuid WHERE m.created_at > NOW() - INTERVAL $DAYS DAY AND '$host' IN (SUBSTRING_INDEX(IFNULL(m.source_compute,''), '.', 1), SUBSTRING_INDEX(IFNULL(m.dest_compute,''), '.', 1)) ORDER BY m.created_at" > "$W/mig"
    awk -F'\t' '$10 == 1 || $5 !~ /^(completed|confirmed|finished|done)$/ {printf "      #%s %s %s %s %s -> %s, %s %s .. %s%s\n", $1, $2, $3, $4, $6, $7, $5, $8, $9, ($10 == 1 ? "  <= had LUN number of this disk" : "")}' "$W/mig"
    echo "     ($(grep -c . "$W/mig") migration(s) touched $host in $DAYS days in all)"
    echo "  D. Actions of the instances in B with an event on $host in the last $DAYS days:"
    sql "SELECT ia.instance_uuid, IFNULL(i.display_name,'-'), ia.action, e.event, IFNULL(e.result,'-'), DATE_ADD(e.start_time, INTERVAL 7 HOUR), IFNULL(DATE_ADD(e.finish_time, INTERVAL 7 HOUR),'-') FROM nova.instance_actions ia JOIN nova.instance_actions_events e ON e.action_id = ia.id LEFT JOIN nova.instances i ON i.uuid = ia.instance_uuid WHERE ia.instance_uuid IN ($HOLD) AND SUBSTRING_INDEX(IFNULL(e.host,''), '.', 1) = '$host' AND e.start_time > NOW() - INTERVAL $DAYS DAY ORDER BY e.start_time" |
      awk -F'\t' '{printf "      %s %s %s / %s = %s, %s .. %s\n", $1, $2, $3, $4, $5, $6, $7}'
    [ -n "$T" ] || continue
    FROM=$(date -u -d "@$((T - 1800))" '+%F %T'); TO=$(date -u -d "@$((T + 300))" '+%F %T')
    echo "  E. Everything on $host from 30 min before to 5 min after the first removal ($(TZ=Asia/Jakarta date -d "@$T" '+%F %T') WIB):"
    echo "     Nova events (any instance):"
    sql "SELECT ia.instance_uuid, IFNULL(i.display_name,'-'), ia.action, e.event, IFNULL(e.result,'-'), DATE_ADD(e.start_time, INTERVAL 7 HOUR), IFNULL(DATE_ADD(e.finish_time, INTERVAL 7 HOUR),'-') FROM nova.instance_actions ia JOIN nova.instance_actions_events e ON e.action_id = ia.id LEFT JOIN nova.instances i ON i.uuid = ia.instance_uuid WHERE SUBSTRING_INDEX(IFNULL(e.host,''), '.', 1) = '$host' AND e.start_time <= '$TO' AND IFNULL(e.finish_time, e.start_time) >= '$FROM' ORDER BY e.start_time" |
      awk -F'\t' '{printf "      %s %s %s / %s = %s, %s .. %s\n", $1, $2, $3, $4, $5, $6, $7}'
    echo "     migrations:"
    sql "SELECT m.id, m.instance_uuid, IFNULL(i.display_name,'-'), m.migration_type, m.status, SUBSTRING_INDEX(IFNULL(m.source_compute,'-'), '.', 1), SUBSTRING_INDEX(IFNULL(m.dest_compute,'-'), '.', 1), DATE_ADD(m.created_at, INTERVAL 7 HOUR), IFNULL(DATE_ADD(m.updated_at, INTERVAL 7 HOUR),'-') FROM nova.migrations m LEFT JOIN nova.instances i ON i.uuid = m.instance_uuid WHERE '$host' IN (SUBSTRING_INDEX(IFNULL(m.source_compute,''), '.', 1), SUBSTRING_INDEX(IFNULL(m.dest_compute,''), '.', 1)) AND m.created_at <= '$TO' AND IFNULL(m.updated_at, m.created_at) >= '$FROM' ORDER BY m.created_at" |
      awk -F'\t' '{printf "      #%s %s %s %s %s -> %s, %s %s .. %s\n", $1, $2, $3, $4, $6, $7, $5, $8, $9}'
    echo "     Cinder attachments on $host made or deleted then (with their LUN):"
    sql "SELECT a.id, a.volume_id, IFNULL(a.instance_uuid,'-'), IFNULL(i.display_name,'-'), a.attach_status, IFNULL($LUNQ,'-'), DATE_ADD(a.created_at, INTERVAL 7 HOUR), IFNULL(DATE_ADD(a.deleted_at, INTERVAL 7 HOUR),'-') FROM cinder.volume_attachment a LEFT JOIN nova.instances i ON i.uuid = a.instance_uuid WHERE SUBSTRING_INDEX(IFNULL(JSON_VALUE(a.connector,'\$.host'),''), '.', 1) = '$host' AND (a.created_at BETWEEN '$FROM' AND '$TO' OR a.deleted_at BETWEEN '$FROM' AND '$TO') ORDER BY a.created_at" |
      awk -F'\t' '{printf "      attachment %s volume %s instance %s %s, %s, LUN %s, created %s, deleted %s\n", $1, $2, $3, $4, $5, $6, $7, $8}'
  done < "$W/bdm"
done
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, last $DAYS days$([ $DBONLY = 1 ] && echo ', database only'), instances: $SIDS; management host $MGMT_HOST, director $DIR_USER@$DIR_HOST (keys and secrets are not printed; times WIB)"
  printf 'SIDS=%q\nDAYS=%q\nDBONLY=%q\nONNODE=%q\nRC=%s\n%s\n' "$SIDS" "$DAYS" "$DBONLY" "$ONNODE" "$RC" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1 | grep -v 'post-quantum\|store now, decrypt\|openssh.com/pq'
  echo "== exit $?"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

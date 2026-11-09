#!/usr/bin/env bash
# Read-only: the evidence needed before repairing instances that migration-readiness.sh reported at RISK, for EVERY
# disk of each instance (no secret is printed):
#   - Nova: state, host, each volume's BDM (attachment id, target, LUN, driver type); Cinder: size, status and every
#     attachment of the volume (status, instance, attached host, connector host / initiator, LUN Cinder gave it);
#   - on the instance's compute, per disk: the domain's device, its map name = WWID, the NetApp LUN serial in it, size,
#     open count, each path and its state; SCSI devices carrying that WWID; the devices at Nova's LUN number on every
#     session of the target (WWID, serial, size, map, who opens it); the LUN numbers the target reports to this host
#     (REPORT LUNS) that have no device here; kernel lines of 7 days for those LUNs and maps;
#   - Neutron: every binding of the instance's ports (host, ACTIVE / INACTIVE, profile: a leftover migrating_to);
#   - the instance's nova-compute log lines of attach / detach / migration / reboot / errors (secrets masked).
# Same path as the portal: portal service account -> management host -> director -> controller / compute.
# Run on the bastion:  sudo bash ~/risk-evidence.sh <SITE> <server ID> [<server ID>...]
set -u
SITE="${1:-}"
shift 2>/dev/null
SIDS="$*"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[ -n "$SIDS" ] || { echo "Server ID(s): one or more UUIDs"; exit 1; }
for s in $SIDS; do
  [[ "$s" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || { echo "Not a UUID: $s"; exit 1; }
done
OUT="/home/deploy/risk-evidence-$(date +%Y%m%d-%H%M%S).txt"
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

# on the compute, read-only. Input: SID, and BDMS = lines "<device> <volume> <target iqn> <lun>"
ONNODE=$(cat <<'NODE'
c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$')
V="podman exec $c virsh -c qemu:///system"
MPD=$(podman ps --format '{{.Names}}' | grep -m1 -x multipathd)
MP() { if [ -n "$MPD" ]; then podman exec "$MPD" multipath "$@"; else multipath "$@"; fi; }
MPLL=$(MP -ll 2>/dev/null)
wwid_sd() { sed 's/^naa\./3/' /sys/block/$1/device/wwid 2>/dev/null; }
ser() { [[ "${1:-}" == 3600a0980* ]] && printf '%b' "$(printf '%s' "${1:9}" | sed 's/../\\x&/g')"; }   # NetApp: 3600a0980 + hex of the LUN serial
gib() { awk -v s="$(cat /sys/block/$1/size 2>/dev/null || echo 0)" 'BEGIN {printf "%.1fG", s * 512 / 1073741824}'; }
opn() { dmsetup info -c --noheadings -o open "$1" 2>/dev/null | tr -d ' '; }
mpaths() { printf '%s\n' "$MPLL" | awk -v d="$1" '$2 == d || $3 == d {on=1; next} /^[0-9a-f]{33} / {on=0} on && / sd[a-z]+ / {sub(/^[ |`-]+/, ""); print}'; }
USERS=$(for x in $($V list --name); do $V domblklist $x 2>/dev/null | awk -v x=$x '$2 ~ /^\/dev\// {print $2, x}'; done |
  while read -r s x; do echo "$(basename "$(readlink -f "$s")") $x"; done)
who() { printf '%s\n' "$USERS" | awk -v d="$1" '$1 == d {print $2}' | paste -sd, -; }
KLOG=$(journalctl -k --since '-7 days' --no-pager 2>/dev/null | grep -E 'alua: Detached|Attached SCSI disk|I/O error, dev dm-|remaining active paths|Fail all paths|Failing path|reinstat|offline')
SGL=""; command -v sg_luns >/dev/null && SGL=sg_luns
[ -z "$SGL" ] && [ -n "$MPD" ] && podman exec "$MPD" sh -c 'command -v sg_luns' >/dev/null 2>&1 && SGL="podman exec $MPD sg_luns"
DN=$($V domname $SID 2>/dev/null | head -1)
echo "domain: ${DN:-none}, state $($V domstate $SID 2>&1 | head -1), its qemu started $(ps -o lstart= -p "$(pgrep -f "guest=$DN," | head -1)" 2>/dev/null | grep . || echo '-')"
echo "host: up since $(uptime -s); oldest kernel line the journal still keeps: $(journalctl -k -o short-iso --no-pager 2>/dev/null | head -1 | cut -c1-24)"
for ss in /sys/class/iscsi_session/session*; do
  [ -e "$ss/targetname" ] || continue
  h=$(ls -d $ss/device/target* 2>/dev/null | head -1 | sed -E 's/.*target([0-9]+):.*/\1/')
  echo "SESSION host$h $(cat $ss/targetname) state=$(cat $ss/state 2>/dev/null)"
done | sort -u | sed 's/^/  /'
printf '%s\n' "$BDMS" | while read -r dev vol iqn lun; do
  [ -n "$dev" ] || continue
  t=${dev#/dev/}
  src=$($V domblklist $SID 2>/dev/null | awk -v t="$t" '$1 == t {print $2}')
  echo "--- $dev  volume $vol  (Nova: LUN $lun of $iqn)"
  w=""; d=""
  if [ -n "$src" ]; then
    d=$(basename "$(readlink -f "$src")")
    if [[ "$d" == dm-* ]]; then w=$(cat /sys/block/$d/dm/name 2>/dev/null); o=$(opn "$w"); else w=$(wwid_sd "$d"); o="- (a single SCSI device, no multipath map)"; fi
    echo "  domain disk: $src -> $d  wwid=$w  serial='$(ser "$w")'  size=$(gib "$d")  open=$o  device node since $(stat -c %z /dev/$d 2>/dev/null | cut -c1-19)"
    if [[ "$d" == dm-* ]]; then
      p=$(mpaths "$d"); echo "  its paths:"; printf '%s\n' "${p:-none}" | sed 's/^/    /'
    else
      echo "    $(basename "$(readlink -f /sys/block/$d/device)") $d state=$(cat /sys/block/$d/device/state 2>/dev/null)"
    fi
    echo "  SCSI devices carrying this WWID:"
    for b in /sys/block/sd*; do
      sd=${b##*/}; [ "$(wwid_sd $sd)" = "$w" ] || continue
      echo "    $(basename "$(readlink -f $b/device)") $sd state=$(cat $b/device/state 2>/dev/null) holder=$(ls $b/holders 2>/dev/null | head -1 | grep . || echo none)"
    done
  else
    echo "  domain disk: none ($dev is not in domblklist)"
  fi
  hosts=$(for ss in /sys/class/iscsi_session/session*; do [ "$(cat $ss/targetname 2>/dev/null)" = "$iqn" ] && ls -d $ss/device/target* | head -1 | sed -E 's/.*target([0-9]+):.*/\1/'; done | sort -un)
  echo "  devices at Nova's LUN $lun on the target's sessions (hosts: $(echo $hosts)):"
  n=0
  for h in $hosts; do for L in $lun $((lun + 16384)); do for a in /sys/class/scsi_device/$h:*:*:$L; do
    [ -e "$a" ] || continue
    sd=$(ls $a/device/block 2>/dev/null | head -1); [ -n "$sd" ] || continue
    sw=$(wwid_sd $sd); hold=$(ls /sys/block/$sd/holders 2>/dev/null | head -1)
    m=""; [ -n "$hold" ] && m="map=$hold open=$(opn "$(cat /sys/block/$hold/dm/name 2>/dev/null)") used-by=$(who $hold)"
    echo "    ${a##*/} $sd state=$(cat $a/device/state 2>/dev/null) wwid=$sw serial='$(ser "$sw")' size=$(gib $sd) ${m:-map=none used-by=$(who $sd)}$([ -n "$w" ] && [ "$sw" = "$w" ] && echo '  SAME as the domain disk' || echo '  NOT the domain disk')"
    n=$((n + 1))
  done; done; done
  [ "$n" = 0 ] && echo "    none"
  for h in $hosts; do
    sd=$(for b in /sys/block/sd*; do a=$(basename "$(readlink -f $b/device)"); [[ "$a" == $h:* ]] && [ "$(cat $b/device/state)" = running ] && { echo ${b##*/}; break; }; done)
    if [ -z "$SGL" ] || [ -z "$sd" ]; then echo "  REPORT LUNS host$h: not read (${SGL:+no running device}${SGL:-sg_luns not installed})"; continue; fi
    rep=$($SGL -q /dev/$sd 2>/dev/null | awk '{print and(strtonum("0x" substr($1, 1, 4)), 16383)}' | sort -n)
    have=$(ls /sys/class/scsi_device | awk -F: -v h=$h '$1 == h {print and($4, 16383)}' | sort -n)
    miss=$(comm -23 <(printf '%s\n' $rep | sort) <(printf '%s\n' $have | sort) | sort -n | paste -sd' ' -)
    echo "  REPORT LUNS host$h: the target maps $(printf '%s\n' $rep | grep -c .) LUN(s) to this host; mapped but no device here: ${miss:-none}"
  done
  ls=$(mpaths "${d:-x}" | grep -oE '^[0-9]+:[0-9]+:[0-9]+:[0-9]+' | awk -F: '{print and($4, 16383)}' | sort -u | paste -sd'|' -)
  pat=":($lun|$((lun + 16384))${ls:+|$ls}): |[^0-9a-z-]${d:-none}[^0-9]"
  [[ "$d" == dm-* ]] && pat+="|multipath: [0-9]+:${d#dm-}: "
  kl=$(printf '%s\n' "$KLOG" | grep -E "$pat")
  ke=$(printf '%s\n' "$kl" | grep -c 'I/O error')
  echo "  kernel, 7 days (LUN $lun${ls:+, $ls} and ${d:-none}): $ke I/O error line(s)$([ "$ke" -gt 0 ] && echo ", first $(printf '%s\n' "$kl" | grep -m1 'I/O error' | cut -c1-15), last $(printf '%s\n' "$kl" | grep 'I/O error' | tail -1 | cut -c1-15)"); path events:"
  printf '%s\n' "$kl" | grep -v 'I/O error' | grep . | tail -12 | cut -c1-170 | sed 's/^/    /'
  # who flushed / disconnected this disk: nova-compute (os-brick DEBUG) lines naming its WWID, or a disconnect of its LUN
  if [ -n "$w" ]; then
    echo "  nova-compute log lines naming WWID $w or a disconnect of LUN $lun (logs since $(for f in $(ls -tr /var/log/containers/nova/nova-compute.log* 2>/dev/null | head -1); do zcat -f "$f" | head -1 | cut -c1-19; done)):"
    for f in $(ls -tr /var/log/containers/nova/nova-compute.log* 2>/dev/null); do zgrep -hE "$w|disconnect_volume.*'target_lun': $lun[,}]" "$f"; done |
      grep -iE 'flush|remov|disconnect|delet' | sed -E "s/(auth_password|auth_username|password|secret)([\"']?[:=] ?[\"']?)[^\"', }]*/\1\2***/g" |
      sed -E 's/^([0-9-]+ [0-9:.]+) [0-9]+ ([A-Z]+) ([a-z_.]+) \[(req-[0-9a-f-]+)[^]]*\] ?(\[instance: [0-9a-f-]+\])?/\1 \2 \4 \5/' |
      cut -c1-220 | awk 'NR <= 4 {print; next} {last[NR % 6] = $0; n = NR} END {if (n > 4) {print "    ..."; for (i = n - 5; i <= n; i++) if (i > 4) print last[i % 6]}}' | sed 's/^/    /'
  fi
  # what nova-compute was doing on this host in the minutes the devices of these LUNs were removed
  printf '%s\n' "$kl" | grep 'alua: Detached' | cut -c1-12 | sort -u | tail -3 | while read -r m; do
    t=$(date -d "$m" +%s 2>/dev/null) || continue
    keys=$(for o in -2 -1 0 1; do date -d "@$((t + o * 60))" '+%Y-%m-%d %H:%M'; done)
    echo "  nova-compute around $m (devices removed), lines of migration / detach / reboot / delete / rollback:"
    for f in $(ls -tr /var/log/containers/nova/nova-compute.log* 2>/dev/null); do zgrep -hF "$keys" "$f"; done |
      grep -E 'instance: [0-9a-f-]{36}' | grep -iE 'migrat|detach|reboot|delet|terminat|rollback|disconnect|Flushing|DestinationDiskExists|cleanup|power' |
      grep -vE 'instance_info_cache|\] {2,}|Traceback \(most' | sed -E "s/(auth_password|password|secret)([\"']?[:=] ?[\"']?)[^\"', }]*/\1\2***/g" |
      cut -c1-230 | head -12 | sed 's/^/    /'
  done
done
echo "--- nova-compute log of the instance (last 30 lines of attach / detach / migration / reboot / errors; secrets masked)"
for f in $(ls -tr /var/log/containers/nova/nova-compute.log* 2>/dev/null); do zgrep -h "$SID" "$f"; done |
  grep -iE 'attach|detach|connect|migrat|reboot|rollback|ERROR|WARNING|Flushing|duplicate|power|start' |
  grep -vE ' DEBUG |instance_info_cache|\[instance: [0-9a-f-]+\] {2,}|Traceback \(most recent' |
  sed -E "s/(auth_password|auth_username|password|secret)([\"']?[:=] ?[\"']?)[^\"', }]*/\1\2***/g" | tail -30 | cut -c1-260 | sed 's/^/  /'
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
W=$(mktemp -d /tmp/re-XXXXXX); trap 'rm -rf "$W"' EXIT
IDS=$(printf "'%s'," $SIDS); IDS=${IDS%,}
sql "SELECT i.uuid, i.display_name, SUBSTRING_INDEX(IFNULL(i.host,'-'), '.', 1), i.vm_state, IFNULL(i.power_state,'-'), IFNULL(i.task_state,'-'), i.locked FROM nova.instances i WHERE i.deleted = 0 AND i.uuid IN ($IDS)" > "$W/inst"
sql "SELECT b.instance_uuid, b.device_name, b.volume_id, IFNULL(b.attachment_id,'-'), IFNULL(JSON_VALUE(b.connection_info,'\$.driver_volume_type'),'-'), IFNULL(JSON_VALUE(b.connection_info,'\$.data.target_iqn'),'-'), IFNULL(JSON_VALUE(b.connection_info,'\$.data.target_lun'),'-'), IFNULL(JSON_EXTRACT(b.connection_info,'\$.data.target_luns'),'-'), IFNULL(v.size,'-'), IFNULL(v.status,'-'), IFNULL(v.multiattach,'-') FROM nova.block_device_mapping b LEFT JOIN cinder.volumes v ON v.id = b.volume_id WHERE b.deleted = 0 AND b.destination_type = 'volume' AND b.instance_uuid IN ($IDS) ORDER BY b.instance_uuid, b.device_name" > "$W/bdm"
sql "SELECT a.volume_id, a.id, a.attach_status, IFNULL(a.instance_uuid,'-'), IFNULL(a.attached_host,'-'), IFNULL(JSON_VALUE(a.connector,'\$.host'),'-'), IFNULL(JSON_VALUE(a.connector,'\$.initiator'),'-'), IFNULL(COALESCE(JSON_VALUE(a.connection_info,'\$.target_lun'), JSON_VALUE(a.connection_info,'\$.data.target_lun')),'-'), a.created_at, IFNULL(a.updated_at,'-') FROM cinder.volume_attachment a WHERE a.deleted = 0 AND a.volume_id IN (SELECT volume_id FROM nova.block_device_mapping WHERE deleted = 0 AND destination_type = 'volume' AND instance_uuid IN ($IDS)) ORDER BY a.volume_id, a.created_at" > "$W/att"
sql "SELECT a.instance_uuid, a.volume_id, IFNULL(v.display_name,'-'), IFNULL(v.size,'-'), IFNULL(v.status,'-'), a.id, a.attach_status, IFNULL(JSON_VALUE(a.connector,'\$.host'),'-'), a.created_at, IFNULL(a.updated_at,'-') FROM cinder.volume_attachment a LEFT JOIN cinder.volumes v ON v.id = a.volume_id WHERE a.deleted = 0 AND a.instance_uuid IN ($IDS) ORDER BY a.created_at" > "$W/att2"
sql "SELECT ia.instance_uuid, ia.start_time, ia.action, ia.request_id, IFNULL(ia.message,'-'), IFNULL(GROUP_CONCAT(CONCAT(e.event, '=', IFNULL(e.result,'?')) ORDER BY e.id SEPARATOR ' '),'-') FROM nova.instance_actions ia LEFT JOIN nova.instance_actions_events e ON e.action_id = ia.id WHERE ia.deleted = 0 AND ia.instance_uuid IN ($IDS) AND ia.start_time > NOW() - INTERVAL 14 DAY GROUP BY ia.id ORDER BY ia.start_time" > "$W/act"
sql "SELECT ia.instance_uuid, e.start_time, e.event, REPLACE(SUBSTRING(IFNULL(e.traceback,''), -1800), '\t', ' ') FROM nova.instance_actions ia JOIN nova.instance_actions_events e ON e.action_id = ia.id WHERE ia.deleted = 0 AND ia.instance_uuid IN ($IDS) AND e.result = 'Error' AND ia.start_time > NOW() - INTERVAL 3 DAY ORDER BY e.start_time DESC" > "$W/tb"
sql "SELECT p.device_id, b.port_id, b.host, b.status, b.vif_type, IFNULL(NULLIF(b.profile,''),'{}'), p.status FROM ovs_neutron.ml2_port_bindings b JOIN ovs_neutron.ports p ON p.id = b.port_id WHERE p.device_id IN ($IDS) ORDER BY p.device_id, b.port_id, b.status" > "$W/port" 2>/dev/null
for SID in $SIDS; do
  IFS=$'\t' read -r u name host vm power task locked < <(grep "^$SID" "$W/inst")
  echo
  echo "################ $SID ${name:-?}  host ${host:-?}  vm_state ${vm:-?} power ${power:-?} task ${task:-?} locked ${locked:-?}"
  [ -n "${host:-}" ] || { echo "  not found in nova.instances"; continue; }
  BDMS=""
  while IFS=$'\t' read -r u dev vol att typ iqn lun luns size vst multi; do
    echo "  BDM $dev volume $vol (${size}G, $vst, multiattach $multi): Nova attachment $att, type $typ, LUN $lun, LUNs $luns, $iqn"
    awk -F'\t' -v v="$vol" -v a="$att" '$1 == v {printf "      cinder attachment %s %s instance %s attached_host %s connector %s %s LUN %s created %s updated %s%s\n", $2, $3, $4, $5, $6, $7, $8, $9, $10, ($2 == a ? "  <= Nova uses this one" : "")}' "$W/att"
    BDMS+="$dev $vol $iqn $lun"$'\n'
  done < <(grep "^$SID" "$W/bdm")
  awk -F'\t' -v s="$SID" '$1 == s {printf "  PORT %s (port %s) binding host %s %s vif %s profile %s%s\n", $2, $7, $3, $4, $5, $6, ($6 ~ /migrating_to/ ? "  <= migrating_to" : "")}' "$W/port"
  echo "  Cinder attachments of this instance (every volume, also ones without a BDM):"
  awk -F'\t' -v s="$SID" '$1 == s {printf "      volume %s \"%s\" %sG %s: attachment %s %s connector %s created %s updated %s\n", $2, $3, $4, $5, $6, $7, $8, $9, $10}' "$W/att2"
  echo "  Nova instance actions, last 14 days (action, request, message, events=result):"
  awk -F'\t' -v s="$SID" '$1 == s {printf "      %s %s %s %s  %s\n", $2, $3, $4, $5, $6}' "$W/act" | tail -15
  echo "  Last failed event, end of its traceback (secrets masked): $(awk -F'\t' -v s="$SID" '$1 == s && !n++ {print $2, $3}' "$W/tb")"
  awk -F'\t' -v s="$SID" '$1 == s && !n++ {print $4}' "$W/tb" | sed -E 's/\\n/\n/g' |
    sed -E "s/(auth_password|auth_username|password|secret)([\"']?[:=] ?[\"']?)[^\"', }]*/\1\2***/g" | grep -vE '^ +File |^Traceback' | tail -20 | cut -c1-240 | sed 's/^/        /'
  echo "  == on $host"
  printf 'SID=%q\nBDMS=%q\n%s\n' "$SID" "$BDMS" "$ONNODE" | asroot "$host" 2>&1
done
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, instances: $SIDS; management host $MGMT_HOST, director $DIR_USER@$DIR_HOST (keys and secrets are not printed)"
  printf 'SIDS=%q\nONNODE=%q\nRC=%s\n%s\n' "$SIDS" "$ONNODE" "$RC" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1 | grep -v 'post-quantum\|store now, decrypt\|openssh.com/pq'
  echo "== exit $?"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

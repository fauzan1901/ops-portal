#!/usr/bin/env bash
# Read-only: whose disk was a multipath map (by its WWID) on a compute, and what stopped using it. For a map that gave
# I/O errors and was flushed since (the dm number may belong to another disk now). On the compute: the multipathd lines
# of the WWID, the I/O errors of the dm per hour (first and last), the nova-compute lines that name the WWID (time,
# request, instance, device only: never the connection data), the instance and message of each such request, and around
# the last I/O error: the guest interfaces removed (a VM stopped or left) and the qemu log lines of the domains that shut
# down. On the director: each instance found (name, status, host now), its actions and migrations, its volumes.
# Same path as the portal: portal service account -> management host -> director -> compute. Only show / list / grep.
# Run on the bastion:  sudo bash ~/wwid-history.sh <SITE> <compute> <WWID> <dm-N> [hours, default 48]
#   e.g. sudo bash ~/wwid-history.sh DCA overcloud-novacomputeha-0 3600a09803831384c715d557a44344c72 dm-23 48
set -u
SITE="${1:-}"
NODE="${2:-}"
WWID="${3:-}"
DM="${4:-}"
HOURS="${5:-48}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$NODE" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "Compute: a name such as overcloud-novacomputeha-0"; exit 1; }
[[ "$WWID" =~ ^3[0-9a-f]{32}$ ]] || { echo "WWID: 3 and 32 hex digits, e.g. 3600a09803831384c715d557a44344c72"; exit 1; }
[[ "$DM" =~ ^dm-[0-9]+$ ]] || { echo "Device: dm-N, e.g. dm-23"; exit 1; }
[[ "$HOURS" =~ ^[0-9]+$ ]] && [ "$HOURS" -ge 1 ] && [ "$HOURS" -le 168 ] || { echo "Hours: 1-168"; exit 1; }
OUT="/home/deploy/wwid-history-$SITE-${WWID: -8}-$(date +%Y%m%d-%H%M%S).txt"
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
[ "${MGMT_HOST:-"-"}" != "-" ] || { echo "No management host for $SITE in /etc/ops-portal/sites.yml (run with sudo)"; exit 1; }
OPTS=(-o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new -p "$MGMT_PORT")
[ "$MGMT_KEY" != "-" ] && OPTS+=(-i "$MGMT_KEY")
TARGET="$MGMT_HOST"
[ "$MGMT_USER" != "-" ] && TARGET="$MGMT_USER@$MGMT_HOST"

# runs on the compute (as its overcloud user, sudo -n for root reads)
COMPUTE=$(cat <<'EOF'
set -u
echo "== Compute $(hostname -s), now $(date '+%F %T %Z'); WWID $WWID, $DM, last $HOURS h"
echo "== multipathd lines of the WWID (journal, then the multipathd container log if any)"
{ sudo -n journalctl --since "-${HOURS}h" --no-pager -o short-iso -t multipathd 2>/dev/null
  m=$(sudo -n podman ps -a --format '{{.Names}}' | grep -m1 -x multipathd)
  [ -n "$m" ] && sudo -n podman logs --since "${HOURS}h" "$m" 2>&1; } | grep -F "$WWID" | cut -c1-200 | tail -n 60
echo "== I/O errors of $DM per hour (a dm number can have been given to another disk in between)"
E=$(sudo -n journalctl -k --since "-${HOURS}h" --no-pager -o short-iso 2>/dev/null | grep -F "I/O error, dev $DM,")
printf '%s\n' "$E" | grep . | awk '{print substr($1,1,13) ":00"}' | uniq -c
echo "-- first: $(printf '%s\n' "$E" | grep . | head -n 1 | cut -c1-160)"
echo "-- last:  $(printf '%s\n' "$E" | grep . | tail -n 1 | cut -c1-160)"
LAST=$(printf '%s\n' "$E" | grep . | tail -n 1 | awk '{print $1}')
echo "== nova-compute lines naming the WWID (time, request, device, logger; the connection data is not printed)"
LOGS=$(sudo -n sh -c 'ls -tr /var/log/containers/nova/nova-compute.log* 2>/dev/null')
HITS=$(for f in $LOGS; do sudo -n zgrep -h -F "$WWID" "$f" 2>/dev/null; done)
printf '%s\n' "$HITS" | grep . | while read -r d t pid lvl logger rest; do
  req=$(printf '%s' "$rest" | grep -oE 'req-[0-9a-f-]{36}' | head -n 1)
  dev=$(printf '%s' "$rest" | grep -oE "'path': '/dev/[^']+'" | head -n 1)
  what=$(printf '%s' "$rest" | grep -oE '(==> |<== )?(connect_volume|disconnect_volume|Attached iSCSI volume|Detached|_disconnect|flush|remove)' | head -n 1)
  echo "   $d $t $logger ${req:--} ${what:--} ${dev:-}"
done | uniq | tail -n 60
echo "== The instance and first message of each request above"
for req in $(printf '%s\n' "$HITS" | grep -oE 'req-[0-9a-f-]{36}' | sort -u | head -n 20); do
  l=$(for f in $LOGS; do sudo -n zgrep -h -F "$req" "$f" 2>/dev/null; done | grep -m1 -F '[instance: ')
  u=$(printf '%s' "$l" | grep -oE '\[instance: [0-9a-f-]{36}\]' | grep -oE '[0-9a-f-]{36}')
  msg=$(printf '%s' "$l" | sed -E 's/.*\[instance: [0-9a-f-]{36}\] //' | grep -viE 'auth_|password|secret' | cut -c1-110)
  echo "   $req instance ${u:-?} $(printf '%s' "$l" | awk '{print $1, $2}') ${msg:-}"
  [ -n "$u" ] && echo "@inst $u"
done
if [ -n "$LAST" ]; then
  L=$(date -d "$LAST" +%s)
  echo "== Around the last I/O error ($LAST): guest interfaces removed, kernel (+-10 min)"
  sudo -n journalctl -k --since "@$((L - 600))" --until "@$((L + 600))" --no-pager -o short-iso 2>/dev/null \
    | grep -E "tap[0-9a-f-]+: (left|entered) promiscuous|device tap[0-9a-f-]+ (left|entered)|tap[0-9a-f-]+: (left|entered) allmulticast" | cut -c1-160 | tail -n 30
  from=$(date -u -d "@$((L - 600))" '+%F %H:%M'); to=$(date -u -d "@$((L + 600))" '+%F %H:%M')
  echo "== qemu log lines of domains that shut down or migrated between $from and $to UTC (qemu logs are in UTC)"
  for f in $(sudo -n sh -c 'ls /var/log/containers/libvirt/qemu/instance-*.log /var/log/libvirt/qemu/instance-*.log 2>/dev/null'); do
    sudo -n awk -v a="$from" -v b="$to" -v n="$(basename "$f" .log)" \
      '{s = substr($0,1,16); sub(/T/, " ", s)} s >= a && s <= b && /shutting down|terminating on signal|reason=|migrat/ {print "   " n ": " substr($0,1,150)}' "$f"
  done | tail -n 40
fi
EOF
)

# runs on the director (stack, overcloudrc): finds the compute, runs the part above there, then Nova's view
REMOTE=$(cat <<'EOF'
set -u
source $RC >/dev/null 2>&1 || { echo "source $RC failed"; exit 1; }
INV=$(ls ~/overcloud-deploy/*/tripleo-ansible-inventory.yaml ~/config-download/*/tripleo-ansible-inventory.yaml \
  ~/tripleo-ansible-inventory.yaml 2>/dev/null | head -1)
DEFUSR=$(grep -q '17\.' /etc/rhosp-release && echo tripleo-admin || echo heat-admin)
read -r IP USR < <(python3 - "$NODE" "$INV" "$DEFUSR" <<'PY'
import sys, yaml
want, path, default = sys.argv[1].split(".")[0].lower(), sys.argv[2], sys.argv[3]
try:
    inv = yaml.safe_load(open(path)) or {}
except Exception:
    inv = {}
for group, body in inv.items():
    for host, hv in ((body or {}).get("hosts") or {}).items() if isinstance(body, dict) else []:
        if host.split(".")[0].lower() == want and isinstance(hv, dict) and (hv.get("ctlplane_ip") or hv.get("ansible_host")):
            print(hv.get("ctlplane_ip") or hv.get("ansible_host"), hv.get("ansible_ssh_user") or default)
            raise SystemExit
print("-", "-")
PY
)
[ "${IP:-"-"}" != "-" ] || { echo "$NODE is not in the director's inventory"; exit 1; }
CO=$(printf 'WWID=%q\nDM=%q\nHOURS=%q\n%s\n' "$WWID" "$DM" "$HOURS" "$COMPUTE" \
  | ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR "$USR@$IP" bash -s 2>&1)
printf '%s\n' "$CO" | grep -v '^@inst '
for SID in $(printf '%s\n' "$CO" | awk '/^@inst [0-9a-f-]{36}$/ {print $2}' | sort -u); do
  echo "== Instance $SID now"
  openstack server show "$SID" -f json -c name -c status -c OS-EXT-STS:task_state -c OS-EXT-STS:vm_state \
    -c OS-EXT-SRV-ATTR:host -c OS-EXT-SRV-ATTR:instance_name -c project_id -c volumes_attached -c updated 2>&1 \
    | tr -d '\n' | sed 's/  */ /g'; echo
  echo "-- actions (newest first)"
  openstack server event list "$SID" -f value 2>&1 | head -n 8
  echo "-- migrations (newest first)"
  openstack --os-compute-api-version 2.80 server migration list --server "$SID" -f json 2>&1 | python3 -c '
import json, sys
try:
    rows = json.load(sys.stdin)
except ValueError:
    print("   not read"); raise SystemExit
for r in rows[:6]:
    g = lambda *k: next((str(r[x]) for x in r for w in k if x.lower() == w), "-")
    print("  ", g("id"), g("type", "migration type"), g("status"), g("source compute"), "->", g("dest compute"), g("created at"), g("updated at"))'
  echo "-- volumes (status and attachments only)"
  for v in $(openstack server show "$SID" -f json -c volumes_attached | python3 -c 'import json,sys; print(" ".join(x.get("id","") for x in json.load(sys.stdin).get("volumes_attached") or []))'); do
    openstack volume show "$v" -f json -c id -c name -c status -c size -c attachments 2>&1 | python3 -c '
import json, sys
try:
    v = json.load(sys.stdin)
except ValueError:
    print("   not read"); raise SystemExit
att = [(a.get("server_id", "")[:8], a.get("host_name"), a.get("device"), str(a.get("attached_at", ""))[:19]) for a in v.get("attachments") or []]
print("  ", v.get("id"), v.get("name") or "-", v.get("status"), str(v.get("size")) + " GB", "attachments:", att)'
  done
done
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, compute $NODE, WWID $WWID, $DM, last $HOURS h; director $DIR_USER@$DIR_HOST (keys are not printed)"
  printf 'NODE=%q\nWWID=%q\nDM=%q\nHOURS=%q\nRC=%s\nCOMPUTE=%q\n%s\n' "$NODE" "$WWID" "$DM" "$HOURS" "$RC" "$COMPUTE" "$REMOTE" \
    | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
      "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1 | grep -v '^\*\* '
  echo "== exit ${PIPESTATUS[1]}"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

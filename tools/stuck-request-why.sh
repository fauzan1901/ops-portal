#!/usr/bin/env bash
# Read-only: why did an instance stay in a task (e.g. "migrating") while no compute ever worked on it? A request Nova
# accepted (instance action recorded, task_state set) but with no event at all: nova-conductor never started on it.
# The actions of the instance (user, events), every line of the request in nova-api / nova-conductor / nova-scheduler
# on the controllers (HTTP status and time of the call), the API calls on the instance after it (reset state, abort,
# migrate, confirm), the ERROR / WARNING and AMQP trouble of nova and RabbitMQ in the window of the request, the
# containers and queues now, other migrations of the site at that time and the instances left in a task now.
# Same path as the portal: portal service account -> management host -> director -> controllers. Only show / list /
# grep of logs.   Run on the bastion:  sudo bash ~/stuck-request-why.sh <SITE> <server ID> [<request ID>]
set -u
SITE="${1:-}"
SID="${2:-}"
REQARG="${3:-}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$SID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || { echo "Server ID: an OpenStack UUID"; exit 1; }
[ -z "$REQARG" ] || [[ "$REQARG" =~ ^req-[0-9a-f-]{36}$ ]] || { echo "Request ID: req-<uuid>"; exit 1; }
OUT="/home/deploy/stuck-request-why-$(date +%Y%m%d-%H%M%S).txt"
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
openstack server show "$SID" -f json -c name -c status -c OS-EXT-STS:vm_state -c OS-EXT-STS:task_state \
  -c OS-EXT-SRV-ATTR:host -c flavor -c created -c updated 2>&1
echo "== Actions of the instance in the last 3 days (newest first): user, events (none = no service ever worked on it)"
CUT=$(date -u -d '-3 days' +%Y-%m-%dT%H:%M:%S)
ACT=$(openstack server event list "$SID" -f value -c "Request ID" -c Action -c "Start Time" 2>&1 | awk -v c="$CUT" '$3 >= c {print $3, $1, $2}' | sort -r)
REQ=$REQARG
[ -n "$REQ" ] || REQ=$(printf '%s\n' "$ACT" | awk '$3 == "live-migration" {print $2; exit}')
for req in $(printf '%s\n' "$ACT" | head -8 | awk '{print $2}'); do
  openstack server event show "$SID" "$req" -f json 2>/dev/null
  echo "@@@"
done | python3 -c '
import json, subprocess, sys
users = {}
def user(u):
    if u and u not in users:
        p = subprocess.run(["openstack", "user", "show", u, "-f", "value", "-c", "name"], capture_output=True, text=True)
        users[u] = (p.stdout.strip() or "?") if p.returncode == 0 else "?"
    return users.get(u, "-")
for chunk in sys.stdin.read().split("@@@"):
    try:
        a = json.loads(chunk)
    except ValueError:
        continue
    ev = a.get("events") or []
    line = "%s %s %s by %s (%s)" % (a.get("start_time"), a.get("action"), a.get("request_id"), user(a.get("user_id")), a.get("user_id"))
    if a.get("message"):
        line += " message: %s" % a.get("message")
    print(line + ("" if ev else "  << NO EVENT: no service started on it"))
    for e in sorted(ev, key=lambda e: e.get("start_time") or ""):
        print("     %s %s %s .. %s" % (e.get("event"), e.get("result"), e.get("start_time"), e.get("finish_time")))
        tb = (e.get("traceback") or "").strip().splitlines()
        if tb:
            print("       " + " | ".join(tb[-3:])[:400])
'
T=$(printf '%s\n' "$ACT" | awk -v r="$REQ" '$2 == r {print $1; exit}')
echo "== The request: ${REQ:-none found} started ${T:-?} (UTC)"
[ -n "$REQ" ] && [ -n "$T" ] || { echo "no live-migration request in the last 3 days: pass the request ID as the 3rd argument"; exit 0; }
E=$(python3 -c 'import datetime, sys; print(int(datetime.datetime.strptime(sys.argv[1][:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc).timestamp()))' "$T")
echo "== Other migrations of the site created between 20 minutes before and 40 minutes after it (did others go through?)"
openstack --os-compute-api-version 2.59 server migration list --changes-since "$(date -u -d @$((E - 1200)) +%Y-%m-%dT%H:%M:%S)" -f json 2>&1 | E=$E python3 -c '
import datetime, json, os, sys
text = sys.stdin.read()
try:
    rows = json.loads(text)
except ValueError:
    print(text[:800]); rows = []
e = int(os.environ["E"])
def ts(v):
    try:
        return int(datetime.datetime.strptime(str(v)[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc).timestamp())
    except ValueError:
        return None
near = [r for r in rows if ts(r.get("Created At")) is not None and e - 1200 <= ts(r.get("Created At")) <= e + 2400]
for r in sorted(near, key=lambda r: r.get("Created At")):
    print(r.get("Id"), r.get("Type"), r.get("Status"), str(r.get("Source Compute")).split(".")[0], "->",
          str(r.get("Dest Compute")).split(".")[0], "server", r.get("Server UUID"), "created", r.get("Created At"))
print(f"{len(near)} migration(s) in that window")'
INV=$(ls ~/overcloud-deploy/*/tripleo-ansible-inventory.yaml ~/config-download/*/tripleo-ansible-inventory.yaml \
  ~/tripleo-ansible-inventory.yaml 2>/dev/null | head -1)
DEFUSR=$(grep -q '17\.' /etc/rhosp-release && echo tripleo-admin || echo heat-admin)
first=1
python3 - "$INV" <<'PY' > /tmp/wi-ctl.$$
import sys, yaml
try:
    inv = yaml.safe_load(open(sys.argv[1])) or {}
except Exception:
    inv = {}
seen = set()
for group, body in inv.items():
    for host, hv in ((body or {}).get("hosts") or {}).items() if isinstance(body, dict) else []:
        name = host.split(".")[0].lower()
        if isinstance(hv, dict) and "controller" in (group + name).lower() and name not in seen:
            seen.add(name)
            print(name, hv.get("ctlplane_ip") or hv.get("ansible_host") or "-", hv.get("ansible_ssh_user") or "-")
PY
while read -r N IP USR; do
  [ "$IP" = "-" ] && continue
  [ "$USR" = "-" ] && USR=$DEFUSR
  echo
  echo "######## controller $N"
  ssh -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
    "$USR@$IP" "sudo bash -s -- $SID $REQ $E $first" <<'NODE' | cut -c1-450
SID=$1 REQ=$2 E=$3 FIRST=$4
L=/var/log/containers
A=$(date -d @$((E - 300)) '+%Y-%m-%d %H:%M:%S'); B=$(date -d @$((E + 2400)) '+%Y-%m-%d %H:%M:%S')
echo "(times here are $(date +%Z); window $A .. $B: 5 minutes before the request to 40 minutes after)"
echo "-- containers now (a restart since then shows as a short uptime)"
podman ps -a --format '{{.Names}} {{.Status}}' 2>/dev/null | grep -E '^(nova_(api|api_cron|conductor|scheduler)|rabbitmq|haproxy|galera|mysql)' | sort
echo "-- every line of $REQ in nova-api / nova-conductor / nova-scheduler (rotated logs too)"
for f in nova-api nova-conductor nova-scheduler; do
  x=$(zgrep -h "$REQ" $L/nova/$f.log* 2>/dev/null | sort -s -k1,2)
  [ -n "$x" ] || { echo "[$f] none"; continue; }
  echo "[$f] $(printf '%s\n' "$x" | grep -c .) line(s)"
  printf '%s\n' "$x" | head -8
  printf '%s\n' "$x" | tail -n +9 | tail -12
done
echo "-- calls on the instance from 1 hour before the request on (nova-api: POST / PUT / DELETE, status, microversion, time)"
C=$(date -d @$((E - 3600)) '+%Y-%m-%d %H:%M:%S')
for f in $(find $L/nova -name 'nova-api.log*' -newermt "$C" 2>/dev/null); do zcat -f "$f"; done |
  grep -F "$SID" | grep -E '"(POST|PUT|DELETE) ' | awk -v c="$C" '($1 " " $2) >= c' | sort -s -k1,2 | tail -30
echo "-- nova ERROR / WARNING lines in the window (last 15 per service) and AMQP / database trouble (count per kind)"
for f in nova-conductor nova-api nova-scheduler; do
  x=$(for g in $(find $L/nova -name "$f.log*" -newermt "$A" 2>/dev/null); do zcat -f "$g"; done |
      awk -v a="$A" -v b="$B" '($1 " " $2) >= a && ($1 " " $2) <= b' | grep -E ' (ERROR|WARNING|CRITICAL) ')
  n=$(printf '%s\n' "$x" | grep -c .)
  echo "[$f] $n ERROR/WARNING line(s) in the window"
  [ "$n" -gt 0 ] || continue
  for k in 'MessagingTimeout|Timed out waiting for a reply' 'AMQP server .* is unreachable|Connection reset by peer|ConnectionForced|Broken pipe' \
           'heartbeat' 'DBConnectionError|Lost connection to MySQL|Too many connections|Deadlock' 'NoValidHost'; do
    c=$(printf '%s\n' "$x" | grep -cE "$k")
    [ "$c" -gt 0 ] && echo "   $c x $k"
  done
  printf '%s\n' "$x" | sort -s -k1,2 | tail -15
done
echo "-- rabbitmq log in the window: errors / warnings / partitions (last 20) and closed connections (count)"
R=$(for g in $(find $L/rabbitmq -name '*.log*' -newermt "$A" 2>/dev/null); do zcat -f "$g"; done |
    awk -v a="$A" -v b="$B" '($1 " " substr($2, 1, 8)) >= a && ($1 " " substr($2, 1, 8)) <= b')
echo "   $(printf '%s\n' "$R" | grep -c .) line(s); $(printf '%s\n' "$R" | grep -ciE 'closing AMQP connection|connection_closed_abruptly|client unexpectedly closed') closed connection(s); $(printf '%s\n' "$R" | grep -ciE 'missed heartbeats') missed heartbeat(s)"
printf '%s\n' "$R" | grep -iE '\[(error|warning|warn)\]|partition|node down|nodedown|alarm|memory high|disk free' | tail -20
if [ "$FIRST" = 1 ]; then
  r=$(podman ps --format '{{.Names}}' | grep -m1 -E '^rabbitmq')
  if [ -n "$r" ]; then
    echo "-- rabbitmq now: partitions and the conductor / scheduler / compute queues (messages, consumers)"
    timeout 60 podman exec "$r" rabbitmqctl cluster_status 2>/dev/null | grep -iA3 'partition' | head -8
    timeout 90 podman exec "$r" rabbitmqctl list_queues -q name messages consumers 2>/dev/null |
      grep -E '^(conductor|scheduler)(\s|\.)|^compute\.[a-z]' | sort | head -20
  fi
  echo "-- pacemaker: rabbitmq / galera / haproxy resources and failures"
  timeout 60 pcs status 2>/dev/null | grep -E 'rabbitmq|galera|haproxy|Failed|failed|Stopped' | head -15
fi
NODE
  first=0
done < /tmp/wi-ctl.$$
rm -f /tmp/wi-ctl.$$
echo
echo "== Instances of the site in a task now (task state not empty), with their newest migration"
openstack server list --all-projects --long -f json -c ID -c Name -c Status -c "Task State" -c Host 2>&1 | python3 -c '
import json, sys
text = sys.stdin.read()
try:
    rows = json.loads(text)
except ValueError:
    print(text[:800]); rows = []
busy = [r for r in rows if r.get("Task State") not in (None, "", "None")]
for r in busy[:20]:
    print(r.get("ID"), r.get("Task State"), r.get("Status"), str(r.get("Host")).split(".")[0], r.get("Name"))
print(f"{len(busy)} instance(s) in a task")' | tee /tmp/wi-busy.$$
for s in $(awk '$2 ~ /migrat/ {print $1}' /tmp/wi-busy.$$ | head -10); do
  echo "   $s newest migration: $(openstack --os-compute-api-version 2.59 server migration list --server "$s" --limit 1 -f value -c Id -c Status -c "Created At" 2>&1 | head -1)"
done
rm -f /tmp/wi-busy.$$
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, server $SID${REQARG:+, request $REQARG}; management host $MGMT_HOST, director $DIR_USER@$DIR_HOST (keys are not printed)"
  printf 'SID=%q\nREQARG=%q\nRC=%s\n%s\n' "$SID" "$REQARG" "$RC" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1 | grep -v '^\*\* '
  echo "== exit ${PIPESTATUS[1]}"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

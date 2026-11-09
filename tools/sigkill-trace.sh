#!/usr/bin/env bash
# Who kills clustercheck (a real case: since the kernel 5.14.0-284.199.1 patch, socat with "fork" gets SIGKILL right
# after it starts; without "fork" it works). On one controller: the security / EDR agents installed and running, then a
# 6 s test on a spare port (127.0.0.1:9201, never 9200) with the same socat command inside the galera container, while the
# kernel's signal_generate trace event records every SIGKILL and the task that sent it. The trace event is switched off
# again and the test listener ends by itself; nothing else is changed. Path: portal service account -> management host ->
# director -> controller.
# Run on the bastion:  sudo bash ~/sigkill-trace.sh <SITE> <controller, e.g. overcloud-controller-2>
set -u
SITE="${1:-}"
NODE="${2:-}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$NODE" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$ && "$NODE" == *controller* ]] || { echo "Controller: a node name, e.g. overcloud-controller-2"; exit 1; }
OUT="/home/deploy/sigkill-trace-$SITE-$(date +%Y%m%d-%H%M%S).txt"
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

REMOTE=$(cat <<'EOF'
set -u
INV=$(ls ~/overcloud-deploy/*/tripleo-ansible-inventory.yaml ~/config-download/*/tripleo-ansible-inventory.yaml \
  ~/tripleo-ansible-inventory.yaml 2>/dev/null | head -1)
nodes() {   # "<short name> <ctlplane ip> <ssh user>" of the node named $1
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
        if isinstance(hv, dict) and want == name and name not in seen:
            seen.add(name)
            print(name, hv.get("ctlplane_ip") or hv.get("ansible_host") or "-", hv.get("ansible_ssh_user") or "-")
PY
}
DEFUSR=$(grep -q '17\.' /etc/rhosp-release && echo tripleo-admin || echo heat-admin)
CTL=$(cat <<'CTLEOF'
set -u
echo "== Kernel, uptime"
uname -r; uptime -s
echo "== Security / EDR agents: packages, services, kernel modules, processes"
rpm -qa 2>/dev/null | grep -iE 'falcon|sentinel|ds_agent|deepsecurity|trend|wazuh|ossec|qualys|tanium|mfe|mcafee|trellix|cybereason|osquery|elastic-agent|auditbeat|sysdig|mdatp|defender|cbsensor|carbonblack|esets|fapolicyd' | sort
systemctl list-units --type=service --all --no-legend 2>/dev/null | grep -iE 'falcon|sentinel|ds_agent|trend|wazuh|ossec|qualys|tanium|mfe|trellix|cybereason|osquery|elastic|auditbeat|sysdig|mdatp|cbagent|cbsensor|esets|fapolicy' | cut -c1-150
lsmod | grep -iE 'falcon|sentinel|dsa|tmhook|redirfs|cbsensor|mfe|esets|sysdig|snare' | head -5
ps -eo pid,lstart,comm | grep -iE 'falcon|sentinel|ds_agent|wazuh|ossec|qualys|tanium|mfe|cybereason|osquery|elastic|auditbeat|sysdig|mdatp|cbagent|fapolicyd' | head -10
echo "== Test: socat with fork on 127.0.0.1:9201 in the galera container for 6 s, recording every SIGKILL"
T=/sys/kernel/tracing
[ -e $T/events/signal/signal_generate ] || T=/sys/kernel/debug/tracing
E=$T/events/signal/signal_generate
if [ ! -e $E/enable ]; then echo "signal_generate trace event not available"; else
  echo 'sig == 9' > $E/filter
  echo > $T/trace
  echo 1 > $E/enable
  g=$(podman ps -q -f name=galera-bundle | head -1)
  podman exec "$g" timeout 6 socat -d -d tcp4-listen:9201,bind=127.0.0.1,reuseaddr,fork system:/usr/bin/clustercheck \
    < /dev/null > /tmp/sigkill-trace-socat.log 2>&1 &
  P=$!
  sleep 1
  for i in 1 2 3; do curl -s -m 2 -o /dev/null -w "curl 127.0.0.1:9201 -> HTTP %{http_code}\n" http://127.0.0.1:9201/ < /dev/null; sleep 0.5; done
  wait $P
  echo "podman exec socat (with fork) exit code: $?   (124 = ran until the timeout, not killed; 137 = SIGKILL)"
  echo 0 > $E/enable
  echo 0 > $E/filter
  echo "-- socat output (last 8):"; tail -8 /tmp/sigkill-trace-socat.log
  rm -f /tmp/sigkill-trace-socat.log
  echo "-- every SIGKILL sent during the test (sender task-pid at the start of the line; target comm= pid=):"
  grep -v '^#' $T/trace | tail -15
  echo > $T/trace
fi
echo "== Log lines naming socat or clustercheck in the last 3 hours (not podman / systemd / ansible)"
journalctl --since "-3h" --no-pager -o short-iso 2>/dev/null | grep -iE 'socat|clustercheck' | grep -viE 'podman\[|systemd\[|ansible|sudo\[|conmon' | tail -10 | cut -c1-220
for f in /var/log/crowdstrike/falconctl.log /var/log/sentinelone/*.log /opt/ds_agent/diag/*.log /var/ossec/logs/active-responses.log /var/log/fapolicyd*.log; do
  [ -f "$f" ] && { echo "-- $f"; grep -iE 'socat|clustercheck|kill|block' "$f" | tail -5 | cut -c1-220; }
done
CTLEOF
)
[ -n "$INV" ] || { echo "No tripleo-ansible-inventory.yaml on the director"; exit 1; }
nodes "$NODE" | while read -r N IP USR; do
  [ "$IP" = "-" ] && continue
  u="$USR"; [ "$u" = "-" ] && u=$DEFUSR
  echo "######## $N ($IP)"
  printf '%s\n' "$CTL" | ssh -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR "$u@$IP" "sudo bash -s" 2>&1
done
EOF
)

{
  echo "SIGKILL trace, $(date -Is), site $SITE, node $NODE; management host $MGMT_HOST, director $DIR_USER@$DIR_HOST (keys are not printed)"
  printf 'NODE=%q\n%s\n' "$NODE" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1
  echo "== exit $?"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

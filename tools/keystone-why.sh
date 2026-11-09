#!/usr/bin/env bash
# Read-only: why keystone does not come up on a controller. On the named controller (or every controller): the systemd
# unit tripleo_keystone and its journal, the keystone and memcached containers, the last errors of keystone.log and of
# Apache (mod_wsgi), whether port 5000 listens and answers /v3, the fernet and credential keys (count and a short hash of
# each, never the key) compared between the controllers, Galera / RabbitMQ / HAProxy in pcs status, disk and memory.
# Same path as the portal: portal service account -> management host -> director -> controllers. Only status / list / tail.
# Run on the bastion:  sudo bash ~/keystone-why.sh <SITE> [controller, e.g. overcloud-controller-2] [hours, default 6]
set -u
SITE="${1:-}"
NODE="${2:-controller}"
HOURS="${3:-6}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$NODE" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$ ]] || { echo "Controller: a node name, e.g. overcloud-controller-2"; exit 1; }
[[ "$HOURS" =~ ^[0-9]{1,3}$ ]] || { echo "Hours: a number"; exit 1; }
OUT="/home/deploy/keystone-why-$SITE-$(date +%Y%m%d-%H%M%S).txt"
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
INV=$(ls ~/overcloud-deploy/*/tripleo-ansible-inventory.yaml ~/config-download/*/tripleo-ansible-inventory.yaml \
  ~/tripleo-ansible-inventory.yaml 2>/dev/null | head -1)
nodes() {   # "<short name> <ctlplane ip> <ssh user>" of the nodes whose name or group matches $1
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
on() {   # on <ip> <user> <command>
  local u="$2"; [ "$u" = "-" ] && u=$DEFUSR
  ssh -n -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$u@$1" "$3"
}
mask() { sed -E 's/((password|passwd|secret|token|key)[^=:]{0,20}[=:] *)[^ ,;"]+/\1<masked>/Ig'; }
KEYS='for d in fernet-keys credential-keys; do p=/var/lib/config-data/puppet-generated/keystone/etc/keystone/$d; n=$(sudo ls "$p" 2>/dev/null | wc -l); h=$(for f in $(sudo ls "$p" 2>/dev/null | sort -n); do printf "%s:%s " "$f" "$(sudo sha256sum "$p/$f" | cut -c1-8)"; done); echo "$d: $n file(s) $h"; done'

[ -n "$INV" ] || { echo "No tripleo-ansible-inventory.yaml on the director"; exit 1; }
echo "== Controllers in the inventory: $(nodes controller | awk '{print $1}' | tr '\n' ' ')"
echo "== Fernet / credential keys on every controller (file names and the first 8 hex of their sha256; all controllers must match)"
nodes controller | while read -r N IP USR; do
  [ "$IP" = "-" ] && continue
  echo "-- $N"; on "$IP" "$USR" "$KEYS" 2>&1 | sed 's/^/   /'
done

nodes "$NODE" | while read -r N IP USR; do
  [ "$IP" = "-" ] && continue
  echo
  echo "######## $N ($IP)"
  echo "== Uptime, memory, disks"
  on "$IP" "$USR" "uptime; free -m | head -2; df -h / /var /var/log /var/lib/containers 2>/dev/null | sort -u" 2>&1
  echo "== tripleo_keystone.service"
  on "$IP" "$USR" "systemctl is-active tripleo_keystone.service; sudo systemctl status tripleo_keystone.service --no-pager -l 2>&1 | tail -15" 2>&1 | mask | cut -c1-300
  echo "== Its journal, last $HOURS hours (last 40)"
  on "$IP" "$USR" "sudo journalctl -u tripleo_keystone.service -u tripleo_keystone_healthcheck.service --since '-${HOURS}h' --no-pager -o short-iso 2>&1 | tail -40" 2>&1 | mask | cut -c1-300
  echo "== Containers: keystone, memcached, httpd-based APIs"
  on "$IP" "$USR" "sudo podman ps -a --format '{{.Names}}  {{.Status}}  {{.Image}}' | grep -Ei 'keystone|memcached' " 2>&1
  echo "== Previous boot: its last lines (why it went down)"
  on "$IP" "$USR" "sudo journalctl -b -1 --no-pager -o short-iso 2>/dev/null | grep -iE 'reboot|shutdown|power|fence|stonith|Stopping|kernel: (Out of memory|BUG|watchdog)' | tail -8" 2>&1 | mask | cut -c1-250
  echo "== Galera on this node (clustercheck, wsrep)"
  on "$IP" "$USR" "c=\$(sudo podman ps -q -f name=galera-bundle | head -1); if [ -n \"\$c\" ]; then sudo timeout 20 podman exec \"\$c\" clustercheck 2>&1 | tail -1; sudo timeout 20 podman exec \"\$c\" mysql -N -e \"SHOW STATUS WHERE Variable_name IN ('wsrep_local_state_comment','wsrep_cluster_size','wsrep_ready','wsrep_connected')\" 2>&1 | head -6; else echo 'no galera-bundle container running here'; fi" 2>&1 | mask
  echo "== pcs status: nodes, galera, rabbitmq, haproxy, failed actions"
  on "$IP" "$USR" "sudo timeout 30 pcs status 2>&1 | grep -E -A4 'Node List|Online|OFFLINE|galera-bundle |rabbitmq-bundle |haproxy-bundle |Failed Resource Actions|Stopped|FAILED' | head -60" 2>&1 | cut -c1-200
  echo "== HAProxy: the keystone backends as this node's HAProxy sees them"
  on "$IP" "$USR" "for s in /var/lib/haproxy/stats /run/haproxy/admin.sock; do sudo test -S \$s || continue; echo 'show stat' | sudo timeout 5 socat stdio \$s 2>/dev/null | awk -F, '\$1 ~ /keystone/ && \$2 != \"FRONTEND\" {print \$1, \$2, \$18, \$19}'; break; done; c=\$(sudo podman ps -q -f name=haproxy-bundle | head -1); [ -n \"\$c\" ] && sudo timeout 5 podman exec \"\$c\" sh -c \"echo 'show stat' | socat stdio /var/lib/haproxy/stats 2>/dev/null\" | awk -F, '\$1 ~ /keystone/ && \$2 != \"FRONTEND\" {print \$1, \$2, \$18, \$19}' | sort -u" 2>&1
  echo "== keystone container: health check now, WSGI daemon processes, their sockets"
  on "$IP" "$USR" "sudo timeout 30 podman healthcheck run keystone >/dev/null 2>&1; echo \"podman healthcheck run keystone: rc=\$?  (0 = healthy)\"; sudo timeout 10 podman exec keystone sh -c 'ps -eo pid,etime,stat,args | grep -E \"wsgi|httpd\" | grep -v grep | head -15; ls -l /var/run/wsgi.* /run/httpd/wsgi.* 2>/dev/null | head -10'" 2>&1 | cut -c1-200
  echo "== Port 5000: who listens, and does /v3 answer (5 s each)"
  on "$IP" "$USR" "sudo ss -ltn | awk '\$4 ~ /:5000\$/ {print \$4}' | sort -u | while read -r a; do printf '%s /v3 -> HTTP %s\\n' \"\$a\" \"\$(curl -s -m 5 -o /dev/null -w '%{http_code} in %{time_total} s' http://\$a/v3)\"; done" 2>&1
  echo "== podman logs keystone (last 30)"
  on "$IP" "$USR" "sudo podman logs --tail 30 keystone 2>&1" 2>&1 | mask | cut -c1-300
  echo "== keystone.log (newest file): its last 10 lines, and its errors since this boot (last 25)"
  on "$IP" "$USR" "f=\$(sudo ls -t /var/log/containers/keystone/keystone.log* 2>/dev/null | head -1); b=\$(date -d \"\$(uptime -s)\" '+%Y-%m-%d %H:%M'); echo \"file \$f, boot \$b\"; sudo tail -n 10 \"\$f\"; echo '-- errors since boot:'; sudo awk -v b=\"\$b\" 'substr(\$0,1,16) >= b' \"\$f\" | grep -E 'ERROR|CRITICAL|WARNING .*(timed out|refused|Unable)' | tail -25" 2>&1 | mask | cut -c1-300
  echo "== Apache keystone error log (newest file): WSGI errors per 10 minutes since this boot, and the last 10 lines"
  on "$IP" "$USR" "f=\$(sudo ls -t /var/log/containers/httpd/keystone/*error* 2>/dev/null | head -1); echo \"file \$f\"; sudo grep -E 'Unable to connect to WSGI daemon|Timeout when reading response|Truncated or oversized' \"\$f\" | sed -E 's/^\\[[A-Za-z]{3} ([A-Za-z]{3} [0-9]{2} [0-9:]{4}).*/\\1x/' | uniq -c | tail -12; echo '-- last 10:'; sudo tail -n 10 \"\$f\"" 2>&1 | mask | cut -c1-260
done
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, node $NODE, last $HOURS hours; management host $MGMT_HOST, director $DIR_USER@$DIR_HOST (keys are not printed)"
  printf 'NODE=%q\nHOURS=%q\n%s\n' "$NODE" "$HOURS" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1
  echo "== exit $?"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

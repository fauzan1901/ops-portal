#!/usr/bin/env bash
# The console of an instance as Horizon shows it (virsh screenshot) and, with --enter, whether it answers: ONE Enter key
# (virsh send-key KEY_ENTER, nothing else), then a second screenshot 3 s later. A changed screen = the guest reacts.
# Enter is pressed only with --enter: at a login prompt it shows the prompt again; at a maintenance prompt it counts as an
# empty password ("Login incorrect"). Look at the screenshot first: never use --enter on a screen with a typed command.
# Same path as the portal: portal service account -> management host -> director -> the compute of the instance.
# Run on the bastion:  sudo bash ~/vm-console-test.sh <SITE> <server ID> [--enter]
set -u
SITE="${1:-}"
SID="${2:-}"
ENTER="${3:-}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$SID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || { echo "Server ID: an OpenStack UUID"; exit 1; }
case "$ENTER" in ""|--enter) ;; *) echo "Third argument: --enter or nothing"; exit 1;; esac
STAMP=$(date +%Y%m%d-%H%M%S)
OUT="/home/deploy/vm-console-test-$STAMP.txt"
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
openstack server show "$SID" -f json -c name -c status -c OS-EXT-STS:power_state -c OS-EXT-SRV-ATTR:host -c OS-EXT-SRV-ATTR:instance_name
HOST=$(openstack server show "$SID" -f value -c OS-EXT-SRV-ATTR:host)
INST=$(openstack server show "$SID" -f value -c OS-EXT-SRV-ATTR:instance_name)
[[ "$INST" =~ ^instance-[0-9a-f]{8}$ ]] || { echo "no instance name"; exit 1; }
SHORT=${HOST%%.*}
INV=$(ls ~/overcloud-deploy/*/tripleo-ansible-inventory.yaml ~/config-download/*/tripleo-ansible-inventory.yaml \
  ~/tripleo-ansible-inventory.yaml 2>/dev/null | head -1)
read -r IP USR < <(python3 - "$SHORT" "$INV" <<'PY'
import sys, yaml
want, path = sys.argv[1].lower(), sys.argv[2]
try:
    inv = yaml.safe_load(open(path)) or {}
except Exception:
    inv = {}
for body in inv.values():
    for host, hv in ((body or {}).get("hosts") or {}).items() if isinstance(body, dict) else []:
        if host.split(".")[0].lower() == want and isinstance(hv, dict):
            print(hv.get("ctlplane_ip") or hv.get("ansible_host") or "-", hv.get("ansible_ssh_user") or "-")
            sys.exit()
print("- -")
PY
)
[ "${IP:--}" = "-" ] && { echo "$HOST: not in the TripleO inventory"; exit 1; }
[ "${USR:--}" = "-" ] && { grep -q '17\.' /etc/rhosp-release && USR=tripleo-admin || USR=heat-admin; }
NODE=(ssh -n -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$USR@$IP")
C=$("${NODE[@]}" "sudo podman ps --format '{{.Names}}'" | grep -E '^nova_(virtqemud|libvirt)$' | head -1)
shot() {   # $1 = before | after
  echo "@@SHOT-BEGIN $INST-$1"
  "${NODE[@]}" "sudo podman exec $C virsh screenshot $INST /tmp/wi-test-$INST.img >/dev/null && sudo podman exec $C cat /tmp/wi-test-$INST.img | base64; sudo podman exec $C rm -f /tmp/wi-test-$INST.img"
  echo "@@SHOT-END"
}
echo "== $INST on $HOST: domain $("${NODE[@]}" "sudo podman exec $C virsh domstate $INST --reason")"
shot before
if [ "$ENTER" = "--enter" ]; then
  echo "== Pressing Enter once on the console of $INST (virsh send-key KEY_ENTER)"
  "${NODE[@]}" "sudo podman exec $C virsh send-key $INST KEY_ENTER"
  sleep 3
  shot after
fi
EOF
)

{
  echo "$(date -Is), site $SITE, server $SID${ENTER:+, Enter pressed once}; management host $MGMT_HOST, director $DIR_USER@$DIR_HOST"
  printf 'SID=%q\nENTER=%q\nRC=%s\n%s\n' "$SID" "$ENTER" "$RC" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1
  echo "== exit $?"
} | awk -v base="/home/deploy/vm-console-test-$STAMP" '
  /^@@SHOT-BEGIN / {f = base "-" $2 ".b64"; on = 1; next}
  /^@@SHOT-END/ {if (on) {close(f); print "screenshot: " f}; on = 0; next}
  on {print > f; next}
  {print}' | tee "$OUT"
for b in /home/deploy/vm-console-test-$STAMP-*.b64; do
  [ -s "$b" ] && base64 -d "$b" > "${b%.b64}.png" 2>/dev/null && chown deploy: "${b%.b64}.png" && echo "Saved: ${b%.b64}.png"
  rm -f "$b"
done
B=$(ls /home/deploy/vm-console-test-$STAMP-*-before.png 2>/dev/null | head -1)
A=$(ls /home/deploy/vm-console-test-$STAMP-*-after.png 2>/dev/null | head -1)
if [ -n "$B" ] && [ -n "$A" ]; then
  if cmp -s "$B" "$A"; then echo "RESULT: the screen did NOT change after Enter (the console may be frozen, or the prompt looks the same)"
  else echo "RESULT: the screen changed after Enter: the console answers"; fi | tee -a "$OUT"
fi
chown deploy: "$OUT"

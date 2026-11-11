#!/usr/bin/env bash
# Set the LVM filter of ONE compute with Red Hat's own TripleO role tripleo_lvmfilter (tripleo-ansible, what
# `openstack overcloud deploy` runs with LVMFilterEnabled: true), only on that compute, only when it is empty.
#   0. read-only checks: Nova has no instance on it that is not SHUTOFF, its libvirt runs no domain, no guest LV is active
#      on it; then a DRY RUN of the role on that compute only (tripleo_tripleo_lvmfilter_dry_run: the role writes its
#      filter to /tmp/tripleo_lvmfilter.conf, /etc/lvm/lvm.conf is not touched). The filter it would set must end with
#      r|.*| and allow only local disks of the host (never an iSCSI path or a multipath map: the role allows the PVs it
#      finds in use, and a guest PV in use would be allowed);
#   1. typed APPLY: the empty compute checked again, then the role with tripleo_tripleo_lvmfilter_enabled: true on that
#      compute only (it keeps a backup of lvm.conf and refreshes the LVM caches; no service is restarted, no instance is
#      touched); the filter read again. The lines to add to the overcloud templates are printed, so that the next
#      `openstack overcloud deploy` sets the same filter (director stays the source of the configuration).
# Same path as the portal: portal service account -> management host -> director (ansible-playbook as stack).
# Run on the bastion:  sudo bash ~/lvm-filter-apply.sh <SITE> <compute short name>
set -u
SITE="${1:-}"
CMP="${2:-}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$CMP" =~ ^[a-z0-9-]{1,63}$ ]] || { echo "Compute: its short name"; exit 1; }
OUT="/home/deploy/lvm-filter-apply-$(date +%Y%m%d-%H%M%S).txt"
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

# on the compute, as root, read-only: running domains, active guest LVs, the filter now / of the dry run
ONNODE=$(cat <<'NODE'
c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$')
[ -n "$c" ] || { echo "@@domains unknown"; exit 0; }
echo "@@domains $(podman exec "$c" virsh -c qemu:///system list --name | grep -c .)"
podman exec "$c" virsh -c qemu:///system list --name | grep . | head -5 | sed 's/^/   running: /'
g=0
for x in /sys/block/dm-*; do
  [[ "$(cat $x/dm/uuid 2>/dev/null)" == LVM-* ]] || continue
  for v in $(ls $x/slaves); do p=$v
    [ -e /sys/class/block/$v/partition ] && p=$(basename "$(dirname "$(readlink -f /sys/class/block/$v)")")
    if [[ "$p" == dm-* ]]; then [ "$(cut -c1-6 /sys/block/$p/dm/uuid)" = mpath- ] && g=$((g+1))
    elif [[ "$p" == sd* ]]; then a=$(basename "$(readlink -f /sys/block/$p/device 2>/dev/null)" 2>/dev/null); [ -e /sys/class/iscsi_host/host${a%%:*} ] && g=$((g+1)); fi
  done
done
echo "@@guestlvs $g"
echo "@@filter $(lvmconfig --type full devices/global_filter 2>/dev/null | cut -d= -f2-)"
if [ -s /tmp/tripleo_lvmfilter.conf ]; then echo "@@dryrun $(grep -E '^\s*global_filter\s*=' /tmp/tripleo_lvmfilter.conf | tail -1 | cut -d= -f2- | tr -d ' ')"
  echo "@@dryrun_age $(( $(date +%s) - $(stat -c %Y /tmp/tripleo_lvmfilter.conf) ))"; fi
for e in $(grep -E '^\s*global_filter\s*=' /tmp/tripleo_lvmfilter.conf 2>/dev/null | tail -1 | grep -oE '"a\|[^|]*\|"' | sed -E 's/^"a\|//; s/\|"$//'); do
  d=$(readlink -f "$e" 2>/dev/null); b=$(basename "$d"); q=$b
  [ -e /sys/class/block/$b/partition ] && q=$(basename "$(dirname "$(readlink -f /sys/class/block/$b)")")
  a=$(basename "$(readlink -f /sys/block/$q/device 2>/dev/null)" 2>/dev/null)
  if [[ "$q" == dm-* ]] || [ -e /sys/class/iscsi_host/host${a%%:*} ] 2>/dev/null || [ -z "$a" ]; then echo "@@allow-guest $e ($b)"; else echo "@@allow-local $e ($b)"; fi
done
NODE
)

REMOTE=$(cat <<'EOF'
set -u
source $RC >/dev/null 2>&1 || { echo "source $RC failed"; exit 1; }
INV=$(ls ~/overcloud-deploy/*/tripleo-ansible-inventory.yaml ~/config-download/*/tripleo-ansible-inventory.yaml \
  ~/tripleo-ansible-inventory.yaml 2>/dev/null | head -1)
read -r NAME IP USR ROLE < <(python3 - "$CMP" "$INV" <<'PY'
import sys, yaml
want, path = sys.argv[1].lower(), sys.argv[2]
inv = yaml.safe_load(open(path)) or {}
node, role = None, "-"
for g, body in inv.items():
    for h, hv in (((body or {}).get("hosts") or {}).items() if isinstance(body, dict) else []):
        if h.split(".")[0].lower() == want:
            if isinstance(hv, dict) and (hv.get("ctlplane_ip") or hv.get("ansible_host")) and not node:
                node = (h, hv.get("ctlplane_ip") or hv.get("ansible_host"), hv.get("ansible_ssh_user") or "-")
            if g.startswith("overcloud_"):
                role = g[len("overcloud_"):]
print(*(node or ("-", "-", "-")), role)
PY
)
[ "${NAME:--}" != "-" ] || { echo "$CMP: not in the inventory $INV"; echo "@@stop"; exit 0; }
[ "$USR" = "-" ] && USR=$(grep -q '17\.' /etc/rhosp-release && echo tripleo-admin || echo heat-admin)
onnode() { printf '%s\n' "$ONNODE" | ssh -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$USR@$IP" "sudo -n bash -s"; }
empty() {   # Nova: no instance that is not SHUTOFF; libvirt: no running domain; no active guest LV
  local H L N S R
  H=$(openstack compute service list --service nova-compute -f value -c Host 2>/dev/null | grep -m1 -E "^$CMP(\.|$)")
  [ -n "$H" ] || { echo "   Nova: no nova-compute service named $CMP"; return 1; }
  L=$(openstack server list --all-projects --host "$H" -f value -c ID -c Name -c Status 2>/dev/null)
  N=$(printf '%s\n' "$L" | grep -c .); S=$(printf '%s\n' "$L" | awk '$NF != "SHUTOFF"' | grep -c .)
  echo "   Nova on $H: $N instance(s), not SHUTOFF: $S"
  printf '%s\n' "$L" | awk '$NF != "SHUTOFF"' | grep . | head -5 | sed 's/^/     /'
  R=$(onnode)
  printf '%s\n' "$R" | grep -v '^@@'
  echo "   libvirt running domains: $(printf '%s\n' "$R" | awk '$1 == "@@domains" {print $2}'); guest LVs active: $(printf '%s\n' "$R" | awk '$1 == "@@guestlvs" {print $2}')"
  [ "$S" = 0 ] && printf '%s\n' "$R" | grep -qx "@@domains 0" && printf '%s\n' "$R" | grep -qx "@@guestlvs 0"
}
PLAY=$(mktemp /tmp/lvmfilter-XXXXXX.yml)
trap 'rm -f "$PLAY"' EXIT
printf -- '- hosts: all\n  gather_facts: false\n  any_errors_fatal: true\n  roles:\n    - role: tripleo_lvmfilter\n' > "$PLAY"
role() {   # $1 = true (apply) | false (dry run)
  local V
  if [ "$1" = true ]; then V='{"tripleo_tripleo_lvmfilter_enabled": true, "tripleo_tripleo_lvmfilter_dry_run": false, "tripleo_tripleo_lvmfilter_devices_allowlist": [], "tripleo_tripleo_lvmfilter_devices_denylist": [".*"]}'
  else V='{"tripleo_tripleo_lvmfilter_enabled": false, "tripleo_tripleo_lvmfilter_dry_run": true, "tripleo_tripleo_lvmfilter_devices_allowlist": [], "tripleo_tripleo_lvmfilter_devices_denylist": [".*"]}'; fi
  ANSIBLE_HOST_KEY_CHECKING=False ANSIBLE_STDOUT_CALLBACK=default ansible-playbook -i "$INV" --limit "$NAME" -e "$V" "$PLAY" 2>&1 |
    grep -E "^(TASK|ok:|changed:|fatal:|failed:|skipping:|PLAY RECAP|$NAME)|unreachable|ERROR" | grep -v "^$" | tail -30 | sed 's/^/   /'
}
echo "== compute $NAME ($IP, $USR), role $ROLE"
echo "== role tripleo_lvmfilter: $(rpm -qf /usr/share/ansible/roles/tripleo_lvmfilter 2>/dev/null | head -1); its handlers:"
grep -vE '^\s*(#|$|---)' /usr/share/ansible/roles/tripleo_lvmfilter/handlers/main.yml 2>/dev/null | sed 's/^/   /'
echo "== roles of the overcloud (roles_data): $(grep -hE '^- name: ' ~/overcloud-deploy/*/tripleo-*-roles-data.yaml 2>/dev/null | sed 's/^- name: //' | sort -u | paste -sd' ' -)"
grep -nE "^  LVMFilter(Enabled|Allowlist|Denylist):" -A3 /usr/share/openstack-tripleo-heat-templates/deployment/iscsid/iscsid-container-puppet.yaml 2>/dev/null | grep -E "LVMFilter|default" | sed 's/^/   template /'
echo "== 1. is it empty?"
if ! empty; then echo "STOP: $CMP is not empty (instances not SHUTOFF, running domains or active guest LVs): nothing was changed"; echo "@@stop"; exit 0; fi
if [ "$MODE" = "check" ]; then
  echo "== 2. dry run of tripleo_lvmfilter on $NAME only (lvm.conf is not touched)"
  role false
  R=$(onnode)
  echo "   filter now:        $(printf '%s\n' "$R" | awk '$1 == "@@filter" {sub(/^@@filter /, ""); print}')"
  echo "   filter of the run: $(printf '%s\n' "$R" | awk '$1 == "@@dryrun" {sub(/^@@dryrun /, ""); print}')"
  printf '%s\n' "$R" | grep -E '^@@allow-' | sed 's/^@@/   /'
  D=$(printf '%s\n' "$R" | awk '$1 == "@@dryrun" {print $2}')
  A=$(printf '%s\n' "$R" | awk '$1 == "@@dryrun_age" {print $2}')
  [ -n "$D" ] && [ "${A:-99999}" -lt 600 ] || { echo "STOP: the dry run wrote no new filter (age ${A:-none} s): nothing was changed"; echo "@@stop"; exit 0; }
  printf '%s\n' "$D" | grep -q '"r|\.\*|"' || { echo "STOP: the filter of the dry run does not end with r|.*|: nothing was changed"; echo "@@stop"; exit 0; }
  printf '%s\n' "$R" | grep -q '^@@allow-guest' && { echo "STOP: the filter of the dry run would allow a guest volume (an iSCSI path or a multipath map): nothing was changed"; echo "@@stop"; exit 0; }
  echo "READY"
  exit 0
fi
echo "== 2. apply tripleo_lvmfilter on $NAME only"
role true
R=$(onnode)
echo "   filter now: $(printf '%s\n' "$R" | awk '$1 == "@@filter" {sub(/^@@filter /, ""); print}')"
echo "== 3. add this to the overcloud templates (an environment file given to every later openstack overcloud deploy):"
echo "   parameter_defaults:"
echo "     ${ROLE}Parameters:      # role $ROLE: the exact role name of roles_data above"
echo "       LVMFilterEnabled: true"
echo "       LVMFilterDenylist: ['.*']"
EOF
)

remote() {
  printf 'MODE=%q\nCMP=%q\nONNODE=%q\nRC=%s\n%s\n' "$1" "$CMP" "$ONNODE" "$RC" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1 | grep -v 'post-quantum\|store now, decrypt\|openssh.com/pq'
}

exec > >(tee "$OUT") 2>&1
echo "$(date -Is) site $SITE, compute $CMP"
echo "######## 0. Checks and dry run (nothing is changed)"
R0=$(remote check)
printf '%s\n' "$R0" | grep -v '^@@stop'
printf '%s\n' "$R0" | grep -qx "READY" || { echo "Not going on."; chown deploy: "$OUT" 2>/dev/null; exit 1; }
echo
read -r -p ">>> Set this LVM filter on $CMP with tripleo_lvmfilter (the compute is checked empty again first)? Type APPLY to go on: " ans </dev/tty
[ "$ans" = "APPLY" ] || { echo "Stopped, nothing was changed."; chown deploy: "$OUT" 2>/dev/null; exit 0; }
echo "######## 1. Apply"
remote apply | grep -v '^@@stop'
chown deploy: "$OUT" 2>/dev/null
echo "Saved: $OUT"

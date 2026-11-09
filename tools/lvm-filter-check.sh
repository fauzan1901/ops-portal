#!/usr/bin/env bash
# Read-only: everything needed before the LVM filter of ONE compute is set the Red Hat way (the TripleO role
# tripleo_lvmfilter, what `openstack overcloud deploy` runs with LVMFilterEnabled: true), and whether that compute is
# empty. Nothing is changed. Prints:
#   - the compute: Nova's instances on it (any state) and the running domains of its libvirt (both must be 0 to go on);
#   - its role (TripleO inventory groups) and the LVMFilter* settings in the templates of the director;
#   - the tripleo_lvmfilter role installed on the director (defaults, tasks) and how the heat templates pass
#     LVMFilterEnabled / LVMFilterAllowlist / LVMFilterDenylist to it;
#   - on the compute: the LVM filter now, the host's own disks and PVs (local, not iSCSI), whether / is on LVM, the guest
#     LVs active there now;
#   - the deploy scripts / commands kept on the director (to know the -e files of the last overcloud deploy).
# Same path as the portal: portal service account -> management host -> director -> the compute.
# Run on the bastion:  sudo bash ~/lvm-filter-check.sh <SITE> <compute short name>
set -u
SITE="${1:-}"
CMP="${2:-}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$CMP" =~ ^[a-z0-9-]{1,63}$ ]] || { echo "Compute: its short name"; exit 1; }
OUT="/home/deploy/lvm-filter-check-$(date +%Y%m%d-%H%M%S).txt"
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

# on the compute, as root, read-only
ONNODE=$(cat <<'NODE'
c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$')
echo "== running domains (libvirt): $([ -n "$c" ] && podman exec "$c" virsh -c qemu:///system list --name | grep -c . || echo 'no libvirt container')"
[ -n "$c" ] && podman exec "$c" virsh -c qemu:///system list --name | grep . | head -20 | sed 's/^/   /'
echo "== LVM now"
echo "   lvmconfig global_filter: $(lvmconfig --type full devices/global_filter 2>/dev/null | cut -d= -f2-)"
echo "   lvmconfig filter: $(lvmconfig --type full devices/filter 2>/dev/null | cut -d= -f2-)"
echo "   use_devicesfile: $(lvmconfig --type full devices/use_devicesfile 2>/dev/null | cut -d= -f2), system.devices: $([ -s /etc/lvm/devices/system.devices ] && echo present || echo absent)"
grep -nE '^\s*(global_filter|filter|use_devicesfile)\s*=' /etc/lvm/lvm.conf 2>/dev/null | sed 's/^/   lvm.conf:/'
ls -l /etc/lvm/lvm.conf* 2>/dev/null | sed 's/^/   /'
echo "== the host's own disks (not iSCSI)"
for b in /sys/block/sd* /sys/block/nvme* /sys/block/vd*; do [ -e "$b" ] || continue; d=${b##*/}
  a=$(basename "$(readlink -f $b/device 2>/dev/null)" 2>/dev/null); [ -e /sys/class/iscsi_host/host${a%%:*} ] 2>/dev/null && continue
  echo "   $d size=$(( $(cat $b/size) / 2097152 ))G model=$(cat $b/device/model 2>/dev/null | tr -s ' ') by-path=$(ls -l /dev/disk/by-path 2>/dev/null | awk -v d="../../$d" '$NF == d {print $(NF-2)}' | head -1)"
done
echo "   / is on: $(findmnt -n -o SOURCE /)  type $(lsblk -no TYPE "$(findmnt -n -o SOURCE /)" 2>/dev/null | head -1)"
echo "== PVs LVM sees now (with its current filter): local = a disk of the host, iSCSI = a guest volume"
pvs --noheadings -o pv_name,vg_name 2>/dev/null | while read -r p v; do b=$(basename "$(readlink -f "$p")")
  q=$b; [ -e /sys/class/block/$b/partition ] && q=$(basename "$(dirname "$(readlink -f /sys/class/block/$b)")")
  a=$(basename "$(readlink -f /sys/block/$q/device 2>/dev/null)" 2>/dev/null)
  if [[ "$q" == dm-* ]]; then k="dm ($(cat /sys/block/$q/dm/uuid 2>/dev/null | cut -c1-6))"
  elif [ -e /sys/class/iscsi_host/host${a%%:*} ] 2>/dev/null; then k=iSCSI; else k=local; fi
  echo "   $p vg=$v $k"; done | sort -k3 | head -40
echo "== guest LVs active on this host now: $(for x in /sys/block/dm-*; do case "$(cat $x/dm/uuid 2>/dev/null)" in LVM-*) for v in $(ls $x/slaves); do p=$v; [ -e /sys/class/block/$v/partition ] && p=$(basename "$(dirname "$(readlink -f /sys/class/block/$v)")"); case "$p" in dm-*) [ "$(cut -c1-6 /sys/block/$p/dm/uuid)" = mpath- ] && echo "${x##*/}";; sd*) a=$(basename "$(readlink -f /sys/block/$p/device 2>/dev/null)" 2>/dev/null); [ -e /sys/class/iscsi_host/host${a%%:*} ] && echo "${x##*/}";; esac; done;; esac; done | sort -u | paste -sd' ' - | grep . || echo none)"
NODE
)

REMOTE=$(cat <<'EOF'
set -u
source $RC >/dev/null 2>&1 || { echo "source $RC failed"; exit 1; }
INV=$(ls ~/overcloud-deploy/*/tripleo-ansible-inventory.yaml ~/config-download/*/tripleo-ansible-inventory.yaml \
  ~/tripleo-ansible-inventory.yaml 2>/dev/null | head -1)
echo "== inventory: $INV"
python3 - "$CMP" "$INV" <<'PY'
import sys, yaml
want, path = sys.argv[1].lower(), sys.argv[2]
inv = yaml.safe_load(open(path)) or {}
groups, node = [], None
for g, body in inv.items():
    hosts = (body or {}).get("hosts") or {} if isinstance(body, dict) else {}
    for h, hv in hosts.items():
        if h.split(".")[0].lower() == want:
            groups.append(g)
            if isinstance(hv, dict) and hv.get("ctlplane_ip") or isinstance(hv, dict) and hv.get("ansible_host"):
                node = (h, hv.get("ctlplane_ip") or hv.get("ansible_host"), hv.get("ansible_ssh_user") or "-")
print("   groups of", want + ":", ", ".join(groups) or "none")
print("@@node", *(node or ("-", "-", "-")))
PY
NODE=$(python3 - "$CMP" "$INV" <<'PY'
import sys, yaml
want, path = sys.argv[1].lower(), sys.argv[2]
inv = yaml.safe_load(open(path)) or {}
for g, body in inv.items():
    for h, hv in (((body or {}).get("hosts") or {}).items() if isinstance(body, dict) else []):
        if h.split(".")[0].lower() == want and isinstance(hv, dict) and (hv.get("ctlplane_ip") or hv.get("ansible_host")):
            print(hv.get("ctlplane_ip") or hv.get("ansible_host"), hv.get("ansible_ssh_user") or "-"); sys.exit()
PY
)
read -r IP USR <<< "$NODE"
[ "${USR:--}" = "-" ] && USR=$(grep -q '17\.' /etc/rhosp-release && echo tripleo-admin || echo heat-admin)
HOSTNAME_NOVA=$(openstack compute service list --service nova-compute -f value -c Host 2>/dev/null | grep -m1 -E "^$CMP(\.|$)")
echo "== Nova: compute service ${HOSTNAME_NOVA:-not found}"
if [ -n "$HOSTNAME_NOVA" ]; then
  openstack compute service list --service nova-compute --host "$HOSTNAME_NOVA" -f value -c Status -c State -c "Disabled Reason" 2>/dev/null | sed 's/^/   status: /'
  L=$(openstack server list --all-projects --host "$HOSTNAME_NOVA" -f value -c ID -c Name -c Status 2>/dev/null)
  echo "   instances Nova has on it (any state): $(printf '%s\n' "$L" | grep -c .)"
  printf '%s\n' "$L" | grep . | head -20 | sed 's/^/     /'
fi
echo "== LVMFilter in the templates and deploy files of the director"
grep -rn "LVMFilter" ~/templates ~/overcloud-deploy/*/*.yaml ~/*.yaml 2>/dev/null | grep -v "\.log:" | head -20 | sed 's/^/   /'
echo "== the TripleO role tripleo_lvmfilter on the director"
R=$(ls -d /usr/share/ansible/roles/tripleo_lvmfilter /usr/share/ansible/roles/tripleo-lvmfilter 2>/dev/null | head -1)
echo "   role: ${R:-not found}; package: $(rpm -qf "${R:-/nonexistent}" 2>/dev/null | head -1)"
[ -n "$R" ] && { echo "   --- defaults/main.yml"; grep -vE '^\s*(#|$)' "$R/defaults/main.yml" 2>/dev/null | sed 's/^/   /'
  echo "   --- tasks"; ls "$R/tasks" 2>/dev/null | sed 's/^/   /'; grep -vE '^\s*(#|$)' "$R/tasks/main.yml" 2>/dev/null | head -60 | sed 's/^/   /'; }
echo "== how the heat templates pass LVMFilter* to it"
grep -rln "LVMFilterEnabled" /usr/share/openstack-tripleo-heat-templates/ 2>/dev/null | head -5 | sed 's/^/   /'
f=$(grep -rln "LVMFilterEnabled" /usr/share/openstack-tripleo-heat-templates/deployment 2>/dev/null | head -1)
[ -n "$f" ] && grep -nE "LVMFilter|tripleo_lvmfilter" "$f" | head -20 | sed 's/^/   /'
echo "== deploy scripts / last deploy (for the -e files)"
grep -lsE "overcloud deploy" ~/*.sh ~/templates/*.sh ~/templates/**/*.sh 2>/dev/null | head -5 | sed 's/^/   script: /'
ls -lt ~/overcloud-deploy/*/ 2>/dev/null | head -15 | sed 's/^/   /'
echo "== on $CMP ($IP, $USR)"
[ -n "${IP:-}" ] && printf '%s\n' "$ONNODE" | ssh -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$USR@$IP" "sudo -n bash -s"
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, compute $CMP; management host $MGMT_HOST, director $DIR_USER@$DIR_HOST (keys are not printed)"
  printf 'CMP=%q\nONNODE=%q\nRC=%s\n%s\n' "$CMP" "$ONNODE" "$RC" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1 | grep -v 'post-quantum\|store now, decrypt\|openssh.com/pq\|^@@node'
  echo "== exit $?"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

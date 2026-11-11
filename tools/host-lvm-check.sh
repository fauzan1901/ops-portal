#!/usr/bin/env bash
# Read-only: guest LVM volume groups that a compute HOST activated on Cinder iSCSI devices (a real case: storage-vm,
# app-staging-1-restore, dcbvm-mdt01). When a volume whose guest put LVM on the whole disk is connected to a host
# that does not know its WWID yet, the host's LVM can activate the guest's LVs on the first SCSI path before multipathd
# claims it. multipathd then builds the map from the other path only, and os-brick takes the first dm holder it finds
# (the host LV) as "the multipath device". The domain then runs on the guest's INNER LV: the guest sees that LV's
# content as its whole disk, its LVM is not found after a reboot, and a running guest reads and writes at shifted
# offsets after a live migration onto it.
# Per compute: host LVM / multipath settings that decide it; every device-mapper LV whose devices are iSCSI paths or
# multipath maps (= a guest LV on the host), its table (device + offset), who opens it (domain = instance UUID), the
# multipath map of the same WWID; activation lines in the journal (30 days) for those volume groups.
# Same path as the portal: portal service account -> management host -> director -> controller / computes.
# Run on the bastion:  sudo bash ~/host-lvm-check.sh <SITE> all          (every nova-compute that is up)
#                  or:  sudo bash ~/host-lvm-check.sh <SITE> <compute>...
set -u
SITE="${1:-}"
shift 2>/dev/null
WHICH="$*"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$WHICH" =~ ^[a-z0-9-]+( [a-z0-9-]+)*$ ]] || { echo "Computes: all, or short names"; exit 1; }
OUT="/home/deploy/host-lvm-check-$(date +%Y%m%d-%H%M%S).txt"
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

# on a compute, read-only
ONNODE=$(cat <<'NODE'
c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$')
V="podman exec $c virsh -c qemu:///system"
MPD=$(podman ps --format '{{.Names}}' | grep -m1 -x multipathd)
MP() { if [ -n "$MPD" ]; then podman exec "$MPD" multipath "$@"; else multipath "$@"; fi; }
MPLL=$(MP -ll 2>/dev/null)
lc() { lvmconfig --type full "$1" 2>/dev/null | head -1 | cut -d= -f2-; }
wwid_sd() { sed 's/^naa\./3/' /sys/block/$1/device/wwid 2>/dev/null; }
opn() { dmsetup info -c --noheadings -o open "$1" 2>/dev/null | tr -d ' '; }
echo "CONF lvm: use_devicesfile=$(lc devices/use_devicesfile) system.devices=$([ -s /etc/lvm/devices/system.devices ] && echo present || echo absent) global_filter=$(lc devices/global_filter) filter=$(lc devices/filter) event_activation=$(lc global/event_activation) multipath_component_detection=$(lc devices/multipath_component_detection) multipath_wwids_file=$(lc devices/multipath_wwids_file) auto_activation_volume_list=$(lc activation/auto_activation_volume_list)"
echo "CONF multipath: find_multipaths=$(grep -hE '^[[:space:]]*find_multipaths' /etc/multipath.conf /etc/multipath/conf.d/*.conf 2>/dev/null | awk '{print $2}' | paste -sd, - | grep . || echo default) wwids_on_host=$([ -f /etc/multipath/wwids ] && echo "present ($(grep -c '^/' /etc/multipath/wwids) wwids)" || echo absent) host_package=$(rpm -q device-mapper-multipath >/dev/null 2>&1 && echo installed || echo absent) host_udev_rules=$(ls /usr/lib/udev/rules.d/ /etc/udev/rules.d/ 2>/dev/null | grep -i multipath | paste -sd, - | grep . || echo none)"
USERS=$(for x in $($V list --name); do u=$($V domuuid $x 2>/dev/null); $V domblklist $x 2>/dev/null | awk -v u=$u '$2 ~ /^\/dev\// {print $2, u, $1}'; done |
  while read -r s u t; do echo "$(basename "$(readlink -f "$s")") $u $t"; done)
who() { printf '%s\n' "$USERS" | awk -v d="$1" '$1 == d {print $2 "(" $3 ")"}' | paste -sd, -; }
VGS=""
for d in /sys/block/dm-*; do
  [[ "$(cat $d/dm/uuid 2>/dev/null)" == LVM-* ]] || continue
  dm=${d##*/}; n=$(cat $d/dm/name); on=""
  for s in $(ls $d/slaves); do
    p=$s; [ -e /sys/class/block/$s/partition ] && p=$(basename "$(dirname "$(readlink -f /sys/class/block/$s)")")
    if [[ "$p" == sd* ]]; then
      a=$(basename "$(readlink -f /sys/block/$p/device)")
      [ -e /sys/class/iscsi_host/host${a%%:*} ] || continue
      w=$(wwid_sd $p)
      m=$(for x in /sys/block/dm-*; do [ "$(cat $x/dm/uuid 2>/dev/null)" = "mpath-$w" ] && echo ${x##*/}; done | head -1)
      act=0; [ -n "$m" ] && act=$(printf '%s\n' "$MPLL" | awk -v d="$m" '$2 == d {on=1; next} /^[0-9a-f]{33} / {on=0} on && / sd[a-z]+ / && /active ready/ {n++} END {print n+0}')
      on+=" $s(iSCSI $a wwid=$w; map of this WWID: ${m:-none}${m:+ active-paths=$act open=$(opn $(cat /sys/block/$m/dm/name)) used-by=$(who $m)})"
    elif [[ "$p" == dm-* ]] && [[ "$(cat /sys/block/$p/dm/uuid 2>/dev/null)" == mpath-* ]]; then
      on+=" $s(multipath map $(cat /sys/block/$p/dm/name) used-by=$(who $p))"
    fi
  done
  [ -n "$on" ] || continue   # an LV of the host itself
  vg=$(printf '%s' "$n" | sed 's/--/\x01/g' | cut -d- -f1 | tr '\001' '-')
  VGS+="$vg"$'\n'
  echo "GUESTLV $dm name=$n vg=$vg open=$(opn "$n") used-by=$(who $dm) size=$(awk '{printf "%.1fG", $1 * 512 / 1073741824}' /sys/block/$dm/size) table=[$(dmsetup table "$n" 2>/dev/null | head -2 | paste -sd';' -)] on:$on"
done
if [ -n "$VGS" ]; then
  J=$(journalctl --since '-30 days' --no-pager -o short-iso 2>/dev/null | grep -E 'now active|lvm-activate|pvscan.*(activat|online)')
  printf '%s' "$VGS" | sort -u | while read -r vg; do
    [ -n "$vg" ] || continue
    l=$(printf '%s\n' "$J" | grep -F "\"$vg\"" ; printf '%s\n' "$J" | grep -F "lvm-activate-$vg[")
    echo "JOURNAL $vg: $(printf '%s\n' "$l" | grep -c .) activation line(s); first: $(printf '%s\n' "$l" | grep . | sort | head -1 | cut -c1-150); last: $(printf '%s\n' "$l" | grep . | sort | tail -1 | cut -c1-150)"
  done
fi
echo "DONE"
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
W=$(mktemp -d /tmp/hl-XXXXXX); trap 'rm -rf "$W"' EXIT
if [ "$WHICH" = "all" ]; then
  SVCS=$(openstack compute service list --service nova-compute -f value -c Host -c Status -c State 2>/dev/null | sed 's/^\([^. ]*\)[^ ]*/\1/')
  ALL=$(printf '%s\n' "$SVCS" | awk '$3 == "up" {print $1}' | sort -u)
  DOWN=$(printf '%s\n' "$SVCS" | awk '$3 != "up" {print $1}' | sort -u | paste -sd' ' -)
  echo "== nova-compute up: $(echo $ALL | wc -w); down, not read: ${DOWN:-none}"
else
  ALL="$WHICH"
fi
export ONNODE INV DEFUSR W
export -f nodes asroot
printf '%s\n' $ALL | xargs -P 6 -I{} bash -c 'printf "%s\n" "$ONNODE" | asroot {} > "$W/node-{}" 2>&1'
sql "SELECT i.uuid, i.display_name, SUBSTRING_INDEX(IFNULL(i.host,'-'), '.', 1), i.vm_state FROM nova.instances i WHERE i.deleted = 0" > "$W/inst"
python3 - "$W" $ALL <<'PY'
import sys, os, re
w, computes = sys.argv[1], sys.argv[2:]
inst = {}
for l in open(os.path.join(w, "inst"), errors="replace"):
    p = l.rstrip("\n").split("\t")
    if len(p) >= 4:
        inst[p[0]] = (p[1], p[3])
def name(m):
    u = m.group(1)
    return f"{u} {inst.get(u, ('?', '?'))[0]} [{inst.get(u, ('?', '?'))[1]}]({m.group(2)})"
tot_lv, tot_dom, tot_ok, bad = 0, 0, 0, []
for c in computes:
    f = os.path.join(w, f"node-{c}")
    t = [l.rstrip("\n") for l in open(f, errors="replace")] if os.path.exists(f) else []
    if "DONE" not in t:
        print(f"######## {c}: NOT READ ({(t[0] if t else 'no answer')[:150]})")
        bad.append(c)
        continue
    lv = [l for l in t if l.startswith("GUESTLV ")]
    dom = [l for l in lv if not re.search(r"used-by= ", l)]
    tot_lv += len(lv); tot_dom += len(dom); tot_ok += 1
    print(f"######## {c}: guest LVs active on the host {len(lv)}, of them used by a domain as its disk {len(dom)}")
    for l in t:
        if l.startswith("CONF "):
            print("  " + l)
    for l in lv:
        print("  " + re.sub(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\((vd[a-z]+)\)", name, l))
    for l in t:
        if l.startswith("JOURNAL "):
            print("  " + l)
print(f"== SITE TOTAL: computes read {tot_ok} (not read: {' '.join(bad) or 'none'}); guest LVs active on hosts {tot_lv}; "
      f"used by a domain as its disk {tot_dom}")
PY
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, computes: $WHICH; management host $MGMT_HOST, director $DIR_USER@$DIR_HOST (keys are not printed)"
  printf 'WHICH=%q\nONNODE=%q\nRC=%s\n%s\n' "$WHICH" "$ONNODE" "$RC" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1 | grep -v 'post-quantum\|store now, decrypt\|openssh.com/pq'
  echo "== exit $?"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

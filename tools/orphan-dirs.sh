#!/usr/bin/env bash
# Instance directories left on computes (/var/lib/nova/instances/<uuid> with no domain of that instance on that
# compute): a live migration of that instance BACK to the compute is refused (DestinationDiskExists), and the rollback
# of that refusal disconnects volumes on the compute with the source's LUN numbers, which can be other VMs' disks.
# Read-only by default: per compute, every instance directory, whether a domain of it is defined there, where Nova has
# the instance now (or deleted), its age, its files; SAFE = storage local, no domain, Nova has the instance elsewhere
# (or it is deleted), no task running on it, not changed in the last 30 minutes.
# With "move" as the last argument and a typed MOVE: the SAFE ones are renamed <dir>.leftover-<UTC> (never deleted).
# Same path as the portal: portal service account -> management host -> director -> the computes.
# Run on the bastion:  sudo bash ~/orphan-dirs.sh <SITE> <compute>... [move]
set -u
SITE="${1:-}"
shift 1 2>/dev/null
MOVE=0
ARGS=()
for x in "$@"; do [ "$x" = "move" ] && MOVE=1 || ARGS+=("$x"); done
NODES="${ARGS[*]:-}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$NODES" =~ ^[a-z0-9-]+( [a-z0-9-]+)*$ ]] || { echo "Computes: short names, e.g. dccrhosp-compute-1 dccrhosp-compute-0"; exit 1; }
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT="/home/deploy/orphan-dirs-$(date +%Y%m%d-%H%M%S).txt"
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

# on a compute, read-only: "<uuid> <domain yes|no> <age minutes> <fstype> <files>" for every instance directory
LIST=$(cat <<'NODE'
c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$')
FS=$(findmnt -n -T /var/lib/nova/instances -o FSTYPE)
NOW=$(date +%s)
for d in /var/lib/nova/instances/*; do
  u=$(basename "$d")
  [[ "$u" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || continue
  [ -d "$d" ] || continue
  dom=no; podman exec $c virsh -c qemu:///system dominfo "$u" >/dev/null 2>&1 && dom=yes
  age=$(( (NOW - $(stat -c %Y "$d")) / 60 ))
  echo "DIR $u $dom $age $FS $(ls "$d" 2>/dev/null | tr '\n' ',' | cut -c1-60)"
done
echo "DOMAINS $(podman exec $c virsh -c qemu:///system list --all --name | grep -c .)"
NODE
)
# on a compute, as root: rename the given directories (only when still there and still without a domain)
MOVEIT=$(cat <<'NODE'
c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$')
for u in $UUIDS; do
  d=/var/lib/nova/instances/$u
  if [ ! -d "$d" ]; then echo "$u: gone already"; continue; fi
  if podman exec $c virsh -c qemu:///system dominfo "$u" >/dev/null 2>&1; then echo "$u: a domain is defined now, not moved"; continue; fi
  mv "$d" "$d.leftover-$STAMP" && echo "$u: moved to $d.leftover-$STAMP"
done
NODE
)

REMOTE=$(cat <<'EOF'
set -u
source $RC >/dev/null 2>&1 || { echo "source $RC failed"; exit 1; }
INV=$(ls ~/overcloud-deploy/*/tripleo-ansible-inventory.yaml ~/config-download/*/tripleo-ansible-inventory.yaml \
  ~/tripleo-ansible-inventory.yaml 2>/dev/null | head -1)
nodeip() {
  python3 - "$1" "$INV" <<'PY'
import sys, yaml
want, path = sys.argv[1].lower(), sys.argv[2]
try:
    inv = yaml.safe_load(open(path)) or {}
except Exception:
    inv = {}
for group, body in inv.items():
    for host, hv in ((body or {}).get("hosts") or {}).items() if isinstance(body, dict) else []:
        if host.split(".")[0].lower() == want and isinstance(hv, dict):
            print(hv.get("ctlplane_ip") or hv.get("ansible_host") or "-", hv.get("ansible_ssh_user") or "-")
            raise SystemExit
print("- -")
PY
}
DEFUSR=$(grep -q '17\.' /etc/rhosp-release && echo tripleo-admin || echo heat-admin)
onnode() {
  local IP USR
  read -r IP USR < <(nodeip "$1")
  [ "$IP" = "-" ] && { echo "$1: not in the inventory"; return 1; }
  [ "$USR" = "-" ] && USR=$DEFUSR
  ssh -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$USR@$IP" "sudo -n bash -s"
}
echo "== Live migrations running on the site now (nothing is moved on a compute one of them goes to or from)"
RUNNING=$(openstack --os-compute-api-version 2.59 server migration list --status running -f value -c Id -c "Server UUID" -c "Source Compute" -c "Dest Compute" 2>/dev/null; \
          openstack --os-compute-api-version 2.59 server migration list --status preparing -f value -c Id -c "Server UUID" -c "Source Compute" -c "Dest Compute" 2>/dev/null)
printf '%s\n' "${RUNNING:-none}"
for NODE in $NODES; do
  echo
  echo "######## $NODE"
  L=$(printf '%s\n' "$LIST" | onnode "$NODE")
  printf '%s\n' "$L" | grep '^DOMAINS'
  SAFE=""
  printf '%-36s %-6s %-8s %-6s %-44s %s\n' "instance directory" domain "age(min)" fs "Nova: host / status" verdict
  while read -r _ U DOM AGE FS FILES; do
    if [ "$DOM" = "yes" ]; then
      printf '%-36s %-6s %-8s %-6s %-44s %s\n' "$U" yes "$AGE" "$FS" "-" "in use (domain defined)"; continue
    fi
    J=$(openstack server show "$U" -f value -c OS-EXT-SRV-ATTR:host -c status -c OS-EXT-STS:task_state 2>&1 | paste -sd' ')
    NV="$J"; [[ "$J" == *"No server with"* || "$J" == *"could not be found"* ]] && NV="deleted"
    V="SAFE"
    [[ "$FS" =~ ^(nfs|nfs4|ceph|glusterfs|fuse.glusterfs|cifs)$ ]] && V="shared storage: not touched"
    [ "$AGE" -lt 30 ] && V="changed <30 min ago: not touched"
    [[ "$NV" == *"$NODE"* ]] && V="Nova has the instance HERE without a domain: not touched (check it)"
    [[ "$NV" =~ (MIGRATING|RESIZE|migrating|resize) ]] && V="a migration of it runs: not touched"
    TASK=$(printf '%s' "$NV" | awk '{print $2}')   # -f value: host, task_state, status (sorted by name)
    [ "$NV" != "deleted" ] && [ -n "$TASK" ] && [ "$TASK" != "None" ] && V="task $TASK running: not touched"
    printf '%-36s %-6s %-8s %-6s %-44s %s\n' "$U" no "$AGE" "$FS" "${NV:0:44}" "$V   files: $FILES"
    [ "$V" = "SAFE" ] && SAFE="$SAFE $U"
  done < <(printf '%s\n' "$L" | grep '^DIR ')
  echo "SAFE_ON $NODE:$SAFE"
  if [ "$MOVE" = 1 ] && [ -n "$SAFE" ]; then
    if printf '%s\n' "$RUNNING" | grep -q "$NODE"; then echo "not moved on $NODE: a live migration to or from it runs now"; continue; fi
    printf 'UUIDS=%q\nSTAMP=%q\n%s\n' "$SAFE" "$STAMP" "$MOVEIT" | onnode "$NODE"
  fi
done
EOF
)

remote() {   # remote <move 0|1>
  printf 'NODES=%q\nMOVE=%q\nSTAMP=%q\nLIST=%q\nMOVEIT=%q\nRC=%s\n%s\n' "$NODES" "$1" "$STAMP" "$LIST" "$MOVEIT" "$RC" "$REMOTE" \
    | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
      "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1 \
    | grep -v 'post-quantum\|store now, decrypt\|openssh.com/pq'
}

exec > >(tee "$OUT") 2>&1
echo "$(date -Is) site $SITE, computes $NODES, mode $( [ $MOVE = 1 ] && echo move || echo read-only )"
R=$(remote 0)
printf '%s\n' "$R"
if [ "$MOVE" = 1 ]; then
  N=$(printf '%s\n' "$R" | grep '^SAFE_ON' | awk -F: '{print $2}' | wc -w)
  echo
  read -r -p ">>> Rename the $N SAFE directories above to <dir>.leftover-$STAMP (never deleted)? Type MOVE to go on: " ans </dev/tty
  [ "$ans" = "MOVE" ] || { echo "Stopped, nothing was moved."; chown deploy: "$OUT" 2>/dev/null; exit 0; }
  remote 1 | grep -E "moved|gone|not moved|domain is defined|####"
fi
chown deploy: "$OUT" 2>/dev/null
echo "Saved: $OUT"

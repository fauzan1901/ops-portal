#!/usr/bin/env bash
# Read-only: the Nova code installed on a site, for the steps that disconnect a volume on a compute with the connection
# info saved in the block device mapping. Prints the lines (no change anywhere):
#   controller nova_api   : nova-manage volume_attachment refresh (_do_refresh: does it call remove_volume_connection?)
#   compute nova_compute  : the libvirt volume drivers by type (is "local" there?), the base disconnect_volume (no-op?),
#                           detach_volume when the domain is gone, _disconnect_volume, block_device _do_detach.
# Same path as the portal: portal service account -> management host -> director -> controller / compute.
# Run on the bastion:  sudo bash ~/nova-detach-code.sh <SITE> <compute short name>
set -u
SITE="${1:-}"
NODE="${2:-}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$NODE" =~ ^[a-z0-9-]{1,63}$ ]] || { echo "Compute: its short name, e.g. dcbrhosp-az1-compute-2"; exit 1; }
OUT="/home/deploy/nova-detach-code-$(date +%Y%m%d-%H%M%S).txt"
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

ONCTL=$(cat <<'EOF'
P=$(podman exec nova_api python3 -c 'import nova, os; print(os.path.dirname(nova.__file__))')
echo "== nova_api: $P/cmd/manage.py, _do_refresh"
podman exec nova_api awk '/def _do_refresh\(/,/def refresh\(/' "$P/cmd/manage.py" | grep -nE "def _do_refresh|attachment_create|remove_volume_connection|instance.host == connector|HostConflict|attachment_update|bdm.connection_info =|attachment_complete|attachment_delete" | head -20
EOF
)
ONCMP=$(cat <<'EOF'
P=$(podman exec nova_compute python3 -c 'import nova, os; print(os.path.dirname(nova.__file__))')
echo "== nova_compute: libvirt volume drivers by type ($P/virt/libvirt/driver.py)"
podman exec nova_compute grep -nE "^\s*'(iscsi|local|fake)': " "$P/virt/libvirt/driver.py" | head -5
echo "== nova_compute: base disconnect_volume ($P/virt/libvirt/volume/volume.py)"
podman exec nova_compute awk '/^class LibvirtBaseVolumeDriver/,/^class LibvirtVolumeDriver/' "$P/virt/libvirt/volume/volume.py" | grep -nA3 "def disconnect_volume"
podman exec nova_compute grep -nA12 "^class LibvirtVolumeDriver" "$P/virt/libvirt/volume/volume.py" | head -14
echo "== nova_compute: detach_volume when the domain is gone, and _disconnect_volume ($P/virt/libvirt/driver.py)"
podman exec nova_compute awk '/    def detach_volume\(/,/    def extend_volume\(/' "$P/virt/libvirt/driver.py" | grep -nE "def detach_volume|InstanceNotFound|disappeared|_disconnect_volume" | head -8
podman exec nova_compute awk '/    def _disconnect_volume\(/,/    def _extend_volume\(|    def _attach_encryptor\(/' "$P/virt/libvirt/driver.py" | head -30
echo "== nova_compute: block_device _do_detach ($P/virt/block_device.py)"
podman exec nova_compute awk '/    def _do_detach\(/,/    def detach\(/' "$P/virt/block_device.py" | grep -nE "CONF.host == instance.host|driver_detach|Skipping|attachment_delete" | head -8
EOF
)

REMOTE=$(cat <<'EOF'
set -u
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
run() {   # run <node> <script>: as root on the node
  read -r N IP USR < <(nodes "$1")
  [ -z "${IP:-}" ] || [ "$IP" = "-" ] && { echo "$1: not in the inventory"; return; }
  [ "$USR" = "-" ] && USR=$DEFUSR
  echo "######## $N"
  printf '%s\n' "$2" | ssh -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR "$USR@$IP" "sudo -n bash -s"
}
run "$(nodes controller | head -1 | cut -d' ' -f1)" "$ONCTL"
run "$NODE" "$ONCMP"
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, compute $NODE; management host $MGMT_HOST, director $DIR_USER@$DIR_HOST (keys are not printed)"
  printf 'NODE=%q\nONCTL=%q\nONCMP=%q\n%s\n' "$NODE" "$ONCTL" "$ONCMP" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1
  echo "== exit $?"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

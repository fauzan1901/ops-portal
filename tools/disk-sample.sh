#!/usr/bin/env bash
# Read-only: what is on the boot disk of an instance whose sector 0 is not a boot sector? Reads (never writes) its
# multipath device on its compute: sector 0 in full (hex), the GPT headers (sector 1 and the last sector: "EFI PART"),
# the share of 0xFF and 0x00 bytes in 1 MiB samples across the disk, and how many FreeBSD / pfSense / ZFS / UFS
# signatures the first and last 64 MiB hold (counts and offsets only, no content).
# Same path as the portal: portal service account -> management host -> director -> the compute.
# Run on the bastion:  sudo bash ~/disk-sample.sh <SITE> <server ID>
set -u
SITE="${1:-}"
SID="${2:-}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$SID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || { echo "Server ID: an OpenStack UUID"; exit 1; }
OUT="/home/deploy/disk-sample-$(date +%Y%m%d-%H%M%S).txt"
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

ONNODE=$(cat <<'NODE'
c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$')
SRC=$(podman exec $c virsh -c qemu:///system domblklist $INST | awk '$2 ~ /^\/dev\// {print $2; exit}')
[ -n "$SRC" ] || { echo "no disk of $INST here"; exit 0; }
SZ=$(blockdev --getsize64 "$SRC")
echo "== $INST disk $SRC, $SZ bytes, $(cat /sys/block/$(basename $SRC)/dm/name 2>/dev/null)"
rd() { dd if="$SRC" bs=512 skip="$1" count="${2:-1}" iflag=direct status=none; }
echo "-- sector 0 (hex)"
rd 0 | od -A d -t x1 | head -40
echo "-- sector 1: GPT header signature (EFI PART expected): $(rd 1 | head -c 8 | od -A n -c | tr -s ' ')"
echo "-- last sector: backup GPT header signature: $(rd $((SZ / 512 - 1)) | head -c 8 | od -A n -c | tr -s ' ')"
echo "-- 1 MiB samples: offset, bytes 0xFF, bytes 0x00 (of 1048576)"
for off in 0 1 64 512 1024 2048 5120 10240 15360 19456 $((SZ / 1048576 - 1)); do
  S=$(dd if="$SRC" bs=1M skip=$off count=1 iflag=direct status=none | od -A n -v -t x1)
  printf '%8s MiB  ff %8s  00 %8s\n' "$off" "$(printf '%s' "$S" | tr ' ' '\n' | grep -c '^ff$')" "$(printf '%s' "$S" | tr ' ' '\n' | grep -c '^00$')"
done
echo "-- signatures in the first and last 64 MiB (count, first offsets)"
for part in first last; do
  if [ $part = first ]; then SKIP=0; else SKIP=$((SZ / 1048576 - 64)); fi
  dd if="$SRC" bs=1M skip=$SKIP count=64 iflag=direct status=none > /tmp/ds.bin
  for sig in FreeBSD gptboot BTX pfSense zfs; do
    echo "$part 64 MiB: '$sig' $(grep -c -a "$sig" /tmp/ds.bin) line(s), offsets $(grep -obUa "$sig" /tmp/ds.bin | head -3 | cut -d: -f1 | tr '\n' ' ')"
  done
  echo "$part 64 MiB: ZFS uberblock magic 0cb1ba00 at offsets $(grep -obUaP '\x0c\xb1\xba\x00\x00\x00\x00\x00' /tmp/ds.bin | head -3 | cut -d: -f1 | tr '\n' ' ')"
  echo "$part 64 MiB: UFS2 magic 19015419 at offsets $(grep -obUaP '\x19\x01\x54\x19' /tmp/ds.bin | head -3 | cut -d: -f1 | tr '\n' ' ')"
  rm -f /tmp/ds.bin
done
NODE
)

REMOTE=$(cat <<'EOF'
set -u
source $RC >/dev/null 2>&1 || { echo "source $RC failed"; exit 1; }
INV=$(ls ~/overcloud-deploy/*/tripleo-ansible-inventory.yaml ~/config-download/*/tripleo-ansible-inventory.yaml \
  ~/tripleo-ansible-inventory.yaml 2>/dev/null | head -1)
HOST=$(openstack server show "$SID" -f value -c OS-EXT-SRV-ATTR:host 2>/dev/null)
INST=$(openstack server show "$SID" -f value -c OS-EXT-SRV-ATTR:instance_name 2>/dev/null)
read -r IP USR < <(python3 - "${HOST%%.*}" "$INV" <<'PY'
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
)
[ "$IP" = "-" ] && { echo "$HOST: not in the inventory"; exit 1; }
[ "$USR" = "-" ] && USR=$(grep -q '17\.' /etc/rhosp-release && echo tripleo-admin || echo heat-admin)
echo "######## ${HOST%%.*} ($USR@$IP)"
printf 'INST=%q\n%s\n' "$INST" "$ONNODE" | ssh -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$USR@$IP" "sudo -n bash -s"
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, instance $SID; management host $MGMT_HOST, director $DIR_USER@$DIR_HOST (keys are not printed)"
  printf 'SID=%q\nONNODE=%q\nRC=%s\n%s\n' "$SID" "$ONNODE" "$RC" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1 | grep -v 'post-quantum\|store now, decrypt\|openssh.com/pq'
  echo "== exit $?"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

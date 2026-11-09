#!/usr/bin/env bash
# Read-only: is only sector 0 (the protective MBR with the BIOS boot code) of a boot volume damaged, and is the original
# one known? Compares the first 1 MiB of the volume (on the compute of its instance) with the first 1 MiB of the Glance
# image the volume was created from (downloaded on the director to a temporary file, removed at the end): which sectors
# differ (numbers only), whether the GPT header (sector 1) and partition entries (2-33) are identical, the image's
# sector 0 in hex (a public image's boot code) and its boot signature, and the image's backup GPT header position.
# Nothing is written to the volume or to Glance.
# Same path as the portal: portal service account -> management host -> director -> the compute.
# Run on the bastion:  sudo bash ~/pmbr-compare.sh <SITE> <server ID> <volume ID>
set -u
SITE="${1:-}"
SID="${2:-}"
VOL="${3:-}"
UUID_RE='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
for x in "$SID" "$VOL"; do [[ "$x" =~ $UUID_RE ]] || { echo "Usage: <SITE> <server ID> <volume ID>"; exit 1; }; done
OUT="/home/deploy/pmbr-compare-$(date +%Y%m%d-%H%M%S).txt"
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
W=$(mktemp -d /tmp/pmbr-XXXXXX)
trap 'rm -rf "$W"' EXIT
INV=$(ls ~/overcloud-deploy/*/tripleo-ansible-inventory.yaml ~/config-download/*/tripleo-ansible-inventory.yaml \
  ~/tripleo-ansible-inventory.yaml 2>/dev/null | head -1)
HOST=$(openstack server show "$SID" -f value -c OS-EXT-SRV-ATTR:host 2>/dev/null)
INST=$(openstack server show "$SID" -f value -c OS-EXT-SRV-ATTR:instance_name 2>/dev/null)
IMG=$(openstack volume show "$VOL" -f json -c volume_image_metadata | python3 -c 'import json,sys; print((json.load(sys.stdin).get("volume_image_metadata") or {}).get("image_id") or "")')
echo "== Image the volume was created from: ${IMG:-unknown}"
[ -n "$IMG" ] || exit 1
openstack image show "$IMG" -f value -c name -c disk_format -c size -c status 2>&1 | paste -sd' '
ISZ=$(openstack image show "$IMG" -f value -c size 2>/dev/null)
FREE=$(df -B1 --output=avail /tmp | tail -1 | tr -d ' ')
echo "image $ISZ bytes; free space in /tmp of the director: $FREE bytes"
[[ "$ISZ" =~ ^[0-9]+$ ]] || { echo "not downloaded: the image no longer exists in Glance (or has no size)"; exit 1; }
[ "$ISZ" -lt $((FREE / 2)) ] || { echo "not downloaded: the image would take more than half of the free space"; exit 1; }
echo "== Download (temporary, removed at the end)"
openstack image save --file "$W/img" "$IMG" && ls -l "$W/img" | awk '{print $5, "bytes"}'
FMT=$(qemu-img info --output=json "$W/img" | python3 -c 'import json,sys; print(json.load(sys.stdin)["format"])')
VSZ=$(qemu-img info --output=json "$W/img" | python3 -c 'import json,sys; print(json.load(sys.stdin)["virtual-size"])')
echo "image format $FMT, virtual size $VSZ bytes"
qemu-img dd -f "$FMT" -O raw bs=512 count=2048 if="$W/img" of="$W/img-first.raw"
qemu-img dd -f "$FMT" -O raw bs=512 skip=$((VSZ / 512 - 1)) count=1 if="$W/img" of="$W/img-last.raw"
echo "image last sector ($((VSZ / 512 - 1))): $(head -c 8 "$W/img-last.raw" | od -A n -c | tr -s ' ')"
echo "== The image's sector 0 (hex): its boot signature at 510-511 must be 55 aa"
head -c 512 "$W/img-first.raw" | od -A d -t x1 | tail -6
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
[ "$USR" = "-" ] && USR=$(grep -q '17\.' /etc/rhosp-release && echo tripleo-admin || echo heat-admin)
echo "== The volume's first 1 MiB and the sector at the image's end, read on ${HOST%%.*} (read-only)"
printf 'INST=%q\nLAST=%q\n%s\n' "$INST" "$((VSZ / 512 - 1))" '
c=$(podman ps --format "{{.Names}}" | grep -m1 -E "^(nova_virtqemud|nova_libvirt)$")
SRC=$(podman exec $c virsh -c qemu:///system domblklist $INST | awk "\$2 ~ /^\\/dev\\// {print \$2; exit}")
dd if="$SRC" bs=512 count=2048 iflag=direct status=none | base64 -w0; echo
dd if="$SRC" bs=512 skip=$LAST count=1 iflag=direct status=none | base64 -w0; echo' \
  | ssh -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$USR@$IP" "sudo -n bash -s" > "$W/vol.b64"
sed -n 1p "$W/vol.b64" | base64 -d > "$W/vol-first.raw"
sed -n 2p "$W/vol.b64" | base64 -d > "$W/vol-last.raw"
echo "volume bytes read: $(stat -c %s "$W/vol-first.raw") (first), $(stat -c %s "$W/vol-last.raw") (sector $((VSZ / 512 - 1)))"
python3 - "$W/img-first.raw" "$W/vol-first.raw" "$W/img-last.raw" "$W/vol-last.raw" <<'PY'
import sys
img, vol, il, vl = (open(p, "rb").read() for p in sys.argv[1:5])
n = min(len(img), len(vol)) // 512
diff = [i for i in range(n) if img[i * 512:(i + 1) * 512] != vol[i * 512:(i + 1) * 512]]
print("sectors compared:", n, "| differing:", len(diff), "| first ones:", diff[:20])
print("sector 0 identical:", 0 not in diff, "| GPT header (1) identical:", 1 not in diff,
      "| partition entries (2-33) identical:", not any(2 <= i <= 33 for i in diff),
      "| sectors 34-2047 identical:", not any(i >= 34 for i in diff))
print("image sector 0 ends with 55 aa:", img[510:512] == b"\x55\xaa", "| volume sector 0 ends with 55 aa:", vol[510:512] == b"\x55\xaa")
print("sector at the image's end identical on the volume (backup GPT header):", il == vl, "| image has EFI PART there:", il[:8] == b"EFI PART")
PY
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, instance $SID, volume $VOL; management host $MGMT_HOST, director $DIR_USER@$DIR_HOST (keys are not printed)"
  printf 'SID=%q\nVOL=%q\nRC=%s\n%s\n' "$SID" "$VOL" "$RC" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1 | grep -v 'post-quantum\|store now, decrypt\|openssh.com/pq'
  echo "== exit $?"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

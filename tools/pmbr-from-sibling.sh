#!/usr/bin/env bash
# Read-only: where to get the original sector 0 (protective MBR + BIOS boot code) of a boot volume whose sector 0 is
# damaged, when the Glance image it came from is deleted: other volumes created from the same image (Cinder keeps the
# image ID in their volume_image_metadata). For each one attached to an instance, on that instance's compute, reads
# only sectors 0 and 1 (boot code and GPT header: no user data) and compares them with the damaged volume: an identical
# GPT header (same disk GUID and CRC) proves the same origin, so its sector 0 is the original one. Prints its sector 0
# in hex and base64 (the input of the repair) and its SHA-256. Nothing is written anywhere.
# Same path as the portal: portal service account -> management host -> director -> computes.
# Run on the bastion:  sudo bash ~/pmbr-from-sibling.sh <SITE> <server ID> <volume ID>
set -u
SITE="${1:-}"
SID="${2:-}"
VOL="${3:-}"
UUID_RE='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
for x in "$SID" "$VOL"; do [[ "$x" =~ $UUID_RE ]] || { echo "Usage: <SITE> <server ID> <volume ID>"; exit 1; }; done
OUT="/home/deploy/pmbr-from-sibling-$(date +%Y%m%d-%H%M%S).txt"
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

# on a compute: sectors 0 and 1 of the disk of $INST whose serial is $DVOL, base64 on one line ("-" when not found)
READ01=$(cat <<'NODE'
c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$')
SRC=$(podman exec $c virsh -c qemu:///system dumpxml $INST 2>/dev/null | awk -v v="$DVOL" '/<disk /{b=""; on=1} on{b=b $0 "\n"} /<\/disk>/{on=0; if (index(b, "<serial>" v "</serial>")) print b}' | grep -oE "<source dev='[^']+'" | head -1 | cut -d"'" -f2)
if [ -n "$SRC" ]; then dd if="$SRC" bs=512 count=2 iflag=direct status=none | base64 -w0; echo; else echo "-"; fi
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
read01() {   # read01 <server ID> <volume ID>: base64 of sectors 0-1 of that volume on the compute of that server
  local H I IP USR
  H=$(openstack server show "$1" -f value -c OS-EXT-SRV-ATTR:host 2>/dev/null); I=$(openstack server show "$1" -f value -c OS-EXT-SRV-ATTR:instance_name 2>/dev/null)
  read -r IP USR < <(nodeip "${H%%.*}")
  [ "$IP" = "-" ] && { echo "-"; return; }
  [ "$USR" = "-" ] && USR=$DEFUSR
  printf 'INST=%q\nDVOL=%q\n%s\n' "$I" "$2" "$READ01" | ssh -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$USR@$IP" "sudo -n bash -s" | tail -1
}
IMG=$(openstack volume show "$VOL" -f json -c volume_image_metadata | python3 -c 'import json,sys; print((json.load(sys.stdin).get("volume_image_metadata") or {}).get("image_id") or "")')
echo "== Image of the volume: ${IMG:-unknown} ($(openstack image show "$IMG" -f value -c name 2>&1 | head -1))"
MINE=$(read01 "$SID" "$VOL")
echo "the damaged volume: $( [ "$MINE" = "-" ] && echo 'not read' || echo 'sectors 0-1 read')"
echo "== Other volumes created from that image (all projects)"
LIST=$(cinder --os-volume-api-version 3.4 list --all-tenants --image_metadata image_id="$IMG" 2>&1)
printf '%s\n' "$LIST" | grep -E '^\| [0-9a-f]{8}-' | awk -F'|' '{gsub(/ /,"",$2); gsub(/ /,"",$4); print $2, $4}' | grep -v "^$VOL " > /tmp/sib-$$
cat /tmp/sib-$$ | head -20
N=0
while read -r V ST; do
  [ "$ST" = "in-use" ] || continue
  N=$((N + 1)); [ $N -gt 5 ] && break
  S=$(openstack volume show "$V" -f json -c attachments | python3 -c 'import json,sys; a=json.load(sys.stdin).get("attachments") or []; print(a[0].get("server_id") if a else "")')
  [ -n "$S" ] || continue
  B=$(read01 "$S" "$V")
  echo "-- $V (instance $S): $( [ "$B" = "-" ] && echo 'not read' || echo 'read')"
  [ "$B" = "-" ] && continue
  MINE="$MINE" B="$B" python3 - <<'PY'
import base64, hashlib, os
mine = base64.b64decode(os.environ["MINE"]) if os.environ["MINE"] != "-" else b""
sib = base64.b64decode(os.environ["B"])
s0, s1 = sib[:512], sib[512:1024]
print("   sector 0 ends with 55 aa:", s0[510:512] == b"\x55\xaa", "| sha256", hashlib.sha256(s0).hexdigest()[:16])
print("   GPT header (sector 1) identical to the damaged volume's:", bool(mine) and s1 == mine[512:1024],
      "| EFI PART:", s1[:8] == b"EFI PART")
if s0[510:512] == b"\x55\xaa":
    print("   sector 0 base64:", base64.b64encode(s0).decode())
    for i in range(0, 512, 16):
        if i < 48 or i >= 432:
            print("   %04d " % i + " ".join("%02x" % b for b in s0[i:i + 16]))
PY
done < /tmp/sib-$$
rm -f /tmp/sib-$$
[ $N -eq 0 ] && echo "no other volume of that image is in use"
EOF
)

{
  echo "Read-only, $(date -Is), site $SITE, instance $SID, volume $VOL; management host $MGMT_HOST, director $DIR_USER@$DIR_HOST (keys are not printed)"
  printf 'SID=%q\nVOL=%q\nREAD01=%q\nRC=%s\n%s\n' "$SID" "$VOL" "$READ01" "$RC" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1 | grep -v 'post-quantum\|store now, decrypt\|openssh.com/pq'
  echo "== exit $?"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

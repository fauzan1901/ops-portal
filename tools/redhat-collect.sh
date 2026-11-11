#!/usr/bin/env bash
# Read-only: the logs and states a Red Hat case about a live migration needs, besides the sosreports, in one tar.gz on the
# bastion. Nothing is changed anywhere. Passwords / CHAP values are masked; Nova's and Cinder's connection_info is never
# read from the databases.
#   source and destination compute: nova-compute.log in the time window (rotated files too), kernel log in the window, multipath.conf,
#     multipath -ll, iSCSI sessions (-P 3, CHAP lines left out), the iSCSI path devices and maps (the portal's host-lvm
#     read), lsblk; and the history of the named devices / WWID: kernel log of 14 days, every nova-compute log line
#     (rotated logs too) naming them, their state in sysfs and udev now;
#   controllers: cinder-volume log lines of the instance's volumes; Nova / Cinder database rows of the instance (its
#     migrations, actions and events, the volumes' attachments with their connector host and status).
# Same path as the portal: portal service account -> management host -> director -> nodes.
# Run on the bastion:
#   sudo bash ~/redhat-collect.sh <SITE> <instance ID> <source> <destination> "<from>" "<to>" [devices,..] [WWID]
#   e.g. sudo bash ~/redhat-collect.sh DCA f6d14761-61f8-4e46-ba5e-48c38872475a overcloud-novacomputeha-2 \
#          overcloud-novacomputeha-0 "2026-10-29 18:30" "2026-10-29 20:30" sdez,sdfa 3600a098038314255672b4f6b4b75564e
#   (times as the logs of the nodes print them)
set -u
SITE="${1:-}"; SID="${2:-}"; SRC="${3:-}"; DST="${4:-}"; FROM="${5:-}"; TO="${6:-}"; DEVS="${7:--}"; WWID="${8:--}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$SID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || { echo "Instance ID: a UUID"; exit 1; }
[[ "$SRC" =~ ^[a-z0-9-]{1,63}$ ]] && [[ "$DST" =~ ^[a-z0-9-]{1,63}$ ]] || { echo "Source and destination: short names"; exit 1; }
for t in "$FROM" "$TO"; do [[ "$t" =~ ^20[0-9]{2}-[0-9]{2}-[0-9]{2}\ [0-9]{2}:[0-9]{2}$ ]] || { echo "Times: \"YYYY-MM-DD HH:MM\""; exit 1; }; done
[[ "$DEVS" =~ ^(-|sd[a-z]{1,4}(,sd[a-z]{1,4}){0,15})$ ]] || { echo "Devices: sdX,sdY or -"; exit 1; }
[[ "$WWID" =~ ^(-|3[0-9a-f]{32})$ ]] || { echo "WWID: 3 + 32 hex, or -"; exit 1; }
STAMP=$(date +%Y%m%d-%H%M%S)
OUT="/home/deploy/redhat-$SITE-${SID:0:8}-$STAMP.tar.gz"
SVC=opsportal
PY=/opt/ops-portal/.venv/bin/python
OPS=/opt/ops-portal/modules/wi/wi_analysis/wi_ops.py
[ -r "$OPS" ] || { echo "$OPS not readable (run with sudo)"; exit 1; }

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
HOP="ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST"

HARNESS=$(cat <<'PY'
import base64, gzip, io, json, os, re, shlex, sys, tarfile, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wi_ops

sid, src, dst, since, until, devs, wwid = sys.argv[1:8]
devs = [] if devs == "-" else devs.split(",")
wwid = "" if wwid == "-" else wwid
d = wi_ops.Director(write=lambda line: None)
work = tempfile.mkdtemp(prefix="wi-rh.")
files = []
MASK = [(re.compile(r"""(['"]?(auth_password|password|secret|target_secret|chap_secret|discovery_auth_password)['"]?\s*[:=]\s*['"]?)[^'",} ]+"""), r"\1***")]


def mask(text):
    for rx, to in MASK:
        text = rx.sub(to, text)
    return text


def save(name, text):
    path = os.path.join(work, name)
    with open(path, "w") as f:
        f.write(mask(text if text.endswith("\n") else text + "\n"))
    files.append(name)
    print(f"  {name}: {len(text.splitlines())} line(s)", flush=True)


# masked on the node itself for the big logs (they go back compressed)
SED_MASK = ("sed -E \"s/(auth_password|password|secret|target_secret|chap_secret)(['\\\"]?[[:space:]]*[:=][[:space:]]*['\\\"]?)"
            "[^'\\\",} ]+/\\1\\2***/g\"")


def save_gz(host, name, inner, timeout=1800):
    """A big read: masked and compressed on the node, kept compressed."""
    out = on_node(host, f"{{ {inner}; }} | {SED_MASK} | gzip -c | base64 -w0", timeout)
    try:
        data = base64.b64decode(out.split("\n")[0].strip(), validate=True)
        lines = len(gzip.decompress(data).splitlines())
    except Exception:   # noqa: BLE001
        data, lines = gzip.compress(mask(out).encode()), -1
    with open(os.path.join(work, name + ".gz"), "wb") as f:
        f.write(data)
    files.append(name + ".gz")
    print(f"  {name}.gz: {lines if lines >= 0 else 'not read, the error kept'} line(s)", flush=True)


def on_node(host, inner, timeout=900):
    ip, user = d.node(host)
    if not ip:
        return f"(no address for {host} in the inventory)"
    rc, out = d.run(wi_ops.SSH + [f"{user}@{ip}", "sudo -n sh -c " + shlex.quote(inner)], show=False, timeout=timeout)
    return str(out or "") + ("" if rc == 0 else f"\n(exit {rc})")


# lines of a log from "since" to "until" (a line without its own time, e.g. a traceback, goes with the line before)
WINDOW = ("awk -v s=%s -v u=%s '/^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-9][0-9]:/ {t = substr($0, 1, 16); in_w = (t >= s && t <= u)} in_w'"
          % (shlex.quote(since), shlex.quote(until)))
CHAP = "grep -viE 'password|username|chap'"
NOVA_LOGS = "/var/log/containers/nova/nova-compute.log"

print(f"Instance {sid}, source {src}, destination {dst}, window {since} .. {until}, devices {','.join(devs) or '-'}, WWID {wwid or '-'}", flush=True)
s = d.server(sid) or {}
vols = s.get("volumes") or []
save("00-instance.txt", json.dumps({k: s.get(k) for k in ("name", "status", "task", "host", "instance", "volumes")}, indent=1))

for role, host in (("source", src), ("destination", dst)):
    tag = f"{role}-{host}"
    # nova-compute logs rotate several times a day at DEBUG: every file, oldest first, each cut to the window
    save_gz(host, f"{tag}-nova-compute-window.log",
            f"for f in $(ls -tr {NOVA_LOGS}* 2>/dev/null); do zcat -f \"$f\" | {WINDOW} | sed \"s|^|$(basename $f): |\"; done")
    save(f"{tag}-kernel-window.log", on_node(host, f"journalctl -k --no-pager -o short-iso --since {shlex.quote(since)} --until {shlex.quote(until)}"))
    save(f"{tag}-multipath.txt", on_node(host,
         "echo '== /etc/multipath.conf'; cat /etc/multipath.conf 2>&1; "
         "m=$(podman ps --format '{{.Names}}' | grep -m1 -x multipathd); echo; echo '== multipath -ll (now)'; "
         "if [ -n \"$m\" ]; then podman exec \"$m\" multipath -ll 2>&1; else multipath -ll 2>&1; fi"))
    save(f"{tag}-iscsi-sessions.txt", on_node(host,
         "i=$(podman ps --format '{{.Names}}' | grep -m1 -x iscsid); "
         f"if [ -n \"$i\" ]; then podman exec \"$i\" iscsiadm -m session -P 3 2>&1; else iscsiadm -m session -P 3 2>&1; fi | {CHAP}"))
    save(f"{tag}-paths-and-maps.txt", on_node(host, wi_ops.HOST_LVS + "\necho; echo '== lsblk'; lsblk -o NAME,KNAME,HCTL,SIZE,TYPE,STATE,WWN 2>&1"))
    if devs or wwid:
        pat = "|".join([rf"\b{x}\b" for x in devs] + ([wwid] if wwid else []))
        save(f"{tag}-history-kernel-14d.log", on_node(host,
             f"journalctl -k --no-pager -o short-iso --since '-14 days' | grep -E {shlex.quote(pat)}"))
        save_gz(host, f"{tag}-history-nova-compute.log",
                f"for f in $(ls -tr {NOVA_LOGS}* 2>/dev/null); do zcat -f \"$f\" | grep -E {shlex.quote(pat)} | sed \"s|^|$(basename $f): |\"; done")
    if devs:
        inner = ""
        for x in devs:
            inner += (f"echo '== {x}'; if [ -e /sys/block/{x}/device ]; then echo \"address $(basename $(readlink -f /sys/block/{x}/device)) "
                      f"state $(cat /sys/block/{x}/device/state) wwid $(cat /sys/block/{x}/device/wwid 2>/dev/null) "
                      f"ioerr $(cat /sys/block/{x}/device/ioerr_cnt 2>/dev/null) holders $(ls /sys/block/{x}/holders | paste -sd, -)\"; "
                      f"udevadm info --query=property --name=/dev/{x} 2>&1 | grep -E '^(DEVLINKS|ID_SERIAL|ID_WWN|ID_PATH|DM_MULTIPATH_DEVICE_PATH|ID_FS_TYPE)='; "
                      f"else echo 'not present now'; fi; ")
        if wwid:
            inner += (f"echo '== map {wwid}'; dmsetup info {wwid} 2>&1; dmsetup table {wwid} 2>&1; dmsetup status {wwid} 2>&1; ")
        save(f"{tag}-devices-now.txt", on_node(host, inner))

# controllers: cinder-volume lines of the volumes; database rows (no connection_info)
d.node(src)   # loads the inventory
ctrls = sorted(h for h in (d._inventory or {}) if "controller" in h)
pat = "|".join([sid] + vols)
for c in ctrls:
    save_gz(c, f"controller-{c}-cinder-volume.log",
            f"for f in $(ls -tr /var/log/containers/cinder/cinder-volume.log* 2>/dev/null); do zcat -f \"$f\" | {WINDOW} | grep -E {shlex.quote(pat)} | sed \"s|^|$(basename $f): |\"; done")
if ctrls:
    q = lambda x: "'" + x.replace("'", "") + "'"
    vin = ",".join(q(v) for v in vols) or "''"
    sql = (f"SELECT 'migration', id, status, migration_type, source_compute, dest_compute, created_at, updated_at FROM nova.migrations "
           f"WHERE instance_uuid={q(sid)} ORDER BY id;\n"
           f"SELECT 'action', a.action, a.request_id, a.start_time, a.finish_time, e.event, e.start_time, e.finish_time, e.result, e.host "
           f"FROM nova.instance_actions a LEFT JOIN nova.instance_actions_events e ON e.action_id=a.id WHERE a.instance_uuid={q(sid)} "
           f"AND a.start_time >= UTC_TIMESTAMP() - INTERVAL 3 DAY ORDER BY a.start_time, e.start_time;\n"
           f"SELECT 'attachment', id, volume_id, attach_status, attached_host, instance_uuid, "
           f"JSON_UNQUOTE(JSON_EXTRACT(connector, '$.host')), JSON_UNQUOTE(JSON_EXTRACT(connector, '$.initiator')), created_at, "
           f"updated_at, deleted, deleted_at FROM cinder.volume_attachment WHERE volume_id IN ({vin}) "
           f"AND created_at >= UTC_TIMESTAMP() - INTERVAL 3 DAY ORDER BY created_at;\n")
    sb = base64.b64encode(sql.encode()).decode()
    save("controller-database-rows.txt", "times in UTC\n" + on_node(ctrls[0],
         f"echo {sb} | base64 -d | podman exec -i $(podman ps -q -f name=galera-bundle | head -1) mysql -N -B"))

buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w:gz") as tar:
    for name in files:
        tar.add(os.path.join(work, name), arcname=f"redhat-{sid[:8]}/{name}")
sys.stdout.write("@@TAR " + base64.b64encode(buf.getvalue()).decode() + "\n")
wi_ops.SSH_POOL.close()
PY
)

REMOTE=$(cat <<'EOF'
set -u
source $RC >/dev/null 2>&1 || { echo "source $RC failed"; exit 1; }
W=$(mktemp -d /tmp/wi-rhc.XXXXXXXX) || exit 1
trap 'rm -rf "$W" /tmp/wi-rh.*' EXIT
printf %s "$OPSB" | base64 -d | gunzip > "$W/wi_ops.py"
printf %s "$HB" | base64 -d > "$W/harness.py"
python3 -u "$W/harness.py" "$SID" "$SRC" "$DST" "$FROM" "$TO" "$DEVS" "$WWID"
EOF
)

echo "Read-only, $(date -Is), site $SITE, instance $SID, $SRC -> $DST, $FROM .. $TO; director $DIR_USER@$DIR_HOST"
OPSB=$(gzip -c "$OPS" | base64 -w0)
HB=$(printf '%s\n' "$HARNESS" | base64 -w0)
TMP=$(mktemp)
printf 'RC=%s\nSID=%q\nSRC=%q\nDST=%q\nFROM=%q\nTO=%q\nDEVS=%q\nWWID=%q\nOPSB=%q\nHB=%q\n%s\n' "$RC" "$SID" "$SRC" "$DST" "$FROM" "$TO" \
  "$DEVS" "$WWID" "$OPSB" "$HB" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" "$HOP bash -s" 2>&1 | grep -v '^\*\* ' > "$TMP"
grep -v '^@@TAR ' "$TMP"
if grep -q '^@@TAR ' "$TMP"; then
  grep '^@@TAR ' "$TMP" | cut -c7- | base64 -d > "$OUT" && chown deploy: "$OUT"
  echo "Saved: $OUT ($(du -h "$OUT" | cut -f1)); files:"
  tar -tzf "$OUT" | sed 's/^/   /'
else
  echo "No archive came back (see the lines above)"
fi
rm -f "$TMP"

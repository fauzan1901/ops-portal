#!/usr/bin/env bash
# Read-only: where the time of a drain goes. For the live migrations from one compute in the last <hours>, from Nova's
# database on a controller (SELECT only): per instance its RAM, Nova's own phases (request -> pre_live_migration on the
# destination -> memory copy -> post on the destination -> completed) and the gap until the next migration starts (the
# portal's checks after this one and before the next one, plus any wait). Then the averages, the instances still on the
# compute and when the drain ends at that pace.
# Same path as the portal: portal service account -> management host -> director -> controller.
# Run on the bastion:  sudo bash ~/migration-timing.sh <SITE> <source compute, short name> [hours back, default 12]
set -u
SITE="${1:-}"
SRC="${2:-}"
HOURS="${3:-12}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$SRC" =~ ^[a-z0-9-]{1,63}$ ]] || { echo "Source compute: its short name, e.g. dcbrhosp-az1-compute-2"; exit 1; }
[[ "$HOURS" =~ ^[0-9]{1,2}$ ]] && [ "$HOURS" -ge 1 ] && [ "$HOURS" -le 72 ] || { echo "Hours back: 1 to 72"; exit 1; }
OUT="/home/deploy/migration-timing-$SITE-$SRC-$(date +%Y%m%d-%H%M%S).txt"
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

MIGS="SELECT instance_uuid FROM nova.migrations WHERE deleted=0 AND migration_type='live-migration'
 AND (source_compute='$SRC' OR source_compute LIKE '$SRC.%') AND created_at >= UTC_TIMESTAMP() - INTERVAL $HOURS HOUR"
SQL="SELECT '@@mig', m.id, m.instance_uuid, IFNULL(REPLACE(i.display_name,'\t',' '),'-'), IFNULL(i.memory_mb,0), m.status,
 IFNULL(m.dest_compute,'-'), IFNULL(m.created_at,'-'), IFNULL(m.updated_at,'-')
 FROM nova.migrations m LEFT JOIN nova.instances i ON i.uuid=m.instance_uuid
 WHERE m.deleted=0 AND m.migration_type='live-migration' AND (m.source_compute='$SRC' OR m.source_compute LIKE '$SRC.%')
 AND m.created_at >= UTC_TIMESTAMP() - INTERVAL $HOURS HOUR ORDER BY m.id;
SELECT '@@ev', a.instance_uuid, a.start_time, e.event, IFNULL(e.start_time,'-'), IFNULL(e.finish_time,'-')
 FROM nova.instance_actions a JOIN nova.instance_actions_events e ON e.action_id=a.id
 WHERE a.action='live-migration' AND a.start_time >= UTC_TIMESTAMP() - INTERVAL $HOURS HOUR AND a.instance_uuid IN ($MIGS)
 ORDER BY a.start_time, e.start_time;
SELECT '@@left', COUNT(*), IFNULL(SUM(memory_mb),0) FROM nova.instances WHERE deleted=0 AND (host='$SRC' OR host LIKE '$SRC.%');
SELECT '@@now', UTC_TIMESTAMP();"
QB=$(printf '%s\n' "$SQL" | base64 -w0)

REMOTE=$(cat <<'EOF'
set -u
INV=$(ls ~/overcloud-deploy/*/tripleo-ansible-inventory.yaml ~/config-download/*/tripleo-ansible-inventory.yaml \
  ~/tripleo-ansible-inventory.yaml 2>/dev/null | head -1)
read -r CN CIP CUSR < <(python3 - "$INV" <<'PY'
import sys, yaml
try:
    inv = yaml.safe_load(open(sys.argv[1])) or {}
except Exception:
    inv = {}
for group, body in inv.items():
    for host, hv in ((body or {}).get("hosts") or {}).items() if isinstance(body, dict) else []:
        if "controller" in (group + host).lower() and isinstance(hv, dict):
            print(host.split(".")[0], hv.get("ctlplane_ip") or hv.get("ansible_host") or "-", hv.get("ansible_ssh_user") or "-")
            raise SystemExit
PY
)
[ -n "${CIP:-}" ] && [ "$CIP" != "-" ] || { echo "no controller in the inventory $INV: database not read"; exit 1; }
U="${CUSR:--}"; [ "$U" = "-" ] && U=$(grep -q '17\.' /etc/rhosp-release && echo tripleo-admin || echo heat-admin)
echo "@@controller $CN"
ssh -n -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$U@$CIP" \
  "echo $QB | base64 -d | sudo podman exec -i \$(sudo podman ps -q -f name=galera-bundle | head -1) mysql -N -B"
EOF
)

REPORT=$(cat <<'PY'
import sys
from datetime import datetime, timedelta, timezone

WIB = timezone(timedelta(hours=7))
src = sys.argv[1]


def ts(text):
    try:
        return datetime.strptime(text[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def mins(sec):
    if sec is None:
        return "-"
    sec = int(round(sec))
    return "%d:%02d" % (sec // 60, sec % 60)


def wib(t):
    return t.astimezone(WIB).strftime("%H:%M:%S") if t else "-"


migs, events, left, now, other = [], {}, None, None, []
for line in sys.stdin:
    f = line.rstrip("\n").split("\t")
    if f[0] == "@@mig" and len(f) == 9:
        migs.append(dict(id=f[1], uuid=f[2], name=f[3], ram=int(f[4] or 0), status=f[5], dest=f[6].split(".")[0],
                         created=ts(f[7]), updated=ts(f[8])))
    elif f[0] == "@@ev" and len(f) == 6:
        # the events of the live-migration action that started closest after the migration record was created
        events.setdefault(f[1], []).append((ts(f[2]), f[3], ts(f[4]), ts(f[5])))
    elif f[0] == "@@left" and len(f) == 3:
        left = (int(f[1]), int(f[2]))
    elif f[0] == "@@now" and len(f) == 2:
        now = ts(f[1])
    elif line.startswith("@@controller "):
        print("== Database on", line.split()[1], "(SELECT only); times in WIB")
    elif line.strip() and not line.lstrip().startswith("** "):
        other.append(line.rstrip())
for line in other[:20]:
    print("  ", line[:300])
if not migs:
    print("No live migration from %s in this window." % src)
    raise SystemExit

print("%-6s %-34s %6s %-10s %-24s %8s %8s %8s %8s %8s %8s" % (
    "Mig", "Instance", "RAM GB", "Status", "Destination", "Start", "Pre", "Copy", "Post", "Nova", "Gap"))
rows = []
for k, m in enumerate(migs):
    evs = [e for e in events.get(m["uuid"], []) if e[0] and m["created"] and abs((e[0] - m["created"]).total_seconds()) < 600]
    ev = {name: (s, f) for _a, name, s, f in evs}
    pre = ev.get("compute_pre_live_migration")
    live = ev.get("compute_live_migration")
    post = ev.get("compute_post_live_migration_at_destination")
    pre_s = (pre[1] - pre[0]).total_seconds() if pre and pre[0] and pre[1] else None
    copy_s = (post[0] - live[0]).total_seconds() if live and post and live[0] and post[0] else None
    post_s = (m["updated"] - post[0]).total_seconds() if post and post[0] and m["updated"] and m["status"] == "completed" else None
    nova_s = (m["updated"] - m["created"]).total_seconds() if m["created"] and m["updated"] else None
    nxt = migs[k + 1]["created"] if k + 1 < len(migs) else None
    gap_s = (nxt - m["updated"]).total_seconds() if nxt and m["updated"] else None
    rows.append(dict(m, pre=pre_s, copy=copy_s, post=post_s, nova=nova_s, gap=gap_s))
    print("%-6s %-34s %6.1f %-10s %-24s %8s %8s %8s %8s %8s %8s" % (
        m["id"], m["name"][:34], m["ram"] / 1024.0, m["status"][:10], m["dest"][-24:], wib(m["created"]),
        mins(pre_s), mins(copy_s), mins(post_s), mins(nova_s), mins(gap_s)))


BREAK = 900   # a gap longer than 15 min is a pause between runs (or an item that was not migrated), not the pace


def median(vals):
    vals = sorted(vals)
    n = len(vals)
    return (vals[n // 2] if n % 2 else (vals[n // 2 - 1] + vals[n // 2]) / 2) if vals else None


def avg(key, only=None):
    vals = [r[key] for r in rows if r[key] is not None and (only is None or only(r)) and not (key == "gap" and r[key] > BREAK)]
    return (median(vals), len(vals)) if vals else (None, 0)


done = [r for r in rows if r["status"] == "completed"]
first = rows[0]["created"]
steps = [(b["created"] - a["created"]).total_seconds() for a, b in zip(rows, rows[1:]) if a["created"] and b["created"]]
pauses = [s for s in steps if s > BREAK]
per_vm = median([s for s in steps if s <= BREAK])
print()
print("== %d live migration(s) from %s since %s WIB: %d completed, %d other (%s)" % (
    len(rows), src, wib(first), len(done), len(rows) - len(done),
    ", ".join(sorted({r["status"] for r in rows if r["status"] != "completed"})) or "none"))
print("   median of each phase (gaps over 15 min left out: %d pause(s), %s in all)" % (
    len(pauses), mins(sum(pauses)) if pauses else "0:00"))
for label, key in (("Pre (destination connects volumes, ports)", "pre"), ("Copy (memory)", "copy"),
                   ("Post (destination)", "post"), ("Nova in all (request -> completed)", "nova"),
                   ("Gap to the next start (portal checks, waits)", "gap")):
    a, n = avg(key, lambda r: r["status"] == "completed")
    print("   %-54s %s  (%d)" % (label, mins(a), n))
if per_vm:
    print("   %-54s %s" % ("Start to start (one instance in all)", mins(per_vm)))
if left:
    print("== Still on %s now: %d instance(s), %.0f GB RAM in all" % (src, left[0], left[1] / 1024.0))
    if per_vm and now:
        total = per_vm * left[0]
        print("   at that pace, without pauses, the last one starts around %s WIB (%d h %02d min from now)" % (
            (now + timedelta(seconds=total)).astimezone(WIB).strftime("%d %b %H:%M"), total // 3600, total % 3600 // 60))
PY
)

{
  echo "Read-only, $(date -Is), site $SITE, source $SRC, last $HOURS h; management host $MGMT_HOST, director $DIR_USER@$DIR_HOST (keys are not printed)"
  printf 'QB=%q\n%s\n' "$QB" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1 | "$PY" -c "$REPORT" "$SRC"
  echo "== exit ${PIPESTATUS[1]}"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

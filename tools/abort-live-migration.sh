#!/usr/bin/env bash
# Abort ONE running live migration (what the portal itself does when a migration is still running at its timeout, with
# stall abort): the instance keeps running on its source, Nova rolls the destination back. Before it, read-only: the
# instance and the migration must still be the ones named (status MIGRATING, migration live and not ended), and what
# libvirt and nova-compute say on the source and the destination (virsh domjobinfo / domstate, the migration lines of the
# nova-compute log; no connection info). After it: followed up to 5 minutes until the instance is ACTIVE on its source.
# The portal item that watches the migration sees it cancelled, runs its own checks of the rollback and ends FAILED (the
# instance did not move); the run then stops or goes on with the next instance, as it was started.
# Same path as the portal: portal service account -> management host -> director -> computes.
# Run on the bastion:  sudo bash ~/abort-live-migration.sh <SITE> <instance ID> <migration ID>
set -u
SITE="${1:-}"
SID="${2:-}"
MID="${3:-}"
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[[ "$SID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || { echo "Instance ID: a UUID"; exit 1; }
[[ "$MID" =~ ^[0-9]{1,10}$ ]] || { echo "Migration ID: a number"; exit 1; }
OUT="/home/deploy/abort-live-migration-$SITE-$(date +%Y%m%d-%H%M%S).txt"
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
import os, shlex, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wi_ops

LOOK = ("c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$'); "
        "echo \"virsh domstate: $(timeout 30 podman exec \"$c\" virsh -c qemu:///system domstate --reason %(inst)s 2>&1)\"; "
        "p=$(pgrep -f 'guest=%(inst)s,' | head -1); "
        "if [ -n \"$p\" ]; then echo \"qemu process $p: state $(ps -o stat= -p $p), $(ps -L -o stat= -p $p | grep -c '^D') "
        "thread(s) waiting on I/O (D), in $(ps -o wchan:30= -p $p)\"; else echo 'no qemu process of %(inst)s here'; fi; "
        "echo 'kernel, disk / path / iSCSI messages of the last 90 minutes (last 8):'; "
        "journalctl -k --since '-90 min' --no-pager 2>/dev/null | grep -iE 'I/O error|blk_update_request|Buffer I/O|"
        "active paths: 0|failing path|reinstated|session recovery|conn error|hung_task|blocked for more than' "
        "| tail -n 8 | cut -c1-300 | sed 's/^/   /'; ")
JOB = "timeout 30 podman exec \"$c\" virsh -c qemu:///system domjobinfo %(inst)s 2>&1 | sed 's/^/   /'; "
LOG = ("echo 'nova-compute log, migration lines of the instance (last %(n)d):'; "
       "grep -h %(sid)s " + wi_ops.NOVA_COMPUTE_LOG + " | grep -E 'Migration running for|downtime|[Ll]ive migration|abort|"
       "rollback|ERROR|WARNING' | grep -viE 'connection_info|password|secret|auth_|chap' | tail -n %(n)d | cut -c1-400 "
       "| sed 's/^/   /'")


def look(d, host, inst, sid, job, n):
    ip, user = d.node(host)
    if not ip:
        print(f"{wi_ops.short(host)}: address not in the inventory, not read")
        return
    inner = LOOK % {"inst": inst} + (JOB % {"inst": inst} if job else "") + LOG % {"sid": sid, "n": n}
    rc, out = d.run(wi_ops.SSH + [f"{user}@{ip}", "sudo -n sh -c " + shlex.quote(inner)], show=False, timeout=180)
    print(f"-- {wi_ops.short(host)} ({ip}):")
    print(str(out or "").rstrip() or f"   (no output, exit {rc})")


def main(d, sid, mid, sleep=time.sleep, clock=time.time):
    s = d.server(sid)
    if not s or s.get("unknown"):
        print(f"Instance {sid} could not be read ({(s or {}).get('unknown', 'not found')}): nothing sent")
        return 1
    print(f"Instance {s['name']} ({sid}): status {s['status']}, task {s['task'] or '-'}, on {s['host']}, {s['instance']}")
    migs = [m for m in d.migrations(sid) if m["type"] in ("", "live-migration")]
    m = next((x for x in migs if x["id"] == mid), None)
    if not m:
        print(f"No live migration {mid} of this instance: nothing sent")
        return 1
    print(f"Migration {mid}: {m['status']}, {m['source']} -> {m['dest']}, created {m['created']} (UTC)")
    if m["status"] not in wi_ops.LIVE_BUSY or (s["status"] != "MIGRATING" and s["task"] != "migrating"):
        print(f"The migration is not running any more ({m['status']}, instance {s['status']}): nothing sent")
        return 0
    print("\n== Before (read-only)")
    look(d, s["host"], s["instance"], sid, True, 12)
    if m["dest"]:
        look(d, m["dest"], s["instance"], sid, False, 6)
    print("\n== Abort of migration %d (the instance keeps running on %s)" % (mid, wi_ops.short(s["host"])))
    rc, out = d.abort(sid, mid)
    if rc != 0:
        print(f"Nova refused the abort ({wi_ops.last_error(out) or f'exit {rc}'}): nothing changed, the migration goes on")
        return 1
    print("Nova accepted the abort; followed until the instance is ACTIVE on its source (up to 5 minutes)")
    start, seen = clock(), ""
    while clock() - start < 300:
        sleep(10)
        s2 = d.server(sid) or {}
        m2 = next((x for x in d.migrations(sid) if x["id"] == mid), {})
        now = f"instance {s2.get('status', '?')}, task {s2.get('task') or '-'}, on {s2.get('host', '?')}; migration {m2.get('status', '?')}"
        if now != seen:
            print(f"  {int(clock() - start)} s: {now}")
            seen = now
        if s2.get("status") == "ACTIVE" and not s2.get("task") and m2.get("status") not in wi_ops.LIVE_BUSY:
            break
    print("\n== After (read-only)")
    look(d, s["host"], s["instance"], sid, False, 8)
    if m["dest"]:
        look(d, m["dest"], s["instance"], sid, False, 6)
    s2 = d.server(sid) or {}
    back = s2.get("status") == "ACTIVE" and not s2.get("task") and wi_ops.short(s2.get("host", "")) == wi_ops.short(s["host"])
    print("\nRESULT " + ("ok: " if back else "ATTENTION: ") + f"{s['name']} is {s2.get('status', '?')} (task {s2.get('task') or '-'}) "
          f"on {s2.get('host', '?')}" + ("" if back else "; not yet back on its source: run this again in a few minutes "
                                         "to read it (the abort is not sent twice once the migration has ended)"))
    return 0 if back else 2


if __name__ == "__main__":
    director = wi_ops.Director(write=print)
    try:
        sys.exit(main(director, sys.argv[1], int(sys.argv[2])))
    finally:
        wi_ops.SSH_POOL.close()
PY
)

REMOTE=$(cat <<'EOF'
set -u
source $RC >/dev/null 2>&1 || { echo "source $RC failed"; exit 1; }
W=$(mktemp -d /tmp/wi-abort.XXXXXXXX) || exit 1
trap 'rm -rf "$W"' EXIT
printf %s "$OPSB" | base64 -d | gunzip > "$W/wi_ops.py"
printf %s "$HB" | base64 -d > "$W/harness.py"
python3 "$W/harness.py" "$SID" "$MID"
EOF
)

{
  echo "$(date -Is), site $SITE, instance $SID, migration $MID; wi_ops.py $OPS ($(md5sum < "$OPS" | cut -c1-8)); director $DIR_USER@$DIR_HOST"
  OPSB=$(gzip -c "$OPS" | base64 -w0)
  HB=$(printf '%s\n' "$HARNESS" | base64 -w0)
  printf 'RC=%s\nSID=%q\nMID=%q\nOPSB=%q\nHB=%q\n%s\n' "$RC" "$SID" "$MID" "$OPSB" "$HB" "$REMOTE" | sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" \
    "$HOP bash -s" 2>&1 | grep -v '^\*\* '
  echo "== exit ${PIPESTATUS[1]}"
} | tee "$OUT"
chown deploy: "$OUT"
echo "Saved: $OUT"

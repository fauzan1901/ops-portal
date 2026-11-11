#!/usr/bin/env bash
# Read-only: the result of each item of a fix of the portal (e.g. a drain: one live migration per instance), from the
# portal's database, with every line of the item's output that names a disk problem: I/O errors in the guest console or
# the compute's kernel, domblkerror of the domain, a filesystem error / read-only remount, a disk that lost its paths, the
# disks of other instances touched by a disconnect, hung tasks. The portal reads these after each migration.
# Run on the bastion:  sudo bash ~/fix-items.sh <fix number>
set -u
FIX="${1:-}"
[[ "$FIX" =~ ^[0-9]{1,7}$ ]] || { echo "Fix number: e.g. 113"; exit 1; }
DB=/var/lib/ops-portal/portal.db
PY=/opt/ops-portal/.venv/bin/python
[ -r "$DB" ] || { echo "$DB not readable (run with sudo)"; exit 1; }
OUT="/home/deploy/fix-items-$FIX-$(date +%Y%m%d-%H%M%S).txt"

"$PY" - "$DB" "$FIX" <<'PY' | tee "$OUT"
import json, re, sqlite3, sys
db, fix = sys.argv[1], int(sys.argv[2])
con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
con.row_factory = sqlite3.Row
a = con.execute("SELECT * FROM wi_actions WHERE id = ?", (fix,)).fetchone()
if not a:
    print(f"Fix #{fix} not found")
    raise SystemExit(1)
r = con.execute("SELECT site, check_id, host, params FROM wi_runs WHERE id = ?", (a["run_id"],)).fetchone()
print(f"Fix #{fix}: {a['status']}, by {a['username']}, started {a['ts']}, ended {a['finished'] or '-'}; run #{a['run_id']}"
      + (f" {r['check_id']} on {r['site']} {r['host'] or ''} {r['params'] or ''}" if r else ""))
if a["error"]:
    print(f"Result: {a['error'][:600]}")
try:
    steps = json.loads(a["output"] or "[]")
except ValueError:
    steps = []
BAD = re.compile(r"I/O error|blk_update_request|Buffer I/O|EXT4-fs (error|warning)|XFS \(\S+\): .*(error|corrupt|shutdown)|"
                 r"[Rr]emounting filesystem read-only|read-only file ?system|disk error|domblkerror|lost (its|their|all) paths|"
                 r"no (running |working )?path|had I/O errors|touched the disks of other instances|blocked for more than|"
                 r"hung_task|soft lockup|paused \(ioerror\)|ioerror", re.I)
FINE = re.compile(r"without disk errors|disk errors: none|no I/O error", re.I)
flagged, done = [], 0
print(f"\n{len(steps)} item(s) in the result")
for st in steps:
    out = str(st.get("out") or "")
    res = next((l for l in reversed(out.splitlines()) if l.startswith("RESULT ")), "(no RESULT line)")
    # the commands the item printed ("$ ssh ... virsh domstate / domblkerror ...") are no finding
    hits = [l.strip() for l in out.splitlines() if BAD.search(l) and not FINE.search(l) and not l.lstrip().startswith("$ ")]
    rc = st.get("rc")
    done += 1 if str(rc) == "0" else 0
    mark = "!!" if hits else "ok" if str(rc) == "0" else "--"
    print(f"\n[{mark}] {st.get('command')}  (exit {rc})")
    print(f"     {res[:400]}")
    for h in list(dict.fromkeys(hits))[:6]:
        print(f"     >> {h[:300]}")
    if hits:
        flagged.append(st.get("command"))
print(f"\n== {len(steps)} item(s): {done} ok, {len(steps) - done} not ok; {len(flagged)} with a disk problem named in their output")
for f in flagged:
    print(f"   {f}")
PY
chown deploy: "$OUT"
echo "Saved: $OUT"

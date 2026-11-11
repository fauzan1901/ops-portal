#!/usr/bin/env bash
# Read-only: the items of the portal's fixes of the last days that name an instance (its name or ID), from the portal's
# database: which fix and item, its exit code, and what the item printed (without the commands it ran and without
# console screenshots): status of the instance, waits, attempts, automatic fixes, progress of the migration, time, result.
# Run on the bastion:  sudo bash ~/fix-search.sh <name or ID>[,<name or ID>...] [days, default 2]
#   e.g. sudo bash ~/fix-search.sh test-10,TenantVM1,TenantVM2
set -u
WHAT="${1:-}"
DAYS="${2:-2}"
[[ "$WHAT" =~ ^[A-Za-z0-9_.,-]{2,400}$ ]] || { echo "Names or IDs, comma separated"; exit 1; }
[[ "$DAYS" =~ ^[0-9]{1,2}$ ]] || { echo "Days: a number"; exit 1; }
DB=/var/lib/ops-portal/portal.db
PY=/opt/ops-portal/.venv/bin/python
[ -r "$DB" ] || { echo "$DB not readable (run with sudo)"; exit 1; }
OUT="/home/deploy/fix-search-$(date +%Y%m%d-%H%M%S).txt"

"$PY" - "$DB" "$WHAT" "$DAYS" <<'PY' | tee "$OUT"
import datetime, json, sqlite3, sys
db, what, days = sys.argv[1], [w.lower() for w in sys.argv[2].split(",") if w], int(sys.argv[3])
con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
con.row_factory = sqlite3.Row
since = (datetime.datetime.now() - datetime.timedelta(days=days)).strftime("%Y-%m-%d")
found = 0
for a in con.execute("SELECT * FROM wi_actions WHERE ts >= ? ORDER BY id", (since,)):
    try:
        steps = json.loads(a["output"] or "[]")
    except ValueError:
        continue
    r = con.execute("SELECT site, check_id, params FROM wi_runs WHERE id = ?", (a["run_id"],)).fetchone()
    for i, st in enumerate(steps, 1):
        out = str(st.get("out") or "")
        label = str(st.get("command") or "")
        if not any(w in (label + "\n" + out).lower() for w in what):
            continue
        found += 1
        print(f"\n== Fix #{a['id']} item {i} ({r['site'] if r else '?'} {r['check_id'] if r else ''}), fix {a['status']}, "
              f"started {a['ts']}, ended {a['finished'] or '-'}, by {a['username']}")
        print(f"   {label}  (exit {st.get('rc')})")
        lines = [l for l in out.splitlines() if l.strip() and not l.startswith("@@WI@@shot") and len(l) < 600
                 and not l.lstrip().startswith("$ ")]
        for l in lines[-45:]:
            print(f"   | {l[:300]}")
print(f"\n{found} item(s) found for {', '.join(what)} since {since}")
PY
chown deploy: "$OUT"
echo "Saved: $OUT"

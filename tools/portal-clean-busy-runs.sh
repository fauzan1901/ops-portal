#!/usr/bin/env bash
# The "Could not run" runs that the check after a fix left in the history while the same check was still running
# (a real case: 30 tries 2 s apart for every fix that ended; fixed in the portal package after 20261101-135458):
# status error, the error the portal gives when the same check is already running, and no fix started from them or
# linked to them. Without --delete it only counts and lists them. With --delete: a copy of the database first (sqlite
# backup, next to it), then those rows only; every other run and every fix stay as they are.
# Run on the bastion:  sudo bash ~/portal-clean-busy-runs.sh            (count, nothing changes)
#                      sudo bash ~/portal-clean-busy-runs.sh --delete   (copy of the database, then delete those rows)
set -u
DB=/var/lib/ops-portal/portal.db
PY=/opt/ops-portal/.venv/bin/python
SVC=opsportal
MODE="${1:-}"
[ -z "$MODE" ] || [ "$MODE" = "--delete" ] || { echo "Usage: sudo bash ~/portal-clean-busy-runs.sh [--delete]"; exit 1; }
[ -r "$DB" ] || { echo "$DB cannot be read (run with sudo)"; exit 1; }
sudo -u "$SVC" "$PY" - "$DB" "$MODE" <<'PY'
import datetime, sqlite3, sys
db, mode = sys.argv[1], sys.argv[2]
BUSY = "The same check, a fix on the same host, or a fix of the same kind on this site%"
WHERE = ("status = 'error' AND error LIKE ? AND id NOT IN (SELECT run_id FROM wi_actions) "
         "AND id NOT IN (SELECT verify_run_id FROM wi_actions WHERE verify_run_id IS NOT NULL)")
con = sqlite3.connect(db, timeout=30)
rows = con.execute(f"SELECT id, ts, site, check_id FROM wi_runs WHERE {WHERE} ORDER BY id", (BUSY,)).fetchall()
total = con.execute("SELECT COUNT(*) FROM wi_runs").fetchone()[0]
print(f"{len(rows)} 'Could not run' run(s) refused because the same check was running (of {total} runs in the history)")
groups = {}
for r in rows:
    groups.setdefault((r[2], r[3]), []).append(r)
for (site, check), rs in sorted(groups.items()):
    print(f"   {site} {check}: {len(rs)} run(s), #{rs[0][0]} .. #{rs[-1][0]}, {rs[0][1][:16].replace('T', ' ')} .. "
          f"{rs[-1][1][:16].replace('T', ' ')}")
if not rows:
    raise SystemExit
if mode != "--delete":
    print("Nothing was deleted. To delete exactly these: sudo bash ~/portal-clean-busy-runs.sh --delete")
    raise SystemExit
bak = f"{db}.before-clean-{datetime.datetime.now():%Y%m%d-%H%M%S}"
dst = sqlite3.connect(bak)
con.backup(dst)
dst.close()
print(f"Copy of the database first: {bak}")
with con:
    n = con.execute(f"DELETE FROM wi_runs WHERE {WHERE}", (BUSY,)).rowcount
left = con.execute("SELECT COUNT(*) FROM wi_runs").fetchone()[0]
print(f"Deleted {n} run(s); {left} runs are left in the history, every fix is unchanged")
PY

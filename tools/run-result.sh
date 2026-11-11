#!/usr/bin/env bash
# Read-only: the result of one check run of the portal (page WI), from the portal's database, as text: its steps (status,
# detail, table, the last evidence lines) and its recommendations (commands, items). Nothing is changed.
# Run on the bastion:  sudo bash ~/run-result.sh <run number> [all]      e.g. sudo bash ~/run-result.sh 416
#   all: every row of every table, cells not shortened, and each table also as a CSV file beside the text.
set -u
RUN="${1:-}"
ALL="${2:-}"
[[ "$RUN" =~ ^[0-9]{1,7}$ ]] || { echo "Run number: e.g. 416"; exit 1; }
[ -z "$ALL" ] || [ "$ALL" = all ] || { echo "Second argument: all (or nothing)"; exit 1; }
DB=/var/lib/ops-portal/portal.db
PY=/opt/ops-portal/.venv/bin/python
[ -r "$DB" ] || { echo "$DB not readable (run with sudo)"; exit 1; }
OUT="/home/deploy/run-result-$RUN-$(date +%Y%m%d-%H%M%S).txt"

"$PY" - "$DB" "$RUN" "$ALL" "${OUT%.txt}" <<'PY' | tee "$OUT"
import csv, json, sqlite3, sys
db, run, full, base = sys.argv[1], int(sys.argv[2]), sys.argv[3] == "all", sys.argv[4]
rows_max, cell_max = (None, None) if full else (60, 90)
con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
con.row_factory = sqlite3.Row
r = con.execute("SELECT * FROM wi_runs WHERE id = ?", (run,)).fetchone()
if not r:
    print(f"Run #{run} not found"); raise SystemExit(1)
print(f"Run #{run}: {r['check_id']} ({r['check_title']}) on {r['site']} {r['host'] or ''} params {r['params'] or '{}'}")
print(f"   by {r['username']}, {r['ts']} .. {r['finished'] or '-'}, status {r['status']}" + (f", error: {r['error'][:300]}" if r["error"] else ""))
try:
    res = json.loads(r["result"] or "{}")
except ValueError:
    res = {}
for n, s in enumerate(res.get("steps") or [], 1):
    print(f"\n[{str(s.get('status')).upper()}] {s.get('title')}")
    print(f"   {s.get('detail') or ''}")
    t = s.get("table") or {}
    if t.get("rows"):
        print("   | " + " | ".join(str(c) for c in t.get("columns") or []))
        for row in t["rows"][:rows_max]:
            print("   | " + " | ".join(str(c)[:cell_max] for c in row))
        if rows_max and len(t["rows"]) > rows_max:
            print(f"   ... {len(t['rows']) - rows_max} more row(s) (all of them: add 'all')")
        if full:
            with open(f"{base}-step{n}.csv", "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(t.get("columns") or [])
                w.writerows(t["rows"])
            print(f"   CSV: {base}-step{n}.csv ({len(t['rows'])} row(s))")
    ev = s.get("evidence") or []
    ev = ev.splitlines() if isinstance(ev, str) else list(ev)
    if ev:
        print(f"   evidence ({len(ev)} line(s), the last 25):")
        for line in ev[-25:]:
            print(f"     {str(line)[:220]}")
for i, rec in enumerate(res.get("recommendations") or [], 1):
    print(f"\n== Recommendation {i}: {rec.get('text') or ''}")
    for c in rec.get("commands") or []:
        print(f"   $ {c}")
    items = rec.get("items") or {}
    for row in (items.get("rows") or [])[:20]:
        print("   - " + " | ".join(str(c) for c in row))
    if rec.get("warning"):
        print(f"   ! {rec['warning']}")
PY
chown deploy: "$OUT" "${OUT%.txt}"-step*.csv 2>/dev/null
echo "Saved: $OUT"

#!/usr/bin/env bash
# Read-only: where the time of a live-migration fix of the portal goes, from the portal's database. Per item: the
# "Time:" line wi_ops prints (checks before, migration, checks after, in all), the waits for another migration of the
# site, the attempts, and the result; per fix: the wall clock per item against the time inside the items (the rest is
# the portal / Ansible between two items), the median and the slowest items per phase.
# Run on the bastion:  sudo bash ~/fix-timing.sh <fix number | SITE> [how many fixes of the site, default 3]
#   e.g. sudo bash ~/fix-timing.sh DCC      (the newest live-migration fixes of DCC)
set -u
ARG="${1:-}"
N="${2:-3}"
[[ "$ARG" =~ ^([0-9]{1,7}|DCB|DCA|DCC)$ ]] || { echo "Fix number or site (DCB, DCA, DCC)"; exit 1; }
[[ "$N" =~ ^[0-9]{1,2}$ ]] || { echo "How many fixes: a number"; exit 1; }
DB=/var/lib/ops-portal/portal.db
PY=/opt/ops-portal/.venv/bin/python
[ -r "$DB" ] || { echo "$DB not readable (run with sudo)"; exit 1; }
OUT="/home/deploy/fix-timing-$ARG-$(date +%Y%m%d-%H%M%S).txt"

"$PY" - "$DB" "$ARG" "$N" <<'PY' | tee "$OUT"
import datetime, json, re, sqlite3, statistics, sys
db, arg, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
con.row_factory = sqlite3.Row
if arg.isdigit():
    fixes = [con.execute("SELECT * FROM wi_actions WHERE id = ?", (int(arg),)).fetchone()]
else:
    # a drain or a live-migration fix: its items print "Attempt 1: live migration ..." and a "Time: checks before" line
    fixes = [a for a in con.execute(
        "SELECT a.* FROM wi_actions a JOIN wi_runs r ON r.id = a.run_id WHERE r.site = ? ORDER BY a.id DESC LIMIT 80", (arg,))
        if re.search(r"Time: checks before|: live migration of ", str(a["output"] or ""))][:n]
fixes = [a for a in fixes if a]
if not fixes:
    print("no live-migration fix found"); raise SystemExit(1)

UNIT = re.compile(r"(\d+) min(?: (\d+) s)?|(\d+) s")
def secs(text):
    m = UNIT.fullmatch(text.strip())
    if not m:
        return None
    return int(m.group(1)) * 60 + int(m.group(2) or 0) if m.group(1) else int(m.group(3))
TIME = re.compile(r"^Time: (.*) \(in all ([^)]+)\)", re.M)
def when(v):
    for f in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            return datetime.datetime.strptime(str(v)[:26].replace("Z", ""), f)
        except ValueError:
            continue
    return None
def med(xs):
    return f"{statistics.median(xs):.0f} s" if xs else "-"

for a in fixes:
    try:
        steps = json.loads(a["output"] or "[]")
    except ValueError:
        steps = []
    t0, t1 = when(a["ts"]), when(a["finished"])
    wall = (t1 - t0).total_seconds() if t0 and t1 else None
    print(f"\n== Fix #{a['id']}: {a['status']}, by {a['username']}, {a['ts']} .. {a['finished'] or '-'}"
          + (f" ({wall / 60:.1f} min)" if wall else ""))
    rows, phases = [], {}
    for st in steps:
        out = str(st.get("out") or "")
        m = TIME.search(out)
        parts = {}
        if m:
            for chunk in m.group(1).split(", "):
                # "checks before 1 min 35 s" -> "checks before", 95
                mm = re.match(r"^(checks before|migration|checks after) (.*)$", chunk)
                if mm and secs(mm.group(2)) is not None:
                    parts[mm.group(1)] = secs(mm.group(2))
            parts["all"] = secs(m.group(2))
        res = next((l[7:] for l in reversed(out.splitlines()) if l.startswith("RESULT ")), "(no RESULT)")
        waited = len(re.findall(r"^Waiting: ", out, re.M))
        tries = len(re.findall(r"^Attempt \d+:", out, re.M))
        name = re.search(r"^(\S+): status ", out, re.M)
        label = str(st.get("command") or "").split(" -> ")[0].lstrip("0123456789. ")
        rows.append((name.group(1) if name else label[:40], parts, waited, tries, res))
        for k, v in parts.items():
            if v is not None:
                phases.setdefault(k, []).append(v)
    print(f"   {len(rows)} item(s); per item: checks before {med(phases.get('checks before', []))}, migration "
          f"{med(phases.get('migration', []))}, checks after {med(phases.get('checks after', []))}, in all "
          f"{med(phases.get('all', []))} (median)")
    inside = sum(phases.get("all", []))
    if wall and rows:
        print(f"   wall clock {wall / len(rows):.0f} s per item; inside the items {inside / len(rows):.0f} s per item; "
              f"between items (portal / Ansible) {(wall - inside) / len(rows):.0f} s per item")
    print("   %-34s %8s %8s %8s %8s  %s" % ("instance", "before", "migrate", "after", "all", "waits / attempts / result"))
    for name, p, waited, tries, res in rows:
        f = lambda k: f"{p[k]} s" if p.get(k) is not None else "-"   # noqa: E731
        print("   %-34s %8s %8s %8s %8s  %s" % (name[:34], f("checks before"), f("migration"), f("checks after"), f("all"),
              f"{waited} wait(s), {tries} attempt(s): {res[:90]}"))
    for k in ("checks before", "migration", "checks after"):
        top = sorted([(p.get(k) or 0, nm) for nm, p, *_ in rows], reverse=True)[:3]
        print(f"   slowest {k}: " + ", ".join(f"{nm} {v} s" for v, nm in top if v))
PY
chown deploy: "$OUT"
echo "Saved: $OUT"

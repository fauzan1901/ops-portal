"""History of Operation Automation runs (SQLite, table wi_runs in the portal database): who ran which check, on which site and
host, with which parameters, the result per step, and the full Ansible log. Written before the check starts."""
import contextlib
import csv
import datetime
import io
import json
import os
import sqlite3

import settings

STATUSES = ("running", "ok", "warn", "fail", "skip", "error", "unknown")
FIELDS = ("id", "ts", "finished", "username", "site", "check_id", "check_title", "host", "params", "status", "summary",
          "error", "client_ip", "job_id")


@contextlib.contextmanager
def _db():
    os.makedirs(os.path.dirname(os.path.abspath(settings.DB_PATH)), exist_ok=True)
    conn = sqlite3.connect(settings.DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def _now():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def init():
    """Create the table; runs still marked running (the portal stopped meanwhile) become unknown. Returns those runs."""
    with _db() as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("""CREATE TABLE IF NOT EXISTS wi_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, finished TEXT, username TEXT NOT NULL,
            site TEXT NOT NULL, check_id TEXT NOT NULL, check_title TEXT NOT NULL, host TEXT, params TEXT,
            status TEXT NOT NULL, summary TEXT, result TEXT, log TEXT, error TEXT, client_ip TEXT, job_id TEXT)""")
        db.execute("CREATE INDEX IF NOT EXISTS wi_runs_ts ON wi_runs(ts)")
        db.execute("CREATE INDEX IF NOT EXISTS wi_runs_site ON wi_runs(site, id)")
        stale = [dict(r) for r in db.execute("SELECT id, username, site, check_id, client_ip FROM wi_runs WHERE status = 'running'")]
        db.execute("UPDATE wi_runs SET status = 'unknown', finished = ?, error = 'The portal stopped while the check was "
                   "running.' WHERE status = 'running'", (_now(),))
    return stale


def begin(username, site, check, params, host, client_ip):
    with _db() as db:
        cur = db.execute("INSERT INTO wi_runs (ts, username, site, check_id, check_title, host, params, status, client_ip)"
                         " VALUES (?,?,?,?,?,?,?,?,?)", (_now(), username, site, check["id"], check["title"], host or "",
                                                          json.dumps(params, sort_keys=True), "running", client_ip))
        return cur.lastrowid


def set_job(run_id, job_id):
    with _db() as db:
        db.execute("UPDATE wi_runs SET job_id = ? WHERE id = ?", (job_id, run_id))


def finish(run_id, job):
    """Store the outcome of a job: the check's own status when it ran, 'error' when it could not run."""
    result = job.get("result") or {}
    ran = job["status"] == "success" and result.get("ok")
    status = result.get("status") if ran and result.get("status") in STATUSES else "error"
    summary = result.get("summary") if ran else ""
    error = "" if ran else (job.get("error") or result.get("error") or "The check could not run.")
    with _db() as db:
        db.execute("UPDATE wi_runs SET finished = ?, status = ?, summary = ?, result = ?, log = ?, error = ? WHERE id = ?",
                   (_now(), status, summary, json.dumps(result), "\n".join(job.get("lines") or []), error, run_id))
    return status


def _row(r, full=False):
    item = {k: r[k] for k in FIELDS}
    try:
        item["params"] = json.loads(r["params"] or "{}")
    except ValueError:
        item["params"] = {}
    if full:
        try:
            item["result"] = json.loads(r["result"]) if r["result"] else None
        except ValueError:
            item["result"] = None
        item["log"] = r["log"] or ""
    return item


def get(run_id):
    with _db() as db:
        r = db.execute("SELECT * FROM wi_runs WHERE id = ?", (run_id,)).fetchone()
    return _row(r, full=True) if r else None


def _where(user="", site="", status="", check="", q="", fix=""):
    where, args = [], []
    if fix == "running":   # runs with a fix running now (wi_actions, the same database)
        where.append("id IN (SELECT run_id FROM wi_actions WHERE status = 'running')")
    for column, value in (("username", user), ("site", site), ("status", status), ("check_id", check)):
        if value:
            where.append(f"{column} = ?")
            args.append(value)
    if q:
        where.append("(check_title LIKE ? OR host LIKE ? OR params LIKE ? OR summary LIKE ?)")
        args += [f"%{q}%"] * 4
    return (" WHERE " + " AND ".join(where)) if where else "", args


def query(limit=50, offset=0, user="", site="", status="", check="", q="", fix=""):
    where, args = _where(user, site, status, check, q, fix)
    limit, offset = max(1, min(int(limit), 200)), max(0, int(offset))
    with _db() as db:
        total = db.execute(f"SELECT COUNT(*) FROM wi_runs{where}", args).fetchone()[0]
        rows = [_row(r) for r in db.execute(f"SELECT * FROM wi_runs{where} ORDER BY id DESC LIMIT ? OFFSET ?", args + [limit, offset])]
        users = [r[0] for r in db.execute("SELECT DISTINCT username FROM wi_runs ORDER BY username LIMIT 500")]
    return {"items": rows, "total": total, "users": users}


def recent(site, per_check=10):
    """The last runs of every check on one site, newest first (the Last ran and Activity columns of the check lists):
    {check_id: [{id, ts, status, username, summary}, ...]}."""
    out = {}
    with _db() as db:
        for r in db.execute("SELECT id, ts, status, username, summary, check_id FROM wi_runs WHERE site = ? "
                            "ORDER BY id DESC LIMIT 20000", (site,)):
            items = out.setdefault(r["check_id"], [])
            if len(items) < per_check:
                items.append({"id": r["id"], "ts": r["ts"], "status": r["status"], "username": r["username"],
                              "summary": (r["summary"] or "")[:200]})
    return out


def all_rows(user="", site="", status="", check="", q=""):
    where, args = _where(user, site, status, check, q)
    with _db() as db:
        return [_row(r) for r in db.execute(f"SELECT * FROM wi_runs{where} ORDER BY id LIMIT 100000", args)]


NUMBER = __import__("re").compile(r"^[-+]?\d+(\.\d+)?%?$")


def _cell(value):
    """A spreadsheet cell that cannot start a formula (=, +, -, @): such text gets a leading quote; a lone "-" and plain
    numbers (-5, +1.5%) stay as they are."""
    text = "" if value is None else str(value)
    if text in ("-", "+") or NUMBER.match(text):
        return text
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def to_csv(rows):
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["ID", "Started", "Finished", "User", "Site", "Check", "Host", "Parameters", "Status", "Summary", "Error", "Client IP"])
    for r in rows:
        writer.writerow([_cell(x) for x in (r["id"], r["ts"], r["finished"], r["username"], r["site"], r["check_title"], r["host"],
                                            json.dumps(r["params"], sort_keys=True), r["status"], r["summary"], r["error"], r["client_ip"])])
    return out.getvalue()


STATUS_WORDS = {"ok": "OK", "warn": "Warning", "fail": "Problem found", "skip": "Not checked", "info": "Info", "error": "Could not run",
                "running": "Running", "unknown": "Unknown"}


def result_csv(item):
    """One run as CSV for a spreadsheet: the run (check, site, parameters, status), then every step with its table
    (the values the thresholds were checked against), then How to fix it (text, where, the items it is about)."""
    out = io.StringIO()
    out.write("\ufeff")   # UTF-8 mark: Excel then shows °C, → and non-ASCII names correctly
    w = csv.writer(out)
    row = lambda *cells: w.writerow([_cell(c) for c in cells])   # noqa: E731
    res = item.get("result") or {}
    row("Operation Automation run", f"#{item['id']}")
    row("Check", item.get("check_title"))
    row("Site", item.get("site"))
    if item.get("host"):
        row("Host", item["host"])
    row("Parameters", "; ".join(f"{k}={v}" for k, v in (item.get("params") or {}).items()))
    row("Status", STATUS_WORDS.get(item.get("status"), item.get("status")))
    row("Summary", res.get("summary") or item.get("summary") or item.get("error") or "")
    row("Started", item.get("ts"))
    row("Finished", item.get("finished") or "")
    row("Launched by", item.get("username"))
    for step in res.get("steps") or []:
        row()
        row("Step", step.get("title"), STATUS_WORDS.get(step.get("status"), step.get("status")), step.get("detail") or "")
        table = step.get("table") or {}
        if table.get("columns"):
            row(*table["columns"])
            for r in table.get("rows") or []:
                row(*r)
            if table.get("more"):
                row(f"{table['more']} more row(s) not shown")
    recs = res.get("recommendations") or []
    if recs:
        row()
        row("How to fix it")
        for i, rec in enumerate(recs, 1):
            row(i, rec.get("text"), rec.get("where") or "", rec.get("warning") or "")
            items = rec.get("items") or {}
            if items.get("columns"):
                row("", *items["columns"])
                for r in items.get("rows") or []:
                    row("", *r)
            for ref in rec.get("references") or []:
                row("", "Vendor reference", f"{ref.get('vendor')}: {ref.get('title')}", ref.get("url"))
    return out.getvalue()

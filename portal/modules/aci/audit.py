"""Change history: who changed what, when, on which site, with which APIC account, and the result.

Stored in the portal's SQLite database (settings.DB_PATH), table aci_audit.
`username` is the portal (Active Directory) account of the operator; `apic_user` is the APIC service account the
change was sent with. Every change is recorded BEFORE it is sent to APIC with status 'pending', then updated to:
  success  APIC accepted the change
  failed   APIC refused it (error answer), so the change was certainly not applied
  unknown  no answer (timeout/dropped connection): the change may or may not have been applied
A record that stays 'pending' means the portal process stopped in the middle of an apply.
An undo of a static-port change is a static-port record of its own: `undo_of` names the change it undoes, and that
change gets `undone_by` when the undo succeeds.
A product template change (action "template", see template_store.py) never reaches APIC: it is written with status
'success' in the same transaction as the template itself. A change of a product as such (added, renamed, deleted) is
for every site and has an empty site.
"""
import contextlib
import csv
import datetime
import io
import json
import re
import sqlite3
import threading

import settings

from .report import safe_cell

DB_PATH = settings.DB_PATH   # one database for the whole portal; the tests point this at a database of their own
ACTIONS = ("static-port", "provisioning", "template")
STATUSES = ("pending", "success", "failed", "unknown")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
MAX_LIMIT = 500
COLUMNS = ("id, ts, finished, username, site, apic, action, target, product, status, summary, error, client_ip, apic_user,"
           " undo_of, undone_by")
CSV_HEADER = ["ID", "Time", "Finished", "User", "Site", "APIC", "Action", "Target", "Product", "Status", "Summary", "Error",
              "Client IP", "APIC user", "Undo of", "Undone by"]   # new columns go at the end: exports keep their positions
SCHEMA = """
CREATE TABLE IF NOT EXISTS aci_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    finished TEXT,
    username TEXT NOT NULL,
    site TEXT NOT NULL,
    apic TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    product TEXT,
    status TEXT NOT NULL,
    summary TEXT NOT NULL,
    details TEXT NOT NULL,
    error TEXT,
    client_ip TEXT,
    apic_user TEXT,
    undo_of INTEGER,
    undone_by INTEGER
);
CREATE INDEX IF NOT EXISTS aci_audit_username ON aci_audit (username);
CREATE INDEX IF NOT EXISTS aci_audit_ts ON aci_audit (ts);
"""
_write_lock = threading.Lock()


@contextlib.contextmanager
def _db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def now():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def init():
    with _db() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(SCHEMA)
        # Databases from before the APIC service accounts have no apic_user column yet, and databases from before the
        # undo of static-port changes have no undo_of / undone_by columns.
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(aci_audit)")}
        for name, kind in (("apic_user", "TEXT"), ("undo_of", "INTEGER"), ("undone_by", "INTEGER")):
            if name not in columns:
                conn.execute(f"ALTER TABLE aci_audit ADD COLUMN {name} {kind}")


def begin(username, site, apic, action, target, product, summary, details, client_ip, apic_user=None, undo_of=None):
    """Record a change that is about to be sent; returns the record id. Raises sqlite3.Error when that fails.
    undo_of: the id of the change this one undoes."""
    if action not in ACTIONS:
        raise ValueError(f"Unknown audit action: {action}")
    row = (now(), username, site, apic, action, target, product, "pending", summary, json.dumps(details, ensure_ascii=False),
           client_ip, apic_user, undo_of)
    with _write_lock, _db() as conn:
        cur = conn.execute("INSERT INTO aci_audit (ts, username, site, apic, action, target, product, status, summary, details,"
                           " client_ip, apic_user, undo_of) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", row)
        return cur.lastrowid


def record(conn, username, site, apic, action, target, product, summary, details, client_ip):
    """A finished change, inside the caller's transaction (conn from _db(), under _write_lock): for changes that are
    not sent to APIC, such as a product template. Returns the record id."""
    if action not in ACTIONS:
        raise ValueError(f"Unknown audit action: {action}")
    ts = now()
    cur = conn.execute("INSERT INTO aci_audit (ts, finished, username, site, apic, action, target, product, status, summary,"
                       " details, client_ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'success', ?, ?, ?)",
                       (ts, ts, username, site, apic, action, target, product, summary,
                        json.dumps(details, ensure_ascii=False), client_ip))
    return cur.lastrowid


def finish(record_id, status, error=None):
    if status not in STATUSES:
        raise ValueError(f"Unknown audit status: {status}")
    with _write_lock, _db() as conn:
        conn.execute("UPDATE aci_audit SET status = ?, error = ?, finished = ? WHERE id = ? AND status = 'pending'",
                     (status, error, now(), record_id))
        if status == "success":
            # A successful undo marks the change it undid, in the same transaction.
            conn.execute("UPDATE aci_audit SET undone_by = ? WHERE id = (SELECT undo_of FROM aci_audit WHERE id = ?)"
                         " AND undone_by IS NULL", (record_id, record_id))


def parse_filters(args):
    """Validate the filters from the query string. All values go to SQL as parameters."""
    f = {k: str(args.get(k) or "").strip() for k in ("user", "site", "action", "status", "q", "since", "until")}
    if f["action"] and f["action"] not in ACTIONS:
        raise ValueError(f"Invalid action filter: {f['action']}")
    if f["status"] and f["status"] not in STATUSES:
        raise ValueError(f"Invalid status filter: {f['status']}")
    for key in ("since", "until"):
        if f[key] and not DATE_RE.match(f[key]):
            raise ValueError(f"Date must be in YYYY-MM-DD format: {f[key]}")
    if len(f["q"]) > 100:
        raise ValueError("Search text is too long (max 100 characters)")
    return f


def _where(f):
    clauses, params = [], []
    for key, column in (("user", "username"), ("site", "site"), ("action", "action"), ("status", "status")):
        if f.get(key):
            clauses.append(f"{column} = ?")
            params.append(f[key])
    if f.get("since"):
        clauses.append("ts >= ?")
        params.append(f["since"])
    if f.get("until"):
        next_day = datetime.date.fromisoformat(f["until"]) + datetime.timedelta(days=1)
        clauses.append("ts < ?")
        params.append(next_day.isoformat())
    if f.get("q"):
        clauses.append("instr(lower(target || ' ' || summary || ' ' || coalesce(product, '') || ' ' || username), lower(?)) > 0")
        params.append(f["q"])
    return ("WHERE " + " AND ".join(clauses)) if clauses else "", params


def query(filters, limit=100, offset=0):
    """(total, records without details), newest first."""
    limit = max(1, min(int(limit), MAX_LIMIT))
    offset = max(0, int(offset))
    where, params = _where(filters)
    with _db() as conn:
        total = conn.execute(f"SELECT count(*) FROM aci_audit {where}", params).fetchone()[0]
        rows = conn.execute(f"SELECT {COLUMNS} FROM aci_audit {where} ORDER BY id DESC LIMIT ? OFFSET ?", params + [limit, offset]).fetchall()
    return total, [dict(r) for r in rows]


def all_rows(filters):
    """All matching records (without details), for the export."""
    where, params = _where(filters)
    with _db() as conn:
        return [dict(r) for r in conn.execute(f"SELECT {COLUMNS} FROM aci_audit {where} ORDER BY id DESC", params)]


def get(record_id):
    with _db() as conn:
        row = conn.execute(f"SELECT {COLUMNS}, details FROM aci_audit WHERE id = ?", (record_id,)).fetchone()
    if not row:
        return None
    record = dict(row)
    record["details"] = json.loads(record["details"])
    return record


def static_port_paths(site, prefix="", exact=False):
    """What the portal last did to each path, from the successful static-port changes of a site whose EPG DN starts
    with prefix (or is prefix, when exact): {(epg_dn, tdn): {**item, "change": record id}}. Read once, oldest first,
    so a later change (or an undo, with its "delete" items) replaces an earlier one."""
    where = "target = ?" if exact else "substr(target, 1, ?) = ?"
    params = [site] + ([prefix] if exact else [len(prefix), prefix])
    with _db() as conn:
        rows = conn.execute("SELECT id, target, details FROM aci_audit WHERE action = 'static-port' AND status = 'success'"
                            f" AND site = ? AND {where} ORDER BY id", params).fetchall()
    latest = {}
    for row in rows:
        try:
            items = json.loads(row["details"]).get("items") or []
        except (ValueError, AttributeError):
            continue
        for item in items:
            if isinstance(item, dict) and item.get("tdn"):
                latest[(row["target"], item["tdn"])] = {**item, "change": row["id"]}
    return latest


def facets():
    """Users and sites that appear in the history, for the filter choices."""
    with _db() as conn:
        return {
            "users": [r[0] for r in conn.execute("SELECT DISTINCT username FROM aci_audit ORDER BY lower(username)")],
            "sites": [r[0] for r in conn.execute("SELECT DISTINCT site FROM aci_audit WHERE site != '' ORDER BY site")],
        }


def to_csv(rows):
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(CSV_HEADER)
    keys = ["id", "ts", "finished", "username", "site", "apic", "action", "target", "product", "status", "summary", "error",
            "client_ip", "apic_user", "undo_of", "undone_by"]
    for row in rows:
        writer.writerow([safe_cell(row.get(k)) for k in keys])
    return out.getvalue()

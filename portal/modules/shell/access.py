"""Which hosts an operator may open in Shell (page Access, administrators). Administrators open every host; an operator
only the hosts given to the account, nothing by default:

    *                         every host of every site
    site:<site>               every host of a site (also hosts added later)
    cat:<site>:<category>     every host of a product on a site (openstack, ontap, apic, vyos, cdn, ...; also later ones)
    host:<target id>          one host (DCA:host:12, DCB:mgmt, DCA:group:dns:dns-01, ...)

A rule can be temporary: valid until a time (at most MAX_DAYS ahead), with the ticket or reason it was given for. An
expired rule gives nothing (it stays listed as expired until the next save); a session opened with it ends by itself
(Manager.reap asks allowed() again).

Table shell_access (portal database): one row per account and rule (expires, ticket: empty = permanent).
"""
import contextlib
import datetime
import os
import re
import sqlite3

import settings

RULE_RE = re.compile(r"^(\*|site:[A-Za-z0-9_.-]{1,40}|cat:[A-Za-z0-9_.-]{1,40}:[a-z0-9_-]{1,32}|"
                     r"host:[A-Za-z0-9_.-]{1,40}:(mgmt|director|ontap|apic|host:\d{1,9}|group:[a-z0-9_-]{1,32}:[A-Za-z0-9_.-]{1,63}))$")
USER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
TICKET_RE = re.compile(r"^[^\x00-\x1f\x7f]{0,80}$")
MAX_RULES = 2000
MAX_DAYS = int(os.environ.get("SHELL_ACCESS_MAX_DAYS", "90"))


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


def init():
    with _db() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS shell_access (
            username TEXT NOT NULL, rule TEXT NOT NULL, updated TEXT, updated_by TEXT, PRIMARY KEY (username, rule))""")
        columns = [r[1] for r in db.execute("PRAGMA table_info(shell_access)")]
        for column in ("expires", "ticket"):
            if column not in columns:
                db.execute(f"ALTER TABLE shell_access ADD COLUMN {column} TEXT NOT NULL DEFAULT ''")


def _now():
    return datetime.datetime.now().astimezone()


def _active(expires, now=None):
    if not expires:
        return True
    try:
        return datetime.datetime.fromisoformat(expires) > (now or _now())
    except ValueError:
        return False


def grants(username):
    """Every rule of an account: [{"rule", "expires", "ticket", "updated", "updated_by", "active"}] (expired ones too)."""
    with _db() as db:
        rows = db.execute("SELECT * FROM shell_access WHERE username = ? ORDER BY rule", (username,)).fetchall()
    now = _now()
    return [{"rule": r["rule"], "expires": r["expires"] or "", "ticket": r["ticket"] or "", "updated": r["updated"],
             "updated_by": r["updated_by"], "active": _active(r["expires"], now)} for r in rows]


def rules(username):
    """The rules of an account that give access now (not expired)."""
    return [g["rule"] for g in grants(username) if g["active"]]


def all_grants():
    out = {}
    with _db() as db:
        rows = db.execute("SELECT * FROM shell_access ORDER BY username, rule").fetchall()
    now = _now()
    for r in rows:
        out.setdefault(r["username"], []).append({"rule": r["rule"], "expires": r["expires"] or "", "ticket": r["ticket"] or "",
                                                  "updated": r["updated"], "updated_by": r["updated_by"],
                                                  "active": _active(r["expires"], now)})
    return out


def _clean(item, now):
    """A rule from the page: "rule" (permanent) or {"rule", "expires" (ISO time, empty: permanent), "ticket"}."""
    if isinstance(item, str):
        item = {"rule": item}
    if not isinstance(item, dict):
        raise ValueError("A rule must be text or {rule, expires, ticket}")
    rule, expires, ticket = str(item.get("rule") or ""), str(item.get("expires") or "").strip(), str(item.get("ticket") or "").strip()
    if not RULE_RE.match(rule):
        raise ValueError(f"Not a valid rule: {rule[:80]}")
    if not TICKET_RE.match(ticket):
        raise ValueError("Ticket / reason: at most 80 characters on one line")
    if expires:
        try:
            when = datetime.datetime.fromisoformat(expires.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError(f"Not a valid time: {expires[:40]}")
        if when.tzinfo is None:
            when = when.astimezone()
        if when > now + datetime.timedelta(days=MAX_DAYS):
            raise ValueError(f"A temporary access lasts at most {MAX_DAYS} days")
        if when <= now:
            return None   # already expired: dropped
        expires = when.astimezone().isoformat(timespec="minutes")
    return {"rule": rule, "expires": expires, "ticket": ticket}


def set_rules(username, new_rules, actor):
    """Replace the rules of an account (texts, or {rule, expires, ticket}); expired ones are dropped. Returns
    (before, after) as lists of grants."""
    if not USER_RE.match(str(username or "")):
        raise ValueError("Invalid username")
    if not isinstance(new_rules, list):
        raise ValueError("rules must be a list")
    if len(new_rules) > MAX_RULES:
        raise ValueError(f"At most {MAX_RULES} rules")
    now = _now()
    clean = {}
    for item in new_rules:
        g = _clean(item, now)
        if g:
            old = clean.get(g["rule"])   # the same rule twice: the one that lasts longer
            if not old or (old["expires"] and (not g["expires"] or g["expires"] > old["expires"])):
                clean[g["rule"]] = g
    if "*" in clean:
        clean = {"*": clean["*"]}   # everything: the other rules add nothing
    stamp = now.isoformat(timespec="seconds")
    before = grants(username)
    with _db() as db:
        db.execute("DELETE FROM shell_access WHERE username = ?", (username,))
        db.executemany("INSERT INTO shell_access (username, rule, updated, updated_by, expires, ticket) VALUES (?,?,?,?,?,?)",
                       [(username, g["rule"], stamp, actor, g["expires"], g["ticket"]) for g in sorted(clean.values(), key=lambda x: x["rule"])])
    return [g for g in before if g["active"]], [dict(g, active=True) for g in sorted(clean.values(), key=lambda x: x["rule"])]


def allows(rule_list, target):
    rule_set = set(rule_list)
    return bool({"*", f"site:{target['site']}", f"cat:{target['site']}:{target['category']}", f"host:{target['id']}"}
                & rule_set)


def allowed(user, target, rule_list=None):
    """May this signed-in user open the target? Administrators: always."""
    if user.get("role") == "admin":
        return True
    return allows(rules(user["username"]) if rule_list is None else rule_list, target)


def describe(grant_list):
    """Short text of the rules (texts or grants) for the activity log."""
    items = [g if isinstance(g, dict) else {"rule": g} for g in grant_list or []]
    if not items:
        return "no host"

    def one(g):
        text = "every host" if g["rule"] == "*" else g["rule"].replace("host:", "").replace("cat:", "").replace("site:", "all of ")
        if g.get("expires"):
            text += f" until {g['expires'][:16].replace('T', ' ')}"
        return text + (f" [{g['ticket']}]" if g.get("ticket") else "")
    return ", ".join(one(g) for g in items[:12]) + (f" (+{len(items) - 12} more)" if len(items) > 12 else "")

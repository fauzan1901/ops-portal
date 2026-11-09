"""Grafana alerts (/wi/#/alerts): Grafana Alerting sends its notifications to the portal (contact point of type Webhook,
POST /wi/api/alerts/grafana), a rule of an administrator picks the check for the alert and fills its parameters from
the alert's labels, and the check runs at once as the account "grafana".

- Sources: one per Grafana. Each has its own token (shown once, stored as a SHA-256 hash only), sent by Grafana in the
  Authorization header ("Bearer <token>", or as the Basic password), and optionally the addresses it may come from.
- Rules: alert name (a * pattern) and label matchers (=, !=, =~, !~ as in Prometheus), the site (fixed or from a
  label), and one or more checks (MAX_RULE_CHECKS), each with its parameters ({{labels.instance|host}},
  {{annotations.summary}}, plain text). Every rule that matches runs its checks, each its own run; the same check of a
  rule with the same site and parameters runs again only after the rule's cooldown.
- Automatic fixes: an administrator allows, per rule, fixes seen in its results. Only fixes on SSH hosts with normal
  risk run by themselves: never on OpenStack, ONTAP or VyOS, never of ticked items, never a high-risk command
  (deletes, restarts, kills, reboots: fixes.HIGH_RE) nor one that changes the firewall, network, packages or
  accounts (AUTO_DENY). At most auto_per_hour per rule; the same fix on the same target again only after
  AUTO_AGAIN_HOURS (an alert that comes back waits for an operator). The check runs again after the fix, as always.
The portal only receives: the alerting itself stays in Grafana. What each alert did is on the page Alerts and in Runs.
Everything is kept WI_ALERT_KEEP_DAYS days (table wi_alert_events)."""
import base64
import contextlib
import datetime
import fnmatch
import hashlib
import ipaddress
import json
import logging
import os
import re
import secrets
import sqlite3
import threading
import time

import settings
import sites

from . import catalog, fixes

log = logging.getLogger("portal.wi.alerts")

ROBOT = "grafana"   # the account checks and fixes of alerts run as (Runs, Activity)
KEEP_DAYS = int(os.environ.get("WI_ALERT_KEEP_DAYS", "180"))
MAX_BODY = 1024 * 1024   # bytes of one notification (the receiver in modules/wi)
MAX_ALERTS = 200   # per notification of Grafana
RATE_PER_MINUTE = 600   # alerts per source
DEFAULT_COOLDOWN = 30   # minutes
MAX_RULE_CHECKS = 10
AUTO_PER_HOUR = 3
MAX_CHECKING = int(os.environ.get("WI_ALERT_MAX_CHECKS", "10"))   # checks of alerts running at once (a flood of alerts)
AUTO_AGAIN_HOURS = 6
STATES = ("checking", "checked", "duplicate", "refused", "no-rule", "resolved")
STATUS_WORDS = {"ok": "OK", "warn": "Warning", "fail": "Problem found", "skip": "Not checked", "error": "Could not run",
                "unknown": "Unknown"}
# Never by itself: the firewall, addresses and links, packages, accounts, mounts (a person decides those).
AUTO_DENY = re.compile(
    r"(^|[\s;|&(])(sudo\s+)?(nft|iptables|ip6tables|ufw|firewall-cmd|semanage|ethtool|nmcli|ifup|ifdown|apt|apt-get|yum|dnf|"
    r"rpm|pip3?|passwd|chpasswd|useradd|usermod|userdel|visudo|crontab|mount|swapoff|setenforce)\b"
    r"|\bip\s+(link|addr|address|route|rule|neigh)\s+(add|del|delete|set|flush|change|replace)\b|\bsysctl\s+-w\b")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.:()/-]{0,79}$")
MATCHER_RE = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]{0,63})\s*(=~|!~|!=|=)\s*(.*?)\s*$')
TOKEN_RE = re.compile(r"\{\{\s*(alertname|labels\.[A-Za-z_][A-Za-z0-9_]*|annotations\.[A-Za-z_][A-Za-z0-9_]*)\s*((?:\|\s*[a-z]+\s*)*)\}\}")

# What this module needs from the Operation Automation module (set by modules/wi/__init__.py; fakes in the tests).
HOOKS = {"start_check": None,   # (site, check, raw params, client) -> run id
         "clean": None,         # (check, raw params, site) -> cleaned params
         "get_run": None,       # (run id) -> stored run
         "fix_state": None,     # (run, index, recommendation, user) -> fixes.state(...)
         "start_fix": None}     # (run, index, user, client, note) -> fix id
_rate = {}
_rate_lock = threading.Lock()
_fix_lock = threading.Lock()


class Unauthorized(Exception):
    pass


class Refused(Exception):
    pass


class TooMany(Refused):
    pass


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


def _ago(minutes):
    return (datetime.datetime.now().astimezone() - datetime.timedelta(minutes=minutes)).isoformat(timespec="seconds")


def _hm(iso):
    try:
        return datetime.datetime.fromisoformat(iso).strftime("%d %b %H:%M")
    except (TypeError, ValueError):
        return str(iso or "")


def init():
    with _db() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS wi_alert_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, token_hash TEXT NOT NULL UNIQUE,
            token_tail TEXT NOT NULL, networks TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1,
            created TEXT NOT NULL, created_by TEXT NOT NULL, updated TEXT, updated_by TEXT, last_seen TEXT, last_ip TEXT)""")
        db.execute("""CREATE TABLE IF NOT EXISTS wi_alert_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, enabled INTEGER NOT NULL DEFAULT 1,
            alertname TEXT NOT NULL, matchers TEXT NOT NULL DEFAULT '[]', site TEXT NOT NULL, checks TEXT NOT NULL DEFAULT '[]',
            cooldown INTEGER NOT NULL DEFAULT 30, auto_fixes TEXT NOT NULL DEFAULT '[]',
            auto_per_hour INTEGER NOT NULL DEFAULT 3, created TEXT, created_by TEXT, updated TEXT, updated_by TEXT)""")
        db.execute("""CREATE TABLE IF NOT EXISTS wi_alert_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, source TEXT NOT NULL, client_ip TEXT,
            fingerprint TEXT, alertname TEXT, status TEXT, starts_at TEXT, labels TEXT, annotations TEXT, value_text TEXT,
            generator_url TEXT, rule_id INTEGER, rule_name TEXT, site TEXT, check_id TEXT, params TEXT, state TEXT NOT NULL, outcome TEXT,
            run_id INTEGER, run_status TEXT, fix_id INTEGER, fix_key TEXT, fix_title TEXT, fix_status TEXT,
            verify_run_id INTEGER, verify_status TEXT, resolved TEXT)""")
        for column in ("ts", "fingerprint", "run_id", "fix_id", "verify_run_id"):
            db.execute(f"CREATE INDEX IF NOT EXISTS wi_alert_events_{column} ON wi_alert_events({column})")
        db.execute("""CREATE TABLE IF NOT EXISTS wi_alert_fixes_seen (
            rule_id INTEGER NOT NULL, key TEXT NOT NULL, check_id TEXT NOT NULL, title TEXT NOT NULL, eligible INTEGER NOT NULL,
            reason TEXT, run_id INTEGER, seen TEXT, PRIMARY KEY (rule_id, key))""")
        db.execute("CREATE TABLE IF NOT EXISTS wi_alert_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    cleanup()


def cleanup():
    """Alerts older than KEEP_DAYS days go (the Runs they started stay)."""
    with _db() as db:
        db.execute("DELETE FROM wi_alert_events WHERE ts < ?", (_ago(KEEP_DAYS * 24 * 60),))


# ---------------- sources (one per Grafana) ----------------
def _hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def _networks(text):
    """Allowed addresses of a source: IPs or networks, comma or space separated; empty = from anywhere."""
    out = []
    for x in re.split(r"[\s,;]+", str(text or "").strip()):
        if not x:
            continue
        try:
            out.append(str(ipaddress.ip_network(x, strict=False)))
        except ValueError:
            raise ValueError(f"{x[:45]} is not an IP address or network") from None
    if len(out) > 32:
        raise ValueError("At most 32 addresses or networks")
    return ",".join(out)


def _source_row(r):
    return {"id": r["id"], "name": r["name"], "token_tail": r["token_tail"], "networks": r["networks"],
            "enabled": bool(r["enabled"]), "created": r["created"], "created_by": r["created_by"], "updated": r["updated"],
            "updated_by": r["updated_by"], "last_seen": r["last_seen"], "last_ip": r["last_ip"]}


def sources():
    with _db() as db:
        return [_source_row(r) for r in db.execute("SELECT * FROM wi_alert_sources ORDER BY name")]


def _new_token():
    token = "gfa_" + secrets.token_urlsafe(32)
    return token, _hash(token), token[-4:]


def add_source(name, networks, username):
    name = str(name or "").strip()
    if not NAME_RE.match(name):
        raise ValueError("Name: 1-80 letters, digits, spaces and _ . : ( ) / -")
    nets = _networks(networks)
    token, digest, tail = _new_token()
    try:
        with _db() as db:
            cur = db.execute("INSERT INTO wi_alert_sources (name, token_hash, token_tail, networks, created, created_by) "
                             "VALUES (?,?,?,?,?,?)", (name, digest, tail, nets, _now(), username))
    except sqlite3.IntegrityError:
        raise ValueError(f"A source named {name} already exists") from None
    return cur.lastrowid, token


def update_source(source_id, name, networks, enabled, username):
    name = str(name or "").strip()
    if not NAME_RE.match(name):
        raise ValueError("Name: 1-80 letters, digits, spaces and _ . : ( ) / -")
    nets = _networks(networks)
    try:
        with _db() as db:
            cur = db.execute("UPDATE wi_alert_sources SET name = ?, networks = ?, enabled = ?, updated = ?, updated_by = ? "
                             "WHERE id = ?", (name, nets, 1 if enabled else 0, _now(), username, source_id))
    except sqlite3.IntegrityError:
        raise ValueError(f"A source named {name} already exists") from None
    if not cur.rowcount:
        raise LookupError("No such source")


def rotate_token(source_id, username):
    token, digest, tail = _new_token()
    with _db() as db:
        cur = db.execute("UPDATE wi_alert_sources SET token_hash = ?, token_tail = ?, updated = ?, updated_by = ? WHERE id = ?",
                         (digest, tail, _now(), username, source_id))
    if not cur.rowcount:
        raise LookupError("No such source")
    return token


def delete_source(source_id):
    with _db() as db:
        row = db.execute("SELECT name FROM wi_alert_sources WHERE id = ?", (source_id,)).fetchone()
        if not row:
            raise LookupError("No such source")
        db.execute("DELETE FROM wi_alert_sources WHERE id = ?", (source_id,))
    return row["name"]


def authenticate(header, remote_ip):
    """The source a notification comes from: its token (Authorization: Bearer <token>, or the password of Basic), its
    allowed addresses, at most RATE_PER_MINUTE alerts a minute. Unauthorized / Refused otherwise."""
    header = str(header or "").strip()
    token = ""
    if header[:7].lower() == "bearer ":
        token = header[7:].strip()
    elif header[:6].lower() == "basic ":
        try:
            token = base64.b64decode(header[6:].strip(), validate=True).decode().split(":", 1)[-1]
        except (ValueError, UnicodeDecodeError):
            token = ""
    if not token:
        raise Unauthorized("Send the token of the source in the Authorization header (Bearer), or as the Basic password.")
    with _db() as db:
        row = db.execute("SELECT * FROM wi_alert_sources WHERE token_hash = ?", (_hash(token),)).fetchone()
    if not row or not row["enabled"]:
        raise Unauthorized("Unknown or disabled token.")
    if row["networks"]:
        try:
            ip = ipaddress.ip_address(str(remote_ip or ""))
        except ValueError:
            ip = None
        if ip is None or not any(ip in ipaddress.ip_network(n) for n in row["networks"].split(",")):
            raise Refused(f"{remote_ip} is not an allowed address of the source {row['name']}.")
    return _source_row(row)


def _count(source_id, n):
    """Count n alerts of a source in this minute; Refused beyond RATE_PER_MINUTE."""
    minute = int(time.time() // 60)
    with _rate_lock:
        for key in [k for k in _rate if k[1] != minute]:
            del _rate[key]
        used = _rate.get((source_id, minute), 0)
        if used + n > RATE_PER_MINUTE:
            raise TooMany(f"More than {RATE_PER_MINUTE} alerts in a minute from this source: wait a minute.")
        _rate[(source_id, minute)] = used + n


# ---------------- rules ----------------
def parse_matchers(text):
    """Label matchers, one per line or comma separated: name=value, name!=value, name=~regex, name!~regex."""
    out = []
    lines = text if isinstance(text, list) else re.split(r"[\n,]+", str(text or ""))
    for line in lines:
        line = str(line).strip()
        if not line:
            continue
        m = MATCHER_RE.match(line)
        if not m:
            raise ValueError(f"Label matcher {line[:60]}: write name=value, name!=value, name=~regex or name!~regex")
        name, op, value = m.groups()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if len(value) > 200:
            raise ValueError(f"Label matcher {name}: the value is too long")
        if op in ("=~", "!~"):
            try:
                re.compile(value)
            except re.error as e:
                raise ValueError(f"Label matcher {name}: {e}") from None
        out.append({"label": name, "op": op, "value": value})
    if len(out) > 20:
        raise ValueError("At most 20 label matchers")
    return out


def matches(rule, labels):
    """Does an alert (its labels) match a rule: the alert name (a * pattern, any case) and every label matcher."""
    name = str(labels.get("alertname") or "")
    if not fnmatch.fnmatchcase(name.lower(), str(rule["alertname"] or "*").lower()):
        return False
    for m in rule["matchers"]:
        value = str(labels.get(m["label"], ""))
        if m["op"] == "=" and value != m["value"]:
            return False
        if m["op"] == "!=" and value == m["value"]:
            return False
        if m["op"] in ("=~", "!~") and bool(re.fullmatch(m["value"], value)) != (m["op"] == "=~"):
            return False
    return True


def _host(value):
    """An address from an alert label: "https://10.253.0.5:9100/metrics" → 10.253.0.5, "[fe80::1]:9100" → fe80::1."""
    v = re.sub(r"^[A-Za-z][A-Za-z0-9+.-]*://", "", value.strip()).split("/")[0]
    if v.startswith("[") and "]" in v:
        return v[1:v.index("]")]
    return v.rsplit(":", 1)[0] if v.count(":") == 1 else v


FILTERS = {"host": _host, "short": lambda v: _host(v).split(".")[0] if not re.fullmatch(r"[\d.]+", _host(v)) else _host(v),
           "lower": str.lower, "upper": str.upper, "trim": str.strip}


def check_template(template):
    """ValueError when a parameter text has an unknown placeholder or filter."""
    text = str(template or "")
    if len(text) > 300:
        raise ValueError("A parameter is at most 300 characters")
    for m in TOKEN_RE.finditer(text):
        for f in [x.strip() for x in m.group(2).split("|") if x.strip()]:
            if f not in FILTERS:
                raise ValueError(f"Unknown filter |{f} (use {', '.join('|' + k for k in FILTERS)})")
    rest = TOKEN_RE.sub("", text)
    if "{{" in rest or "}}" in rest:
        raise ValueError(f"Unknown placeholder in {text[:60]}: use {{{{labels.<name>}}}}, {{{{annotations.<name>}}}} or {{{{alertname}}}}")


def render(template, alert):
    """A parameter of a rule for one alert: {{labels.x}}, {{annotations.x}}, {{alertname}}, with filters |host |short
    |lower |upper |trim. ValueError when the alert has no such label."""
    def value(m):
        key = m.group(1)
        if key == "alertname":
            v = alert["labels"].get("alertname")
            missing = "alert name"
        else:
            area, name = key.split(".", 1)
            v = alert[area].get(name)
            missing = f"{area[:-1]} {name}"
        if v is None or str(v).strip() == "":
            raise ValueError(f"The alert has no {missing}")
        v = str(v)
        for f in [x.strip() for x in m.group(2).split("|") if x.strip()]:
            v = FILTERS[f](v)
        return v
    return TOKEN_RE.sub(value, str(template or "")).strip()


def site_of(rule, alert):
    """The site of an alert: the rule's site, or the text it makes from the alert matched to a site of sites.yml
    (same name in any case, else the one site name that is a word of it: "dca-openstack" → DCA)."""
    value = render(rule["site"], alert)
    names = list(sites.sites())
    exact = [n for n in names if n.lower() == value.lower()]
    if exact:
        return exact[0]
    words = {w for w in re.split(r"[^a-z0-9]+", value.lower()) if w}
    hits = [n for n in names if n.lower() in words]
    if len(hits) == 1:
        return hits[0]
    raise ValueError(f"No site for {value[:60]!r} (sites: {', '.join(names)})")


def _rule_row(r):
    return {"id": r["id"], "name": r["name"], "enabled": bool(r["enabled"]), "alertname": r["alertname"],
            "matchers": json.loads(r["matchers"] or "[]"), "site": r["site"], "checks": json.loads(r["checks"] or "[]"),
            "cooldown": r["cooldown"],
            "auto_fixes": json.loads(r["auto_fixes"] or "[]"), "auto_per_hour": r["auto_per_hour"],
            "created": r["created"], "created_by": r["created_by"], "updated": r["updated"], "updated_by": r["updated_by"]}


def rules(enabled_only=False):
    with _db() as db:
        rows = db.execute("SELECT * FROM wi_alert_rules" + (" WHERE enabled = 1" if enabled_only else "") + " ORDER BY name").fetchall()
    return [_rule_row(r) for r in rows]


def rule_stats():
    """{rule id: {"last": time of its last alert, "week": alerts of the last 7 days, "fixes": automatic fixes of them}}."""
    with _db() as db:
        rows = db.execute("SELECT rule_id, MAX(ts) AS last, COUNT(*) AS n, COUNT(fix_id) AS f FROM wi_alert_events "
                          "WHERE rule_id IS NOT NULL AND ts >= ? GROUP BY rule_id", (_ago(7 * 24 * 60),)).fetchall()
    return {r["rule_id"]: {"last": r["last"], "week": r["n"], "fixes": r["f"]} for r in rows}


def rule(rule_id):
    with _db() as db:
        r = db.execute("SELECT * FROM wi_alert_rules WHERE id = ?", (rule_id,)).fetchone()
    return _rule_row(r) if r else None


def checks_for_rules():
    """The checks a rule can run: ready, not a log collection (those stay for a person to start)."""
    out = []
    for c in catalog.CATALOG["checks"]:
        if c.get("status") != "ready" or c.get("bundle") or c.get("permission"):
            continue
        out.append({"id": c["id"], "title": c["title"], "category": c.get("category"), "fix": bool(c.get("fix")),
                    "params": [{k: p.get(k) for k in ("name", "label", "type", "required", "default", "help") if k in p}
                               for p in c["params"]]})
    return out


def clean_rule(data, current=None):
    """A rule from the form: validated, every text and template checked. ValueError otherwise."""
    d = data if isinstance(data, dict) else {}
    name = str(d.get("name") or "").strip()
    if not NAME_RE.match(name):
        raise ValueError("Name: 1-80 letters, digits, spaces and _ . : ( ) / -")
    alertname = str(d.get("alertname") or "").strip()
    if not alertname or len(alertname) > 200:
        raise ValueError("Alert name: the alertname of the Grafana alert rule (* matches any text)")
    matchers = parse_matchers(d.get("matchers"))
    site = str(d.get("site") or "").strip()
    if not site:
        raise ValueError("Site: a site, or a label such as {{labels.site}}")
    check_template(site)
    if not TOKEN_RE.search(site) and site not in sites.sites():
        raise ValueError(f"Unknown site {site}")
    allowed = {c["id"]: c for c in checks_for_rules()}
    checks = []
    for item in d.get("checks") or []:
        item = item if isinstance(item, dict) else {}
        check_id = str(item.get("check_id") or "")
        if check_id not in allowed:
            raise ValueError("Choose checks that can run from an alert")
        names = {p["name"] for p in allowed[check_id]["params"]}
        params = {}
        for k, v in (item.get("params") or {}).items():
            if k not in names:
                raise ValueError(f"{allowed[check_id]['title']} has no parameter {k}")
            if str(v or "").strip():
                check_template(v)
                params[k] = str(v).strip()
        if {"check_id": check_id, "params": params} in checks:
            raise ValueError(f"{allowed[check_id]['title']} is twice in the rule with the same parameters")
        checks.append({"check_id": check_id, "params": params})
    if not 1 <= len(checks) <= MAX_RULE_CHECKS:
        raise ValueError(f"A rule runs 1-{MAX_RULE_CHECKS} checks")
    try:
        cooldown = int(d.get("cooldown", DEFAULT_COOLDOWN))
        per_hour = int(d.get("auto_per_hour", AUTO_PER_HOUR))
    except (TypeError, ValueError):
        raise ValueError("Cooldown and automatic fixes per hour are whole numbers") from None
    if not 0 <= cooldown <= 24 * 60:
        raise ValueError("Cooldown: 0-1440 minutes")
    if not 1 <= per_hour <= 20:
        raise ValueError("Automatic fixes per hour: 1-20")
    # fixes are allowed from the results of this rule, for the checks it still runs
    ids = {c["check_id"] for c in checks}
    seen = {f["key"]: f for f in fixes_seen(current["id"]) if f["check_id"] in ids} if current else {}
    auto = [str(k) for k in d.get("auto_fixes") or [] if str(k) in seen or not current]
    for k in auto:
        if k not in seen or not seen[k]["eligible"]:
            raise ValueError("Only fixes seen in this rule's results that may run by themselves can be allowed")
    return {"name": name, "enabled": bool(d.get("enabled", True)), "alertname": alertname, "matchers": matchers, "site": site,
            "checks": checks, "cooldown": cooldown, "auto_fixes": sorted(set(auto)), "auto_per_hour": per_hour}


def save_rule(data, username, rule_id=None, confirm=""):
    """Add (rule_id None) or change a rule. Allowing a fix to run by itself needs the rule's name typed (confirm)."""
    current = rule(rule_id) if rule_id else None
    if rule_id and not current:
        raise LookupError("No such rule")
    r = clean_rule(data, current)
    added = set(r["auto_fixes"]) - set((current or {}).get("auto_fixes") or [])
    if added and str(confirm or "").strip() != r["name"]:
        raise ValueError(f"Fixes that run by themselves: type the rule name {r['name']} to confirm.")
    values = (r["name"], 1 if r["enabled"] else 0, r["alertname"], json.dumps(r["matchers"]), r["site"],
              json.dumps(r["checks"], sort_keys=True), r["cooldown"], json.dumps(r["auto_fixes"]), r["auto_per_hour"], _now(), username)
    try:
        with _db() as db:
            if current:
                db.execute("UPDATE wi_alert_rules SET name = ?, enabled = ?, alertname = ?, matchers = ?, site = ?, checks = ?, "
                           "cooldown = ?, auto_fixes = ?, auto_per_hour = ?, updated = ?, updated_by = ? WHERE id = ?", values + (rule_id,))
                ids = sorted({c["check_id"] for c in r["checks"]})   # the fixes of checks the rule no longer runs go
                db.execute(f"DELETE FROM wi_alert_fixes_seen WHERE rule_id = ? AND check_id NOT IN ({','.join('?' * len(ids))})",
                           [rule_id, *ids])
            else:
                rule_id = db.execute("INSERT INTO wi_alert_rules (name, enabled, alertname, matchers, site, checks, cooldown, "
                                     "auto_fixes, auto_per_hour, created, created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                                     values).lastrowid
    except sqlite3.IntegrityError:
        raise ValueError(f"A rule named {r['name']} already exists") from None
    return rule_id, sorted(added)


def delete_rule(rule_id):
    with _db() as db:
        row = db.execute("SELECT name FROM wi_alert_rules WHERE id = ?", (rule_id,)).fetchone()
        if not row:
            raise LookupError("No such rule")
        db.execute("DELETE FROM wi_alert_rules WHERE id = ?", (rule_id,))
        db.execute("DELETE FROM wi_alert_fixes_seen WHERE rule_id = ?", (rule_id,))
    return row["name"]


def preview(data, event_id):
    """What a rule (not saved yet) would do with a received alert: matches, site, and per check its parameters or why
    it would not run."""
    r = clean_rule(dict(data or {}, auto_fixes=[]))
    ev = event(event_id)
    if not ev:
        raise LookupError("No such alert")
    alert = {"labels": ev["labels"], "annotations": ev["annotations"]}
    out = {"matches": matches(r, ev["labels"]), "site": "", "error": "", "checks": []}
    try:
        out["site"] = site_of(r, alert)
    except ValueError as e:
        out["error"] = str(e)
        return out
    for item in r["checks"]:
        check = catalog.get(item["check_id"])
        one = {"check_id": check["id"], "title": check["title"], "params": {}, "error": ""}
        try:
            one["params"] = HOOKS["clean"](check, {k: render(v, alert) for k, v in item["params"].items()}, out["site"])
        except (ValueError, LookupError) as e:
            one["error"] = str(e)
        out["checks"].append(one)
    return out


# ---------------- fixes of a rule's results ----------------
TITLE_END = re.compile(r'(?<!\be\.g)(?<!\bi\.e)(?<!\betc)(?<!\bvs)(?<!\bapprox)(?<!\d)\.\s+(?=[A-Z0-9("])')


def _title(text):
    """The first sentence of a recommendation: its bold title in the result (splitTitle of static/wi.js)."""
    text = str(text or "").strip()
    m = TITLE_END.search(text)
    return re.sub(r"\s+", " ", text[:m.start() + 1] if m else text)[:300]


def fix_key(check_id, rec):
    """The same fix in every result of a check: its title with the numbers left out ("Empty /var/log/x (12 GB)")."""
    norm = re.sub(r"\d+([.,]\d+)?", "#", _title(rec.get("text")).lower())
    return hashlib.sha256(f"{check_id}\n{norm}".encode()).hexdigest()[:16]


def auto_reason(state, action):
    """Why this fix may never run by itself ('' when it may, once the rule allows it)."""
    if not state:
        return "No fix the portal can run"
    if state["kind"] != "host":
        return {"openstack": "OpenStack changes always wait for an operator", "ontap": "ONTAP changes always wait for an operator"
                }.get(state["kind"], "VyOS changes always wait for an operator")
    if state.get("selectable"):
        return "A fix of ticked items waits for an operator"
    if (action or {}).get("operation"):
        return "The change steps of a template wait for an operator"
    if state["risk"] != "normal":
        return "High risk (deletes, restarts, kills, reboots): waits for an operator"
    if any(AUTO_DENY.search(str(c)) for c in state.get("commands") or []):
        return "Changes the firewall, network, packages or accounts: waits for an operator"
    return ""


def fixes_seen(rule_id):
    with _db() as db:
        return [{"key": r["key"], "check_id": r["check_id"], "title": r["title"], "eligible": bool(r["eligible"]), "reason": r["reason"],
                 "run_id": r["run_id"], "seen": r["seen"]}
                for r in db.execute("SELECT * FROM wi_alert_fixes_seen WHERE rule_id = ? ORDER BY check_id, title", (rule_id,))]


def _remember_fixes(rule_id, record, robot_user):
    """Note the fixes of a result of a rule (the administrator allows them on the rule); returns [(index, key, title,
    reason, state)] of the recommendations with a fix."""
    out = []
    recs = (record.get("result") or {}).get("recommendations") or []
    for i, rec in enumerate(recs):
        action = rec.get("action") if isinstance(rec, dict) else None
        if not action:
            continue
        state = HOOKS["fix_state"](record, i, rec, robot_user)
        reason = auto_reason(state, action)
        key, title = fix_key(record["check_id"], rec), _title(rec.get("text"))
        out.append((i, key, title, reason, state))
        with _db() as db:
            db.execute("INSERT INTO wi_alert_fixes_seen (rule_id, key, check_id, title, eligible, reason, run_id, seen) VALUES (?,?,?,?,?,?,?,?) "
                       "ON CONFLICT(rule_id, key) DO UPDATE SET title = excluded.title, eligible = excluded.eligible, "
                       "reason = excluded.reason, run_id = excluded.run_id, seen = excluded.seen",
                       (rule_id, key, record["check_id"], title, 0 if reason else 1, reason, record["id"], _now()))
    return out


# ---------------- settings ----------------
def get_settings():
    """auto_fix: allowed fixes run by themselves (off: every alert waits for an operator; the checks still run)."""
    with _db() as db:
        row = db.execute("SELECT value FROM wi_alert_settings WHERE key = 'auto_fix'").fetchone()
    return {"auto_fix": (row["value"] if row else "1") == "1"}


def save_settings(data):
    d = data if isinstance(data, dict) else {}
    value = "1" if d.get("auto_fix", get_settings()["auto_fix"]) else "0"
    with _db() as db:
        db.execute("INSERT INTO wi_alert_settings (key, value) VALUES ('auto_fix', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                   (value,))
    return get_settings()


# ---------------- alerts received ----------------
EVENT_FIELDS = ("id", "ts", "source", "client_ip", "fingerprint", "alertname", "status", "starts_at", "value_text", "generator_url",
                "rule_id", "rule_name", "site", "check_id", "state", "outcome", "run_id", "run_status", "fix_id", "fix_title", "fix_status",
                "verify_run_id", "verify_status", "resolved")


def _event_row(r):
    item = {k: r[k] for k in EVENT_FIELDS}
    for k in ("labels", "annotations", "params"):
        try:
            item[k] = json.loads(r[k] or "{}")
        except ValueError:
            item[k] = {}
    return item


def event(event_id):
    with _db() as db:
        r = db.execute("SELECT * FROM wi_alert_events WHERE id = ?", (event_id,)).fetchone()
    return _event_row(r) if r else None


def events(limit=50, offset=0, q="", site="", state=""):
    where, args = [], []
    if site:
        where.append("site = ?")
        args.append(site)
    if state:
        where.append("state = ?")
        args.append(state)
    if q:
        where.append("(alertname LIKE ? OR labels LIKE ? OR annotations LIKE ? OR rule_name LIKE ? OR outcome LIKE ?)")
        args += [f"%{q}%"] * 5
    sql = (" WHERE " + " AND ".join(where)) if where else ""
    limit, offset = max(1, min(int(limit), 200)), max(0, int(offset))
    with _db() as db:
        total = db.execute(f"SELECT COUNT(*) FROM wi_alert_events{sql}", args).fetchone()[0]
        rows = [_event_row(r) for r in db.execute(f"SELECT * FROM wi_alert_events{sql} ORDER BY id DESC LIMIT ? OFFSET ?",
                                                  args + [limit, offset])]
    return {"items": rows, "total": total}


def _text_map(value, limit, size):
    if not isinstance(value, dict):
        return {}
    return {str(k)[:64]: str(v)[:size] for k, v in list(value.items())[:limit]}


def _insert(fields):
    cols = list(fields)
    with _db() as db:
        return db.execute(f"INSERT INTO wi_alert_events ({', '.join(cols)}) VALUES ({','.join('?' * len(cols))})",
                          [fields[c] for c in cols]).lastrowid


def _set(event_id, **fields):
    if fields:
        with _db() as db:
            db.execute(f"UPDATE wi_alert_events SET {', '.join(f'{k} = ?' for k in fields)} WHERE id = ?", (*fields.values(), event_id))


def receive(source, body, client_ip):
    """One notification of Grafana: every alert in it is recorded; a firing alert runs the checks of each rule it matches
    (except a check of that rule that ran within its cooldown); a resolved one closes the alerts it resolves."""
    if not isinstance(body, dict) or not isinstance(body.get("alerts"), list):
        raise ValueError("Not a Grafana Alerting notification (no alerts list)")
    items = [a for a in body["alerts"][:MAX_ALERTS] if isinstance(a, dict)]
    _count(source["id"], len(items))
    with _db() as db:
        db.execute("UPDATE wi_alert_sources SET last_seen = ?, last_ip = ? WHERE id = ?", (_now(), str(client_ip or "")[:100], source["id"]))
    enabled = rules(enabled_only=True)
    out = {"alerts": len(items), "checks": 0}
    for a in items:
        labels = _text_map(a.get("labels"), 64, 512)
        annotations = _text_map(a.get("annotations"), 32, 2000)
        values = a.get("values") if isinstance(a.get("values"), dict) else {}
        base = {"ts": _now(), "source": source["name"], "client_ip": str(client_ip or "")[:100],
                "fingerprint": str(a.get("fingerprint") or "")[:64], "alertname": labels.get("alertname", "")[:200],
                "status": "resolved" if a.get("status") == "resolved" else "firing", "starts_at": str(a.get("startsAt") or "")[:40],
                "labels": json.dumps(labels, sort_keys=True), "annotations": json.dumps(annotations, sort_keys=True),
                "value_text": (str(a.get("valueString") or "") or ", ".join(f"{k}={v}" for k, v in list(values.items())[:8]))[:500],
                "generator_url": str(a.get("generatorURL") or "")[:500]}
        if base["status"] == "resolved":
            _resolved(base)
            continue
        alert = {"labels": labels, "annotations": annotations}
        hit = [r for r in enabled if matches(r, labels)]
        if not hit:
            _insert(dict(base, state="no-rule", outcome="No rule matches this alert."))
            continue
        for r in hit:
            out["checks"] += _checks_for(r, alert, base, client_ip)
    return out


def _checks_for(r, alert, base, client_ip):
    """The checks of one rule for one firing alert, one row each; returns how many started."""
    fields = dict(base, rule_id=r["id"], rule_name=r["name"])
    try:
        fields["site"] = site_of(r, alert)
    except ValueError as e:
        _insert(dict(fields, state="refused", outcome=f"Not checked: {e}"))
        return 0
    return sum(_check_for(r, item, alert, fields, client_ip) for item in r["checks"])


def _check_for(r, item, alert, fields, client_ip):
    """One check of a rule for one firing alert; True when it started."""
    site = fields["site"]
    fields = dict(fields, check_id=item["check_id"])
    try:
        check = catalog.get(item["check_id"])
        raw = {k: render(v, alert) for k, v in item["params"].items()}
        params = HOOKS["clean"](check, raw, site)
        fields["params"] = json.dumps(params, sort_keys=True)
        if r["cooldown"]:
            with _db() as db:
                prev = db.execute("SELECT run_id, ts FROM wi_alert_events WHERE rule_id = ? AND check_id = ? AND site = ? AND params = ? "
                                  "AND run_id IS NOT NULL AND state IN ('checking', 'checked') AND ts >= ? ORDER BY id DESC LIMIT 1",
                                  (r["id"], check["id"], site, fields["params"], _ago(r["cooldown"]))).fetchone()
            if prev:
                _insert(dict(fields, state="duplicate", run_id=prev["run_id"],
                             outcome=f"Already checked for this rule at {_hm(prev['ts'])} (run #{prev['run_id']}); the cooldown is {r['cooldown']} min."))
                return False
        with _db() as db:
            running = db.execute("SELECT COUNT(*) FROM wi_alert_events WHERE state = 'checking' AND ts >= ?", (_ago(60),)).fetchone()[0]
        if running >= MAX_CHECKING:
            raise ValueError(f"{running} checks of alerts are running: this one waits for the next notification of Grafana")
        run_id = HOOKS["start_check"](site, check, raw, client_ip)
    except (ValueError, LookupError) as e:
        busy = "already running" in str(e)
        _insert(dict(fields, state="duplicate" if busy else "refused", outcome=f"Not checked: {e}"))
        return False
    _insert(dict(fields, state="checking", run_id=run_id, outcome="Check started."))
    return True


def _resolved(base):
    """A resolved alert closes the firing alerts with its fingerprint (one row of its own when nothing was open)."""
    with _db() as db:
        rows = db.execute("SELECT id FROM wi_alert_events WHERE fingerprint = ? AND status = 'firing' AND resolved IS NULL",
                          (base["fingerprint"],)).fetchall() if base["fingerprint"] else []
        for r in rows:
            db.execute("UPDATE wi_alert_events SET resolved = ? WHERE id = ?", (base["ts"], r["id"]))
    if not rows:
        _insert(dict(base, state="resolved", outcome="Resolved in Grafana."))


# ---------------- after a check, after a fix ----------------
def robot(fix=False):
    """The account the checks and fixes of alerts run as (an operator; fixes on SSH hosts only)."""
    return {"username": ROBOT, "display_name": "Grafana alerts", "role": "operator", "source": "alert",
            "modules": ["wi", fixes.PERMISSION] if fix else ["wi"]}


def run_finished(run_id, status):
    """A run ended (modules/wi start_run): the alerts it was started for get its result and may start an allowed fix by
    itself; the run of the check after an automatic fix is noted too."""
    with _db() as db:
        started = [r["id"] for r in db.execute("SELECT id FROM wi_alert_events WHERE run_id = ? AND state = 'checking'", (run_id,))]
        verified = [r["id"] for r in db.execute("SELECT id FROM wi_alert_events WHERE verify_run_id = ?", (run_id,))]
    for eid in verified:
        ev = event(eid) or {}
        _set(eid, verify_status=status, outcome=f"Checked: {STATUS_WORDS.get(ev.get('run_status'), ev.get('run_status'))}. Fix #{ev.get('fix_id')} "
                                                f"ran by itself; the check after it: {STATUS_WORDS.get(status, status)}.")
    if not started:
        return
    record = HOOKS["get_run"](run_id) or {}
    for eid in started:
        _set(eid, state="checked", run_status=status, outcome=f"Checked: {STATUS_WORDS.get(status, status)}.")
        ev = event(eid)
        try:
            if record:
                _auto_fix(ev, record)
        except Exception:
            log.exception("Alert %s: the automatic fix could not start", eid)


def _auto_fix(ev, record):
    """Start the first fix of the result that the rule allows to run by itself; True when one started. The reasons
    an allowed fix waits for an operator go to the alert's outcome."""
    r = rule(ev["rule_id"]) if ev.get("rule_id") else None
    if not r:
        return False
    seen = _remember_fixes(r["id"], record, robot(fix=True))
    allowed = [x for x in seen if x[1] in r["auto_fixes"]]
    if not allowed or record.get("status") not in ("fail", "warn"):
        return False
    note = ""
    if not get_settings()["auto_fix"]:
        note = "Automatic fixes are paused (Alerts → Settings): the fix waits for an operator."
    else:
        with _fix_lock:
            for index, key, title, reason, state in allowed:
                if reason:
                    note = f"The allowed fix waits for an operator: {reason}."
                    continue
                if not state or not state.get("available"):
                    note = f"The allowed fix cannot run by itself: {(state or {}).get('reason') or 'no fix'}"
                    continue
                with _db() as db:
                    hour = db.execute("SELECT COUNT(*) FROM wi_alert_events WHERE rule_id = ? AND fix_id IS NOT NULL AND ts >= ?",
                                      (r["id"], _ago(60))).fetchone()[0]
                    again = AUTO_AGAIN_HOURS > 0 and db.execute("SELECT fix_id, ts FROM wi_alert_events WHERE rule_id = ? AND site = ? AND params = ? AND fix_key = ? "
                                       "AND fix_id IS NOT NULL AND ts >= ? ORDER BY id DESC LIMIT 1",
                                       (r["id"], ev["site"], json.dumps(ev["params"], sort_keys=True), key,
                                        _ago(AUTO_AGAIN_HOURS * 60))).fetchone()
                if again:
                    note = (f"The alert came back after the automatic fix #{again['fix_id']} at {_hm(again['ts'])}: the fix waits "
                            f"for an operator (by itself once every {AUTO_AGAIN_HOURS} hours).")
                    break
                if hour >= r["auto_per_hour"]:
                    note = f"{r['auto_per_hour']} automatic fixes of this rule in the last hour: the fix waits for an operator."
                    break
                fix_id = HOOKS["start_fix"](record, index, robot(fix=True), ev.get("client_ip") or "",
                                            f"alert rule {r['name']} (alert #{ev['id']})")
                _set(ev["id"], fix_id=fix_id, fix_key=key, fix_title=title, fix_status="running",
                     outcome=f"Checked: {STATUS_WORDS.get(record.get('status'), record.get('status'))}. Fix #{fix_id} started by itself.")
                return True
    if note:
        _set(ev["id"], outcome=f"Checked: {STATUS_WORDS.get(record.get('status'), record.get('status'))}. {note}")
    return False


def fix_finished(action_id, status, error="", verify_run_id=None):
    """A fix ended (modules/wi _fix_finished): the alert that started it gets its result and the check that runs after it."""
    with _db() as db:
        ids = [r["id"] for r in db.execute("SELECT id FROM wi_alert_events WHERE fix_id = ?", (action_id,))]
    for eid in ids:
        _set(eid, fix_status=status, **({"verify_run_id": verify_run_id} if verify_run_id else {}))
        if status != "ok":
            ev = event(eid) or {}
            _set(eid, outcome=(ev.get("outcome") or "") + f" The fix failed: {error}"[:400])

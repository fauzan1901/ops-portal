"""Grafana alerts (/runbook/#/alerts): Grafana Alerting sends its notifications to the portal (contact point of type Webhook,
POST /runbook/api/alerts/grafana), a rule of an administrator picks the check for the alert and fills its parameters from
the alert's labels, and the check runs at once as the account "grafana".

- Sources: one per Grafana. Each has its own token (shown once, stored as a SHA-256 hash only), sent by Grafana in the
  Authorization header ("Bearer <token>", or as the Basic password), and optionally the addresses it may come from.
  A sender that cannot send a header (the SRE team's AlertHub-Webhook) is accepted without a token only from exact IPv4
  addresses an administrator lists on its source ("Accept without a token from": at most MAX_TOKENLESS, inside the
  source's allowed addresses, never on two enabled sources; a change needs the source name typed). A request with no
  Authorization header from such an address is that source's; a wrong token is refused from there too. Alerts that
  came without a token are marked so (auth "none"); the rules, including their automatic fixes, treat them as any other.
- Ignore alerts named: per source, alert name patterns (* as in rules, any case, MAX_IGNORE) of alerts nobody needs (AlertHub's
  "Speedtest Bandwidth Low"): the notification is accepted, those alerts (firing or resolved) are not recorded and start
  nothing; the answer counts them and the source keeps a count per day (wi_alert_ignored, IGNORED_DAYS shown). The
  alerts of that source received before the pattern are hidden, never deleted (history): wi_alert_events.ignored = 1
  while a pattern of their source matches them (set when the patterns are saved, and at start-up), shown again when
  it no longer does; the list hides them unless its filter is "Ignored". Rules and cooldowns read them as before.
- Notifications the portal cannot read (not JSON, no alerts list) from an authenticated sender are kept as samples
  (wi_alert_samples, the last MAX_SAMPLES, body cut to SAMPLE_BYTES, never a header but User-Agent and Content-Type) so an
  administrator can see what a new sender sends and a mapping can be written. "Read again" reads a sample with the
  mapping of now (normalize) and, when it is readable, receives it as a notification of its source (rules, checks,
  ignore patterns, cooldown as the receiver), then the sample goes; a body cut at SAMPLE_BYTES cannot be read again.
- Rules: alert name (a * pattern) and label matchers (=, !=, =~, !~ as in Prometheus), the site (fixed or from a
  label), and one or more checks (MAX_RULE_CHECKS), each with its parameters ({{labels.instance|host}},
  {{annotations.summary}}, plain text). Every rule that matches runs its checks, each its own run; the same check of a
  rule with the same site and parameters runs again only after the rule's cooldown.
- Automatic actions: per check of a rule, an administrator may choose one fix seen in its results, or in any other run
  of that check in the portal (an operator's, a health round's: rule_id KNOWN, read by scan_runs), so a rule gets its
  action before its first alert (any kind: SSH host, OpenStack, ONTAP, VyOS, ticked items) with how its items are
  ordered (as listed, or smallest / largest first when they have a size: the flavor RAM of a live migration), at most
  how many items per alert (ACTION_ITEMS), and a stop condition: a measuring check of the rule (the same check, or
  another one) with threshold parameters (memory, CPU, disk %; STOP_DEFAULTS when the rule sets none). The same fix
  for another host is the same action (fix_shape: "off ha-2" and "off compute-7").
- Presets (alert_presets.yml): for the alerts that may come (compute memory or CPU, nodes, control plane, storage, CDN,
  Linux hosts, certificates, hardware), Create rule on an alert fills the rule of the first preset whose alert name
  and labels match it: checks, parameters from labels, and the automatic action observe only. Nothing is saved by it.
  The loop (wi_alert_actions): measure; while the measuring check still reports the problem for the fix's target, run
  ONE item (or the whole fix once), then measure again; stop when the problem is gone, the maximum is used, at the first
  item that fails, when the measuring check cannot tell, or when the switch is turned off or the site frozen meanwhile.
  A customer-impacting fix (impact_of: anything but a normal-risk fix on an SSH host) runs only with the owner's
  approval recorded on the rule (approver, ticket, the rule name typed; it covers the rule's scope: changing what the
  rule matches or does locks it again). Never: on a site listed in "Sites where automatic changes never run"
  (frozen_sites: the check still runs), on VMware Cloud or an ESXi host (read-only), nor a fix that changes a database
  directly (DB_WRITE: an operator runs those). One automatic action per target at a time (a second alert for the same
  compute is noted "already being handled"); at most auto_per_hour actions per rule; the same fix on the same target
  again only after AUTO_AGAIN_HOURS (an alert that comes back waits for an operator). The destination guards of the
  live migrations (wi_ops: large-VM spread, server group affinity, capacity) apply to every item as from Run fix.
- Pilot (mode "observe", MODES): the action measures and decides as in Run, but changes nothing: when the problem is
  still there it records the items it would run (in its order, at most its maximum, status "observed") with the
  destinations the acting result shows now (the destination of each item is chosen when it runs), the reason Run would
  stop now (paused, frozen site, no approval), and stops ("observed"). It needs no approval and runs on frozen sites
  and while the switch is off (the checks run there anyway); never_reason, the rule changed and one action per target
  still apply; it does not count for auto_per_hour nor AUTO_AGAIN_HOURS. A stored action without a mode runs (the
  actions of before); the form makes a new one observe only. Run is a change of the rule: it needs the owner's
  approval again when it is customer-impacting.
The portal only receives: the alerting itself stays in Grafana. What each alert did is on the page Alerts and in Runs.
The list shows the alerts still firing by default; resolved and ignored ones move to the history (filters History:
resolved, History: ignored, All), never deleted before their time. Ignore on an alert adds its exact name to the
ignore patterns of its source (Stop ignoring takes it out again). Everything is kept RUNBOOK_ALERT_KEEP_DAYS days (table
wi_alert_events)."""
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

from . import catalog, fixes, reviews

log = logging.getLogger("portal.wi.alerts")

ROBOT = "grafana"   # the account checks and fixes of alerts run as (Runs, Activity)
KEEP_DAYS = int(os.environ.get("RUNBOOK_ALERT_KEEP_DAYS", "30"))   # the owner, 11 Nov 2026: 30 days, not 180
MAX_BODY = 1024 * 1024   # bytes of one notification (the receiver in modules/wi)
MAX_ALERTS = 200   # per notification of Grafana
RATE_PER_MINUTE = 600   # alerts per source
DEFAULT_COOLDOWN = 30   # minutes
MAX_RULE_CHECKS = 10
MAX_TOKENLESS = 10       # addresses a source accepts without a token
MAX_SAMPLES = 20         # notifications the portal could not read, kept for the administrator
MAX_IGNORE = 20          # alert name patterns a source ignores
IGNORED_DAYS = 7         # the count of ignored alerts on the row of a source
SAMPLE_BYTES = 8 * 1024
AUTO_PER_HOUR = 3
MAX_CHECKING = int(os.environ.get("RUNBOOK_ALERT_MAX_CHECKS", "10"))   # checks of alerts running at once (a flood of alerts)
AUTO_AGAIN_HOURS = 6
ACTION_ITEMS = 5         # items of an automatic action per alert, unless its rule says otherwise (1-MAX_ACTION_ITEMS)
MAX_ACTION_ITEMS = 50
STOP_DEFAULTS = {"mem_warn": "75"}   # the stop condition of a rule that sets no threshold at all (memory of the node, %)
THRESHOLD_SUFFIXES = ("_warn", "_fail")   # parameters of a measuring check that set its thresholds (mem_warn, cpu_fail)
KNOWN = 0                # rule_id of the fixes seen in any run of the portal (wi_alert_fixes_seen), not a rule's own
KNOWN_SCAN = 200         # runs read per pass of scan_runs (the newest first)
PRESETS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alert_presets.yml")
ORDERS = {"listed": "as listed", "smallest": "smallest first", "largest": "largest first"}
MODES = {"observe": "observe only", "run": "runs"}   # an action without a mode runs (stored before the pilot existed)
OPS_DONE = {"live-migrate": "moved", "cold-migrate": "moved", "migrate-volume": "moved", "retype-volume": "retyped",
            "delete-image": "deleted", "delete-snapshots": "deleted"}
TICKET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.:#/()-]{1,79}$")
# Never by itself, approved or not (team rule: database changes are run by an operator): SQL that writes, *-manage, the
# status reset in Cinder's or Nova's database.
DB_WRITE = re.compile(r"(?i)\b(mysql|psql|sqlite3)\b.*\b(update|insert|delete|alter|drop|truncate|replace)\b"
                      r"|\b(nova|cinder|glance|neutron|keystone)-manage\b|\breset-state\b")
STATES =("checking", "checked", "duplicate", "refused", "no-rule", "resolved")
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

# Other modules add their gauges to /runbook/api/alerts/metrics (the scrape of the SRE Grafana): callables returning
# [(name, type, help, [(labels, value)])] (modules.health).
EXTRA_METRICS = []

# What this module needs from the Runbook Automation module (set by modules/wi/__init__.py; fakes in the tests).
HOOKS = {"start_check": None,   # (site, check, raw params, client) -> run id
         "clean": None,         # (check, raw params, site) -> cleaned params
         "get_run": None,       # (run id) -> stored run
         "fix_state": None,     # (run, index, recommendation, user) -> fixes.state(...) with "group" and "category"
         "start_fix": None,     # (run, index, user, client, note, body) -> fix id (body: selected items, confirmation)
         "measure": None,       # (site, check, raw params, client, since) -> id of a run of it started at or after since
         "audit": None,         # (action, target, detail, client): an entry of the activity log, as "grafana"
         "runs_with_fixes": None}   # (check ids, after run id, limit) -> stored runs whose result offers a fix, newest first
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
        db.execute("""CREATE TABLE IF NOT EXISTS wi_alert_samples (
            id INTEGER PRIMARY KEY AUTOINCREMENT, received TEXT NOT NULL, source_id INTEGER, source_name TEXT NOT NULL DEFAULT '',
            client_ip TEXT NOT NULL DEFAULT '', user_agent TEXT NOT NULL DEFAULT '', content_type TEXT NOT NULL DEFAULT '',
            size INTEGER NOT NULL DEFAULT 0, reason TEXT NOT NULL DEFAULT '', body TEXT NOT NULL DEFAULT '')""")
        # columns added after the first version (tables of an older portal get them here)
        db.execute("""CREATE TABLE IF NOT EXISTS wi_alert_ignored (
            source_id INTEGER NOT NULL, day TEXT NOT NULL, n INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (source_id, day))""")
        # one automatic action of a rule for one alert: its loop (measure, one item, measure again...) and what it did
        db.execute("""CREATE TABLE IF NOT EXISTS wi_alert_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER, rule_id INTEGER, rule_name TEXT NOT NULL DEFAULT '',
            check_n INTEGER, check_id TEXT NOT NULL DEFAULT '', site TEXT NOT NULL DEFAULT '', target TEXT NOT NULL DEFAULT '',
            target_key TEXT NOT NULL DEFAULT '', fix_key TEXT NOT NULL DEFAULT '', fix_title TEXT NOT NULL DEFAULT '',
            kind TEXT NOT NULL DEFAULT '', noun TEXT NOT NULL DEFAULT '', impact TEXT NOT NULL DEFAULT '',
            approval TEXT NOT NULL DEFAULT '{}', order_by TEXT NOT NULL DEFAULT 'listed', max_items INTEGER NOT NULL DEFAULT 5,
            measure_check TEXT NOT NULL DEFAULT '', measure_raw TEXT NOT NULL DEFAULT '{}', measure_params TEXT NOT NULL DEFAULT '{}',
            thresholds TEXT NOT NULL DEFAULT '{}', config TEXT NOT NULL DEFAULT '{}', step TEXT NOT NULL, source_run INTEGER, measure_run INTEGER, fix_id INTEGER,
            items TEXT NOT NULL DEFAULT '[]', stop TEXT NOT NULL DEFAULT '', outcome TEXT NOT NULL DEFAULT '', started TEXT NOT NULL,
            ended TEXT, client_ip TEXT NOT NULL DEFAULT '')""")
        for column in ("step", "fix_id", "measure_run", "target_key"):
            db.execute(f"CREATE INDEX IF NOT EXISTS wi_alert_actions_{column} ON wi_alert_actions({column})")
        for table, column, kind in (("wi_alert_sources", "tokenless", "TEXT NOT NULL DEFAULT ''"), ("wi_alert_events", "auth", "TEXT"),
                                    ("wi_alert_sources", "ignore_names", "TEXT NOT NULL DEFAULT ''"), ("wi_alert_samples", "auth", "TEXT"),
                                    ("wi_alert_events", "ignored", "INTEGER NOT NULL DEFAULT 0"),
                                    ("wi_alert_rules", "approval", "TEXT NOT NULL DEFAULT ''"), ("wi_alert_events", "check_n", "INTEGER"),
                                    ("wi_alert_events", "action_id", "INTEGER"), ("wi_alert_fixes_seen", "impact", "TEXT NOT NULL DEFAULT ''"),
                                    ("wi_alert_fixes_seen", "items", "INTEGER NOT NULL DEFAULT 0"),
                                    ("wi_alert_fixes_seen", "sized", "INTEGER NOT NULL DEFAULT 0"),
                                    ("wi_alert_fixes_seen", "noun", "TEXT NOT NULL DEFAULT ''"),
                                    ("wi_alert_fixes_seen", "kind", "TEXT NOT NULL DEFAULT ''"),
                                    ("wi_alert_actions", "mode", "TEXT NOT NULL DEFAULT 'run'")):
            if column not in {r[1] for r in db.execute(f"PRAGMA table_info({table})")}:
                db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {kind}")
        # fixes noted by the version before automatic actions: what "waited for an operator" is now customer-impacting
        for old, new in OLD_WAITS.items():
            db.execute("UPDATE wi_alert_fixes_seen SET eligible = 1, impact = ?, reason = '' WHERE eligible = 0 AND reason = ?", (new, old))
        # the portal stopped during an automatic action: its item ended with the portal (or runs on without a loop): it stops
        stale = db.execute("SELECT id, event_id FROM wi_alert_actions WHERE step != 'done'").fetchall()
        for a in stale:
            text = (f"Automatic action #{a['id']} stopped: the portal restarted during it; nothing more runs by itself (an "
                    "operator looks at the last fix in Runs).")
            db.execute("UPDATE wi_alert_actions SET step = 'done', stop = 'restart', outcome = ?, ended = ? WHERE id = ?",
                       (text, _now(), a["id"]))
            db.execute("UPDATE wi_alert_events SET outcome = ? WHERE id = ?", (text, a["event_id"]))
    cleanup()
    notes = _migrate_auto_fixes()
    # the alerts received before a source got its patterns (or before this version): hidden by the patterns of now
    for s in sources():
        hidden, shown = apply_ignore(s["id"])
        if hidden or shown:
            log.info("Alerts of %s: %s earlier alert(s) hidden, %s shown again by its ignore patterns", s["name"], hidden, shown)
    return notes


# The reasons of the version before automatic actions (wi_alert_fixes_seen) and what they are now
OLD_WAITS = {"OpenStack changes always wait for an operator": "OpenStack change",
             "ONTAP changes always wait for an operator": "ONTAP change",
             "VyOS changes always wait for an operator": "VyOS change",
             "A fix of ticked items waits for an operator": "ticked items",
             "The change steps of a template wait for an operator": "the change steps of a template",
             "High risk (deletes, restarts, kills, reboots): waits for an operator": "high risk (deletes, restarts, kills, reboots)",
             "Changes the firewall, network, packages or accounts: waits for an operator":
                 "changes the firewall, network, packages or accounts"}


def _migrate_auto_fixes():
    """The fixes a rule allowed to run by themselves (the version before automatic actions) become the automatic action
    of their check (the whole fix once, measured by the same check); a second allowed fix of the same check is not kept
    (one action per check) and said so. Returns [(rule name, text)] for the activity log."""
    notes = []
    with _db() as db:
        rows = db.execute("SELECT id, name, checks, auto_fixes FROM wi_alert_rules WHERE auto_fixes NOT IN ('', '[]')").fetchall()
    for row in rows:
        seen = {f["key"]: f for f in fixes_seen(row["id"])}
        checks, kept, left = json.loads(row["checks"] or "[]"), [], []
        for key in json.loads(row["auto_fixes"] or "[]"):
            f = seen.get(key)
            n = next((i for i, c in enumerate(checks) if f and c["check_id"] == f["check_id"] and not c.get("action")), None)
            if n is None:
                left.append((f or {}).get("title") or key)
                continue
            checks[n]["action"] = {"fix": key, "title": f["title"], "order": "listed", "max_items": ACTION_ITEMS, "measure": n,
                                   "thresholds": {}}
            kept.append(f["title"])
        with _db() as db:
            db.execute("UPDATE wi_alert_rules SET checks = ?, auto_fixes = '[]' WHERE id = ?", (json.dumps(checks, sort_keys=True), row["id"]))
        text = (f"Alert rule {row['name']}: the fixes it allowed to run by themselves are now the automatic actions of their checks"
                + (f" ({'; '.join(kept)})" if kept else "") + (f"; not kept, one automatic action per check: {'; '.join(left)}" if left else ""))
        log.info(text)
        notes.append((row["name"], text[:1000]))
    return notes


def cleanup():
    """Alerts older than KEEP_DAYS days go (the Runs they started stay)."""
    with _db() as db:
        db.execute("DELETE FROM wi_alert_events WHERE ts < ?", (_ago(KEEP_DAYS * 24 * 60),))
        db.execute("DELETE FROM wi_alert_actions WHERE started < ? AND step = 'done'", (_ago(KEEP_DAYS * 24 * 60),))
        db.execute("DELETE FROM wi_alert_ignored WHERE day < ?", (_ago(31 * 24 * 60)[:10],))


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


def _client_ip(value):
    """The client address as text; an IPv4 address mapped into IPv6 (::ffff:a.b.c.d) as the IPv4 address."""
    try:
        ip = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return ""
    return str(ip.ipv4_mapped or ip) if ip.version == 6 else str(ip)


def tokenless_addresses(text, networks, source_id=None, enabled=True):
    """The addresses a source accepts without a token, cleaned: exact IPv4 addresses only (no network, no range), at most
    MAX_TOKENLESS, each inside the source's allowed addresses when it has some, none of them on another enabled source."""
    out = []
    for x in re.split(r"[\s,;]+", str(text or "").strip()):
        if not x:
            continue
        if "/" in x or "-" in x or "*" in x:
            raise ValueError(f"{x[:45]}: only single IPv4 addresses are accepted without a token (no networks or ranges)")
        try:
            ip = ipaddress.IPv4Address(x)
        except ValueError:
            raise ValueError(f"{x[:45]} is not an IPv4 address") from None
        if str(ip) not in out:
            out.append(str(ip))
    if len(out) > MAX_TOKENLESS:
        raise ValueError(f"At most {MAX_TOKENLESS} addresses without a token")
    nets = [ipaddress.ip_network(n) for n in str(networks or "").split(",") if n]
    outside = [a for a in out if nets and not any(ipaddress.ip_address(a) in n for n in nets)]
    if outside:
        raise ValueError(f"{', '.join(outside)} {'is' if len(outside) == 1 else 'are'} not inside Allowed from of this source")
    if out and enabled:
        with _db() as db:
            for r in db.execute("SELECT id, name, tokenless FROM wi_alert_sources WHERE enabled = 1 AND tokenless != ''"):
                same = sorted(set(out) & set(r["tokenless"].split(",")))
                if same and r["id"] != source_id:
                    raise ValueError(f"{', '.join(same)} {'is' if len(same) == 1 else 'are'} already accepted without a token for the "
                                     f"source {r['name']}: an address belongs to one enabled source")
    return ",".join(out)


def ignore_patterns(text):
    """The alert name patterns a source ignores, cleaned: comma or line separated, at most MAX_IGNORE, each up to 200
    characters; * and ? as in the alert name of a rule, any case. Returned one per line."""
    out = []
    for x in re.split(r"[,\n]+", str(text or "")):
        x = x.strip()
        if not x:
            continue
        if len(x) > 200:
            raise ValueError(f"Ignore alerts named: {x[:40]}… is longer than 200 characters")
        if x.lower() not in [o.lower() for o in out]:
            out.append(x)
    if len(out) > MAX_IGNORE:
        raise ValueError(f"Ignore alerts named: at most {MAX_IGNORE} patterns")
    return "\n".join(out)


def ignored_by(patterns, alertname):
    """The first pattern of a source that ignores this alert name ("" when none does)."""
    name = str(alertname or "").lower()
    return next((p for p in patterns if fnmatch.fnmatchcase(name, p.lower())), "")


def _ignored_counts():
    with _db() as db:
        return {r["source_id"]: r["n"] for r in db.execute("SELECT source_id, SUM(n) AS n FROM wi_alert_ignored WHERE day >= ? "
                                                           "GROUP BY source_id", (_ago((IGNORED_DAYS - 1) * 24 * 60)[:10],))}


def _source_row(r, ignored=None):
    return {"id": r["id"], "name": r["name"], "token_tail": r["token_tail"], "networks": r["networks"],
            "tokenless": r["tokenless"] or "", "ignore": [p for p in (r["ignore_names"] or "").split("\n") if p],
            "ignored": (ignored or {}).get(r["id"], 0), "ignored_days": IGNORED_DAYS,
            "enabled": bool(r["enabled"]), "created": r["created"], "created_by": r["created_by"], "updated": r["updated"],
            "updated_by": r["updated_by"], "last_seen": r["last_seen"], "last_ip": r["last_ip"]}


def source(source_id):
    with _db() as db:
        r = db.execute("SELECT * FROM wi_alert_sources WHERE id = ?", (source_id,)).fetchone()
    return _source_row(r, _ignored_counts()) if r else None


def sources():
    counts = _ignored_counts()
    with _db() as db:
        return [_source_row(r, counts) for r in db.execute("SELECT * FROM wi_alert_sources ORDER BY name")]


def set_ignore(source_id, text, username):
    """Change the alert names a source ignores (no confirmation: nothing runs that did not before), and hide or show
    again its earlier alerts by the new patterns. Returns (before, after, hidden, shown), the patterns one per line."""
    current = source(source_id)
    if not current:
        raise LookupError("No such source")
    after = ignore_patterns(text)
    before = "\n".join(current["ignore"])
    if after != before:
        with _db() as db:
            db.execute("UPDATE wi_alert_sources SET ignore_names = ?, updated = ?, updated_by = ? WHERE id = ?",
                       (after, _now(), username, source_id))
    hidden, shown = apply_ignore(source_id)
    return before, after, hidden, shown


def apply_ignore(source_id):
    """The earlier alerts of a source (by its name) hidden while one of its patterns matches them, shown again when none
    does; never deleted. Returns (hidden, shown) of this pass."""
    src = source(source_id)
    if not src:
        return 0, 0
    patterns = src["ignore"]
    hide, show = [], []
    with _db() as db:
        for r in db.execute("SELECT id, alertname, ignored FROM wi_alert_events WHERE source = ?", (src["name"],)):
            want = 1 if patterns and ignored_by(patterns, r["alertname"]) else 0
            if want != (r["ignored"] or 0):
                (hide if want else show).append(r["id"])
        for ids, value in ((hide, 1), (show, 0)):
            for n in range(0, len(ids), 500):
                part = ids[n:n + 500]
                db.execute(f"UPDATE wi_alert_events SET ignored = ? WHERE id IN ({','.join('?' * len(part))})", [value, *part])
    return len(hide), len(show)


def exact_pattern(alertname):
    """An ignore pattern that matches this alert name only (* ? [ taken literally)."""
    return re.sub(r"([*?\[])", r"[\1]", str(alertname or ""))


def _event_source(event_id):
    ev = event(event_id)
    if not ev:
        raise LookupError("No such alert")
    if not str(ev.get("alertname") or "").strip():
        raise ValueError("This alert has no alertname to ignore")
    with _db() as db:
        r = db.execute("SELECT id FROM wi_alert_sources WHERE name = ?", (ev["source"],)).fetchone()
    if not r:
        raise LookupError(f"The source {ev['source']} of this alert no longer exists")
    return ev, source(r["id"])


def ignore_event(event_id, username):
    """Ignore button of an alert: its source ignores its exact name from now on (no check runs for it), and its alerts
    of that name so far are hidden (history). Returns (source, pattern, hidden)."""
    ev, src = _event_source(event_id)
    already = ignored_by(src["ignore"], ev["alertname"])
    if already:
        raise ValueError(f"{ev['alertname']} is already ignored by the pattern {already} of the source {src['name']}")
    pattern = exact_pattern(ev["alertname"])
    _b, _a, hidden, _s = set_ignore(src["id"], "\n".join(src["ignore"] + [pattern]), username)
    return src, pattern, hidden


def unignore_event(event_id, username):
    """Stop ignoring on an ignored alert: the exact name pattern of Ignore goes again (a * pattern of the source stays:
    Edit source changes it). Returns (source, pattern, shown)."""
    ev, src = _event_source(event_id)
    pattern = exact_pattern(ev["alertname"])
    rest = [p for p in src["ignore"] if p.lower() != pattern.lower()]
    if len(rest) == len(src["ignore"]):
        by = ignored_by(src["ignore"], ev["alertname"])
        raise ValueError(f"{ev['alertname']} is ignored by the pattern {by} of the source {src['name']}: change it on Edit source"
                         if by else f"{ev['alertname']} is not ignored")
    if ignored_by(rest, ev["alertname"]):
        raise ValueError(f"{ev['alertname']} is also ignored by the pattern {ignored_by(rest, ev['alertname'])} of the source "
                         f"{src['name']}: change it on Edit source")
    _b, _a, _h, shown = set_ignore(src["id"], "\n".join(rest), username)
    return src, pattern, shown


def _new_token():
    token = "gfa_" + secrets.token_urlsafe(32)
    return token, _hash(token), token[-4:]


def _confirm_tokenless(before, after, name, confirm):
    """Accepting alerts without a token (or changing from where): the source name typed."""
    if before != after and str(confirm or "").strip() != name:
        raise ValueError(f"Accept without a token: type the source name {name} to confirm.")


def add_source(name, networks, username, tokenless="", confirm="", ignore=""):
    name = str(name or "").strip()
    if not NAME_RE.match(name):
        raise ValueError("Name: 1-80 letters, digits, spaces and _ . : ( ) / -")
    nets = _networks(networks)
    free = tokenless_addresses(tokenless, nets)
    _confirm_tokenless("", free, name, confirm)
    skip = ignore_patterns(ignore)
    token, digest, tail = _new_token()
    try:
        with _db() as db:
            cur = db.execute("INSERT INTO wi_alert_sources (name, token_hash, token_tail, networks, tokenless, ignore_names, created, created_by) "
                             "VALUES (?,?,?,?,?,?,?,?)", (name, digest, tail, nets, free, skip, _now(), username))
    except sqlite3.IntegrityError:
        raise ValueError(f"A source named {name} already exists") from None
    return cur.lastrowid, token


def update_source(source_id, name, networks, enabled, username, tokenless=None, confirm=""):
    """Change a source; tokenless None keeps the addresses accepted without a token (they are checked again: the allowed
    addresses or the switch may have changed). Returns (before, after) of the tokenless addresses."""
    current = source(source_id)
    if not current:
        raise LookupError("No such source")
    name = str(name or "").strip()
    if not NAME_RE.match(name):
        raise ValueError("Name: 1-80 letters, digits, spaces and _ . : ( ) / -")
    nets = _networks(networks)
    free = tokenless_addresses(current["tokenless"] if tokenless is None else tokenless, nets, source_id, bool(enabled))
    _confirm_tokenless(current["tokenless"], free, name, confirm)
    try:
        with _db() as db:
            cur = db.execute("UPDATE wi_alert_sources SET name = ?, networks = ?, enabled = ?, tokenless = ?, updated = ?, updated_by = ? "
                             "WHERE id = ?", (name, nets, 1 if enabled else 0, free, _now(), username, source_id))
    except sqlite3.IntegrityError:
        raise ValueError(f"A source named {name} already exists") from None
    if not cur.rowcount:
        raise LookupError("No such source")
    return current["tokenless"], free


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
    if not header:   # no Authorization header at all: only from an address a source accepts without a token
        ip = _client_ip(remote_ip)
        with _db() as db:
            rows = [r for r in db.execute("SELECT * FROM wi_alert_sources WHERE enabled = 1 AND tokenless != ''")
                    if ip and ip in r["tokenless"].split(",")]
        if len(rows) == 1:
            row = rows[0]
            if row["networks"] and not any(ipaddress.ip_address(ip) in ipaddress.ip_network(n) for n in row["networks"].split(",")):
                raise Refused(f"{remote_ip} is not an allowed address of the source {row['name']}.")
            return dict(_source_row(row), auth="none")
        raise Unauthorized("Send the token of the source in the Authorization header (Bearer), or as the Basic password.")
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
    return dict(_source_row(row), auth="token")


# ---------------- notifications the portal cannot read (samples for the administrator) ----------------
SAMPLE_FIELDS = ("id", "received", "source_id", "source_name", "client_ip", "user_agent", "content_type", "size", "reason", "body",
                 "auth")


# ---------------- notifications of other senders, read as Grafana's ----------------
# AlertHub (the webhook of the SRE team, User-Agent AlertHub-Webhook/1.0, "event": "alertify.*") forwards the Grafana notification
# it got in "grafana" (and again in "raw"); a short one only has its markdown message: "*ALERT: <alert name>*", then
# "**Node:** ...", "**Cluster:** ...", "**Site:** ...", "**Role:** ...", "**Instance:** ...", "**Status:** *Firing*".
ALERTHUB_LABELS = {"node": "nodename", "node name": "nodename", "nodename": "nodename", "cluster": "cluster", "site": "site",
               "role": "role", "instance": "instance"}
MARKDOWN = re.compile(r"[*_`]")


def normalize(body):
    """A notification as Grafana's ({"alerts": [...]}): Grafana and Alertmanager ones as they are, AlertHub's from the Grafana
    notification it carries or else from its message; anything else unchanged (unreadable() then says why)."""
    if not isinstance(body, dict) or isinstance(body.get("alerts"), list):
        return body
    if str(body.get("event") or "").startswith("alertify"):
        for key in ("grafana", "raw"):
            inner = body.get(key)
            if isinstance(inner, dict) and isinstance(inner.get("alerts"), list) and not unreadable(inner):
                return inner
        alert = _alerthub_alert(body)
        if alert:
            return {"status": alert["status"], "alerts": [alert]}
    return body


def _alerthub_alert(body):
    """The alert of a AlertHub message without a Grafana notification: its fields as labels (node, cluster, site, role,
    instance), the rest (usage, ...) as annotations; the fingerprint from the alert name and its node / instance."""
    text = str(body.get("message") or "")
    fields, name = {}, ""
    for raw in text.splitlines():
        line = MARKDOWN.sub("", raw).strip()
        m = re.match(r"(?i)^alert\s*:\s*(.+)$", line)
        if m and not name:
            name = m.group(1).strip()
            continue
        key, sep, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if sep and value and re.fullmatch(r"[a-z][a-z ]{0,30}", key):
            fields.setdefault(key, value)
    if not name:
        return None
    labels = {"alertname": name[:200]}
    annotations = {}
    for key, value in fields.items():
        if key in ALERTHUB_LABELS:
            labels[ALERTHUB_LABELS[key]] = value[:512]
        elif key != "status":
            annotations[key.replace(" ", "_")] = value[:500]
    state = str(fields.get("status") or body.get("status") or "").lower()
    annotations["summary"] = name + (f" on {labels['nodename']}" if labels.get("nodename") else "")
    annotations["description"] = MARKDOWN.sub("", text)[:2000]
    key = "|".join([name, labels.get("nodename", ""), labels.get("instance", ""), labels.get("cluster", "")])
    return {"status": "resolved" if state.startswith("resolv") else "firing", "labels": labels, "annotations": annotations,
            "startsAt": str(body.get("timestamp") or "")[:40], "fingerprint": "alerthub-" + hashlib.sha256(key.encode()).hexdigest()[:16]}


def unreadable(body):
    """Why a parsed notification is not one of Grafana Alerting / Alertmanager ("" when it is)."""
    if not isinstance(body, dict):
        return "The JSON is not an object (Grafana and Alertmanager send an object with an alerts list)"
    if not isinstance(body.get("alerts"), list):
        return "No alerts list (not a Grafana Alerting or Alertmanager notification)"
    items = body["alerts"]
    if items and not any(isinstance(a, dict) and isinstance(a.get("labels"), dict) for a in items):
        return "The alerts have no labels (not a Grafana Alerting or Alertmanager notification)"
    return ""


def record_sample(source, client_ip, user_agent, content_type, data, reason):
    """Keep what an authenticated sender sent that the portal could not read: the body (cut to SAMPLE_BYTES), its size,
    User-Agent and Content-Type; never the Authorization header. The last MAX_SAMPLES stay."""
    _count(source["id"], 1)   # a flood of junk is refused like a flood of alerts
    raw = bytes(data or b"")
    body = raw[:SAMPLE_BYTES].decode("utf-8", errors="replace")
    with _db() as db:
        sample_id = db.execute("INSERT INTO wi_alert_samples (received, source_id, source_name, client_ip, user_agent, content_type, "
                               "size, reason, body, auth) VALUES (?,?,?,?,?,?,?,?,?,?)",
                               (_now(), source["id"], source["name"], str(client_ip or "")[:100], str(user_agent or "")[:200],
                                str(content_type or "")[:100], len(raw), str(reason)[:300], body, source.get("auth") or "token")).lastrowid
        db.execute("DELETE FROM wi_alert_samples WHERE id NOT IN (SELECT id FROM wi_alert_samples ORDER BY id DESC LIMIT ?)",
                   (MAX_SAMPLES,))
        db.execute("UPDATE wi_alert_sources SET last_seen = ?, last_ip = ? WHERE id = ?", (_now(), str(client_ip or "")[:100], source["id"]))
    return sample_id


def samples():
    with _db() as db:
        return [{k: r[k] for k in SAMPLE_FIELDS} for r in db.execute("SELECT * FROM wi_alert_samples ORDER BY id DESC")]


def delete_samples():
    with _db() as db:
        return db.execute("DELETE FROM wi_alert_samples").rowcount


def sample(sample_id):
    with _db() as db:
        r = db.execute("SELECT * FROM wi_alert_samples WHERE id = ?", (sample_id,)).fetchone()
    return {k: r[k] for k in SAMPLE_FIELDS} if r else None


def read_sample(sample_id):
    """Read a sample again with the mapping of now: when it is readable, it is received as a notification of its source
    (from the sample's address, as the receiver would), and the sample goes. ValueError (the sample stays) when its body
    was cut at SAMPLE_BYTES, its source is gone or off, or it is still not readable. Returns (sample, receive() answer)."""
    x = sample(sample_id)
    if not x:
        raise LookupError("This sample is no longer kept")
    if x["size"] > SAMPLE_BYTES:
        raise ValueError(f"Sample #{sample_id} was cut to {SAMPLE_BYTES // 1024} KB ({x['size']} bytes came): it cannot be read "
                         "again. The sender has to send it again.")
    src = source(x["source_id"]) if x["source_id"] else None
    if not src:
        raise ValueError(f"The source {x['source_name']} of sample #{sample_id} was removed.")
    if not src["enabled"]:
        raise ValueError(f"The source {src['name']} is off: turn it on first.")
    try:
        body = normalize(json.loads(x["body"] or "null"))
        reason = unreadable(body)
    except ValueError:
        reason = "The body is not JSON"
    if reason:
        raise ValueError(f"Sample #{sample_id} is still not readable: {reason}")
    # an older sample does not say how it came: without a token when it came from an address its source takes so
    auth = x["auth"] or ("none" if x["client_ip"] in src["tokenless"].split(",") else "token")
    out = receive(dict(src, auth=auth), body, x["client_ip"])
    with _db() as db:
        db.execute("DELETE FROM wi_alert_samples WHERE id = ?", (sample_id,))
    return x, out


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
    """An address from an alert label: "https://10.253.128.5:9100/metrics" → 10.253.128.5, "[fe80::1]:9100" → fe80::1."""
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
            "cooldown": r["cooldown"], "auto_per_hour": r["auto_per_hour"], "approval": json.loads(r["approval"] or "{}"),
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
        if any(c["check_id"] == check_id and c["params"] == params for c in checks):
            raise ValueError(f"{allowed[check_id]['title']} is twice in the rule with the same parameters")
        checks.append({"check_id": check_id, "params": params})
    if not 1 <= len(checks) <= MAX_RULE_CHECKS:
        raise ValueError(f"A rule runs 1-{MAX_RULE_CHECKS} checks")
    try:
        cooldown = int(d.get("cooldown", DEFAULT_COOLDOWN))
        per_hour = int(d.get("auto_per_hour", AUTO_PER_HOUR))
    except (TypeError, ValueError):
        raise ValueError("Cooldown and automatic actions per hour are whole numbers") from None
    if not 0 <= cooldown <= 24 * 60:
        raise ValueError("Cooldown: 0-1440 minutes")
    if not 1 <= per_hour <= 20:
        raise ValueError("Automatic actions per hour: 1-20")
    # automatic actions: per check, a fix seen in the results of this rule or in another run of that check (fixes_for)
    seen = {f["key"]: f for f in fixes_for(current["id"] if current else None)}
    raw = d.get("checks") or []
    for n, item in enumerate(checks):
        action = _clean_action((raw[n] if isinstance(raw[n], dict) else {}).get("action"), n, checks, seen, allowed)
        if action:
            item["action"] = action
    return {"name": name, "enabled": bool(d.get("enabled", True)), "alertname": alertname, "matchers": matchers, "site": site,
            "checks": checks, "cooldown": cooldown, "auto_per_hour": per_hour}


def _clean_action(a, n, checks, seen, allowed):
    """The automatic action of check n of a rule (None: none): the fix, the order of its items, at most how many per
    alert, and the stop condition (the measuring check of the rule and its thresholds). ValueError otherwise."""
    if not isinstance(a, dict) or not str(a.get("fix") or "").strip():
        return None
    where = f"Check {n + 1}"
    f = seen.get(str(a["fix"]).strip())
    if not f or f["check_id"] != checks[n]["check_id"]:
        raise ValueError(f"{where}: the automatic action is a fix seen in the results of this check (listed once it ran in the "
                         "portal and offered it)")
    if not f["eligible"]:
        raise ValueError(f"{where}: {f['title']} never runs by itself: {f['reason']}")
    mode = str(a.get("mode") or "run")
    if mode not in MODES:
        raise ValueError(f"{where}: the mode of the automatic action is observe (it changes nothing) or run")
    order = str(a.get("order") or "listed")
    if order not in ORDERS or (order != "listed" and not f["sized"]):
        raise ValueError(f"{where}: the order of the items is " + ("as listed, smallest first or largest first" if f["sized"]
                                                                   else "as listed (they have no size)"))
    try:
        max_items, measure = int(a.get("max_items", ACTION_ITEMS if f["items"] else 1)), int(a.get("measure", n))
    except (TypeError, ValueError):
        raise ValueError(f"{where}: the maximum of items and the measuring check are whole numbers") from None
    if not 1 <= max_items <= MAX_ACTION_ITEMS:
        raise ValueError(f"{where}: 1-{MAX_ACTION_ITEMS} items per alert")
    if not 0 <= measure < len(checks):
        raise ValueError(f"{where}: the stop condition is measured by a check of this rule")
    mcheck = allowed[checks[measure]["check_id"]]
    names = {p["name"] for p in mcheck["params"]}
    thresholds = {}
    for k, v in (a.get("thresholds") or {}).items():
        if k not in names:
            raise ValueError(f"{where}: {mcheck['title']} (the measuring check) has no parameter {k}")
        if str(v or "").strip():
            check_template(v)
            thresholds[k] = str(v).strip()
    # e.g. memory 75%, only when neither the stop condition nor the measuring check sets a threshold: a CPU stop
    # (cpu_warn) must not keep moving instances for the memory
    if not thresholds and not any(k.endswith(THRESHOLD_SUFFIXES) for k in checks[measure]["params"]):
        thresholds = {k: v for k, v in STOP_DEFAULTS.items() if k in names}
    # a fix without items runs once per volume or host it offers (the same fix, one at a time), up to max_items
    out = {"fix": f["key"], "title": f["title"], "order": order, "max_items": max_items, "measure": measure, "thresholds": thresholds}
    then = a.get("then") if isinstance(a.get("then"), dict) else {}
    if str(then.get("fix") or "").strip():   # Then: another fix of this check, once its fix has nothing left (snapshots, then migrations)
        g = seen.get(str(then["fix"]).strip())
        if not g or g["check_id"] != checks[n]["check_id"] or g["key"] == f["key"]:
            raise ValueError(f"{where}: Then is another fix seen in the results of this check")
        if not g["eligible"]:
            raise ValueError(f"{where}: {g['title']} never runs by itself: {g['reason']}")
        t_order = str(then.get("order") or "listed")
        if t_order not in ORDERS or (t_order != "listed" and not g["sized"]):
            raise ValueError(f"{where}: the order of Then is " + ("as listed, smallest first or largest first" if g["sized"]
                                                                  else "as listed (its items have no size)"))
        try:
            t_max = int(then.get("max_items", ACTION_ITEMS))
        except (TypeError, ValueError):
            raise ValueError(f"{where}: the maximum of Then is a whole number") from None
        if not 1 <= t_max <= MAX_ACTION_ITEMS:
            raise ValueError(f"{where}: Then runs 1-{MAX_ACTION_ITEMS} per alert")
        out["then"] = {"fix": g["key"], "title": g["title"], "order": t_order, "max_items": t_max}
    if mode == "observe":   # "run" is left out: an action stored before the pilot is the same action
        out["mode"] = mode
    return out


def mode_of(cfg):
    """observe or run (an action without a mode runs)."""
    return "observe" if (cfg or {}).get("mode") == "observe" else "run"


def _run_impact(r, seen):
    """The customer-impacting actions of a rule that run (observe only changes nothing: no approval)."""
    return [t for c in r["checks"] if c.get("action") and mode_of(c["action"]) == "run"
            for _w, k, t, _o, _m in _phases(c["action"]) if (seen.get(k) or {}).get("impact")]


def _scope_sig(r):
    """What the owner's approval of a rule covers: what it matches, where, which checks with which actions, how often."""
    scope = {k: r.get(k) for k in ("alertname", "matchers", "site", "checks", "auto_per_hour")}
    return hashlib.sha256(json.dumps(scope, sort_keys=True).encode()).hexdigest()[:24]


def approved(r):
    """The owner's approval recorded on the rule covers it as it is now (changed since: locked again)."""
    a = (r or {}).get("approval") or {}
    return bool(a.get("ticket")) and a.get("sig") == _scope_sig(r)


def approval_state(r, seen=None):
    """For the page: the customer-impacting actions of a rule and whether the owner's approval covers them."""
    seen = {f["key"]: f for f in fixes_for(r["id"])} if seen is None else seen
    impact = _run_impact(r, seen)
    a = r.get("approval") or {}
    ok = approved(r)
    return {"needed": bool(impact), "impact": impact, "valid": bool(impact) and ok, "stale": bool(a.get("ticket")) and not ok,
            **{k: a.get(k, "") for k in ("by", "name", "ticket", "at")}}


def save_rule(data, username, rule_id=None, confirm="", ticket="", approver=""):
    """Add (rule_id None) or change a rule. A new or changed automatic action needs the rule's name typed (confirm); a
    ticket records the owner's approval of its customer-impacting actions (approver: the administrator saving, who
    types the rule name too). Without it they are saved locked. Returns (rule id, {"added", "approved", "locked"})."""
    current = rule(rule_id) if rule_id else None
    if rule_id and not current:
        raise LookupError("No such rule")
    r = clean_rule(data, current)
    seen = {f["key"]: f for f in fixes_for(rule_id if current else None)}
    before = {json.dumps(c, sort_keys=True) for c in (current or {}).get("checks") or [] if c.get("action")}
    added = [c["action"]["title"] for c in r["checks"] if c.get("action") and json.dumps(c, sort_keys=True) not in before]
    impact = _run_impact(r, seen)
    ticket = str(ticket or "").strip()
    if ticket and not impact:
        raise ValueError("No automatic action of this rule that runs is customer-impacting (observe only changes nothing): "
                         "it needs no approval.")
    if ticket and not TICKET_RE.match(ticket):
        raise ValueError("Ticket or reference: 2-80 letters, digits, spaces and _ . : # / ( ) -")
    if (added or ticket) and str(confirm or "").strip() != r["name"]:
        raise ValueError(f"Automatic actions: type the rule name {r['name']} to confirm.")
    approval = (current or {}).get("approval") or {}
    if ticket:
        approval = {"by": username, "name": str(approver or username)[:120], "ticket": ticket, "at": _now(), "sig": _scope_sig(r),
                    "actions": impact}
    elif not impact:
        approval = {}
    values = (r["name"], 1 if r["enabled"] else 0, r["alertname"], json.dumps(r["matchers"]), r["site"],
              json.dumps(r["checks"], sort_keys=True), r["cooldown"], "[]", r["auto_per_hour"], json.dumps(approval, sort_keys=True),
              _now(), username)
    try:
        with _db() as db:
            if current:
                db.execute("UPDATE wi_alert_rules SET name = ?, enabled = ?, alertname = ?, matchers = ?, site = ?, checks = ?, "
                           "cooldown = ?, auto_fixes = ?, auto_per_hour = ?, approval = ?, updated = ?, updated_by = ? WHERE id = ?",
                           values + (rule_id,))
                ids = sorted({c["check_id"] for c in r["checks"]})   # the fixes of checks the rule no longer runs go
                db.execute(f"DELETE FROM wi_alert_fixes_seen WHERE rule_id = ? AND check_id NOT IN ({','.join('?' * len(ids))})",
                           [rule_id, *ids])
            else:
                rule_id = db.execute("INSERT INTO wi_alert_rules (name, enabled, alertname, matchers, site, checks, cooldown, "
                                     "auto_fixes, auto_per_hour, approval, created, created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                                     values).lastrowid
    except sqlite3.IntegrityError:
        raise ValueError(f"A rule named {r['name']} already exists") from None
    saved = rule(rule_id)
    return rule_id, {"added": added, "approved": bool(ticket), "locked": [] if approved(saved) else impact}


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
    data = data if isinstance(data, dict) else {}
    r = clean_rule(dict(data, checks=[{k: v for k, v in c.items() if k != "action"} if isinstance(c, dict) else c
                                      for c in data.get("checks") or []]))
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


def fix_shape(title):
    """A fix title with its numbers and host names left out: the same fix for another compute or host ("off ha-2",
    "off overcloud-novacompute-7.localdomain", "on 10.248.0.11") is the same automatic action. A word with a dash or a
    dot is a host name only with a digit in it ("live-migrate" stays)."""
    norm = re.sub(r"\d+([.,]\d+)?", "#", re.sub(r"\s+", " ", str(title or "")).strip().lower())
    return re.sub(r"[a-z0-9_#]+(?:[.:-][a-z0-9_#]+)+", lambda m: "<host>" if "#" in m.group() else m.group(), norm)


def impact_of(state, action):
    """Why this fix is customer-impacting ('' for a normal-risk fix on an SSH host): it runs by itself only with the
    owner's approval recorded on its rule."""
    if not state:
        return ""
    why = []
    if state["kind"] != "host":
        why.append({"openstack": "OpenStack change", "ontap": "ONTAP change"}.get(state["kind"], "VyOS change"))
    if state.get("selectable"):
        why.append("ticked items")
    if (action or {}).get("operation"):
        why.append("the change steps of a template")
    if state["risk"] != "normal" or any(i.get("delete") for i in state.get("items") or []):
        why.append("high risk (deletes, restarts, kills, reboots)")
    if any(AUTO_DENY.search(str(c)) for c in _commands(state)):
        why.append("changes the firewall, network, packages or accounts")
    return "; ".join(why)


def never_reason(state):
    """Why this fix never runs by itself, approved or not ('' when it may)."""
    if not state:
        return "No fix the portal can run"
    if state.get("category") == "prime" or state.get("kind") == "vmware":
        return "VMware Cloud is read-only from the portal"
    if state.get("group") == "esxi":
        return "ESXi hosts (VMware Cloud) are read-only from the portal"
    if any(DB_WRITE.search(str(c)) for c in _commands(state)):
        return "It changes a database directly (SQL, *-manage, reset-state): an operator runs it"
    return ""


def _commands(state):
    return [str(c) for c in (state or {}).get("commands") or []] + [str(c) for i in (state or {}).get("items") or []
                                                                    for c in i.get("commands") or []]


def item_size(item):
    """The size of an item of a fix (the flavor RAM of an instance to migrate, MiB), or None."""
    size = (item or {}).get("size")
    if isinstance(size, (int, float)) and not isinstance(size, bool):
        return size
    m = re.search(r"^(live|cold)-migrate .* ram (\d+)\b", " ".join(str(c) for c in (item or {}).get("commands") or []))
    return int(m.group(2)) if m else None   # a result made before the items had their size


def _size_text(item):
    if (item or {}).get("size_text"):
        return str(item["size_text"])
    size = item_size(item)
    return "" if size is None else f"{size / 1024:g} GiB"


def _item_key(item):
    """The same item in a newer result of the check: its operation and what it acts on (an instance ID)."""
    words = str(((item or {}).get("commands") or [""])[0]).split()
    return " ".join(words[:2]) if len(words) >= 2 else str((item or {}).get("label") or "")


def ordered(items, order):
    """[(index, item)] of the items that can run, in the order of the action (ties as listed; unsized ones last)."""
    runnable = [(i, it) for i, it in enumerate(items or []) if it.get("commands") and not it.get("disabled") and not it.get("manual")]
    if order not in ("smallest", "largest"):
        return runnable
    sized = [x for x in runnable if item_size(x[1]) is not None]
    sized.sort(key=lambda x: item_size(x[1]), reverse=order == "largest")
    return sized + [x for x in runnable if item_size(x[1]) is None]


def _phases(cfg):
    """(which, fix key, title, order, at most) of an automatic action: its fix, then its Then fix (when it has one)."""
    out = [("fix", cfg["fix"], cfg["title"], cfg.get("order") or "listed", int(cfg.get("max_items") or 1))]
    t = cfg.get("then") or {}
    if t.get("fix"):
        out.append(("then", t["fix"], t["title"], t.get("order") or "listed", int(t.get("max_items") or 1)))
    return out


def _matches(x, key, title):
    return x["key"] == key or fix_shape(x["title"]) == fix_shape(title)   # the same fix for another volume or host


def _pick(cfg, offered, items):
    """What an automatic action runs next from a result: its fix while it has something left (an item not run yet, or
    the same fix for another volume or host not run yet by this action, up to its maximum), then its Then fix.
    Returns (offered fix, which, items left or None)."""
    done_items = {i.get("key") for i in items if i.get("key")}
    done = {i.get("done") for i in items if i.get("done")}
    for which, key, title, order, limit in _phases(cfg):
        if sum(1 for i in items if i.get("which", "fix") == which) >= limit:
            continue
        for x in offered:
            if not _matches(x, key, title):
                continue
            st = x["state"] or {}
            if st.get("selectable"):
                rest = [y for y in ordered(st.get("items"), order) if _item_key(y[1]) not in done_items]
                if rest:
                    return x, which, rest
            elif str(st.get("target") or x["key"]) not in done and not st.get("manual"):   # manual: only an operator
                return x, which, None
    return None, "", None


def _plan(cfg, offered):
    """Observe only: everything the action would run from this result, in its order: [(offered fix, which, item)]."""
    out = []
    for which, key, title, order, limit in _phases(cfg):
        picked = 0
        for x in offered:
            if picked >= limit or not _matches(x, key, title):
                continue
            st = x["state"] or {}
            if st.get("selectable"):
                for y in ordered(st.get("items"), order)[:limit - picked]:
                    out.append((x, which, y))
                    picked += 1
            elif not st.get("manual"):   # a fix only an operator runs (LUN copy guard)
                out.append((x, which, None))
                picked += 1
    return out


def _seen_row(r):
    return {"key": r["key"], "check_id": r["check_id"], "title": r["title"], "eligible": bool(r["eligible"]), "reason": r["reason"] or "",
            "impact": r["impact"] or "", "items": bool(r["items"]), "sized": bool(r["sized"]), "noun": r["noun"] or "", "kind": r["kind"] or "",
            "run_id": r["run_id"], "seen": r["seen"]}


def fixes_seen(rule_id):
    """The fixes the results of a rule offered: eligible (may be an automatic action; reason: why never), impact (why
    it needs the owner's approval), items (ticked items), sized (its items have a size: smallest / largest first)."""
    with _db() as db:
        return [_seen_row(r) for r in db.execute("SELECT * FROM wi_alert_fixes_seen WHERE rule_id = ? ORDER BY check_id, title", (rule_id,))]


def fixes_for(rule_id=None):
    """The fixes an automatic action of a rule can be: those its own results offered, then those other runs of the same
    checks in the portal offered (known: True; one per fix_shape, the newest), so a new rule has them before its first
    alert. rule_id None: a rule not saved yet."""
    own = fixes_seen(rule_id) if rule_id else []
    shapes = {(f["check_id"], fix_shape(f["title"])) for f in own}
    out = list(own)
    for f in sorted(fixes_seen(KNOWN), key=lambda x: x["seen"] or "", reverse=True):
        shape = (f["check_id"], fix_shape(f["title"]))
        if shape not in shapes:
            shapes.add(shape)
            out.append(dict(f, known=True))
    return out


def scan_runs():
    """Note the fixes offered by the runs of the portal since the last pass (rule_id KNOWN): the checks a rule can run
    that have a fix, the newest KNOWN_SCAN runs. Returns the runs read."""
    hook = HOOKS.get("runs_with_fixes")
    ids = [c["id"] for c in checks_for_rules() if c["fix"]]
    if not hook or not ids:
        return 0
    with _db() as db:
        row = db.execute("SELECT value FROM wi_alert_settings WHERE key = 'known_run'").fetchone()
    after = int(row["value"]) if row and str(row["value"]).isdigit() else 0
    records = hook(ids, after, KNOWN_SCAN) or []
    for record in records:
        try:
            _remember_fixes(KNOWN, record)
        except Exception:   # one result the portal cannot read again does not stop the others
            log.exception("Fixes of run %s could not be noted", record.get("id"))
    last = max([after] + [int(r["id"]) for r in records])
    if last != after:
        with _db() as db:
            db.execute("INSERT INTO wi_alert_settings (key, value) VALUES ('known_run', ?) ON CONFLICT(key) DO UPDATE SET "
                       "value = excluded.value", (str(last),))
    return len(records)


# ---------------- presets: the rules of the alerts that may come ----------------
_presets = {"stamp": None, "items": []}


def presets():
    """The presets of alert_presets.yml, read again when the file changes: [{"id", "title", "alertname": [patterns],
    "labels": {label: regex}, "rule": {...}}]. A broken file gives none (logged); the tests check every preset."""
    import yaml
    try:
        st = os.stat(PRESETS_FILE)
        stamp = (st.st_mtime_ns, st.st_size)
        if stamp != _presets["stamp"]:
            with open(PRESETS_FILE, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            _presets.update(stamp=stamp, items=list(data.get("presets") or []))
    except (OSError, ValueError, yaml.YAMLError, AttributeError):
        log.exception("Alert presets %s could not be read", PRESETS_FILE)
        return []
    return _presets["items"]


def preset_for(alertname, labels):
    """The first preset whose alert name pattern and label patterns (regex, full match, any case) fit this alert."""
    name = str(alertname or "").lower()
    labels = labels or {}
    for p in presets():
        if not any(fnmatch.fnmatchcase(name, str(x).lower()) for x in p.get("alertname") or []):
            continue
        if all(re.fullmatch(str(rx), str(labels.get(k, "")), re.I) for k, rx in (p.get("labels") or {}).items()):
            return p
    return None


def preset_list():
    """For the form: [{"id", "title", "alertname", "labels", "help"}]."""
    return [{"id": p["id"], "title": p["title"], "alertname": p.get("alertname") or [], "labels": p.get("labels") or {},
             "help": p.get("help", "")} for p in presets()]


def preset_rule(preset_id=None, event_id=None):
    """The form of a new rule filled from a preset (by its id, or the first that fits a received alert: then its exact
    name), nothing saved: {"preset", "title", "help", "name", "alertname", "matchers", "site", "checks", "notes"}; None
    when no preset fits. An automatic action is the fix of the check seen in a run of the portal whose title holds the
    preset's fix text, observe only; when none was seen yet a note says so."""
    ev = event(event_id) if event_id else None
    if event_id and not ev:
        raise LookupError("No such alert")
    p = (next((x for x in presets() if x["id"] == preset_id), None) if preset_id
         else preset_for(ev["alertname"], ev.get("labels")) if ev else None)
    if not p:
        return None
    rule = p.get("rule") or {}
    known = [f for f in fixes_for(None) if f["eligible"]]
    checks, notes = [], []
    for n, c in enumerate(rule.get("checks") or []):
        item = {"check_id": c["check"], "params": {k: str(v) for k, v in (c.get("params") or {}).items()}}
        a = c.get("action")
        if a:
            want = str(a["fix"]).lower()
            f = next((x for x in known if x["check_id"] == item["check_id"] and want in x["title"].lower()), None)
            t = a.get("then") or {}
            g = next((x for x in known if t and x["check_id"] == item["check_id"] and str(t["fix"]).lower() in x["title"].lower()), None)
            if f:
                item["action"] = {"fix": f["key"], "mode": "observe", "order": a.get("order", "listed") if f["sized"] else "listed",
                                  "max_items": int(a.get("max_items", ACTION_ITEMS)), "measure": int(a.get("measure", n)),
                                  "thresholds": {k: str(v) for k, v in (a.get("thresholds") or {}).items()}}
                if g:
                    item["action"]["then"] = {"fix": g["key"], "order": t.get("order", "listed") if g["sized"] else "listed",
                                              "max_items": int(t.get("max_items", ACTION_ITEMS))}
                elif t:
                    notes.append(f"Check {n + 1}: Then ({t.get('label') or t['fix']}) is listed once this check offered it in a run "
                                 "of the portal; choose it then on Edit rule.")
            else:
                notes.append(f"Check {n + 1}: its automatic action ({a.get('label') or a['fix']}) is listed once this check offered "
                             "it in a run of the portal: run the check once from Checks (Run fix not needed), or save the rule "
                             "and choose it after its first alert.")
        checks.append(item)
    patterns = p.get("alertname") or ["*"]
    name = (ev["alertname"] if ev else rule.get("name") or p["title"])[:80]
    return {"preset": p["id"], "title": p["title"], "help": p.get("help", ""),
            "name": re.sub(r"[^A-Za-z0-9 _.:()/-]", " ", name).strip() or p["id"],
            "alertname": ev["alertname"] if ev else patterns[0],
            "matchers": "\n".join(f"{k}=~{rx}" for k, rx in (p.get("labels") or {}).items()),
            "site": rule.get("site", "{{labels.site}}"), "cooldown": int(rule.get("cooldown", DEFAULT_COOLDOWN)),
            "checks": checks, "notes": notes}


def _offered(record):
    """[{"index", "key", "title", "never", "impact", "state", "action"}] of the recommendations of a run with a fix."""
    out = []
    for i, rec in enumerate((record.get("result") or {}).get("recommendations") or []):
        action = rec.get("action") if isinstance(rec, dict) else None
        if not action:
            continue
        state = HOOKS["fix_state"](record, i, rec, robot(fix=True, openstack=True))
        never = never_reason(state)
        out.append({"index": i, "key": fix_key(record["check_id"], rec), "title": _title(rec.get("text")), "never": never,
                    "impact": "" if never else impact_of(state, action), "state": state, "action": action})
    return out


def _remember_fixes(rule_id, record):
    """Note the fixes of a result of a rule (an administrator makes one the automatic action of its check); returns
    _offered(record)."""
    out = _offered(record)
    for x in out:
        state, items = x["state"] or {}, (x["state"] or {}).get("items") or []
        with _db() as db:
            db.execute("INSERT INTO wi_alert_fixes_seen (rule_id, key, check_id, title, eligible, reason, impact, items, sized, noun, kind, "
                       "run_id, seen) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(rule_id, key) DO UPDATE SET title = excluded.title, "
                       "eligible = excluded.eligible, reason = excluded.reason, impact = excluded.impact, items = excluded.items, "
                       "sized = excluded.sized, noun = excluded.noun, kind = excluded.kind, run_id = excluded.run_id, seen = excluded.seen",
                       (rule_id, x["key"], record["check_id"], x["title"], 0 if x["never"] else 1, x["never"], x["impact"],
                        1 if state.get("selectable") else 0, 1 if any(item_size(i) is not None for i in items) else 0,
                        str(state.get("noun") or ""), str(state.get("kind") or ""), record["id"], _now()))
    return out


# ---------------- settings ----------------
def get_settings():
    """auto_fix: automatic actions run (off: every alert waits for an operator; the checks still run). frozen_sites:
    the sites where automatic changes never run (their checks still run)."""
    with _db() as db:
        rows = {r["key"]: r["value"] for r in db.execute("SELECT key, value FROM wi_alert_settings")}
    return {"auto_fix": rows.get("auto_fix", "1") == "1", "frozen_sites": [s for s in rows.get("frozen_sites", "").split(",") if s]}


def frozen(site):
    return str(site or "").lower() in {s.lower() for s in get_settings()["frozen_sites"]}


def _frozen_sites(value, before):
    """The sites of the setting: known sites (any case, as sites.yml names them); one no longer in sites.yml stays only
    when it was there before."""
    items = value if isinstance(value, list) else str(value or "").split(",")
    known = {s.lower(): s for s in sites.sites()}
    kept = {s.lower(): s for s in before}
    out = []
    for x in items:
        x = str(x or "").strip()
        if not x:
            continue
        name = known.get(x.lower()) or kept.get(x.lower())
        if not name:
            raise ValueError(f"Unknown site {x}")
        if name not in out:
            out.append(name)
    return sorted(out)


def save_settings(data):
    """Returns (before, after)."""
    d = data if isinstance(data, dict) else {}
    before = get_settings()
    auto = "1" if d.get("auto_fix", before["auto_fix"]) else "0"
    sites_ = _frozen_sites(d["frozen_sites"], before["frozen_sites"]) if "frozen_sites" in d else before["frozen_sites"]
    with _db() as db:
        for key, value in (("auto_fix", auto), ("frozen_sites", ",".join(sites_))):
            db.execute("INSERT INTO wi_alert_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                       (key, value))
    return before, get_settings()


# ---------------- alerts received ----------------
EVENT_FIELDS = ("id", "ts", "source", "auth", "client_ip", "fingerprint", "alertname", "status", "starts_at", "value_text", "generator_url",
                "rule_id", "rule_name", "site", "check_id", "state", "outcome", "run_id", "run_status", "fix_id", "fix_title", "fix_status",
                "verify_run_id", "verify_status", "resolved", "ignored", "check_n", "action_id")


def _event_row(r):
    item = {k: r[k] for k in EVENT_FIELDS}
    item["ignored"] = bool(item["ignored"])
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


RESOLVED_SQL = "(status = 'resolved' OR state = 'resolved' OR resolved IS NOT NULL)"


def events(limit=50, offset=0, q="", site="", state=""):
    """The alerts received, newest first. No state: only the alerts still firing (the default view, so resolved and
    ignored ones do not pile up); "all": every alert but the ignored ones; "resolved": the resolved ones; "ignored":
    only the ones their source ignores; another state: the alerts in it."""
    where, args = ["ignored = ?"], [1 if state == "ignored" else 0]
    if site:
        where.append("site = ?")
        args.append(site)
    if not state:
        where.append(f"NOT {RESOLVED_SQL}")
    elif state == "resolved":
        where.append(RESOLVED_SQL)
    elif state not in ("ignored", "all"):
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
    ids = sorted({e["action_id"] for e in rows if e["action_id"]})
    acts = {a["id"]: brief(a) for a in actions(ids)} if ids else {}
    for e in rows:
        e["action"] = acts.get(e["action_id"])
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
    reason = unreadable(body)
    if reason:
        raise ValueError(reason)
    items = [a for a in body["alerts"][:MAX_ALERTS] if isinstance(a, dict)]
    _count(source["id"], len(items))
    with _db() as db:
        db.execute("UPDATE wi_alert_sources SET last_seen = ?, last_ip = ? WHERE id = ?", (_now(), str(client_ip or "")[:100], source["id"]))
    enabled = rules(enabled_only=True)
    skip = list(source.get("ignore") or [])
    out = {"alerts": len(items), "checks": 0, "ignored": 0}
    for a in items:
        labels = _text_map(a.get("labels"), 64, 512)
        if skip and ignored_by(skip, labels.get("alertname")):   # not needed: not recorded, starts nothing (resolved too)
            out["ignored"] += 1
            continue
        annotations = _text_map(a.get("annotations"), 32, 2000)
        values = a.get("values") if isinstance(a.get("values"), dict) else {}
        base = {"ts": _now(), "source": source["name"], "auth": source.get("auth") or "token", "client_ip": str(client_ip or "")[:100],
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
    if out["ignored"]:
        with _db() as db:
            db.execute("INSERT INTO wi_alert_ignored (source_id, day, n) VALUES (?,?,?) ON CONFLICT(source_id, day) DO UPDATE SET "
                       "n = n + excluded.n", (source["id"], _now()[:10], out["ignored"]))
    return out


def _checks_for(r, alert, base, client_ip):
    """The checks of one rule for one firing alert, one row each; returns how many started."""
    fields = dict(base, rule_id=r["id"], rule_name=r["name"])
    try:
        fields["site"] = site_of(r, alert)
    except ValueError as e:
        _insert(dict(fields, state="refused", outcome=f"Not checked: {e}"))
        return 0
    return sum(_check_for(r, n, item, alert, fields, client_ip) for n, item in enumerate(r["checks"]))


def _check_for(r, n, item, alert, fields, client_ip):
    """Check n of a rule for one firing alert; True when it started."""
    site = fields["site"]
    fields = dict(fields, check_id=item["check_id"], check_n=n)
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


# ---------------- after a check, after a fix: automatic actions ----------------
def robot(fix=False, openstack=False):
    """The account the checks and fixes of alerts run as (an operator; fixes only as the automatic action of a rule)."""
    modules = ["wi"] + ([fixes.PERMISSION] if fix else []) + ([fixes.OPENSTACK_PERMISSION] if fix and openstack else [])
    return {"username": ROBOT, "display_name": "Grafana alerts", "role": "operator", "source": "alert", "modules": modules}


def _words(status):
    return STATUS_WORDS.get(status, status or "no result")


def _check_title(check_id):
    try:
        return catalog.get(check_id)["title"]
    except (LookupError, ValueError, KeyError):
        return str(check_id)


def _audit(action, target, detail, client=""):
    if HOOKS.get("audit"):
        try:
            HOOKS["audit"](action, str(target or "")[:200], str(detail or "")[:1000], client or "")
        except Exception:
            log.exception("The activity log could not be written: %s", detail)


ACTION_JSON = ("approval", "measure_raw", "measure_params", "thresholds", "items", "config")


def _action_row(r):
    a = dict(r)
    for k in ACTION_JSON:
        try:
            a[k] = json.loads(a.get(k) or ("[]" if k == "items" else "{}"))
        except ValueError:
            a[k] = [] if k == "items" else {}
    return a


def action(action_id):
    with _db() as db:
        r = db.execute("SELECT * FROM wi_alert_actions WHERE id = ?", (action_id,)).fetchone()
    return _action_row(r) if r else None


def actions(ids):
    if not ids:
        return []
    with _db() as db:
        return [_action_row(r) for r in db.execute(f"SELECT * FROM wi_alert_actions WHERE id IN ({','.join('?' * len(ids))})", list(ids))]


def brief(a):
    """An automatic action on the row of its alert."""
    items = a["items"]
    return {"id": a["id"], "step": a["step"], "stop": a["stop"], "done": sum(1 for i in items if i.get("status") == "ok"), "ran": len(items),
            "observed": sum(1 for i in items if i.get("status") == "observed"), "mode": a.get("mode") or "run",
            "max": a["max_items"] if a["noun"] else 1, "noun": a["noun"], "order": a["order_by"], "fix_id": a["fix_id"],
            "target": a["target"], "title": a["fix_title"], "impact": a["impact"], "outcome": a["outcome"], "started": a["started"],
            "ended": a["ended"]}


def _short(name):
    """A host as the checks name it: the short name (an address as it is), lower case."""
    name = str(name or "").strip().lower()
    return name if re.fullmatch(r"[\d.]+|[0-9a-f:]+", name) else name.split(".")[0]


def _target_key(site, target, check_id, fix):
    """One automatic action at a time per target (a compute, a host); a fix without a target: per site, check and fix."""
    return f"{site}|{_short(target)}" if str(target or "").strip() else f"{site}|{check_id}|{fix}"


def _mentions(text, target):
    short = _short(target)
    return bool(short) and re.search(rf"(?<![\w-]){re.escape(short)}(?![\w-])", str(text or "").lower()) is not None


def _step_text(s):
    rows = " ".join(" ".join(str(c) for c in row) for row in ((s.get("table") or {}).get("rows") or []))
    return " ".join([str(s.get("title") or ""), str(s.get("detail") or ""), rows, " ".join(str(m) for m in s.get("marks") or [])])


def _measured_steps(record, target, params, thresholds):
    """The rated steps of a measuring result that are about the problem of the target: those of the thresholds' topic
    (mem_warn: Memory) when the rule sets thresholds, and, unless the check read only this target (a parameter names
    it), those that name the target."""
    steps = [s for s in (record.get("result") or {}).get("steps") or [] if s.get("status") in ("ok", "warn", "fail")]
    topics = {str(k).split("_")[0].lower() for k in thresholds or {}}
    if topics:
        hit = [s for s in steps if any(t in str(s.get("key") or "").lower() or t in str(s.get("title") or "").lower() for t in topics)]
        steps = hit or steps
    if str(target or "").strip() and not any(_mentions(v, target) for v in (params or {}).values()):
        steps = [s for s in steps if _mentions(_step_text(s), target)]
    return steps


def problem_left(record, target, params, thresholds):
    """Does the measuring result still report the problem of the target: True, False, or None (it could not tell:
    not checked, could not run)."""
    status = record.get("status")
    if status == "ok":
        return False
    if status not in ("warn", "fail"):
        return None
    if not any(s.get("status") in ("warn", "fail") for s in (record.get("result") or {}).get("steps") or []):
        return True   # no rated step to look into: its status says it
    return any(s["status"] in ("warn", "fail") for s in _measured_steps(record, target, params, thresholds))


def measure_text(record, target, params, thresholds):
    """What the measuring result says about the target, short (for the alert and the activity log)."""
    order = {"fail": 0, "warn": 1, "ok": 2}
    steps = sorted(_measured_steps(record, target, params, thresholds), key=lambda s: order.get(s["status"], 3))
    parts = [f"{s.get('title')}: {str(s.get('detail') or '').strip()[:200]}".strip() for s in steps[:2]]
    return "; ".join(parts) or str(record.get("summary") or record.get("error") or "")[:300]


def _check_n(r, ev):
    n = ev.get("check_n")
    if n is not None and 0 <= n < len(r["checks"]) and r["checks"][n]["check_id"] == ev.get("check_id"):
        return n
    return next((i for i, c in enumerate(r["checks"]) if c["check_id"] == ev.get("check_id")), None)   # alerts of before


def _measure_params(r, cfg, ev):
    """The measuring check of an automatic action, its parameters from the alert with the thresholds of the rule, and
    those cleaned (as its runs keep them)."""
    m = r["checks"][cfg["measure"]]
    check = catalog.get(m["check_id"])
    alert = {"labels": ev.get("labels") or {}, "annotations": ev.get("annotations") or {}}
    raw = {k: render(v, alert) for k, v in m["params"].items()}
    raw.update({k: render(v, alert) for k, v in cfg["thresholds"].items()})
    return check, raw, HOOKS["clean"](check, raw, ev["site"])


def _refusal(r, n, cfg, site, state, impact, observe=False):
    """Why the automatic action does not run (now), '' when it may: checked before it starts and before every item. An
    action that only observes changes nothing: the switch, a frozen site and the owner's approval do not stop it (its
    note says what would stop Run: this function with observe False)."""
    if not r or not r["enabled"]:
        return "Its rule was removed or switched off: nothing more runs by itself."
    if n is None or n >= len(r["checks"]) or r["checks"][n].get("action") != cfg:
        return "Its rule changed (the automatic action of this check): nothing more runs by itself."
    if not observe and not get_settings()["auto_fix"]:
        return "Automatic actions are paused (Alerts → Automatic fixes): it waits for an operator."
    if not observe and frozen(site):
        return f"{site} is a site where automatic changes never run (Alerts → Automatic fixes): the check ran, nothing was changed."
    never = never_reason(state)
    if never:
        return f"It never runs by itself: {never}."
    if impact and not observe and not approved(r):
        return (f"Locked: customer-impacting ({impact}); it runs by itself only with the owner's approval recorded on the rule "
                "(Alerts → Rules → Edit).")
    return ""


def _describe(a):
    """The automatic action in one line (activity log)."""
    th = ", ".join(f"{k}={v}" for k, v in a["thresholds"].items())
    ap = a["approval"]
    observe = a.get("mode") == "observe"
    t = (a.get("config") or {}).get("then") or {}
    return (("Observe only (changes nothing): " if observe else "") + a["fix_title"]
            + (f" ({ORDERS.get(a['order_by'], a['order_by'])}, at most {a['max_items']} {a['noun']} per alert)" if a["noun"]
               else f" (at most {a['max_items']} per alert, one volume or host at a time)" if a["max_items"] > 1 else "")
            + (f"; then {t['title'].rstrip('.')} ({ORDERS.get(t['order'], t['order'])}, at most {t['max_items']})" if t else "")
            + f"; stops when {_check_title(a['measure_check'])}" + (f" ({th})" if th else "")
            + f" no longer reports {a['target'] or 'the problem'}"
            + ((f"; customer-impacting in Run mode ({a['impact']})" if observe else
                f"; customer-impacting ({a['impact']}), approved by {ap.get('name') or ap.get('by')}, ticket {ap.get('ticket')}")
               if a["impact"] else ""))


def run_finished(run_id, status):
    """A run ended (modules/wi start_run): the alerts it was started for get its result and may start the automatic
    action of their check; a run measuring for an automatic action decides its next step; the run of the check after
    a fix is noted too."""
    with _db() as db:
        started = [r["id"] for r in db.execute("SELECT id FROM wi_alert_events WHERE run_id = ? AND state = 'checking'", (run_id,))]
        verified = db.execute("SELECT id, action_id FROM wi_alert_events WHERE verify_run_id = ?", (run_id,)).fetchall()
        measured = [r["id"] for r in db.execute("SELECT id FROM wi_alert_actions WHERE measure_run = ? AND step = 'measuring'", (run_id,))]
    for row in verified:
        if row["action_id"]:   # its outcome is the automatic action's
            _set(row["id"], verify_status=status)
            continue
        ev = event(row["id"]) or {}
        _set(row["id"], verify_status=status, outcome=f"Checked: {_words(ev.get('run_status'))}. Fix #{ev.get('fix_id')} "
                                                     f"ran by itself; the check after it: {_words(status)}.")
    for aid in measured:
        try:
            _measured(aid, run_id)
        except Exception:
            log.exception("Automatic action #%s: the measurement (run #%s) could not be used", aid, run_id)
            _fail_safe(aid)
    if not started:
        return
    record = HOOKS["get_run"](run_id) or {}
    for eid in started:
        _set(eid, state="checked", run_status=status, outcome=f"Checked: {_words(status)}.")
        try:
            if record:
                _start_action(event(eid), record)
        except Exception:
            log.exception("Alert %s: the automatic action could not start", eid)


def _start_action(ev, record):
    """After the check of an alert: start the automatic action of that check of the rule, or say on the alert why
    not. True when one started."""
    r = rule(ev["rule_id"]) if ev.get("rule_id") else None
    if not r:
        return False
    offered = _remember_fixes(r["id"], record)
    n = _check_n(r, ev)
    cfg = r["checks"][n].get("action") if n is not None else None
    if not cfg:
        return False
    checked = f"Checked: {_words(record.get('status'))}."
    hit, _which, _rest = _pick(cfg, offered, [])   # its fix (or the same for another host), else its Then fix
    if not hit:
        if record.get("status") in ("fail", "warn"):
            names = " / ".join(t for _w, _k, t, _o, _m in _phases(cfg))
            _set(ev["id"], outcome=f"{checked} The fix of its automatic action ({names}) is not in this result, or has nothing "
                                   "that can run by itself: nothing ran.")
        return False
    state = hit["state"] or {}
    observe = mode_of(cfg) == "observe"   # what Run would refuse is only noted when it decides
    reason = _refusal(r, n, cfg, ev["site"], state, hit["impact"], observe)
    if not reason and not observe and not state.get("available"):
        reason = f"The automatic action cannot run: {state.get('reason') or 'no fix'}"
    measure = None
    if not reason:
        try:
            measure = _measure_params(r, cfg, ev)
        except (ValueError, LookupError) as e:
            reason = f"The stop condition cannot be measured: {e}"
    if reason:
        _set(ev["id"], outcome=f"{checked} {reason}")
        return False
    mcheck, mraw, mparams = measure
    target = str((hit.get("action") or {}).get("scope") or state.get("target") or "")   # a pool, a compute, a host
    if (mcheck["id"] == record["check_id"] and (record.get("params") or {}) == mparams
            and problem_left(record, target, mparams, cfg["thresholds"]) is False):
        _set(ev["id"], outcome=f"{checked} The result is its own measurement and reports no problem of {target or 'the target'}: "
                               "the automatic action has nothing to do.")
        return False
    key = _target_key(ev["site"], target, record["check_id"], cfg["fix"])
    note, aid = "", None
    with _fix_lock:
        with _db() as db:
            busy = db.execute("SELECT id, source_run, rule_name FROM wi_alert_actions WHERE target_key = ? AND step != 'done' "
                              "ORDER BY id LIMIT 1", (key,)).fetchone()
            # the limits are of changes: an action that observes is not limited by them and does not count for them
            again = not observe and AUTO_AGAIN_HOURS > 0 and db.execute(
                "SELECT id, started FROM wi_alert_actions WHERE rule_id = ? AND target_key = ? AND fix_key = ? AND items != '[]' "
                "AND mode = 'run' AND started >= ? ORDER BY id DESC LIMIT 1",
                (r["id"], key, cfg["fix"], _ago(AUTO_AGAIN_HOURS * 60))).fetchone()
            hour = 0 if observe else db.execute("SELECT COUNT(*) FROM wi_alert_actions WHERE rule_id = ? AND mode = 'run' AND started >= ?",
                                                (r["id"], _ago(60))).fetchone()[0]
            if busy:
                note = (f"{target or 'Its target'} is already being handled by run #{busy['source_run']} (automatic action "
                        f"#{busy['id']} of rule {busy['rule_name']}): this alert starts nothing more.")
            elif again:
                note = (f"The alert came back after automatic action #{again['id']} at {_hm(again['started'])}: it waits for an "
                        f"operator (by itself once every {AUTO_AGAIN_HOURS} hours on the same target).")
            elif hour >= r["auto_per_hour"]:
                note = f"{r['auto_per_hour']} automatic actions of this rule in the last hour: it waits for an operator."
            else:
                aid = db.execute(
                    "INSERT INTO wi_alert_actions (event_id, rule_id, rule_name, check_n, check_id, site, target, target_key, fix_key, "
                    "fix_title, kind, noun, impact, approval, order_by, max_items, measure_check, measure_raw, measure_params, thresholds, "
                    "config, step, source_run, items, started, client_ip, mode) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (ev["id"], r["id"], r["name"], n, record["check_id"], ev["site"], target, key, cfg["fix"], cfg["title"],
                     str(state.get("kind") or ""), str(state.get("noun") or "") if state.get("selectable") else "", hit["impact"],
                     json.dumps(r["approval"] if hit["impact"] and not observe else {}, sort_keys=True), cfg["order"], cfg["max_items"],
                     mcheck["id"], json.dumps(mraw, sort_keys=True), json.dumps(mparams, sort_keys=True),
                     json.dumps(cfg["thresholds"], sort_keys=True), json.dumps(cfg, sort_keys=True), "measuring", record["id"], "[]",
                     _now(), ev.get("client_ip") or "", mode_of(cfg))).lastrowid
    if note:
        _set(ev["id"], outcome=f"{checked} {note}")
        return False
    a = action(aid)
    _set(ev["id"], action_id=aid, outcome=f"{checked} Automatic action #{aid}{' (observe only)' if observe else ''} started: it measures first.")
    _audit("wi.alert_action", target or record["check_id"],
           f"Automatic action #{aid} of rule {r['name']} (alert #{ev['id']}, run #{record['id']}) on {ev['site']} {target}: "
           f"started. {_describe(a)}", a["client_ip"])
    _measure(a, ev["ts"], record)
    return True


def _measure(a, since, record=None):
    """Measure for an automatic action: the given result when it is the measuring check with the same parameters (the
    acting check's own result, or the check after its last fix), else a run of the measuring check started at or after
    since (one running is waited for, else one starts)."""
    if record and record.get("id") and record.get("check_id") == a["measure_check"] and (record.get("params") or {}) == a["measure_params"]:
        run_id = record["id"]
    else:
        try:
            run_id = HOOKS["measure"](a["site"], catalog.get(a["measure_check"]), a["measure_raw"], a["client_ip"], since)
        except (ValueError, LookupError) as e:
            return _stop(a, "measure", f"The measuring check {_check_title(a['measure_check'])} could not run ({e}): an operator decides.")
    with _db() as db:
        db.execute("UPDATE wi_alert_actions SET step = 'measuring', measure_run = ? WHERE id = ?", (run_id, a["id"]))
    rec = HOOKS["get_run"](run_id) or {}
    if rec.get("status") and rec["status"] != "running":   # it has ended already (the acting result, a fast run)
        _measured(a["id"], run_id)
    return True


def _measured(aid, run_id):
    """The measuring run of an automatic action ended: decide (once: the action is claimed)."""
    with _fix_lock, _db() as db:
        claimed = db.execute("UPDATE wi_alert_actions SET step = 'deciding' WHERE id = ? AND step = 'measuring' AND measure_run = ?",
                             (aid, run_id)).rowcount
    if claimed:
        _decide(action(aid), HOOKS["get_run"](run_id) or {})


def _source(a, record):
    """The newest finished result of the acting check to take the next item from: the measuring result when it is that
    check with the same parameters, else the check after the last fix, else the result the action started from."""
    first = HOOKS["get_run"](a["source_run"]) or {}
    cands = []
    if record.get("check_id") == a["check_id"] and (record.get("params") or {}) == (first.get("params") or {}):
        cands.append(record)
    last = a["items"][-1] if a["items"] else {}
    if last.get("verify"):
        cands.append(HOOKS["get_run"](last["verify"]) or {})
    cands.append(first)
    return next((c for c in cands if c.get("id") and c.get("status") not in (None, "running", "error", "unknown") and c.get("result")), first)


def _decide(a, record):
    """The measuring check of an automatic action ended: stop (the problem is gone, the maximum is used, it could not
    tell, something changed), or run the next item."""
    measured = f"{_check_title(a['measure_check'])} (run #{record.get('id', a['measure_run'])})"
    seen = measure_text(record, a["target"], a["measure_params"], a["thresholds"])
    measured = (measured + (f": {seen}" if seen else "")).rstrip(". ")
    left = problem_left(record, a["target"], a["measure_params"], a["thresholds"])
    target = a["target"] or "the target"
    if left is None:
        return _stop(a, "measure", f"{measured}. The measuring check could not tell ({_words(record.get('status'))}): an operator decides.")
    if not left:
        return _stop(a, "gone", f"{measured}. The problem of {target} is gone" + (": stopped." if a["items"] else ": nothing to do."))
    cfg = a["config"]
    phases = _phases(cfg)
    if all(sum(1 for i in a["items"] if i.get("which", "fix") == w) >= m for w, _k, _t, _o, m in phases):
        limit = phases[0][4]
        used = ("; ".join(f"{t.rstrip('.')}: at most {m}" for _w, _k, t, _o, m in phases) if len(phases) > 1 else
                f"the maximum of {limit} {a['noun']} per alert is used up" if a["noun"] else
                "the fix ran once" if limit == 1 else f"the fix ran {limit} times")
        return _stop(a, "max", f"{measured}. Still a problem, and " + (f"the maximum per alert is used up ({used})" if len(phases) > 1 else used)
                     + ": an operator continues.")
    r = rule(a["rule_id"])
    src = _source(a, record)
    offered = _offered(src) if src else []
    if a.get("mode") == "observe":
        plan = _plan(cfg, offered)
        if not plan:
            return _stop(a, "no-fix", f"{measured}. Still a problem, but run #{src.get('id')} offers nothing of the action that can run "
                                      "by itself: an operator looks.")
        return _observe(a, r, src, plan, measured)
    hit, which, rest = _pick(cfg, offered, a["items"])
    if not hit:
        if any(_matches(x, k, t) for x in offered for _w, k, t, _o, _m in phases):
            more = f"no further {a['noun']} can run" if a["noun"] and len(phases) == 1 else "nothing more of the action can run by itself"
            return _stop(a, "no-items", f"{measured}. Still a problem, but {more}: an operator continues.")
        return _stop(a, "no-fix", f"{measured}. Still a problem, but run #{src.get('id')} offers the fix no longer: an operator looks.")
    state = hit["state"] or {}
    observe = a.get("mode") == "observe"
    reason = _refusal(r, a["check_n"], a["config"], a["site"], state, hit["impact"], observe)
    if not reason and not observe and not state.get("available"):
        reason = f"The fix cannot run now: {state.get('reason') or 'no fix'}"
    if reason:
        return _stop(a, "refused", f"{measured}. {reason}")
    return _launch(a, r, src, hit, which, state, rest[0] if rest else None, measured)


def _entry(a, src, it, status, hit=None, which="fix"):
    """An item of an automatic action (it ran, or would run): what it acts on, its size, its fix (which: its fix or its
    Then fix; done: the target of a fix without items, e.g. the volume whose snapshots it deletes)."""
    words = str((it.get("commands") or [""])[0]).split() if it else []
    st = (hit or {}).get("state") or {}
    target = "" if it else str(st.get("target") or "")
    title = str((hit or {}).get("title") or a["fix_title"]).rstrip(".")
    return {"key": _item_key(it) if it else "", "label": (it or {}).get("label") or (f"{title} ({target})" if target else title),
            "size": item_size(it) if it else None, "size_text": _size_text(it) if it else "", "op": words[0] if words else "",
            "fix_id": None, "run_id": src.get("id"), "status": status, "verify": None, "which": which,
            "done": "" if it else (target or str((hit or {}).get("key") or "")), "fix": (hit or {}).get("key") or a["fix_key"]}


def _destinations(src):
    """What the acting result says about the destinations now (compute-drain: how many computes are under the limit,
    which), '' when it has no such step. The destination of each item is chosen when it runs (wi_ops)."""
    step = next((s for s in (src.get("result") or {}).get("steps") or [] if s.get("key") == "destinations"), None)
    if not step:
        return ""
    table = step.get("table") or {}
    cols, rows = table.get("columns") or [], table.get("rows") or []
    under = [str(x[0]) for x in rows if cols and str(cols[-1]).startswith("Under") and x and x[-1] == "yes"]
    return (f"{step.get('title')}: {_title(step.get('detail'))}".rstrip(". ") + "."
            + (f" Under the limit now: {', '.join(under[:8])}{f' (+{len(under) - 8})' if len(under) > 8 else ''}." if under else ""))


def _observe(a, r, src, plan, measured):
    """Observe only: record what Run would do now (its fix: the items in its order, or the same fix for each volume or
    host, at most its maximum; then its Then fix) and why Run would stop now, then stop. Nothing is started."""
    first = plan[0][0]
    state = first["state"] or {}
    would = _refusal(r, a["check_n"], a["config"], a["site"], state, first["impact"])
    if not would and not state.get("available"):
        would = f"The fix cannot run now: {state.get('reason') or 'no fix'}"
    entries = [_entry(a, src, y[1] if y else None, "observed", x, w) for x, w, y in plan]
    with _db() as db:
        db.execute("UPDATE wi_alert_actions SET items = ? WHERE id = ?", (json.dumps(a["items"] + entries), a["id"]))
    a = dict(a, items=a["items"] + entries)
    check, target = _check_title(a["measure_check"]), a["target"] or "the target"
    name = lambda k, e: f"{k}. {str(e['label']).split(' -> ')[0]}" + (f" ({e['size_text']})" if e["size_text"] else "")   # noqa: E731
    sized = [y for _x, _w, y in plan if y]
    if len(plan) == 1 and not sized:
        what = (f"it would run the fix once ({entries[0]['label']}). In Run mode {check} measures again after it, and an "
                "operator continues when the problem is still there")
    elif all(w == "fix" for _x, w, _y in plan) and len(sized) == len(plan):
        rest = ordered((first["state"] or {}).get("items"), a["order_by"])
        more = f" of {len(rest)} that can run" if len(rest) > len(entries) else ""
        what = (f"it would run {len(entries)} {a['noun']}{more}, {ORDERS.get(a['order_by'], a['order_by'])}: "
                f"{', '.join(name(k, e) for k, e in enumerate(entries, 1))}. In Run mode they run one at a time, {check} measures "
                f"again after each, and it stops as soon as {target} is no longer reported (it may run fewer)")
    else:
        parts = []
        for which, _key, title, order, _limit in _phases(a["config"]):
            es = [e for e in entries if e["which"] == which]
            if es:
                parts.append(f"{title.rstrip('.')} ({len(es)}, {ORDERS.get(order, order)}): " + ", ".join(name(k, e) for k, e in enumerate(es, 1)))
        what = ("it would run " + "; then ".join(parts) + f". In Run mode one at a time, {check} measures again after each, and it "
                f"stops as soon as {target} is no longer reported (it may run fewer)")
    dest = _destinations(src) if sized else ""
    return _stop(a, "observed", f"{measured}. Observe only, {what}."
                 + (f" {dest} The destination of each is chosen when it runs, with the guards of Run fix." if dest else "")
                 + (f" In Run mode now: {would}" if would else "") + " Nothing was changed.")


def _launch(a, r, src, hit, which, state, item, measured):
    """Run ONE item of the fix (or the whole fix), as "grafana", with the confirmation the owner's approval stands for."""
    if a.get("mode") == "observe":   # never: an action that observes changes nothing (_decide records it instead)
        return _stop(a, "error", f"{measured}. An action that only observes cannot start a fix: nothing was changed.")
    index, limit = hit["index"], next(m for w, _k, _t, _o, m in _phases(a["config"]) if w == which)
    noun = str(state.get("noun") or "items") if state.get("selectable") else ""
    body, label, it = {}, str(hit["title"]), item[1] if item else {}
    if item:
        body["selected"] = [item[0]]
        if it.get("delete"):
            body["confirm"] = f"1 {state.get('noun') or 'items'}"
        label = it.get("label") or label
    elif state.get("risk") == "high":
        body["confirm"] = str(state.get("target") or "")
    k, ap = sum(1 for i in a["items"] if i.get("which", "fix") == which) + 1, a["approval"]
    note = (f"alert rule {r['name']} (alert #{a['event_id']}), automatic action #{a['id']}" + (", then" if which == "then" else "")
            + (f", {noun} {k} of at most {limit}" if item else f", fix {k} of at most {limit}" if limit > 1 else "")
            + (f"; approved by {ap.get('name') or ap.get('by')}, ticket {ap.get('ticket')}" if a["impact"] else ""))
    try:
        fix_id = HOOKS["start_fix"](src, index, robot(fix=True, openstack=state.get("kind") == "openstack"), a["client_ip"], note, body)
    except (ValueError, LookupError) as e:
        return _stop(a, "error", f"{measured}. {label} could not start: {e}")
    entry = dict(_entry(a, src, it if item else None, "running", hit, which), fix_id=fix_id)
    with _db() as db:
        db.execute("UPDATE wi_alert_actions SET step = 'fixing', fix_id = ?, items = ? WHERE id = ?",
                   (fix_id, json.dumps(a["items"] + [entry]), a["id"]))
    _set(a["event_id"], fix_id=fix_id, fix_key=hit["key"], fix_title=hit["title"], fix_status="running")
    _tell(a, f"Automatic action #{a['id']}: {measured}. Fix #{fix_id} running"
             + (f": {noun} {k} of at most {limit}, {label}." if item else f": {entry['label']}"))
    return True


def _tell(a, text):
    ev = event(a["event_id"]) or {}
    _set(a["event_id"], outcome=f"Checked: {_words(ev.get('run_status'))}. {text}"[:1500])


def _done_text(a):
    items = a["items"]
    if a.get("mode") == "observe":
        seen = [i for i in items if i.get("status") == "observed"]
        return ("observe only" + (f", would run {len(seen)} {a['noun']}" if seen and a["noun"] else ", would run the fix" if seen else "")
                + ", nothing changed")
    if not items:
        return "nothing ran"
    ok = [i for i in items if i.get("status") == "ok"]
    if not a["noun"] and len(items) == 1:
        return f"fix #{items[0]['fix_id']} " + ("ran" if ok else str(items[0].get("status") or "running"))
    if not ok or not any(i.get("size_text") for i in ok):
        return f"{len(ok)} of {len(items)} fixes done" + (": " + ", ".join(str(i.get("label") or "") for i in ok[:10]) if ok else "")
    verb = OPS_DONE.get(ok[0].get("op") if ok else "", "done")
    names = ", ".join(str(i.get("label") or "").split(" -> ")[0] + (f" ({i['size_text']})" if i.get("size_text") else "") for i in ok[:10])
    return f"{len(ok)} {a['noun']} {verb}" + (f", {ORDERS.get(a['order_by'], a['order_by'])}: {names}" if ok else "")


def _stop(a, code, text):
    """The automatic action ends: what it did and why it stopped, on the action, its alert and in the activity log."""
    outcome = f"Automatic action #{a['id']} ({_done_text(a)}): {text}"[:2000]
    with _db() as db:
        db.execute("UPDATE wi_alert_actions SET step = 'done', stop = ?, outcome = ?, ended = ? WHERE id = ?", (code, outcome, _now(), a["id"]))
    _tell(a, outcome)
    _audit("wi.alert_action", a["target"] or a["check_id"], f"Rule {a['rule_name']} (alert #{a['event_id']}) on {a['site']}: {outcome}",
           a["client_ip"])
    return False


def _fail_safe(aid):
    """An error of the portal in the loop: the action stops (its target is free again for an operator)."""
    try:
        a = action(aid)
        if a and a["step"] != "done":
            _stop(a, "error", "An error of the portal (see its log): nothing more runs by itself, an operator looks.")
    except Exception:
        log.exception("Automatic action #%s could not be stopped", aid)


def fix_finished(fix_id, status, error="", verify_run_id=None):
    """A fix ended (modules/wi _fix_finished): the alert that started it gets its result and the check after it; its
    automatic action measures again, or stops at the first failure."""
    ended = _now()
    with _db() as db:
        rows = db.execute("SELECT id, action_id FROM wi_alert_events WHERE fix_id = ?", (fix_id,)).fetchall()
    for row in rows:
        _set(row["id"], fix_status=status, **({"verify_run_id": verify_run_id} if verify_run_id else {}))
        if status != "ok" and not row["action_id"]:
            ev = event(row["id"]) or {}
            _set(row["id"], outcome=(ev.get("outcome") or "") + f" The fix failed: {error}"[:400])
    with _fix_lock, _db() as db:
        mine = [r["id"] for r in db.execute("SELECT id FROM wi_alert_actions WHERE fix_id = ? AND step = 'fixing'", (fix_id,)).fetchall()]
        claimed = [aid for aid in mine
                   if db.execute("UPDATE wi_alert_actions SET step = 'deciding' WHERE id = ? AND step = 'fixing'", (aid,)).rowcount]
    for aid in claimed:
        try:
            _fixed(action(aid), fix_id, status, error, verify_run_id, ended)
        except Exception:
            log.exception("Automatic action #%s: the end of fix #%s could not be used", aid, fix_id)
            _fail_safe(aid)


def _fixed(a, fix_id, status, error, verify, ended):
    for it in a["items"]:
        if it.get("fix_id") == fix_id:
            it.update(status=status, verify=verify)
    with _db() as db:
        db.execute("UPDATE wi_alert_actions SET items = ? WHERE id = ?", (json.dumps(a["items"]), a["id"]))
    last = a["items"][-1] if a["items"] else {"label": a["fix_title"]}
    if status != "ok":
        why = "was cancelled by an operator" if status == "cancelled" else f"failed: {str(error).rstrip('. ')}" if error else str(status)
        return _stop(a, "failed", f"Fix #{fix_id} ({last.get('label')}) {why}. Stopped at the first failure: nothing more runs by itself.")
    return _measure(a, ended, HOOKS["get_run"](verify) if verify else None)


# ---------------- metrics: the way back to an operator ----------------
# The portal sends nothing itself. The SRE team's Prometheus reads these (GET /runbook/api/alerts/metrics with the token of a
# source), their Grafana alerts on them, and AlertHub forwards that alert to the operators like any other alert.
NEED_OPERATOR = ("failed", "error", "refused", "measure", "no-fix", "no-items", "max", "restart")   # stops an operator takes over
METRIC_WINDOWS = (("1h", 60), ("24h", 24 * 60))


def _label(value):
    """A Prometheus label value: backslash, double quote and line feed escaped."""
    return str(value or "").replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")[:120]


def metrics():
    """Prometheus text format 0.0.4 of the alerts and their automatic actions: running now, ended per window (site, rule,
    mode, how it stopped), ended in Run mode with a stop an operator takes over (per site, every site listed), alerts
    received per window and state, the switch and the frozen sites, and the fix requests waiting for an engineer's review
    (per site). Counts only: no target, no outcome text."""
    known = sorted(set(sites.sites()))
    with _db() as db:
        running = {r["site"]: r["n"] for r in db.execute("SELECT site, COUNT(*) AS n FROM wi_alert_actions WHERE step != 'done' GROUP BY site")}
        ended, need, received = {}, {}, {}
        marks = ",".join("?" * len(NEED_OPERATOR))
        for window, minutes in METRIC_WINDOWS:
            since = _ago(minutes)
            ended[window] = db.execute("SELECT site, rule_name, mode, stop, COUNT(*) AS n FROM wi_alert_actions WHERE step = 'done' "
                                       "AND ended >= ? GROUP BY site, rule_name, mode, stop ORDER BY site, rule_name, mode, stop",
                                       (since,)).fetchall()
            need[window] = {r["site"]: r["n"] for r in db.execute(
                f"SELECT site, COUNT(*) AS n FROM wi_alert_actions WHERE step = 'done' AND mode = 'run' AND stop IN ({marks}) "
                "AND ended >= ? GROUP BY site", (*NEED_OPERATOR, since))}
            received[window] = db.execute("SELECT COALESCE(site, '') AS site, state, COUNT(*) AS n FROM wi_alert_events "
                                          "WHERE ts >= ? AND ignored = 0 GROUP BY site, state ORDER BY site, state", (since,)).fetchall()
    settings_ = get_settings()
    out = []

    def metric(name, kind, text, rows):
        out.append(f"# HELP {name} {text}")
        out.append(f"# TYPE {name} {kind}")
        for labels, value in rows:
            inner = ",".join(f'{k}="{_label(v)}"' for k, v in labels.items())
            out.append(f"{name}{{{inner}}} {value}" if inner else f"{name} {value}")

    metric("ops_alert_actions_running", "gauge", "Automatic actions of alert rules running now.",
           [({"site": s}, running.get(s, 0)) for s in sorted(set(known) | set(running))])
    metric("ops_alert_actions_need_operator", "gauge",
           "Automatic actions in Run mode that ended in the window with a stop an operator takes over (failed, refused, could not measure, maximum used, ...).",
           [({"window": w, "site": s}, need[w].get(s, 0)) for w, _m in METRIC_WINDOWS for s in sorted(set(known) | set(need[w]))])
    metric("ops_alert_actions_ended", "gauge", "Automatic actions that ended in the window, by site, rule, mode and how they stopped.",
           [({"window": w, "site": r["site"], "rule": r["rule_name"], "mode": r["mode"] or "run", "stop": r["stop"]}, r["n"])
            for w, _m in METRIC_WINDOWS for r in ended[w]])
    metric("ops_alerts_received", "gauge", "Alerts received in the window (not the ignored ones), by site and state (no-rule: no rule matched).",
           [({"window": w, "site": r["site"], "state": r["state"]}, r["n"]) for w, _m in METRIC_WINDOWS for r in received[w]])
    metric("ops_alert_automatic_actions_paused", "gauge", "1 when every automatic action is paused (Alerts, Automatic fixes).",
           [({}, 0 if settings_["auto_fix"] else 1)])
    metric("ops_alert_site_frozen", "gauge", "1 for a site where automatic changes never run.",
           [({"site": s}, 1 if s in settings_["frozen_sites"] else 0) for s in sorted(set(known) | set(settings_["frozen_sites"]))])
    # the fixes operators asked for that wait for an engineer (reviews.py): Grafana alerts on them, AlertHub tells the engineers
    waiting = reviews.waiting_counts()
    metric("ops_fix_reviews_waiting", "gauge",
           "Fix requests whose pre-check passed and that wait for an engineer's review (Runbook Automation, Fix reviews), by site.",
           [({"site": s}, waiting.get(s, 0)) for s in sorted(set(known) | set(waiting))])
    for provider in EXTRA_METRICS:   # other modules on the same scrape (Status: the status of every product of every site)
        try:
            for name, kind, text, samples in provider():
                metric(name, kind, text, samples)
        except Exception:
            log.exception("Metrics of %s could not be read", getattr(provider, "__module__", provider))
    return "\n".join(out) + "\n"

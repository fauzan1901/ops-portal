"""Findings of Tenable kept by the portal (remediation tracking), the syncs that brought them and the trend per site.

Tables (portal database, settings.DB_PATH):
  nessus_findings  one row per asset uuid + plugin id + port + protocol, as the last sync saw it (state OPEN, REOPENED or
                   FIXED with first_found / last_found / last_fixed from Tenable, state_changed = the sync that saw the
                   state change), the site of its address (scope.site_of_ip; mapped again when sites.yml changes)
  nessus_syncs     every sync: started, finished, status (running / ok / error), who, since, counts, error
  nessus_trend     after every successful sync, per site and severity: active (OPEN + REOPENED), reopened, and fixed in
                   the last 30 days
  nessus_meta      the networks the site column was computed with
For "How to fix it" (remedy.py) every finding also keeps what the export says about the plugin and the asset: see_also
(links, one per line), has_patch, patch_date, exploit (1 / 0 / unknown), description (4 KB), plugin_type (local or remote
check), os (the first operating system of the asset), fqdn. Columns added to an older table by init() (ALTER TABLE).
The site of a finding: the site whose network (sites.yml tenable.networks) holds its address ("network 10.248.0.0/24");
when no network does, the site whose tenable.scanner / tenable.groups names the scanner that found the host
("scanner tenable-scanner-dcb", the scan of the finding: scan_uuid / schedule_uuid of the export, mapped to its scanner
through nessus_scanners, which the scan list of Tenable fills); else no site ("Other", e.g. Tenable's cloud scanners).
One site per address: when several scanners of different sites found a host, the site with most of its findings.
"""
import contextlib
import csv
import datetime
import io
import ipaddress
import os
import sqlite3

import settings

from . import remedy, scope

SEVERITIES = ("info", "low", "medium", "high", "critical")
RANK = {s: i for i, s in enumerate(SEVERITIES)}
STATES = ("OPEN", "REOPENED", "FIXED")
ACTIVE = ("OPEN", "REOPENED")
STATE_FILTERS = {"active": ACTIVE, "open": ("OPEN",), "reopened": ("REOPENED",), "fixed": ("FIXED",), "all": STATES}
OTHER = "(other)"   # the site filter for findings outside every site's networks (stored as site "")
OUTPUT_MAX = 8 * 1024
FIXED_DAYS = 30
TREND_KEEP = 400   # syncs kept in the trend (6-hourly: about 100 days)
MAX_ROWS = 5000    # rows of one list in the browser (the CSV has every row)
DESCRIPTION_MAX = 4 * 1024
EXTRA_COLUMNS = (("see_also", "TEXT NOT NULL DEFAULT ''"), ("has_patch", "INTEGER"), ("patch_date", "TEXT NOT NULL DEFAULT ''"),
                 ("exploit", "INTEGER"), ("description", "TEXT NOT NULL DEFAULT ''"), ("plugin_type", "TEXT NOT NULL DEFAULT ''"),
                 ("os", "TEXT NOT NULL DEFAULT ''"), ("fqdn", "TEXT NOT NULL DEFAULT ''"),
                 # the scan that found it (export "scan"), its scanner and how the finding got its site
                 ("scan_uuid", "TEXT NOT NULL DEFAULT ''"), ("schedule_uuid", "TEXT NOT NULL DEFAULT ''"),
                 ("scan_started", "TEXT NOT NULL DEFAULT ''"), ("scanner", "TEXT NOT NULL DEFAULT ''"),
                 ("site_via", "TEXT NOT NULL DEFAULT ''"))
SEEN_PREFIX = 24   # "networks seen": the /24 of every host a site's scanner found


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


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def utc(value):
    """A Tenable date (ISO with Z or an offset, or epoch seconds) as YYYY-MM-DDTHH:MM:SSZ, so dates compare as text."""
    if value in (None, ""):
        return ""
    try:
        if isinstance(value, (int, float)) or str(value).isdigit():
            d = datetime.datetime.fromtimestamp(int(value), datetime.timezone.utc)
        else:
            d = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            d = d if d.tzinfo else d.replace(tzinfo=datetime.timezone.utc)
        return d.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OverflowError, OSError):
        return ""


def days_ago(days):
    return (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def init():
    with _db() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS nessus_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT, asset_uuid TEXT NOT NULL, plugin_id INTEGER NOT NULL,
            port INTEGER NOT NULL DEFAULT 0, protocol TEXT NOT NULL DEFAULT '', service TEXT NOT NULL DEFAULT '',
            ipv4 TEXT NOT NULL DEFAULT '', hostname TEXT NOT NULL DEFAULT '', site TEXT NOT NULL DEFAULT '',
            plugin_name TEXT NOT NULL DEFAULT '', plugin_family TEXT NOT NULL DEFAULT '', severity TEXT NOT NULL DEFAULT '',
            severity_rank INTEGER NOT NULL DEFAULT 0, cvss3 REAL, vpr REAL, cves TEXT NOT NULL DEFAULT '',
            state TEXT NOT NULL, first_found TEXT, last_found TEXT, last_fixed TEXT, synopsis TEXT, solution TEXT,
            output TEXT, state_changed TEXT, updated TEXT, UNIQUE (asset_uuid, plugin_id, port, protocol))""")
        for cols in ("site, state", "ipv4", "plugin_id"):
            db.execute(f"CREATE INDEX IF NOT EXISTS nessus_findings_{cols.split(',')[0]} ON nessus_findings({cols})")
        db.execute("""CREATE TABLE IF NOT EXISTS nessus_syncs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, started TEXT NOT NULL, finished TEXT, status TEXT NOT NULL,
            username TEXT NOT NULL, reason TEXT NOT NULL DEFAULT 'manual', since TEXT, received INTEGER NOT NULL DEFAULT 0,
            new INTEGER NOT NULL DEFAULT 0, updated INTEGER NOT NULL DEFAULT 0, fixed INTEGER NOT NULL DEFAULT 0,
            reopened INTEGER NOT NULL DEFAULT 0, error TEXT, client_ip TEXT)""")
        db.execute("""CREATE TABLE IF NOT EXISTS nessus_trend (
            sync_id INTEGER NOT NULL, ts TEXT NOT NULL, site TEXT NOT NULL, severity TEXT NOT NULL,
            active INTEGER NOT NULL, reopened INTEGER NOT NULL, fixed INTEGER NOT NULL, PRIMARY KEY (sync_id, site, severity))""")
        db.execute("CREATE TABLE IF NOT EXISTS nessus_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        # scan (uuid of the scan, of its schedule, of each run) -> the scanner that ran it, from the scan list of Tenable
        db.execute("CREATE TABLE IF NOT EXISTS nessus_scanners (uuid TEXT PRIMARY KEY, scanner TEXT NOT NULL, updated TEXT NOT NULL)")
        # columns of "How to fix it", added to a table made by an earlier version (idempotent: only the missing ones)
        have = {r[1] for r in db.execute("PRAGMA table_info(nessus_findings)")}
        added = [name for name, _kind in EXTRA_COLUMNS if name not in have]
        for name, kind in EXTRA_COLUMNS:
            if name in added:
                db.execute(f"ALTER TABLE nessus_findings ADD COLUMN {name} {kind}")
        # findings kept before have the new columns empty: the next sync reads the whole window again, once
        if added and db.execute("SELECT 1 FROM nessus_findings LIMIT 1").fetchone():
            db.execute("INSERT OR REPLACE INTO nessus_meta (key, value) VALUES ('full_sync', ?)", (now_iso(),))
        # a sync still "running" in the database ran in a portal that stopped
        db.execute("UPDATE nessus_syncs SET status = 'error', finished = ?, error = 'The portal stopped during the sync' "
                   "WHERE status = 'running'", (now_iso(),))


def full_sync_needed():
    with _db() as db:
        return db.execute("SELECT 1 FROM nessus_meta WHERE key = 'full_sync'").fetchone() is not None


def full_sync_done():
    with _db() as db:
        db.execute("DELETE FROM nessus_meta WHERE key = 'full_sync'")


# ---------------- sites of the stored findings ----------------
def record_scanners(mapping):
    """Remember which scanner ran which scan ({scan, schedule or run uuid: scanner name}); True when it changed (the
    findings are then placed again at the next read)."""
    clean = {str(k): str(v) for k, v in (mapping or {}).items() if k and v}
    if not clean:
        return False
    with _db() as db:
        known = {r["uuid"]: r["scanner"] for r in db.execute("SELECT uuid, scanner FROM nessus_scanners")}
        changed = {k: v for k, v in clean.items() if known.get(k) != v}
        if not changed:
            return False
        ts = now_iso()
        db.executemany("INSERT INTO nessus_scanners (uuid, scanner, updated) VALUES (?,?,?) ON CONFLICT(uuid) DO UPDATE SET "
                       "scanner = excluded.scanner, updated = excluded.updated", [(k, v, ts) for k, v in changed.items()])
        db.execute("INSERT OR REPLACE INTO nessus_meta (key, value) VALUES ('scanner_map', ?)", (f"{ts}#{len(known) + len(changed)}",))
    return True


def scanner_map():
    with _db() as db:
        return {r["uuid"]: r["scanner"] for r in db.execute("SELECT uuid, scanner FROM nessus_scanners")}


def place(ip, scanners, cfg):
    """(site, how) of one address: its network first ("network 10.248.0.0/24"), else the site of the scanners that found it
    ("scanner tenable-scanner-dcb", the site with most of its findings), else ("", "")."""
    site, net = scope.network_of_ip(ip, cfg)
    if site:
        return site, f"network {net}"
    votes, order = {}, list(cfg)
    for name in scanners:
        s = scope.site_of_scanner(name, cfg) if name else ""
        if s:
            votes.setdefault(s, {}).setdefault(name, 0)
            votes[s][name] += 1
    if not votes:
        return "", ""
    best = max(votes, key=lambda s: (sum(votes[s].values()), -order.index(s)))
    name = max(votes[best], key=lambda n: votes[best][n])
    return best, f"scanner {name}"


def remap_sites(cfg=None, force=False):
    """When the networks, scanners or scanner groups of sites.yml changed, or the scanners of the scans became known
    (record_scanners), every stored finding goes to the site of its address again (place); force: after a sync."""
    cfg = scope.config() if cfg is None else cfg
    with _db() as db:
        known = db.execute("SELECT value FROM nessus_meta WHERE key = 'scanner_map'").fetchone()
        stamp = f"{scope.fingerprint(cfg)}|{scope.scanner_stamp(cfg)}|{known['value'] if known else ''}"
        row = db.execute("SELECT value FROM nessus_meta WHERE key = 'site_map'").fetchone()
        if not force and row and row["value"] == stamp:
            return False
        smap = {r["uuid"]: r["scanner"] for r in db.execute("SELECT uuid, scanner FROM nessus_scanners")}
        per_ip = {}
        for r in db.execute("SELECT id, ipv4, scan_uuid, schedule_uuid, scanner FROM nessus_findings"):
            name = smap.get(r["schedule_uuid"]) or smap.get(r["scan_uuid"]) or r["scanner"] or ""
            per_ip.setdefault(r["ipv4"], []).append((r["id"], name))
        updates = []
        for ip, items in per_ip.items():
            site, via = place(ip, [n for _id, n in items], cfg)
            updates += [(site, via, name, fid) for fid, name in items]
        db.executemany("UPDATE nessus_findings SET site = ?, site_via = ?, scanner = ? WHERE id = ?", updates)
        db.execute("INSERT INTO nessus_meta (key, value) VALUES ('site_map', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                   (stamp,))
    return True


def networks_seen(names):
    """The /24 networks (IPv4) of the hosts these scanners found, with host counts: [(network, hosts)], most hosts first."""
    want = {str(n).lower() for n in names if n}
    if not want:
        return []
    with _db() as db:
        rows = db.execute("SELECT DISTINCT ipv4, scanner FROM nessus_findings WHERE scanner != ''").fetchall()
    hosts = {}
    for r in rows:
        if r["scanner"].lower() not in want:
            continue
        try:
            net = str(ipaddress.ip_network(f"{ipaddress.IPv4Address(r['ipv4'])}/{SEEN_PREFIX}", strict=False))
        except ValueError:
            continue
        hosts.setdefault(net, set()).add(r["ipv4"])
    return sorted(((n, len(h)) for n, h in hosts.items()), key=lambda x: (-x[1], ipaddress.ip_network(x[0])))


def scanners_seen():
    """Every scanner name the findings name, with its hosts: {name: hosts}."""
    with _db() as db:
        return {r["scanner"]: r["n"] for r in db.execute("SELECT scanner, COUNT(DISTINCT ipv4) AS n FROM nessus_findings "
                                                         "WHERE scanner != '' GROUP BY scanner")}


def other_scanners():
    """The scanners that found the hosts of no site (e.g. Tenable's cloud scanners): [{"scanner", "hosts"}]."""
    with _db() as db:
        rows = db.execute("SELECT scanner, COUNT(DISTINCT ipv4) AS n FROM nessus_findings WHERE site = '' "
                          "GROUP BY scanner ORDER BY n DESC").fetchall()
    return [{"scanner": r["scanner"] or "unknown scanner", "hosts": r["n"]} for r in rows]


# ---------------- saving what a sync received ----------------
def _first(value):
    if isinstance(value, list):
        return str(value[0]) if value else ""
    return str(value or "")


def _number(value):
    try:
        return round(float(value), 1) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _flag(value):
    """1 / 0 of a Tenable boolean, None when the export does not say."""
    if value in (None, ""):
        return None
    if isinstance(value, str):
        return 1 if value.strip().lower() in ("true", "yes", "1") else 0
    return 1 if value else 0


def _links(value):
    items = value if isinstance(value, list) else str(value or "").split()
    return "\n".join([str(u).strip() for u in items if str(u).strip().lower().startswith(("https://", "http://"))][:20])


def normalise(item):
    """One finding of a vulnerability export as a row (None when it has no asset or plugin)."""
    asset, plugin, port = item.get("asset") or {}, item.get("plugin") or {}, item.get("port") or {}
    scan = item.get("scan") if isinstance(item.get("scan"), dict) else {}
    ipv4 = _first(asset.get("ipv4"))
    uuid = str(asset.get("uuid") or "") or ipv4
    try:
        plugin_id = int(plugin.get("id"))
    except (TypeError, ValueError):
        return None
    if not uuid:
        return None
    severity = str(item.get("severity") or "").lower()
    state = str(item.get("state") or "").upper()   # Tenable answers OPEN / open; the portal keeps upper case
    if state not in STATES:
        state = "OPEN"
    output = str(item.get("output") or "")
    if len(output.encode("utf-8")) > OUTPUT_MAX:
        output = output.encode("utf-8")[:OUTPUT_MAX].decode("utf-8", errors="ignore") + "\n[… output truncated by the portal]"
    cves = plugin.get("cve") or []
    try:
        port_no = int(port.get("port") or 0)
    except (TypeError, ValueError):
        port_no = 0
    return {"asset_uuid": uuid, "plugin_id": plugin_id, "port": port_no, "protocol": str(port.get("protocol") or "").upper(),
            "service": str(port.get("service") or ""), "ipv4": ipv4,
            "hostname": _first(asset.get("hostname")) or _first(asset.get("fqdn")) or _first(asset.get("netbios_name")),
            "plugin_name": str(plugin.get("name") or f"Plugin {plugin_id}"), "plugin_family": str(plugin.get("family") or ""),
            "severity": severity if severity in RANK else "info", "severity_rank": RANK.get(severity, 0),
            "cvss3": _number(plugin.get("cvss3_base_score")), "vpr": _number((plugin.get("vpr") or {}).get("score")),
            "cves": ",".join(str(c) for c in (cves if isinstance(cves, list) else [cves]) if c)[:2000],
            "state": state, "first_found": utc(item.get("first_found")), "last_found": utc(item.get("last_found")),
            "last_fixed": utc(item.get("last_fixed")), "synopsis": str(plugin.get("synopsis") or "")[:4000],
            "solution": str(plugin.get("solution") or "")[:4000], "output": output,
            "see_also": _links(plugin.get("see_also")), "has_patch": _flag(plugin.get("has_patch")),
            "patch_date": utc(plugin.get("patch_publication_date")), "exploit": _flag(plugin.get("exploit_available")),
            "description": str(plugin.get("description") or "")[:DESCRIPTION_MAX], "plugin_type": str(plugin.get("type") or "")[:20],
            "os": _first(asset.get("operating_system"))[:200], "fqdn": _first(asset.get("fqdn"))[:255],
            "scan_uuid": str(scan.get("uuid") or "")[:80], "schedule_uuid": str(scan.get("schedule_uuid") or "")[:80],
            "scan_started": utc(scan.get("started_at")), "scanner": "", "site_via": ""}


COLUMNS = ("asset_uuid", "plugin_id", "port", "protocol", "service", "ipv4", "hostname", "site", "plugin_name", "plugin_family",
           "severity", "severity_rank", "cvss3", "vpr", "cves", "state", "first_found", "last_found", "last_fixed", "synopsis",
           "solution", "output", "state_changed", "updated", *(name for name, _kind in EXTRA_COLUMNS))


def upsert(items, cfg=None):
    """Save the findings of one export chunk. Returns the counts {received, new, updated, fixed, reopened}: new = not seen
    before, fixed = FIXED now and not before, reopened = REOPENED now and not before."""
    cfg = scope.config() if cfg is None else cfg
    counts = {"received": 0, "new": 0, "updated": 0, "fixed": 0, "reopened": 0}
    ts = now_iso()
    smap = scanner_map()
    with _db() as db:
        for item in items or []:
            row = normalise(item) if isinstance(item, dict) else None
            if not row:
                continue
            counts["received"] += 1
            # placed on its own here; a sync places every finding of an address together afterwards (remap_sites)
            row["scanner"] = smap.get(row["schedule_uuid"]) or smap.get(row["scan_uuid"]) or ""
            site, via = place(row["ipv4"], [row["scanner"]], cfg)
            row.update(site=site, site_via=via, updated=ts)
            key = (row["asset_uuid"], row["plugin_id"], row["port"], row["protocol"])
            old = db.execute("SELECT state, state_changed FROM nessus_findings WHERE asset_uuid = ? AND plugin_id = ? AND port = ? "
                             "AND protocol = ?", key).fetchone()
            if old is None:
                counts["new"] += 1
                counts["reopened"] += row["state"] == "REOPENED"
                row["state_changed"] = ts
                db.execute(f"INSERT INTO nessus_findings ({', '.join(COLUMNS)}) VALUES ({', '.join('?' * len(COLUMNS))})",
                           [row[c] for c in COLUMNS])
                continue
            changed = old["state"] != row["state"]
            counts["fixed"] += changed and row["state"] == "FIXED"
            counts["reopened"] += changed and row["state"] == "REOPENED"
            counts["updated"] += not (changed and row["state"] in ("FIXED", "REOPENED"))
            row["state_changed"] = ts if changed else old["state_changed"]
            sets = [c for c in COLUMNS if c not in ("asset_uuid", "plugin_id", "port", "protocol")]
            db.execute(f"UPDATE nessus_findings SET {', '.join(f'{c} = ?' for c in sets)} WHERE asset_uuid = ? AND plugin_id = ? "
                       "AND port = ? AND protocol = ?", [row[c] for c in sets] + list(key))
    return counts


# ---------------- syncs ----------------
SYNC_FIELDS = ("id", "started", "finished", "status", "username", "reason", "since", "received", "new", "updated", "fixed",
               "reopened", "error")


def _sync(row):
    return {k: row[k] for k in SYNC_FIELDS} if row else None


def sync_start(username, reason, since, client_ip=""):
    with _db() as db:
        return db.execute("INSERT INTO nessus_syncs (started, status, username, reason, since, client_ip) VALUES (?,?,?,?,?,?)",
                          (now_iso(), "running", username, reason, since, client_ip)).lastrowid


def sync_finish(sync_id, status, counts=None, error=""):
    c = counts or {}
    with _db() as db:
        db.execute("UPDATE nessus_syncs SET finished = ?, status = ?, received = ?, new = ?, updated = ?, fixed = ?, reopened = ?, "
                   "error = ? WHERE id = ?", (now_iso(), status, c.get("received", 0), c.get("new", 0), c.get("updated", 0),
                                              c.get("fixed", 0), c.get("reopened", 0), (error or "")[:1000], sync_id))


def last_sync(status=None):
    with _db() as db:
        sql = "SELECT * FROM nessus_syncs" + (" WHERE status = ?" if status else "") + " ORDER BY id DESC LIMIT 1"
        return _sync(db.execute(sql, (status,) if status else ()).fetchone())


def syncs(limit=10):
    with _db() as db:
        return [_sync(r) for r in db.execute("SELECT * FROM nessus_syncs ORDER BY id DESC LIMIT ?", (int(limit),))]


def trend_snapshot(sync_id):
    """After a successful sync: per site and severity, active (OPEN + REOPENED), reopened, fixed in the last 30 days."""
    since = days_ago(FIXED_DAYS)
    with _db() as db:
        rows = db.execute("SELECT site, severity, SUM(state IN ('OPEN', 'REOPENED')) AS active, SUM(state = 'REOPENED') AS reopened, "
                          "SUM(state = 'FIXED' AND last_fixed >= ?) AS fixed FROM nessus_findings GROUP BY site, severity",
                          (since,)).fetchall()
        ts = now_iso()
        for r in rows:
            db.execute("INSERT OR REPLACE INTO nessus_trend (sync_id, ts, site, severity, active, reopened, fixed) VALUES (?,?,?,?,?,?,?)",
                       (sync_id, ts, r["site"], r["severity"], r["active"] or 0, r["reopened"] or 0, r["fixed"] or 0))
        db.execute("DELETE FROM nessus_trend WHERE sync_id NOT IN (SELECT DISTINCT sync_id FROM nessus_trend ORDER BY sync_id DESC LIMIT ?)",
                   (TREND_KEEP,))


# ---------------- reading ----------------
def _site_where(site):
    """SQL for the site filter: a site name, OTHER (outside every site's networks) or "" (every site)."""
    if not site:
        return "1", []
    return "site = ?", ["" if site == OTHER else site]


def _filters(site="", severity="", state="active", q="", plugin=None, ip=""):
    where, args = _site_where(site)
    where, args = [where], list(args)
    if severity:
        if severity not in RANK:
            raise ValueError("Unknown severity")
        where.append("severity_rank >= ?")
        args.append(RANK[severity])
    states = STATE_FILTERS.get(state or "active")
    if states is None:
        raise ValueError("Unknown state")
    where.append(f"state IN ({', '.join('?' * len(states))})")
    args += list(states)
    if plugin is not None:
        where.append("plugin_id = ?")
        args.append(int(plugin))
    if ip:
        where.append("ipv4 = ?")
        args.append(ip)
    q = str(q or "").strip()[:100]
    if q:
        like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        where.append("(ipv4 LIKE ? ESCAPE '\\' OR hostname LIKE ? ESCAPE '\\' OR plugin_name LIKE ? ESCAPE '\\' "
                     "OR CAST(plugin_id AS TEXT) = ? OR cves LIKE ? ESCAPE '\\')")
        args += [like, like, like, q, like]
    return " AND ".join(where), args


def _row(r, full=False):
    out = {"id": r["id"], "ipv4": r["ipv4"], "hostname": r["hostname"], "site": r["site"], "plugin_id": r["plugin_id"],
           "plugin_name": r["plugin_name"], "plugin_family": r["plugin_family"], "severity": r["severity"], "cvss3": r["cvss3"],
           "vpr": r["vpr"], "cves": [c for c in (r["cves"] or "").split(",") if c], "state": r["state"], "port": r["port"],
           "protocol": r["protocol"], "service": r["service"], "first_found": r["first_found"], "last_found": r["last_found"],
           "last_fixed": r["last_fixed"], "state_changed": r["state_changed"], "scanner": r["scanner"] or "",
           "site_via": r["site_via"] or "", "scan_started": r["scan_started"] or ""}
    if full:
        out.update(synopsis=r["synopsis"] or "", solution=r["solution"] or "", output=r["output"] or "",
                   see_also=[u for u in (r["see_also"] or "").split("\n") if u], description=r["description"] or "",
                   has_patch=None if r["has_patch"] is None else bool(r["has_patch"]), patch_date=r["patch_date"] or "",
                   exploit_available=None if r["exploit"] is None else bool(r["exploit"]), plugin_type=r["plugin_type"] or "",
                   os=r["os"] or "", fqdn=r["fqdn"] or "")
    return out


def with_plan(row):
    """A full row with its fix plan (remedy.plan)."""
    return dict(row, plan=remedy.plan(row))


ORDER = "severity_rank DESC, COALESCE(vpr, 0) DESC, plugin_name, ipv4, port"


def flat(limit=MAX_ROWS, **filters):
    where, args = _filters(**filters)
    with _db() as db:
        total = db.execute(f"SELECT COUNT(*) FROM nessus_findings WHERE {where}", args).fetchone()[0]
        rows = db.execute(f"SELECT * FROM nessus_findings WHERE {where} ORDER BY {ORDER} LIMIT ?", args + [int(limit)]).fetchall()
    return {"items": [_row(r) for r in rows], "total": total}


def by_plugin(limit=MAX_ROWS, **filters):
    """One row per plugin: hosts (distinct addresses), findings per state, first and last found."""
    where, args = _filters(**filters)
    with _db() as db:
        rows = db.execute(
            f"SELECT plugin_id, MAX(plugin_name) AS plugin_name, MAX(plugin_family) AS plugin_family, MAX(severity_rank) AS rank, "
            "MAX(cvss3) AS cvss3, MAX(vpr) AS vpr, MAX(cves) AS cves, COUNT(DISTINCT ipv4) AS hosts, COUNT(*) AS findings, "
            "SUM(state = 'OPEN') AS open, SUM(state = 'REOPENED') AS reopened, SUM(state = 'FIXED') AS fixed, "
            f"MIN(first_found) AS first_found, MAX(last_found) AS last_found FROM nessus_findings WHERE {where} "
            "GROUP BY plugin_id ORDER BY rank DESC, COALESCE(MAX(vpr), 0) DESC, hosts DESC, plugin_name", args).fetchall()
    items = [{"plugin_id": r["plugin_id"], "plugin_name": r["plugin_name"], "plugin_family": r["plugin_family"],
              "severity": SEVERITIES[r["rank"]], "cvss3": r["cvss3"], "vpr": r["vpr"],
              "cves": [c for c in (r["cves"] or "").split(",") if c], "hosts": r["hosts"], "findings": r["findings"],
              "open": r["open"] or 0, "reopened": r["reopened"] or 0, "fixed": r["fixed"] or 0,
              "first_found": r["first_found"], "last_found": r["last_found"]} for r in rows]
    return {"items": items[:limit], "total": len(items)}


def by_host(limit=MAX_ROWS, **filters):
    """One row per address: findings per severity (of the state filter), reopened, fixed in 30 days, last found."""
    where, args = _filters(**filters)
    since = days_ago(FIXED_DAYS)
    sev = ", ".join(f"SUM(severity = '{s}') AS {s}" for s in SEVERITIES[1:])   # constant names, no user input
    with _db() as db:
        rows = db.execute(
            f"SELECT ipv4, MAX(hostname) AS hostname, MAX(site) AS site, MAX(severity_rank) AS rank, COUNT(*) AS findings, {sev}, "
            "SUM(state = 'REOPENED') AS reopened, SUM(state = 'FIXED' AND last_fixed >= ?) AS fixed, MAX(last_found) AS last_found "
            f"FROM nessus_findings WHERE {where} GROUP BY ipv4 ORDER BY critical DESC, high DESC, medium DESC, low DESC, ipv4",
            [since] + args).fetchall()
    items = [{"ipv4": r["ipv4"], "hostname": r["hostname"], "site": r["site"], "findings": r["findings"],
              "severity": SEVERITIES[r["rank"] or 0], **{s: r[s] or 0 for s in SEVERITIES[1:]},
              "reopened": r["reopened"] or 0, "fixed": r["fixed"] or 0, "last_found": r["last_found"]} for r in rows]
    return {"items": items[:limit], "total": len(items)}


def host(ip):
    """Every finding of one address (every state), with the plugin output and the solution."""
    with _db() as db:
        rows = db.execute(f"SELECT * FROM nessus_findings WHERE ipv4 = ? ORDER BY state = 'FIXED', {ORDER}", (ip,)).fetchall()
    return [_row(r, full=True) for r in rows]


def get(finding_id):
    """One finding with every field (None when it is not in the portal)."""
    with _db() as db:
        r = db.execute("SELECT * FROM nessus_findings WHERE id = ?", (int(finding_id),)).fetchone()
    return _row(r, full=True) if r else None


def has_host(site, ip):
    """Is ip an address of a finding of this site (the hosts a Verify fix may scan)?"""
    with _db() as db:
        return db.execute("SELECT 1 FROM nessus_findings WHERE site = ? AND ipv4 = ? LIMIT 1", (site, ip)).fetchone() is not None


def site_counts():
    """{site ("" = other): {"findings": active findings, "hosts": addresses with an active finding}}."""
    with _db() as db:
        rows = db.execute("SELECT site, COUNT(*) AS findings, COUNT(DISTINCT ipv4) AS hosts FROM nessus_findings "
                          "WHERE state IN ('OPEN', 'REOPENED') GROUP BY site").fetchall()
    return {r["site"]: {"findings": r["findings"], "hosts": r["hosts"]} for r in rows}


def overview(site_names):
    """Per site (and "" for the findings outside every site): active findings per severity, reopened, fixed in the last
    30 days, addresses, and the trend (one point per sync: active, reopened, fixed)."""
    since = days_ago(FIXED_DAYS)
    out = {s: {"active": {k: 0 for k in SEVERITIES[1:]}, "reopened": 0, "fixed": 0, "hosts": 0, "trend": []}
           for s in list(site_names) + [""]}
    with _db() as db:
        for r in db.execute("SELECT site, severity, SUM(state IN ('OPEN', 'REOPENED')) AS active, SUM(state = 'REOPENED') AS reopened, "
                            "SUM(state = 'FIXED' AND last_fixed >= ?) AS fixed FROM nessus_findings GROUP BY site, severity", (since,)):
            o = out.setdefault(r["site"], {"active": {k: 0 for k in SEVERITIES[1:]}, "reopened": 0, "fixed": 0, "hosts": 0, "trend": []})
            if r["severity"] in o["active"]:
                o["active"][r["severity"]] += r["active"] or 0
            o["reopened"] += r["reopened"] or 0
            o["fixed"] += r["fixed"] or 0
        for r in db.execute("SELECT site, COUNT(DISTINCT ipv4) AS n FROM nessus_findings WHERE state IN ('OPEN', 'REOPENED') GROUP BY site"):
            if r["site"] in out:
                out[r["site"]]["hosts"] = r["n"]
        points = db.execute("SELECT sync_id, MAX(ts) AS ts, site, SUM(active) AS active, SUM(reopened) AS reopened, SUM(fixed) AS fixed "
                            "FROM nessus_trend WHERE sync_id IN (SELECT DISTINCT sync_id FROM nessus_trend ORDER BY sync_id DESC LIMIT 30) "
                            "GROUP BY sync_id, site ORDER BY sync_id").fetchall()
        syncs_seen = sorted({p["sync_id"] for p in points})
    by = {}
    for p in points:
        by.setdefault(p["site"], {})[p["sync_id"]] = p
    when = {p["sync_id"]: p["ts"] for p in points}
    for site, o in out.items():
        mine = by.get(site, {})
        # a site without findings at a sync still has a point (0): the lines of every site have the same syncs
        o["trend"] = [{"sync_id": s, "ts": when[s], "active": (mine.get(s) or {"active": 0})["active"] or 0,
                       "reopened": (mine.get(s) or {"reopened": 0})["reopened"] or 0, "fixed": (mine.get(s) or {"fixed": 0})["fixed"] or 0}
                      for s in syncs_seen]
    return out


CSV_HEADER = ["Site", "IP", "Host name", "Plugin ID", "Plugin", "Family", "Severity", "CVSS v3", "VPR", "CVE", "State", "Port",
              "Protocol", "Service", "First found", "Last found", "Last fixed", "Synopsis", "Solution", "Fixed version", "Fix"]


def _cell(value):
    """A CSV cell that a spreadsheet does not run as a formula (as portal_auth and Runbook Automation export)."""
    if value is None:
        return ""
    text = str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def to_csv(**filters):
    where, args = _filters(**filters)
    out = io.StringIO()
    out.write("﻿")   # UTF-8 mark: Excel then shows non-ASCII host names and plugin names correctly
    w = csv.writer(out)
    w.writerow(CSV_HEADER)
    with _db() as db:
        for r in db.execute(f"SELECT * FROM nessus_findings WHERE {where} ORDER BY site, {ORDER}", args):
            p = remedy.plan(_row(r, full=True))   # the short form of "How to fix it"
            w.writerow([_cell(x) for x in (r["site"] or "Other", r["ipv4"], r["hostname"], r["plugin_id"], r["plugin_name"],
                                           r["plugin_family"], r["severity"].capitalize(), r["cvss3"], r["vpr"],
                                           " ".join((r["cves"] or "").split(",")), r["state"].capitalize(), r["port"] or "",
                                           r["protocol"], r["service"], r["first_found"], r["last_found"], r["last_fixed"],
                                           r["synopsis"], r["solution"], p["fixed_version"], p["fix"])])
    return out.getvalue()


def counts_text(c):
    return (f"{c.get('received', 0)} findings received: {c.get('new', 0)} new, {c.get('fixed', 0)} fixed, "
            f"{c.get('reopened', 0)} reopened")


"""Nessus module (/vulns/): the vulnerabilities Tenable Vulnerability Management (cloud.tenable.com) found with the
Nessus scanner linked at every site, kept in the portal for remediation tracking.

- Findings come from vulnerability exports of Tenable (sync.py, every VULNS_SYNC_HOURS or "Sync now") and stay in the
  portal database (findings.py): open, reopened and fixed per site, host and plugin, the trend after every sync.
- Scans: the scans of Tenable with their scanner, site and status. An administrator, or an operator with the permission
  "nessus-scan", may launch and stop an existing scan and launch the scan of a site for one host only (Verify fix:
  alt_targets = that address). The portal never creates or edits a scan.
- Hard rule (scope.py): the scanners scan only the management networks of their site. A scan is launched only when every
  target is inside the networks of its site (sites.yml tenable.networks), for administrators too; stopping is always
  allowed. Every launch, stop, verify and refusal is typed-confirmed where it changes something and in the activity log.
- Tenable is reached through VULNS_PROXY (the Squid of the bastion) with one API user: Administration -> Credentials,
  target "tenable" (username = access key, password = secret key).
- How to fix it (remedy.py): every finding comes with a fix plan (versions, steps per platform with the commands, vendor
  links, Tenable's solution) that the pages show; the module never runs a command. When the Web Terminal module is loaded and the
  account may open the host there, the plan links to Shell.
"""
import datetime
import functools
import hashlib
import ipaddress
import json
import logging
import os
import sys
import threading
import time

from flask import Blueprint, jsonify, make_response, render_template, request

import portal_auth
import settings
import sites
from core import PORTAL, register

from . import findings, scope, sync, tenable

log = logging.getLogger("portal.nessus")
HERE = os.path.dirname(os.path.abspath(__file__))
MODULE = "nessus"
TITLE = "Vulnerability Scans"
PERMISSION = "nessus-scan"
CREDENTIAL = "tenable"
CACHE_SECONDS = 60       # scan list and scanners: Tenable is behind a proxy and rate-limited
FORCE_SECONDS = 10       # "Refresh" at most this often
# Tenable scan states: a scan in one of these cannot be launched again; stoppable = may be stopped now.
RUNNING = {"running", "pending", "initializing", "processing", "resuming", "publishing", "stopping", "pausing", "paused",
           "canceling", "aborting"}
STOPPABLE = {"running", "pending", "initializing", "processing", "resuming", "pausing", "paused"}

blueprint = Blueprint(MODULE, __name__, url_prefix="/vulns", template_folder="templates", static_folder="static",
                      static_url_path="/static")


# ---------------- service account (Administration -> Credentials) ----------------
def credential_targets():
    return [{"name": CREDENTIAL, "label": "Tenable Vulnerability Management (access key / secret key)", "host": tenable.host(),
             "kind": "tenable", "site": ""}]


def test_credential(target, username, password):
    """Connection test after an administrator saved the API keys: GET /session and the scanners."""
    client = tenable.Client(username, password)
    me = client.session()
    scanners = client.scanners()
    online = sum(1 for s in scanners if str(s.get("status") or "").lower() == "on")
    via = f" (through {tenable._proxy_label(client.proxy)})" if client.proxy else ""
    return (f"Connected to Tenable as {me.get('username') or me.get('name') or 'the API user'}{via}: "
            f"{len(scanners)} scanner{'' if len(scanners) == 1 else 's'} ({online} online)")


_cache_lock = threading.Lock()
_cache = {"scans": None, "scans_at": 0.0, "forced_at": 0.0, "details": {}, "scanners": None, "scanners_at": 0.0}


def clear_cache():
    with _cache_lock:
        _cache.update(scans=None, scans_at=0.0, details={}, scanners=None, scanners_at=0.0)


def credential_changed(name):
    if name == CREDENTIAL:
        clear_cache()


def _running():
    r = sync.running()
    return [{"id": f"nessus-sync-{r['id']}", "title": f"Nessus: sync of the findings ({r['username']})", "user": r["username"]}] if r else []


register(MODULE, TITLE, "Vulnerabilities of the management networks from Tenable (the Nessus scanner of every site): findings, "
         "hosts, scans and remediation tracking.", "/vulns/", "lock", targets=credential_targets, tester=test_credential,
         on_credential_change=credential_changed, running_jobs=_running,
         permissions=[{"id": PERMISSION, "title": "Vulnerability Scans: launch and stop scans"}])
findings.init()


def _ui_version():
    digest = hashlib.sha256()
    for name in ("static/nessus.js", "static/nessus.css", "static/guides.js", "templates/nessus/index.html",
                 "../../static/guide.js", "../../static/guide.css"):
        with open(os.path.join(HERE, name), "rb") as f:
            digest.update(f.read())
    return digest.hexdigest()[:12]


UI_VERSION = _ui_version()


# ---------------- helpers ----------------
def json_body():
    body = request.get_json(silent=True)   # only application/json (extra protection against CSRF)
    return body if isinstance(body, dict) else {}


def can_scan(user):
    """Launch, stop, verify: administrators, and operators with the permission nessus-scan on the Users page."""
    return bool(user) and (user.get("role") == "admin" or PERMISSION in (user.get("modules") or []))


def require_scan():
    user = PORTAL.require(MODULE)
    if not can_scan(user):
        raise portal_auth.Forbidden("Your account cannot launch or stop scans. An administrator can allow it on the Users page "
                                    "(Vulnerability Scans: launch and stop scans).")
    return user


def client():
    cred = PORTAL.credential(CREDENTIAL)   # CredentialError (400) when it is not set
    return tenable.Client(cred["username"], cred["password"])


def configured():
    return PORTAL.credential_configured(CREDENTIAL)


def sync_status():
    return {"running": sync.running(), "last": findings.last_sync(), "last_ok": findings.last_sync("ok")}


def session_payload():
    payload = PORTAL.payload()
    user = payload["user"]
    allowed = bool(user and MODULE in user["modules"])
    out = {"ui_version": UI_VERSION, **payload, "allowed": allowed, "is_admin": bool(user and user["role"] == "admin"),
           "can_scan": allowed and can_scan(user), "configured": False, "sites": [], "counts": {}, "problems": []}
    if allowed:
        cfg = scope.config()
        findings.remap_sites(cfg)
        out.update(configured=configured(), counts=findings.site_counts(), sync=sync_status(),
                   sites=[{"name": s, "scanner": c["scanner"], "networks": [str(n) for n in c["networks"]]} for s, c in cfg.items()],
                   problems=[p for c in cfg.values() for p in c["problems"]], sync_hours=sync.SYNC_HOURS,
                   severities=sync.SEVERITIES, other=findings.OTHER)
    return out


def json_api(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        try:
            return jsonify(ok=True, **view(*args, **kwargs))
        except portal_auth.NotSignedIn as e:
            return jsonify(ok=False, error=str(e), session=session_payload()), 401
        except portal_auth.Forbidden as e:
            return jsonify(ok=False, error=str(e)), 403
        except tenable.TenableError as e:   # Tenable or the proxy: not a mistake of the request
            return jsonify(ok=False, error=str(e)), 502
        except (ValueError, LookupError) as e:   # also portal_auth.CredentialError and sync.Busy
            return jsonify(ok=False, error=str(e)), 400
    return wrapper


def _site_param(value):
    """The site filter of a request: a site of sites.yml, findings.OTHER, or "" (every site)."""
    site = str(value or "").strip()
    if site and site != findings.OTHER and site not in sites.sites():
        raise ValueError(f"Unknown site: {site[:40]}")
    return site


def _filters(a):
    return {"site": _site_param(a.get("site")), "severity": str(a.get("severity") or "").lower(),
            "state": str(a.get("state") or "active").lower(), "q": str(a.get("q") or "")[:100]}


def _ip(value):
    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError:
        raise ValueError("Not an IP address") from None


def _event(user, action, target, detail):
    PORTAL.store.event(user["username"], action, target, detail, PORTAL.client_address())


def _start_sync(user, reason):
    # before the export: the scans of Tenable, so the findings no network places get the site of their scanner
    return sync.start(user["username"], client, PORTAL.store.event, reason, PORTAL.client_address(), before=lambda: scan_list(force=True))


# ---------------- scans (cached: Tenable is far away) ----------------
WEEKDAYS = {"MO": "Mon", "TU": "Tue", "WE": "Wed", "TH": "Thu", "FR": "Fri", "SA": "Sat", "SU": "Sun"}


def schedule_text(s):
    """A Tenable schedule (rrules "FREQ=WEEKLY;INTERVAL=1;BYDAY=MO", starttime "20261110T020000") in words."""
    rules = dict(p.split("=", 1) for p in str(s.get("rrules") or "").split(";") if "=" in p)
    if not s.get("enabled") or not rules:
        return "Not scheduled"
    try:
        start = datetime.datetime.strptime(str(s.get("starttime") or ""), "%Y%m%dT%H%M%S")
        at = f" at {start:%H:%M}"
    except ValueError:
        start, at = None, ""
    freq, interval = rules.get("FREQ", "").upper(), int(rules.get("INTERVAL") or 1) if str(rules.get("INTERVAL") or "1").isdigit() else 1
    zone = f" ({s['timezone']})" if s.get("timezone") else ""
    if freq == "ONETIME":
        return (f"Once on {start:%d %b %Y %H:%M}" if start else "Once") + zone
    unit = {"DAILY": "day", "WEEKLY": "week", "MONTHLY": "month", "YEARLY": "year"}.get(freq)
    if not unit:
        return "Scheduled" + zone
    every = {"day": "Daily", "week": "Weekly", "month": "Monthly", "year": "Yearly"}[unit] if interval == 1 else f"Every {interval} {unit}s"
    days = [WEEKDAYS.get(d[-2:], d) for d in rules.get("BYDAY", "").split(",") if d]
    on = f" on {', '.join(days)}" if days and unit in ("week", "month") else (f" on day {rules['BYMONTHDAY']}" if rules.get("BYMONTHDAY") else "")
    return f"{every}{on}{at}{zone}"


def _summary(detail):
    """What the scan list needs of GET /scans/{id}: scanner, targets, policy, last run."""
    info = detail.get("info") or {}
    runs = [h for h in detail.get("history") or [] if isinstance(h, dict)]
    last = max((int(h.get("last_modification_date") or h.get("creation_date") or 0) for h in runs), default=0)
    return {"scanner": str(info.get("scanner_name") or ""), "targets": str(info.get("targets") or ""),
            "other": scope.other_targets(info), "policy": str(info.get("policy") or ""),
            "last_run": findings.utc(last) if last else "", "error": "",
            "runs": [str(h["uuid"]) for h in runs if h.get("uuid")][-200:]}   # the scan uuid of each run (vuln export: scan.uuid)


def _item(s, d, cfg):
    site = scope.site_of_scanner(d["scanner"], cfg)
    if d.get("error"):
        guard = {"ok": False, "reason": f"The portal could not read this scan from Tenable: {d['error']}", "outside": [], "networks": []}
    else:
        guard = scope.check_scan(site, d["targets"], cfg, d["scanner"], d.get("other") or ())
    status = str(s.get("status") or "").lower()
    if not guard["ok"]:
        why = guard["reason"]
    elif status in RUNNING:
        why = f"The scan is {status}."
    else:
        why = ""
    return {"id": int(s["id"]), "uuid": str(s.get("uuid") or ""), "schedule_uuid": str(s.get("schedule_uuid") or ""),
            "name": str(s.get("name") or f"Scan {s['id']}"),
            "status": status or "empty", "enabled": bool(s.get("enabled")), "schedule": schedule_text(s),
            "last_run": d["last_run"] or findings.utc(s.get("last_modification_date")), "scanner": d["scanner"], "site": site,
            "targets": d["targets"], "policy": d["policy"], "guard": guard, "can_launch": not why, "launch_reason": why,
            "can_stop": status in STOPPABLE}


def scan_list(force=False):
    """Every scan of Tenable (not in the trash) with its site and whether the portal may launch it. The details of a
    scan are read again only when it changed (last_modification_date)."""
    now = time.time()
    with _cache_lock:
        fresh = _cache["scans"] is not None and now - _cache["scans_at"] < CACHE_SECONDS
        if force and now - _cache["forced_at"] >= FORCE_SECONDS:
            fresh, _cache["forced_at"] = False, now
        if fresh:
            return _cache["scans"]
        details = dict(_cache["details"])
    c = client()
    data = c.scans()
    trash = {f.get("id") for f in data.get("folders") or [] if str(f.get("type") or "") == "trash"}
    cfg = scope.config()
    items = []
    for s in data.get("scans") or []:
        if not isinstance(s, dict) or s.get("id") is None or s.get("folder_id") in trash:
            continue
        sid, stamp = int(s["id"]), s.get("last_modification_date")
        if sid not in details or details[sid][0] != stamp or details[sid][1].get("error"):
            try:
                details[sid] = (stamp, _summary(c.scan(sid)))
            except tenable.TenableError as e:   # one scan the API user may not read: shown, never launched
                details[sid] = (stamp, {"scanner": "", "targets": "", "policy": "", "last_run": "", "error": str(e)})
        items.append(_item(s, details[sid][1], cfg))
    items.sort(key=lambda x: (x["site"] or "~", x["name"].lower()))
    # which scanner ran which scan (its uuid, its schedule, each run): the site of findings no network places
    ran = {}
    for i in items:
        if i["scanner"]:
            for key in [i["uuid"], i["schedule_uuid"], *details[i["id"]][1].get("runs", [])]:
                if key:
                    ran[key] = i["scanner"]
    findings.record_scanners(ran)
    with _cache_lock:
        _cache.update(scans=items, scans_at=time.time(), details={k: v for k, v in details.items() if k in {i["id"] for i in items}})
    return items


def scanners():
    """(scanners of Tenable with their site, error text): cached like the scans."""
    with _cache_lock:
        if _cache["scanners"] is not None and time.time() - _cache["scanners_at"] < CACHE_SECONDS:
            return _cache["scanners"], ""
    try:
        raw = client().scanners()
    except (tenable.TenableError, portal_auth.CredentialError) as e:
        return [], str(e)
    cfg = scope.config()
    items = [{"name": str(s.get("name") or ""), "status": str(s.get("status") or "").lower(), "type": str(s.get("type") or ""),
              "engine_version": str(s.get("engine_version") or ""), "last_connect": findings.utc(s.get("last_connect")),
              "plugin_set": str(s.get("loaded_plugin_set") or ""), "site": scope.site_of_scanner(s.get("name"), cfg)}
             for s in raw if isinstance(s, dict)]
    with _cache_lock:
        _cache.update(scanners=items, scanners_at=time.time())
    return items, ""


def _changed():
    """After a launch or stop: the next list reads Tenable again."""
    with _cache_lock:
        _cache.update(scans=None, scans_at=0.0)


_launching = threading.Lock()   # two clicks (or two operators) never launch the same scan twice


def _scan_now(c, scan_id):
    """The scan as Tenable has it now (never the cache: the targets are checked on what will run)."""
    detail = c.scan(scan_id)
    info = detail.get("info") or {}
    if not info:
        raise LookupError("Scan not found in Tenable")
    cfg = scope.config()
    name = str(info.get("name") or f"Scan {scan_id}")
    scanner = str(info.get("scanner_name") or "")
    site = scope.site_of_scanner(scanner, cfg)
    return detail, info, name, scanner, site, cfg


def _label(site, name):
    return f"{site or 'Other'} · {name}"


def _short(text, n=300):
    text = " ".join(str(text or "").split())
    return text if len(text) <= n else text[:n - 1] + "…"


# ---------------- pages ----------------
@blueprint.get("/")
def index():
    return render_template("nessus/index.html", ui_version=UI_VERSION)


@blueprint.get("/api/session")
def session():
    """The module's session payload; a page that opens also starts the sync when the last one is too old."""
    out = session_payload()
    if out["allowed"] and out["configured"] and sync.due():
        try:
            _start_sync(out["user"], "auto")
            out["sync"] = sync_status()
        except sync.Busy:
            pass
    return jsonify(ok=True, **out)


@blueprint.get("/api/sync")
@json_api
def sync_view():
    PORTAL.require(MODULE)
    return {"sync": sync_status(), "history": findings.syncs(10), "counts": findings.site_counts()}


@blueprint.post("/api/sync")
@json_api
def sync_now():
    user = PORTAL.require(MODULE)
    if not configured():
        raise ValueError("Tenable is not connected: an administrator enters the API keys on Administration → Credentials.")
    return {"id": _start_sync(user, "manual"), "sync": sync_status()}


@blueprint.get("/api/overview")
@json_api
def overview():
    """Per site: active findings per severity, reopened, fixed in the last 30 days, hosts, trend and its scanner."""
    user = PORTAL.require(MODULE)
    cfg = scope.config()
    findings.remap_sites(cfg)
    data = findings.overview(list(cfg))
    found, error = scanners()
    admin = user["role"] == "admin"
    names = set(findings.scanners_seen()) | {s["name"] for s in found}
    out = []
    for site, c in cfg.items():
        mine = next((s for s in found if s["site"] == site), None)
        item = {"name": site, "scanner": c["scanner"], "groups": c.get("groups") or [], "networks": [str(n) for n in c["networks"]],
                "scanner_status": mine, **data.get(site, {})}
        if admin:   # a suggestion for sites.yml, never used by the launch guard
            item["seen"] = networks_suggestion(site, c, names, {s["name"] for s in found})
        out.append(item)
    return {"sites": out, "other": {**data.get("", {}), "scanners": [s for s in found if not s["site"]],
                                    "found_by": findings.other_scanners()},
            "scanners_error": error, "sync": sync_status()}


def networks_suggestion(site, c, names, scanner_names):
    """For administrators: the /24 networks of the hosts the site's scanner found, and a tenable line for sites.yml, when
    tenable.networks is empty or misses some of them. Only a suggestion to check: the launch and verify guard read the
    networks of sites.yml, never these. A site that names no scanner yet: the scanners with the site name in theirs."""
    configured = [n for n in [c["scanner"], *(c.get("groups") or [])] if n]
    used = configured or scope.guess_scanners(site, names)
    seen = findings.networks_seen(used)
    if not seen:
        return None
    nets = [{"network": n, "hosts": h, "covered": scope._inside([ipaddress.ip_network(n)], c["networks"])} for n, h in seen]
    missing = [x["network"] for x in nets if not x["covered"]]
    if not missing:
        return None
    scanner = c["scanner"] or next((n for n in used if n in scanner_names), used[0])
    groups = c.get("groups") or [n for n in used if n != scanner]
    networks = [str(n) for n in c["networks"]] + missing
    q = lambda v: json.dumps(v, ensure_ascii=False)   # noqa: E731 (flow YAML with JSON strings: valid YAML)
    line = f"tenable: {{scanner: {q(scanner)}, groups: [{', '.join(q(g) for g in groups)}], networks: [{', '.join(q(n) for n in networks)}]}}"
    return {"scanners": used, "guessed": not configured, "networks": nets, "missing": missing, "yaml": line}


@blueprint.get("/api/findings")
@json_api
def findings_view():
    """?site= &severity= (at least) &state=active|open|reopened|fixed|all &q= &view=plugins|list &plugin=<id>"""
    PORTAL.require(MODULE)
    f = _filters(request.args)
    findings.remap_sites()
    plugin = request.args.get("plugin")
    if plugin not in (None, ""):
        if not str(plugin).isdigit():
            raise ValueError("Unknown plugin")
        return {"view": "list", **findings.flat(plugin=int(plugin), **f)}
    view = request.args.get("view") or "plugins"
    if view not in ("plugins", "list"):
        raise ValueError("view: plugins or list")
    return {"view": view, **(findings.by_plugin(**f) if view == "plugins" else findings.flat(**f))}


def shell_hosts(user, ip):
    """The Shell hosts with this address the account may open: [] when the Web Terminal module is not loaded (it is never imported
    from here: importing it would add it to the portal), the account has no Shell, or Shell has no host with the address."""
    shell = sys.modules.get("modules.shell")
    if not shell or not ip or "shell" not in (user.get("modules") or []):
        return []
    try:
        every = shell.targets.all_targets()
        rules = None if user.get("role") == "admin" else shell.access.rules(user["username"])
    except Exception as e:   # Shell cannot read its hosts now: the plan has no link, nothing else changes
        log.warning("Shell hosts for %s not readable: %s", ip, e)
        return []
    return [{"site": t["site"], "category": t.get("category_label") or t.get("category") or "", "name": t["name"],
             "address": t["address"], "problem": t.get("problem") or ""}
            for t in every if t.get("address") == ip and (rules is None or shell.access.allows(rules, t))]


@blueprint.get("/api/findings/<int:finding_id>")
@json_api
def finding_view(finding_id):
    """One finding with every field and its fix plan ("How to fix it"), and the Shell hosts of its address."""
    user = PORTAL.require(MODULE)
    row = findings.get(finding_id)
    if not row:
        raise LookupError("This finding is not in the portal (any more)")
    return {"finding": findings.with_plan(row), "shell": shell_hosts(user, row["ipv4"])}


@blueprint.get("/api/hosts")
@json_api
def hosts_view():
    PORTAL.require(MODULE)
    findings.remap_sites()
    return findings.by_host(**_filters(request.args))


@blueprint.get("/api/hosts/<address>")
@json_api
def host_view(address):
    """Every finding of one address with output and solution, and the scans of its site (for Verify fix)."""
    user = PORTAL.require(MODULE)
    ip = _ip(address)
    findings.remap_sites()
    items = findings.host(ip)
    if not items:
        raise LookupError(f"No finding of {ip} in the portal")
    site = items[0]["site"]
    scans, error = [], ""
    if site and can_scan(user):
        try:
            # the scans that cover only management networks first: their policy was made for these hosts
            scans = sorted((s for s in scan_list() if s["site"] == site), key=lambda s: (not s["guard"]["ok"], s["name"].lower()))
        except (tenable.TenableError, portal_auth.CredentialError) as e:
            error = str(e)
    return {"ip": ip, "hostname": next((i["hostname"] for i in items if i["hostname"]), ""), "site": site,
            "site_via": items[0].get("site_via") or "", "scanners": sorted({i["scanner"] for i in items if i.get("scanner")}),
            "items": [findings.with_plan(i) for i in items], "shell": shell_hosts(user, ip),
            "os": next((i["os"] for i in items if i.get("os")), ""),
            "verify": {"scans": [{k: s[k] for k in ("id", "name", "status", "scanner", "can_stop")} for s in scans],
                       "reason": scope.check_ip(site, ip) if site else "This address is outside the management networks of every site.",
                       "error": error}}


@blueprint.get("/api/scans")
@json_api
def scans_view():
    """?site= (a site, findings.OTHER for scans of no site's scanner, empty: every scan) &force=1 (read Tenable again)."""
    user = PORTAL.require(MODULE)
    site = _site_param(request.args.get("site"))
    every = scan_list(force=request.args.get("force") == "1")
    items = [s for s in every if s["site"] == ("" if site == findings.OTHER else site)] if site else every
    with _cache_lock:
        age = int(time.time() - _cache["scans_at"]) if _cache["scans_at"] else 0
    # administrators: what sites.yml lacks for these scans (tenable.networks, tenable.scanner), to add: never applied
    admin = user["role"] == "admin"
    return {"items": items, "age": age, "proposals": scope.proposals(every) if admin else {},
            "sites_file": settings.SITES_FILE if admin else ""}


@blueprint.get("/api/scans/<int:scan_id>")
@json_api
def scan_view(scan_id):
    """One scan as Tenable has it now: info, the hosts of its last run with their counts, and its history."""
    PORTAL.require(MODULE)
    c = client()
    detail, info, name, scanner, site, cfg = _scan_now(c, scan_id)
    try:   # the schedule is only in the list of scans
        listed = next((s for s in scan_list() if s["id"] == scan_id), None)
    except tenable.TenableError:
        listed = None
    status = str(info.get("status") or (listed or {}).get("status") or "").lower()
    guard = scope.check_scan(site, info.get("targets"), cfg, scanner, scope.other_targets(info))
    why = guard["reason"] if not guard["ok"] else f"The scan is {status}." if status in RUNNING else ""
    hosts = []
    for h in detail.get("hosts") or []:
        if not isinstance(h, dict):
            continue
        address = str(h.get("hostname") or "")
        hosts.append({"host_id": h.get("host_id"), "hostname": address, **{k: int(h.get(k) or 0) for k in ("critical", "high", "medium", "low", "info")},
                      "in_portal": bool(site) and findings.has_host(site, address)})
    history = sorted(({"history_id": h.get("history_id"), "status": str(h.get("status") or "").lower(),
                       "started": findings.utc(h.get("creation_date")), "ended": findings.utc(h.get("last_modification_date")),
                       "scheduled": bool(h.get("scheduler"))} for h in detail.get("history") or [] if isinstance(h, dict)),
                     key=lambda h: h["started"], reverse=True)[:50]
    return {"scan": {"id": scan_id, "name": name, "status": status or "empty", "scanner": scanner, "site": site,
                     "targets": str(info.get("targets") or ""), "policy": str(info.get("policy") or ""),
                     "schedule": (listed or {}).get("schedule", ""), "guard": guard, "can_launch": not why, "launch_reason": why,
                     "can_stop": status in STOPPABLE, "hosts": hosts, "history": history,
                     "started": findings.utc(info.get("scan_start")), "ended": findings.utc(info.get("scan_end"))}}


@blueprint.get("/api/scans/<int:scan_id>/status")
@json_api
def scan_status(scan_id):
    PORTAL.require(MODULE)
    status = client().latest_status(scan_id).lower()
    return {"status": status, "running": status in RUNNING, "can_stop": status in STOPPABLE}


@blueprint.post("/api/scans/<int:scan_id>/launch")
@json_api
def scan_launch(scan_id):
    """Launch an existing scan: only when every target is inside the management networks of its site (administrators
    too), after the scan name was typed."""
    user = require_scan()
    body = json_body()
    c = client()
    _detail, info, name, scanner, site, cfg = _scan_now(c, scan_id)
    targets = str(info.get("targets") or "")
    guard = scope.check_scan(site, targets, cfg, scanner, scope.other_targets(info))
    if not guard["ok"]:
        _event(user, "nessus.refused", _label(site, name), f"Launch of scan #{scan_id} refused: {guard['reason']}")
        raise ValueError(guard["reason"])
    if str(body.get("confirm") or "").strip() != name:
        raise ValueError(f"Type the scan name {name} to confirm the launch.")
    with _launching:
        status = c.latest_status(scan_id).lower()
        if status in RUNNING:
            raise ValueError(f"{name} is {status} already: stop it first, or wait until it ends.")
        result = c.launch(scan_id)
    _changed()
    _event(user, "nessus.launch", _label(site, name), f"Scan #{scan_id} launched on the scanner {scanner}: {_short(targets)}")
    return {"scan_uuid": str(result.get("scan_uuid") or ""), "name": name}


@blueprint.post("/api/scans/<int:scan_id>/stop")
@json_api
def scan_stop(scan_id):
    """Stop a running scan (always allowed for who may launch: stopping is safe), after the scan name was typed."""
    user = require_scan()
    body = json_body()
    c = client()
    _detail, info, name, scanner, site, _cfg = _scan_now(c, scan_id)
    if str(body.get("confirm") or "").strip() != name:
        raise ValueError(f"Type the scan name {name} to confirm the stop.")
    status = c.latest_status(scan_id).lower()
    if status not in STOPPABLE:
        raise ValueError(f"{name} is not running ({status or 'no run yet'}).")
    c.stop(scan_id)
    _changed()
    _event(user, "nessus.stop", _label(site, name), f"Scan #{scan_id} stopped ({status}) on the scanner {scanner}")
    return {"name": name}


@blueprint.post("/api/scans/<int:scan_id>/verify")
@json_api
def scan_verify(scan_id):
    """Verify fix: launch the scan of a site for one host only (alt_targets = [ip]). The address must be one IPv4 inside
    the management networks of the scan's site and a host with findings of that site in the portal; the IP is typed."""
    user = require_scan()
    body = json_body()
    raw = str(body.get("ip") or "").strip()
    c = client()
    _detail, info, name, scanner, site, cfg = _scan_now(c, scan_id)
    problem = scope.check_ip(site, raw, cfg)
    if problem:
        _event(user, "nessus.refused", _label(site, name), f"Verify fix of {raw[:45] or '(no address)'} with scan #{scan_id} refused: {problem}")
        raise ValueError(problem)
    ip = str(ipaddress.IPv4Address(raw))
    if not findings.has_host(site, ip):
        raise ValueError(f"{ip} is not a host with findings of {site} in the portal: Verify fix scans again a host the portal "
                         "has findings of (sync first when it is new).")
    if str(body.get("confirm") or "").strip() != ip:
        raise ValueError(f"Type the address {ip} to confirm.")
    with _launching:
        status = c.latest_status(scan_id).lower()
        if status in RUNNING:
            raise ValueError(f"{name} is {status}: wait until it ends, or stop it first.")
        result = c.launch(scan_id, alt_targets=[ip])
    _changed()
    active = sum(1 for f in findings.host(ip) if f["state"] in findings.ACTIVE)
    _event(user, "nessus.verify", _label(site, name), f"Scan #{scan_id} launched for {ip} only (Verify fix, {active} open "
           f"finding{'' if active == 1 else 's'}) on the scanner {scanner}")
    return {"scan_uuid": str(result.get("scan_uuid") or ""), "name": name, "ip": ip}


@blueprint.get("/export/findings.csv")
def findings_csv():
    """The findings of the current filter (every row, with synopsis and solution) for a spreadsheet."""
    try:
        PORTAL.require(MODULE)
        f = _filters(request.args)
        findings.remap_sites()
        body = findings.to_csv(**f)
    except portal_auth.NotSignedIn as e:
        return jsonify(ok=False, error=str(e)), 401
    except portal_auth.Forbidden as e:
        return jsonify(ok=False, error=str(e)), 403
    except ValueError as e:
        return jsonify(ok=False, error=str(e)), 400
    name = (f["site"] if f["site"] and f["site"] != findings.OTHER else "Other" if f["site"] else "All")
    resp = make_response(body)
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = f'attachment; filename="Nessus_Findings_{name}_{datetime.datetime.now():%Y%m%d-%H%M}.csv"'
    return resp

"""Status (portal module /status/): the read-only checks of Runbook Automation for every product of every site, run
by themselves every few hours (rounds.py), on one page per site: each product safe or not, what was checked, what each
check found, its recommendations, and the checks to run next when it is not safe.

- Products (products.py): OpenStack, NetApp ONTAP, VMware Cloud (read only), chosen by the owner on 11 Nov 2026.
- A round runs the checks as the account "health" (Runbook Automation without fixes): they are in Runs as any run,
  and a fix is asked for from the run as always (pre-check, engineer review). Nothing changes by a round.
- Run now: every user of the module, for the site shown (read-only checks; one round of a site at a time).
- Metrics: the status of every product of every site and the age of the last round join /runbook/api/alerts/metrics (the
  scrape of the SRE Grafana), so a product that is not safe reaches an operator (Prometheus → Grafana → AlertHub).
Users of the module see every site; the checks need Runbook Automation configured as for an operator.
"""
import functools
import hashlib
import logging
import os
import re

from flask import Blueprint, jsonify, render_template, request

import portal_auth
import sites
from core import PORTAL, register
from modules import wi as wi_module
from modules.wi import alerts, bmcs, catalog, runs

from . import products, rounds

log = logging.getLogger("portal.health")
HERE = os.path.dirname(os.path.abspath(__file__))
MODULE = "health"
TITLE = "Status"
OWNER = wi_module.owner_of("health-rounds")
TITLE_END = re.compile(r'(?<!\be\.g)(?<!\bi\.e)(?<!\betc)(?<!\bvs)(?<!\d)\.\s+(?=[A-Z0-9("])')
MAX_FINDINGS = 6          # steps with a problem shown per check
MAX_RECOMMENDATIONS = 5   # recommendations shown per check

blueprint = Blueprint(MODULE, __name__, url_prefix="/status", template_folder="templates", static_folder="static",
                      static_url_path="/static")


# ---------------- what this module uses of Runbook Automation ----------------
def _start(user, site, check_id, raw, after, note):
    return wi_module.start_run(user, site, catalog.get(check_id), raw, "health", OWNER, after=after, note=note)[0]


def _access(check_id, site):
    try:
        check = catalog.get(check_id)
        cfg = wi_module.site_cfg(site)
    except (LookupError, ValueError, KeyError) as e:
        return {"runnable": False, "missing": [str(e)]}
    if check.get("status") != "ready":
        return {"runnable": False, "missing": [str(check.get("reason") or check.get("status"))]}
    state = catalog.access(check, site, cfg, PORTAL.credential_configured)
    return {"runnable": bool(state.get("runnable")), "missing": list(state.get("missing") or [])}


def _targets(site, kind):
    return sorted(bmcs.members(site)) if kind == "bmc" else []


rounds.HOOKS.update(start=_start, access=_access, get_run=runs.get, targets=_targets)
runs.HIDDEN_USERS.add(rounds.ROBOT["username"])   # Runs leaves the rounds out unless the user health is chosen
register(MODULE, TITLE, "Status of every product of every site (OpenStack, NetApp ONTAP, VMware Cloud): read-only checks "
         "every few hours, what is safe and what is not, with recommendations; the hardware of every BMC.", "/status/", "checklist",
         running_jobs=rounds.jobs)
rounds.init()


def _ui_version():
    digest = hashlib.sha256()
    for name in ("static/health.js", "static/health.css", "static/guides.js", "templates/health/index.html",
                 "../../static/guide.js", "../../static/guide.css"):
        with open(os.path.join(HERE, name), "rb") as f:
            digest.update(f.read())
    return digest.hexdigest()[:12]


UI_VERSION = _ui_version()


# ---------------- what a page shows ----------------
def _title(text):
    text = str(text or "").strip()
    m = TITLE_END.search(text)
    return re.sub(r"\s+", " ", text[:m.start() + 1] if m else text)[:300]


def _check_title(check_id):
    try:
        return catalog.get(check_id)["title"]
    except (LookupError, KeyError, ValueError):
        return check_id


def _next_checks(entry):
    out = []
    for check_id in entry.get("next") or []:
        try:
            check = catalog.get(check_id)
        except LookupError:
            continue
        if check.get("status") == "ready":
            out.append({"id": check_id, "title": check["title"]})
    return out


def _check_view(entry, item, target=""):
    """One check of a product in the last round (of one target of a "per" product: a BMC): its status, what it found,
    its recommendations, what to check next."""
    target = (item or {}).get("target") or target
    title = _check_title(entry["check"])
    out = {"check_id": entry["check"], "key": f"{entry['check']}:{target}" if target else entry["check"], "target": target,
           "title": f"{title}: {target}" if target else title, "status": "never", "note": "", "run_id": None,
           "finished": "", "summary": "", "findings": [], "recommendations": [], "next": []}
    if not item:
        return out
    out.update(status=item["status"], note=item["note"] or "", run_id=item["run_id"], finished=item["finished"] or "")
    run = rounds.HOOKS["get_run"](item["run_id"]) if item["run_id"] else None
    if run:
        result = run.get("result") or {}
        out["summary"] = str(run.get("summary") or run.get("error") or "")[:500]
        out["finished"] = run.get("finished") or out["finished"]
        out["findings"] = [{"title": str(s.get("title") or s.get("key") or ""), "status": s.get("status"),
                            "detail": str(s.get("detail") or "")[:400]}
                           for s in result.get("steps") or [] if s.get("status") in ("warn", "fail")][:MAX_FINDINGS]
        recs = {}   # one per title (a check may say the same thing for two items)
        for r in result.get("recommendations") or []:
            if isinstance(r, dict) and r.get("text"):
                title = _title(r.get("text"))
                recs[title] = recs.get(title, False) or bool(r.get("action"))
        out["recommendations"] = [{"title": t, "fix": fix} for t, fix in recs.items()][:MAX_RECOMMENDATIONS]
    if out["status"] in ("warn", "fail", "error", "unknown", "stopped"):
        out["next"] = _next_checks(entry)
    return out


def _product_status(checks):
    statuses = [c["status"] for c in checks if c["status"] not in ("not-configured", "never")]
    if not statuses:
        return "not-configured" if any(c["status"] == "not-configured" for c in checks) else "never"
    return products.PRODUCT_STATUS[min(products.RANK.get(s, 2) for s in statuses)]


def _product_checks(site, p, its):
    """The checks of a product in a round: one per check, or for a "per" product one per target it had (else the
    targets of the site now, not checked yet)."""
    mine = [x for x in its if x["product"] == p["id"]]
    if p.get("per"):
        if mine:
            return [_check_view(c, x) for c in p["checks"] for x in mine if x["check_id"] == c["check"]]
        return [_check_view(c, None, t) for c in p["checks"] for t in rounds.targets(site, p) or [""]]
    by = {x["check_id"]: x for x in mine}
    return [_check_view(c, by.get(c["check"])) for c in p["checks"]]


def overview(site):
    last = rounds.last_round(site)
    its = rounds.items(last["id"]) if last else []
    out = []
    for p in products.PRODUCTS:
        checks = _product_checks(site, p, its)
        counts = {}
        for c in checks:
            counts[c["status"]] = counts.get(c["status"], 0) + 1
        out.append({"id": p["id"], "title": p["title"], "icon": p["icon"], "read_only": bool(p.get("read_only")),
                    "status": _product_status(checks), "counts": counts, "checks": checks})
    return {"site": site, "round": last, "running": rounds.running(site), "next": rounds.next_round(site),
            "interval_hours": rounds.INTERVAL_HOURS, "products": out}


def metrics():
    """Gauges for /runbook/api/alerts/metrics: the status of every product of every site from its last finished round, the age
    of the last round, and whether a round runs now."""
    status, age, running = [], [], []
    for site in sorted(sites.sites()):
        last = rounds.last_round(site, finished=True)
        if last:
            view = overview_finished(site, last)
            for p in view:
                if p["status"] in products.METRIC_VALUE:
                    status.append(({"site": site, "product": p["id"]}, products.METRIC_VALUE[p["status"]]))
            seconds = rounds._age(last["started"])
            if seconds is not None:
                age.append(({"site": site}, int(seconds)))
        running.append(({"site": site}, 1 if rounds.running(site) else 0))
    return [("ops_platform_status", "gauge", "Status of a product of a site from its last round: 0 safe, 1 needs attention, "
             "2 not safe, 3 could not check (Status module).", status),
            ("ops_platform_round_age_seconds", "gauge", "Seconds since the last finished health round of a site started.", age),
            ("ops_platform_round_running", "gauge", "1 while a health round of the site runs.", running)]


def overview_finished(site, last):
    its = rounds.items(last["id"])
    out = []
    for p in products.PRODUCTS:
        mine = [x for x in its if x["product"] == p["id"]]
        checks = [{"status": x["status"]} for x in mine] or [{"status": "never"}]
        out.append({"id": p["id"], "status": _product_status(checks)})
    return out


alerts.EXTRA_METRICS.append(metrics)


# ---------------- helpers ----------------
def json_body():
    body = request.get_json(silent=True)   # only application/json (extra protection against CSRF)
    return body if isinstance(body, dict) else {}


def session_payload():
    payload = PORTAL.payload()
    user = payload["user"]
    allowed = bool(user and MODULE in user["modules"])
    out = {"ui_version": UI_VERSION, **payload, "allowed": allowed, "is_admin": bool(user and user["role"] == "admin"),
           "sites": [], "interval_hours": rounds.INTERVAL_HOURS,
           "products": [{"id": p["id"], "title": p["title"]} for p in products.PRODUCTS]}
    if allowed:
        out["sites"] = [{"name": s, "products": rounds.configured(s), "running": rounds.running(s)} for s in sites.sites()]
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
        except (ValueError, LookupError) as e:
            return jsonify(ok=False, error=str(e)), 400
    return wrapper


def _site(value):
    site = str(value or "").strip()
    if site not in sites.sites():
        raise ValueError(f"Unknown site {site}")
    return site


# ---------------- pages ----------------
@blueprint.get("/")
def index():
    return render_template("health/index.html", ui_version=UI_VERSION)


@blueprint.get("/api/session")
def session():
    return jsonify(ok=True, **session_payload())


@blueprint.get("/api/overview")
@json_api
def overview_view():
    """The health of one site: its products from the last round, each with its checks."""
    PORTAL.require(MODULE)
    return overview(_site(request.args.get("site")))


@blueprint.post("/api/rounds")
@json_api
def round_start():
    """Run now: the round of one site (read-only checks)."""
    user = PORTAL.require(MODULE)
    site = _site(json_body().get("site"))
    if not rounds.configured(site):
        raise ValueError(f"No product is configured on {site}: nothing to check.")
    rid = rounds.start(site, user, "manual")
    PORTAL.store.event(user["username"], "health.round", site, f"Status round #{rid} of {site} started (Run now)",
                       PORTAL.client_address())
    return {"round_id": rid}


rounds.start_scheduler()

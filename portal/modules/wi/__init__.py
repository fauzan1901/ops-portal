"""Runbook Automation module (/runbook/): read-only checks from the Knowledge Base work instructions, run with Ansible.

The operator picks a check from the catalog (one or more WI pages), the site and the parameters of the alert; the
portal runs playbooks/run_check.yml and shows the result per WI step (OK / warning / problem / skipped) with the
evidence, how to fix it (commands with the values found and where to run them), and the full Ansible output. Nothing is changed on any system.
"""
import base64
import datetime
import functools
import hashlib
import io
import json
import logging
import os
import threading
import time

from flask import Blueprint, jsonify, make_response, render_template, request, send_file

import jobs
import portal_auth
import sites
from core import PORTAL, register

from . import access, alerts, bmcs, catalog, files, fixes, hosts, progress, reviews, runs, templates, topology, wi_analysis

log = logging.getLogger("portal.wi")
HERE = os.path.dirname(os.path.abspath(__file__))
PLAYBOOK_DIR = os.path.join(HERE, "playbooks")
MODULE = "wi"
TITLE = "Runbook Automation"
JOBS = jobs.Jobs(PLAYBOOK_DIR, {"check": int(os.environ.get("RUNBOOK_CHECK_TIMEOUT_SECONDS", "600")),
                               "action": int(os.environ.get("RUNBOOK_FIX_TIMEOUT_SECONDS", "1800"))},   # OpenStack: see below
                 busy_message=("The same check, a fix on the same host, or a fix of the same kind on this site (migrations and image "
                               "clean-ups run one at a time per site) is already running. Open it from Runs."),
                 timeout_message="The {timeout}-second time limit was reached; the check was stopped.")
# OpenStack fixes retype / migrate volumes one after the other and wait for each: hours for large volumes.
OPENSTACK_FIX_TIMEOUT = int(os.environ.get("RUNBOOK_OPENSTACK_FIX_TIMEOUT_SECONDS", "28800"))
CONSOLE_TEST_TIMEOUT = 600   # the connection, three screenshots and one key
# s: how long the check run again after a fix waits for the same check still running (another fix ended just before)
VERIFY_WAIT = 15 * 60
SECRET_ENV = {"ontap": "RUNBOOK_ONTAP", "ro-vcenter": "RUNBOOK_VCENTER", "ro-nsxt": "RUNBOOK_NSXT", "vcd-reader": "RUNBOOK_VCD"}

blueprint = Blueprint(MODULE, __name__, url_prefix="/runbook", template_folder="templates", static_folder="static",
                      static_url_path="/static")
register(MODULE, TITLE, "Checks from the Knowledge Base work instructions and platform health (OpenStack, VMware, NSX-T, BMC), with Ansible; fixes on SSH hosts, ONTAP and OpenStack.",
         "/runbook/", "checklist", targets=access.targets, tester=access.test, running_jobs=JOBS.running,
         permissions=[{"id": fixes.PERMISSION, "title": "Runbook Automation: run fixes (SSH hosts, ONTAP)"},
                      {"id": fixes.OPENSTACK_PERMISSION, "title": "Runbook Automation: run OpenStack fixes (OpenStack Cloud)"},
                      {"id": reviews.PERMISSION, "title": "Runbook Automation: review fixes (approve or reject the fixes operators ask to run)"},
                      {"id": files.PERMISSION, "title": "Runbook Automation: collect logs (log bundles, sos report, raw output)"}])

hosts.init()
bmcs.init()
templates.init()
for _rule_name, _note in alerts.init():   # the allowed fixes of before became automatic actions: said in the activity log
    PORTAL.store.event(alerts.ROBOT, "wi.alert_rule", _rule_name, _note, "")
files.cleanup()
for _req in reviews.init():   # a pre-check, or a Run now, cut by a stop of the portal
    PORTAL.store.event(_req["username"], "wi.fix_precheck" if _req["status"] == "prechecking" else "wi.fix_expired", _req["check_id"],
                       f"Fix request #{_req['id']} of troubleshooting run #{_req['run_id']} on {_req['site']}: the portal stopped "
                       + ("during its pre-check" if _req["status"] == "prechecking" else "while its fix was starting"), "")
for _stale in runs.init():
    PORTAL.store.event(_stale["username"], "wi.error", _stale["check_id"],
                       f"Operation run #{_stale['id']}, site {_stale['site']}: the portal stopped while the check was running",
                       _stale.get("client_ip") or "")


def _ui_version():
    digest = hashlib.sha256()
    for name in ("static/wi.js", "static/guides.js", "../../static/guide.js", "../../static/guide.css", "static/wi.css", "templates/wi/index.html", "static/consoles/consoles.css", "static/consoles/icons.js"):
        with open(os.path.join(HERE, name), "rb") as f:
            digest.update(f.read())
    return digest.hexdigest()[:12]


UI_VERSION = _ui_version()


def json_body():
    body = request.get_json(silent=True)   # only application/json (extra protection against CSRF)
    return body if isinstance(body, dict) else {}


def session_payload():
    payload = PORTAL.payload()
    user = payload["user"]
    allowed = bool(user and MODULE in user["modules"])
    site_list = []
    if allowed:
        for name, cfg in sites.sites().items():
            site_list.append({"name": name, "openstack": bool((cfg.get("mgmt") or {}).get("host")),
                              "groups": sorted(catalog.host_groups(cfg))})
    return {"ui_version": UI_VERSION, **payload, "allowed": allowed, "sites": site_list, "kb_url": catalog.KB_URL,
            "can_fix": allowed and fixes.can_fix_any(user), "can_logs": allowed and files.can_collect(user),
            "can_fix_openstack": allowed and fixes.can_fix(user, "openstack"),
            "can_review": allowed and reviews.can_review(user), "review_minutes": reviews.get_settings()["minutes"],
            "reviews_waiting": sum(reviews.waiting_counts().values()) if allowed else 0,
            "keep_days": files.KEEP_DAYS, "is_admin": bool(user and user["role"] == "admin")}


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


def site_cfg(name):
    """Configuration of a site (sites.yml, the shared vCloud Director, addresses set on Administration -> Credentials)."""
    return access.site_config(name)


# ---------------- pages ----------------
@blueprint.get("/")
def index():
    return render_template("wi/index.html", ui_version=UI_VERSION)


@blueprint.get("/api/session")
def session():
    return jsonify(ok=True, **session_payload())


@blueprint.get("/api/catalog")
@json_api
def catalog_view():
    """Every check of the catalog, with what it needs on the selected site and the hosts it can read there."""
    user = PORTAL.require(MODULE)
    site = request.args.get("site", "")
    cfg = site_cfg(site)
    items = []
    recent = runs.recent(site) if site else {}
    for c in catalog.CATALOG["checks"] + templates.checks():   # the built-in checks, then the templates made on the portal
        item = {k: c.get(k) for k in ("id", "category", "activity", "title", "summary", "status", "reason", "link", "module",
                                      "validation", "wi", "basis", "steps", "params", "needs", "uses", "permission", "template",
                                      "does", "fix", "collect")}
        item["access"] = catalog.access(c, site, cfg, PORTAL.credential_configured)
        if c.get("permission") == files.PERMISSION and not files.can_collect(user):
            item["access"] = dict(item["access"], runnable=False, missing=item["access"]["missing"] + [files.NO_PERMISSION])
        item["hosts"] = catalog.host_options(c, cfg, site)
        item["topology"] = topology.build(c, site, cfg) if c["status"] == "ready" else {}
        item["runs"] = recent.get(c["id"], [])   # the last 10 runs on this site, newest first
        items.append(item)
    return {"site": site, "categories": catalog.CATALOG["categories"], "activities": catalog.ACTIVITIES,
            "symptoms": catalog.CATALOG["symptoms"], "checks": items}


# ---------------- run a check ----------------
def run_context(check, site, cfg, params, target=None):
    """Site data the analysis needs (not secrets): overcommit, old volume types, collectors, upstream peer, the host and
    the managers the fixes are run on (so the commands carry real names and addresses)."""
    wi = cfg.get("wi") or {}
    openstack = cfg.get("openstack") or {}
    ctx = {"site": site, "overcommit_ratio": openstack.get("overcommit_ratio", 1),
           "siem_collector": wi.get("esxi_collector" if check["id"] == "esxi-syslog" else "siem_collector", ""),
           "upstream_peer": ((cfg.get("hosts") or {}).get("huawei") or {}).get("upstream_peer", ""),
           "vyos_image_url": str(wi.get("vyos_image_url") or ""),
           "vcenter_host": str((cfg.get("vcenter") or {}).get("host") or ""),
           "nsxt_host": str((cfg.get("nsxt") or {}).get("host") or ""),
           "vcd_host": str((cfg.get("vcd") or {}).get("host") or ""),
           "vcd_brand": str((cfg.get("vcd") or {}).get("brand") or ""),
           "netapp": bool(str((cfg.get("ontap") or {}).get("host") or "")),   # the LUN copy guard reads NetApp only then
           "timezone": str(cfg.get("timezone") or "")}
    director_cfg = cfg.get("director") or {}
    ctx.update(director=str(director_cfg.get("host") or ""), horizon_host=str(openstack.get("horizon") or ""),
               ontap_host=str((cfg.get("ontap") or {}).get("host") or ""))
    # Overcloud nodes (Pacemaker, logs): the SSH user from the director (default from /etc/rhosp-release: heat-admin on
    # 16.x, tripleo-admin on 17.x) and the controller names when they do not contain "controller".
    if director_cfg.get("overcloud_user") in ("heat-admin", "tripleo-admin"):
        ctx["overcloud_user"] = director_cfg["overcloud_user"]
    if check["id"] == "cert-expiry":   # the BMCs of the page BMC (name, management IP, HTTPS port)
        ctx["bmc_targets"] = [[b["name"], b["address"], b["port"]] for b in bmcs.bmcs(site)]
        ctx["horizon_host"] = str(openstack.get("horizon") or "")
    if isinstance(director_cfg.get("controllers"), list):
        ctx["controllers"] = [str(x) for x in director_cfg["controllers"]][:9]
    if target:
        ctx.update(host_name=target["name"], host_address=target["address"], host_group=target["group"],
                   host_user=str(target.get("user") or ""), host_auth=str(target.get("auth") or ""),
                   host_port=int(target.get("port") or 22))
        if target.get("jump"):   # VyOS upgrade: the image is copied from the jump host
            ctx.update(host_jump=str(target["jump"].get("name") or ""), host_jump_address=str(target["jump"].get("address") or ""))
        if check["id"] == "vyos-upgrade":
            ctx["vyos_poll_seconds"] = int(wi.get("vyos_poll_seconds") or 15)
        if target.get("connection") == "redfish":
            ctx["bmc_vendor"] = str(target.get("vendor") or "")
            if int(target.get("port") or 443) != 443:
                ctx["host_address"] = f"{target['address']}:{target['port']}"
    if "legacy_volume_types" in openstack:
        ctx["legacy_volume_types"] = openstack.get("legacy_volume_types") or {}
    if check.get("basis") == "template":   # the steps as stored now (wi_analysis.template rates each command again)
        t = templates.get(check["id"])
        if not t:
            raise LookupError("This template was deleted.")
        ctx["template"] = templates.context(t)
    return ctx


def rest_access(check, site, cfg):
    """REST systems the check may read: {ontap|vcenter|nsxt|vcd: {ok, base, validate_certs, reason}} and the secrets."""
    out, secrets = {}, {}
    for kind, key, _label in access.KINDS:
        entry = {"ok": False, "base": "", "validate_certs": False, "reason": ""}
        if kind in check["needs"] or kind in check["uses"]:
            host = str((cfg.get(key) or {}).get("host") or "")
            if not host:
                entry["reason"] = catalog.access_problem(kind, site, cfg, PORTAL.credential_configured)
            elif not PORTAL.credential_configured(access.credential_name(kind, site)):
                entry["reason"] = catalog.access_problem(kind, site, cfg, PORTAL.credential_configured)
            else:
                cred = PORTAL.credential(access.credential_name(kind, site))
                entry.update(ok=True, base=access.base_url(cfg, key), validate_certs=bool((cfg.get(key) or {}).get("validate_certs", False)))
                if key == "vcd":
                    entry["api_version"] = access.vcd_version(cfg)
                secrets[f"{SECRET_ENV[kind]}_USER"] = cred["username"]
                secrets[f"{SECRET_ENV[kind]}_PASSWORD"] = cred["password"]
        else:
            entry["reason"] = "not used by this check"
        out[key] = entry
    return out, secrets


def owner_of(sid):
    return hashlib.sha256(str(sid).encode()).hexdigest()[:16]


def host_secrets(target):
    """A host of the page Hosts & SSH reads (and fixes) with its own credential: the key or password in the environment,
    root through sudo when the credential says so. Returns the secrets; target gets become."""
    if target and target.get("connection") == "redfish":   # a BMC: its web account, for Redfish over HTTPS
        if not target.get("credential_id"):
            raise ValueError(f"{target['name']} has no BMC credential: give it one on the page BMC.")
        cred = bmcs.secret_of(PORTAL.vault, target["credential_id"])
        return {"RUNBOOK_BMC_USER": cred["username"], "RUNBOOK_BMC_PASSWORD": cred["password"]}
    if not target or target.get("source") != "portal":
        return {}
    if not target.get("credential_id"):
        raise ValueError(f"{target['name']} has no SSH credential: give it one on Hosts & SSH.")
    cred = hosts.secret_of(PORTAL.vault, target["credential_id"])
    target["become"] = cred["privilege"] in ("sudo", "sudo_password") and target.get("connection") != "local"
    return {"RUNBOOK_SSH_SECRET": cred["secret"], **hosts.jump_secrets(PORTAL.vault, target)}


def check_key(site, check, params):
    """The job key of a check: one run of a check with the same (cleaned) params per site at a time."""
    return (site, check["id"], json.dumps(params, sort_keys=True))


def start_run(user, site, check, raw_params, client, owner, after=None, note=""):
    """Start one check (from the launch form, again after a fix, or as the pre-check of a fix request). Returns (run id,
    job id). The same check still running: refused before anything is recorded (no "Could not run" run in the history).
    after(run id, status): called when the run has ended and its result is stored; note: why it runs (activity log)."""
    cfg = site_cfg(site)
    if check["status"] != "ready":
        raise ValueError(f"{check['title']} cannot run in the portal: {check.get('reason') or check['status']}.")
    state = catalog.access(check, site, cfg, PORTAL.credential_configured)
    if not state["runnable"]:
        raise ValueError(f"{check['title']} cannot run on {site}: " + "; ".join(state["missing"]))
    if check.get("permission") == files.PERMISSION and not files.can_collect(user):
        raise portal_auth.Forbidden(files.NO_PERMISSION)
    params, target = catalog.clean_params(check, raw_params, site, cfg)
    if JOBS.busy(check_key(site, check, params)):
        raise ValueError(JOBS.busy_message)
    if check.get("bundle"):   # a log collection: refused while the portal server is short of disk
        files.ensure_room()
    rest, secrets = rest_access(check, site, cfg)
    secrets.update(host_secrets(target))
    variables = {"site": site, "check_id": check["id"], "check_params": params, "wi_ctx": run_context(check, site, cfg, params, target),
                 "rest_access": rest}
    if target:
        variables["host_target"] = target
    record = runs.begin(user["username"], site, check, params, target["name"] if target else "", client)
    files.cleanup_now_and_then()   # raw outputs and bundles older than KEEP_DAYS
    variables["raw_file"] = files.pending("run", record)
    variables["wi_ctx"]["now"] = int(time.time())   # time windows (logs, events) end when the run starts
    timeout = None
    if check.get("basis") == "template" and templates.read_wait(check):   # the waits between its read steps
        timeout = JOBS.timeouts["check"] + templates.read_wait(check)
    if check.get("bundle"):   # archives of the nodes go to the bundle folder of the run; the time window ends now
        timeout = int(check.get("timeout_minutes") or 60) * 60
        variables["bundle_dir"] = files.bundle_dir(record)
        variables["collect_timeout"] = 3600 if check["id"] == "sos-report" else max(600, timeout - 600)
        variables["wi_ctx"].update(run_id=record, keep_days=files.KEEP_DAYS)
    detail = ", ".join(f"{k}={v}" for k, v in params.items())
    PORTAL.store.event(user["username"], "wi.run", check["id"],
                       (f"Operation run #{record}, site {site}: {check['title']}" + (f" ({detail})" if detail else "")
                        + (f" — {note}" if note else ""))[:1000], client)

    def finished(job):
        try:   # everything read, masked, for the download Raw output (kept KEEP_DAYS days)
            files.keep_run(record, check["id"], params, variables["wi_ctx"])
        except Exception:
            log.exception("Operation run #%s: the raw output could not be kept", record)
        if check.get("bundle"):   # before the run shows as finished: its page then offers the download at once
            try:
                res = job.get("result") or {}
                made = files.finalize_bundle({"id": record, "site": site, "check_title": check["title"], "params": params,
                                              "username": user["username"], "status": res.get("status") or job["status"],
                                              "error": job.get("error")}, res)
                if made:
                    log.info("Operation run #%s: bundle %s (%s bytes)", record, made["name"], made["size"])
            except Exception:
                log.exception("Operation run #%s: the log bundle could not be made", record)
        status = runs.finish(record, job)
        rec = runs.get(record) or {}
        PORTAL.store.event(user["username"], f"wi.{status if status in ('ok', 'warn', 'fail', 'error') else 'error'}",
                           check["id"], (f"Operation run #{record}, site {site}: {check['title']}: "
                                         + (rec.get("summary") or rec.get("error") or ""))[:1000], client)
        log.info("Operation run #%s %s site=%s status=%s", record, check["id"], site, status)
        try:   # a run started for a Grafana alert: its result, an allowed fix by itself, the notification
            alerts.run_finished(record, status)
        except Exception:
            log.exception("Operation run #%s: the alerts could not be updated", record)
        if after:   # e.g. the pre-check of a fix request: waits for review, or fails
            try:
                after(record, status)
            except Exception:
                log.exception("Operation run #%s: what follows the run could not be done", record)
    try:
        job = JOBS.start("check", variables, secrets=secrets, playbook="run_check.yml", on_finish=finished,
                         key=check_key(site, check, params), owner=owner, user=user["username"],
                         timeout=timeout)
    except ValueError as e:
        runs.finish(record, {"status": "failed", "error": str(e), "lines": [], "result": None})
        raise
    runs.set_job(record, job["id"])
    log.info("Operation run #%s started: %s site=%s user=%s params=%s", record, check["id"], site, user["username"], params)
    return record, job["id"]


@blueprint.post("/api/runs")
@json_api
def run_check():
    user = PORTAL.require(MODULE)
    d = json_body()
    check = catalog.get(str(d.get("check") or ""))
    record, job_id = start_run(user, str(d.get("site") or ""), check, d.get("params"), PORTAL.client_address(),
                               owner_of(PORTAL.session_id()))
    return {"run_id": record, "job_id": job_id}


@blueprint.get("/api/runs")
@json_api
def run_list():
    PORTAL.require(MODULE)
    a = request.args
    status = a.get("status", "")
    fix = ""
    if status == "fix-running":   # the runs with a fix running now
        status, fix = "", "running"
    if status and status not in runs.STATUSES:
        raise ValueError("Unknown status")
    data = runs.query(a.get("limit", 50, type=int), a.get("offset", 0, type=int), a.get("user", ""), a.get("site", ""),
                      status, a.get("check", ""), a.get("q", "")[:100], fix)
    fixes_of = hosts.actions_by_runs([r["id"] for r in data["items"]])
    for r in data["items"]:
        r["fixes"] = fixes_of.get(r["id"], [])
    return data


@blueprint.get("/api/fixes/running")
@json_api
def fixes_running():
    """The fixes running now on every site (a fix keeps running on the portal server when its page is closed): the run
    it was started from, its progress (items done of the ticked ones, the item running) and how long it has run."""
    PORTAL.require(MODULE)
    _sweep()
    items = []
    for a in hosts.running_actions():
        a["progress"] = files.progress(a["id"])
        items.append(a)
    return {"items": items, "reviews_waiting": sum(reviews.waiting_counts().values())}


@blueprint.get("/api/runs/<int:run_id>")
@json_api
def run_detail(run_id):
    user = PORTAL.require(MODULE)
    item = runs.get(run_id)
    if not item:
        raise LookupError(f"Run #{run_id} not found")
    try:
        check = catalog.get(item["check_id"])
        item["wi"], item["steps_plan"] = check["wi"], check["steps"]
        item["category"] = check["category"]
    except ValueError:
        item["wi"], item["steps_plan"], check = [], [], None
    try:   # the diagram is a help: a site removed from sites.yml since the run must not hide the run itself
        item["topology"] = topology.build(check, item["site"], site_cfg(item["site"]), item.get("params") or {},
                                          item.get("result") or {}) if check else {}
    except (ValueError, LookupError):
        item["topology"] = {}
    # Fixes: which recommendations can run now for this user, and the fixes already run from this result.
    item["fixes"] = []
    if check:
        try:
            cfg = site_cfg(item["site"])
        except (ValueError, LookupError):
            cfg = None
        for i, rec in enumerate((item.get("result") or {}).get("recommendations") or []):
            item["fixes"].append(fixes.state(item, i, rec, check, cfg, user, PORTAL.credential_configured) if cfg is not None
                                 and rec.get("action") else None)
    item["actions"] = hosts.actions_of_run(run_id)
    approved = reviews.by_actions([a["id"] for a in item["actions"]])
    for a in item["actions"]:
        a["cancellable"] = fixes.cancellable(a)
        a["cancel"] = files.cancel_request(a["id"]) if a["status"] == "running" else None
        x = approved.get(a["id"])
        a["review"] = {"request_id": x["id"], "reviewed_by": x["reviewed_by"], "reviewed_at": x["reviewed_at"],
                       "precheck_run_id": x["precheck_run_id"]} if x else None
    _sweep()   # the fix requests asked from this run, and those this run is the pre-check of
    asked = reviews.query(run_id=run_id, limit=200)["items"]
    item["requests"] = [_request_view(x, user) for x in asked if x["run_id"] == run_id]
    item["precheck_of"] = [{"id": x["id"], "run_id": x["run_id"], "state": x["state"], "status": x["status"]}
                           for x in asked if x["precheck_run_id"] == run_id]
    item["files"] = {"raw": os.path.exists(files.raw_path(run_id)), "bundle": _bundle_info(run_id),
                     "can": files.can_collect(user), "keep_days": files.KEEP_DAYS}
    return {"item": item}


def _bundle_info(run_id):
    b = files.bundle(run_id)
    return {k: b[k] for k in ("name", "size", "expires")} if b else None


# ---------------- fixes ----------------
def _fix_finished(action_id, user, record, check, client, owner, check_again=True):
    def finished(job):
        result = job.get("result") or {}
        steps = result.get("steps") or []
        ok = job["status"] == "success" and bool(result.get("ok"))
        cancelled = not ok and bool(result.get("cancelled"))
        error = "" if ok else (result.get("error") or job.get("error") or "The fix did not finish.")
        try:   # the full output (the run page keeps the end of each command)
            files.keep_fix(action_id, (hosts.action(action_id) or {}).get("commands") or [])
        except Exception:
            log.exception("Fix #%s: the full output could not be kept", action_id)
        for path in (files.progress_path(action_id), files.live_path(action_id), files.cancel_path(action_id)):   # now in the fix itself
            try:
                os.remove(path)
            except OSError:
                pass
        try:   # the console screenshots go to files (a run of 300 items would make the run page far too heavy)
            steps = files.keep_shots(action_id, steps)
        except Exception:
            log.exception("Fix #%s: the console screenshots could not be kept", action_id)
            steps = [dict(st, shots=[]) for st in steps]
        status = "ok" if ok else "cancelled" if cancelled else "failed"
        hosts.action_finish(action_id, status, steps, error)
        PORTAL.store.event(user["username"], {"ok": "wi.fix_ok", "cancelled": "wi.fix_cancelled"}.get(status, "wi.fix_failed"),
                           check["id"], (f"Fix #{action_id} of troubleshooting run #{record['id']} on {record['site']} "
                                         f"{record.get('host') or ''}: {'done' if ok else error}")[:1000], client)
        log.info("Fix #%s run #%s %s: %s", action_id, record["id"], check["id"], "ok" if ok else error)
        verify = None
        if not check_again:   # a console test changes nothing the check reads
            pass
        elif job.get("signal"):   # the portal stopped (an update, a restart): the fix did not end, a check now would be cut too
            log.info("Fix #%s was stopped (signal %s): the check does not run again", action_id, job["signal"])
        else:
            verify = check_after_fix(action_id, user, record, check, client, owner)
        try:   # a fix started by itself for a Grafana alert: its result and the check after it
            alerts.fix_finished(action_id, status, error, verify)
        except Exception:
            log.exception("Fix #%s: the alerts could not be updated", action_id)
    return finished


def check_after_fix(action_id, user, record, check, client, owner, sleep=time.sleep, clock=time.time):
    """Run the check again after a fix, so its result shows whether the problem is gone. The same check still running
    (another fix of it ended just before, or someone started it): wait for it without recording anything, up to
    VERIFY_WAIT; then a run of it that started after this fix ended is this fix's check too, else one is started.
    (a real case: snapshot deletions ended together; each tried 30 times 2 s apart, and every try was a "Could not
    run" run in the history.)"""
    ended = runs.now()
    try:
        params, _target = catalog.clean_params(check, record.get("params") or {}, record["site"], site_cfg(record["site"]))
    except (ValueError, LookupError) as e:
        log.warning("Fix #%s: the check could not run again: %s", action_id, e)
        return None
    key, deadline = check_key(record["site"], check, params), clock() + VERIFY_WAIT
    while True:
        if JOBS.busy(key):
            if clock() > deadline:
                log.warning("Fix #%s: the check did not run again: the same check was still running after %s min",
                            action_id, VERIFY_WAIT // 60)
                return None
            sleep(5)
            continue
        later = runs.since(record["site"], check["id"], params, ended)
        if later:   # started after this fix ended (by another fix, or by someone): it shows this fix's result too
            hosts.action_set(action_id, verify_run_id=later)
            return later
        try:
            verify, _ = start_run(user, record["site"], check, record.get("params") or {}, client, owner)
            hosts.action_set(action_id, verify_run_id=verify)
            return verify
        except (ValueError, LookupError) as e:
            if "already running" not in str(e) or clock() > deadline:
                log.warning("Fix #%s: the check could not run again: %s", action_id, e)
                return None
            sleep(5)


@blueprint.post("/api/runs/<int:run_id>/fixes/<int:index>")
@json_api
def start_fix(run_id, index):
    """Run this fix of recommendation `index` of a stored run: a fix request and its pre-check; the fix itself runs after
    an engineer approved it (Run now, /api/fix-requests/<id>/run). Never commands from the browser."""
    user = PORTAL.require(MODULE)
    if not fixes.can_fix_any(user):
        raise portal_auth.Forbidden("Your account cannot run fixes. An administrator can allow it on the Users page.")
    _json_only()
    record = runs.get(run_id)
    if not record:
        raise LookupError(f"Run #{run_id} not found")
    return request_fix(user, record, index, json_body(), PORTAL.client_address(), owner_of(PORTAL.session_id()))


# ---------------- fix requests: pre-check, an engineer's review, Run now (reviews.py) ----------------
_REQUEST_LOCK = threading.Lock()   # one open request per fix, also when two operators press at once


def _json_only():
    """A change of a fix request comes as JSON only (the page always sends it): a form of another site cannot make one."""
    if not request.is_json:
        raise ValueError("Send the request as JSON")


def _sweep():
    """Requests whose time is over expire, each in the activity log."""
    for x in reviews.expire_due():
        PORTAL.store.event(x["username"], "wi.fix_expired", x["check_id"],
                           (f"Fix request #{x['id']} of troubleshooting run #{x['run_id']} on {x['site']} {x['target']}: expired. "
                            f"{x['reason']}")[:1000], "")
        log.info("Fix request #%s expired: %s", x["id"], x["reason"])


def _request_text(x):
    return f"Fix request #{x['id']} of troubleshooting run #{x['run_id']} on {x['site']} {x['target']} ({x['risk']} risk)"


def request_fix(user, record, index, body, client, owner):
    """The fix as the operator asked for it (the ticked items) is checked as launch_fix would, recorded as a fix
    request, and its pre-check starts: the same check again now, with the same parameters. Nothing changes."""
    _sweep()
    check = catalog.get(record["check_id"])
    recs = (record.get("result") or {}).get("recommendations") or []
    if not 0 <= index < len(recs):
        raise LookupError("No such fix in this result")
    rec, cfg = recs[index], site_cfg(record["site"])
    state = fixes.state(record, index, rec, check, cfg, user, PORTAL.credential_configured)
    if not state:
        raise ValueError("This recommendation has no fix that can run from the portal.")
    if not state["available"]:
        raise ValueError(state["reason"])
    body = body if isinstance(body, dict) else {}
    action, selected, items = rec["action"], [], None
    fp = reviews.fingerprint(action, state)
    if state.get("selectable"):
        selected, chosen, commands, deleting = fixes.selection(action, body.get("selected"))
        items = [{"label": i["label"], "commands": [str(c) for c in i["commands"]]} for i in chosen]
        state = dict(state, commands=commands, risk="high" if deleting else "normal")
    params, _target = catalog.clean_params(check, record.get("params") or {}, record["site"], cfg)
    with _REQUEST_LOCK:
        same = reviews.open_for(record["id"], index)
        if same:
            raise ValueError(f"Fix request #{same['id']} of this fix is already {same['state'].lower()}"
                             + (" (by you)" if reviews.same_person(same["username"], user["username"]) else f" (by {same['username']})")
                             + ": it goes on, or is withdrawn, before another can be asked for.")
        if JOBS.busy(check_key(record["site"], check, params)):
            raise ValueError(f"The pre-check cannot start now: {check['title']} with the same parameters is running. Press Run this "
                             "fix again when it has ended.")
        request_id = reviews.begin(user, record, index, rec.get("text", ""), state, fp, selected, items, client)
    try:
        pre, _job = start_run(user, record["site"], check, record.get("params") or {}, client, owner,
                              after=lambda run_id, _status: _precheck_done(request_id, user, items, run_id),
                              note=f"pre-check of fix request #{request_id}")
    except Exception as e:
        reviews.failed_start(request_id, f"The pre-check could not start: {e}")
        PORTAL.store.event(user["username"], "wi.fix_precheck", check["id"],
                           f"{_request_text(reviews.get(request_id))}: the pre-check could not start: {e}"[:1000], client)
        raise
    reviews.precheck_started(request_id, pre)
    what = f": {len(items)} {state['noun']} ({', '.join(i['label'] for i in items[:5])}{', …' if len(items) > 5 else ''})" if items else ""
    PORTAL.store.event(user["username"], "wi.fix_request", check["id"],
                       (f"{_request_text(reviews.get(request_id))} asked{what}: {rec.get('text', '')}. Pre-check: run #{pre} "
                        "(the check again, read-only), then an engineer's review")[:1000], client)
    log.info("Fix request #%s: run #%s fix %s, pre-check run #%s, by %s", request_id, record["id"], index, pre, user["username"])
    return {"request_id": request_id, "precheck_run_id": pre}


def _precheck_done(request_id, user, wanted, run_id):
    """The pre-check of a request ended: the same fix (same commands, the ticked items there, still allowed for the
    requester) waits for review; anything else fails the request, with why (reviews.compare)."""
    item = reviews.get(request_id)
    if not item or item["status"] != "prechecking":
        return
    run = runs.get(run_id) or {"id": run_id, "status": "error", "error": "The run is missing."}
    index, state, selected, notes, problems = None, None, [], [], []
    if run.get("status") not in ("ok", "warn", "fail", "skip"):
        problems = [f"The pre-check could not run: {run.get('error') or run.get('summary') or run.get('status')}"]
    else:
        try:
            check, cfg = catalog.get(run["check_id"]), site_cfg(run["site"])
        except (ValueError, LookupError) as e:
            check, cfg, problems = None, None, [f"The pre-check's result cannot be read: {e}"]
        if check:
            recs = (run.get("result") or {}).get("recommendations") or []
            candidates = []
            for i, rec in enumerate(recs):
                st = fixes.state(run, i, rec, check, cfg, user, PORTAL.credential_configured) if rec.get("action") else None
                if st:
                    candidates.append((i, rec["action"], st))
            index, state, selected, notes, problems = reviews.compare(item["fingerprint"], wanted, candidates)
            if state and state.get("selectable") and not problems:   # the commands that run: the items of the pre-check
                _i, chosen, _cmds, deleting = fixes.selection(recs[index]["action"], selected)
                state = dict(state, risk="high" if deleting else "normal",
                             commands=[c for k, it in enumerate(chosen) for c in [f"# {k + 1}. {it['label']}", *it["commands"]]])
    if not reviews.precheck_ended(request_id, run, index, state, selected, notes, problems):
        return
    item = reviews.get(request_id)
    PORTAL.store.event(item["username"], "wi.fix_precheck", item["check_id"],
                       (f"{_request_text(item)}: pre-check run #{run_id} "
                        + (f"failed: {' '.join(problems)}" if problems else f"passed ({' '.join(notes)}); waiting for review"))[:1000],
                       item["client_ip"] or "")
    log.info("Fix request #%s: pre-check run #%s %s", request_id, run_id, "failed" if problems else "passed")


def _request_view(x, user):
    """A request with what this user may do with it now."""
    now = datetime.datetime.now().astimezone()
    until = reviews._time(x.get("approved_until")) if x["status"] == "approved" else None
    own = reviews.same_person(x["username"], user["username"])
    fresh = reviews.fresh_until(x) if x["status"] == "waiting" else None
    return dict(x, own=own, seconds_left=max(0, int((until - now).total_seconds())) if until else None,
                review_until=reviews._iso(fresh) if fresh else None,
                can_run=bool(own and until and until > now and fixes.can_fix(user, x["kind"])),
                can_review=bool(x["status"] == "waiting" and not own and reviews.can_review(user)),
                can_withdraw=bool(own and x["status"] in ("prechecking", "waiting", "approved")),
                why_not=("You asked for this fix: another engineer reviews it." if own and x["status"] == "waiting" and reviews.can_review(user)
                         else ""))


def _reviewer():
    user = PORTAL.require(MODULE)
    if not reviews.can_review(user):
        raise portal_auth.Forbidden("Your account cannot review fixes. An administrator can allow it on the Users page "
                                    "(Runbook Automation: review fixes).")
    return user


def _request(request_id):
    item = reviews.get(request_id)
    if not item:
        raise LookupError(f"Fix request #{request_id} not found")
    return item


@blueprint.get("/api/fix-requests")
@json_api
def fix_requests():
    """The fix requests (every module user sees them; engineers review them): newest first; status "open" = pre-check
    running, waiting for review or approved."""
    user = PORTAL.require(MODULE)
    _sweep()
    a = request.args
    run_id = a.get("run_id", type=int)
    data = reviews.query(a.get("status", ""), a.get("site", ""), a.get("user", ""), a.get("limit", 50, type=int),
                         a.get("offset", 0, type=int), run_id)
    return dict(data, items=[_request_view(x, user) for x in data["items"]], settings=reviews.get_settings(),
                can_review=reviews.can_review(user), waiting=reviews.waiting_counts(), sites=sorted(sites.sites()),
                fresh_minutes=fixes.MAX_AGE_MINUTES)


@blueprint.get("/api/fix-requests/<int:request_id>")
@json_api
def fix_request_detail(request_id):
    user = PORTAL.require(MODULE)
    _sweep()
    return {"item": _request_view(_request(request_id), user)}


@blueprint.post("/api/fix-requests/<int:request_id>/approve")
@json_api
def fix_request_approve(request_id):
    """An engineer approves: the requester has Run now for the minutes set (never past the freshness of the pre-check)."""
    user = _reviewer()
    _json_only()
    _sweep()
    note = str(json_body().get("note") or "")
    try:
        x = reviews.approve(request_id, user["username"], note)
    except PermissionError as e:
        raise portal_auth.Forbidden(str(e)) from None
    until = reviews._time(x["approved_until"])
    PORTAL.store.event(user["username"], "wi.fix_approve", x["check_id"],
                       (f"{_request_text(x)} of {x['username']} approved by {user['username']} after pre-check run "
                        f"#{x['precheck_run_id']}: Run now until {until.strftime('%H:%M')} ({reviews.get_settings()['minutes']} min)"
                        + (f"; note: {x['review_note']}" if x["review_note"] else ""))[:1000], PORTAL.client_address())
    log.info("Fix request #%s approved by %s until %s", request_id, user["username"], x["approved_until"])
    return {"item": _request_view(x, user)}


@blueprint.post("/api/fix-requests/<int:request_id>/reject")
@json_api
def fix_request_reject(request_id):
    user = _reviewer()
    _json_only()
    _sweep()
    try:
        x = reviews.reject(request_id, user["username"], json_body().get("note"))
    except PermissionError as e:
        raise portal_auth.Forbidden(str(e)) from None
    PORTAL.store.event(user["username"], "wi.fix_reject", x["check_id"],
                       f"{_request_text(x)} of {x['username']} rejected by {user['username']}: {x['review_note']}"[:1000],
                       PORTAL.client_address())
    log.info("Fix request #%s rejected by %s", request_id, user["username"])
    return {"item": _request_view(x, user)}


@blueprint.post("/api/fix-requests/<int:request_id>/withdraw")
@json_api
def fix_request_withdraw(request_id):
    user = PORTAL.require(MODULE)
    _json_only()
    _sweep()
    try:
        x = reviews.withdraw(request_id, user["username"])
    except PermissionError as e:
        raise portal_auth.Forbidden(str(e)) from None
    PORTAL.store.event(user["username"], "wi.fix_withdraw", x["check_id"], f"{_request_text(x)} withdrawn by {user['username']}"[:1000],
                       PORTAL.client_address())
    return {"item": _request_view(x, user)}


@blueprint.post("/api/fix-requests/<int:request_id>/run")
@json_api
def fix_request_run(request_id):
    """Run now of an approved request, by the operator who asked for it, within its time: the fix of the pre-check's
    result (the commands reviewed), shown with the run it was asked from. A high-risk fix still needs its confirmation
    typed ("confirm"); a wrong one leaves the request approved."""
    user = PORTAL.require(MODULE)
    _json_only()
    _sweep()
    x = _request(request_id)
    if not reviews.same_person(x["username"], user["username"]):
        raise portal_auth.Forbidden(f"Only {x['username']}, who asked for fix request #{request_id}, runs it.")
    if x["status"] != "approved":
        raise ValueError(f"Fix request #{request_id} is {x['state'].lower()}" + (f": {x['reason']}" if x["reason"] else "")
                         + (" Press Run this fix again for a new pre-check and review." if x["status"] in ("expired", "rejected") else ""))
    pre, home = runs.get(x["precheck_run_id"] or 0), runs.get(x["run_id"])
    if not pre or not home:
        raise LookupError("The run of this request or its pre-check is missing.")
    if not reviews.claim(request_id):
        raise ValueError(f"Fix request #{request_id} was changed meanwhile: open it again.")
    try:
        out = launch_fix(user, pre, x["precheck_index"], {"confirm": json_body().get("confirm"), "selected": x["precheck_selected"]},
                         PORTAL.client_address(), owner_of(PORTAL.session_id()), home=(home["id"], x["rec_index"]), review=x)
    except BaseException:
        reviews.release(request_id)
        raise
    reviews.ran(request_id, out["action_id"])
    return dict(out, request_id=request_id, run_id=home["id"])


@blueprint.put("/api/fix-requests/settings")
@json_api
def fix_review_settings():
    """How long Run now stays valid after an approval (administrators; 5 to 30 minutes, default 15)."""
    user = _admin("the review of fixes")
    before, after = reviews.save_settings(json_body(), user["username"])
    _audit(user, "wi.fix_review_settings", "fix-review", f"Run now of an approved fix stays valid {before} → {after} minutes")
    return {"settings": reviews.get_settings()}


def launch_fix(user, record, index, body, client, owner, note="", home=None, review=None):
    """Start the fix of recommendation `index` of a stored run: for the operator who asked for it, after an engineer
    approved it (review: the request; record is its pre-check, home the run and recommendation it was asked from, where
    the fix is shown), or by itself for a Grafana alert (alerts: an automatic action its owner approved on the rule; note
    says why, for Activity)."""
    run_id = record["id"]
    home_run, home_index = home or (run_id, index)
    check = catalog.get(record["check_id"])
    recs = (record.get("result") or {}).get("recommendations") or []
    if not 0 <= index < len(recs):
        raise LookupError("No such fix in this result")
    rec, cfg = recs[index], site_cfg(record["site"])
    state = fixes.state(record, index, rec, check, cfg, user, PORTAL.credential_configured)
    if not state:
        raise ValueError("This recommendation has no fix that can run from the portal.")
    if not state["available"]:
        raise ValueError(state["reason"])
    if review is not None and reviews.fingerprint(rec["action"], state) != review["fingerprint"]:
        raise ValueError("The pre-check's result no longer holds the fix that was approved: press Run this fix again.")
    body = body if isinstance(body, dict) else {}
    confirm = str(body.get("confirm") or "").strip()
    action = rec["action"]
    chosen, select = None, action.get("select") if state.get("selectable") else None
    if select:   # only the ticked items, with their own commands from the stored result
        _idx, chosen, commands, deleting = fixes.selection(action, body.get("selected"))
        noun = state["noun"]
        state = dict(state, commands=commands, risk="high" if deleting else "normal",
                     confirm_text=f"{len(chosen)} {noun}")
        if deleting and confirm != state["confirm_text"]:
            raise ValueError(f"High-risk fix: type {state['confirm_text']} to confirm (the number of ticked {noun}).")
    elif state["risk"] == "high" and confirm != state["target"]:
        what = "the ID or name" if state["kind"] == "openstack" else "the host name"
        raise ValueError(f"High-risk fix: type {what} {state['target']} to confirm.")
    if state["kind"] in fixes.HOST_KINDS:
        target = fixes.target_of(record, check, cfg)
        credential = hosts.secret_of(PORTAL.vault, target["credential_id"])
        variables, secrets = fixes.host_job(target, action, credential)
        secrets.update(hosts.jump_secrets(PORTAL.vault, target))
        if state["kind"] in fixes.VYOS_KINDS:   # the VyOS upgrade / roll back: its own steps (tasks/vyos_upgrade.yml)
            variables.update(action_kind=state["kind"], vu=action["upgrade"], action_commands=["vyos upgrade"])
    elif state["kind"] == "openstack":   # as admin on the director of the site (overcloudrc), like the read-only checks
        variables = {"action_kind": "openstack", "action_commands": [str(c) for c in action.get("commands") or []]}
        if chosen:
            variables.update(action_commands=[str(c) for c in state["commands"]],
                             action_items=[{"label": i["label"], "commands": [str(c) for c in i["commands"]]} for i in chosen],
                             action_stop_rcs=[int(x) for x in select.get("stop") or [6]],
                             action_item_timeout=int(select.get("timeout") or 3600))
        secrets = {}
    else:   # ontap: revert the LIF with the Snapshot Restore account of the site
        cred = PORTAL.credential(f"ontap:{record['site']}")
        ontap = cfg.get("ontap") or {}
        variables = {"action_kind": "ontap", "ontap_op": action.get("op"), "ontap_lif_uuid": action.get("uuid"),
                     "ontap_lif": action.get("lif"), "ontap_enable": bool(action.get("enable")),
                     "ontap_hosts": [h for h in [access.base_url(cfg, "ontap")] + [f"https://{ip}" for ip in action.get("hosts") or []] if h],
                     "ontap_validate_certs": bool(ontap.get("validate_certs", False))}
        secrets = {"RUNBOOK_ONTAP_FIX_USER": cred["username"], "RUNBOOK_ONTAP_FIX_PASSWORD": cred["password"]}
    variables.update(site=record["site"], action_title=rec.get("text", "")[:200], run_id=home_run)
    title = rec.get("text", "")[:500]
    timeout, key = (OPENSTACK_FIX_TIMEOUT if state["kind"] == "openstack" else None), ("fix", record["site"], state["target"])
    if state["kind"] in fixes.VYOS_KINDS:   # copy, install, the reboot and its wait, the post-check
        timeout = int(action["upgrade"].get("wait") or 900) + 3600
    if action.get("operation") and action.get("wait"):   # the change steps of a template and their waits
        timeout = JOBS.timeouts["action"] + min(int(action["wait"]), templates.MAX_WAITS)
    if chosen:
        title = f"{state['label']}: {len(chosen)} {state['noun']} ({', '.join(i['label'] for i in chosen[:5])}" \
                f"{', …' if len(chosen) > 5 else ''}). {title}"[:500]
        # one item after the other, each up to its own time limit (wi_ops starts no change and waits no longer after it), so
        # the whole run is bounded by their sum: no cap of its own that would stop a long run (300 migrations) halfway; one
        # fix of this kind per site at a time (a lock such as "migration": never two migrations together on a site)
        timeout = len(chosen) * int(select.get("timeout") or 3600) + 1800
        key = ("fix", record["site"], select.get("lock") or state["target"])
    if review is not None:   # exactly the commands the engineer saw (both from the stored pre-check)
        shown = ([c for k, it in enumerate(chosen) for c in [f"# {k + 1}. {it['label']}", *it["commands"]]] if chosen
                 else list(state["commands"]))
        if [str(c) for c in shown] != [str(c) for c in review["precheck_commands"]]:
            raise ValueError("The commands of the pre-check's result are not the ones approved: press Run this fix again.")
    action_id = hosts.action_begin(home_run, home_index, title, state["risk"], state["target"], state["commands"], user["username"], client)
    variables["raw_file"] = files.pending("fix", action_id)
    if chosen:
        variables["progress_file"] = files.progress_path(action_id)
        if state["kind"] == "openstack":
            variables["shots_dir"] = files.items_shots_dir(action_id)
        if fixes.cancellable({"status": "running", "commands": state["commands"]}):   # read before each item
            variables["cancel_file"] = files.cancel_path(action_id)
            try:
                os.remove(variables["cancel_file"])
            except OSError:
                pass
    if state["kind"] == "openstack":   # the output of the item running now, shown on the run page while it runs
        variables["live_file"] = files.live_path(action_id)
    approved = (f" — fix request #{review['id']}, pre-check run #{run_id}, approved by {review['reviewed_by']}"
                if review is not None else "")
    PORTAL.store.event(user["username"], "wi.fix", check["id"],
                       (f"Fix #{action_id} of troubleshooting run #{home_run} on {record['site']} {state['target']} "
                        f"({state['risk']} risk): {title}" + (f" — by itself, {note}" if note else "") + approved)[:1000], client)
    try:   # the check runs again afterwards with the same parameters (the pre-check's are those of the run asked from)
        job = JOBS.start("action", variables, secrets=secrets, playbook="run_action.yml",
                         on_finish=_fix_finished(action_id, user, dict(record, id=home_run), check, client, owner),
                         key=key, owner=owner, user=user["username"], timeout=timeout)
    except ValueError as e:
        hosts.action_finish(action_id, "failed", [], str(e))
        raise
    hosts.action_set(action_id, job_id=job["id"])
    log.info("Fix #%s started: run #%s %s site=%s target=%s user=%s%s", action_id, home_run, check["id"], record["site"],
             state["target"], user["username"], f" request #{review['id']}" if review is not None else "")
    return {"action_id": action_id, "job_id": job["id"]}


@blueprint.post("/api/fixes/<int:action_id>/console-test")
@json_api
def console_test(action_id):
    """ONE Enter key on the console of an instance a finished OpenStack fix took screenshots of (wi_ops console-test:
    screenshots before and after, as an action of the same recommendation). Only an instance of that fix's screenshots,
    for an account that may run OpenStack fixes; the operator looked at the console (the dialog says what Enter does)."""
    user = PORTAL.require(MODULE)
    if not fixes.can_fix(user, "openstack"):
        raise portal_auth.Forbidden("Your account cannot run OpenStack fixes. An administrator can allow it on the Users page "
                                    "(Runbook Automation: run OpenStack fixes).")
    item = hosts.action(action_id)
    if not item:
        raise LookupError("Fix not found")
    if item["status"] == "running":
        raise ValueError(f"Fix #{action_id} is still running: test the console when it has ended.")
    server = str(json_body().get("server") or "")
    shot = next((x for st in item.get("output") or [] for x in st.get("shots") or [] if x.get("server") == server), None)
    if not shot:
        raise ValueError(f"Fix #{action_id} took no screenshot of the console of this instance.")
    record = runs.get(item["run_id"])
    if not record:
        raise LookupError(f"Run #{item['run_id']} not found")
    check, cfg = catalog.get(record["check_id"]), site_cfg(record["site"])
    if not (cfg.get("mgmt") or {}).get("host") or not (cfg.get("director") or {}).get("host"):
        raise ValueError(f"OpenStack of {record['site']} is not in sites.yml (mgmt, director).")
    command = wi_analysis.openstack_fix_command(f"console-test {server} instance {shot['instance']}")
    client, owner = PORTAL.client_address(), owner_of(PORTAL.session_id())
    title = f"Console test of {shot['instance']} (server {server}): one Enter key, screenshots before and after"
    test_id = hosts.action_begin(record["id"], item["rec_index"], title, "normal", shot["instance"], [command], user["username"], client)
    variables = {"action_kind": "openstack", "action_commands": [command], "site": record["site"], "action_title": title,
                 "run_id": record["id"], "raw_file": files.pending("fix", test_id)}
    PORTAL.store.event(user["username"], "wi.console_test", check["id"],
                       f"Fix #{test_id} of troubleshooting run #{record['id']} on {record['site']}: {title} (after fix #{action_id})"[:1000],
                       client)
    try:
        job = JOBS.start("action", variables, secrets={}, playbook="run_action.yml",
                         on_finish=_fix_finished(test_id, user, record, check, client, owner, check_again=False),
                         key=("console", record["site"], server), owner=owner, user=user["username"], timeout=CONSOLE_TEST_TIMEOUT)
    except ValueError as e:
        hosts.action_finish(test_id, "failed", [], str(e))
        raise
    hosts.action_set(test_id, job_id=job["id"])
    log.info("Console test #%s started: run #%s site=%s server=%s user=%s", test_id, record["id"], record["site"], server,
             user["username"])
    return {"action_id": test_id, "job_id": job["id"]}


@blueprint.post("/api/fixes/<int:action_id>/cancel")
@json_api
def cancel_fix(action_id):
    """Cancel a running fix with ticked items, safely: the live migration of the item running now is aborted (the
    playbook puts the flag next to its script on the director at its next read of the output; wi_ops.py aborts it, the
    instance stays on its source, a migration in post-copy runs to its end); no further item starts. Only a run of live
    migrations for now (fixes.CANCEL_OPS), for an account that may run OpenStack fixes. Asking again changes nothing."""
    user = PORTAL.require(MODULE)
    if not fixes.can_fix(user, "openstack"):
        raise portal_auth.Forbidden("Your account cannot run OpenStack fixes, so it cannot cancel them either. An administrator "
                                    "can allow it on the Users page (Runbook Automation: run OpenStack fixes).")
    item = hosts.action(action_id)
    if not item:
        raise LookupError("Fix not found")
    if item["status"] != "running":
        raise ValueError(f"Fix #{action_id} is no longer running: nothing to cancel.")
    if not fixes.cancellable(item):
        raise ValueError(f"Fix #{action_id} cannot be cancelled from the portal: for now only runs of live migrations can.")
    asked = files.cancel_request(action_id)
    if asked:
        return {"cancel": asked, "already": True}
    asked = {"by": user["username"], "at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
             "client": PORTAL.client_address()}
    path = files.cancel_path(action_id)
    with open(path + ".tmp", "w", encoding="utf-8") as f:
        json.dump(asked, f)
    os.chmod(path + ".tmp", 0o600)
    os.replace(path + ".tmp", path)
    record = runs.get(item["run_id"]) or {}
    PORTAL.store.event(user["username"], "wi.fix_cancel", record.get("check_id") or "",
                       (f"Fix #{action_id} of troubleshooting run #{item['run_id']} on {record.get('site') or ''}: cancel asked; "
                        "the live migration running now is aborted, no further item starts")[:1000], PORTAL.client_address())
    log.info("Fix #%s: cancel asked by %s", action_id, user["username"])
    return {"cancel": {"by": asked["by"], "at": asked["at"]}, "already": False}


@blueprint.get("/api/fixes/<int:action_id>/shots/<int:number>")
def fix_shot(action_id, number):
    """One console screenshot of a fix (PNG), kept files.SHOTS_KEEP_DAYS days."""
    try:
        PORTAL.require(MODULE)
    except portal_auth.NotSignedIn as e:
        return jsonify(ok=False, error=str(e)), 401
    except portal_auth.Forbidden as e:
        return jsonify(ok=False, error=str(e)), 403
    path = files.shot_path(action_id, number)
    if not os.path.exists(path):
        return jsonify(ok=False, error=f"This screenshot is no longer kept (screenshots are kept {files.SHOTS_KEEP_DAYS} days)."), 404
    return send_file(path, mimetype="image/png", max_age=3600)


@blueprint.get("/api/fixes/<int:action_id>/items/<int:item>/shots/<int:number>")
def fix_item_shot(action_id, item, number):
    """One console screenshot of an item of a fix that still runs (PNG), from what the playbook wrote as the item ended."""
    try:
        PORTAL.require(MODULE)
    except portal_auth.NotSignedIn as e:
        return jsonify(ok=False, error=str(e)), 401
    except portal_auth.Forbidden as e:
        return jsonify(ok=False, error=str(e)), 403
    shots = files.item_shots(action_id, item, with_png=True)
    if not 1 <= number <= len(shots):
        return jsonify(ok=False, error="No such screenshot (when the fix has ended, its screenshots are shown with its items)."), 404
    return send_file(io.BytesIO(base64.b64decode(shots[number - 1]["png"])), mimetype="image/png", max_age=3600)


@blueprint.get("/api/fixes/<int:action_id>")
@json_api
def fix_status(action_id):
    PORTAL.require(MODULE)
    item = hosts.action(action_id)
    if not item:
        raise LookupError("Fix not found")
    job = JOBS.get(item["job_id"]) if item.get("job_id") else None
    since = max(0, request.args.get("since", 0, type=int))
    lines = (job or {}).get("lines", [])[since:]
    running = item.get("status") == "running"
    # items done and the one running (from the playbook's progress file: complete also after the page was reopened), with
    # the console screenshots of the items done
    items = files.progress(action_id) if running else None
    for d in (items or {}).get("done") or []:
        if isinstance(d, dict) and str(d.get("n", "")).isdigit():
            d["shots"] = files.item_shots(action_id, int(d["n"]))
    item["cancellable"] = fixes.cancellable(item)
    item["cancel"] = files.cancel_request(action_id) if running else None
    return {"item": item, "lines": lines, "next": since + len(lines), "progress": items,
            # the progress bar, and the output of the item running now (OpenStack fixes: read every few seconds)
            "bar": progress.of_fix((job or {}).get("lines", []), items, not running),
            "live": files.live(action_id) if running else [],
            "elapsed": round(((job or {}).get("finished") or time.time()) - (job or {}).get("started", time.time()))}


# ---------------- Hosts & SSH (administrators) ----------------
def _admin(what="hosts and SSH credentials"):
    user = PORTAL.require(MODULE)
    if user["role"] != "admin":
        raise portal_auth.Forbidden(f"Only administrators manage {what}.")
    return user


# ---------------- Grafana alerts: Grafana sends its alerts, a rule runs a check (alerts.py) ----------------
ALERT_OWNER = owner_of("grafana-alerts")


def _alert_hooks():
    def start_check(site, check, raw, client):
        return start_run(alerts.robot(), site, check, raw, client, ALERT_OWNER)[0]

    def clean(check, raw, site):
        return catalog.clean_params(check, raw, site, site_cfg(site))[0]

    def fix_state(record, index, rec, user):
        try:
            cfg = site_cfg(record["site"])
            check = catalog.get(record["check_id"])
        except (ValueError, LookupError):
            return None
        state = fixes.state(record, index, rec, check, cfg, user, PORTAL.credential_configured)
        if state is None:
            return None
        target = fixes.target_of(record, check, cfg) if state["kind"] in fixes.HOST_KINDS else None
        # where it acts: an automatic action never runs on VMware Cloud or an ESXi host (alerts.never_reason)
        return dict(state, group=(target or {}).get("group") or "", category=check.get("category") or "")

    def start_fix(record, index, user, client, note, body=None):
        # body: the item of the automatic action and the confirmation its owner's approval stands for (alerts._launch)
        return launch_fix(user, record, index, body or {}, client, ALERT_OWNER, note=note)["action_id"]

    def measure(site, check, raw, client, since, sleep=time.sleep, clock=time.time):
        """A run of the measuring check of an automatic action: one started at or after since (the rule's own run of it
        for the alert, or one running now), else a new one; the same check running for another reason is waited for, as
        the check after a fix (check_after_fix)."""
        params = catalog.clean_params(check, raw, site, site_cfg(site))[0]
        key, deadline = check_key(site, check, params), clock() + VERIFY_WAIT
        while True:
            later = runs.since(site, check["id"], params, since)
            if later:
                return later
            if not JOBS.busy(key):
                try:
                    return start_run(alerts.robot(), site, check, raw, client, ALERT_OWNER)[0]
                except ValueError as e:
                    if "already running" not in str(e):
                        raise
            if clock() > deadline:
                raise ValueError(f"the same check was still running after {VERIFY_WAIT // 60} min")
            sleep(5)

    def audit(action, target, detail, client):
        PORTAL.store.event(alerts.ROBOT, action, target, detail, client)

    alerts.HOOKS.update(start_check=start_check, clean=clean, get_run=runs.get, fix_state=fix_state, start_fix=start_fix,
                        measure=measure, audit=audit, runs_with_fixes=runs.with_fixes)


_alert_hooks()


@blueprint.post("/api/alerts/grafana")
def alert_receive():
    """Grafana Alerting (contact point Webhook) or Prometheus Alertmanager (webhook_config) sends its alerts here. No
    portal session: the token of a source (Authorization: Bearer <token>, or the Basic password) instead, or no
    Authorization header at all from an address its source accepts without a token. A notification of an authenticated
    sender that is not Grafana's (not JSON, no alerts list) is kept as a sample for the administrator."""
    ip = request.remote_addr or ""
    try:
        source = alerts.authenticate(request.headers.get("Authorization"), ip)
        data = request.stream.read(alerts.MAX_BODY + 1)
        if len(data) > alerts.MAX_BODY:
            return jsonify(ok=False, error=f"The notification is larger than {alerts.MAX_BODY // 1024} KiB."), 413
        try:
            body = alerts.normalize(json.loads(data or b"null"))   # AlertHub's notification read as Grafana's
            reason = alerts.unreadable(body)
        except ValueError:
            reason = "The body is not JSON"
        if reason:   # another format (e.g. a webhook that is not Grafana's): kept so a mapping can be written
            alerts.record_sample(source, ip, request.headers.get("User-Agent"), request.headers.get("Content-Type"), data, reason)
            log.warning("Grafana alerts from %s (%s, %s) not read, sample kept: %s", source["name"], ip,
                        str(request.headers.get("User-Agent") or "-")[:80], reason)
            return jsonify(ok=False, error=f"{reason}. The notification was recorded for the portal administrator "
                                           "(Runbook Automation → Alerts)."), 400
        out = alerts.receive(source, body, ip)
    except alerts.Unauthorized as e:
        log.warning("Grafana alerts from %s refused: %s", ip, e)
        return jsonify(ok=False, error=str(e)), 401
    except alerts.Refused as e:
        log.warning("Grafana alerts from %s refused: %s", ip, e)
        return jsonify(ok=False, error=str(e)), 429 if isinstance(e, alerts.TooMany) else 403
    except ValueError as e:
        log.warning("Grafana alerts from %s not read: %s", ip, e)
        return jsonify(ok=False, error=str(e)), 400
    log.info("Grafana alerts from %s (%s%s): %s alert(s), %s ignored, %s check(s) started", source["name"], ip,
             ", no token" if source.get("auth") == "none" else "", out["alerts"], out["ignored"], out["checks"])
    return jsonify(ok=True, **out)


@blueprint.get("/api/alerts/metrics")
def alert_metrics():
    """Prometheus metrics of the alerts and their automatic actions, for the SRE team's Grafana: the way a failed
    automatic action reaches an operator (Grafana alerts on them, AlertHub forwards). No portal session: the token of a
    source, or no Authorization header from an address its source accepts without a token, as the receiver. Counts
    only, no targets or outcome texts."""
    ip = request.remote_addr or ""
    text = {"Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store"}
    try:
        alerts.authenticate(request.headers.get("Authorization"), ip)
    except alerts.Unauthorized as e:
        return make_response(f"{e}\n", 401, text)
    except alerts.Refused as e:
        return make_response(f"{e}\n", 403, text)
    return make_response(alerts.metrics(), 200, dict(text, **{"Content-Type": "text/plain; version=0.0.4; charset=utf-8"}))


@blueprint.get("/api/alerts")
@json_api
def alert_list():
    """The alerts received (every module user), newest first."""
    PORTAL.require(MODULE)
    a = request.args
    state = a.get("state", "")
    if state and state not in alerts.STATES + ("ignored", "all"):   # none: still firing; all: with resolved; ignored: hidden
        raise ValueError("Unknown state")
    data = alerts.events(a.get("limit", 50, type=int), a.get("offset", 0, type=int), a.get("q", "")[:100], a.get("site", ""), state)
    titles = {c["id"]: c["title"] for c in catalog.CATALOG["checks"]}
    for e in data["items"]:
        e["check_title"] = titles.get(e["check_id"] or "", e["check_id"] or "")
    return dict(data, sites=sorted(sites.sites()), connected=bool(alerts.sources()))


@blueprint.get("/api/alerts/config")
@json_api
def alert_config():
    """Rules, sources (never their tokens) and the switch of the automatic fixes (administrators)."""
    _admin("Grafana alerts")
    try:
        alerts.scan_runs()   # the fixes of the runs since the last look: a rule can get its action before its first alert
    except Exception:
        log.exception("The fixes of the recent runs could not be read")
    stats = alerts.rule_stats()
    rule_list = []
    for r in alerts.rules():
        seen = alerts.fixes_for(r["id"])
        rule_list.append(dict(r, fixes_seen=seen, stats=stats.get(r["id"]) or {},
                              approval=alerts.approval_state(r, {f["key"]: f for f in seen})))
    return {"rules": rule_list, "known_fixes": alerts.fixes_for(None), "presets": alerts.preset_list(),
            "sources": alerts.sources(), "settings": alerts.get_settings(), "checks": alerts.checks_for_rules(),
            "sites": sorted(sites.sites()), "max_checks": alerts.MAX_RULE_CHECKS, "samples": alerts.samples(),
            "max_tokenless": alerts.MAX_TOKENLESS, "max_samples": alerts.MAX_SAMPLES,
            "limits": {"auto_again_hours": alerts.AUTO_AGAIN_HOURS, "keep_days": alerts.KEEP_DAYS, "rate": alerts.RATE_PER_MINUTE,
                       "cooldown": alerts.DEFAULT_COOLDOWN, "auto_per_hour": alerts.AUTO_PER_HOUR,
                       "action_items": alerts.ACTION_ITEMS, "max_action_items": alerts.MAX_ACTION_ITEMS},
            "orders": alerts.ORDERS, "stop_defaults": alerts.STOP_DEFAULTS}


def _rule_detail(r, saved=None):
    """A rule in the activity log: what it matches and runs, its automatic actions, the owner's approval."""
    saved = saved or {}
    text = (f"Alert rule {r['name']} ({'on' if r['enabled'] else 'off'}): {r['alertname']}"
            + "".join(f", {m['label']}{m['op']}{m['value']}" for m in r["matchers"])
            + f" → {', '.join(c['check_id'] for c in r['checks'])} on {r['site']}")
    acts = []
    for n, c in enumerate(r["checks"]):
        a = c.get("action")
        if a:
            stop = r["checks"][a["measure"]]["check_id"] + "".join(f" {k}={v}" for k, v in a["thresholds"].items())
            acts.append(f"check {n + 1}: {a['title']} ({'observe only, ' if alerts.mode_of(a) == 'observe' else ''}"
                        f"{alerts.ORDERS[a['order']]}, at most {a['max_items']}, stops: {stop})"
                        + (f", then {a['then']['title']} ({alerts.ORDERS[a['then']['order']]}, at most {a['then']['max_items']})"
                           if a.get("then") else ""))
    if acts:
        text += "; automatic actions: " + "; ".join(acts)
    if saved.get("added"):
        text += "; new or changed: " + "; ".join(saved["added"])
    ap = r.get("approval") or {}
    if saved.get("approved"):
        text += (f"; customer-impacting actions approved by {ap.get('name') or ap.get('by')} ({ap.get('by')}), ticket {ap.get('ticket')}: "
                 + "; ".join(ap.get("actions") or []))
    elif saved.get("locked"):
        text += "; locked until the owner's approval is recorded: " + "; ".join(saved["locked"])
    return text[:1000]


@blueprint.post("/api/alerts/rules")
@json_api
def alert_rule_add():
    user = _admin("Grafana alerts")
    d = json_body()
    rule_id, saved = alerts.save_rule(d, user["username"], None, d.get("confirm"), d.get("ticket"), user.get("display_name"))
    r = alerts.rule(rule_id)
    _audit(user, "wi.alert_rule", r["name"], "Added: " + _rule_detail(r, saved))
    return {"id": rule_id, "locked": saved["locked"]}


@blueprint.put("/api/alerts/rules/<int:rule_id>")
@json_api
def alert_rule_update(rule_id):
    """Change a rule. A new or changed automatic action needs the rule name typed (confirm); "ticket" records the owner's
    approval of its customer-impacting actions with the administrator saving as approver (without it they are saved
    locked: the answer lists them)."""
    user = _admin("Grafana alerts")
    d = json_body()
    _id, saved = alerts.save_rule(d, user["username"], rule_id, d.get("confirm"), d.get("ticket"), user.get("display_name"))
    r = alerts.rule(rule_id)
    _audit(user, "wi.alert_rule", r["name"], "Changed: " + _rule_detail(r, saved))
    return {"id": rule_id, "locked": saved["locked"]}


@blueprint.delete("/api/alerts/rules/<int:rule_id>")
@json_api
def alert_rule_delete(rule_id):
    user = _admin("Grafana alerts")
    name = alerts.delete_rule(rule_id)
    _audit(user, "wi.alert_rule", name, f"Alert rule {name} removed")
    return {}


@blueprint.post("/api/alerts/rules/preview")
@json_api
def alert_rule_preview():
    """What a rule of the form would do with one received alert (nothing runs)."""
    _admin("Grafana alerts")
    d = json_body()
    return {"preview": alerts.preview(d.get("rule"), int(d.get("event_id") or 0))}


@blueprint.post("/api/alerts/presets/fill")
@json_api
def alert_preset_fill():
    """The form of a new rule filled from a preset (preset_id), or from the preset that fits a received alert
    (event_id); nothing is saved."""
    _admin("Grafana alerts")
    d = json_body()
    return {"rule": alerts.preset_rule(str(d.get("preset_id") or "") or None, int(d.get("event_id") or 0) or None)}


@blueprint.post("/api/alerts/<int:event_id>/ignore")
@json_api
def alert_ignore(event_id):
    """Ignore on an alert: its source ignores its exact name from now on, its alerts of that name so far are hidden."""
    user = _admin("Grafana alerts")
    src, pattern, hidden = alerts.ignore_event(event_id, user["username"])
    _audit(user, "wi.alert_source", src["name"], f"Grafana source {src['name']}: ignore alerts named {pattern} (Ignore on alert "
                                                 f"#{event_id}; {_earlier(hidden, 'hidden')}; no check runs for them)")
    return {"source": src["name"], "pattern": pattern, "hidden": hidden}


@blueprint.post("/api/alerts/<int:event_id>/unignore")
@json_api
def alert_unignore(event_id):
    """Stop ignoring on an ignored alert: the exact name pattern of Ignore goes again."""
    user = _admin("Grafana alerts")
    src, pattern, shown = alerts.unignore_event(event_id, user["username"])
    _audit(user, "wi.alert_source", src["name"], f"Grafana source {src['name']}: no longer ignores alerts named {pattern} "
                                                 f"(Stop ignoring on alert #{event_id}; {_earlier(shown, 'shown again')})")
    return {"source": src["name"], "pattern": pattern, "shown": shown}


@blueprint.post("/api/alerts/sources")
@json_api
def alert_source_add():
    """A new Grafana source; its token is in this answer only (it is stored as a hash)."""
    user = _admin("Grafana alerts")
    d = json_body()
    source_id, token = alerts.add_source(d.get("name"), d.get("networks"), user["username"], d.get("tokenless", ""), d.get("confirm"),
                                         d.get("ignore", ""))
    s = alerts.source(source_id)
    free = f"; without a token from {s['tokenless'].replace(',', ', ')}" if s["tokenless"] else ""
    hidden, _shown = alerts.apply_ignore(source_id)   # a source made again under an old name: its earlier alerts
    skip = (f"; ignores alerts named {', '.join(s['ignore'])}" + (f" ({_earlier(hidden, 'hidden')})" if hidden else "")
            if s["ignore"] else "")
    _audit(user, "wi.alert_source", s["name"], f"Grafana source {s['name']} added (from {d.get('networks') or 'anywhere'}{free}{skip})")
    return {"id": source_id, "token": token}


def _earlier(n, what):
    return f"{n} earlier alert{'' if n == 1 else 's'} {what}"


@blueprint.put("/api/alerts/sources/<int:source_id>")
@json_api
def alert_source_update(source_id):
    user = _admin("Grafana alerts")
    d = json_body()
    if "ignore" in d:
        alerts.ignore_patterns(d["ignore"])   # checked before anything is saved
    before, after = alerts.update_source(source_id, d.get("name"), d.get("networks"), d.get("enabled", True), user["username"],
                                         d.get("tokenless"), d.get("confirm"))
    skip_before, skip_after, hidden, shown = (alerts.set_ignore(source_id, d["ignore"], user["username"]) if "ignore" in d
                                              else ("", "", 0, 0))
    name = str(d.get("name") or "").strip()
    show = lambda v: v.replace(",", ", ") if v else "none"   # noqa: E731
    free = f"; accept without a token from: {show(before)} → {show(after)}" if before != after else (
        f"; without a token from {show(after)}" if after else "")
    moved = ", ".join(x for x in (_earlier(hidden, "hidden") if hidden else "", _earlier(shown, "shown again") if shown else "") if x)
    skip = (f"; ignore alerts named: {show(skip_before.replace(chr(10), ','))} → {show(skip_after.replace(chr(10), ','))}"
            + (f" ({moved})" if moved else "") if skip_before != skip_after else (f"; {moved}" if moved else ""))
    _audit(user, "wi.alert_source", name, f"Grafana source {name} changed ({'on' if d.get('enabled', True) else 'off'}, "
                                          f"from {d.get('networks') or 'anywhere'}{free}{skip})")
    return {}


@blueprint.post("/api/alerts/sources/<int:source_id>/token")
@json_api
def alert_source_token(source_id):
    """A new token for a source (the old one stops working at once); shown in this answer only."""
    user = _admin("Grafana alerts")
    token = alerts.rotate_token(source_id, user["username"])
    name = next((s["name"] for s in alerts.sources() if s["id"] == source_id), str(source_id))
    _audit(user, "wi.alert_source", name, f"Grafana source {name}: new token (the old one no longer works)")
    return {"token": token}


@blueprint.delete("/api/alerts/sources/<int:source_id>")
@json_api
def alert_source_delete(source_id):
    user = _admin("Grafana alerts")
    name = alerts.delete_source(source_id)
    _audit(user, "wi.alert_source", name, f"Grafana source {name} removed")
    return {}


@blueprint.get("/api/alerts/samples")
@json_api
def alert_samples():
    """Notifications the portal could not read (administrators: the bodies may hold anything the sender put in)."""
    _admin("Grafana alerts")
    return {"items": alerts.samples(), "max": alerts.MAX_SAMPLES}


def _read_sample(user, sample_id):
    """One sample read again (alerts.read_sample) and its activity entry; ValueError / LookupError leave it as it is."""
    x, out = alerts.read_sample(sample_id)
    _audit(user, "wi.alert_samples", x["source_name"],
           f"Sample #{sample_id} (received {x['received']} from {x['client_ip'] or '-'}) read again: {out['alerts']} alert"
           f"{'' if out['alerts'] == 1 else 's'}, {out['checks']} check{'' if out['checks'] == 1 else 's'} started"
           + (f", {out['ignored']} ignored" if out["ignored"] else ""))
    log.info("Alert sample #%s of %s read again: %s alert(s), %s ignored, %s check(s) started", sample_id, x["source_name"],
             out["alerts"], out["ignored"], out["checks"])
    return out


@blueprint.post("/api/alerts/samples/<int:sample_id>/read")
@json_api
def alert_sample_read(sample_id):
    """Read a sample again with the mapping of now: readable, it is received as a notification of its source and goes."""
    user = _admin("Grafana alerts")
    try:
        return dict(_read_sample(user, sample_id), id=sample_id)
    except alerts.Refused as e:   # the source's alerts of this minute: try again later
        raise ValueError(str(e)) from None


@blueprint.post("/api/alerts/samples/read")
@json_api
def alert_samples_read():
    """Every sample read again, oldest first (as they came): those readable now are received and go, the others stay."""
    user = _admin("Grafana alerts")
    done, left = [], []
    for x in sorted(alerts.samples(), key=lambda x: x["id"]):
        try:
            done.append(dict(_read_sample(user, x["id"]), id=x["id"]))
        except (ValueError, LookupError, alerts.Refused) as e:
            left.append({"id": x["id"], "reason": str(e)})
    return {"read": done, "left": left}


@blueprint.delete("/api/alerts/samples")
@json_api
def alert_samples_delete():
    user = _admin("Grafana alerts")
    n = alerts.delete_samples()
    _audit(user, "wi.alert_samples", "alerts", f"{n} sample{'' if n == 1 else 's'} of unreadable notifications deleted")
    return {"deleted": n}


@blueprint.put("/api/alerts/settings")
@json_api
def alert_settings_save():
    user = _admin("Grafana alerts")
    before, cfg = alerts.save_settings(json_body())
    text = f"Automatic actions of alert rules {'on' if cfg['auto_fix'] else 'paused'}"
    if before["frozen_sites"] != cfg["frozen_sites"]:
        text += (f"; sites where automatic changes never run: {', '.join(before['frozen_sites']) or '(none)'} → "
                 f"{', '.join(cfg['frozen_sites']) or '(none)'}")
    elif cfg["frozen_sites"]:
        text += f"; automatic changes never run on {', '.join(cfg['frozen_sites'])}"
    _audit(user, "wi.alert_settings", "alerts", text)
    return {"settings": cfg}


# ---------------- Templates made on the portal (administrators make them, every module user runs them) ----------------
@blueprint.get("/api/templates/meta")
@json_api
def template_meta():
    """What the template form offers: the host groups (Huawei: read-only)."""
    _admin("templates")
    return {"groups": [{"id": g, "label": label, "read_only": g in templates.READ_ONLY_GROUPS, "shell": shell}
                       for g, (label, shell) in templates.GROUPS.items()],
            "max_steps": templates.MAX_STEPS}


@blueprint.post("/api/templates/classify")
@json_api
def template_classify():
    """What each command of the form does (read / change), as the portal will rate it when the template runs."""
    _admin("templates")
    body = json_body()
    group = str(body.get("group") or "")
    commands = body.get("commands") if isinstance(body.get("commands"), list) else []
    out = []
    for cmd in commands[:templates.MAX_STEPS]:
        mode, why = templates.classify(str(cmd or "")[:templates.MAX_COMMAND], group)
        out.append({"mode": mode, "why": why})
    return {"items": out}


@blueprint.get("/api/templates/<template_id>")
@json_api
def template_detail(template_id):
    _admin("templates")
    t = templates.get(template_id)
    if not t:
        raise LookupError("Template not found.")
    return {"template": t}


@blueprint.post("/api/templates")
@json_api
def template_add():
    user = _admin("templates")
    body = json_body()
    template_id = templates.save(user["username"], body)
    t = templates.get(template_id)
    _audit(user, "wi.template", template_id, f"Template created: {t['name']} ({t['group']}, {len(t['steps'])} steps)")
    return {"id": template_id}


@blueprint.put("/api/templates/<template_id>")
@json_api
def template_update(template_id):
    user = _admin("templates")
    if not templates.get(template_id):
        raise LookupError("Template not found.")
    templates.save(user["username"], json_body(), template_id)
    t = templates.get(template_id)
    _audit(user, "wi.template", template_id, f"Template changed: {t['name']} ({t['group']}, {len(t['steps'])} steps)")
    return {"id": template_id}


@blueprint.delete("/api/templates/<template_id>")
@json_api
def template_delete(template_id):
    user = _admin("templates")
    t = templates.get(template_id)
    if not t:
        raise LookupError("Template not found.")
    templates.delete(template_id)
    _audit(user, "wi.template", template_id, f"Template deleted: {t['name']}")
    return {}


@blueprint.get("/api/hosts")
@json_api
def hosts_view():
    _admin()
    return {"hosts": hosts.hosts(), "credentials": hosts.credentials(PORTAL.vault), "groups": hosts.GROUPS,
            "privileges": hosts.PRIVILEGES, "auths": hosts.AUTHS, "sites": sorted(sites.sites())}


def _audit(user, action, target, detail):
    PORTAL.store.event(user["username"], action, target, detail, PORTAL.client_address())


@blueprint.post("/api/credentials")
@json_api
def credential_add():
    user = _admin()
    body = json_body()
    cred_id = hosts.save_credential(PORTAL.vault, user["username"], body)
    _audit(user, "wi.ssh_credential", body.get("name", ""), f"SSH credential added ({body.get('auth')}, {body.get('privilege')}, "
                                                         f"fixes {'allowed' if body.get('fixes') else 'not allowed'})")
    return {"id": cred_id}


@blueprint.put("/api/credentials/<int:cred_id>")
@json_api
def credential_update(cred_id):
    user = _admin()
    body = json_body()
    hosts.save_credential(PORTAL.vault, user["username"], body, cred_id)
    _audit(user, "wi.ssh_credential", body.get("name", ""), f"SSH credential changed{' (new key/password)' if body.get('secret') else ''}"
                                                         f", fixes {'allowed' if body.get('fixes') else 'not allowed'}")
    return {"id": cred_id}


@blueprint.delete("/api/credentials/<int:cred_id>")
@json_api
def credential_delete(cred_id):
    user = _admin()
    name = hosts.delete_credential(cred_id)
    _audit(user, "wi.ssh_credential", name, "SSH credential removed")
    return {}


@blueprint.post("/api/hosts")
@json_api
def host_add():
    user = _admin()
    body = json_body()
    host_id = hosts.save_host(user["username"], body)
    _audit(user, "wi.host", body.get("name", ""), f"Host added: {body.get('site')} {body.get('group')} {body.get('address')}")
    return {"id": host_id}


@blueprint.post("/api/hosts/bulk")
@json_api
def host_add_many():
    user = _admin()
    body = json_body()
    count = hosts.add_many(user["username"], body)
    _audit(user, "wi.host", f"{body.get('site')} {body.get('group')}", f"{count} hosts added at once")
    return {"added": count}


@blueprint.put("/api/hosts/<int:host_id>")
@json_api
def host_update(host_id):
    user = _admin()
    body = json_body()
    hosts.save_host(user["username"], body, host_id)
    _audit(user, "wi.host", body.get("name", ""), f"Host changed: {body.get('site')} {body.get('group')} {body.get('address')}")
    return {"id": host_id}


@blueprint.delete("/api/hosts/<int:host_id>")
@json_api
def host_delete(host_id):
    user = _admin()
    name = hosts.delete_host(host_id)
    _audit(user, "wi.host", name, "Host removed")
    return {}


@blueprint.post("/api/hosts/<int:host_id>/test")
@json_api
def host_test(host_id):
    """Connect with the host's credential and run read commands only (hostname, user, root through sudo)."""
    _admin()
    row = next((h for h in hosts.hosts() if h["id"] == host_id), None)
    if not row:
        raise LookupError("Host not found")
    target = catalog.resolve_host(row["site"], site_cfg(row["site"]), [row["grp"]], row["name"])
    if not target.get("credential_id"):
        raise ValueError(f"{row['name']} has no SSH credential.")
    credential = hosts.secret_of(PORTAL.vault, target["credential_id"])
    variables, secrets = fixes.host_job(target, {"commands": ["hostname", "id -un", "uptime"]}, credential)
    secrets.update(hosts.jump_secrets(PORTAL.vault, target))
    variables.update(site=row["site"], action_title=f"Connection test of {row['name']}", run_id=0)
    job = JOBS.start("action", variables, secrets=secrets, playbook="run_action.yml", key=("test", row["site"], row["name"]),
                     owner=owner_of(PORTAL.session_id()), user=PORTAL.require(MODULE)["username"])
    return {"job_id": job["id"]}


# ---------------- BMC (administrators): the BMC web accounts and the management IP of each server ----------------
def _bmc_admin():
    user = PORTAL.require(MODULE)
    if user["role"] != "admin":
        raise portal_auth.Forbidden("Only administrators manage BMCs and their accounts.")
    return user


@blueprint.get("/api/bmc")
@json_api
def bmc_view():
    _bmc_admin()
    return {"bmcs": bmcs.bmcs(), "credentials": bmcs.credentials(), "vendors": bmcs.VENDORS, "sites": sorted(sites.sites())}


@blueprint.post("/api/bmc/credentials")
@json_api
def bmc_credential_add():
    user = _bmc_admin()
    body = json_body()
    cred_id = bmcs.save_credential(PORTAL.vault, user["username"], body)
    _audit(user, "wi.bmc_credential", body.get("name", ""), f"BMC credential added (user {body.get('username', '')})")
    return {"id": cred_id}


@blueprint.put("/api/bmc/credentials/<int:cred_id>")
@json_api
def bmc_credential_update(cred_id):
    user = _bmc_admin()
    body = json_body()
    bmcs.save_credential(PORTAL.vault, user["username"], body, cred_id)
    _audit(user, "wi.bmc_credential", body.get("name", ""), "BMC credential changed" + (" (new password)" if body.get("secret") else ""))
    return {"id": cred_id}


@blueprint.delete("/api/bmc/credentials/<int:cred_id>")
@json_api
def bmc_credential_delete(cred_id):
    user = _bmc_admin()
    name = bmcs.delete_credential(cred_id)
    _audit(user, "wi.bmc_credential", name, "BMC credential removed")
    return {}


@blueprint.post("/api/bmc")
@json_api
def bmc_add():
    user = _bmc_admin()
    body = json_body()
    bmc_id = bmcs.save_bmc(user["username"], body)
    _audit(user, "wi.bmc", body.get("name", ""), f"BMC added: {body.get('site')} {body.get('address')}")
    return {"id": bmc_id}


@blueprint.post("/api/bmc/bulk")
@json_api
def bmc_add_many():
    user = _bmc_admin()
    body = json_body()
    count = bmcs.add_many(user["username"], body)
    _audit(user, "wi.bmc", str(body.get("site") or ""), f"{count} BMCs added at once")
    return {"added": count}


@blueprint.put("/api/bmc/<int:bmc_id>")
@json_api
def bmc_update(bmc_id):
    user = _bmc_admin()
    body = json_body()
    bmcs.save_bmc(user["username"], body, bmc_id)
    _audit(user, "wi.bmc", body.get("name", ""), f"BMC changed: {body.get('site')} {body.get('address')}")
    return {"id": bmc_id}


@blueprint.delete("/api/bmc/<int:bmc_id>")
@json_api
def bmc_delete(bmc_id):
    user = _bmc_admin()
    name = bmcs.delete_bmc(bmc_id)
    _audit(user, "wi.bmc", name, "BMC removed")
    return {}


@blueprint.get("/api/jobs/<job_id>")
@json_api
def job_status(job_id):
    PORTAL.require(MODULE)
    job = JOBS.get(job_id)
    if not job:
        raise LookupError("Job not found (the portal may have been restarted)")
    since = max(0, request.args.get("since", 0, type=int))
    lines = job["lines"][since:]
    done = job["status"] != "running"
    if job["kind"] == "check":   # the progress bar: how far, what runs now, the last tasks
        try:
            phases = wi_analysis.plan(job["params"].get("check_id"))["phases"]
        except (ValueError, KeyError, TypeError):
            phases = 1
        bar = progress.of_check(job["lines"], phases, done)
    else:
        bar = progress.of_fix(job["lines"], None, done)
    return {"id": job["id"], "status": job["status"], "task": job["task"], "lines": lines, "next": since + len(lines),
            "error": job["error"], "result": job["result"] if done else None, "progress": bar,
            "elapsed": round((job["finished"] or time.time()) - job["started"])}


def _run_for_export(run_id):
    PORTAL.require(MODULE)
    item = runs.get(run_id)
    if not item:
        raise LookupError(f"Run #{run_id} not found")
    if item.get("status") == "running":
        raise ValueError(f"Run #{run_id} is still running")
    return item


def _export_error(e):
    code = 401 if isinstance(e, portal_auth.NotSignedIn) else 403 if isinstance(e, portal_auth.Forbidden) else \
        404 if isinstance(e, LookupError) else 400
    return jsonify(ok=False, error=str(e)), code


@blueprint.get("/export/runs/<int:run_id>.csv")
def run_result_csv(run_id):
    """One result as CSV: the tables of every step (CPU / memory / disk / pool values and their status) and the fixes."""
    try:
        item = _run_for_export(run_id)
    except (portal_auth.NotSignedIn, portal_auth.Forbidden, LookupError, ValueError) as e:
        return _export_error(e)
    resp = make_response(runs.result_csv(item))
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    name = "".join(ch if ch.isalnum() else "_" for ch in item["check_id"])
    resp.headers["Content-Disposition"] = f'attachment; filename="Run_{run_id}_{name}_{item["site"]}.csv"'
    return resp


@blueprint.get("/export/runs/<int:run_id>/raw.zip")
def run_raw_zip(run_id):
    """Raw output of one run (permission collect logs): every command / path the check read with its full output, the
    result, the Ansible log and the full output of each fix run from it. Secrets are masked."""
    try:
        item = _run_for_export(run_id)
        user = PORTAL.require(MODULE)
        if not files.can_collect(user):
            raise portal_auth.Forbidden(files.NO_PERMISSION)
    except (portal_auth.NotSignedIn, portal_auth.Forbidden, LookupError, ValueError) as e:
        return _export_error(e)
    data = files.raw_zip(item, hosts.actions_of_run(run_id), extra=_raw_extra(item))
    PORTAL.store.event(user["username"], "wi.download", item["check_id"],
                       f"Raw output of operation run #{run_id} ({item['site']}) downloaded", PORTAL.client_address())
    resp = make_response(data)
    resp.headers["Content-Type"] = "application/zip"
    name = "".join(ch if ch.isalnum() else "_" for ch in item["check_id"])
    resp.headers["Content-Disposition"] = f'attachment; filename="Run_{run_id}_{name}_{item["site"]}_raw.zip"'
    return resp


def _raw_extra(item):
    """Files a check adds to its raw output (every entry of an event log as CSV), made from the reads kept for the run."""
    from .wi_analysis import export_files
    try:
        return {str(k): str(v) for k, v in export_files(item["check_id"], files.raw_data(item["id"]), item.get("params")).items()}
    except Exception as e:   # the rest of the raw output is still useful
        log.warning("Run #%s: export files could not be made: %r", item["id"], e)
        return {"export-error.txt": f"The export files could not be made: {e!r}"}


@blueprint.get("/export/runs/<int:run_id>/bundle")
def run_bundle(run_id):
    """The log bundle of a Collect logs / sos report run (permission collect logs), streamed from the portal server."""
    try:
        item = _run_for_export(run_id)
        user = PORTAL.require(MODULE)
        if not files.can_collect(user):
            raise portal_auth.Forbidden(files.NO_PERMISSION)
        b = files.bundle(run_id)
        if not b:
            raise LookupError(f"Run #{run_id} has no log bundle (bundles are deleted {files.KEEP_DAYS} days after they were made).")
    except (portal_auth.NotSignedIn, portal_auth.Forbidden, LookupError, ValueError) as e:
        return _export_error(e)
    PORTAL.store.event(user["username"], "wi.download", item["check_id"],
                       f"Log bundle {b['name']} of operation run #{run_id} ({item['site']}) downloaded", PORTAL.client_address())
    return send_file(b["path"], as_attachment=True, download_name=b["name"],
                     mimetype="application/gzip" if b["name"].endswith(".gz") else "application/x-tar", max_age=0)


@blueprint.get("/runs/<int:run_id>/report")
def run_report(run_id):
    """One result as a printable report (A4, light): the browser saves it as PDF (Print → Save as PDF)."""
    try:
        item = _run_for_export(run_id)
    except (portal_auth.NotSignedIn, portal_auth.Forbidden, LookupError, ValueError) as e:
        return _export_error(e)
    try:
        check = catalog.get(item["check_id"])
    except ValueError:
        check = {"wi": [], "category": ""}
    user = PORTAL.require(MODULE)

    def when(value):
        try:
            return datetime.datetime.fromisoformat(str(value)).strftime("%d %b %Y %H:%M:%S (UTC%z)").replace("(UTC+0700)", "WIB")
        except ValueError:
            return str(value or "-")
    item = dict(item, ts=when(item.get("ts")), finished=when(item.get("finished")) if item.get("finished") else "")
    return render_template("wi/report.html", item=item, res=item.get("result") or {}, wi=check.get("wi") or [],
                           words=runs.STATUS_WORDS, printed_by=user["username"],
                           printed=datetime.datetime.now().astimezone().strftime("%d %b %Y %H:%M %Z"),
                           auto_print=request.args.get("print") == "1")


@blueprint.get("/export/runs.csv")
def run_export():
    try:
        PORTAL.require(MODULE)
        a = request.args
        status = a.get("status", "")
        if status and status not in runs.STATUSES:
            raise ValueError("Unknown status")
        rows = runs.all_rows(a.get("user", ""), a.get("site", ""), status, a.get("check", ""), a.get("q", "")[:100])
    except portal_auth.NotSignedIn as e:
        return jsonify(ok=False, error=str(e)), 401
    except portal_auth.Forbidden as e:
        return jsonify(ok=False, error=str(e)), 403
    except ValueError as e:
        return jsonify(ok=False, error=str(e)), 400
    resp = make_response(runs.to_csv(rows))
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = f'attachment; filename="Operation_Automation_Runs_{datetime.datetime.now():%Y%m%d-%H%M}.csv"'
    return resp

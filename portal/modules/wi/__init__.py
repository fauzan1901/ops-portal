"""Operation Automation module (/wi/): read-only checks from the Knowledge Base work instructions, run with Ansible.

The operator picks a check from the catalog (one or more WI pages), the site and the parameters of the alert; the
portal runs playbooks/run_check.yml and shows the result per WI step (OK / warning / problem / skipped) with the
evidence, how to fix it (commands with the values found and where to run them), and the full Ansible output. Nothing is changed on any system.
"""
import datetime
import functools
import hashlib
import json
import logging
import os
import time

from flask import Blueprint, jsonify, make_response, render_template, request, send_file

import jobs
import portal_auth
import sites
from core import PORTAL, register

from . import access, bmcs, catalog, files, fixes, hosts, progress, runs, templates, topology, wi_analysis

log = logging.getLogger("portal.wi")
HERE = os.path.dirname(os.path.abspath(__file__))
PLAYBOOK_DIR = os.path.join(HERE, "playbooks")
MODULE = "wi"
TITLE = "Operation Automation"
JOBS = jobs.Jobs(PLAYBOOK_DIR, {"check": int(os.environ.get("WI_CHECK_TIMEOUT_SECONDS", "600")),
                               "action": int(os.environ.get("WI_FIX_TIMEOUT_SECONDS", "1800"))},   # OpenStack: see below
                 busy_message=("The same check, a fix on the same host, or a fix of the same kind on this site (migrations and image "
                               "clean-ups run one at a time per site) is already running. Open it from Runs."),
                 timeout_message="The {timeout}-second time limit was reached; the check was stopped.")
# OpenStack fixes retype / migrate volumes one after the other and wait for each: hours for large volumes.
OPENSTACK_FIX_TIMEOUT = int(os.environ.get("WI_OPENSTACK_FIX_TIMEOUT_SECONDS", "28800"))
SECRET_ENV = {"ontap": "WI_ONTAP", "ro-vcenter": "WI_VCENTER", "ro-nsxt": "WI_NSXT", "ro-vcd": "WI_VCD"}

blueprint = Blueprint(MODULE, __name__, url_prefix="/wi", template_folder="templates", static_folder="static",
                      static_url_path="/static")
register(MODULE, TITLE, "Checks from the Knowledge Base work instructions and platform health (OpenStack, VMware, NSX-T, BMC), with Ansible; fixes on SSH hosts, ONTAP and OpenStack.",
         "/wi/", "checklist", targets=access.targets, tester=access.test, running_jobs=JOBS.running,
         permissions=[{"id": fixes.PERMISSION, "title": "Operation Automation: run fixes (SSH hosts, ONTAP)"},
                      {"id": fixes.OPENSTACK_PERMISSION, "title": "Operation Automation: run OpenStack fixes (Acme Flex)"},
                      {"id": files.PERMISSION, "title": "Operation Automation: collect logs (log bundles, sos report, raw output)"}])

hosts.init()
bmcs.init()
templates.init()
files.cleanup()
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
        return {"WI_BMC_USER": cred["username"], "WI_BMC_PASSWORD": cred["password"]}
    if not target or target.get("source") != "portal":
        return {}
    if not target.get("credential_id"):
        raise ValueError(f"{target['name']} has no SSH credential: give it one on Hosts & SSH.")
    cred = hosts.secret_of(PORTAL.vault, target["credential_id"])
    target["become"] = cred["privilege"] in ("sudo", "sudo_password") and target.get("connection") != "local"
    return {"WI_SSH_SECRET": cred["secret"], **hosts.jump_secrets(PORTAL.vault, target)}


def start_run(user, site, check, raw_params, client, owner):
    """Start one check (from the launch form, or again after a fix). Returns (run id, job id)."""
    cfg = site_cfg(site)
    if check["status"] != "ready":
        raise ValueError(f"{check['title']} cannot run in the portal: {check.get('reason') or check['status']}.")
    state = catalog.access(check, site, cfg, PORTAL.credential_configured)
    if not state["runnable"]:
        raise ValueError(f"{check['title']} cannot run on {site}: " + "; ".join(state["missing"]))
    if check.get("permission") == files.PERMISSION and not files.can_collect(user):
        raise portal_auth.Forbidden(files.NO_PERMISSION)
    params, target = catalog.clean_params(check, raw_params, site, cfg)
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
                       f"Operation run #{record}, site {site}: {check['title']}" + (f" ({detail})" if detail else ""), client)

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
    try:
        job = JOBS.start("check", variables, secrets=secrets, playbook="run_check.yml", on_finish=finished,
                         key=(site, check["id"], json.dumps(params, sort_keys=True)), owner=owner, user=user["username"],
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
    items = []
    for a in hosts.running_actions():
        a["progress"] = files.progress(a["id"])
        items.append(a)
    return {"items": items}


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
    item["files"] = {"raw": os.path.exists(files.raw_path(run_id)), "bundle": _bundle_info(run_id),
                     "can": files.can_collect(user), "keep_days": files.KEEP_DAYS}
    return {"item": item}


def _bundle_info(run_id):
    b = files.bundle(run_id)
    return {k: b[k] for k in ("name", "size", "expires")} if b else None


# ---------------- fixes ----------------
def _fix_finished(action_id, user, record, check, client, owner):
    def finished(job):
        result = job.get("result") or {}
        steps = result.get("steps") or []
        ok = job["status"] == "success" and bool(result.get("ok"))
        error = "" if ok else (result.get("error") or job.get("error") or "The fix did not finish.")
        try:   # the full output (the run page keeps the end of each command)
            files.keep_fix(action_id, (hosts.action(action_id) or {}).get("commands") or [])
        except Exception:
            log.exception("Fix #%s: the full output could not be kept", action_id)
        for path in (files.progress_path(action_id), files.live_path(action_id)):   # now in the fix itself
            try:
                os.remove(path)
            except OSError:
                pass
        hosts.action_finish(action_id, "ok" if ok else "failed", steps, error)
        PORTAL.store.event(user["username"], "wi.fix_ok" if ok else "wi.fix_failed", check["id"],
                           (f"Fix #{action_id} of troubleshooting run #{record['id']} on {record['site']} "
                            f"{record.get('host') or ''}: {'done' if ok else error}")[:1000], client)
        log.info("Fix #%s run #%s %s: %s", action_id, record["id"], check["id"], "ok" if ok else error)
        # check again, so the result shows whether the problem is gone (a check still running from an earlier fix: wait)
        for attempt in range(30):
            try:
                verify, _ = start_run(user, record["site"], check, record.get("params") or {}, client, owner)
                hosts.action_set(action_id, verify_run_id=verify)
                break
            except (ValueError, LookupError) as e:
                if attempt == 29 or "already running" not in str(e):
                    log.warning("Fix #%s: the check could not run again: %s", action_id, e)
                    break
                time.sleep(2)
    return finished


@blueprint.post("/api/runs/<int:run_id>/fixes/<int:index>")
@json_api
def start_fix(run_id, index):
    """Run the fix of recommendation `index` of a stored run (its own commands, never commands from the browser)."""
    user = PORTAL.require(MODULE)
    if not fixes.can_fix_any(user):
        raise portal_auth.Forbidden("Your account cannot run fixes. An administrator can allow it on the Users page.")
    record = runs.get(run_id)
    if not record:
        raise LookupError(f"Run #{run_id} not found")
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
    body = json_body()
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
    client, owner = PORTAL.client_address(), owner_of(PORTAL.session_id())
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
    else:   # ontap: revert the LIF with the ONTAP Restore account of the site
        cred = PORTAL.credential(f"ontap:{record['site']}")
        ontap = cfg.get("ontap") or {}
        variables = {"action_kind": "ontap", "ontap_op": action.get("op"), "ontap_lif_uuid": action.get("uuid"),
                     "ontap_lif": action.get("lif"), "ontap_enable": bool(action.get("enable")),
                     "ontap_hosts": [h for h in [access.base_url(cfg, "ontap")] + [f"https://{ip}" for ip in action.get("hosts") or []] if h],
                     "ontap_validate_certs": bool(ontap.get("validate_certs", False))}
        secrets = {"WI_ONTAP_FIX_USER": cred["username"], "WI_ONTAP_FIX_PASSWORD": cred["password"]}
    variables.update(site=record["site"], action_title=rec.get("text", "")[:200], run_id=run_id)
    title = rec.get("text", "")[:500]
    timeout, key = (OPENSTACK_FIX_TIMEOUT if state["kind"] == "openstack" else None), ("fix", record["site"], state["target"])
    if state["kind"] in fixes.VYOS_KINDS:   # copy, install, the reboot and its wait, the post-check
        timeout = int(action["upgrade"].get("wait") or 900) + 3600
    if action.get("operation") and action.get("wait"):   # the change steps of a template and their waits
        timeout = JOBS.timeouts["action"] + min(int(action["wait"]), templates.MAX_WAITS)
    if chosen:
        title = f"{state['label']}: {len(chosen)} {state['noun']} ({', '.join(i['label'] for i in chosen[:5])}" \
                f"{', …' if len(chosen) > 5 else ''}). {title}"[:500]
        # one item after the other, each up to its own time limit; one fix of this kind per site at a time (a lock such as
        # "migration": never two migrations together on a site)
        timeout = min(86400, len(chosen) * int(select.get("timeout") or 3600) + 1800)
        key = ("fix", record["site"], select.get("lock") or state["target"])
    action_id = hosts.action_begin(run_id, index, title, state["risk"], state["target"], state["commands"], user["username"], client)
    variables["raw_file"] = files.pending("fix", action_id)
    if chosen:
        variables["progress_file"] = files.progress_path(action_id)
    if state["kind"] == "openstack":   # the output of the item running now, shown on the run page while it runs
        variables["live_file"] = files.live_path(action_id)
    PORTAL.store.event(user["username"], "wi.fix", check["id"],
                       (f"Fix #{action_id} of troubleshooting run #{run_id} on {record['site']} {state['target']} "
                        f"({state['risk']} risk): {title}")[:1000], client)
    try:
        job = JOBS.start("action", variables, secrets=secrets, playbook="run_action.yml",
                         on_finish=_fix_finished(action_id, user, record, check, client, owner),
                         key=key, owner=owner, user=user["username"], timeout=timeout)
    except ValueError as e:
        hosts.action_finish(action_id, "failed", [], str(e))
        raise
    hosts.action_set(action_id, job_id=job["id"])
    log.info("Fix #%s started: run #%s %s site=%s target=%s user=%s", action_id, run_id, check["id"], record["site"],
             state["target"], user["username"])
    return {"action_id": action_id, "job_id": job["id"]}


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
    # items done and the one running (from the playbook's progress file: complete also after the page was reopened)
    items = files.progress(action_id) if running else None
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

"""ONTAP Restore module of the Ops Portal (/ontap/): restore OpenStack volumes from NetApp ONTAP snapshots, run
with Ansible. Sign-in, users, module access and the ONTAP service accounts belong to the portal (core.PORTAL)."""
import datetime
import functools
import hashlib
import logging
import os
import re
import sqlite3
import threading
import time

from flask import Blueprint, jsonify, make_response, render_template, request

import jobs as portal_jobs
import portal_auth
from core import PORTAL, register

from . import config, deletions, history, ontap_api

MODULE_ID = "ontap"
TITLE = "ONTAP Restore"
log = logging.getLogger("portal.ontap")
blueprint = Blueprint(MODULE_ID, __name__, url_prefix=f"/{MODULE_ID}", template_folder="templates",
                      static_folder="static", static_url_path="/static")

TIMEOUTS = {"plan": int(os.environ.get("ONTAP_PLAN_TIMEOUT_SECONDS", "300")),
            "restore": int(os.environ.get("ONTAP_RESTORE_TIMEOUT_SECONDS", "14400")),
            "volume_info": int(os.environ.get("ONTAP_INFO_TIMEOUT_SECONDS", "240")),
            "delete_volume": int(os.environ.get("ONTAP_DELETE_TIMEOUT_SECONDS", "600"))}


class OntapJobs(portal_jobs.Jobs):
    """Ansible jobs of this module (playbooks/). The site's ONTAP service account reaches the playbook as the
    environment variables ONTAP_USER and ONTAP_PASSWORD only (never on the command line or on disk)."""

    def start(self, kind, user, password, params, key=None, on_finish=None, owner="", timeout=None):
        """Start a 'plan', 'restore', 'volume_info' or 'delete_volume' job. key: one job per key (for example site +
        volume) at a time. owner: tag of the portal session that created the job (see owner_of). timeout: seconds
        (default TIMEOUTS)."""
        return super().start(kind, params, secrets={"ONTAP_USER": user, "ONTAP_PASSWORD": password}, key=key,
                             on_finish=on_finish, owner=owner, timeout=timeout, user=user)


JOBS = OntapJobs(config.PLAYBOOK_DIR, TIMEOUTS,
                 busy_message="A job for this volume is already running. Wait until it finishes.",
                 timeout_message="The {timeout}-second time limit was reached; the job was stopped. Check ONTAP and OpenStack.")
PLAN_MAX_AGE_SECONDS = 1800
INFO_WAIT_SECONDS = 150   # wait for the volume_info job (SSH to management -> director) in the Find LUN step
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
PROJECT_RE = re.compile(r"^[0-9A-Za-z_-]{8,64}$")
SNAPSHOT_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,255}$")
VOLUME_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
INSTANCE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
POST_ACTIONS = ("none", "attach", "instance")
MAX_GROUP_VOLUMES = 8   # volumes of one instance restored together
INTERRUPTED = history.init()   # restores that were running when the portal stopped (logged below)
deletions.init()


# ---------------- Service accounts (portal Administration -> Credentials) ----------------
def credential_targets():
    """One ONTAP service account per site in sites.yml (entered by administrators on Administration -> Credentials)."""
    return [{"name": f"ontap:{name}", "label": f"ONTAP {name}", "host": str((cfg.get("ontap") or {}).get("host") or ""),
             "kind": "ontap", "site": name} for name, cfg in config.sites().items()]


def test_credential(target, username, password):
    """Connection test after an administrator saves a service account (read-only: GET /api/cluster)."""
    site_cfg = config.sites().get(target["site"])
    if site_cfg is None:
        raise ValueError(f"Site {target['site']} is no longer in sites.yml")
    info = ontap_api.cluster(site_cfg, username, password)
    return f"Connected to cluster {info['name'] or '?'} ({info['version'] or 'unknown version'})"


register(MODULE_ID, TITLE, "Restore OpenStack volumes from NetApp ONTAP snapshots, with Ansible.", f"/{MODULE_ID}/",
         "database", targets=credential_targets, tester=test_credential, running_jobs=JOBS.running)
for _rec in INTERRUPTED:
    PORTAL.store.event(_rec["username"], "restore.unknown", _rec["volume_id"],
                       f"restore #{_rec['id']}, site {_rec['site']}: the web app stopped while the restore was running; "
                       "check the LUN and volume in ONTAP and OpenStack", _rec.get("client_ip") or "")


def _ui_version():
    """Fingerprint of the module UI files; it changes with every new version, so an old tab knows it must reload."""
    digest = hashlib.sha256()
    for name in ("static/app.js", "static/app.css", "static/guides.js", "../../static/guide.js", "../../static/guide.css",
                 "templates/ontap/index.html"):
        with open(os.path.join(blueprint.root_path, name), "rb") as f:
            digest.update(f.read())
    return digest.hexdigest()[:12]


UI_VERSION = _ui_version()


# ---------------- Helper ----------------
def session_payload():
    """/ontap/api/session: the signed-in user, how sign-in works, whether this account may use ONTAP Restore, and the
    sites (with or without a service account). Sites and their ONTAP addresses are only listed for an allowed user."""
    signed_in = PORTAL.payload()
    user = signed_in["user"]
    allowed = bool(user) and MODULE_ID in (user.get("modules") or [])
    sites = config.sites() if allowed else {}
    return {"ui_version": UI_VERSION, **signed_in, "allowed": allowed,
            "sites": [{"name": name, "host": str((cfg.get("ontap") or {}).get("host") or ""),
                       "configured": PORTAL.credential_configured(f"ontap:{name}")} for name, cfg in sites.items()]}


def owner_of(sid):
    """Owner tag of a job (hash of the portal session), so a plan can only be executed from the session that created it."""
    return hashlib.sha256(str(sid).encode()).hexdigest()[:16]


def json_body():
    # No force=True: only application/json is accepted (extra protection against CSRF).
    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else {}


def pick_site(name):
    """Configuration and ONTAP service account of a site. The service account is the same for every operator;
    portal_auth.CredentialError (a ValueError, so HTTP 400) when an administrator has not set it yet."""
    sites = config.sites()
    if name not in sites:
        raise ValueError(f"Unknown site: {name!r}")
    return sites[name], PORTAL.credential(f"ontap:{name}")


def service_account_refused(site, creds, error):
    """ONTAP answered 401 to the stored service account: operators cannot fix that themselves."""
    return ontap_api.OntapError(f"ONTAP {site} refused the service account {creds['username']} ({error}). "
                                "An administrator must update it in Administration → Credentials.")


def volume_id_from(value):
    volume_id = str(value or "").strip().lower()
    if not UUID_RE.match(volume_id):
        raise ValueError("The volume ID must be an OpenStack UUID, for example a80a1a07-06b8-489b-a984-b046981f68b9")
    return volume_id


def json_api(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        try:
            return jsonify(ok=True, **view(*args, **kwargs))
        except portal_auth.NotSignedIn as e:
            return jsonify(ok=False, error=str(e), session=session_payload()), 401
        except portal_auth.Forbidden as e:   # no access to this module, or an administrator-only action
            return jsonify(ok=False, error=str(e)), 403
        except (ValueError, LookupError) as e:   # includes portal_auth.CredentialError (service account not set)
            return jsonify(ok=False, error=str(e)), 400
        except ontap_api.OntapError as e:
            return jsonify(ok=False, error=str(e)), 502
    return wrapper


# ---------------- Page & session ----------------
@blueprint.get("/")
def index():
    return render_template("ontap/index.html", ui_version=UI_VERSION)


# Sign-in and sign-out (/api/login, /api/logout, /auth/...), the administration APIs (/api/admin/...) and the activity
# export (/export/events.csv) belong to the portal. This session answer never fails with 403: the page shows "no access".
@blueprint.get("/api/session")
def session():
    return jsonify(ok=True, **session_payload())


# ---------------- Restore ----------------
@blueprint.get("/api/snapshots")
@json_api
def snapshots():
    """List of the snapshots available for this volume, straight from the ONTAP API (read-only).

    1. Find the LUN volume-<volume ID>.
    2. Not found: get the volume's name_id from OpenStack (playbook volume_info.yml, read-only), then look for the
       LUN volume-<name_id>. A volume that was migrated/retyped uses that backend name.
    """
    PORTAL.require(MODULE_ID)
    site = request.args.get("site", "")
    cfg, creds = pick_site(site)
    volume_id = volume_id_from(request.args.get("volume_id"))
    try:
        return find_snapshots(site, cfg, creds, volume_id)
    except ontap_api.OntapAuthError as e:
        raise service_account_refused(site, creds, e) from e


def find_snapshots(site, cfg, creds, volume_id):
    try:
        return ontap_api.volume_snapshots(cfg, creds["username"], creds["password"], volume_id)
    except ontap_api.LunNotFound:
        pass
    try:
        name_id = str(volume_info(site, creds, volume_id).get("name_id") or "").lower()
    except ValueError as e:
        raise ValueError(f"LUN volume-{volume_id} was not found in ONTAP {site}, and {e}")
    if not UUID_RE.match(name_id) or name_id == volume_id:
        raise ValueError(f"LUN volume-{volume_id} was not found in ONTAP {site}, and the volume has no name_id "
                         "in OpenStack. Check the volume ID and the site.")
    try:
        data = ontap_api.volume_snapshots(cfg, creds["username"], creds["password"], name_id)
    except ontap_api.LunNotFound:
        raise ValueError(f"No LUN found in ONTAP {site}: neither volume-{volume_id} nor volume-{name_id} (name_id from OpenStack).")
    log.info("LUN for volume %s found via name_id %s (site %s)", volume_id, name_id, site)
    return {**data, "name_id": name_id}


def volume_info(site, creds, volume_id):
    """Run volume_info.yml (openstack volume show) and wait for the result. ValueError when it fails."""
    job = JOBS.start("volume_info", creds["username"], creds["password"], {"site": site, "volume_id": volume_id},
                     owner=owner_of(PORTAL.session_id()))
    deadline = time.time() + INFO_WAIT_SECONDS
    while job["status"] == "running" and time.time() < deadline:
        time.sleep(0.3)
    if job["status"] == "running":
        raise ValueError("OpenStack did not return the volume info (name_id) in time. Try again.")
    if job["status"] != "success":
        raise ValueError(f"the OpenStack volume info check failed: {job['error']}")
    return (job["result"] or {}).get("volume") or {}


@blueprint.post("/api/volume_info")
@json_api
def volume_info_job():
    """Volume step: a read-only volume show job -> the instance the volume is attached to (flavor, network interfaces,
    other volumes) and the role of the volume (boot / extended / detached). The browser follows the result through
    /api/jobs/<id>."""
    PORTAL.require(MODULE_ID)
    d = json_body()
    site = str(d.get("site") or "")
    _, creds = pick_site(site)
    job = JOBS.start("volume_info", creds["username"], creds["password"],
                     {"site": site, "volume_id": volume_id_from(d.get("volume_id")), "with_instance": True},
                     owner=owner_of(PORTAL.session_id()))
    return {"job_id": job["id"]}


@blueprint.post("/api/plan")
@json_api
def plan():
    """Read-only Ansible job: checks the OpenStack volume, target project, LUN, FlexVol and the chosen snapshot."""
    PORTAL.require(MODULE_ID)
    d = json_body()
    site = str(d.get("site") or "")
    _, creds = pick_site(site)
    snapshot = str(d.get("snapshot") or "").strip()
    project_id = str(d.get("project_id") or "").strip()
    if not SNAPSHOT_RE.match(snapshot):
        raise ValueError("Select a snapshot first")
    if project_id and not PROJECT_RE.match(project_id):
        raise ValueError("Invalid target project ID")
    job = JOBS.start("plan", creds["username"], creds["password"],
                     {"site": site, "volume_id": volume_id_from(d.get("volume_id")), "snapshot": snapshot, "project_id": project_id},
                     owner=owner_of(PORTAL.session_id()))
    return {"job_id": job["id"]}


def pick_type(plan_result, value):
    """Volume type of the new volume: the original type (default), or another type from the plan's type_options that
    has a usable pool. Result: (type name, its pools from the plan)."""
    original = str((plan_result.get("volume") or {}).get("type") or "")
    name = str(value or "").strip() or original
    option = next((o for o in plan_result.get("type_options") or [] if o.get("name") == name), None)
    if option is None:
        if name == original:   # a plan without type_options (older version): the pools of the original type
            return name, plan_result.get("pools") or {}
        raise ValueError(f"Volume type {name} cannot be used for this volume (unknown, private, or hidden on this site).")
    if name != original and not option.get("selectable"):
        raise ValueError(f"No Cinder pool of volume type {name} can take this volume.")
    return name, option.get("pools") or {}


def pick_pool(pools, value):
    """Cinder pool chosen by the operator (host@backend#pool): it must be a pool of the chosen volume type in the plan
    result and must be able to take the volume (not full, same SVM, online). There is no automatic choice. Result:
    (host, FlexVol, needs a lun move)."""
    host = str(value or "").strip()
    if not host:
        raise ValueError("Select a Cinder pool first.")
    for pool in (pools or {}).get("pools") or []:
        if pool.get("host") != host:
            continue
        if not pool.get("selectable"):
            raise ValueError(f"Cinder pool {pool.get('flexvol')} cannot take the volume: {pool.get('reason')}")
        return host, str(pool.get("flexvol") or ""), not pool.get("current")
    raise ValueError("The Cinder pool is not in the plan for this volume type. Click Check again in the Review step.")


def pick_post_action(plan_result, d):
    """Action after the restore: 'none' (only transfer to the project), 'attach' (Instance ID in the target project)
    or 'instance' (a new instance like the old one; boot volumes only). Checked against the plan result; the playbook
    checks it again before ONTAP is changed. Result: (action, attach_server_id, new_instance_name)."""
    action = str(d.get("post_action") or "none").strip().lower()
    if action not in POST_ACTIONS:
        raise ValueError("Unknown action after the restore")
    after = plan_result.get("after_restore") or {}
    if action == "attach":
        server_id = str(d.get("attach_server_id") or "").strip().lower()
        if not UUID_RE.match(server_id):
            raise ValueError("The instance ID must be an OpenStack UUID")
        server = next((x for x in after.get("servers") or [] if x.get("id") == server_id), None)
        if not server:
            project = (plan_result.get("project") or {}).get("name") or (plan_result.get("project") or {}).get("id")
            raise ValueError(f"Instance {server_id} is not in project {project}")
        if not server.get("attachable"):
            raise ValueError(f"Instance {server.get('name')} is {server.get('status')}; a volume cannot be attached to it")
        return action, server_id, ""
    if action == "instance":
        plan = after.get("new_instance") or {}
        if not plan.get("possible"):
            raise ValueError(f"A new instance cannot be created: {plan.get('reason') or 'the volume is not a boot volume'}")
        name = str(d.get("new_instance_name") or plan.get("default_name") or "").strip()
        if not INSTANCE_NAME_RE.match(name):
            raise ValueError("The instance name may only contain letters, digits, _ . - (max. 63, starting with a letter or digit)")
        return action, "", name
    return action, "", ""


def pick_port_networks(plan_result, d):
    """Network (and subnet) of every network interface of a new instance, in port order: the original network when the
    target project can use it, or a network of the target project (its VPCs) or a shared network from the plan
    (network_options). A port whose original network the target project cannot use needs a choice. The playbook checks
    it again. Result: [{network_id, subnet_id}] (subnet_id empty: the original subnets, or the first IPv4 subnet)."""
    plan = (plan_result.get("after_restore") or {}).get("new_instance") or {}
    project = plan_result.get("project") or {}
    raw = d.get("new_port_networks")
    raw = raw if isinstance(raw, list) else []
    options = {str(o.get("id")): o for o in plan.get("network_options") or []}
    picked = []
    for i, port in enumerate(plan.get("ports") or []):
        item = raw[i] if i < len(raw) and isinstance(raw[i], dict) else {}
        net = str(item.get("network_id") or "").strip().lower() or str(port.get("default_network_id") or "")
        sub = str(item.get("subnet_id") or "").strip().lower()
        where = f"network interface {port.get('index', i + 1)} ({port.get('original_network_name') or port.get('original_network_id')})"
        if not net:
            raise ValueError(f"Choose a network of project {project.get('name') or project.get('id')} for {where} of the new instance.")
        if not UUID_RE.match(net) or (sub and not UUID_RE.match(sub)):
            raise ValueError(f"Invalid network or subnet ID for {where}.")
        if net == port.get("original_network_id") and port.get("original_usable", True):
            if sub and sub not in (port.get("original_subnet_ids") or []):
                raise ValueError(f"Subnet {sub} is not a subnet of the original port of {where}.")
        elif net not in options:
            raise ValueError(f"Network {net} cannot be used for {where}: it is not a network of project "
                             f"{project.get('name') or project.get('id')} or a shared network. Click Check again in the Review step.")
        elif sub and sub not in [str(s.get("id")) for s in options[net].get("subnets") or []]:
            raise ValueError(f"Subnet {sub} is not on network {options[net].get('name') or net}.")
        picked.append({"network_id": net, "subnet_id": sub})
    return picked


def port_network_names(plan_result, port_networks):
    """Names of the networks of a new instance, in port order (with the CIDR of a chosen subnet), for the activity log."""
    plan = (plan_result.get("after_restore") or {}).get("new_instance") or {}
    options = {str(o.get("id")): o for o in plan.get("network_options") or []}
    names = []
    for port, pick in zip(plan.get("ports") or [], port_networks or []):
        net = pick.get("network_id")
        option = options.get(net) or {}
        name = (port.get("original_network_name") if net == port.get("original_network_id") else option.get("name")) or net
        subnet = next((s for s in option.get("subnets") or [] if s.get("id") == pick.get("subnet_id")), None)
        names.append(name + (f" {subnet.get('cidr') or subnet.get('id')}" if subnet else ""))
    return names


def ready_plan(plan_job_id):
    """The Review plan of this portal session: finished, all prerequisites met, and not older than 30 minutes."""
    plan_job = JOBS.get(str(plan_job_id or ""))
    if not plan_job or plan_job["kind"] != "plan" or plan_job["owner"] != owner_of(PORTAL.session_id()):
        raise ValueError("Plan not found. Open the Review step again.")
    result = plan_job["result"] or {}
    if plan_job["status"] != "success" or not result.get("ready"):
        raise ValueError("The plan does not meet all restore prerequisites.")
    if time.time() - plan_job["finished"] > PLAN_MAX_AGE_SECONDS:
        raise ValueError("The plan is older than 30 minutes. Click Check again in the Review step to refresh it.")
    return plan_job, result


def new_volume_name(result, value):
    name = str(value or result.get("default_new_name") or "").strip()
    if not VOLUME_NAME_RE.match(name):
        raise ValueError("The new volume name may only contain letters, digits, _ . : - (max. 128)")
    return name


def portal_event(actor, action, target, detail, client):
    """Activity log entry with an explicit client address (group restores run outside the request)."""
    PORTAL.store.event(actor, action, target, detail, client)
    log.info("PORTAL %s actor=%s target=%s %s", action, actor, target or "-", detail or "")


def launch_restore(plan_job, result, name, target_pool, flexvol, moved, action, attach_server_id, instance_name, delete_after,
                   username, client, group_id=None, extra_volumes=None, on_done=None, target_type=None, port_networks=None):
    """Write the history record (before anything runs), log it, and start the restore job. Also used by group restores,
    outside a request. extra_volumes ([{id, device}]): restored volumes the new instance gets at creation.
    port_networks ([{network_id, subnet_id}]): the network of every network interface of the new instance.
    on_done(record, job) runs after the record is finished. Returns (record id, job)."""
    original_type = str((result.get("volume") or {}).get("type") or "")
    target_type = original_type if target_type is None else target_type
    params = dict(plan_job["params"], new_volume_name=name, target_pool=target_pool, post_action=action,
                  attach_server_id=attach_server_id, new_instance_name=instance_name,
                  new_instance_volumes=list(extra_volumes or []) if action == "instance" else [],
                  new_port_networks=list(port_networks or []) if action == "instance" else [],
                  target_type=target_type if target_type != original_type else "")
    _, creds = pick_site(params["site"])
    # A lun move to another pool and a new instance take extra time: the job time limit plus the wait limit of that site.
    site_cfg = config.sites().get(params["site"]) or {}
    timeout = TIMEOUTS["restore"]
    if moved:
        timeout += int((site_cfg.get("ontap") or {}).get("move_wait_seconds", 7200))
    if action == "instance":
        timeout += int((site_cfg.get("openstack") or {}).get("instance_wait_seconds", 900))
    post = {"none": "", "attach": f"attach {attach_server_id}", "instance": f"instance {instance_name}"}[action]
    # The history and the log name the signed-in AD user; ONTAP only sees the site's service account.
    try:
        record = history.begin(username, params["site"], dict(result, new_volume_name=name, volume_type=target_type,
                                                              move_flexvol=flexvol if moved else "",
                                                              cinder_pool=target_pool, post_action=post,
                                                              delete_after=delete_after),
                               client, group_id=group_id)
    except sqlite3.Error as e:
        raise ValueError(f"The job record could not be written, restore canceled: {e}")
    portal_event(username, "restore.start", params["volume_id"],
                 restore_start_text(record, params["site"], result, name, target_pool, flexvol, moved, action,
                                    attach_server_id, instance_name, delete_after, group_id, extra_volumes, target_type,
                                    port_network_names(result, params["new_port_networks"])), client)
    log.info("RESTORE started #%s user=%s site=%s volume=%s snapshot=%s project=%s type=%s pool=%s lun_move=%s after=%s delete_after=%sh ontap_account=%s%s",
             record, username, params["site"], params["volume_id"], params["snapshot"], result["project"]["id"],
             target_type or "-", target_pool, "yes" if moved else "no", post or "none", delete_after, creds["username"],
             f" group=#{group_id}" if group_id else "")
    original = {"site": params["site"], "volume_id": params["volume_id"], "volume_name": (result.get("volume") or {}).get("name", ""),
                "source_project_id": (result.get("volume") or {}).get("project_id", ""),
                "source_project_name": (result.get("project") or {}).get("name", "") if (result.get("project") or {}).get("same_as_source") else "",
                "username": username, "lun_path": (result.get("lun") or {}).get("name", ""),
                "lun_svm": (result.get("lun") or {}).get("svm", ""), "lun_ref_id": (result.get("lun") or {}).get("ref_id", "")}

    def finished(job):
        _finish_restore(record, job, original, delete_after)
        if on_done:
            on_done(record, job)
    try:
        job = JOBS.start("restore", creds["username"], creds["password"], params, key=(params["site"], params["volume_id"]),
                         on_finish=finished, owner=plan_job["owner"], timeout=timeout)
    except ValueError as e:
        history.finish(record, {"status": "failed", "error": str(e), "lines": []})
        raise
    history.set_job(record, job["id"])
    return record, job


@blueprint.post("/api/restore")
@json_api
def restore():
    """Run the restore from a plan that was reviewed (the parameters come from the plan, not from the browser)."""
    s = PORTAL.require(MODULE_ID)
    d = json_body()
    plan_job, result = ready_plan(d.get("plan_job_id"))
    if d.get("confirm") is not True:
        raise ValueError("Tick the confirmation first.")
    name = new_volume_name(result, d.get("new_volume_name"))
    target_type, type_pools = pick_type(result, d.get("target_type"))
    target_pool, flexvol, moved = pick_pool(type_pools, d.get("target_pool"))
    action, attach_server_id, instance_name = pick_post_action(result, d)
    port_networks = pick_port_networks(result, d) if action == "instance" else []
    # The original volume is deleted only after it is due AND an administrator approves it (Approvals menu).
    delete_after = int(result.get("delete_after_hours") or deletions.DEFAULT_HOURS) if d.get("schedule_delete") is True else 0
    record, job = launch_restore(plan_job, result, name, target_pool, flexvol, moved, action, attach_server_id, instance_name,
                                 delete_after, s["username"], PORTAL.client_address(), target_type=target_type,
                                 port_networks=port_networks)
    return {"job_id": job["id"], "history_id": record}


# ---------------- Restore several volumes of one instance (group) ----------------
def group_members(members):
    """Volumes of ONE instance, from the same snapshot into the same project, each once and with its own new name.
    Sorted by device: the boot disk (vda) first, then vdb, vdc, ..."""
    p0, r0 = members[0]["plan_job"]["params"], members[0]["result"]
    project, instance = (r0.get("project") or {}).get("id"), (r0.get("instance") or {}).get("id")
    for m in members:
        p, r = m["plan_job"]["params"], m["result"]
        if p["site"] != p0["site"]:
            raise ValueError("All volumes must be on the same site.")
        if p["snapshot"] != p0["snapshot"]:
            raise ValueError("All volumes must be restored from the same snapshot.")
        if (r.get("project") or {}).get("id") != project:
            raise ValueError("All volumes must go to the same target project.")
        if not instance or (r.get("instance") or {}).get("id") != instance:
            raise ValueError("All volumes must be attached to the same instance.")
    ids = [m["plan_job"]["params"]["volume_id"] for m in members]
    if len(set(ids)) != len(ids):
        raise ValueError("A volume is in the list twice.")
    names = [m["name"] for m in members]
    if len(set(names)) != len(names):
        raise ValueError("Each new volume needs its own name.")

    def device_order(m):
        role = m["result"].get("role") or {}
        return role.get("role") != "boot", str(role.get("device") or "~")
    return sorted(members, key=device_order)


@blueprint.post("/api/restore_group")
@json_api
def restore_group():
    """Several volumes of one instance from the same snapshot, one restore (job) after the other. Action after the
    restore for the group: 'none' (every new volume only moved to the project), 'attach' (every new volume attached to an
    instance of the target project), or 'instance' (the other volumes first, then the boot volume: a new instance like the
    old one that gets all new volumes when it is created). A failed restore stops the group; a failed action does not."""
    s = PORTAL.require(MODULE_ID)
    d = json_body()
    raw = d.get("volumes")
    if not isinstance(raw, list) or not 2 <= len(raw) <= MAX_GROUP_VOLUMES:
        raise ValueError(f"Restoring several volumes needs 2 to {MAX_GROUP_VOLUMES} volumes.")
    members = []
    for item in raw:
        item = item if isinstance(item, dict) else {}
        plan_job, result = ready_plan(item.get("plan_job_id"))
        members.append({"plan_job": plan_job, "result": result, "item": item})
    if d.get("confirm") is not True:
        raise ValueError("Tick the confirmation first.")
    for m in members:
        m["name"] = new_volume_name(m["result"], m["item"].get("new_volume_name"))
        m["type"], type_pools = pick_type(m["result"], m["item"].get("target_type"))
        m["pool"], m["flexvol"], m["moved"] = pick_pool(type_pools, m["item"].get("target_pool"))
    members = group_members(members)
    action = str(d.get("post_action") or "none").strip().lower()
    if action not in POST_ACTIONS:
        raise ValueError("Unknown action after the restore")
    server_id = instance_name = ""
    port_networks = []
    if action == "attach":
        _, server_id, _ = pick_post_action(members[0]["result"], d)
    elif action == "instance":
        boot = next((m for m in members if (m["result"].get("role") or {}).get("role") == "boot"), None)
        if not boot:
            raise ValueError("A new instance needs the boot disk (vda) of the instance in the list.")
        _, _, instance_name = pick_post_action(boot["result"], d)
        port_networks = pick_port_networks(boot["result"], d)
        members = [m for m in members if m is not boot] + [boot]   # the new instance gets the other new volumes at creation
    site = members[0]["plan_job"]["params"]["site"]
    for m in members:
        if JOBS.busy((site, m["plan_job"]["params"]["volume_id"])):
            raise ValueError(f"A job for volume {m['plan_job']['params']['volume_id']} is already running. Wait until it finishes.")
    r0 = members[0]["result"]
    delete_after = int(r0.get("delete_after_hours") or deletions.DEFAULT_HOURS) if d.get("schedule_delete") is True else 0
    client = PORTAL.client_address()
    info = {"instance_id": (r0.get("instance") or {}).get("id", ""), "instance_name": (r0.get("instance") or {}).get("name", ""),
            "snapshot": r0["snapshot"]["name"], "snapshot_time": r0["snapshot"].get("local_time", ""),
            "project_id": r0["project"]["id"], "project_name": r0["project"].get("name", ""),
            "post_action": {"none": "", "attach": f"attach {server_id}", "instance": f"instance {instance_name}"}[action]}
    rows = [{"volume_id": m["plan_job"]["params"]["volume_id"], "volume_name": (m["result"].get("volume") or {}).get("name", ""),
             "size_gb": (m["result"].get("volume") or {}).get("size_gb"), "device": (m["result"].get("role") or {}).get("device", ""),
             "role": (m["result"].get("role") or {}).get("role", ""), "new_volume_name": m["name"], "volume_type": m["type"],
             "cinder_pool": m["pool"],
             "lun_move": bool(m["moved"]), "restore_id": None, "new_volume_id": "", "status": "waiting", "note": ""} for m in members]
    try:
        group = history.begin_group(s["username"], site, info, rows, client)
    except sqlite3.Error as e:
        raise ValueError(f"The group record could not be written, restore canceled: {e}")
    portal_event(s["username"], "restore.group_start", info["instance_id"], group_start_text(group, site, info, rows, action), client)
    threading.Thread(target=run_group, args=(group, members, action, server_id, instance_name, delete_after, s["username"], client,
                                             port_networks),
                     name=f"restore-group-{group}", daemon=True).start()
    return {"group_id": group}


def group_start_text(group, site, info, rows, action):
    after = {"none": f"every new volume only moved to project {info['project_name'] or info['project_id']}",
             "attach": f"attach every new volume to instance {info['post_action'][7:]}",
             "instance": f"new instance {info['post_action'][9:]} with all new volumes"}[action]
    volumes = ", ".join(f"{(r['device'] or '').replace('/dev/', '') or '-'} {r['volume_name'] or r['volume_id']}" for r in rows)
    return (f"restore group #{group}, site {site}: {len(rows)} volumes of instance {info['instance_name'] or info['instance_id']} "
            f"({volumes}) from snapshot {info['snapshot']} ({info['snapshot_time']}) -> project "
            f"{info['project_name'] or info['project_id']}; after the restore: {after}")


def run_group(group, members, action, server_id, instance_name, delete_after, username, client, port_networks=None):
    """Restore the volumes of a group one after the other (background thread). A failed restore stops the group: the
    volumes after it are not restored. With 'instance' the boot volume comes last and its new instance gets the volumes
    restored before it."""
    restored, problems, index = [], [], 0
    try:
        for index, m in enumerate(members):
            member_action = "none" if action == "instance" and index < len(members) - 1 else action
            done, box = threading.Event(), {}

            def on_done(record, job, box=box, done=done):
                box["job"] = job
                done.set()
            record, _ = launch_restore(m["plan_job"], m["result"], m["name"], m["pool"], m["flexvol"], m["moved"], member_action,
                                       server_id if member_action == "attach" else "",
                                       instance_name if member_action == "instance" else "", delete_after, username, client,
                                       group_id=group, extra_volumes=restored if member_action == "instance" else None,
                                       on_done=on_done, target_type=m["type"],
                                       port_networks=port_networks if member_action == "instance" else None)
            history.update_group_member(group, index, restore_id=record, status="running")
            done.wait()
            job, rec = box["job"], history.get(record) or {}
            if job["status"] != "success":
                history.update_group_member(group, index, status=job["status"], note=job.get("error") or "")
                return end_group(group, members, index + 1, "failed", f"restore #{record} failed: {job.get('error') or 'no message'}",
                                 username, client)
            new_volume = (job.get("result") or {}).get("new_volume") or {}
            restored.append({"id": new_volume.get("id", ""), "device": (m["result"].get("role") or {}).get("device", "")})
            post = str(rec.get("post_result") or "")
            if post.startswith("failed"):
                problems.append(f"restore #{record}: {post[8:]}")
            history.update_group_member(group, index, status="partial" if post.startswith("failed") else "success",
                                        new_volume_id=new_volume.get("id", ""), note=post)
        end_group(group, members, len(members), "partial" if problems else "success", "; ".join(problems), username, client)
    except Exception as e:   # ValueError from launch_restore (job busy, record not written) or anything unexpected
        log.exception("Restore group #%s stopped", group)
        history.update_group_member(group, index, status="failed", note=str(e))
        end_group(group, members, index + 1, "failed", str(e), username, client)


def end_group(group, members, first_skipped, status, error, username, client):
    for i in range(first_skipped, len(members)):
        history.update_group_member(group, i, status="skipped", note="not started: an earlier restore of the group failed")
    history.finish_group(group, status, error)
    g = history.get_group(group) or {}
    done = [m for m in g.get("members") or [] if m.get("status") in ("success", "partial")]
    restores = ", ".join(f"restore #{m.get('restore_id')}" for m in done)
    detail = (f"restore group #{group}, site {g.get('site')}: {len(done)} of {len(members)} volumes restored"
              + (f" ({restores})" if restores else "") + (f"; {error}" if error else ""))
    portal_event(username, f"restore.group_{'done' if status == 'success' else status}", g.get("instance_id") or "",
                 detail[:1000], client)
    log.info("RESTORE GROUP finished #%s status=%s %s", group, status, error)


@blueprint.get("/api/restore_groups/<int:group_id>")
@json_api
def group_detail(group_id):
    """A group with the state of each volume; running volumes carry their current task."""
    PORTAL.require(MODULE_ID)
    group = history.get_group(group_id)
    if not group:
        raise LookupError("Group not found")
    for m in group["members"]:
        rec = history.get(m["restore_id"]) if m.get("restore_id") else None
        job = JOBS.get(rec["job_id"]) if rec and rec.get("job_id") else None
        m["task"] = job["task"] if job and job["status"] == "running" else ""
        m["post_result"] = (rec or {}).get("post_result") or ""
    return {"group": group}


def restore_start_text(record, site, result, name, pool, flexvol, moved, action, server_id, instance_name, delete_after,
                       group=None, extra_volumes=None, target_type=None, networks=None):
    """What the user asked for, for the activity log: source, snapshot, new volume, project, Cinder pool, action after it."""
    volume, project, snap = result.get("volume") or {}, result.get("project") or {}, result.get("snapshot") or {}
    project_text = f"{project.get('name') or project.get('id')} ({project.get('id')})" if project.get("name") else project.get("id")
    server = next((x for x in (result.get("after_restore") or {}).get("servers") or [] if x.get("id") == server_id), {})
    after = {"none": f"only moved to project {project.get('name') or project.get('id')}",
             "attach": f"attach to instance {server.get('name') or server_id} ({server_id})",
             "instance": f"new instance {instance_name}"}[action]
    if action == "instance" and networks:
        after += f" on network{'' if len(networks) == 1 else 's'} {', '.join(networks)}"
    if action == "instance" and extra_volumes:
        after += f" with {len(extra_volumes)} more new volume{'' if len(extra_volumes) == 1 else 's'} of the group"
    lun_pool = (result.get("lun") or {}).get("flexvol") or "?"
    return (f"restore #{record}{f' (group #{group})' if group else ''}, site {site}: {volume.get('name') or '(no name)'} ({volume.get('size_gb', '?')} GB, "
            f"type {volume.get('type') or '-'}{', bootable' if volume.get('bootable') else ''}) from snapshot "
            f"{snap.get('name')} ({snap.get('local_time')}) -> new volume {name}"
            + (f" (volume type changed to {target_type})" if target_type is not None and target_type != (volume.get("type") or "") else "")
            + f" in project {project_text}; "
            f"Cinder pool {pool} ({f'lun move from {lun_pool} to {flexvol}' if moved else 'pool of the LUN, no lun move'}); "
            f"after the restore: {after}; original volume: "
            + (f"delete after {delete_after} h with administrator approval" if delete_after else "not scheduled for deletion"))


def restore_finish_event(rec):
    """Activity log entry for a finished restore (the client address is the one the restore was launched from)."""
    post = str(rec.get("post_result") or "")
    where = f"restore #{rec['id']}, site {rec['site']}"
    if rec.get("status") == "success":
        action = "restore.partial" if post.startswith("failed") else "restore.done"
        after = (post[4:] if post.startswith("ok: ") else f"the action after the restore FAILED: {post[8:]}" if post.startswith("failed: ")
                 else f"only moved to project {rec.get('project_name') or rec.get('project_id')}")
        detail = (f"{where}: new volume {rec.get('new_volume_name')} ({rec.get('new_volume_id')}) in project "
                  f"{rec.get('project_name') or rec.get('project_id')}, Cinder pool {rec.get('cinder_pool') or '-'}; {after}")
    else:
        action = "restore.failed" if rec.get("status") == "failed" else "restore.unknown"
        detail = f"{where}: {rec.get('error') or 'no message'}"
    PORTAL.store.event(rec["username"], action, rec["volume_id"], detail, rec.get("client_ip") or "")


def _finish_restore(record, job, original=None, delete_after=0):
    history.finish(record, job)
    log.info("RESTORE finished #%s status=%s new_volume=%s %s", record, job["status"],
             ((job["result"] or {}).get("new_volume") or {}).get("id", "-"), job["error"])
    rec = history.get(record) or {}
    if rec:
        restore_finish_event(rec)
    if job["status"] != "success" or not delete_after or not original:
        return
    new_volume = (job["result"] or {}).get("new_volume") or {}
    deletion = deletions.schedule(record, dict(original, new_volume_id=new_volume.get("id", ""),
                                               new_volume_name=new_volume.get("name", "")), delete_after)
    if deletion:
        item = deletions.get(deletion)
        PORTAL.store.event(original["username"], "deletion.schedule", original["volume_id"],
                           f"restore #{record}, site {original['site']}, due {item['due']} (admin approval required)",
                           rec.get("client_ip") or "")
        log.info("DELETION scheduled #%s restore=#%s site=%s volume=%s due=%s", deletion, record, original["site"],
                 original["volume_id"], item["due"])


@blueprint.get("/api/jobs/<job_id>")
@json_api
def job_status(job_id):
    PORTAL.require(MODULE_ID)
    job = JOBS.get(job_id)
    if not job:
        raise LookupError("Job not found (the web app may have been restarted)")
    since = max(0, request.args.get("since", 0, type=int))
    lines = job["lines"][since:]
    done = job["status"] != "running"
    return {"id": job["id"], "kind": job["kind"], "status": job["status"], "task": job["task"], "lines": lines,
            "next": since + len(lines), "error": job["error"], "result": job["result"] if done else None,
            "elapsed": round((job["finished"] or time.time()) - job["started"])}


@blueprint.get("/api/guide")
@json_api
def guide_data():
    """For the guide of the Restore page, nothing runs: the newest check (plan) of this session on the site and the
    OpenStack read (volume_info) of its volume, from jobs that already ran. Without a plan, the newest OpenStack read."""
    PORTAL.require(MODULE_ID)
    site = request.args.get("site", "")
    owner = owner_of(PORTAL.session_id())
    plan_job = JOBS.latest("plan", owner, site=site)
    volume_id = plan_job["params"]["volume_id"] if plan_job else None
    info_job = JOBS.latest("volume_info", owner, site=site, with_instance=True,
                           **({"volume_id": volume_id} if volume_id else {}))
    return {"plan": {"job_id": plan_job["id"], "params": plan_job["params"], "result": plan_job["result"],
                     "age": round(time.time() - plan_job["finished"])} if plan_job else None,
            "volume_info": {"volume_id": info_job["params"]["volume_id"], "result": info_job["result"]} if info_job else None}


# ---------------- History ----------------
@blueprint.get("/api/history")
@json_api
def history_list():
    PORTAL.require(MODULE_ID)
    a = request.args
    st = a.get("status", "")
    if st and st not in history.STATUSES:
        raise ValueError("Unknown status")
    return history.query(a.get("limit", 50, type=int), a.get("offset", 0, type=int), a.get("user", ""), a.get("site", ""),
                         st, a.get("q", "")[:100])


@blueprint.get("/export/jobs.csv")
def history_export():
    """Every restore that matches the filters of the Jobs page (CSV, oldest first), for an audit."""
    try:
        PORTAL.require(MODULE_ID)
        a = request.args
        st = a.get("status", "")
        if st and st not in history.STATUSES:
            raise ValueError("Unknown status")
        rows = history.all_rows(a.get("user", ""), a.get("site", ""), st, a.get("q", "")[:100])
    except portal_auth.NotSignedIn as e:
        return jsonify(ok=False, error=str(e), session=session_payload()), 401
    except portal_auth.Forbidden as e:
        return jsonify(ok=False, error=str(e)), 403
    except ValueError as e:
        return jsonify(ok=False, error=str(e)), 400
    resp = make_response(history.to_csv(rows))
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = f'attachment; filename="ONTAP_Restore_Jobs_{datetime.datetime.now():%Y%m%d-%H%M}.csv"'
    return resp


@blueprint.get("/api/history/<int:record_id>")
@json_api
def history_detail(record_id):
    PORTAL.require(MODULE_ID)
    item = history.get(record_id)
    if not item:
        raise LookupError("Job not found")
    return {"item": item, "deletion": deletions.for_restore(record_id)}


# ---------------- Delete the old volume (only with administrator approval) ----------------
def deletion_or_404(deletion_id):
    item = deletions.get(deletion_id)
    if not item:
        raise LookupError("Deletion not found")
    return item


def start_delete_job(item, check_only, on_finish=None, detach_servers=None, delete_server=None, delete_snapshots=None):
    """Job delete_volume.yml: checks OpenStack + the LUN on NetApp, then deletes (unless check_only). detach_servers =
    detach from those instances first (must be the same as the attachments at deletion time). delete_server = (ID,
    name typed by the administrator): the volume is the boot disk of that instance, so the instance is deleted first.
    delete_snapshots = the Cinder snapshots of the volume shown in the check: deleted before the volume (must be the
    same as its snapshots at deletion time). One job per volume (same key as the restore)."""
    _, creds = pick_site(item["site"])
    params = {"site": item["site"], "volume_id": item["volume_id"], "expect_project": item["project_id"],
              "keep_volume_id": item["new_volume_id"], "lun_ref_id": item.get("lun_ref_id") or "",
              "lun_path": item.get("lun_path") or "", "check_only": check_only}
    if detach_servers:
        params.update(detach=True, detach_servers=detach_servers)
    if delete_server:
        params.update(delete_instance=True, delete_server=delete_server[0], delete_server_name=delete_server[1])
    if delete_snapshots:
        params.update(delete_snapshots=delete_snapshots)
    return JOBS.start("delete_volume", creds["username"], creds["password"], params,
                      key=(item["site"], item["volume_id"]), on_finish=on_finish, owner=owner_of(PORTAL.session_id()))


@blueprint.get("/api/deletions")
@json_api
def deletion_list():
    PORTAL.require(MODULE_ID)
    view = request.args.get("view", "open")
    if view not in ("open", "awaiting", "done", "all"):
        raise ValueError("Unknown view")
    return {"items": deletions.query(view), "summary": deletions.summary()}


@blueprint.get("/api/deletions/summary")
@json_api
def deletion_summary():
    """Masthead notification: the number of old volumes that wait for an administrator decision."""
    PORTAL.require(MODULE_ID)
    return {"summary": deletions.summary()}


@blueprint.get("/api/deletions/<int:deletion_id>")
@json_api
def deletion_detail(deletion_id):
    PORTAL.require(MODULE_ID)
    return {"item": deletion_or_404(deletion_id)}


@blueprint.post("/api/deletions/<int:deletion_id>/check")
@json_api
def deletion_check(deletion_id):
    """Check now (read-only): the volume still exists, its project, status, attachments, snapshots."""
    PORTAL.require(MODULE_ID)
    item = deletion_or_404(deletion_id)
    job = start_delete_job(item, True, on_finish=lambda j: deletions.save_check(
        deletion_id, j["result"] if j["status"] == "success" else {"error": j["error"]}))
    return {"job_id": job["id"]}


@blueprint.post("/api/deletions/<int:deletion_id>/approve")
@json_api
def deletion_approve(deletion_id):
    """An administrator approves deleting the old volume (only after it is due). The playbook checks again first."""
    s = PORTAL.admin()
    d = json_body()
    if d.get("confirm") is not True:
        raise ValueError("Confirm the deletion first.")
    # Detach and delete: the instances the administrator saw in the check; the playbook refuses when they changed.
    detach_servers = []
    if d.get("detach") is True:
        raw = d.get("detach_servers")
        if not isinstance(raw, list) or not raw or len(raw) > 10:
            raise ValueError("Detach and delete needs the instance IDs from the check")
        detach_servers = [str(x).strip().lower() for x in raw]
        if not all(UUID_RE.match(x) for x in detach_servers):
            raise ValueError("Invalid instance ID")
    # Delete the instance whose boot disk the volume is, then the volume: the instance of the check, its name typed by the
    # administrator; the playbook checks both again and refuses when they changed.
    delete_server = None
    if d.get("delete_instance") is True:
        sid, name = str(d.get("delete_server") or "").strip().lower(), str(d.get("delete_server_name") or "").strip()
        if not UUID_RE.match(sid):
            raise ValueError("Delete the instance first needs the instance ID from the check")
        if not name or len(name) > 255:
            raise ValueError("Type the name of the instance to delete")
        if detach_servers:
            raise ValueError("Either detach or delete the instance, not both")
        delete_server = (sid, name)
    # The Cinder snapshots of the volume the administrator saw in the check: deleted first, so the volume can be deleted;
    # the playbook refuses when the volume has other snapshots by then.
    raw = d.get("snapshots") if d.get("snapshots") is not None else []
    if not isinstance(raw, list) or len(raw) > 200:
        raise ValueError("Snapshots: the snapshot IDs from the check")
    delete_snapshots = [str(x).strip().lower() for x in raw]
    if not all(UUID_RE.match(x) for x in delete_snapshots):
        raise ValueError("Invalid snapshot ID")
    item = deletions.start_delete(deletion_id, s["username"])
    client = PORTAL.client_address()   # the job ends in a background thread, without the request
    try:
        job = start_delete_job(item, False, on_finish=lambda j: _finish_delete(deletion_id, item, s["username"], j, client),
                               detach_servers=detach_servers, delete_server=delete_server, delete_snapshots=delete_snapshots)
    except ValueError as e:
        deletions.finish_delete(deletion_id, {"status": "failed", "error": str(e), "lines": []})
        raise
    deletions.set_job(deletion_id, job["id"])
    PORTAL._event(s["username"], "deletion.approve", item["volume_id"], f"restore #{item['restore_id']}, site {item['site']}"
                  + (f", detach from {', '.join(detach_servers)} first" if detach_servers else "")
                  + (f", delete instance {delete_server[1]} ({delete_server[0]}) first" if delete_server else "")
                  + (f", delete {len(delete_snapshots)} snapshot(s) first ({', '.join(delete_snapshots)})" if delete_snapshots else ""))
    log.info("DELETION approved #%s by %s site=%s volume=%s", deletion_id, s["username"], item["site"], item["volume_id"])
    return {"job_id": job["id"]}


def _finish_delete(deletion_id, item, actor, job, client=""):
    ok = deletions.finish_delete(deletion_id, job)
    note = ((job.get("result") or {}).get("note") or "") if ok else ""
    detail = f"restore #{item['restore_id']}, site {item['site']}" + (f": {note}" if note else "") + ("" if ok else f": {job['error']}")
    PORTAL.store.event(actor, "deletion.done" if ok else "deletion.failed", item["volume_id"], detail[:500], client)
    log.info("DELETION finished #%s status=%s volume=%s %s", deletion_id, "deleted" if ok else "failed", item["volume_id"], job["error"])


@blueprint.post("/api/deletions/<int:deletion_id>/keep")
@json_api
def deletion_keep(deletion_id):
    s = PORTAL.admin()
    note = str(json_body().get("note") or "").strip()
    item = deletion_or_404(deletion_id)
    deletions.keep(deletion_id, s["username"], note)
    PORTAL._event(s["username"], "deletion.keep", item["volume_id"], note or f"restore #{item['restore_id']}")
    return {"item": deletions.get(deletion_id)}


@blueprint.post("/api/deletions/<int:deletion_id>/postpone")
@json_api
def deletion_postpone(deletion_id):
    s = PORTAL.admin()
    hours = json_body().get("hours")
    if hours not in (24, 72, 168):
        raise ValueError("Postpone by 24, 72 or 168 hours")
    item = deletion_or_404(deletion_id)
    due = deletions.postpone(deletion_id, s["username"], hours)
    PORTAL._event(s["username"], "deletion.postpone", item["volume_id"], f"restore #{item['restore_id']}, due {due}")
    return {"item": deletions.get(deletion_id)}


"""ACI module of the Ops Portal (/aci/): Static Port, Provisioning, Report and change history on Cisco ACI for all
sites. Taken from ACI Web UI (aci_webui/); decision in docs/ADR-003-one-portal.md, module contract in MODULES.md.

The portal signs users in (Active Directory, Duo, local accounts) and decides who may use this module. APIC is reached
with one service account per site, entered by an administrator on Administration -> Credentials of the portal
(targets apic:<site>) and shared by all signed-in users. The sites are the sites of sites.yml with an `apic` entry.
"""
import datetime
import functools
import hashlib
import logging
import os
import sqlite3
import threading

from flask import Blueprint, g, jsonify, make_response, render_template, request, send_file

import portal_auth
from core import PORTAL, register

from . import aci, audit, ip_usage, report, template_store
from .apic_sites import ApicHttpError, ServiceConnections, ServiceLoginError, site_from_request, site_hosts, test_login

MODULE_ID = "aci"
log = logging.getLogger("portal.aci")
blueprint = Blueprint(MODULE_ID, __name__, url_prefix="/aci", template_folder="templates", static_folder="static",
                      static_url_path="/static")
APIC_TIMEOUT_SECONDS = 60
audit.init()
template_store.init()
ip_usage.init()


def credential_name(site):
    return f"apic:{site}"


def credential_targets():
    """Service accounts on Administration -> Credentials: one APIC account per site of sites.yml."""
    return [{"name": credential_name(site), "label": f"APIC {site}", "host": host, "kind": "apic", "site": site}
            for site, host in site_hosts().items()]


def test_credential(target, username, password):
    return test_login(target["host"], username, password)


def credential_changed(name):
    if name.startswith("apic:"):
        CONNECTIONS.drop(name.split(":", 1)[1])


register(MODULE_ID, "ACI", "Static port, provisioning, report and change history on Cisco ACI (APIC).", "/aci/", "network",
         targets=credential_targets, tester=test_credential, on_credential_change=credential_changed,
         permissions=[{"id": template_store.PERMISSION, "title": "ACI: edit product templates"}])
# APIC tokens are kept in memory, like the portal sessions: the portal runs as a single process.
CONNECTIONS = ServiceConnections(lambda site: PORTAL.credential(credential_name(site)))


def _ui_version():
    """Fingerprint of the UI (JS, CSS, HTML). It changes with every new version, so open tabs know to reload."""
    digest = hashlib.sha256()
    for name in ("static/app.js", "static/app.css", "templates/aci/index.html"):
        with open(os.path.join(blueprint.root_path, name), "rb") as f:
            digest.update(f.read())
    return digest.hexdigest()[:12]


UI_VERSION = _ui_version()


def signed_in():
    """The portal user of this request, allowed to use this module; raises portal_auth.NotSignedIn without a valid
    session and portal_auth.Forbidden for an account without access to ACI."""
    if "portal_user" not in g:
        g.portal_user = PORTAL.require(MODULE_ID)
    return g.portal_user


def current_user():
    return signed_in()["username"]


def sites_payload(allowed):
    """Sites for the UI. Only users of this module see whether a service account is set and the last connection error."""
    hosts = site_hosts()
    if not allowed:
        return [{"name": name, "host": host} for name, host in hosts.items()]
    sites = []
    for name, host in hosts.items():
        configured = PORTAL.credential_configured(credential_name(name))
        sites.append({"name": name, "host": host, "configured": configured, "error": CONNECTIONS.error(name) if configured else ""})
    return sites


def session_payload():
    payload = PORTAL.payload()
    user = payload["user"]
    allowed = bool(user) and MODULE_ID in user["modules"]
    return {"ui_version": UI_VERSION, **payload, "allowed": allowed, "sites": sites_payload(allowed),
            "can_edit_templates": allowed and template_store.can_edit(user)}


def site_api(site=None):
    """api(path, method, body) bound to one site (default: the site of this request), using that site's service account."""
    site = site or site_from_request()
    return lambda path, method="GET", body=None: CONNECTIONS.call(site, path, method=method, body=body, timeout=APIC_TIMEOUT_SECONDS)


def json_body():
    # Without force=True: only Content-Type application/json is accepted (extra protection against CSRF).
    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else {}


def error_response(e):
    if isinstance(e, portal_auth.NotSignedIn):
        return jsonify(ok=False, error=str(e), session=session_payload()), 401
    if isinstance(e, portal_auth.Forbidden):
        return jsonify(ok=False, error=str(e)), 403
    if isinstance(e, ValueError):   # invalid input, unknown site, or a service account that is not set
        return jsonify(ok=False, error=str(e)), 400
    return jsonify(ok=False, error=str(e)), 502


def json_api(view):
    """API for users of this module: {"ok": true, ...}, or {"ok": false, "error": ...} with a fitting HTTP status."""
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        try:
            signed_in()
            return jsonify(ok=True, **view(*args, **kwargs))
        except (ValueError, RuntimeError) as e:
            return error_response(e)
    return wrapper


# ---------------- Page & session ----------------
@blueprint.get("/")
def index():
    return render_template("aci/index.html", ui_version=UI_VERSION)


@blueprint.get("/api/session")
def session():
    """Never 401/403: the page itself sends a browser without a session to the portal sign-in, and shows "no access"
    to an account that may not use ACI."""
    return jsonify(ok=True, **session_payload())


@blueprint.post("/api/keepalive")
def keepalive():
    """Called by an open page while its user is active: keeps the sign-in alive and refreshes existing APIC tokens."""
    try:
        signed_in()
    except (portal_auth.NotSignedIn, portal_auth.Forbidden):
        pass
    else:
        CONNECTIONS.keepalive()
    return jsonify(ok=True, **session_payload())


# ---------------- Discovery ----------------
@blueprint.get("/api/discover")
@json_api
def discover():
    a = request.args
    return {"items": aci.discover(site_api(), a.get("kind", ""), a.get("tenant", ""), a.get("app", ""))}


@blueprint.get("/api/paths")
@json_api
def paths():
    return {"items": aci.search_paths(site_api(), request.args.get("kind", "physical"), request.args.get("q", ""))}


@blueprint.post("/api/paths/check")
@json_api
def paths_check():
    """Which of these path TDNs exist in this site's fabric (fabricPathEp), for the template editor. Read-only."""
    tdns = json_body().get("tdns")
    if not isinstance(tdns, list) or not all(isinstance(t, str) for t in tdns):
        raise ValueError("tdns must be a list of path TDNs")
    if len(tdns) > template_store.MAX_PATHS:
        raise ValueError(f"At most {template_store.MAX_PATHS} paths per check")
    existing = aci.fabric_paths(site_api())
    return {"site": site_from_request(), "exists": {t: t in existing for t in tdns}}


# ---------------- Product templates ----------------
@blueprint.get("/api/templates")
@json_api
def templates():
    """Product templates for this site (as edited on Fabric -> Templates, else the shipped default); every path is
    flagged as existing or not in the APIC fabric."""
    existing = aci.fabric_paths(site_api())
    products = template_store.for_site(site_from_request())
    for product in products:
        for group in product["groups"]:
            group["paths"] = [{"tdn": tdn, "exists": tdn in existing} for tdn in group["paths"]]
    return {"products": products, "can_edit": template_store.can_edit(signed_in())}


def template_editor():
    """The signed-in user, when the account may change product templates; Forbidden otherwise."""
    user = signed_in()
    if not template_store.can_edit(user):
        raise portal_auth.Forbidden("Only administrators and accounts with the permission \u201cACI: edit product templates\u201d "
                                    "can change product templates. Ask an administrator to tick it on the Users page.")
    return user


def template_plan(site, product_id, body):
    """What saving (or, with "reset": true, resetting) a product's template on this site would change. Every path is
    looked up in the site's fabric: a path added to the template must exist there (blocked otherwise, as a typing
    error); a path already in the template that is missing now is only flagged, as on Static Port. Read-only."""
    current = template_store.state(site, product_id)
    template_store.check_version(current, body.get("version"))
    reset = body.get("reset") is True
    if reset and current["custom"]:
        raise ValueError(f"{current['label']} was added by a user and has no default template")
    groups = template_store.default_groups(site, product_id) if reset else template_store.normalize(body)
    plan = template_store.diff(current["groups"], groups)
    existing = aci.fabric_paths(site_api(site))
    for item in plan["items"]:
        item["exists"] = item["tdn"] in existing
    # The shipped default is taken as it is (its missing paths are flagged on Static Port, as before).
    plan["missing"] = [] if reset else [i["tdn"] for i in plan["items"] if i["status"] == "new" and not i["exists"]]
    plan["blocked"] = bool(plan["missing"])
    product = {k: current[k] for k in ("id", "label", "platform", "mode", "immediacy", "custom", "edited", "version")}
    return {"site": site, "product": product, "reset": reset, "groups_after": groups, **plan}


def template_event(record_id, event, site, product, summary):
    """Activity log entry (Users page) of a template or product change; the full record is change #<id> in History."""
    text = f"change #{record_id}" + (f", site {site}" if site else "") + f", product {product}: {summary}"
    PORTAL._event(current_user(), f"static_port.{event}", f"templates/{site}" if site else "products", text[:1000])
    log.info("TEMPLATE %s user=%s site=%s product=%s audit=%s %s", event, current_user(), site or "-", product, record_id, summary)


def store_call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except sqlite3.Error as e:
        log.error("TEMPLATE write failed: %s", e)
        raise RuntimeError(f"Cannot write the product template to the portal database: {e}")


@blueprint.post("/api/templates/<product_id>/preview")
@json_api
def template_preview(product_id):
    template_editor()
    plan = template_plan(site_from_request(), product_id, json_body())
    plan.pop("groups_after")
    return plan


@blueprint.post("/api/templates/<product_id>/save")
@json_api
def template_save(product_id):
    """Save (or reset) a product's template on this site. Checked again here, never taken from the preview; only the
    portal database changes, nothing is sent to APIC."""
    template_editor()
    site, body = site_from_request(), json_body()
    plan = template_plan(site, product_id, body)
    if plan["blocked"]:
        raise ValueError(f"{len(plan['missing'])} added path(s) do not exist in the {site} fabric, so the template was not saved: "
                         + ", ".join(plan["missing"][:10]) + (" …" if len(plan["missing"]) > 10 else ""))
    record_id, summary = store_call(template_store.save, site, product_id, plan["groups_after"], body.get("version"),
                                    current_user(), PORTAL.client_address(), apic=site_hosts().get(site, ""), reset=plan["reset"])
    template_event(record_id, "template_reset" if plan["reset"] else "template_saved", site, plan["product"]["label"], summary)
    plan.pop("groups_after")
    return {**plan, "saved": True, "audit_id": record_id, "summary_text": summary}


@blueprint.post("/api/products")
@json_api
def product_add():
    """A product of its own (label, platform, default mode and immediacy), on every site with an empty template."""
    template_editor()
    body = json_body()
    product_id, record_id = store_call(template_store.add_product, body, current_user(), PORTAL.client_address())
    product = template_store.product(product_id)
    template_event(record_id, "product_added", "", product["label"], "product added")
    return {"product": product, "audit_id": record_id}


@blueprint.post("/api/products/<product_id>")
@json_api
def product_update(product_id):
    template_editor()
    record_id = store_call(template_store.update_product, product_id, json_body(), current_user(), PORTAL.client_address())
    product = template_store.product(product_id)
    template_event(record_id, "product_changed", "", product["label"], "product settings changed")
    return {"product": product, "audit_id": record_id}


@blueprint.post("/api/products/<product_id>/delete")
@json_api
def product_delete(product_id):
    """Delete a product users added, with its templates on every site. Built-in products cannot be deleted."""
    template_editor()
    if json_body().get("confirm") is not True:
        raise ValueError('Confirm the deletion with {"confirm": true}')
    label = template_store.label(product_id) or product_id
    record_id = store_call(template_store.delete_product, product_id, current_user(), PORTAL.client_address())
    template_event(record_id, "product_deleted", "", label, "product deleted with its templates")
    return {"deleted": product_id, "audit_id": record_id}


# ---------------- Static port ----------------
def static_port_plan(api):
    d = json_body()
    bindings = aci.normalize_bindings(d.get("physical"), d.get("paths"))
    return aci.static_port_plan(api, d.get("tenant"), d.get("app"), d.get("epg"), bindings)


@blueprint.get("/api/static-port/existing")
@json_api
def static_port_existing():
    a = request.args
    return {"items": aci.existing_bindings(site_api(), aci.epg_dn(a.get("tenant"), a.get("app"), a.get("epg")))}


@blueprint.get("/api/vlan-usage")
@json_api
def vlan_usage():
    """Checked while the operator types a VLAN: where each VLAN is already used on this site by another EPG (static
    path / static leaf) or an L3Out. Bindings of the selected EPG itself are not counted. Read-only."""
    a = request.args
    vlans = []
    for part in str(a.get("vlans") or "").split(","):
        if part.strip():
            vlan = aci.positive_int(part, "VLAN")
            if vlan > 4094:
                raise ValueError(f"VLAN must be 1-4094, not {vlan}")
            vlans.append(vlan)
    if not vlans:
        raise ValueError("No VLAN to check")
    if len(set(vlans)) > 200:
        raise ValueError("At most 200 VLANs per check")
    own = aci.epg_dn(a.get("tenant"), a.get("app"), a.get("epg")) if a.get("epg") else ""
    usage = aci.vlan_usage(site_api(), [f"vlan-{v}" for v in vlans], own)
    return {"site": site_from_request(), "epg_dn": own, "usage": {e.split("-", 1)[1]: users for e, users in usage.items()}}


@blueprint.get("/api/vlan-suggest")
@json_api
def vlan_suggest():
    """Free VLAN IDs for a static port of the selected EPG ("Suggest free VLAN"): from the static blocks of the VLAN
    pools of its domains, not used on this site by any EPG or L3Out. Also the EPG's own VLANs. Read-only."""
    a = request.args
    count = aci.positive_int(a.get("count") or 10, "Count")
    if count > 100:
        raise ValueError(f"Count must be 1-100, not {count}")
    return {"site": site_from_request(), **aci.vlan_suggestions(site_api(), a.get("tenant"), a.get("app"), a.get("epg"), count)}


@blueprint.post("/api/static-port/preview")
@json_api
def static_port_preview():
    return {"site": site_from_request(), **static_port_plan(site_api())}


def product_label(product_id):
    """Product label from the templates (not from the browser), for the audit record."""
    return template_store.label(product_id)


def audited_apply(action, target, product, summary, details, send, site=None, event="applied", undo_of=None):
    """Record the change in the audit BEFORE sending it to APIC, then mark it success/failed. No record, no change.
    site: default the site of this request; event: activity log status of a success; undo_of: the change it undoes."""
    site = site or site_from_request()
    apic_user = CONNECTIONS.account(site)   # the service account the change is sent with
    try:
        record_id = audit.begin(current_user(), site, site_hosts().get(site, ""), action, target, product, summary, details,
                                PORTAL.client_address(), apic_user=apic_user, undo_of=undo_of)
    except sqlite3.Error as e:
        log.error("AUDIT write failed, apply canceled: %s", e)
        raise RuntimeError(f"Cannot write the audit log, so the change was canceled: {e}")
    try:
        send()
    except Exception as e:
        # Refused by APIC (or no APIC login possible) = certainly not applied; timeout/dropped connection = unknown.
        status = "failed" if isinstance(e, (ApicHttpError, ServiceLoginError, ValueError)) else "unknown"
        _finish_audit(record_id, status, str(e))
        change_event(record_id, action, status, site, target, product, summary, details, str(e))
        log.warning("APPLY %s %s user=%s apic_user=%s site=%s target=%s audit=%s: %s", action, status.upper(), current_user(),
                    apic_user, site, target, record_id, e)
        raise
    _finish_audit(record_id, "success")
    change_event(record_id, action, event, site, target, product, summary, details)
    log.info("APPLY %s user=%s apic_user=%s site=%s target=%s audit=%s %s", action, current_user(), apic_user, site, target,
             record_id, summary)
    return record_id


def change_event(record_id, action, status, site, target, product, summary, details, error=""):
    """Activity log entry (Users page) for a change sent to APIC; the full record is change #<id> in History."""
    encaps = (i.get("encap") or (i.get("before") or {}).get("encap") for i in details.get("items") or [])   # a deleted path: its old VLAN
    vlans = sorted({str(e).replace("vlan-", "") for e in encaps if e}, key=lambda v: (len(v), v))
    text = (f"change #{record_id}, site {site}" + (f", product {product}" if product else "") + f": {summary}"
            + (f" (VLAN {', '.join(vlans[:10])}{' …' if len(vlans) > 10 else ''})" if vlans else "") + (f"; {error}" if error else ""))
    PORTAL._event(current_user(), f"{action.replace('-', '_')}.{status}", target, text[:1000])


def _finish_audit(record_id, status, error=None):
    try:
        audit.finish(record_id, status, error)
    except sqlite3.Error as e:
        # The change on APIC already happened; the record stays 'pending' and is visible in the history.
        log.error("AUDIT #%s could not be updated to %s: %s", record_id, status, e)


@blueprint.post("/api/static-port/apply")
@json_api
def static_port_apply():
    api = site_api()
    plan = static_port_plan(api)
    # Checked again here with the data on APIC now: a VLAN of another EPG / L3Out is never sent.
    if plan["conflicts"]:
        raise ValueError(aci.conflict_message(plan["conflicts"]))
    if plan["payload"]:
        s = plan["summary"]
        changed = [i for i in plan["items"] if i["status"] != "same"]
        plan["audit_id"] = audited_apply("static-port", plan["epg_dn"], product_label(json_body().get("product")),
                                         f"{s['new']} new, {s['change']} changed", {"items": changed},
                                         lambda: aci.apply_static_port(api, plan))
    return {"site": site_from_request(), "applied": True, **plan}


# ---------------- Provisioning ----------------
@blueprint.post("/api/provision/preview")
@json_api
def provision_preview():
    return {"site": site_from_request(), **aci.provisioning_plan(site_api(), json_body())}


@blueprint.post("/api/provision/apply")
@json_api
def provision_apply():
    api = site_api()
    plan = aci.provisioning_plan(api, json_body())
    created = sum(s["kind"] == "new" for s in plan["steps"])
    changed = sum(s["kind"] == "change" for s in plan["steps"])
    plan["audit_id"] = audited_apply("provisioning", plan["epg_dn"], None, f"{created} created, {changed} updated",
                                     {"steps": plan["steps"], "warnings": plan["warnings"], "payload": plan["payload"]},
                                     lambda: aci.apply_provisioning(api, plan))
    return {"site": site_from_request(), "applied": True, **plan}


# ---------------- Report ----------------
def report_rows():
    a = request.args
    rows = aci.report_rows(site_api(), a.get("tenant", ""), a.get("app", ""), a.get("epg", ""))
    site = site_from_request()
    # Source of every binding: the portal's successful static-port changes of this site within the same filters,
    # read once per request.
    prefix, exact = aci.report_scope(a.get("tenant", ""), a.get("app", ""), a.get("epg", ""))
    rows = aci.binding_sources(rows, audit.static_port_paths(site, prefix, exact))
    for row in rows:
        row["Site"] = site
    return rows


@blueprint.get("/api/report")
@json_api
def report_json():
    return {"items": report_rows()}


@blueprint.get("/export/report.<fmt>")
def report_export(fmt):
    if fmt not in ("xlsx", "csv"):
        return jsonify(ok=False, error="Unknown export format"), 404
    try:
        signed_in()
        rows = report_rows()
    except (ValueError, RuntimeError) as e:
        return error_response(e)
    site, a = site_from_request(), request.args
    now = datetime.datetime.now()
    filename = f"ACI_Static_Port_Report_{site}_{now:%Y%m%d-%H%M}.{fmt}"
    if fmt == "csv":
        resp = make_response(report.to_csv(rows))
        resp.headers["Content-Type"] = "text/csv; charset=utf-8"
        resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        return resp
    info = {
        "Site": f"{site} ({site_hosts().get(site, '')})",
        "Filter": ", ".join(f"{k}={a.get(k)}" for k in ("tenant", "app", "epg") if a.get(k)) or "All",
        "Generated by": current_user(),
        "Generated at": f"{now:%Y-%m-%d %H:%M}",
    }
    return send_file(report.to_xlsx(rows, info), as_attachment=True, download_name=filename,
                     mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


# ---------------- IP usage ----------------
@blueprint.get("/api/ip-usage")
@json_api
def ip_usage_json():
    """Learned endpoint IPs, gateways and free addresses per EPG subnet (Client Endpoints of APIC). Read-only on APIC;
    the learned IPs are also kept in the portal database, so a host that is silent now is not suggested as free."""
    a = request.args
    site = site_from_request()
    rows = ip_usage.usage(site_api(), site, a.get("tenant", ""), a.get("app", ""), a.get("epg", ""))
    return {"site": site, "items": rows, "recent_days": ip_usage.RECENT_DAYS}


@blueprint.get("/export/ip-usage.csv")
def ip_usage_export():
    try:
        signed_in()
        a = request.args
        site = site_from_request()
        rows = ip_usage.usage(site_api(), site, a.get("tenant", ""), a.get("app", ""), a.get("epg", ""))
    except (ValueError, RuntimeError) as e:
        return error_response(e)
    if a.get("scope") == "public":
        rows = [r for r in rows if r["scope"] == "public"]
    if a.get("learned") == "1":
        rows = [r for r in rows if r["learned"]]
    resp = make_response(ip_usage.to_csv(rows))
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = f'attachment; filename="ACI_IP_Usage_{site}_{datetime.datetime.now():%Y%m%d-%H%M}.csv"'
    return resp


# ---------------- Change history (audit) ----------------
@blueprint.get("/api/audit")
@json_api
def audit_list():
    a = request.args
    try:
        limit, offset = int(a.get("limit", 100)), int(a.get("offset", 0))
    except ValueError:
        raise ValueError("limit and offset must be numbers")
    total, items = audit.query(audit.parse_filters(a), limit, offset)
    return {"total": total, "items": items, **audit.facets()}


@blueprint.get("/api/audit/<int:record_id>")
@json_api
def audit_detail(record_id):
    record = audit.get(record_id)
    if not record:
        raise ValueError(f"Audit record #{record_id} not found")
    return {"item": record}


# One undo at a time, so two requests cannot undo the same change twice.
UNDO_LOCK = threading.Lock()


def undo_target(record_id):
    """The change to undo, after the checks that need no APIC. Only administrators and the user who made the change
    may undo it; anyone else gets 403."""
    record = audit.get(record_id)
    if not record:
        raise ValueError(f"Audit record #{record_id} not found")
    if record["action"] == "template":
        raise ValueError(f"Change #{record_id} is a product template change. It never touched APIC, so there is nothing to "
                         "undo there; edit the template again (or reset it to the default) on Fabric \u2192 Templates.")
    if record["action"] != "static-port":
        raise ValueError(f"Change #{record_id} is a provisioning change. Provisioning changes cannot be undone here, "
                         "because the portal never deletes objects.")
    if record["status"] != "success":
        raise ValueError(f"Only a successful change can be undone; change #{record_id} has status {record['status']}.")
    if record["undo_of"]:
        raise ValueError(f"Change #{record_id} is itself an undo (of change #{record['undo_of']}) and cannot be undone.")
    if record["undone_by"]:
        raise ValueError(f"Change #{record_id} was already undone by change #{record['undone_by']}.")
    user = signed_in()
    if user["role"] != "admin" and user["username"] != record["username"]:
        raise portal_auth.Forbidden(f"Only administrators and {record['username']}, who made change #{record_id}, can undo it.")
    return record


def undo_plan(record):
    """(api, plan) of the undo, always on the site of the change, never on the site selected in the browser."""
    api = site_api(record["site"])
    details = record["details"] if isinstance(record["details"], dict) else {}
    return api, aci.static_port_undo_plan(api, record["target"], details.get("items") or [])


@blueprint.post("/api/audit/<int:record_id>/undo/preview")
@json_api
def audit_undo_preview(record_id):
    """What an undo of a static-port change would do, from the bindings on APIC now. Read-only."""
    record = undo_target(record_id)
    return {"site": record["site"], "undo_of": record_id, **undo_plan(record)[1]}


@blueprint.post("/api/audit/<int:record_id>/undo")
@json_api
def audit_undo(record_id):
    """Undo a static-port change. The plan is made again here from APIC (never taken from the browser) and recorded
    like an apply: a static-port change of its own with undo_of, sent in one POST."""
    if json_body().get("confirm") is not True:
        raise ValueError('Confirm the undo with {"confirm": true}')
    with UNDO_LOCK:
        record = undo_target(record_id)   # checked again inside the lock: another request may have undone it meanwhile
        api, plan = undo_plan(record)
        if plan["conflicts"]:
            raise ValueError(aci.conflict_message(plan["conflicts"], "The undo cannot put these VLANs back."))
        if not plan["payload"]:
            raise ValueError(f"Nothing to undo: every path of change #{record_id} was changed or removed since.")
        s = plan["summary"]
        summary = (f"undo of change #{record_id}: {s['delete']} removed, {s['restore']} restored"
                   + (f", {s['skip']} skipped" if s["skip"] else ""))
        details = {"undo_of": record_id, "items": aci.undo_audit_items(plan["items"])}
        skipped = [{"tdn": i["tdn"], "reason": i["reason"]} for i in plan["items"] if i["action"] == "skip"]
        if skipped:
            details["skipped"] = skipped
        plan["audit_id"] = audited_apply("static-port", plan["epg_dn"], record["product"], summary, details,
                                         lambda: aci.apply_static_port(api, plan), site=record["site"], event="undone",
                                         undo_of=record_id)
    return {"site": record["site"], "undo_of": record_id, "applied": True, **plan}


@blueprint.get("/export/audit.csv")
def audit_export():
    try:
        signed_in()
        rows = audit.all_rows(audit.parse_filters(request.args))
    except (ValueError, RuntimeError) as e:
        return error_response(e)
    resp = make_response(audit.to_csv(rows))
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = f'attachment; filename="ACI_Change_History_{datetime.datetime.now():%Y%m%d-%H%M}.csv"'
    return resp

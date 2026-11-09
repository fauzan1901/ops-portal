"""Operation Automation catalog (catalog.yml): checks, their Knowledge Base pages, parameters, and what access they need.

Parameters from the browser are validated here before anything runs; a host parameter is resolved against the hosts
groups of the site in sites.yml, so the browser never sends an address that is not configured (no SSRF, no arbitrary
SSH target).
"""
import ipaddress
import os
import re

import yaml

from . import bmcs
from . import hosts as portal_hosts

HERE = os.path.dirname(os.path.abspath(__file__))
CATALOG_FILE = os.path.join(HERE, "catalog.yml")
KB_URL = os.environ.get("WI_KB_URL", "https://kb.example.com/index.php/apps/collectives/Knowledge-Based-2")
STATUSES = ("ready", "planned", "manual", "module")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
SERVICE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}$")
REST_KINDS = {"ontap": "ontap", "ro-vcenter": "vcenter", "ro-nsxt": "nsxt", "ro-vcd": "vcd"}
SHARED_KINDS = ("ro-vcd",)   # one system (and one account) for every site


def kb_url(page, title):
    slug = re.sub(r"[^A-Za-z0-9]+", "-", str(title or "")).strip("-")
    return f"{KB_URL}/{slug}-{int(page)}" if slug else f"{KB_URL}/{int(page)}"


# What the operator wants to do: the first level of the left menu and the filter of every list (id, title, sprite icon,
# summary). A check without "activity" is health (basis platform) or troubleshoot (a WI).
ACTIVITIES = [
    {"id": "troubleshoot", "title": "Troubleshoot a problem", "short": "Troubleshoot", "icon": "alert",
     "summary": "An alert or a customer problem: the work instructions of the Knowledge Base, the cause found and the fix."},
    {"id": "health", "title": "Health checks", "short": "Health", "icon": "check-circle",
     "summary": "The state of the platform: services and agents, nodes, capacity, hardware, certificates."},
    {"id": "operations", "title": "Operations", "short": "Operations", "icon": "refresh",
     "summary": "Planned changes and their pre- and post-checks: live migration, upgrades, clean-up, restore, ACI ports."},
    {"id": "logs", "title": "Logs & exports", "short": "Logs", "icon": "download",
     "summary": "Read error logs, collect log bundles and sos reports, export events for a vendor case."},
]
ACTIVITY_IDS = [a["id"] for a in ACTIVITIES]


def load(path=CATALOG_FILE):
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    categories = data.get("categories") or []
    checks = []
    ids = set()
    for c in data.get("checks") or []:
        if c["id"] in ids:
            raise ValueError(f"catalog.yml: check {c['id']} is listed twice")
        ids.add(c["id"])
        if c.get("status") not in STATUSES:
            raise ValueError(f"catalog.yml: check {c['id']} has an unknown status {c.get('status')!r}")
        item = dict(c, needs=list(c.get("needs") or []), uses=list(c.get("uses") or []), params=list(c.get("params") or []),
                    steps=list(c.get("steps") or []))
        item["activity"] = c.get("activity") or ("health" if c.get("basis") == "platform" else "troubleshoot")
        if item["activity"] not in ACTIVITY_IDS:
            raise ValueError(f"catalog.yml: check {c['id']} has an unknown activity {item['activity']!r}")
        # a WI not (yet) in the Knowledge Base has no page: its title is shown without a link
        item["wi"] = [dict(w, url=kb_url(w["page"], w["title"]) if w.get("page") else "") for w in c.get("wi") or []]
        if not item.get("does") or len(item["does"]) > 100:
            raise ValueError(f"catalog.yml: check {c['id']} needs does: one sentence of at most 100 characters")
        item["fix"], item["collect"] = bool(c.get("fix")), bool(c.get("collect"))
        checks.append(item)
    symptoms = []
    for s in data.get("symptoms") or []:
        unknown = [x for x in s.get("checks") or [] if x not in ids]
        if unknown or not s.get("checks"):
            raise ValueError(f"catalog.yml: symptom {s.get('id')} lists unknown checks {unknown}")
        symptoms.append({"id": s["id"], "title": s["title"], "icon": s.get("icon") or "search", "checks": list(s["checks"])})
    return {"categories": categories, "checks": checks, "symptoms": symptoms}


CATALOG = load()


def get(check_id):
    item = next((c for c in CATALOG["checks"] if c["id"] == check_id), None)
    if not item and str(check_id).startswith("tpl-"):   # a template made on the portal (templates.py)
        from . import templates
        t = templates.get(check_id)
        item = templates.as_check(t) if t else None
    if not item:
        raise ValueError(f"Unknown troubleshooting check: {check_id!r}")
    return item


# ---------------- access per site ----------------
def host_groups(site_cfg):
    return site_cfg.get("hosts") or {}


def group_members(site_cfg, group, site=""):
    """Members of a hosts group: {name: address} from sites.yml (members may be a mapping or a list of {name, host}),
    plus the hosts administrators added on the page Hosts & SSH for this site (when the site is given)."""
    if group == "bmc":   # the page BMC (Redfish over HTTPS, not SSH)
        return bmcs.members(site) if site else {}
    members = (host_groups(site_cfg).get(group) or {}).get("members") or {}
    if isinstance(members, list):
        members = {str(m.get("name")): str(m.get("host")) for m in members if isinstance(m, dict)}
    out = {str(k): str(v) for k, v in members.items()}
    if site:
        for name, address in portal_hosts.members(site, group).items():
            out.setdefault(name, address)
    return out


def access_problem(need, site, site_cfg, credential_configured):
    """Why a REST system (need ontap, ro-vcenter, ro-nsxt, ro-vcd) cannot be read on the site, "" when it can. ONTAP is
    read with the ONTAP Restore account of the site; the others with read-only accounts whose address the
    administrator sets on Administration -> Credentials."""
    kind = REST_KINDS[need]
    name = f"ontap:{site}" if need == "ontap" else need if need in SHARED_KINDS else f"{need}:{site}"
    where = f"Administration → Credentials, {name}"
    if not (site_cfg.get(kind) or {}).get("host"):
        if need == "ontap":
            return f"ontap of {site} is not in sites.yml (ONTAP Restore)"
        return f"no {kind} address" + ("" if need in SHARED_KINDS else f" for {site}") + f" ({where})"
    if not credential_configured(name):
        if need == "ontap":
            return f"no ONTAP Restore account (ontap) for {site} ({where})"
        return f"no read-only {kind} account" + ("" if need in SHARED_KINDS else f" for {site}") + f" ({where})"
    return ""


def access(check, site, site_cfg, credential_configured):
    """What the check needs on this site: {"runnable": bool, "missing": [reasons], "optional": [reasons]}."""
    missing, optional = [], []

    def problem(need):
        if need in ("openstack", "undercloud"):
            if not (site_cfg.get("mgmt") or {}).get("host") or not (site_cfg.get("director") or {}).get("host"):
                return f"OpenStack of {site} is not in sites.yml (mgmt, director)"
        elif need in REST_KINDS:
            return access_problem(need, site, site_cfg, credential_configured)
        elif need.startswith("hosts:"):
            groups = need.split(":", 1)[1].split("|")   # hosts:a|b|c = a host of any of these groups
            if groups == ["bmc"] and not group_members(site_cfg, "bmc", site):
                return f"no BMC for {site} (Operation Automation → BMC)"
            if not any(group_members(site_cfg, g, site) for g in groups):
                return f"no {'/'.join(groups)} hosts for {site} (sites.yml hosts.{groups[0]}, or Hosts & SSH)"
        return ""
    for need in check["needs"]:
        reason = problem(need)
        if reason:
            missing.append(reason)
    for use in check["uses"]:
        reason = problem(use)
        if reason:
            optional.append(reason)
    return {"runnable": check["status"] == "ready" and not missing, "missing": missing, "optional": optional}


# ---------------- parameters ----------------
def clean_params(check, raw, site, site_cfg):
    """Validated parameters of a run, plus the host it reads (or None). ValueError with the reason otherwise."""
    raw = raw if isinstance(raw, dict) else {}
    params, target = {}, None
    for p in check["params"]:
        name, kind, label = p["name"], p.get("type", "text"), p.get("label", p["name"])
        value = raw.get(name)
        value = "" if value is None else str(value).strip()
        if value == "" and p.get("default") is not None and kind != "host":
            value = str(p["default"])
        if value == "":
            if p.get("required"):
                raise ValueError(f"{label} is required")
            continue
        if kind == "uuid_list":   # several IDs (rows of the form, or pasted together): kept comma separated, in order
            items, seen = [], set()
            for x in re.split(r"[\s,;]+", value.lower()):
                if not x:
                    continue
                if not UUID.match(x):
                    raise ValueError(f"{label}: {x[:40]} is not an OpenStack UUID")
                if x not in seen:
                    seen.add(x)
                    items.append(x)
            limit = int(p.get("max") or 16)
            if len(items) > limit:
                raise ValueError(f"{label}: at most {limit} IDs per run")
            if not items and p.get("required"):
                raise ValueError(f"{label} is required")
            if items:
                params[name] = ",".join(items)
            continue
        if kind == "ip_list":   # addresses or networks (IPv4 / IPv6), comma separated, in order, once each
            items = []
            for x in re.split(r"[\s,;]+", value):
                if not x:
                    continue
                try:
                    net = ipaddress.ip_network(x, strict=False)
                except ValueError:
                    raise ValueError(f"{label}: {x[:45]} is not an IP address or network") from None
                text = str(net.network_address) if net.num_addresses == 1 else str(net)   # 10.253.0.5/32 = 10.253.0.5
                if text not in items:
                    items.append(text)
            limit = int(p.get("max") or 16)
            if len(items) > limit:
                raise ValueError(f"{label}: at most {limit} addresses")
            if items:
                params[name] = ",".join(items)
            elif p.get("required"):
                raise ValueError(f"{label} is required")
            continue
        if len(value) > 256:
            raise ValueError(f"{label} is too long")
        if kind == "int":
            if not re.fullmatch(r"-?\d+", value):
                raise ValueError(f"{label} must be a whole number")
            number = int(value)
            if ("min" in p and number < p["min"]) or ("max" in p and number > p["max"]):
                raise ValueError(f"{label} must be {p.get('min', '…')}-{p.get('max', '…')}")
            params[name] = number
        elif kind == "port":
            if not value.isdigit() or not 1 <= int(value) <= 65535:
                raise ValueError(f"{label} must be a port number 1-65535")
            params[name] = int(value)
        elif kind == "uuid":
            if not UUID.match(value.lower()):
                raise ValueError(f"{label} must be an OpenStack UUID")
            params[name] = value.lower()
        elif kind in ("project", "uuid_or_name"):
            if not (UUID.match(value.lower()) or re.fullmatch(r"[0-9a-f]{32}", value.lower()) or NAME.match(value)):
                raise ValueError(f"{label}: use the project ID or its name (letters, digits, _ . -)")
            params[name] = value
        elif kind == "ip":
            try:
                params[name] = str(ipaddress.ip_address(value))
            except ValueError:
                raise ValueError(f"{label} must be an IP address")
        elif kind == "cidr":
            try:
                params[name] = str(ipaddress.ip_network(value, strict=False))
            except ValueError:
                raise ValueError(f"{label} must be a prefix like 11.5.244.0/23")
        elif kind == "ip_port":
            m = re.fullmatch(r"([0-9.]+):(\d{1,5})", value)
            try:
                ipaddress.ip_address(m.group(1) if m else "")
            except ValueError:
                m = None
            if not m or not 1 <= int(m.group(2)) <= 65535:
                raise ValueError(f"{label} must be IP:port, e.g. 172.26.0.40:541")
            params[name] = value
        elif kind == "service":
            if not SERVICE.match(value):
                raise ValueError(f"{label} must be a systemd unit name, e.g. nginx")
            params[name] = value
        elif kind == "select":
            if value not in [str(o) for o in p.get("options") or []]:
                raise ValueError(f"{label}: choose one of {', '.join(map(str, p.get('options') or []))}")
            params[name] = value
        elif kind == "host":
            target = resolve_host(site, site_cfg, p.get("groups") or [], value, label)
            params[name] = target["name"]
        else:   # text with a pattern from the catalog
            pattern = p.get("pattern") or r"^[A-Za-z0-9 _.,:@#/-]{1,128}$"
            if not re.fullmatch(pattern, value):
                raise ValueError(f"{label} has characters that are not allowed")
            params[name] = value
    return params, target


def resolve_host(site, site_cfg, groups, value, label="Host"):
    """A member of one of the groups, by name or address ("11.16.30.4:9100" from an alert: the port is ignored)."""
    wanted = value.strip()
    if "bmc" in groups:   # a BMC of the page BMC: read with Redfish (HTTPS) and its own credential
        target = bmcs.target(site, wanted)
        if target:
            return target
        names = sorted(bmcs.members(site))
        raise ValueError(f"{label}: {value} is not a BMC of {site} (Operation Automation → BMC)"
                         + (f" (known: {', '.join(names[:12])}{' …' if len(names) > 12 else ''})" if names else ""))
    address_only = re.sub(r":\d+$", "", wanted) if wanted.count(":") == 1 else wanted
    # A host of the page Hosts & SSH: its own SSH credential (and fixes when the credential allows them).
    target = portal_hosts.target(site, groups, wanted)
    if target:
        test = str((site_cfg.get("wi") or {}).get("test_ssh_command") or "")
        if test:   # test mode only: a fake host program instead of ssh (its jump host too)
            target.update(connection="local", command=test.replace("{name}", target["name"]).replace("{address}", target["address"]))
            if target.get("jump"):
                target["jump"]["command"] = test.replace("{name}", target["jump"]["name"]).replace("{address}", target["jump"]["address"])
        return target
    for group in groups:
        members = group_members(site_cfg, group)
        for name, address in members.items():
            if wanted in (name, address) or address_only == address:
                g = host_groups(site_cfg).get(group) or {}
                target = {"name": name, "address": address, "group": group, "port": int(g.get("port") or 22),
                          "sudo": bool(g.get("sudo")), "connection": g.get("connection") or "ssh"}
                for key in ("user", "private_key", "ssh_args", "command"):
                    if g.get(key):
                        target[key] = str(g[key]).replace("{name}", name).replace("{address}", address)
                if target["connection"] == "ssh" and portal_hosts.ssh_proxy(address):
                    target["proxy"] = portal_hosts.ssh_proxy(address)
                return target
    names = sorted({n for g in groups for n in group_members(site_cfg, g, site)})
    raise ValueError(f"{label}: {value} is not a {'/'.join(groups)} host of {site} in sites.yml"
                     + (f" (known: {', '.join(names[:12])}{' …' if len(names) > 12 else ''})" if names else ""))


def host_options(check, site_cfg, site=""):
    """For the launch form: the hosts each host parameter can take on this site."""
    out = {}
    for p in check["params"]:
        if p.get("type") == "host":
            out[p["name"]] = [{"name": n, "address": a, "group": g} for g in p.get("groups") or []
                              for n, a in group_members(site_cfg, g, site).items()]
    return out

"""Where a check reads: the systems on the way from the portal to what is checked, for the diagram on the launch and run
pages (the Topology view of OpenShift / PatternFly: nodes, the connections between them, a status per node).

    {"root": node, "lanes": [[node, ...], ...]}      one lane per source of the check, read left to right
    node = {"id", "kind", "label", "sub", "via", "status", "steps": [{"title", "status"}]}

kind is an icon of the portal sprite; via is the label of the connection into the node; status is the worst status of
the steps read there ("" before a run, "reached" for a system on the way that answered). Only names and addresses from
sites.yml and the run's own parameters are shown, never an account or a secret.
"""
from . import catalog, wi_analysis

ORDER = {"fail": 4, "error": 4, "warn": 3, "ok": 2, "info": 1, "skip": 0}
OBJECTS = (  # parameter -> label of the object node at the end of the first lane
    ("volume", "Volume"), ("instance", "Instance"), ("vm", "VM"), ("edge", "Edge gateway"), ("tier1", "Tier-1 gateway"),
    ("project", "Project"), ("pool", "Cinder pool"), ("prefix", "Prefix"), ("ip", "Alert IP"),
)


def worst(statuses):
    statuses = [s for s in statuses if s]
    if not statuses:
        return ""
    best = max(statuses, key=lambda s: ORDER.get(s, 0))
    return "skip" if ORDER.get(best, 0) == 0 else best


def _node(id_, kind, label, sub="", via="", steps=None, status=""):
    steps = steps or []
    return {"id": id_, "kind": kind, "label": label, "sub": sub, "via": via, "steps": steps,
            "status": status or worst(s["status"] for s in steps)}


def _host(cfg, key):
    item = cfg.get(key) or {}
    if item.get("connection") == "local":
        return "this server"
    return str(item.get("host") or "")


def build(check, site, cfg, params=None, result=None):
    """The diagram of one check on one site; with params and the result of a run, the objects and the status per node."""
    params, result = params or {}, result or {}
    try:
        cls = wi_analysis.check(check["id"])
    except ValueError:
        return {}
    sources = list(cls.sources)
    if check.get("basis") == "template":   # one host of the group: a device (one command per SSH exec) or a shell host
        sources = ["device" if (check.get("template") or {}).get("group") == "huawei" else "host"]
    at = getattr(cls, "at", {})
    by_source = {}
    for s in result.get("steps") or []:
        for src in at.get(s.get("key"), [sources[0]]):
            by_source.setdefault(src, []).append({"title": s.get("title", ""), "status": s.get("status", "")})
    ran = bool(result.get("steps"))
    root = _node("portal", "checklist", "Ops Portal", "Ansible, read-only", status="ok" if ran else "")
    lanes = []
    for src in sources:
        steps = by_source.get(src, [])
        reached = "reached" if steps and any(s["status"] != "skip" for s in steps) else ""
        if src == "openstack":
            lanes.append([
                _node("mgmt", "server", "Management host", _host(cfg, "mgmt"), "SSH", status=reached),
                _node("director", "terminal", "Director", _host(cfg, "director"), "SSH", status=reached),
                _node("openstack", "cloud", f"OpenStack {site}", "list / show only", "source overcloudrc", steps)])
        elif src == "undercloud" and "overcloud" in sources:   # only the node list of the overcloud is read there
            continue
        elif src == "undercloud":
            lanes.append([
                _node("mgmt", "server", "Management host", _host(cfg, "mgmt"), "SSH", status=reached),
                _node("director", "terminal", "Director (undercloud)", _host(cfg, "director"), "SSH", status=reached),
                _node("ironic", "server", "Bare metal nodes", "ironic, through each BMC", "source stackrc", steps)])
        elif src == "overcloud":
            steps = by_source.get("overcloud", []) + by_source.get("undercloud", [])
            reached = "reached" if steps and any(s["status"] != "skip" for s in steps) else ""
            lanes.append([
                _node("mgmt", "server", "Management host", _host(cfg, "mgmt"), "SSH", status=reached),
                _node("director", "terminal", "Director", _host(cfg, "director"), "SSH, node list with stackrc", status=reached),
                _node("overcloud", "cubes", "Overcloud nodes", "controllers, computes", "SSH heat-admin / tripleo-admin", steps)])
        elif src == "redfish":
            target = None
            param = next((p for p in check["params"] if p.get("type") == "host"), None)
            if param and params.get(param["name"]):
                try:
                    target = catalog.resolve_host(site, cfg, param.get("groups") or [], str(params[param["name"]]))
                except ValueError:
                    target = None
            lanes.append([_node("bmc", "server", (target or {}).get("name") or "BMC",
                                (target or {}).get("address", "chosen when the check runs"), "Redfish (HTTPS GET)", steps)])
        elif src == "ontap":
            lanes.append([_node("ontap", "database", f"ONTAP {site}", _host(cfg, "ontap"), "REST GET", steps)])
        elif src in ("vcenter", "vsphere"):
            lanes.append([_node("vcenter", "server", f"vCenter {site}", _host(cfg, "vcenter"),
                                "REST GET" if src == "vcenter" else "vSphere API (read)", steps)])
        elif src == "nsxt":
            lanes.append([_node("nsxt", "network", f"NSX-T Manager {site}", _host(cfg, "nsxt"), "REST GET", steps)])
        elif src == "vcd":
            lanes.append([_node("vcd", "cloud", "vCloud Director", _host(cfg, "vcd"), "REST GET", steps)])
        elif src in ("host", "device"):
            target = None
            host_param = next((p for p in check["params"] if p.get("type") == "host"), None)
            if host_param and params.get(host_param["name"]):
                try:
                    target = catalog.resolve_host(site, cfg, host_param.get("groups") or [], str(params[host_param["name"]]))
                except ValueError:
                    target = None
            group = (target or {}).get("group") or ((host_param or {}).get("groups") or ["host"])[0]
            kind = "network" if group in ("vyos", "huawei") else "server"
            label = (target or {}).get("name") or f"{group} host"
            lanes.append([_node("host", kind, label, (target or {}).get("address", "chosen when the check runs"),
                                "SSH (display commands)" if group == "huawei" else "SSH", steps)])
        elif src == "tls":
            lanes.append([_node("tls", "lock", "Systems of the site", "vCenter, NSX-T, vCloud, ONTAP, Horizon, BMCs",
                                "TLS handshake (no account)", steps)])
        elif src == "tcp":
            ip = params.get("probe_ip") or params.get("ip")
            if ip or steps:
                lanes.append([_node("tcp", "network", "TCP test", f"{ip}:{params.get('port')}" if ip else "no IP given",
                                    "from the portal server", steps)])
    # The object of the check (from its parameters) at the end of the first lane.
    if lanes:
        obj = next(((label, params[name]) for name, label in OBJECTS if params.get(name)), None)
        if params.get("port") and sources[0] == "host":
            obj = ("Port", f"{params['port']}" + (f" ({params['service']})" if params.get("service") else ""))
        if obj:
            first = lanes[0][-1]
            lanes[0].append(_node("object", "search", obj[0], str(obj[1]), "checked", status=first["status"] if ran else ""))
    return {"root": root, "lanes": lanes}

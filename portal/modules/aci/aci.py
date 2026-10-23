"""ACI logic: discovery, static port binding, provisioning, and report data.

Every function takes `api(path, method="GET", body=None)`, already bound to one site,
so it can be tested without a real APIC. Invalid input raises ValueError with
a message that can be shown to the user as is.
"""
import ipaddress
import re
from urllib.parse import quote

NAME_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
DESCR_RE = re.compile(r"^[A-Za-z0-9\\!#$%()*,\-./:;@ _{|}~?&+]{0,128}$")
INTERFACE_RE = re.compile(r"^[A-Za-z0-9_./:-]{1,64}$")
PHYSICAL_TDN_RE = re.compile(r"^topology/pod-(\d+)/paths-(\d+)(?:/extpaths-(\d+))?/pathep-\[([^\[\]]+)\]$")
VPC_TDN_RE = re.compile(r"^topology/pod-(\d+)/protpaths-(\d+)-(\d+)(?:/extprotpaths-(\d+)-(\d+))?/pathep-\[([^\[\]]+)\]$")
EPG_CHILD_DN_RE = re.compile(r"^uni/tn-([^/]+)/ap-([^/]+)/epg-([^/]+)/")
L3OUT_CHILD_DN_RE = re.compile(r"^uni/tn-([^/]+)/out-([^/]+)/")
NODE_OF_TDN_RE = re.compile(r"/(?:paths-(\d+)|protpaths-(\d+)-(\d+)|node-(\d+))(?:/|$)")
DOMAIN_DN_RE = re.compile(r"^uni/(phys-[^/\[\]]+|vmmp-[^/\[\]]+/dom-[^/\[\]]+)$")
ETH_RE = re.compile(r"^eth\d+/\d+(/\d+)?$")
EPG_DN_RE = re.compile(r"^uni/tn-([^/]+)/ap-([^/]+)/epg-([^/]+)$")
POOL_DN_RE = re.compile(r"^uni/infra/vlanns-\[([^\[\]]+)\]-(static|dynamic)$")
VLAN_ENCAP_RE = re.compile(r"^vlan-(\d+)$")

MODES = {
    "regular": "regular", "trunk": "regular",
    "native": "native", "access_8021p": "native", "802.1p": "native",
    "untagged": "untagged", "access": "untagged", "access_untagged": "untagged",
}
IMMEDIACY = ("immediate", "lazy")
RESOLUTION = ("immediate", "lazy", "pre-provision")
SUBNET_SCOPES = ("public", "private", "shared")
PAGE_SIZE = 5000
PATH_SEARCH_LIMIT = 300


# ---------------- Validasi ----------------
def check_name(value, label):
    value = str(value or "").strip()
    if not NAME_RE.match(value):
        raise ValueError(f"{label} is invalid: '{value}' (letters, digits, and _ . : - only; max 64 characters)")
    return value


def choice(value, allowed, label):
    value = str(value or "").strip()
    if value not in allowed:
        raise ValueError(f"{label} is invalid: '{value}' (options: {', '.join(allowed)})")
    return value


def positive_int(value, label):
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        raise ValueError(f"{label} must be a number: '{value}'")
    if number < 1:
        raise ValueError(f"{label} must be greater than 0")
    return number


def truthy(value):
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def with_descr(attrs, section):
    """Add descr only when it is filled in, so the description of an existing object is not erased."""
    descr = str(section.get("descr") or "").strip()
    if descr:
        if not DESCR_RE.match(descr):
            raise ValueError(f"Invalid description: '{descr}' (max 128 characters, no quotation marks)")
        attrs["descr"] = descr
    return attrs


def epg_dn(tenant, app, epg):
    return f"uni/tn-{check_name(tenant, 'Tenant')}/ap-{check_name(app, 'Application profile')}/epg-{check_name(epg, 'EPG')}"


# ---------------- Query APIC ----------------
def mo(cls, attrs, children=None):
    body = {"attributes": attrs}
    if children:
        body["children"] = children
    return {cls: body}


def query_all(api, path):
    """GET with APIC paging until all objects are fetched."""
    items, page = [], 0
    sep = "&" if "?" in path else "?"
    while True:
        result = api(f"{path}{sep}page-size={PAGE_SIZE}&page={page}")
        batch = result.get("imdata", [])
        items.extend(batch)
        if not batch or len(items) >= int(result.get("totalCount") or 0):
            return items
        page += 1


def attrs_of(items, cls):
    return [x[cls]["attributes"] for x in items if cls in x]


def child_names(api, parent_dn, classes):
    """Names of the direct child objects of parent_dn, grouped by class."""
    items = query_all(api, f"/api/node/mo/{parent_dn}.json?query-target=children&target-subtree-class={','.join(classes)}")
    return {cls: sorted(a["name"] for a in attrs_of(items, cls)) for cls in classes}


def get_mo(api, dn):
    """Attributes of the object at dn, or None if it does not exist."""
    for item in api(f"/api/node/mo/{dn}.json").get("imdata", []):
        for body in item.values():
            return body.get("attributes", {})
    return None


# ---------------- Discovery ----------------
def vmm_provider(dn):
    match = re.match(r"^uni/vmmp-([^/]+)/", dn)
    return match.group(1) if match else "VMM"


def discover(api, kind, tenant="", app=""):
    if kind == "tenants":
        return sorted(a["name"] for a in attrs_of(query_all(api, "/api/node/class/fvTenant.json"), "fvTenant"))
    if kind == "apps":
        return child_names(api, f"uni/tn-{check_name(tenant, 'Tenant')}", ["fvAp"])["fvAp"]
    if kind == "epgs":
        return child_names(api, f"uni/tn-{check_name(tenant, 'Tenant')}/ap-{check_name(app, 'Application profile')}", ["fvAEPg"])["fvAEPg"]
    if kind == "tenant_objects":
        found = child_names(api, f"uni/tn-{check_name(tenant, 'Tenant')}", ["fvCtx", "fvBD", "fvAp", "l3extOut"])
        return {"vrfs": found["fvCtx"], "bds": found["fvBD"], "apps": found["fvAp"], "l3outs": found["l3extOut"]}
    if kind == "domains":
        physical = sorted(attrs_of(query_all(api, "/api/node/class/physDomP.json"), "physDomP"), key=lambda a: a["name"])
        vmm = sorted(attrs_of(query_all(api, "/api/node/class/vmmDomP.json"), "vmmDomP"), key=lambda a: a["dn"])
        return ([{"dn": a["dn"], "label": f"Physical / {a['name']}"} for a in physical]
                + [{"dn": a["dn"], "label": f"{vmm_provider(a['dn'])} / {a['name']}"} for a in vmm])
    raise ValueError(f"Unknown discovery type: {kind}")


def fabric_paths(api):
    """All paths (fabricPathEp) in the fabric of this site."""
    return {a["dn"] for a in attrs_of(query_all(api, "/api/node/class/fabricPathEp.json?order-by=fabricPathEp.dn"), "fabricPathEp")}


def search_paths(api, kind, keyword):
    """Search fabricPathEp. kind 'physical' = interface/PC/FEX of one leaf, 'vpc' = vPC."""
    pattern = choice(kind, ("physical", "vpc"), "Path type")
    regex = PHYSICAL_TDN_RE if pattern == "physical" else VPC_TDN_RE
    keyword = str(keyword or "").strip().lower()
    found = []
    for a in attrs_of(query_all(api, "/api/node/class/fabricPathEp.json?order-by=fabricPathEp.dn"), "fabricPathEp"):
        dn = a.get("dn", "")
        if not regex.match(dn):
            continue
        if keyword and keyword not in f"{dn} {a.get('name', '')} {a.get('descr', '')}".lower():
            continue
        found.append({"dn": dn, "name": a.get("name", ""), "descr": a.get("descr", "")})
        if len(found) >= PATH_SEARCH_LIMIT:
            break
    return found


# ---------------- Static port binding ----------------
def _binding(tdn, row):
    vlan_text = re.sub(r"^vlan[-_ =]?", "", str(row.get("vlan") or "").strip(), flags=re.I)
    vlan = positive_int(vlan_text, "VLAN")
    if vlan > 4094:
        raise ValueError(f"VLAN must be 1-4094, not {vlan}")
    mode = MODES.get(str(row.get("mode") or "regular").strip().lower())
    if not mode:
        raise ValueError(f"Unknown mode: '{row.get('mode')}' (trunk/regular, native, untagged)")
    immediacy = choice(str(row.get("immediacy") or "immediate").lower(), IMMEDIACY, "Immediacy")
    return {"tdn": tdn, "encap": f"vlan-{vlan}", "mode": mode, "immediacy": immediacy}


def normalize_bindings(physical, paths):
    """Validate the UI table rows into a list of bindings. All errors per row are collected at once."""
    bindings, errors = [], []
    for i, row in enumerate(physical or [], 1):
        try:
            pod = positive_int(row.get("pod") or 1, "Pod")
            node = positive_int(row.get("node"), "Node")
            interface = str(row.get("interface") or "").strip()
            if interface.lower().startswith("eth"):
                interface = "eth" + interface[3:]
            if not INTERFACE_RE.match(interface):
                raise ValueError(f"Invalid interface / PC: '{interface}'")
            bindings.append(_binding(f"topology/pod-{pod}/paths-{node}/pathep-[{interface}]", row))
        except ValueError as e:
            errors.append(f"Physical/PC row {i}: {e}")
    for i, row in enumerate(paths or [], 1):
        try:
            tdn = str(row.get("tdn") or "").strip()
            if not (PHYSICAL_TDN_RE.match(tdn) or VPC_TDN_RE.match(tdn)):
                raise ValueError(f"Invalid path TDN: '{tdn}'")
            bindings.append(_binding(tdn, row))
        except ValueError as e:
            errors.append(f"vPC/TDN row {i}: {e}")
    seen = set()
    for b in bindings:
        if b["tdn"] in seen:
            errors.append(f"Path {b['tdn']} is entered more than once (a path can have only one binding per EPG)")
        seen.add(b["tdn"])
    if not bindings and not errors:
        errors.append("No bindings entered")
    if errors:
        raise ValueError("\n".join(errors))
    return bindings


def existing_bindings(api, dn):
    items = query_all(api, f"/api/node/mo/{dn}.json?query-target=children&target-subtree-class=fvRsPathAtt")
    keys = ("tDn", "encap", "mode", "instrImedcy")
    return sorted(({k: a.get(k, "") for k in keys} for a in attrs_of(items, "fvRsPathAtt")), key=lambda b: b["tDn"])


def nodes_of(tdn):
    """Leaf node IDs of a path or node DN: paths-101 -> [101], protpaths-103-104 -> [103, 104], node-101 -> [101]."""
    match = NODE_OF_TDN_RE.search(str(tdn or ""))
    return [int(n) for n in match.groups() if n] if match else []


def _owner(dn):
    """Who a binding belongs to: an EPG (static path / static leaf) or an L3Out interface."""
    match = EPG_CHILD_DN_RE.match(dn)
    if match:
        return {"kind": "EPG", "tenant": match.group(1), "app": match.group(2), "name": match.group(3),
                "owner_dn": f"uni/tn-{match.group(1)}/ap-{match.group(2)}/epg-{match.group(3)}"}
    match = L3OUT_CHILD_DN_RE.match(dn)
    if match:
        return {"kind": "L3Out", "tenant": match.group(1), "app": "", "name": match.group(2),
                "owner_dn": f"uni/tn-{match.group(1)}/out-{match.group(2)}"}
    return {"kind": "Other", "tenant": "", "app": "", "name": dn, "owner_dn": dn}


# Objects that bind a VLAN to a port or leaf: static paths and static leafs of EPGs, and L3Out interfaces (SVI /
# sub-interface). A VLAN already used by one of them for ANOTHER EPG / L3Out is refused for a new static port.
VLAN_USERS = (("fvRsPathAtt", "static path"), ("fvRsNodeAtt", "static leaf"), ("l3extRsPathL3OutAtt", "L3Out interface"))
VLAN_QUERY_CHUNK = 40


def vlan_usage(api, encaps, own_epg_dn=""):
    """Where each encap (vlan-N) is already used in this fabric by another EPG or an L3Out: {encap: [usage, ...]}.
    Bindings of own_epg_dn itself are not counted (an EPG may use its VLAN on many ports)."""
    encaps = sorted(set(encaps))
    usage = {e: [] for e in encaps}
    for i in range(0, len(encaps), VLAN_QUERY_CHUNK):
        chunk = encaps[i:i + VLAN_QUERY_CHUNK]
        for cls, label in VLAN_USERS:
            terms = [f'eq({cls}.encap,"{e}")' for e in chunk]
            flt = terms[0] if len(terms) == 1 else f"or({','.join(terms)})"
            for a in attrs_of(query_all(api, f"/api/node/class/{cls}.json?query-target-filter={quote(flt, safe='(),.')}"), cls):
                encap, dn = a.get("encap", ""), a.get("dn", "")
                if encap not in usage or (own_epg_dn and dn.startswith(own_epg_dn + "/")):
                    continue
                target = a.get("tDn", "")
                usage[encap].append({**_owner(dn), "binding": label, "path": target, "nodes": nodes_of(target)})
    for users in usage.values():
        users.sort(key=lambda u: (u["owner_dn"], u["path"]))
    return usage


def vlan_conflicts(api, dn, adds):
    """VLANs that the items in adds ({"tdn", "encap"}) would put on a path of EPG dn although another EPG or an L3Out
    already uses them on this site. Every such item gets conflict=True."""
    conflicts = []
    for encap, users in vlan_usage(api, [i["encap"] for i in adds], dn).items():
        if not users:
            continue
        rows = [i for i in adds if i["encap"] == encap]
        new_nodes = {n for i in rows for n in nodes_of(i["tdn"])}
        for u in users:
            u["same_leaf"] = bool(new_nodes & set(u["nodes"]))
        for i in rows:
            i["conflict"] = True
        conflicts.append({"encap": encap, "vlan": int(encap.split("-")[1]), "paths": [i["tdn"] for i in rows], "used_by": users})
    return conflicts


def static_port_plan(api, tenant, app, epg, bindings):
    """Compare the new bindings with those already on the EPG: new / change / same.
    A VLAN already used by another EPG (static path / static leaf) or an L3Out in the fabric of this site is refused:
    conflicts is filled, blocked = True, and there is no payload. The operator must use a new VLAN ID."""
    dn = epg_dn(tenant, app, epg)
    if get_mo(api, dn) is None:
        raise ValueError(f"EPG {dn} not found on this site")
    current = {b["tDn"]: b for b in existing_bindings(api, dn)}
    items, children = [], []
    for b in bindings:
        before = current.get(b["tdn"])
        if before is None:
            status = "new"
        elif (before["encap"], before["mode"], before["instrImedcy"]) == (b["encap"], b["mode"], b["immediacy"]):
            status = "same"
        else:
            status = "change"
        items.append({**b, "status": status, "before": before})
        if status != "same":
            children.append(mo("fvRsPathAtt", {"tDn": b["tdn"], "encap": b["encap"], "mode": b["mode"], "instrImedcy": b["immediacy"]}))
    summary = {k: sum(i["status"] == k for i in items) for k in ("new", "change", "same")}
    # Only a VLAN this plan adds to a path is checked (a new binding, or a changed encap); a binding that only changes
    # mode or immediacy keeps its VLAN.
    checked = [i for i in items if i["status"] == "new" or (i["status"] == "change" and i["before"]["encap"] != i["encap"])]
    conflicts = vlan_conflicts(api, dn, checked)
    # One POST with all bindings: APIC processes it as a single transaction.
    payload = {"fvAEPg": {"attributes": {"dn": dn}, "children": children}} if children and not conflicts else None
    return {"epg_dn": dn, "items": items, "summary": summary, "payload": payload, "conflicts": conflicts,
            "blocked": bool(conflicts)}


def conflict_message(conflicts, advice="Use a new VLAN ID that no other EPG uses."):
    """One line per VLAN for an error message: which EPG / L3Out already uses it."""
    lines = []
    for c in conflicts:
        owners = list(dict.fromkeys(f"{u['kind']} {u['tenant']}/{u['app'] + '/' if u['app'] else ''}{u['name']}" for u in c["used_by"]))
        more = f" and {len(owners) - 3} more" if len(owners) > 3 else ""
        lines.append(f"VLAN {c['vlan']} is already used by {', '.join(owners[:3])}{more}")
    return "; ".join(lines) + ". " + advice


def apply_static_port(api, plan):
    if plan.get("conflicts"):
        raise ValueError(conflict_message(plan["conflicts"]))
    if plan["payload"]:
        api(f"/api/node/mo/{plan['epg_dn']}.json", "POST", plan["payload"])


# ---------------- Free VLAN suggestions ----------------
def vlan_id(encap):
    """VLAN number of an encap such as vlan-100; None for anything else (vxlan-..., unknown, empty)."""
    match = VLAN_ENCAP_RE.match(str(encap or ""))
    return int(match.group(1)) if match else None


def domain_label(dn):
    """Domain as in the domain list of Provisioning: "Physical / DCB-PHYS", "VMware / DCB-DVS"."""
    match = re.match(r"^uni/phys-(.+)$", dn)
    if match:
        return f"Physical / {match.group(1)}"
    match = re.match(r"^uni/vmmp-([^/]+)/dom-(.+)$", dn)
    return f"{match.group(1)} / {match.group(2)}" if match else dn


def ranges_text(vlans):
    """VLAN IDs as ranges: {100, 101, 102, 105} -> "100-102, 105"."""
    parts = []
    for v in sorted(vlans):
        if parts and v == parts[-1][1] + 1:
            parts[-1][1] = v
        else:
            parts.append([v, v])
    return ", ".join(f"{a}-{b}" if a != b else str(a) for a, b in parts)


def vlans_in_use(api, own_epg_dn=""):
    """(used, own): every VLAN ID bound on this site by a static path, static leaf, or L3Out interface, and the ones
    bound by own_epg_dn itself."""
    used, own = set(), set()
    for cls, _ in VLAN_USERS:
        for a in attrs_of(query_all(api, f"/api/node/class/{cls}.json"), cls):
            vlan = vlan_id(a.get("encap"))
            if vlan is None:
                continue
            used.add(vlan)
            if own_epg_dn and a.get("dn", "").startswith(own_epg_dn + "/"):
                own.add(vlan)
    return used, own


def vlan_suggestions(api, tenant, app, epg, count=10):
    """VLAN IDs a new static port of the EPG can use: inside the static blocks of the VLAN pools of the EPG's domains
    (a block with allocMode inherit takes the mode of its pool) and not used on this site by any EPG (the EPG itself
    included) or L3Out. Also the VLANs the EPG already uses, which it may use on more ports. Read-only."""
    dn = epg_dn(tenant, app, epg)
    if get_mo(api, dn) is None:
        raise ValueError(f"EPG {dn} not found on this site")
    rels = query_all(api, f"/api/node/mo/{dn}.json?query-target=children&target-subtree-class=fvRsDomAtt")
    domains = sorted({a.get("tDn", "") for a in attrs_of(rels, "fvRsDomAtt")} - {""})
    pools, no_pool = {}, []   # pool DN -> {"name", "mode", "domains", "vlans"}
    for domain in domains:
        found = attrs_of(query_all(api, f"/api/node/mo/{domain}.json?query-target=children&target-subtree-class=infraRsVlanNs"),
                         "infraRsVlanNs")
        pool_dn = next((a["tDn"] for a in found if a.get("tDn")), "")
        match = POOL_DN_RE.match(pool_dn)   # the allocation mode of a pool is part of its DN
        if not match:
            no_pool.append(domain_label(domain))
            continue
        pool = pools.setdefault(pool_dn, {"name": match.group(1), "mode": match.group(2), "domains": [], "vlans": set()})
        pool["domains"].append(domain_label(domain))
    for pool_dn, pool in pools.items():
        blocks = attrs_of(query_all(api, f"/api/node/mo/{pool_dn}.json?query-target=children&target-subtree-class=fvnsEncapBlk"),
                          "fvnsEncapBlk")
        for b in blocks:
            mode = b.get("allocMode") or "inherit"
            low, high = vlan_id(b.get("from")), vlan_id(b.get("to"))
            if (pool["mode"] if mode == "inherit" else mode) != "static" or low is None or high is None:
                continue
            low, high = sorted((low, high))
            pool["vlans"].update(range(max(low, 1), min(high, 4094) + 1))
    used, own = vlans_in_use(api, dn)
    static = set().union(*(p["vlans"] for p in pools.values()))
    free = sorted(static - used)
    note = ""
    if not free and not domains:
        note = "This EPG has no physical or VMM domain, so there is no VLAN pool to take a VLAN from. Add a domain to the EPG first."
    elif not free:
        reasons = [f"no VLAN pool on domain {', '.join(no_pool)}"] if no_pool else []
        dynamic = [p["name"] for p in pools.values() if not p["vlans"]]
        if dynamic:
            reasons.append(f"only dynamic VLAN blocks in pool {', '.join(dynamic)} (a static port needs a static block)")
        if static:
            reasons.append(f"every VLAN of the static blocks ({ranges_text(static)}) is already used on this site")
        note = "No free VLAN: " + "; ".join(reasons) + "."
    return {"epg_dn": dn, "own": sorted(own), "free": free[:count], "free_total": len(free), "note": note,
            "pools": [{"name": p["name"], "domain": ", ".join(p["domains"]), "ranges": ranges_text(p["vlans"]),
                       "free_count": len(p["vlans"] - used)} for p in pools.values() if p["vlans"]]}


# ---------------- Undo of a static-port change ----------------
UNDO_ACTIONS = ("delete", "restore", "skip")


def static_port_undo_plan(api, target, items):
    """Plan that undoes a successful static-port change of EPG `target`, from the items of its audit record: a new path
    is deleted, a changed path gets back its values from before the change. Every path is first read on APIC; one that
    no longer has what the change set (changed or removed since) is skipped, so a later change is never overwritten.
    A restore that brings back a VLAN is checked like an apply: a VLAN of another EPG or L3Out blocks the undo."""
    match = EPG_DN_RE.match(str(target or ""))
    if not match:
        raise ValueError(f"Not an EPG: {target}")
    dn = epg_dn(*match.groups())
    if get_mo(api, dn) is None:
        raise ValueError(f"EPG {dn} no longer exists on this site, so there is nothing to undo")
    current = {b["tDn"]: b for b in existing_bindings(api, dn)}
    planned, children = [], []
    for item in (i for i in items if isinstance(i, dict)):
        tdn, status = str(item.get("tdn") or ""), item.get("status")
        now = current.get(tdn)
        entry = {"tdn": tdn, "before": now, "expected": {k: item.get(k) for k in ("encap", "mode", "immediacy")}}
        old = item.get("before") or {}
        restore = (old.get("encap"), old.get("mode"), old.get("instrImedcy"))
        if status not in ("new", "change") or not (PHYSICAL_TDN_RE.match(tdn) or VPC_TDN_RE.match(tdn)):
            entry.update(action="skip", reason="Cannot be undone: not a path this change added or changed.")
        elif now is None:
            entry.update(action="skip", reason=("Already removed" if status == "new" else "Removed since")
                         + ": the path is no longer on APIC.")
        elif (now["encap"], now["mode"], now["instrImedcy"]) != (item.get("encap"), item.get("mode"), item.get("immediacy")):
            entry.update(action="skip", reason=f"Changed since: APIC now has {now['encap']}, {now['mode']}, {now['instrImedcy']};"
                                               " a later change is never overwritten.")
        elif status == "new":
            entry.update(action="delete", status="delete")
            children.append(mo("fvRsPathAtt", {"tDn": tdn, "status": "deleted"}))
        elif vlan_id(restore[0]) is None or restore[1] not in MODES.values() or restore[2] not in IMMEDIACY:
            entry.update(action="skip", reason="Cannot be restored: the values from before this change are not recorded.")
        else:
            entry.update(action="restore", status="change", encap=restore[0], mode=restore[1], immediacy=restore[2])
            children.append(mo("fvRsPathAtt", {"tDn": tdn, "encap": restore[0], "mode": restore[1], "instrImedcy": restore[2]}))
        planned.append(entry)
    summary = {k: sum(i["action"] == k for i in planned) for k in UNDO_ACTIONS}
    # Only a restore that puts another VLAN back on its path is checked; a delete frees its VLAN.
    conflicts = vlan_conflicts(api, dn, [i for i in planned if i["action"] == "restore" and i["encap"] != i["before"]["encap"]])
    # One POST for the whole undo: APIC processes it as a single transaction.
    payload = {"fvAEPg": {"attributes": {"dn": dn}, "children": children}} if children and not conflicts else None
    return {"epg_dn": dn, "items": planned, "summary": summary, "payload": payload, "conflicts": conflicts,
            "blocked": bool(conflicts)}


def undo_audit_items(items):
    """The paths an undo plan changes, as static-port audit items: status "delete" (before = the binding as it was) or
    "change" (the values put back; before = the values before the undo)."""
    keys = ("tdn", "encap", "mode", "immediacy", "status", "before")
    return [{k: i[k] for k in keys if k in i} for i in items if i["action"] != "skip"]


# ---------------- Provisioning ----------------
def check_subnet(entry):
    ip = str(entry.get("ip") or "").strip()
    try:
        iface = ipaddress.ip_interface(ip)
    except ValueError:
        raise ValueError(f"Invalid subnet: '{ip}' (e.g. 10.249.10.1/24)")
    if "/" not in ip:
        raise ValueError(f"Subnet '{ip}' must include a prefix length, e.g. 10.249.10.1/24")
    if iface.network.prefixlen < iface.max_prefixlen - 1 and iface.ip == iface.network.network_address:
        raise ValueError(f"Subnet '{ip}' is the network address; enter the gateway IP instead, e.g. {iface.network.network_address + 1}/{iface.network.prefixlen}")
    scopes = [s.strip().lower() for s in str(entry.get("scope") or "public").split(",") if s.strip()]
    if not scopes or set(scopes) - set(SUBNET_SCOPES) or {"public", "private"} <= set(scopes):
        raise ValueError(f"Scope of subnet '{ip}' is invalid: '{entry.get('scope')}' (public or private, optionally plus shared)")
    return {"ip": ip, "scope": ",".join(scopes), "preferred": "yes" if truthy(entry.get("preferred")) else "no",
            "virtual": "yes" if truthy(entry.get("virtual")) else "no"}


def provisioning_plan(api, req):
    """Build one fvTenant payload (one APIC transaction) with the steps and warnings for the preview."""
    t, v, b, a, e = ((req or {}).get(k) or {} for k in ("tenant", "vrf", "bd", "app", "epg"))
    tenant_mode = choice(t.get("mode"), ("existing", "new"), "Tenant mode")
    vrf_mode = choice(v.get("mode") or "none", ("none", "existing", "new"), "VRF mode")
    bd_mode = choice(b.get("mode") or "none", ("none", "existing", "new"), "Bridge domain mode")
    app_mode = choice(a.get("mode"), ("existing", "new"), "Application profile mode")
    tenant = check_name(t.get("name"), "Tenant name")
    vrf = check_name(v.get("name"), "VRF name") if vrf_mode != "none" else ""
    bd = check_name(b.get("name"), "Bridge domain name") if bd_mode != "none" else ""
    app = check_name(a.get("name"), "Application profile name")
    epg = check_name(e.get("name"), "EPG name")
    deployment = choice(req.get("deployment") or "immediate", IMMEDIACY, "Deployment immediacy")
    resolution = choice(req.get("resolution") or "immediate", RESOLUTION, "Resolution immediacy")
    domains = []
    for dn in req.get("domains") or []:
        if not DOMAIN_DN_RE.match(str(dn)):
            raise ValueError(f"Invalid domain: '{dn}'")
        if dn not in domains:
            domains.append(dn)
    subnets = [check_subnet(s) for s in (b.get("subnets") or [])] if bd_mode == "new" else []
    l3outs = [check_name(x, "L3Out name") for x in (b.get("l3outs") or [])] if bd_mode == "new" else []
    unknown_unicast = choice(b.get("unknown_unicast") or "proxy", ("proxy", "flood"), "L2 Unknown Unicast")

    tenant_dn = f"uni/tn-{tenant}"
    tenant_exists = get_mo(api, tenant_dn) is not None
    have = child_names(api, tenant_dn, ["fvCtx", "fvBD", "fvAp"]) if tenant_exists else {"fvCtx": [], "fvBD": [], "fvAp": []}
    app_exists = app in have["fvAp"]
    epg_path = f"{tenant_dn}/ap-{app}/epg-{epg}"
    epg_exists = app_exists and get_mo(api, epg_path) is not None
    steps, warnings = [], []

    def step(obj, name, kind, action):
        steps.append({"object": obj, "name": name, "kind": kind, "action": action})

    def track(obj, name, mode, found, note):
        if mode == "existing":
            if not found:
                raise ValueError(f"{obj} '{name}' does not exist on this site")
            step(obj, name, "use", "use existing")
        elif found:
            step(obj, name, "change", "update existing")
            warnings.append(f"{obj} '{name}' already exists on this site: {note}")
        else:
            step(obj, name, "new", "create")

    track("Tenant", tenant, tenant_mode, tenant_exists, "its description is updated if one is entered.")
    tenant_attrs = {"dn": tenant_dn}
    if tenant_mode == "new":
        with_descr(tenant_attrs, t).update(name=tenant)
    tenant_children = []

    if vrf_mode != "none":
        track("VRF", vrf, vrf_mode, vrf in have["fvCtx"], "its description is updated if one is entered.")
        if vrf_mode == "new":
            tenant_children.append(mo("fvCtx", with_descr({"name": vrf}, v)))

    if bd_mode != "none":
        track("Bridge domain", bd, bd_mode, bd in have["fvBD"], "its VRF, ARP flooding, unknown unicast, and subnets will be set to match the form.")
        if bd_mode == "new":
            bd_children = []
            if vrf:
                bd_children.append(mo("fvRsCtx", {"tnFvCtxName": vrf}))
                step("BD → VRF", f"{bd} → {vrf}", "link", "relation")
            else:
                warnings.append(f"Bridge domain '{bd}' is created without a VRF; the BD will have a fault until a VRF is set.")
            for s in subnets:
                bd_children.append(mo("fvSubnet", s))
                step("Subnet", f"{s['ip']} ({s['scope']})", "new", "create / update")
            for out in l3outs:
                bd_children.append(mo("fvRsBDToOut", {"tnL3extOutName": out}))
                step("BD → L3Out", f"{bd} → {out}", "link", "relation")
            bd_attrs = with_descr({"name": bd, "arpFlood": "yes" if truthy(b.get("arp_flood")) else "no", "unkMacUcastAct": unknown_unicast}, b)
            tenant_children.append(mo("fvBD", bd_attrs, bd_children))

    track("Application profile", app, app_mode, app_exists, "its description is updated if one is entered.")
    app_attrs = {"name": app}
    if app_mode == "new":
        with_descr(app_attrs, a)

    step("EPG", epg, "change" if epg_exists else "new", "update existing" if epg_exists else "create")
    epg_children = []
    if bd:
        epg_children.append(mo("fvRsBd", {"tnFvBDName": bd}))
        step("EPG → BD", f"{epg} → {bd}", "link", "relation")
        current_bd = (get_mo(api, f"{epg_path}/rsbd") or {}).get("tnFvBDName") if epg_exists else None
        if current_bd and current_bd != bd:
            warnings.append(f"EPG '{epg}' currently uses BD '{current_bd}' and will be moved to BD '{bd}'.")
    for dn in domains:
        epg_children.append(mo("fvRsDomAtt", {"tDn": dn, "instrImedcy": deployment, "resImedcy": resolution}))
        step("EPG → Domain", dn, "link", f"deployment {deployment}, resolution {resolution}")
    if epg_exists:
        warnings.append(f"EPG '{epg}' already exists: the BD and domain relations in the form will be added or updated.")
    tenant_children.append(mo("fvAp", app_attrs, [mo("fvAEPg", with_descr({"name": epg}, e), epg_children)]))

    payload = {"fvTenant": {"attributes": tenant_attrs, "children": tenant_children}}
    return {"tenant_dn": tenant_dn, "epg_dn": epg_path, "steps": steps, "warnings": warnings, "payload": payload}


def apply_provisioning(api, plan):
    api(f"/api/node/mo/{plan['tenant_dn']}.json", "POST", plan["payload"])


# ---------------- Report ----------------
def path_info(tdn):
    match = VPC_TDN_RE.match(tdn or "")
    if match:
        return {"Binding Type": "vPC", "Pod": int(match.group(1)), "Node(s)": f"{match.group(2)}-{match.group(3)}", "Interface / Policy Group": match.group(6)}
    match = PHYSICAL_TDN_RE.match(tdn or "")
    if match:
        interface = match.group(4)
        node = match.group(2) + (f"/FEX-{match.group(3)}" if match.group(3) else "")
        return {"Binding Type": "Physical" if ETH_RE.match(interface) else "PC", "Pod": int(match.group(1)), "Node(s)": node, "Interface / Policy Group": interface}
    return {"Binding Type": "Other", "Pod": "", "Node(s)": "", "Interface / Policy Group": ""}


def report_rows(api, tenant="", app="", epg=""):
    """All static bindings (fvRsPathAtt) matching the filters; an empty filter means all."""
    subtree = "target-subtree-class=fvRsPathAtt&order-by=fvRsPathAtt.dn"
    if epg:
        path = f"/api/node/mo/{epg_dn(tenant, app, epg)}.json?query-target=children&{subtree}"
    elif app:
        path = f"/api/node/mo/uni/tn-{check_name(tenant, 'Tenant')}/ap-{check_name(app, 'Application profile')}.json?query-target=subtree&{subtree}"
    elif tenant:
        path = f"/api/node/mo/uni/tn-{check_name(tenant, 'Tenant')}.json?query-target=subtree&{subtree}"
    else:
        path = "/api/node/class/fvRsPathAtt.json?order-by=fvRsPathAtt.dn"
    rows = []
    for a in attrs_of(query_all(api, path), "fvRsPathAtt"):
        match = EPG_CHILD_DN_RE.match(a.get("dn", ""))
        if not match:
            continue
        encap = a.get("encap", "")
        vlan = re.match(r"^vlan-(\d+)$", encap)
        rows.append({
            "Tenant": match.group(1), "Application Profile": match.group(2), "EPG": match.group(3),
            "VLAN": int(vlan.group(1)) if vlan else "", "Encapsulation": encap, "Mode": a.get("mode", ""),
            "Deployment Immediacy": a.get("instrImedcy", ""), "Path TDN": a.get("tDn", ""), **path_info(a.get("tDn", "")),
            "Last Changed (APIC)": a.get("modTs", ""),
        })
    rows.sort(key=lambda r: (r["Tenant"], r["Application Profile"], r["EPG"], r["Path TDN"]))
    return rows


# Where a binding of the report comes from, compared with the portal's own record of its static-port changes.
SOURCES = {"portal": "Portal", "outside": "Outside portal", "changed": "Changed outside portal",
           "removed": "Removed outside portal"}


def report_scope(tenant="", app="", epg=""):
    """The EPG DNs a report with these filters covers, as (prefix, exact): one EPG, or every EPG under a prefix."""
    if epg:
        return epg_dn(tenant, app, epg), True
    if app:
        return f"uni/tn-{check_name(tenant, 'Tenant')}/ap-{check_name(app, 'Application profile')}/epg-", False
    if tenant:
        return f"uni/tn-{check_name(tenant, 'Tenant')}/ap-", False
    return "", False


def _source(row, source, item):
    row["source"], row["Source"] = source, SOURCES[source]
    row["portal"] = {"change": item["change"], "status": item.get("status", ""), "encap": item.get("encap", ""),
                     "mode": item.get("mode", ""), "immediacy": item.get("immediacy", "")} if item else None


def binding_sources(rows, portal):
    """Mark every report row with its source. portal: {(epg_dn, tdn): the latest item of a successful static-port
    change for that path} for the report's filters. A path the portal set that APIC no longer has is added as a row
    with the portal's values and no APIC data."""
    seen = set()
    for row in rows:
        key = (f"uni/tn-{row['Tenant']}/ap-{row['Application Profile']}/epg-{row['EPG']}", row["Path TDN"])
        seen.add(key)
        item = portal.get(key)
        if item is None:
            _source(row, "outside", None)
        elif item.get("status") != "delete" and (item.get("encap"), item.get("mode"), item.get("immediacy")) == (
                row["Encapsulation"], row["Mode"], row["Deployment Immediacy"]):
            _source(row, "portal", item)
        else:   # APIC has other values now, or the portal deleted the path and it is back
            _source(row, "changed", item)
    for (dn, tdn), item in portal.items():
        match = EPG_DN_RE.match(dn)
        if (dn, tdn) in seen or item.get("status") == "delete" or not match:
            continue
        encap = str(item.get("encap") or "")
        vlan = vlan_id(encap)
        row = {"Tenant": match.group(1), "Application Profile": match.group(2), "EPG": match.group(3),
               "VLAN": vlan if vlan is not None else "", "Encapsulation": encap, "Mode": item.get("mode", ""),
               "Deployment Immediacy": item.get("immediacy", ""), "Path TDN": tdn, **path_info(tdn), "Last Changed (APIC)": ""}
        _source(row, "removed", item)
        rows.append(row)
    rows.sort(key=lambda r: (r["Tenant"], r["Application Profile"], r["EPG"], r["Path TDN"]))
    return rows

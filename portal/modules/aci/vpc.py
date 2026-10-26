"""New vPC on a pair of leaves (Fabric > Access Policies), as an operator does it in the APIC GUI, after a Review:

  vPC policy group   uni/infra/funcprof/accbundle-<name>   infraAccBndlGrp lagT=node, with its AAEP and interface policies
  interface selector uni/infra/accportprof-<profile>/hports-<selector>-typ-range, port blocks, infraRsAccBaseGrp -> the
                     policy group, in the interface profile(s) the leaf profiles attach to the two leaves: one profile of the
                     pair (the same ports on both leaves, one selector) or one profile per leaf (a selector in each)

then APIC shows the path topology/pod-<pod>/protpaths-<a>-<b>/pathep-[<name>] that Static Port binds to EPGs.

The portal only ADDS objects: it never changes or deletes a policy group, selector or port that exists. Everything is
read again from APIC for the plan (never taken from the browser) and sent in one POST (one APIC transaction).
"""
import re
from urllib.parse import quote

from . import fabric
from .aci import DESCR_RE, attrs_of, check_name, mo, query_all

PERMISSION = "aci-interfaces"
PORT_RE = re.compile(r"^eth(\d+)/(\d+)$")
MAX_PORTS = 16   # per leaf
# Settings of the policy group: (key, label, policy class, relation class, relation attribute, required)
SETTINGS = (
    ("aaep", "AAEP", "infraAttEntityP", "infraRsAttEntP", "tDn", True),
    ("link", "Link level", "fabricHIfPol", "infraRsHIfPol", "tnFabricHIfPolName", False),
    ("lacp", "Port-channel policy (LACP)", "lacpLagPol", "infraRsLacpPol", "tnLacpLagPolName", True),
    ("cdp", "CDP", "cdpIfPol", "infraRsCdpIfPol", "tnCdpIfPolName", False),
    ("lldp", "LLDP", "lldpIfPol", "infraRsLldpIfPol", "tnLldpIfPolName", False),
    ("mcp", "MCP", "mcpIfPol", "infraRsMcpIfPol", "tnMcpIfPolName", False),
)
AAEP_DN = "uni/infra/attentp-{}"
FUNCPROF = "uni/infra/funcprof"


def can_create(user):
    """Administrators, and accounts with the permission 'ACI: create vPCs' (ticked on the Users page)."""
    return bool(user) and (user.get("role") == "admin" or PERMISSION in (user.get("modules") or []))


def _get(api, cls):
    return attrs_of(query_all(api, f"/api/node/class/{cls}.json"), cls)


def _parent(dn, marker):
    i = dn.find(marker)
    return dn[:i] if i >= 0 else ""


def profile_name(dn):
    return re.sub(r"^uni/infra/accportprof-", "", dn)


def _value(key, rel):
    value = rel.get("tDn" if key == "aaep" else next(s[4] for s in SETTINGS if s[0] == key), "")
    return re.sub(r"^uni/infra/attentp-", "", value) if key == "aaep" else value


def read(api):
    """Everything a new vPC is planned from: the fabric ports, the vPC pairs, the interface profiles of each leaf, the
    policy groups (their names, and the settings of the vPC ones) and the interface policies. GET only."""
    data = fabric.fabric_interfaces(api)
    profiles = fabric.profile_nodes(api)
    bundles = {g["dn"]: g for g in _get(api, "infraAccBndlGrp")}
    names = sorted({g.get("name", "") for g in bundles.values()} | {g.get("name", "") for g in _get(api, "infraAccPortGrp")})
    settings = {}
    for key, _label, _cls, rel_cls, _attr, _req in SETTINGS:
        for rel in _get(api, rel_cls):
            parent = _parent(rel["dn"], "/rs")
            if parent in bundles:
                settings.setdefault(parent, {})[key] = _value(key, rel)
    policies = {key: sorted(p.get("name", "") for p in _get(api, cls)) for key, _label, cls, *_ in SETTINGS}
    return {"data": data, "profiles": profiles, "bundles": bundles, "names": names, "settings": settings, "policies": policies}


def _pair_profiles(profiles, a, b):
    """Interface profiles of the pair (applied to exactly these two leaves) and of each leaf alone (DNs, sorted)."""
    pair = sorted(dn for dn, nodes in profiles.items() if nodes == {a, b})
    leaf = {n: sorted(dn for dn, nodes in profiles.items() if nodes == {n}) for n in (a, b)}
    return pair, leaf


def options(api):
    """For the Create vPC page: the vPC pairs with their profiles and ports, the vPC policy groups with their settings
    (to copy from), the interface policies and every policy group name in use."""
    r = read(api)
    pod = {n["id"]: n["pod"] for n in r["data"]["nodes"]}
    pairs, used_nodes = [], set()
    for p in r["data"]["vpc_pairs"]:
        a, b = p["nodes"]
        pair, leaf = _pair_profiles(r["profiles"], a, b)
        used_nodes.update((a, b))
        pairs.append({"name": p["name"], "nodes": [a, b], "pod": pod.get(a, 1), "vpcs": [v["name"] for v in p["vpcs"]],
                      "profiles": {"pair": [profile_name(x) for x in pair], "leaf": {str(n): [profile_name(x) for x in leaf[n]] for n in (a, b)}}})
    pair_of = {v: f"{p['nodes'][0]}-{p['nodes'][1]}" for p in pairs for v in p["vpcs"]}
    groups = [dict({"name": g.get("name", ""), "descr": g.get("descr", ""), "pair": pair_of.get(g.get("name", ""), "")},
                   **{key: r["settings"].get(dn, {}).get(key, "") for key, *_ in SETTINGS})
              for dn, g in sorted(r["bundles"].items()) if g.get("lagT") == "node"]
    ports = {}
    for row in r["data"]["interfaces"]:
        if row["node"] in used_nodes and PORT_RE.match(row["interface"]):
            ports.setdefault(str(row["node"]), []).append({
                "interface": row["interface"], "status": row["status"], "oper": row["oper"], "admin": row["admin"],
                "neighbor": row["neighbor"], "bindings": len(row["bindings"]), "policy_group": row["policy_group"] or row["channel"],
                "selector": row["selector"], "profile": row["profile"], "descr": row["descr"]})
    return {"pairs": pairs, "ports": ports, "groups": groups, "policies": r["policies"], "names": r["names"]}


def _ports(value, label):
    if not isinstance(value, list) or not value:
        raise ValueError(f"Tick at least one port on {label}.")
    if len(value) > MAX_PORTS:
        raise ValueError(f"At most {MAX_PORTS} ports per leaf ({label}).")
    out = []
    for item in value:
        port = str(item or "").strip().lower()
        if not PORT_RE.match(port):
            raise ValueError(f"Invalid interface on {label}: '{item}' (for example eth1/23)")
        if port not in out:
            out.append(port)
    return sorted(out, key=fabric.port_key)


def blocks(ports):
    """Port blocks of a selector: consecutive ports of a card in one block (eth1/23-24), named like the APIC GUI does."""
    nums = sorted({(int(PORT_RE.match(p)[1]), int(PORT_RE.match(p)[2])) for p in ports})
    ranges = []
    for card, port in nums:
        if ranges and ranges[-1][0] == card and ranges[-1][2] == port - 1:
            ranges[-1][2] = port
        else:
            ranges.append([card, port, port])
    return [{"name": f"block{i + 2}", "fromCard": str(c), "toCard": str(c), "fromPort": str(lo), "toPort": str(hi)}
            for i, (c, lo, hi) in enumerate(ranges)]


def block_text(ports):
    return ", ".join(f"eth{b['fromCard']}/{b['fromPort']}" + (f"-{b['toPort']}" if b["toPort"] != b["fromPort"] else "") for b in blocks(ports))


def plan(api, d):
    """The new vPC as it would be sent, checked against APIC now. Result: {"pair", "nodes", "pod", "name", "pg_dn",
    "path", "selector", "profiles": [{"dn", "name", "nodes", "ports"}], "ports", "settings", "checks", "warnings",
    "blocked", "steps", "payload" (None when blocked)}. Raises ValueError for input that is not valid at all."""
    r = read(api)
    rows = {(row["node"], row["interface"]): row for row in r["data"]["interfaces"]}
    pairs = {f"{p['nodes'][0]}-{p['nodes'][1]}": p for p in r["data"]["vpc_pairs"]}
    key = str(d.get("pair") or "").strip()
    if key not in pairs:
        raise ValueError(f"Leaf pair '{key}' is not a vPC pair (vPC protection group) of this site: choose one of {', '.join(pairs) or 'none'}.")
    a, b = pairs[key]["nodes"]
    pod = next((n["pod"] for n in r["data"]["nodes"] if n["id"] == a), 1)
    name = check_name(d.get("name"), "Policy group name")
    descr = str(d.get("descr") or "").strip()
    if descr and not DESCR_RE.match(descr):
        raise ValueError(f"Invalid description: '{descr}' (max 128 characters, no quotation marks)")
    raw = d.get("ports") if isinstance(d.get("ports"), dict) else {}
    ports = {a: _ports(raw.get(str(a)), f"leaf {a}"), b: _ports(raw.get(str(b)), f"leaf {b}")}
    selector = check_name(d.get("selector") or re.sub(r"-PG$", "", name), "Selector name")
    settings_in = d.get("settings") if isinstance(d.get("settings"), dict) else {}
    checks, warnings, blocked = [], [], []

    def check(ok, text, block=True):
        checks.append({"ok": bool(ok), "text": text})
        if not ok and block:
            blocked.append(text)

    check(True, f"Leaves {a} and {b} are vPC pair {pairs[key]['name']} (vPC protection group).")
    taken = [n for n in r["names"] if n.lower() == name.lower()]
    check(not taken, f"Policy group name {name} is not used yet." if not taken
          else f"A policy group named {taken[0]} exists already: choose another name.")
    for n in (a, b):
        for port in ports[n]:
            row = rows.get((n, port))
            if not row:
                check(False, f"{port} does not exist on leaf {n}.")
            elif row["status"] == "uplink":
                check(False, f"{port} on leaf {n} is a fabric uplink.")
            elif row["status"] != "free":
                where = f"selector {row['selector']} of {row['profile']}" if row["selector"] else f"port-channel {row['channel']}"
                check(False, f"{port} on leaf {n} is in use: {where} (policy group {row['policy_group'] or row['channel']}).")
            else:
                check(True, f"{port} on leaf {n} is in no interface selector.")
                if row["oper"] == "up" or row["neighbor"]:
                    seen = f", connected to {row['neighbor']['name']} {row['neighbor']['port']}".rstrip() if row["neighbor"] else ""
                    warnings.append(f"{port} on leaf {n} is {row['oper'] or 'unknown'}{seen}: make sure it is the server of this vPC.")
                if row["bindings"]:
                    warnings.append(f"{port} on leaf {n} has {len(row['bindings'])} static path(s) on the port itself; "
                                    "once it is in the vPC, bind the vPC path instead.")
    if len(ports[a]) != len(ports[b]):
        warnings.append(f"Leaf {a} gets {len(ports[a])} port(s) and leaf {b} gets {len(ports[b])}: a vPC usually has the same links on both leaves.")
    settings = {}
    for skey, label, _cls, _rel, _attr, required in SETTINGS:
        value = str(settings_in.get(skey) or "").strip()
        if not value:
            if required:
                check(False, f"{label}: choose one.")
            continue
        exists = value in r["policies"][skey]
        check(exists, f"{label} {value} exists." if exists else f"{label} {value} does not exist on this site.")
        if exists:
            settings[skey] = value
    if settings.get("aaep"):
        domains = [x for x in _get(api, "infraRsDomP") if x["dn"].startswith(AAEP_DN.format(settings["aaep"]) + "/")]
        if not domains:
            warnings.append(f"AAEP {settings['aaep']} has no domain: an EPG binding on this vPC would fail (domain / VLAN pool).")
    # Where the selector goes: the profile of the pair (the same ports on both leaves), else one profile per leaf.
    pair_ifps, leaf_ifps = _pair_profiles(r["profiles"], a, b)
    wanted = str(d.get("profile") or "").strip()
    targets = []
    if pair_ifps and ports[a] == ports[b] and (not wanted or wanted in [profile_name(x) for x in pair_ifps]):
        dn = next((x for x in pair_ifps if profile_name(x) == wanted), pair_ifps[0])
        targets = [{"dn": dn, "name": profile_name(dn), "nodes": [a, b], "ports": ports[a]}]
    elif leaf_ifps[a] and leaf_ifps[b]:
        targets = [{"dn": leaf_ifps[n][0], "name": profile_name(leaf_ifps[n][0]), "nodes": [n], "ports": ports[n]} for n in (a, b)]
    elif pair_ifps:
        check(False, f"Interface profile {profile_name(pair_ifps[0])} applies to both leaves, so the ports must be the same on leaf {a} and leaf {b}.")
    else:
        check(False, f"No interface profile applies to leaves {a}-{b} or to each of them alone: create the leaf and interface profiles on APIC first.")
    selectors = {}
    for sel in _get(api, "infraHPortS"):
        selectors.setdefault(_parent(sel["dn"], "/hports-"), set()).add(sel.get("name", ""))
    for t in targets:
        free = selector not in selectors.get(t["dn"], set())
        check(free, f"Selector {selector} is new in interface profile {t['name']} ({' and '.join(f'leaf {n}' for n in t['nodes'])})."
              if free else f"Interface profile {t['name']} has a selector named {selector} already: choose another selector name.")
    pg_dn = f"{FUNCPROF}/accbundle-{name}"
    path = f"topology/pod-{pod}/protpaths-{a}-{b}/pathep-[{name}]"
    relations = [mo(rel, {attr: AAEP_DN.format(settings[k]) if k == "aaep" else settings[k]})
                 for k, _label, _cls, rel, attr, _req in SETTINGS if k in settings]
    group = mo("infraAccBndlGrp", dict({"name": name, "lagT": "node"}, **({"descr": descr} if descr else {})), relations)
    profiles_payload = [mo("infraAccPortP", {"dn": t["dn"]}, [mo("infraHPortS", {"name": selector, "type": "range"},
                        [mo("infraPortBlk", blk) for blk in blocks(t["ports"])] + [mo("infraRsAccBaseGrp", {"tDn": pg_dn})])])
                        for t in targets]
    payload = mo("infraInfra", {"dn": "uni/infra"}, [mo("infraFuncP", {"dn": FUNCPROF}, [group])] + profiles_payload)
    steps = [{"object": "vPC policy group", "name": pg_dn, "kind": "new", "action": "Create"}]
    steps += [{"object": label, "name": AAEP_DN.format(settings[k]) if k == "aaep" else settings[k], "kind": "link", "action": "Link"}
              for k, label, *_ in SETTINGS if k in settings]
    for t in targets:
        sel_dn = f"{t['dn']}/hports-{selector}-typ-range"
        steps.append({"object": "Interface selector", "name": sel_dn, "kind": "new", "action": "Create"})
        steps.append({"object": "Port blocks", "name": f"{block_text(t['ports'])} on {' and '.join(f'leaf {n}' for n in t['nodes'])}",
                      "kind": "new", "action": "Create"})
    steps.append({"object": "vPC path (made by APIC)", "name": path, "kind": "new", "action": "Appears"})
    return {"pair": key, "pair_name": pairs[key]["name"], "nodes": [a, b], "pod": pod, "name": name, "descr": descr,
            "pg_dn": pg_dn, "path": path, "selector": selector, "profiles": targets,
            "ports": {str(n): ports[n] for n in (a, b)}, "settings": settings, "checks": checks, "warnings": warnings,
            "blocked": blocked, "steps": steps, "payload": None if blocked else payload}


def apply(api, p):
    """One POST to uni/infra: the policy group and the selectors in one APIC transaction."""
    api("/api/node/mo/uni/infra.json", "POST", p["payload"])


def path_ready(api, path):
    """Whether APIC shows the vPC path (fabricPathEp) yet."""
    flt = quote(f'eq(fabricPathEp.dn,"{path}")', safe="(),.")
    found = attrs_of(query_all(api, f"/api/node/class/fabricPathEp.json?query-target-filter={flt}"), "fabricPathEp")
    return any(x.get("dn") == path for x in found)

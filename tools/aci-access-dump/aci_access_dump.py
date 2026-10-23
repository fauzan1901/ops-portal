#!/usr/bin/env python3
"""Read-only dump of the Cisco ACI fabric access policies of one site, for the design of the interface /
port-channel / vPC automation (docs/ADR-004-aci-access-policies.md).

    python3 aci_access_dump.py --site DCB --user <APIC account>          # asks for the password
    APIC_HOST=172.26.2.250 APIC_USER=<account> APIC_PASSWORD=... python3 aci_access_dump.py --site DCB --out DIR

Writes DIR/<site>-<time>/: raw/<class>.json (every object of each class), ports.csv, policy_groups.csv,
selectors.csv and summary.md. Only aaaLogin and aaaLogout are POSTed (sign-in and sign-out); every other request is a
GET, so nothing on APIC changes. Python 3 standard library only; APIC is always reached directly (proxy variables are
ignored), the certificate is not checked unless --verify-tls is given (as the portal, APIC_VERIFY_TLS=0).
"""
import argparse
import collections
import csv
import datetime
import getpass
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.request

SITES = {"DCB": "172.26.2.250", "DCA": "172.24.27.251", "DCC": "172.25.172.53"}
PAGE_SIZE = 5000
SIGN_IN = ("/api/aaaLogin.json", "/api/aaaLogout.json")
# Every class that is read: (class, what it is). A class this APIC version does not know is noted and skipped.
CLASSES = [
    ("firmwareCtrlrRunning", "APIC version"),
    ("firmwareRunning", "switch software version per node"),
    ("fabricNode", "APICs, spines, leaves (id, name, model)"),
    ("fabricExplicitGEp", "vPC protection group (vPC pair)"),
    ("fabricNodePEp", "the two leaves of a vPC pair"),
    ("infraNodeP", "leaf (switch) profile"),
    ("infraLeafS", "switch selector of a leaf profile"),
    ("infraNodeBlk", "node block of a switch selector"),
    ("infraRsAccPortP", "leaf profile -> interface profile"),
    ("infraAccPortP", "leaf interface profile"),
    ("infraHPortS", "interface (port) selector"),
    ("infraPortBlk", "port block of a selector"),
    ("infraSubPortBlk", "sub-port block (breakout)"),
    ("infraRsAccBaseGrp", "selector -> policy group"),
    ("infraFexP", "FEX profile"),
    ("infraFexBndlGrp", "FEX policy group"),
    ("infraAccPortGrp", "policy group: leaf access port"),
    ("infraAccBndlGrp", "policy group: port-channel (lagT=link) or vPC (lagT=node)"),
    ("infraBrkoutPortGrp", "policy group: breakout"),
    ("infraRsAttEntP", "policy group -> AAEP"),
    ("infraRsHIfPol", "policy group -> link level policy"),
    ("infraRsLacpPol", "policy group -> LACP policy"),
    ("infraRsCdpIfPol", "policy group -> CDP policy"),
    ("infraRsLldpIfPol", "policy group -> LLDP policy"),
    ("infraRsMcpIfPol", "policy group -> MCP policy"),
    ("infraRsStormctrlIfPol", "policy group -> storm control policy"),
    ("infraRsL2IfPol", "policy group -> L2 interface policy (VLAN scope)"),
    ("infraPortConfig", "interface configuration (port-centric model, newer APIC versions)"),
    ("infraAttEntityP", "AAEP (attachable access entity profile)"),
    ("infraRsDomP", "AAEP -> domain"),
    ("physDomP", "physical domain"),
    ("vmmDomP", "VMM domain"),
    ("l3extDomP", "L3 domain"),
    ("l2extDomP", "L2 external domain"),
    ("infraRsVlanNs", "domain -> VLAN pool"),
    ("fvnsVlanInstP", "VLAN pool"),
    ("fvnsEncapBlk", "VLAN block of a pool"),
    ("fabricHIfPol", "link level policy (speed)"),
    ("lacpLagPol", "LACP policy"),
    ("cdpIfPol", "CDP policy"),
    ("lldpIfPol", "LLDP policy"),
    ("mcpIfPol", "MCP policy"),
    ("stormctrlIfPol", "storm control policy"),
    ("l2IfPol", "L2 interface policy"),
    ("l1PhysIf", "physical interface of a switch (admin state, usage)"),
    ("ethpmPhysIf", "operational state of a physical interface"),
    ("pcAggrIf", "port-channel on a leaf"),
    ("pcRsMbrIfs", "member port of a port-channel"),
    ("lldpAdjEp", "LLDP neighbour on a port"),
    ("cdpAdjEp", "CDP neighbour on a port"),
    ("fabricPathEp", "paths that can be bound to an EPG (static port)"),
    ("fvRsPathAtt", "static port bindings of the EPGs"),
]
PORT_DN_RE = re.compile(r"^topology/pod-(\d+)/node-(\d+)/sys/phys-\[(eth(\d+)/(\d+)(?:/(\d+))?)\]$")
NEIGHBOUR_DN_RE = re.compile(r"^topology/pod-(\d+)/node-(\d+)/sys/(?:lldp|cdp)/inst/if-\[(eth[\d/]+)\]/")
AGGR_DN_RE = re.compile(r"^topology/pod-(\d+)/node-(\d+)/sys/aggr-\[([^\]]+)\]")


class ApicError(RuntimeError):
    pass


class Apic:
    """GET-only APIC client: sign-in, paged class queries, sign-out."""

    def __init__(self, host, verify=False, ca_file=None, timeout=60):
        self.host, self.timeout, self.token = host, timeout, None
        self.username = self.password = None
        ctx = ssl.create_default_context(cafile=ca_file) if (verify or ca_file) else ssl._create_unverified_context()
        # Always direct: http(s)_proxy of the bastion (apt, pip) is never used for APIC.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
        self.requests = []   # (method, path) of every request, for the read-only check of the tests

    def _request(self, method, path, body=None):
        if method != "GET" and path not in SIGN_IN:
            raise AssertionError(f"read-only tool: {method} {path} is not allowed")
        self.requests.append((method, path.split("?", 1)[0]))
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Cookie"] = f"APIC-cookie={self.token}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f"https://{self.host}{path}", data=data, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")
            try:
                detail = json.loads(detail)["imdata"][0]["error"]["attributes"]["text"]
            except (ValueError, KeyError, IndexError, TypeError):
                pass
            raise ApicError(f"HTTP {e.code}: {detail}")
        except OSError as e:
            raise ApicError(f"{type(e).__name__}: {e}")

    def login(self, username, password):
        self.username, self.password = username, password
        result = self._request("POST", "/api/aaaLogin.json", {"aaaUser": {"attributes": {"name": username, "pwd": password}}})
        self.token = result["imdata"][0]["aaaLogin"]["attributes"]["token"]

    def logout(self):
        if self.token:
            try:
                self._request("POST", "/api/aaaLogout.json", {"aaaUser": {"attributes": {"name": self.username}}})
            except ApicError:
                pass   # the token expires by itself
            self.token = None

    def get_class(self, cls):
        """Every object of a class (attributes only), page by page; one new sign-in when the token was refused."""
        items, page = [], 0
        while True:
            path = f"/api/node/class/{cls}.json?order-by={cls}.dn&page-size={PAGE_SIZE}&page={page}"
            try:
                result = self._request("GET", path)
            except ApicError as e:
                if "Token" not in str(e) and "HTTP 401" not in str(e) and "HTTP 403" not in str(e):
                    raise
                self.login(self.username, self.password)
                result = self._request("GET", path)
            chunk = [next(iter(o.values()))["attributes"] for o in result.get("imdata", []) if isinstance(o, dict) and o]
            items += chunk
            total = int(result.get("totalCount") or 0)
            if len(chunk) < PAGE_SIZE or len(items) >= total:
                return items
            page += 1


# ---------------- analysis ----------------
def parent(dn):
    """Parent of a DN, minding '/' inside [ ] (e.g. rsaccPortP-[uni/infra/accportprof-X])."""
    depth = 0
    for i in range(len(dn) - 1, -1, -1):
        if dn[i] == "]":
            depth += 1
        elif dn[i] == "[":
            depth -= 1
        elif dn[i] == "/" and depth == 0:
            return dn[:i]
    return ""


def name_of(dn):
    """Name in the last RN: accbundle-X -> X, accportprof-X -> X, hports-X-typ-range -> X."""
    rn = dn[len(parent(dn)) + 1:] if parent(dn) else dn
    rn = re.sub(r"-typ-\w+$", "", rn)
    return rn.split("-", 1)[1] if "-" in rn else rn


def pool_name(dn):
    """uni/infra/vlanns-[NAME]-static -> 'NAME (static)'."""
    m = re.match(r"^uni/infra/vlanns-\[(.+)\]-(\w+)$", dn or "")
    return f"{m[1]} ({m[2]})" if m else name_of(dn) if dn else ""


def ranges(numbers, prefix="eth1/"):
    """[1, 2, 3, 7] -> 'eth1/1-3, eth1/7'."""
    out, numbers = [], sorted(set(numbers))
    while numbers:
        start = end = numbers.pop(0)
        while numbers and numbers[0] == end + 1:
            end = numbers.pop(0)
        out.append(f"{prefix}{start}" + (f"-{end}" if end != start else ""))
    return ", ".join(out)


def pattern(name):
    """Naming pattern of a policy group: 'Openstack-Traffic-A-PG' -> 'Openstack-Traffic-*-PG', digits -> #."""
    parts = name.split("-")
    if len(parts) >= 3 and parts[-1].upper() == "PG":
        parts[-2] = "*"
    return re.sub(r"\d+", "#", "-".join(parts))


def common(values):
    counts = collections.Counter(v for v in values if v)
    return ", ".join(f"{v} ({n})" for v, n in counts.most_common(3)) or "—"


def analyze(objs):
    """Tables and findings from the raw classes: {"nodes", "pairs", "profiles", "selectors", "groups", "ports",
    "aaeps", "policies", "warnings", ...}."""
    by_dn = {cls: {o["dn"]: o for o in items} for cls, items in objs.items()}
    children = collections.defaultdict(list)   # parent dn -> [(class, attributes)]
    for cls, items in objs.items():
        for o in items:
            children[parent(o["dn"])].append((cls, o))

    def child(dn, cls):
        return [o for c, o in children.get(dn, []) if c == cls]

    nodes = {int(o["id"]): o for o in objs.get("fabricNode", []) if str(o.get("id", "")).isdigit()}
    leaves = sorted(n for n, o in nodes.items() if o.get("role") == "leaf")
    pairs = []
    for g in objs.get("fabricExplicitGEp", []):
        members = sorted(int(o["id"]) for o in child(g["dn"], "fabricNodePEp") if str(o.get("id", "")).isdigit())
        pairs.append({"name": g.get("name", ""), "id": g.get("id", ""), "nodes": members})

    # Leaf profiles -> nodes -> interface profiles.
    profile_nodes = collections.defaultdict(set)   # interface profile dn -> leaves
    leaf_profiles = []
    for p in objs.get("infraNodeP", []):
        nodes_of = set()
        for sel in child(p["dn"], "infraLeafS"):
            for blk in child(sel["dn"], "infraNodeBlk"):
                try:
                    nodes_of |= set(range(int(blk.get("from_")), int(blk.get("to_")) + 1))
                except (TypeError, ValueError):
                    pass
        targets = [r.get("tDn", "") for r in child(p["dn"], "infraRsAccPortP")]
        for t in targets:
            profile_nodes[t] |= nodes_of
        leaf_profiles.append({"name": p.get("name", ""), "nodes": sorted(nodes_of), "interface_profiles": [name_of(t) for t in targets]})

    # Policy groups.
    groups = {}
    for cls, kind in (("infraAccPortGrp", None), ("infraAccBndlGrp", None), ("infraBrkoutPortGrp", "Breakout"), ("infraFexBndlGrp", "FEX")):
        for g in objs.get(cls, []):
            if cls == "infraAccPortGrp":
                kind = "Access"
            elif cls == "infraAccBndlGrp":
                kind = "vPC" if g.get("lagT") == "node" else "PC"
            rel = lambda c, attr: next((o.get(attr, "") or "default" for o in child(g["dn"], c)), "")
            groups[g["dn"]] = {"name": g.get("name", ""), "type": kind, "class": cls, "descr": g.get("descr", ""),
                               "aaep": name_of(rel("infraRsAttEntP", "tDn")) if rel("infraRsAttEntP", "tDn") not in ("", "default") else "",
                               "link": rel("infraRsHIfPol", "tnFabricHIfPolName"), "lacp": rel("infraRsLacpPol", "tnLacpLagPolName"),
                               "cdp": rel("infraRsCdpIfPol", "tnCdpIfPolName"), "lldp": rel("infraRsLldpIfPol", "tnLldpIfPolName"),
                               "mcp": rel("infraRsMcpIfPol", "tnMcpIfPolName"), "storm": rel("infraRsStormctrlIfPol", "tnStormctrlIfPolName"),
                               "l2": rel("infraRsL2IfPol", "tnL2IfPolName"), "selectors": [], "ports": set()}

    # Interface profiles and their selectors.
    selectors, profiles = [], []
    port_config = collections.defaultdict(list)   # (node, card, port) -> [selector]
    for ifp in objs.get("infraAccPortP", []) + objs.get("infraFexP", []):
        attached = sorted(profile_nodes.get(ifp["dn"], set()))
        sels = child(ifp["dn"], "infraHPortS")
        profiles.append({"name": ifp.get("name", ""), "class": "FEX" if ifp["dn"].startswith("uni/infra/fexprof-") else "leaf",
                         "nodes": attached, "selectors": len(sels)})
        for sel in sels:
            blocks = []
            for blk in child(sel["dn"], "infraPortBlk"):
                try:
                    for card in range(int(blk["fromCard"]), int(blk["toCard"]) + 1):
                        for port in range(int(blk["fromPort"]), int(blk["toPort"]) + 1):
                            blocks.append((card, port))
                except (KeyError, ValueError):
                    pass
            pg_dn = next((r.get("tDn", "") for r in child(sel["dn"], "infraRsAccBaseGrp")), "")
            pg = groups.get(pg_dn)
            row = {"profile": ifp.get("name", ""), "nodes": attached, "selector": sel.get("name", ""), "descr": sel.get("descr", ""),
                   "blocks": blocks, "sub_ports": len(child(sel["dn"], "infraSubPortBlk")), "pg": pg["name"] if pg else name_of(pg_dn) if pg_dn else "",
                   "pg_type": pg["type"] if pg else ("missing" if pg_dn else ""), "pg_dn": pg_dn}
            selectors.append(row)
            if pg:
                pg["selectors"].append(row)
            for n in attached:
                for card, port in blocks:
                    port_config[(n, card, port)].append(row)
                    if pg:
                        pg["ports"].add(f"{n}:eth{card}/{port}")

    # Ports with their state, configuration, port-channel, neighbour and bindings.
    eth = {o["dn"][:-len("/phys")]: o for o in objs.get("ethpmPhysIf", [])}
    members = {}
    for m in objs.get("pcRsMbrIfs", []):
        match = AGGR_DN_RE.match(m["dn"])
        if match:
            aggr = by_dn.get("pcAggrIf", {}).get(f"topology/pod-{match[1]}/node-{match[2]}/sys/aggr-[{match[3]}]", {})
            members[(int(match[2]), m.get("tSKey", ""))] = aggr.get("name") or match[3]
    neighbours = {}
    for cls, attr in (("lldpAdjEp", "sysName"), ("cdpAdjEp", "devId")):
        for o in objs.get(cls, []):
            match = NEIGHBOUR_DN_RE.match(o["dn"])
            if match:
                neighbours.setdefault((int(match[2]), match[3]), f"{o.get(attr, '')} ({o.get('portIdV') or o.get('portId') or ''})".replace(" ()", ""))
    bindings = collections.Counter(o.get("tDn", "") for o in objs.get("fvRsPathAtt", []))
    paths = {o["dn"] for o in objs.get("fabricPathEp", [])}
    ports, warnings = [], []
    for p in objs.get("l1PhysIf", []):
        m = PORT_DN_RE.match(p["dn"])
        if not m or m[6]:   # sub-ports (breakout) are listed with their parent
            continue
        pod, node, iface, card, port = int(m[1]), int(m[2]), m[3], int(m[4]), int(m[5])
        state = eth.get(p["dn"], {})
        sels = port_config.get((node, card, port), [])
        sel = sels[0] if sels else None
        pg = groups.get(sel["pg_dn"]) if sel else None
        fabric = p.get("usage") == "fabric" or state.get("usage") == "fabric" or p.get("portT") == "fab"
        if pg and pg["type"] == "vPC":
            pair = next((x["nodes"] for x in pairs if node in x["nodes"]), [])
            pg_path = f"topology/pod-{pod}/protpaths-{pair[0]}-{pair[1]}/pathep-[{pg['name']}]" if len(pair) == 2 else ""
        elif pg and pg["type"] == "PC":
            pg_path = f"topology/pod-{pod}/paths-{node}/pathep-[{pg['name']}]"
        else:
            pg_path = f"topology/pod-{pod}/paths-{node}/pathep-[{iface}]"
        bound = bindings.get(pg_path, 0)
        status = ("fabric uplink" if fabric else "overlap" if len(sels) > 1 else "free" if not sel
                  else "configured, bound" if bound else "configured, no EPG binding")
        if len(sels) > 1:
            warnings.append(f"Node {node} {iface} is in {len(sels)} selectors: " + ", ".join(f"{s['profile']}/{s['selector']}" for s in sels))
        ports.append({"node": node, "node_name": nodes.get(node, {}).get("name", ""), "interface": iface, "card": card, "port": port,
                      "admin": p.get("adminSt", ""), "oper": state.get("operSt", ""), "speed": state.get("operSpeed", ""),
                      "usage": state.get("usage") or p.get("usage", ""), "descr": p.get("descr", ""), "status": status,
                      "profile": sel["profile"] if sel else "", "selector": sel["selector"] if sel else "", "pg": pg["name"] if pg else (sel["pg"] if sel else ""),
                      "pg_type": pg["type"] if pg else (sel["pg_type"] if sel else ""), "aaep": pg["aaep"] if pg else "", "link": pg["link"] if pg else "",
                      "port_channel": members.get((node, iface), ""), "path": pg_path, "path_exists": pg_path in paths, "bindings": bound,
                      "neighbour": neighbours.get((node, iface), "")})

    # Findings on the configuration itself.
    for s in selectors:
        if not s["pg_dn"]:
            warnings.append(f"Selector {s['profile']}/{s['selector']} has no policy group")
        elif s["pg_type"] == "missing":
            warnings.append(f"Selector {s['profile']}/{s['selector']} points to a missing policy group {s['pg_dn']}")
        if not s["nodes"]:
            warnings.append(f"Selector {s['profile']}/{s['selector']}: its interface profile is not attached to any leaf profile")
    for g in groups.values():
        if g["type"] in ("Access", "PC", "vPC") and not g["aaep"]:
            warnings.append(f"Policy group {g['name']} ({g['type']}) has no AAEP")
        if g["type"] == "vPC":
            used_nodes = {int(p.split(":")[0]) for p in g["ports"]}
            if len(used_nodes) == 1:
                warnings.append(f"vPC policy group {g['name']} has ports on one leaf only ({sorted(used_nodes)[0]})")
    unused = sorted(g["name"] for g in groups.values() if not g["selectors"] and g["type"] in ("Access", "PC", "vPC"))

    # AAEPs -> domains -> VLAN pools.
    pool_blocks = collections.defaultdict(list)
    for b in objs.get("fvnsEncapBlk", []):
        pool_blocks[parent(b["dn"])].append(f"{b.get('from', '').replace('vlan-', '')}-{b.get('to', '').replace('vlan-', '')}"
                                            + (f" ({b.get('allocMode')})" if b.get("allocMode") not in ("", "inherit", None) else ""))
    domain_pool = {parent(r["dn"]): r.get("tDn", "") for r in objs.get("infraRsVlanNs", [])}
    aaeps = []
    for a in objs.get("infraAttEntityP", []):
        domains = [r.get("tDn", "") for r in child(a["dn"], "infraRsDomP")]
        aaeps.append({"name": a.get("name", ""), "domains": [
            {"domain": d, "pool": pool_name(domain_pool.get(d, "")), "blocks": pool_blocks.get(domain_pool.get(d, ""), [])}
            for d in domains], "policy_groups": sum(1 for g in groups.values() if g["aaep"] == a.get("name"))})
    policies = {
        "Link level": [(o.get("name"), f"speed {o.get('speed', '')}, auto-neg {o.get('autoNeg', '')}") for o in objs.get("fabricHIfPol", [])],
        "LACP": [(o.get("name"), f"mode {o.get('mode', '')}") for o in objs.get("lacpLagPol", [])],
        "CDP": [(o.get("name"), o.get("adminSt", "")) for o in objs.get("cdpIfPol", [])],
        "LLDP": [(o.get("name"), f"rx {o.get('adminRxSt', '')}, tx {o.get('adminTxSt', '')}") for o in objs.get("lldpIfPol", [])],
        "MCP": [(o.get("name"), o.get("adminSt", "")) for o in objs.get("mcpIfPol", [])],
    }
    return {"nodes": nodes, "leaves": leaves, "pairs": pairs, "leaf_profiles": leaf_profiles, "profiles": profiles,
            "selectors": selectors, "groups": list(groups.values()), "unused_groups": unused, "ports": ports, "aaeps": aaeps,
            "policies": policies, "warnings": warnings, "port_config_objects": len(objs.get("infraPortConfig", []))}


# ---------------- output ----------------
def write_csv(path, header, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def summary_md(site, host, a, objs, errors, started):
    version = ", ".join(sorted({o.get("version", "") for o in objs.get("firmwareCtrlrRunning", [])})) or "?"
    switch_versions = common(o.get("version", "") for o in objs.get("firmwareRunning", []))
    lines = [f"# ACI access policies — {site} ({host})", "",
             f"Read-only dump, {started:%Y-%m-%d %H:%M}. APIC version: **{version}**; switch software: {switch_versions}.", ""]
    counts = [("Leaves", len(a["leaves"])), ("vPC pairs", len(a["pairs"])), ("Leaf profiles", len(a["leaf_profiles"])),
              ("Interface profiles", len(a["profiles"])), ("Selectors", len(a["selectors"])),
              ("Policy groups", len(a["groups"])), ("AAEPs", len(a["aaeps"])),
              ("Interface configurations (port-centric model)", a["port_config_objects"])]
    lines += ["| Object | Count |", "|---|---|"] + [f"| {k} | {v} |" for k, v in counts] + [""]
    if a["port_config_objects"]:
        lines += ["**Note:** this fabric also uses *Interface Configuration* (infraPortConfig, the port-centric model); "
                  "automation must follow that model for those ports.", ""]
    lines += ["## Leaves and vPC pairs", "", "| Node | Name | Model | vPC pair |", "|---|---|---|---|"]
    for n in a["leaves"]:
        o = a["nodes"][n]
        pair = next((p["name"] for p in a["pairs"] if n in p["nodes"]), "—")
        lines.append(f"| {n} | {o.get('name', '')} | {o.get('model', '')} | {pair} |")
    lines += ["", "## Leaf profiles → interface profiles", "",
              "How the interface profiles are attached tells whether a new port needs one selector (profile per vPC pair) or two "
              "(one per leaf).", "", "| Leaf profile | Leaves | Interface profiles |", "|---|---|---|"]
    lines += [f"| {p['name']} | {', '.join(map(str, p['nodes'])) or '—'} | {', '.join(p['interface_profiles']) or '—'} |" for p in a["leaf_profiles"]]
    shape = collections.Counter("per vPC pair" if len(p["nodes"]) == 2 else "per leaf" if len(p["nodes"]) == 1 else
                                "not attached" if not p["nodes"] else f"{len(p['nodes'])} leaves" for p in a["profiles"])
    lines += ["", "Interface profiles: " + ", ".join(f"{k}: {v}" for k, v in shape.items()), ""]
    lines += ["## Policy groups: naming patterns", "",
              "| Type | Pattern | Count | Examples | AAEP | Link level | LACP | CDP / LLDP |", "|---|---|---|---|---|---|---|---|"]
    by_pattern = collections.defaultdict(list)
    for g in a["groups"]:
        by_pattern[(g["type"], pattern(g["name"]))].append(g)
    for (kind, pat), items in sorted(by_pattern.items(), key=lambda x: (x[0][0], -len(x[1]))):
        lines.append(f"| {kind} | `{pat}` | {len(items)} | {', '.join(g['name'] for g in items[:3])} | {common(g['aaep'] for g in items)} "
                     f"| {common(g['link'] for g in items)} | {common(g['lacp'] for g in items)} "
                     f"| {common(g['cdp'] for g in items)} / {common(g['lldp'] for g in items)} |")
    same = sum(1 for s in a["selectors"] if s["pg"] and s["selector"] == s["pg"])
    stripped = sum(1 for s in a["selectors"] if s["pg"] and s["selector"] == re.sub(r"[-_]PG$", "", s["pg"], flags=re.I))
    lines += ["", f"Selector names: {same} equal to the policy group, {stripped} the policy group without -PG, "
              f"{len(a['selectors']) - same - stripped} other. Examples: "
              + ", ".join(f"`{s['selector']}` → `{s['pg']}`" for s in a["selectors"][:6]), ""]
    if a["unused_groups"]:
        lines += [f"Policy groups in no selector ({len(a['unused_groups'])}): " + ", ".join(a["unused_groups"][:30])
                  + (" …" if len(a["unused_groups"]) > 30 else ""), ""]
    lines += ["## AAEPs → domains → VLAN pools", "", "| AAEP | Policy groups | Domain | VLAN pool | Blocks |", "|---|---|---|---|---|"]
    for x in a["aaeps"]:
        for i, d in enumerate(x["domains"] or [{"domain": "—", "pool": "", "blocks": []}]):
            lines.append(f"| {x['name'] if i == 0 else ''} | {x['policy_groups'] if i == 0 else ''} | {d['domain']} | {d['pool'] or '—'} "
                         f"| {', '.join(d['blocks'][:6]) or '—'}{' …' if len(d['blocks']) > 6 else ''} |")
    lines += ["", "## Interface policies", ""]
    for kind, items in a["policies"].items():
        lines.append(f"- **{kind}**: " + (", ".join(f"`{n}` ({d})" for n, d in items) or "—"))
    lines += ["", "## Ports per leaf", "", "| Node | Free (in no selector) | Configured, no EPG binding | Configured, bound (ports) | Uplinks |",
              "|---|---|---|---|---|"]
    for n in a["leaves"]:
        mine = [p for p in a["ports"] if p["node"] == n]
        pick = lambda status: ranges([p["port"] for p in mine if p["status"] == status and p["card"] == 1])
        lines.append(f"| {n} | {pick('free') or '—'} | {pick('configured, no EPG binding') or '—'} | "
                     f"{len([p for p in mine if p['status'] == 'configured, bound'])} | {pick('fabric uplink') or '—'} |")
    lines += ["", "## Findings", ""] + ([f"- {w}" for w in a["warnings"][:100]] or ["- None."])
    if len(a["warnings"]) > 100:
        lines.append(f"- … and {len(a['warnings']) - 100} more")
    if errors:
        lines += ["", "## Not read", ""] + [f"- `{cls}`: {e}" for cls, e in errors.items()]
    lines += ["", "Details: ports.csv, policy_groups.csv, selectors.csv; every object in raw/."]
    return "\n".join(lines) + "\n"


def dump(apic, site, out_dir, log=lambda m: print(m, file=sys.stderr)):
    started = datetime.datetime.now()
    folder = os.path.join(out_dir, f"{site}-{started:%Y%m%d-%H%M}")
    os.makedirs(os.path.join(folder, "raw"), exist_ok=True)
    objs, errors = {}, {}
    for cls, what in CLASSES:
        t = time.time()
        try:
            objs[cls] = apic.get_class(cls)
        except ApicError as e:
            errors[cls] = str(e)
            log(f"  {cls:24} not read: {e}")
            continue
        with open(os.path.join(folder, "raw", f"{cls}.json"), "w", encoding="utf-8") as f:
            json.dump(objs[cls], f, indent=1, ensure_ascii=False)
        log(f"  {cls:24} {len(objs[cls]):6} ({what}, {time.time() - t:.1f} s)")
    a = analyze(objs)
    write_csv(os.path.join(folder, "ports.csv"),
              ["Node", "Node name", "Interface", "Admin", "Oper", "Speed", "Usage", "Status", "Interface profile", "Selector",
               "Policy group", "PG type", "AAEP", "Link level", "Port-channel", "Path", "Path in fabric", "EPG bindings",
               "Neighbour", "Description"],
              [[p["node"], p["node_name"], p["interface"], p["admin"], p["oper"], p["speed"], p["usage"], p["status"], p["profile"],
                p["selector"], p["pg"], p["pg_type"], p["aaep"], p["link"], p["port_channel"], p["path"], "yes" if p["path_exists"] else "no",
                p["bindings"], p["neighbour"], p["descr"]] for p in sorted(a["ports"], key=lambda p: (p["node"], p["card"], p["port"]))])
    write_csv(os.path.join(folder, "policy_groups.csv"),
              ["Name", "Type", "AAEP", "Link level", "LACP", "CDP", "LLDP", "MCP", "Storm control", "L2 interface", "Selectors", "Ports", "Description"],
              [[g["name"], g["type"], g["aaep"], g["link"], g["lacp"], g["cdp"], g["lldp"], g["mcp"], g["storm"], g["l2"],
                len(g["selectors"]), " ".join(sorted(g["ports"])), g["descr"]] for g in sorted(a["groups"], key=lambda g: (g["type"], g["name"]))])
    write_csv(os.path.join(folder, "selectors.csv"),
              ["Interface profile", "Leaves", "Selector", "Ports", "Sub-port blocks", "Policy group", "PG type", "Description"],
              [[s["profile"], " ".join(map(str, s["nodes"])), s["selector"], ranges([p for c, p in s["blocks"]]), s["sub_ports"], s["pg"],
                s["pg_type"], s["descr"]] for s in a["selectors"]])
    with open(os.path.join(folder, "summary.md"), "w", encoding="utf-8") as f:
        f.write(summary_md(site, apic.host, a, objs, errors, started))
    return folder, a, errors


def main(argv=None):
    ap = argparse.ArgumentParser(description="Read-only dump of the ACI access policies of one site (GET only).")
    ap.add_argument("--site", required=True, help="site name, e.g. DCB")
    ap.add_argument("--apic", default=os.environ.get("APIC_HOST"), help="APIC address (default: the known address of the site)")
    ap.add_argument("--user", default=os.environ.get("APIC_USER"), help="APIC account (read-only is enough)")
    ap.add_argument("--out", default=os.path.join(os.getcwd(), "aci-access-dump-out"), help="output folder")
    ap.add_argument("--verify-tls", action="store_true", help="check the APIC certificate against the system CAs")
    ap.add_argument("--ca-file", help="check the APIC certificate against this CA file")
    args = ap.parse_args(argv)
    site = args.site.strip().upper()
    host = args.apic or SITES.get(site)
    if not host:
        ap.error(f"unknown site {site}: give --apic")
    if not args.user:
        ap.error("give --user (or APIC_USER)")
    password = os.environ.get("APIC_PASSWORD") or getpass.getpass(f"Password of {args.user} on APIC {host}: ")
    apic = Apic(host, verify=args.verify_tls, ca_file=args.ca_file)
    print(f"== {site}: APIC {host}, account {args.user} (read-only: GET only)", file=sys.stderr)
    try:
        apic.login(args.user, password)
    except ApicError as e:
        print(f"Sign-in to APIC {host} failed: {e}", file=sys.stderr)
        return 2
    try:
        folder, a, errors = dump(apic, site, args.out)
    finally:
        apic.logout()
    print(f"== {site}: {len(a['ports'])} ports, {len(a['groups'])} policy groups, {len(a['warnings'])} findings"
          + (f", {len(errors)} classes not read" if errors else "") + f" -> {folder}", file=sys.stderr)
    print(folder)
    return 0


if __name__ == "__main__":
    sys.exit(main())

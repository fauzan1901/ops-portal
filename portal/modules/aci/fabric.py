"""Fabric interfaces of one site (READ ONLY): every port of every leaf with what uses it, so an operator finds a port for a
static port binding (eth1/23 on node 101) or for a new vPC, and sends it to the Static Port page.

Read from APIC with class queries (GET only):
  fabricNode                          the leaves (id, name, model, serial, state)
  l1PhysIf, ethpmPhysIf               each port: admin state, description, usage; operational state, speed, reason
  pcAggrIf, pcRsMbrIfs                port-channels per leaf (name = policy group) and their member ports
  fabricExplicitGEp, fabricNodePEp    vPC pairs (vPC protection groups)
  infraNodeP > infraLeafS > infraNodeBlk, infraRsAccPortP     leaf profiles: which leaves use which interface profile
  infraAccPortP > infraHPortS > infraPortBlk, infraRsAccBaseGrp  interface selectors: which ports get which policy group
  infraAccPortGrp, infraAccBndlGrp (lagT), infraRsAttEntP     policy groups: access, port-channel (link) or vPC (node), AAEP
  lldpAdjEp, cdpAdjEp                 what is connected to a port
  fvRsPathAtt, l3extRsPathL3OutAtt    static paths of EPGs and L3Out interfaces on a port, a PC or a vPC

What a port is (status) and how the Static Port page binds it (use):
  uplink   fabric port (spine link): never for a static port
  vpc      member of a vPC (or in a selector of a vPC policy group): the binding is on the vPC path
           topology/pod-1/protpaths-101-102/pathep-[<policy group>]
  pc       member of a port-channel of one leaf: the binding is on the PC path topology/pod-1/paths-101/pathep-[<policy group>]
  access   in a selector of an access policy group: the binding is on the port itself (pod, node, eth1/23)
  free     in no interface selector: no policy yet. A static binding on it raises a fault on APIC until an access (or
           PC / vPC) policy group is set on the port (Fabric > Access Policies), so the page warns about it.
"""
import re

from .aci import EPG_CHILD_DN_RE, L3OUT_CHILD_DN_RE, attrs_of, query_all

NODE_DN_RE = re.compile(r"^topology/pod-(\d+)/node-(\d+)(?:/|$)")
PHYS_DN_RE = re.compile(r"^topology/pod-(\d+)/node-(\d+)/sys/phys-\[([^\[\]]+)\]")
AGGR_DN_RE = re.compile(r"^topology/pod-(\d+)/node-(\d+)/sys/aggr-\[([^\[\]]+)\]")
ADJ_DN_RE = re.compile(r"^topology/pod-\d+/node-(\d+)/sys/(?:lldp|cdp)/inst/if-\[([^\[\]]+)\]/adj-")
PORT_RE = re.compile(r"^eth(\d+)/(\d+)(?:/(\d+))?$")
PATH_RE = re.compile(r"^topology/pod-(\d+)/(?:paths-(\d+)|protpaths-(\d+)-(\d+))/pathep-\[([^\[\]]+)\]$")
STATUSES = ("free", "access", "pc", "vpc", "uplink")


def port_key(name):
    """eth1/23 -> (1, 23, 0), eth1/1/2 (breakout) -> (1, 1, 2); other names sort last."""
    m = PORT_RE.match(str(name or ""))
    return (int(m[1]), int(m[2]), int(m[3] or 0)) if m else (999, 999, 999)


def _get(api, cls):
    return attrs_of(query_all(api, f"/api/node/class/{cls}.json"), cls)


def _parent(dn, marker):
    i = dn.find(marker)
    return dn[:i] if i >= 0 else ""


def profile_nodes(api):
    """Interface profile DN -> set of the leaves it applies to (through the leaf profiles that use it)."""
    nodes_of_profile = {}   # leaf profile DN -> set of node IDs
    for blk in _get(api, "infraNodeBlk"):
        nprof = _parent(blk["dn"], "/leaves-")
        try:
            low, high = int(blk.get("from_") or 0), int(blk.get("to_") or 0)
        except ValueError:
            continue
        if nprof and low and high:
            nodes_of_profile.setdefault(nprof, set()).update(range(low, high + 1))
    nodes_of_ifp = {}
    for rel in _get(api, "infraRsAccPortP"):
        nprof = _parent(rel["dn"], "/rsaccPortP-")
        nodes_of_ifp.setdefault(rel.get("tDn", ""), set()).update(nodes_of_profile.get(nprof, set()))
    return nodes_of_ifp


def _selectors(api):
    """(node, (card, port, sub)) -> {"group": policy group DN, "selector": name, "profile": interface profile name}."""
    nodes_of_ifp = profile_nodes(api)
    group_of = {_parent(r["dn"], "/rsaccBaseGrp"): r.get("tDn", "") for r in _get(api, "infraRsAccBaseGrp")}
    out = {}
    for blk in _get(api, "infraPortBlk"):
        sel = _parent(blk["dn"], "/portblk-")
        ifp = _parent(sel, "/hports-")
        if not sel or "/accportprof-" not in ifp:   # FEX profiles have selectors too: not leaf ports
            continue
        try:
            cards = range(int(blk.get("fromCard") or 1), int(blk.get("toCard") or 1) + 1)
            ports = range(int(blk.get("fromPort") or 0), int(blk.get("toPort") or 0) + 1)
            subs = range(int(blk.get("fromSubPort") or 0), int(blk.get("toSubPort") or 0) + 1)
        except ValueError:
            continue
        name = re.sub(r"-typ-[a-z]+$", "", sel.rsplit("/hports-", 1)[1])
        info = {"group": group_of.get(sel, ""), "selector": name, "profile": re.sub(r"^accportprof-", "", ifp.rsplit("/", 1)[1])}
        for node in nodes_of_ifp.get(ifp, ()):
            for card in cards:
                for port in ports:
                    for sub in subs:
                        out[(node, (card, port, sub))] = info
    return out


def _groups(api):
    """Policy group DN -> {"name", "kind": access | pc | vpc, "aaep"}."""
    aaep = {_parent(r["dn"], "/rsattEntP"): re.sub(r"^.*/attentp-", "", r.get("tDn", "")) for r in _get(api, "infraRsAttEntP")}
    out = {}
    for g in _get(api, "infraAccPortGrp"):
        out[g["dn"]] = {"name": g.get("name", ""), "kind": "access", "aaep": aaep.get(g["dn"], "")}
    for g in _get(api, "infraAccBndlGrp"):
        out[g["dn"]] = {"name": g.get("name", ""), "kind": "vpc" if g.get("lagT") == "node" else "pc", "aaep": aaep.get(g["dn"], "")}
    return out


def _owner(dn):
    m = EPG_CHILD_DN_RE.match(dn)
    if m:
        return f"{m[1]}/{m[2]}/{m[3]}"
    m = L3OUT_CHILD_DN_RE.match(dn)
    return f"L3Out {m[1]}/{m[2]}" if m else dn


def fabric_interfaces(api):
    """Every leaf port of the site with its state and what uses it, the leaves, and the vPC pairs with the ports free on
    both of their leaves (candidates for a new vPC)."""
    leaves = {}
    for n in _get(api, "fabricNode"):
        m = NODE_DN_RE.match(n["dn"])
        if m and n.get("role") == "leaf":
            leaves[int(m[2])] = {"id": int(m[2]), "pod": int(m[1]), "name": n.get("name", ""), "model": n.get("model", ""),
                                 "serial": n.get("serial", ""), "state": n.get("fabricSt", "")}
    oper = {}
    for p in _get(api, "ethpmPhysIf"):
        m = PHYS_DN_RE.match(p["dn"])
        if m:
            oper[(int(m[2]), m[3])] = p
    # port-channels: (node, PC name) -> {"id", "members"}; (node, port) -> PC name
    channels, member_of, po_name = {}, {}, {}
    for a in _get(api, "pcAggrIf"):
        m = AGGR_DN_RE.match(a["dn"])
        if m:
            channels[(int(m[2]), a.get("name", ""))] = {"id": a.get("id") or m[3], "oper": a.get("operSt", ""), "members": []}
            po_name[(int(m[2]), m[3])] = a.get("name", "")   # po3 -> the name of its policy group
    for r in _get(api, "pcRsMbrIfs"):
        m = AGGR_DN_RE.match(r["dn"])
        if not m:
            continue
        node, name = int(m[2]), po_name.get((int(m[2]), m[3]))
        port = r.get("tSKey") or re.sub(r"^.*rsmbrIfs-\[([^\]]+)\]$", r"\1", r["dn"])
        if name is not None:
            channels[(node, name)]["members"].append(port)
            member_of[(node, port)] = name
    pairs = {}   # node -> peer
    pair_names = {}
    groups_of_pairs = {}
    for g in _get(api, "fabricExplicitGEp"):
        groups_of_pairs[g["dn"]] = g.get("name", "")
    members = {}
    for n in _get(api, "fabricNodePEp"):
        members.setdefault(_parent(n["dn"], "/nodepep-"), []).append(int(n.get("id") or 0))
    for dn, ids in members.items():
        if len(ids) == 2:
            a, b = sorted(ids)
            pairs[a], pairs[b] = b, a
            pair_names[(a, b)] = groups_of_pairs.get(dn, f"{a}-{b}")
    selectors, groups = _selectors(api), _groups(api)
    kind_of = {g["name"]: g["kind"] for g in groups.values()}
    neighbors = {}
    for a in _get(api, "lldpAdjEp"):
        m = ADJ_DN_RE.match(a["dn"])
        if m:
            neighbors[(int(m[1]), m[2])] = {"name": a.get("sysName", ""), "port": a.get("portDesc") or a.get("portIdV", ""),
                                            "ip": "" if a.get("mgmtIp") in (None, "", "0.0.0.0", "unspecified") else a["mgmtIp"], "via": "LLDP"}
    for a in _get(api, "cdpAdjEp"):
        m = ADJ_DN_RE.match(a["dn"])
        if m and (int(m[1]), m[2]) not in neighbors:
            neighbors[(int(m[1]), m[2])] = {"name": a.get("devId", ""), "port": a.get("portId", ""), "ip": "", "via": "CDP"}
    # static paths of EPGs and L3Outs: on a port, on a PC (all its members) or on a vPC (its members on both leaves)
    bound = {}

    def bind(node, port, item):
        bound.setdefault((node, port), []).append(item)
    for cls in ("fvRsPathAtt", "l3extRsPathL3OutAtt"):
        for r in _get(api, cls):
            m = PATH_RE.match(r.get("tDn", ""))
            if not m:
                continue
            item = {"owner": _owner(r["dn"]), "encap": r.get("encap", ""), "path": r["tDn"]}
            name = m[5]
            if m[2]:
                node = int(m[2])
                if PORT_RE.match(name):
                    bind(node, name, dict(item, via="port"))
                else:
                    for port in (channels.get((node, name)) or {}).get("members", []):
                        bind(node, port, dict(item, via=f"PC {name}"))
            else:
                for node in (int(m[3]), int(m[4])):
                    for port in (channels.get((node, name)) or {}).get("members", []):
                        bind(node, port, dict(item, via=f"vPC {name}"))
    rows = []
    for p in _get(api, "l1PhysIf"):
        m = PHYS_DN_RE.match(p["dn"])
        if not m or int(m[2]) not in leaves:
            continue
        pod, node, port = int(m[1]), int(m[2]), m[3]
        op = oper.get((node, port), {})
        usage = op.get("usage") or p.get("usage", "")
        sel = selectors.get((node, port_key(port)))
        group = groups.get(sel["group"], {"name": re.sub(r"^.*/(?:accportgrp|accbundle)-", "", sel["group"]), "kind": "", "aaep": ""}) if sel else None
        pc = member_of.get((node, port))
        peer = pairs.get(node)
        pc_kind = ""
        if pc:
            pc_kind = "vpc" if kind_of.get(pc) == "vpc" or (peer and (peer, pc) in channels) else "pc"
        if "fabric" in usage or p.get("portT") == "fab":
            status, use, note = "uplink", None, "Fabric uplink: not for servers."
        elif pc_kind == "vpc" or (not pc and group and group["kind"] == "vpc"):
            name = pc or group["name"]
            a, b = sorted((node, peer)) if peer else (node, node)
            status = "vpc"
            use = {"kind": "paths", "tdn": f"topology/pod-{pod}/protpaths-{a}-{b}/pathep-[{name}]"} if peer else None
            note = f"Member of vPC {name} ({a}-{b}): bind the vPC, not the port." if peer else f"vPC policy group {name}, but node {node} is in no vPC pair."
        elif pc_kind == "pc" or (not pc and group and group["kind"] == "pc"):
            name = pc or group["name"]
            status, use = "pc", {"kind": "physical", "pod": pod, "node": node, "interface": name}
            note = f"Member of port-channel {name}: bind the port-channel, not the port."
        elif sel:
            status, use = "access", {"kind": "physical", "pod": pod, "node": node, "interface": port}
            note = f"Access port, policy group {group['name'] if group else '?'}."
        else:
            status, use = "free", {"kind": "physical", "pod": pod, "node": node, "interface": port}
            note = ("No interface policy on this port yet: a static binding on it raises a fault on APIC until an access, PC "
                    "or vPC policy group is set on it (Fabric > Access Policies).")
        rows.append({
            "pod": pod, "node": node, "node_name": leaves[node]["name"], "interface": port,
            "admin": p.get("adminSt", ""), "oper": op.get("operSt", ""), "reason": op.get("operStQual", ""),
            "speed": op.get("operSpeed") if op.get("operSpeed") not in (None, "", "unknown") else "",
            "descr": p.get("descr", ""), "usage": usage, "status": status, "note": note, "use": use,
            "selector": sel["selector"] if sel else "", "profile": sel["profile"] if sel else "",
            "policy_group": group["name"] if group else "", "group_kind": group["kind"] if group else "",
            "aaep": group["aaep"] if group else "", "channel": pc or "", "channel_kind": pc_kind,
            "neighbor": neighbors.get((node, port)), "bindings": bound.get((node, port), []),
        })
    rows.sort(key=lambda r: (r["node"], port_key(r["interface"]), r["interface"]))
    # vPC pairs: their vPCs, and the ports free (no policy, nothing connected, no binding) on BOTH leaves
    by = {(r["node"], r["interface"]): r for r in rows}
    vpc_pairs = []
    for (a, b), name in sorted(pair_names.items()):
        vpcs = sorted({r["channel"] or r["policy_group"] for r in rows if r["node"] in (a, b) and r["status"] == "vpc"} - {""})
        free = [r["interface"] for r in rows if r["node"] == a and r["status"] == "free" and not r["neighbor"] and not r["bindings"]
                and (b, r["interface"]) in by and by[(b, r["interface"])]["status"] == "free"
                and not by[(b, r["interface"])]["neighbor"] and not by[(b, r["interface"])]["bindings"]]
        vpc_pairs.append({"name": name, "nodes": [a, b], "vpcs": [{
            "name": v, "tdn": f"topology/pod-{leaves.get(a, {}).get('pod', 1)}/protpaths-{a}-{b}/pathep-[{v}]",
            "members": {str(n): [r["interface"] for r in rows if r["node"] == n and (r["channel"] or r["policy_group"]) == v] for n in (a, b)},
            "up": all(by.get((n, port), {}).get("oper") == "up" for n in (a, b)
                      for port in [r["interface"] for r in rows if r["node"] == n and (r["channel"] or r["policy_group"]) == v]),
        } for v in vpcs], "free_both": free})
    counts = {s: sum(1 for r in rows if r["status"] == s) for s in STATUSES}
    return {"nodes": [leaves[n] for n in sorted(leaves)], "interfaces": rows, "vpc_pairs": vpc_pairs, "counts": counts}


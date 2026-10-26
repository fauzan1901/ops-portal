"""WI "FDB Learning Issue" (Acme Flex, ML2/OVN): instances on one network lose unicast traffic (ARP broadcast passes) to
a host or to each other, depending on which instances share a compute.

Root cause (the WI): a port with port security disabled has the address "unknown" in OVN, and OVN learns MAC addresses on
such ports (FDB). When an instance sends frames with a MAC that is not its own (bridging, bonding, a VIP, a reflected
frame), that MAC, e.g. the MAC of a physical host outside OpenStack or of another instance, is recorded on the port of
the instance: unicast to that MAC is then sent to the instance instead of the physical network (localnet), and dropped
when the recorded port is the sender's own port.

The check reads, for the instances given (several IDs, from one or more computes):
  OpenStack        each instance (status, compute), its ports (MAC, IPs, port security, security groups, allowed address
                   pairs), their networks (type, VLAN), the network agents (OVN or not), the port of the destination IP
  OVN Southbound   (ovn-sbctl in the ovn_controller container of a compute, through the director, read only) the datapath
                   of each network (tunnel key), its port bindings (tunnel keys, "unknown" addresses, localnet port), its
                   FDB entries, the FDB entries of every network and the ports with "unknown" addresses (audit)
  optional         a capture of a few seconds on the tap of each instance: frames it sends with a MAC that is not its own
and finds the FDB entries that record a MAC on a port it does not belong to ("poisoned"). Fixes: clear the poisoned
entries (Run this fix, one entry per item, checked again before and after: wi_ops.py clear-fdb); permanent fix: port
security on the ports (Run this fix, one port per item: wi_ops.py port-security), with the security group
port-security-allow-all of their project (every protocol in and out, so the traffic of the application stays as it is
and only the MAC / IP anti-spoofing of port security starts) and the VIPs given in the check (vips) as allowed address
pairs. The ports of the networks without a device (reserved ports, usually a VIP) are listed as VIP candidates.
"""
import ipaddress
import json
import re

from . import overcloud
from .common import Result, json_of, source, unavailable
from .openstack import UUID, os_select, q
from .openstack_ops import node_of
from .overcloud_checks import inventory

MAX_INSTANCES = 16
MAX_PORTS = 40
MAX_NETWORKS = 6
MAX_SB_NODES = 4   # nodes tried for the OVN Southbound DB: the computes of the instances, then the controllers
MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def instance_ids(params):
    """The instance IDs of the run (the parameter keeps them comma separated), in order, once each."""
    out = []
    for x in re.split(r"[\s,;]+", str(params.get("instances") or "").lower()):
        if UUID.match(x) and x not in out:
            out.append(x)
    return out[:MAX_INSTANCES]


def ovsdb_rows(text):
    """Rows of `ovn-sbctl --format=json` ({"headings": [...], "data": [[...]]}) as dicts; uuid / set / map unwrapped."""
    try:
        doc = json.loads(str(text or "").strip() or "{}")
    except ValueError:
        return []
    heads = doc.get("headings") or []

    def atom(v):
        if isinstance(v, list) and len(v) == 2 and v[0] in ("uuid", "named-uuid"):
            return v[1]
        if isinstance(v, list) and len(v) == 2 and v[0] == "set":
            return [atom(x) for x in v[1]]
        if isinstance(v, list) and len(v) == 2 and v[0] == "map":
            return {str(atom(k)): atom(x) for k, x in v[1]}
        return v
    return [{h: atom(v) for h, v in zip(heads, row)} for row in doc.get("data") or [] if isinstance(row, list)]


def as_list(v):
    return v if isinstance(v, list) else [] if v in (None, "") else [v]


def port_macs(binding):
    """The MACs a port binding owns ("fa:16:3e:.. 10.253.0.5" entries), and whether it accepts any MAC ("unknown")."""
    macs, unknown = [], False
    for entry in as_list(binding.get("mac")):
        first = str(entry).split()[0].lower() if str(entry).strip() else ""
        if first == "unknown":
            unknown = True
        elif MAC.match(first):
            macs.append(first)
    return macs, unknown


def fixed_ips(port):
    ips = port.get("fixed_ips") or port.get("Fixed IP Addresses") or []
    if isinstance(ips, str):
        return re.findall(r"ip_address='([^']+)'", ips)
    return [str(x.get("ip_address")) for x in ips if isinstance(x, dict) and x.get("ip_address")]


def is_true(v):
    return str(v).strip().lower() in ("true", "1", "yes")


def vip_list(params):
    """The VIPs / allowed addresses of the run (parameter vips, comma separated, validated by the catalog)."""
    out = []
    for x in str(params.get("vips") or "").split(","):
        x = x.strip()
        try:
            ipaddress.ip_network(x, strict=False)
        except ValueError:
            continue
        if x not in out:
            out.append(x)
    return out[:16]


def covers(addresses, ip):
    """Whether one of the addresses / networks contains ip."""
    try:
        target = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for a in addresses:
        try:
            if target in ipaddress.ip_network(a, strict=False):
                return True
        except ValueError:
            continue
    return False


class OvnFdbLearning:
    """WI "FDB Learning Issue": the ports of the instances, their OVN port bindings and the FDB of their networks."""
    sources = ("openstack", "undercloud", "overcloud")
    phases = 5

    @staticmethod
    def ports(data, ids):
        """[(instance index, port id)] of the instances, in order, at most MAX_PORTS."""
        out = []
        for i, _sid in enumerate(ids):
            for p in json_of(source(data, f"ports_{i}")) or []:
                pid = str((p or {}).get("ID") or (p or {}).get("id") or "") if isinstance(p, dict) else ""
                if UUID.match(pid) and pid not in [x[1] for x in out]:
                    out.append((i, pid))
        return out[:MAX_PORTS]

    @staticmethod
    def networks(data, ids):
        out = []
        for _i, pid in OvnFdbLearning.ports(data, ids):
            nid = str((json_of(source(data, f"port_{pid}")) or {}).get("network_id") or "")
            if UUID.match(nid) and nid not in out:
                out.append(nid)
        return out[:MAX_NETWORKS]

    @staticmethod
    def sb_candidates(data, ctx, ids):
        """([node], user) that may read the OVN Southbound DB, in order: the compute of each instance, then the controllers
        (a compute the director cannot reach over SSH is common; every node with ovn_controller reads the same DB)."""
        found, controllers, user, _v, _p = inventory(data, ctx)
        if user not in overcloud.USERS:
            return [], user
        out = []
        for i, _sid in enumerate(ids):
            host = str((json_of(source(data, f"srv_{i}")) or {}).get("OS-EXT-SRV-ATTR:host") or "")
            n = node_of(host, found) if host else None
            if n and n.get("ip") and n["name"] not in [x["name"] for x in out]:
                out.append(n)
        computes = out[:MAX_SB_NODES - 1] if controllers else out[:MAX_SB_NODES]
        return computes + [c for c in controllers if c.get("ip")][:MAX_SB_NODES - len(computes)], user

    @staticmethod
    def sb_node(data, ctx, ids):
        """(node, user, [(node, why)] of the nodes that did not answer): the first candidate whose probe (phase 3) read
        the Southbound DB."""
        nodes, user = OvnFdbLearning.sb_candidates(data, ctx, ids)
        tried = []
        for n in nodes:
            item = source(data, f"use_sbp_{n['name']}")
            if not unavailable(item) and re.search(r"[0-9a-f]{8}-", str(item.get("out") or "")):
                return n, user, tried
            tried.append((n, unavailable(item) or str(item.get("out") or "").strip()[:160] or "no answer"))
        return None, user, tried

    @staticmethod
    def reads(phase, data, params, ctx):
        ids = instance_ids(params)
        if not ids:
            return {}
        if phase == 1:
            reads = {"agents": "openstack network agent list -f json"}
            for i, sid in enumerate(ids):
                reads[f"srv_{i}"] = f"openstack server show {q(sid)} -f json"
                reads[f"ports_{i}"] = f"openstack port list --server {q(sid)} --long -f json"
            if params.get("dest_ip"):
                reads["dest"] = f"openstack port list --fixed-ip ip-address={q(params['dest_ip'])} --long -f json"
            return {"openstack": reads, "undercloud": dict(overcloud.INVENTORY_READS)}
        if phase == 2:
            reads = {f"port_{pid}": f"openstack port show {q(pid)} -f json" for _i, pid in OvnFdbLearning.ports(data, ids)}
            return {"openstack": reads} if reads else {}
        nets = OvnFdbLearning.networks(data, ids)
        if phase == 3:
            out = {"openstack": {f"net_{nid}": f"openstack network show {q(nid)} -f json" for nid in nets}}
            # the ports of the networks: those without a device are reserved addresses, usually a VIP (port security fix)
            out["openstack"].update({f"nports_{nid}": f"openstack port list --network {q(nid)} --long -f json" for nid in nets})
            nodes, user = OvnFdbLearning.sb_candidates(data, ctx, ids)
            # which node reads the Southbound DB: all candidates at once (use_ reads run in parallel), the first that answers
            oc = {f"use_sbp_{n['name']}": overcloud.read(n["name"], n["ip"], user, "ovn_sb") for n in nodes}
            seconds = int(params.get("capture_seconds") or 0)
            if seconds and nodes:   # all taps at once, each on the compute of its instance
                found, _c, _u, _v, _p = inventory(data, ctx)
                for i, pid in OvnFdbLearning.ports(data, ids):
                    port = json_of(source(data, f"port_{pid}")) or {}
                    host = str((json_of(source(data, f"srv_{i}")) or {}).get("OS-EXT-SRV-ATTR:host") or "")
                    n = node_of(host, found) if host else None
                    mac = str(port.get("mac_address") or "").lower()
                    if n and n.get("ip") and MAC.match(mac):
                        oc[f"use_cap_{pid}"] = overcloud.read(n["name"], n["ip"], user, "ovn_capture", f"tap{pid[:11]}",
                                                              seconds, overcloud.mac_arg(mac))
            if oc:
                out["overcloud"] = oc
            return out
        node, user, _tried = OvnFdbLearning.sb_node(data, ctx, ids)
        if phase == 4 and node:
            oc = {f"dp_{nid}": overcloud.read(node["name"], node["ip"], user, "ovn_dp", nid) for nid in nets}
            oc.update({"fdbcount": overcloud.read(node["name"], node["ip"], user, "ovn_fdb_count"),
                       "unknown": overcloud.read(node["name"], node["ip"], user, "ovn_unknown"),
                       "ovnver": overcloud.read(node["name"], node["ip"], user, "ovn_version")})
            return {"overcloud": oc}
        if phase == 5 and node:
            oc = {}
            for nid in nets:
                dp = next(iter(ovsdb_rows(source(data, f"dp_{nid}").get("out"))), None)
                if dp and UUID.match(str(dp.get("_uuid") or "")) and str(dp.get("tunnel_key") or "").isdigit():
                    oc[f"pb_{nid}"] = overcloud.read(node["name"], node["ip"], user, "ovn_pb", dp["_uuid"])
                    oc[f"fdb_{nid}"] = overcloud.read(node["name"], node["ip"], user, "ovn_fdb", int(dp["tunnel_key"]))
            return {"overcloud": oc} if oc else {}
        return {}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("ovn-fdb-learning")
        ids = instance_ids(params)
        dest_ip = str(params.get("dest_ip") or "")
        if not ids:
            r.step("instances", "Instances", "fail", "No valid instance ID was given.")
            return r.done()
        # ---- 1. the instances and where they run (WI stage 1: which instance fails, on which compute)
        servers, rows = {}, []
        for i, sid in enumerate(ids):
            item = source(data, f"srv_{i}")
            s = json_of(item) or {}
            if unavailable(item) or not isinstance(s, dict) or not s.get("id"):
                rows.append([sid, "-", "not found", "-", unavailable(item) or "not found"])
                continue
            servers[i] = s
            host = str(s.get("OS-EXT-SRV-ATTR:host") or "-")
            rows.append([sid, str(s.get("name") or "-"), str(s.get("status") or "-"), host, str(s.get("addresses") or "")[:80]])
        by_host = {}
        for i, s in servers.items():
            by_host.setdefault(str(s.get("OS-EXT-SRV-ATTR:host") or "-"), []).append(str(s.get("name") or ids[i]))
        missing = [x for x in rows if x[2] == "not found"]
        r.step("instances", "Instances and their computes (WI stage 1)", "fail" if not servers else "warn" if missing else "ok",
               (f"{len(servers)} of {len(ids)} instance(s) found. Per compute: "
                + "; ".join(f"{h}: {', '.join(sorted(v))}" for h, v in sorted(by_host.items())) + "."
                + (f" Not found: {', '.join(x[0] for x in missing)}." if missing else "")
                + " When the problem depends on which instances share a compute, suspect the L2 state per port (FDB)."),
               {"columns": ["Instance ID", "Name", "Status", "Compute", "Addresses"], "rows": rows},
               marks=[x[0] for x in missing])
        if not servers:
            return r.done("None of the instances was found.")
        name_of = {ids[i]: str(s.get("name") or ids[i]) for i, s in servers.items()}
        # ---- 2. the ports (WI stage 2): port security disabled is the risk indicator
        ports, prow = {}, []
        for i, pid in OvnFdbLearning.ports(data, ids):
            p = json_of(source(data, f"port_{pid}")) or {}
            if not isinstance(p, dict) or not p.get("id"):
                continue
            ports[pid] = dict(p, _instance=ids[i])
            aap = ", ".join(str(a.get("ip_address")) for a in p.get("allowed_address_pairs") or [] if isinstance(a, dict)) or "-"
            prow.append([name_of.get(ids[i], ids[i]), pid, str(p.get("mac_address") or "-"), ", ".join(fixed_ips(p)) or "-",
                         "enabled" if is_true(p.get("port_security_enabled")) else "DISABLED",
                         str(len(p.get("security_group_ids") or [])), aap, str(p.get("binding_host_id") or "-")])
        off = [pid for pid, p in ports.items() if not is_true(p.get("port_security_enabled"))]
        r.step("ports", "Ports of the instances (WI stage 2)", "warn" if off else "ok" if ports else "fail",
               (f"{len(off)} of {len(ports)} port(s) have port security DISABLED: OVN gives them the address \"unknown\" and learns "
                "MAC addresses on them (FDB)." if off else
                f"All {len(ports)} port(s) have port security enabled: OVN does not learn MACs on them." if ports else
                "The ports of the instances could not be read."),
               {"columns": ["Instance", "Port ID", "MAC", "IP", "Port security", "Security groups", "Allowed address pairs",
                            "Binding host"], "rows": prow}, marks=off)
        # ---- 3. the backend (WI stage 3): FDB learning is an OVN mechanism
        agents = json_of(source(data, "agents")) or []
        ovn = any("ovn" in (str(a.get("Agent Type") or "") + str(a.get("Binary") or "")).lower() for a in agents if isinstance(a, dict))
        ovs = any("open vswitch" in str(a.get("Agent Type") or "").lower() for a in agents if isinstance(a, dict))
        ver = str(source(data, "ovnver").get("out") or "").strip().splitlines()
        r.step("backend", "Network backend (WI stage 3)", "ok" if ovn else "info",
               ("ML2/OVN (OVN Controller agents)." + (f" {ver[0]}." if ver else "")) if ovn else
               "ML2/OVS (Open vSwitch agents): the OVN FDB of this WI does not apply; check the Open vSwitch MAC table "
               "(ovs-appctl fdb/show br-int) instead." if ovs else "The network agents could not be read.")
        if not ovn:
            return r.done("Not an OVN cloud: this WI does not apply." if ovs else "The backend could not be read.")
        node, user, tried = OvnFdbLearning.sb_node(data, ctx, ids)
        where = (f"{node['name']} ({node['ip']}), from the director: ssh {user}@{node['ip']}" if node else "a compute node")
        missed = "; ".join(f"{n['name']} ({n['ip']}): {why[:120]}" for n, why in tried)
        if not node:
            r.step("ovn", "OVN Southbound DB (read from an overcloud node)", "fail",
                   (f"No overcloud node answered over SSH from the director as {user}: {missed}. Check from the director: "
                    f"ssh {user}@<node> (the ctlplane address of the node, its SSH service)." if tried else
                    "No overcloud node to read it from (the node list of the undercloud)."),
                   marks=[n["name"] for n, _w in tried])
            return r.done("The OVN Southbound DB could not be read: no overcloud node answered from the director.")
        r.step("ovn", "OVN Southbound DB (read from an overcloud node)", "warn" if tried else "ok",
               f"Read from {node['name']} ({node['ip']})." + (f" Did not answer: {missed}." if tried else ""),
               marks=[n["name"] for n, _w in tried])
        # ---- 4. the networks, their OVN datapath and port bindings (WI stage 7)
        nets = OvnFdbLearning.networks(data, ids)
        net_rows, dps, owner, keyport = [], {}, {}, {}
        for nid in nets:
            n = json_of(source(data, f"net_{nid}")) or {}
            dp_item = source(data, f"dp_{nid}")
            dp = next(iter(ovsdb_rows(dp_item.get("out"))), None)
            pbs = ovsdb_rows(source(data, f"pb_{nid}").get("out"))
            unknown_ports = sum(1 for b in pbs if port_macs(b)[1] and str(b.get("type") or "") == "")
            net_rows.append([str(n.get("name") or nid), nid, str(n.get("provider:network_type") or "-"),
                             str(n.get("provider:segmentation_id") or "-"),
                             str(dp.get("tunnel_key")) if dp else (unavailable(dp_item) or "not found")[:60],
                             str(len(pbs)), str(unknown_ports)])
            if not dp:
                continue
            dps[nid] = {"key": int(dp["tunnel_key"]), "uuid": dp["_uuid"], "name": str(n.get("name") or nid)}
            for b in pbs:
                key = str(b.get("tunnel_key") or "")
                lp = str(b.get("logical_port") or "")
                macs, unk = port_macs(b)
                kind = str(b.get("type") or "")
                label = ("localnet (physical network)" if kind == "localnet" else
                         f"{name_of.get(ports[lp]['_instance'], '')} port {lp[:8]}" if lp in ports else
                         f"{kind or 'port'} {lp[:36]}")
                keyport[(nid, key)] = {"port": lp, "label": label, "unknown": unk, "type": kind, "macs": macs}
                for m in macs:
                    owner[(nid, m)] = label
        r.step("networks", "Networks and their OVN datapath (WI stage 7)", "ok" if dps else "fail",
               (f"{len(dps)} network(s); the datapath tunnel key (dp_key) is the key of their FDB entries."
                if dps else "The OVN datapath of the networks could not be read."),
               {"columns": ["Network", "ID", "Type", "VLAN / segment", "dp_key", "Port bindings", "Ports with \"unknown\""],
                "rows": net_rows})
        brow, unknown_vm = [], []
        for pid, p in ports.items():
            nid = str(p.get("network_id") or "")
            b = next((v for (n, _k), v in keyport.items() if n == nid and v["port"] == pid), None)
            key = next((k for (n, k), v in keyport.items() if n == nid and v["port"] == pid), "-")
            if b and b["unknown"]:
                unknown_vm.append(pid)
            brow.append([name_of.get(p["_instance"], ""), pid, key, ", ".join(b["macs"]) if b else "-",
                         "yes (learns MACs)" if b and b["unknown"] else "no" if b else "not found"])
        r.step("bindings", "OVN port bindings of the instances (WI stage 7)", "warn" if unknown_vm else "ok",
               (f"{len(unknown_vm)} port(s) have the address \"unknown\" (port security disabled): OVN learns on them every "
                "source MAC their instance sends." if unknown_vm else "No port of the instances accepts unknown MACs."),
               {"columns": ["Instance", "Port ID", "Tunnel key", "MAC", "\"unknown\""], "rows": brow}, marks=unknown_vm)
        # ---- 5. the FDB entries of the networks: a MAC recorded on a port it does not belong to (WI stages 6-8)
        dest_mac = ""
        dest_ports = json_of(source(data, "dest")) or []
        if dest_ip and isinstance(dest_ports, list) and dest_ports:
            dest_mac = str(dest_ports[0].get("MAC Address") or dest_ports[0].get("mac_address") or "").lower()
        frow, poisoned = [], []
        for nid, dp in dps.items():
            for e in ovsdb_rows(source(data, f"fdb_{nid}").get("out")):
                mac, pkey = str(e.get("mac") or "").lower(), str(e.get("port_key") or "")
                at = keyport.get((nid, pkey), {"label": f"port key {pkey}", "type": "", "port": "", "unknown": False, "macs": []})
                belongs = owner.get((nid, mac), "")
                if at["type"] == "localnet":
                    verdict = "ok (outside host, on the physical network)" if not belongs else f"belongs to {belongs}, recorded on localnet"
                    bad = False
                elif mac in at["macs"]:
                    verdict, bad = "ok (its own MAC)", False
                else:
                    verdict = (f"POISONED: MAC of {belongs}" if belongs else "POISONED: MAC of a host outside OpenStack") \
                              + f", recorded on {at['label']}"
                    bad = True
                if mac == dest_mac:
                    verdict += f" — destination {dest_ip}"
                row = [dp["name"], mac, at["label"], belongs or "not a port of this network", verdict]
                frow.append(row)
                if bad:
                    poisoned.append({"net": nid, "dp": dp["key"], "mac": mac, "port_key": int(pkey) if pkey.isdigit() else 0,
                                     "at": at["label"], "belongs": belongs, "uuid": str(e.get("_uuid") or "")})
        fdb_read = [nid for nid in dps if not unavailable(source(data, f"fdb_{nid}"))]
        r.step("fdb", "FDB entries of the networks (WI stages 6-8)", "fail" if poisoned else "ok" if fdb_read else "fail",
               (f"{len(poisoned)} poisoned entr{'y' if len(poisoned) == 1 else 'ies'}: a MAC recorded on the port of an instance "
                "it does not belong to. Unicast to that MAC is sent to that instance instead of the physical network "
                "(broadcast still passes), and dropped when the instance itself sends it." if poisoned else
                f"{len(frow)} FDB entr{'y' if len(frow) == 1 else 'ies'}, none poisoned." if fdb_read else
                "The FDB could not be read.")
               + (f" Destination {dest_ip}: " + (f"MAC {dest_mac}." if dest_mac else
                                                 "not a port of OpenStack; its MAC is one of the outside MACs below.") if dest_ip else ""),
               {"columns": ["Network", "MAC", "Recorded on", "MAC belongs to", "Verdict"], "rows": frow},
               marks=[p["mac"] for p in poisoned])
        # ---- 6. what fills the FDB: frames with a MAC that is not the instance's own (optional capture)
        caps = {k[len("use_cap_"):]: v for k, v in (data or {}).items() if k.startswith("use_cap_")}
        if caps:
            crow, foreign = [], 0
            for pid, item in caps.items():
                text = str((item or {}).get("out") or "")
                macs = sorted(set(m.lower() for m in re.findall(r"\b([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}) >", text))
                              - {str(ports.get(pid, {}).get("mac_address") or "").lower()})
                n = len([l for l in text.splitlines() if " > " in l])
                foreign += n
                crow.append([name_of.get(ports.get(pid, {}).get("_instance", ""), pid), f"tap{pid[:11]}",
                             "tcpdump is not installed" if "not installed" in text else str(n), ", ".join(macs[:6]) or "-"])
            r.step("capture", "Frames with a foreign source MAC from the instances", "warn" if foreign else "ok",
                   (f"{foreign} frame(s) sent with a MAC that is not the instance's own: that is what OVN learns on its port "
                    "(bridging, bonding, VIP or a reflected frame inside the instance)." if foreign else
                    "No frame with a foreign source MAC during the capture."),
                   {"columns": ["Instance", "Tap", "Frames", "Source MACs"], "rows": crow})
        # ---- 7. audit of the other networks (WI stage 10)
        counts = []
        for line in str(source(data, "fdbcount").get("out") or "").splitlines():
            m = re.match(r"^\s*(\d+)\s+(\d+)\s*$", line)
            if m:
                counts.append((int(m.group(2)), int(m.group(1))))
        mine = {dp["key"] for dp in dps.values()}
        others = [(k, n) for k, n in counts if k not in mine]
        unknown_all = [l for l in str(source(data, "unknown").get("out") or "").splitlines() if "|" in l]
        unknown_vm_all = [l for l in unknown_all if not l.split("|", 1)[1].strip()]
        r.step("audit", "Other networks: FDB entries and ports without port security (WI stage 10)",
               "warn" if others or unknown_vm_all else "ok",
               f"{sum(n for _k, n in others)} FDB entr(ies) in {len(others)} other network(s); {len(unknown_vm_all)} port(s) "
               "of instances in the cloud accept any MAC (port security disabled). Each is a candidate for the same problem.",
               {"columns": ["dp_key", "FDB entries"], "rows": [[str(k), str(n)] for k, n in others[:20]]})
        # ---- 8. the addresses to allow when port security goes on (WI stage 9): the VIPs of the check, and candidates
        vips = vip_list(params)
        candidates = []
        for nid in nets:
            for p in json_of(source(data, f"nports_{nid}")) or []:
                if not isinstance(p, dict):
                    continue
                pid = str(p.get("ID") or p.get("id") or "")
                owner_kind = str(p.get("Device Owner") or p.get("device_owner") or "")
                if pid in ports or owner_kind:
                    continue
                for ip in fixed_ips(p):
                    candidates.append([dps.get(nid, {}).get("name") or nid, str(p.get("Name") or p.get("name") or pid[:8]), ip,
                                       str(p.get("Status") or p.get("status") or "-"), "yes" if covers(vips, ip) else "no"])
        allowed_now = sorted({a for pid in off for a in (str(x.get("ip_address")) for x in ports[pid].get("allowed_address_pairs") or []
                                                        if isinstance(x, dict) and x.get("ip_address"))})
        not_given = [c[2] for c in candidates if c[4] == "no" and not covers(allowed_now, c[2])]
        if off:
            r.step("vips", "Addresses to allow when port security goes on (WI stage 9)", "warn" if not_given else "ok",
                   (f"VIPs of the check: {', '.join(vips)}. " if vips else "No VIP given in the check. ")
                   + (f"Allowed already on the ports: {', '.join(allowed_now)}. " if allowed_now else "")
                   + (f"{len(candidates)} reserved port(s) without a device on the network(s) (VIP candidates)"
                      + (f"; not in the check: {', '.join(not_given)}: if the instances answer for them, run the check again "
                         "with them in \"VIPs / allowed addresses\"." if not_given else ", all in the check.")
                      if candidates else "No reserved port without a device on the network(s)."),
                   {"columns": ["Network", "Port", "IP", "Status", "In the check"], "rows": candidates}, marks=not_given)
        # ---- fixes
        nodes_line = f"{node['name']}={node['ip']}"
        if poisoned:
            items = [{"label": f"{p['mac']} on {p['at']} ({dps[p['net']]['name']})",
                      "commands": [f"clear-fdb {p['uuid']} dp {p['dp']} mac {overcloud.mac_arg(p['mac'])} port {p['port_key']} "
                                   f"node {nodes_line} user {user}"],
                      "default": True} for p in poisoned if UUID.match(p["uuid"])]
            r.recommend("Clear the poisoned FDB entries (quick recovery, WI stage 8). OVN learns the right port again from the "
                        "next frames; routing and the MACs of the instances themselves (static flows) are not affected.",
                        ["# dry run: the entries of each network",
                         *(f"sudo podman exec ovn_controller ovn-sbctl --no-leader-only find fdb dp_key={dp['key']}   # {dp['name']}"
                           for dp in dps.values()),
                         *(f"sudo podman exec ovn_controller ovn-sbctl destroy fdb {p['uuid']}   # {p['mac']} on {p['at']}"
                           for p in poisoned),
                         "# the WI clears every entry of the network instead (all relearned):",
                         *(f"for u in $(sudo podman exec ovn_controller ovn-sbctl --no-leader-only --bare --columns=_uuid find fdb "
                           f"dp_key={dp['key']}); do sudo podman exec ovn_controller ovn-sbctl destroy fdb $u; done" for dp in dps.values())],
                        where=where,
                        items={"columns": ["FDB entry", "MAC", "Recorded on", "Network"],
                               "rows": [[p["uuid"], p["mac"], p["at"], dps[p["net"]]["name"]] for p in poisoned]},
                        warning="A write to the OVN Southbound DB (no --no-leader-only for destroy). The entries come back while "
                                "the instances keep sending foreign MACs with port security disabled: do the permanent fix too.",
                        action=os_select(items, target=", ".join(sorted({dps[p['net']]['name'] for p in poisoned})),
                                         label="Clear the ticked FDB entries", noun="FDB entries", lock="ovn-fdb",
                                         stop_on_failure=False, item_timeout=120, max_items=40) if items else None)
        if off:
            allow = ",".join(vips) or "-"
            items, rows = [], []
            for pid in off:
                p = ports[pid]
                nid = str(p.get("network_id") or "")
                project = str(p.get("project_id") or p.get("tenant_id") or "")
                pkey = next((k for (n, k), v in keyport.items() if n == nid and v["port"] == pid), "0")
                dp_key = dps.get(nid, {}).get("key", 0)
                name = name_of.get(p["_instance"], "")
                net = dps.get(nid, {}).get("name") or nid[:8]
                why = ("the project of the port is unknown" if not re.match(r"^[0-9a-f]{32}$", project) else
                       "the OVN datapath of its network could not be read" if nid not in dps else "")
                items.append({"label": f"{name} port {pid[:8]} ({net})",
                              "commands": [] if why else
                              [f"port-security {pid} project {project} sg port-security-allow-all allow {allow} "
                               f"dp {dp_key} pkey {pkey if str(pkey).isdigit() else 0} node {nodes_line} user {user}"],
                              "disabled": why, "default": not why})
                existing = [str(x.get("ip_address")) for x in p.get("allowed_address_pairs") or [] if isinstance(x, dict) and x.get("ip_address")]
                rows.append([pid, name, net, ", ".join(dict.fromkeys(existing + vips)) or "-"])
            projects = sorted({str(ports[pid].get("project_id") or ports[pid].get("tenant_id") or "<project>") for pid in off})
            warning = ((f"VIP candidates not in the check: {', '.join(not_given)}. If the instances answer for them (keepalived, "
                        "Pacemaker, Lustre HA), run the check again with them in \"VIPs / allowed addresses\" first, or the "
                        "traffic to them stops once port security is on. ") if not_given else "") \
                + ("With port security on, an instance only sends from its own MAC and IP" + (f" and {', '.join(vips)}" if vips else "")
                   + ": bridging or routing for other networks inside the instance stops. Port by port: the fix stops at the "
                   "first port that is not done.")
            r.recommend("Turn port security on for the ports (permanent fix, WI stage 9). The portal makes the security group "
                        "port-security-allow-all in the project of the ports (every protocol in and out: the traffic of the "
                        "application stays as it is, only the MAC / IP anti-spoofing of port security starts), enables port "
                        "security port by port with the VIPs of the check as allowed address pairs, checks that the address "
                        "\"unknown\" is gone in OVN and clears the FDB entries recorded on the port.",
                        [*(f"openstack security group create port-security-allow-all --project {pr}   # when it does not exist yet"
                           for pr in projects),
                         *(f"openstack security group rule create --{d} --ethertype {e} --protocol any --remote-ip {px} "
                           "port-security-allow-all" for d in ("ingress", "egress") for e, px in (("IPv4", "0.0.0.0/0"), ("IPv6", "::/0"))),
                         *(f"openstack port set --enable-port-security --security-group port-security-allow-all"
                           + "".join(f" --allowed-address ip-address={v}" for v in vips) + f" {pid}   # "
                           + name_of.get(ports[pid]["_instance"], "") for pid in off),
                         *(f"sudo podman exec ovn_controller ovn-sbctl --no-leader-only find port_binding logical_port={pid}"
                           "   # the address \"unknown\" is gone" for pid in off[:4])],
                        where=f"the director (source overcloudrc); the OVN commands on {node['name']}",
                        items={"columns": ["Port", "Instance", "Network", "Allowed addresses after"], "rows": rows},
                        warning=warning,
                        action=os_select(items, target=", ".join(sorted({name_of.get(ports[pid]["_instance"], "") for pid in off})),
                                         label="Turn port security on for the ticked ports", noun="ports",
                                         lock="ovn-port-security", stop_on_failure=True, item_timeout=300, max_items=40))
        if poisoned or unknown_vm:
            first = next((p for p in ports.values() if p["id"] in unknown_vm), None)
            mac_dst = (poisoned[0]["mac"] if poisoned else dest_mac) or "<destination MAC>"
            if first:
                r.recommend("Confirm with a trace in br-int (WI stages 5-6): table 71 (get FDB) gives reg15 = the port the FDB "
                            "chose; a port of an instance instead of the localnet port means the FDB is poisoned; reg14 = reg15 "
                            "means the frame is dropped (inport = outport).",
                            ["CTL=$(ls /var/run/openvswitch/ovs-vswitchd.*.ctl | head -1)",
                             f"sudo ovs-appctl -t $CTL ofproto/trace br-int in_port=tap{first['id'][:11]},"
                             f"dl_src={first.get('mac_address')},dl_dst={mac_dst},icmp,"
                             f"nw_src={(fixed_ips(first) or ['<instance IP>'])[0]},nw_dst={dest_ip or '<destination IP>'}",
                             f"sudo podman exec ovn_controller ovs-ofctl dump-flows br-int table=71 | grep -i {mac_dst}",
                             f"sudo tcpdump -nei tap{first['id'][:11]} -Q in 'not ether src {first.get('mac_address')}'"],
                            where=f"the compute of {name_of.get(first['_instance'], '')} ({first.get('binding_host_id') or '-'})")
            r.recommend("Prevent it: keep port security disabled only for a strong, documented reason; age the FDB of OVN when "
                        "the OVN / Neutron version supports it (fdb_age_threshold), so a wrong entry does not stay forever; run "
                        "this check after a migration or when instances are added to the network.",
                        ["sudo podman exec ovn_controller ovn-controller --version",
                         "sudo podman exec ovn_controller ovn-sbctl --no-leader-only --bare --columns=dp_key list fdb | grep . | sort | uniq -c"],
                        where=where)
        summary = (f"{len(poisoned)} poisoned FDB entr{'y' if len(poisoned) == 1 else 'ies'}: unicast to "
                   f"{', '.join(sorted({p['mac'] for p in poisoned})[:3])} goes to the wrong instance port."
                   if poisoned else
                   "Ports with port security disabled, but no poisoned FDB entry now." if unknown_vm else
                   "No FDB learning problem on the ports of these instances.")
        return r.done(summary)

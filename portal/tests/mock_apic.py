"""Mock APIC (HTTPS) to test the ACI module of the portal without a real fabric.

Used by the automated tests (tests/test_aci.py) and by the demo, and can be started by hand from the portal folder:

    .venv/bin/python tests/mock_apic.py
    # DCB, DCA and DCC on https://127.0.0.1:9441-9443; put the printed `apic` entries in sites.yml. The APIC service
    # accounts (Administration -> Credentials) can use any user with the password "secret".
    # MOCK_REJECT=DCC (comma-separated) makes a site refuse every login (a site with a connection error).

Tokens expire after refresh_timeout seconds; aaaRefresh replaces the token (the old token is invalid at once),
the behaviour the app has to handle on a real APIC as well.
"""
import datetime
import json
import os
import re
import secrets
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

import importlib  # noqa: E402
import types  # noqa: E402

# product_templates of the ACI module, imported without the module's __init__ (which needs the whole portal: settings,
# database, sign-in): a bare package object for modules/aci, so its relative import of aci.py still works.
_ACI_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules", "aci")
if "_mock_apic_aci" not in sys.modules:
    _package = types.ModuleType("_mock_apic_aci")
    _package.__path__ = [_ACI_DIR]
    sys.modules["_mock_apic_aci"] = _package
product_templates = importlib.import_module("_mock_apic_aci.product_templates")

PASSWORD = "secret"
# Per site: (leaf, interface) and (leaf pair, vPC policy group) in the fabric but in no product template.
SPARE_PATHS = {
    "DCB": (((118, "eth1/47"), (118, "eth1/48"), (119, "eth1/47"), (119, "eth1/48")),
            (("118-119", "Openstack-Traffic-I-PG"), ("122-123", "RHOSO-TRAFFIC-F-PG"), ("122-123", "RHOSO-TRAFFIC-G-PG"))),
    "DCA": (((111, "eth1/25"), (111, "eth1/26"), (112, "eth1/25"), (112, "eth1/26")),
            (("109-110", "Openstack-Traffic-X-PG"), ("109-110", "VMWare-Traffic-C07"))),
    "DCC": (((105, "eth1/36"), (105, "eth1/37"), (106, "eth1/36"), (106, "eth1/37")),
            (("103-104", "Openstack-Traffic-I-PG"), ("107-108", "VPC-VMware-Traffic-J-PG"))),
}

# RN builder per class, for nested POSTs (children without a dn).
RN = {
    "fvTenant": lambda a: f"tn-{a['name']}",
    "fvCtx": lambda a: f"ctx-{a['name']}",
    "fvBD": lambda a: f"BD-{a['name']}",
    "fvSubnet": lambda a: f"subnet-[{a['ip']}]",
    "fvRsCtx": lambda a: "rsctx",
    "fvRsBDToOut": lambda a: f"rsBDToOut-{a['tnL3extOutName']}",
    "fvAp": lambda a: f"ap-{a['name']}",
    "fvAEPg": lambda a: f"epg-{a['name']}",
    "fvRsBd": lambda a: "rsbd",
    "fvRsDomAtt": lambda a: f"rsdomAtt-[{a['tDn']}]",
    "fvRsPathAtt": lambda a: f"rspathAtt-[{a['tDn']}]",
}


def parent_dn(dn):
    """Parent of a dn, minding '/' inside [ ] (for example rspathAtt-[topology/...])."""
    depth = 0
    for i in range(len(dn) - 1, -1, -1):
        if dn[i] == "]":
            depth += 1
        elif dn[i] == "[":
            depth -= 1
        elif dn[i] == "/" and depth == 0:
            return dn[:i]
    return ""


def make_cert(directory):
    cert, key = os.path.join(directory, "cert.pem"), os.path.join(directory, "key.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
                    "-days", "2", "-subj", "/CN=localhost"], check=True, capture_output=True)
    return cert, key


class MockApic:
    def __init__(self, site, cert, key, refresh_timeout=600, reject=False, port=0):
        self.site, self.refresh_timeout, self.reject = site, refresh_timeout, reject
        self.mit = {}          # dn -> (class, attributes)
        self.tokens = {}       # token -> expiry time
        self.requests = []     # (method, path)
        self.posts = []        # (dn, body)
        self.fail_posts = False  # True: every configuration POST is refused, to test a failed apply
        self.drop_posts = False  # True: the connection is closed without an answer, to test an unknown result
        self.lock = threading.Lock()
        self._seed()
        handler = type("Handler", (_Handler,), {"apic": self})
        self.server = ThreadingHTTPServer(("127.0.0.1", port), handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self.host = f"127.0.0.1:{self.port}"

    def start(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self.server.shutdown()
        self.server.server_close()

    # ---- MIT ----
    def add(self, cls, dn, **attrs):
        self.mit[dn] = (cls, {"dn": dn, **attrs})

    def _seed(self):
        s = self.site
        for tenant in ("common", "CLOUD-1", "OpenStack-Tenant", f"{s}-Only"):
            self.add("fvTenant", f"uni/tn-{tenant}", name=tenant, descr=f"{tenant} asli")
        self.add("fvCtx", "uni/tn-CLOUD-1/ctx-VRF-1", name="VRF-1")
        self.add("fvBD", "uni/tn-CLOUD-1/BD-BD-1", name="BD-1", arpFlood="no", unkMacUcastAct="proxy")
        self.add("fvBD", "uni/tn-CLOUD-1/BD-BD-2", name="BD-2", arpFlood="no", unkMacUcastAct="proxy")
        self.add("l3extOut", "uni/tn-CLOUD-1/out-L3OUT-1", name="L3OUT-1")
        for app in ("MGMT-InBand", "PUBLIC-CLOUD-OPENSTACK"):
            self.add("fvAp", f"uni/tn-CLOUD-1/ap-{app}", name=app)
            for epg in ("Mgmt-InBand-EPG", "MGMT-VYOS"):
                self.add("fvAEPg", f"uni/tn-CLOUD-1/ap-{app}/epg-{epg}", name=epg)
                self.add("fvRsBd", f"uni/tn-CLOUD-1/ap-{app}/epg-{epg}/rsbd", tnFvBDName="BD-1")
        bindings = [
            ("topology/pod-1/paths-101/pathep-[eth1/1]", "vlan-11"),
            ("topology/pod-1/paths-101/pathep-[PC-SERVER-01]", "vlan-11"),
            ("topology/pod-1/protpaths-103-104/pathep-[Openstack-Traffic-A-PG]", "vlan-11"),
            ("topology/pod-1/paths-101/extpaths-111/pathep-[eth1/5]", "vlan-11"),
        ]
        for tdn, encap in bindings:
            dn = f"uni/tn-CLOUD-1/ap-MGMT-InBand/epg-Mgmt-InBand-EPG/rspathAtt-[{tdn}]"
            self.add("fvRsPathAtt", dn, tDn=tdn, encap=encap, mode="regular", instrImedcy="immediate")
        self.add("physDomP", f"uni/phys-{s}-PHYS", name=f"{s}-PHYS")
        self.add("vmmDomP", f"uni/vmmp-VMware/dom-{s}-DVS", name=f"{s}-DVS")
        self.add("vmmDomP", f"uni/vmmp-OpenStack/dom-{s}-OSP", name=f"{s}-OSP")
        # VLAN pools, for the free VLAN suggestions: the physical domain has a static pool (VLAN 300-310, plus a dynamic
        # block), the VMware domain a dynamic pool with one static block (VLAN 320-322), the OpenStack domain no pool.
        # Every EPG has the physical domain; Mgmt-InBand-EPG of MGMT-InBand has all three.
        phys_pool, dvs_pool = f"uni/infra/vlanns-[{s}-PHYS-VLANS]-static", f"uni/infra/vlanns-[{s}-DVS-VLANS]-dynamic"
        self.add("fvnsVlanInstP", phys_pool, name=f"{s}-PHYS-VLANS", allocMode="static")
        self.add("fvnsVlanInstP", dvs_pool, name=f"{s}-DVS-VLANS", allocMode="dynamic")
        for pool, low, high, alloc in ((phys_pool, 300, 310, "inherit"), (phys_pool, 1900, 1909, "dynamic"),
                                       (dvs_pool, 2000, 2099, "inherit"), (dvs_pool, 320, 322, "static")):
            self.add("fvnsEncapBlk", f"{pool}/from-[vlan-{low}]-to-[vlan-{high}]", **{"from": f"vlan-{low}", "to": f"vlan-{high}"},
                     allocMode=alloc)
        self.add("infraRsVlanNs", f"uni/phys-{s}-PHYS/rsvlanNs", tDn=phys_pool)
        self.add("infraRsVlanNs", f"uni/vmmp-VMware/dom-{s}-DVS/rsvlanNs", tDn=dvs_pool)
        for app in ("MGMT-InBand", "PUBLIC-CLOUD-OPENSTACK"):
            for epg in ("Mgmt-InBand-EPG", "MGMT-VYOS"):
                domains = [f"uni/phys-{s}-PHYS"]
                if (app, epg) == ("MGMT-InBand", "Mgmt-InBand-EPG"):
                    domains += [f"uni/vmmp-VMware/dom-{s}-DVS", f"uni/vmmp-OpenStack/dom-{s}-OSP"]
                for domain in domains:
                    self.add("fvRsDomAtt", f"uni/tn-CLOUD-1/ap-{app}/epg-{epg}/rsdomAtt-[{domain}]", tDn=domain)
        paths = ["topology/pod-1/paths-101/pathep-[eth1/1]", "topology/pod-1/paths-101/pathep-[eth1/13]",
                 "topology/pod-1/paths-106/pathep-[eth1/17]", "topology/pod-1/paths-101/pathep-[PC-SERVER-01]",
                 "topology/pod-1/paths-101/extpaths-111/pathep-[eth1/5]",
                 "topology/pod-1/protpaths-103-104/pathep-[Openstack-Traffic-A-PG]"]
        # All product template paths of this site exist in the fabric, as on the real APIC.
        paths += [dn for product in product_templates.for_site(s) for group in product["groups"] for dn in group["paths"]]
        # Ports and vPCs of new servers that no template has yet, so the template editor has something to add in the demo.
        leaves, vpcs = SPARE_PATHS.get(s, ((), ()))
        paths += [f"topology/pod-1/paths-{node}/pathep-[{iface}]" for node, iface in leaves]
        paths += [f"topology/pod-1/protpaths-{pair}/pathep-[{pg}]" for pair, pg in vpcs]
        for dn in paths:
            self.add("fabricPathEp", dn, name=dn.rsplit("[", 1)[1][:-1], descr=f"{s} path")
        self._seed_access_policies(paths)
        self._seed_endpoints(paths)

    def _seed_endpoints(self, paths):
        """Client endpoints (fvCEp with fvIp and the path they were learned on), as on the EPGs of tenant CLOUD-03:
        public IP EPGs named after their gateway, one of them sharing its bridge domain with a second EPG, a nearly full
        /28, an empty /26, a Acme Flex EPG, and an MPLS EPG that only sees MAC addresses."""
        s = self.site
        third = {"DCB": 158, "DCA": 160, "DCC": 162}.get(s, 170)
        vpcs = [p for p in paths if "/protpaths-" in p]
        a = next((p for p in vpcs if "25G-CLOUD-A" in p), vpcs[0])
        b = next((p for p in vpcs if "25G-CLOUD-B" in p), vpcs[-1])
        tenant, app = "uni/tn-CLOUD-03", "uni/tn-CLOUD-03/ap-Ip-Public-Shared"
        self.add("fvTenant", tenant, name="CLOUD-03", descr="CLOUD-03 asli")
        self.add("fvAp", app, name="Ip-Public-Shared", descr="PUBLIC-CLOUD")
        public = f"11.8.{third}"

        def bd(name, subnets=()):
            self.add("fvBD", f"{tenant}/BD-{name}", name=name, arpFlood="yes", unkMacUcastAct="proxy")
            for ip in subnets:
                self.add("fvSubnet", f"{tenant}/BD-{name}/subnet-[{ip}]", ip=ip, scope="public")

        def epg(name, bd_name):
            dn = f"{app}/epg-{name}"
            self.add("fvAEPg", dn, name=name)
            self.add("fvRsBd", f"{dn}/rsbd", tnFvBDName=bd_name)
            return dn

        def cep(epg_dn, mac, ips, path, encap="vlan-1604"):
            dn = f"{epg_dn}/cep-{mac}"
            self.add("fvCEp", dn, mac=mac, encap=encap, lcC="learned", ip=ips[0] if ips else "0.0.0.0", name=mac)
            for ip in ips:
                self.add("fvIp", f"{dn}/ip-[{ip}]", addr=ip)
            self.add("fvRsCEpToPathEp", f"{dn}/rscEpToPathEp-[{path}]", tDn=path)

        bd(f"{public}.1", [f"{public}.1/24"])
        main = epg(f"{public}.1", f"{public}.1")
        for i, (mac, hosts, path) in enumerate([("00:50:56:8B:8F:E7", (23, 100), a), ("00:50:56:8B:47:BC", (13, 4, 10, 11, 12), b),
                                                ("00:50:56:8B:70:D6", (6,), b), ("00:50:56:8B:AF:6C", (28,), b),
                                                ("00:50:56:8B:E9:AC", (27, 98), b), ("00:50:56:8B:F6:95", (25, 26), a),
                                                ("00:50:56:8B:FC:AB", (16,), a), ("00:50:56:AB:CD:BC", (247,), b)]):
            cep(main, mac, [f"{public}.{h}" for h in hosts], path)
        # A second EPG on the same bridge domain: its IP is not free for the first EPG either.
        cep(epg(f"{public}.1-DMZ", f"{public}.1"), "00:50:56:8B:D2:AA", [f"{public}.50"], a, "vlan-1605")
        bd("11.13.128.1", ["11.13.128.1/28"])
        full = epg("11.13.128.1", "11.13.128.1")
        for h in (2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14):
            cep(full, f"00:50:56:8C:00:{h:02X}", [f"11.13.128.{h}"], a, "vlan-1701")
        bd("11.15.64.1", ["11.15.64.1/26"])
        epg("11.15.64.1", "11.15.64.1")
        bd("Acme-Flex-1841", ["11.7.101.1/24"])
        flex = epg("Acme-Flex-1841", "Acme-Flex-1841")
        cep(flex, "FA:16:3E:12:34:56", ["11.7.101.10"], b, "vlan-1841")
        cep(flex, "FA:16:3E:65:43:21", ["11.7.101.11", "11.7.101.12"], b, "vlan-1841")
        bd("PAN-TO-ASR9K-L2")
        mpls = epg("PAN-TO-ASR9K-L2", "PAN-TO-ASR9K-L2")
        for mac in ("00:1B:54:C2:10:01", "00:1B:54:C2:10:02"):
            cep(mpls, mac, [], b, "vlan-2001")

    def _seed_access_policies(self, paths):
        """Fabric access policies behind the paths, as on the real APICs: leaves with their ports (l1PhysIf /
        ethpmPhysIf), vPC pairs (fabricExplicitGEp), one interface profile + leaf profile per leaf (access ports,
        port-channels) and per vPC pair (vPCs), a selector with one port block per policy group, AAEPs with their
        domains, the interface policies, port-channel members and LLDP neighbours. Ports in no selector are free."""
        s = self.site
        single, pairs = {}, {}   # leaf -> [interface or PC name]; "a-b" -> [vPC policy group]
        for dn in dict.fromkeys(paths):   # a path can be in the templates of several products
            m = re.match(r"^topology/pod-1/paths-(\d+)/pathep-\[([^\]]+)\]$", dn)
            if m:
                single.setdefault(int(m[1]), []).append(m[2])
            m = re.match(r"^topology/pod-1/protpaths-(\d+)-(\d+)/pathep-\[([^\]]+)\]$", dn)
            if m:
                pairs.setdefault((int(m[1]), int(m[2])), []).append(m[3])
        leaves = sorted(set(single) | {n for pair in pairs for n in pair})
        self.add("fabricNode", "topology/pod-1/node-1", id="1", name=f"{s}-APIC-1", role="controller", model="APIC-SERVER-M3")
        self.add("firmwareCtrlrRunning", "topology/pod-1/node-1/sys/ctrlrfwstatuscont/ctrlrrunning", version="5.2(7g)")
        for n in leaves:
            self.add("fabricNode", f"topology/pod-1/node-{n}", id=str(n), name=f"{s}-LEAF-{n}", role="leaf",
                     model="N9K-C93180YC-FX", serial=f"FDO{s}{n:04d}", fabricSt="active")
            self.add("firmwareRunning", f"topology/pod-1/node-{n}/sys/fwstatuscont/running", version="n9000-15.2(7g)")
        # Policies, AAEPs and domains.
        for speed in ("1G", "10G", "25G", "100G"):
            self.add("fabricHIfPol", f"uni/infra/hintfpol-{speed}", name=speed, speed=speed, autoNeg="on")
        self.add("lacpLagPol", "uni/infra/lacplagp-LACP-ACTIVE", name="LACP-ACTIVE", mode="active", ctrl="fast-sel-hot-stdby,graceful-conv,susp-individual")
        self.add("cdpIfPol", "uni/infra/cdpIfP-CDP-OFF", name="CDP-OFF", adminSt="disabled")
        self.add("lldpIfPol", "uni/infra/lldpIfP-LLDP-ON", name="LLDP-ON", adminRxSt="enabled", adminTxSt="enabled")
        self.add("mcpIfPol", "uni/infra/mcpIfP-MCP-ON", name="MCP-ON", adminSt="enabled")
        aaeps = {"OPENSTACK": [f"uni/phys-{s}-PHYS", f"uni/vmmp-OpenStack/dom-{s}-OSP"],
                 "VMWARE": [f"uni/phys-{s}-PHYS", f"uni/vmmp-VMware/dom-{s}-DVS"], "UPLINK": [f"uni/phys-{s}-PHYS"]}
        for name, domains in aaeps.items():
            dn = f"uni/infra/attentp-{s}-{name}-AAEP"
            self.add("infraAttEntityP", dn, name=f"{s}-{name}-AAEP")
            for domain in domains:
                self.add("infraRsDomP", f"{dn}/rsdomP-[{domain}]", tDn=domain)

        def aaep(pg):
            kind = "OPENSTACK" if re.search(r"openstack|rhoso", pg, re.I) else "VMWARE" if re.search(r"vmware|esxi", pg, re.I) else "UPLINK"
            return f"uni/infra/attentp-{s}-{kind}-AAEP"

        def speed(pg):
            return "1G" if re.search(r"(^|-)1G-", pg) else "10G" if "10G" in pg else "100G" if "100G" in pg else "25G"

        def policy_group(cls, pg, rn, lag=None):
            dn = f"uni/infra/funcprof/{rn}-{pg}"
            self.add(cls, dn, name=pg, **({"lagT": lag} if lag else {}))
            self.add("infraRsAttEntP", f"{dn}/rsattEntP", tDn=aaep(pg))
            self.add("infraRsHIfPol", f"{dn}/rshIfPol", tnFabricHIfPolName=speed(pg))
            self.add("infraRsCdpIfPol", f"{dn}/rscdpIfPol", tnCdpIfPolName="CDP-OFF")
            self.add("infraRsLldpIfPol", f"{dn}/rslldpIfPol", tnLldpIfPolName="LLDP-ON")
            if lag:
                self.add("infraRsLacpPol", f"{dn}/rslacpPol", tnLacpLagPolName="LACP-ACTIVE")
            return dn

        def profiles(name, nodes):
            """Interface profile + leaf profile (switch selector over these nodes); returns the interface profile DN."""
            ifp, nprof = f"uni/infra/accportprof-{name}_IntProf", f"uni/infra/nprof-{name}_SwProf"
            if ifp not in self.mit:
                self.add("infraAccPortP", ifp, name=f"{name}_IntProf")
                self.add("infraNodeP", nprof, name=f"{name}_SwProf")
                leafs = f"{nprof}/leaves-{name}-typ-range"
                self.add("infraLeafS", leafs, name=name, type="range")
                self.add("infraNodeBlk", f"{leafs}/nodeblk-blk1", name="blk1", from_=str(min(nodes)), to_=str(max(nodes)))
                self.add("infraRsAccPortP", f"{nprof}/rsaccPortP-[{ifp}]", tDn=ifp)
            return ifp

        def selector(ifp, name, port, pg_dn):
            sel = f"{ifp}/hports-{name}-typ-range"
            self.add("infraHPortS", sel, name=name, type="range")
            self.add("infraPortBlk", f"{sel}/portblk-block2", name="block2", fromCard="1", toCard="1", fromPort=str(port), toPort=str(port))
            self.add("infraRsAccBaseGrp", f"{sel}/rsaccBaseGrp", tDn=pg_dn)

        used = {n: set() for n in leaves}   # leaf -> front-panel ports in a selector
        bound = {}                          # (leaf, port) -> neighbour name
        for n, names in sorted(single.items()):
            ifp = profiles(f"Leaf{n}", [n])
            for name in names:
                m = re.match(r"^eth1/(\d+)$", name)
                if m:
                    port = int(m[1])
                    pg_dn = policy_group("infraAccPortGrp", "ESXi-25G-Access-PG", "accportgrp")
                    selector(ifp, f"eth1-{port}", port, pg_dn)
                    used[n].add(port)
                    bound[(n, port)] = f"{s.lower()}-esxi-{n}-{port:02d}"
            for name in names:   # port-channels on one leaf: the next free port
                if not re.match(r"^eth", name):
                    port = next(p for p in range(1, 49) if p not in used[n])
                    selector(ifp, name.replace("-PG", ""), port, policy_group("infraAccBndlGrp", name, "accbundle", "link"))
                    used[n].add(port)
                    self.add("pcAggrIf", f"topology/pod-1/node-{n}/sys/aggr-[po{port}]", id=f"po{port}", name=name, pcMode="active", operSt="up")
                    self.add("pcRsMbrIfs", f"topology/pod-1/node-{n}/sys/aggr-[po{port}]/rsmbrIfs-[eth1/{port}]", tSKey=f"eth1/{port}")
                    bound[(n, port)] = f"{s.lower()}-{name.lower()}"
        for gid, ((a, b), pgs) in enumerate(sorted(pairs.items()), 1):
            group = f"uni/fabric/protpol/expgep-VPC-{a}-{b}"
            self.add("fabricExplicitGEp", group, name=f"VPC-{a}-{b}", id=str(gid))
            for n in (a, b):
                self.add("fabricNodePEp", f"{group}/nodepep-{n}", id=str(n))
            ifp = profiles(f"Leaf{a}-{b}", [a, b])
            for pg in pgs:
                free = [p for p in range(1, 49) if p not in used[a] and p not in used[b]]
                if not free:
                    break
                port = free[0]
                selector(ifp, re.sub(r"-PG$", "", pg), port, policy_group("infraAccBndlGrp", pg, "accbundle", "node"))
                for n in (a, b):
                    used[n].add(port)
                    self.add("pcAggrIf", f"topology/pod-1/node-{n}/sys/aggr-[po{port}]", id=f"po{port}", name=pg, pcMode="active", operSt="up")
                    self.add("pcRsMbrIfs", f"topology/pod-1/node-{n}/sys/aggr-[po{port}]/rsmbrIfs-[eth1/{port}]", tSKey=f"eth1/{port}")
                    bound[(n, port)] = f"{s.lower()}-{re.sub(r'-PG$', '', pg).lower()}"
        # Ports of every leaf: 48 front-panel ports (eth1/1-48) and the fabric uplinks (eth1/49-54).
        for n in leaves:
            for port in range(1, 55):
                dn = f"topology/pod-1/node-{n}/sys/phys-[eth1/{port}]"
                uplink, up = port > 48, port > 48 or (n, port) in bound
                self.add("l1PhysIf", dn, id=f"eth1/{port}", adminSt="up", layer="Layer3" if uplink else "Layer2", portT="fab" if uplink else "leaf",
                         usage="fabric" if uplink else "epg" if (n, port) in bound else "discovery", speed="inherit", descr="")
                self.add("ethpmPhysIf", f"{dn}/phys", operSt="up" if up else "down", operSpeed="100G" if uplink else "25G" if up else "unknown",
                         usage="fabric" if uplink else "epg" if (n, port) in bound else "discovery")
                if (n, port) in bound:
                    self.add("lldpAdjEp", f"topology/pod-1/node-{n}/sys/lldp/inst/if-[eth1/{port}]/adj-1", sysName=bound[(n, port)],
                             portIdV="ens1f0" if n % 2 else "ens1f1", mgmtIp="0.0.0.0")

    def add_vlan_users(self):
        """VLANs already used elsewhere, for the VLAN check (tests and demo): VLAN 300 on a static path and VLAN 301 on a
        static leaf of EPG CLOUD-1/PUBLIC-CLOUD-OPENSTACK/MGMT-VYOS, VLAN 302 on an interface of L3Out CLOUD-1/L3OUT-1.
        Returns the DNs, so a test can remove them again."""
        other = "uni/tn-CLOUD-1/ap-PUBLIC-CLOUD-OPENSTACK/epg-MGMT-VYOS"
        added = [(f"{other}/rspathAtt-[topology/pod-1/paths-106/pathep-[eth1/17]]", "fvRsPathAtt",
                  {"tDn": "topology/pod-1/paths-106/pathep-[eth1/17]", "encap": "vlan-300", "mode": "regular", "instrImedcy": "immediate"}),
                 (f"{other}/rsnodeAtt-[topology/pod-1/node-101]", "fvRsNodeAtt",
                  {"tDn": "topology/pod-1/node-101", "encap": "vlan-301", "mode": "regular", "instrImedcy": "immediate"}),
                 ("uni/tn-CLOUD-1/out-L3OUT-1/lnodep-NP/lifp-IFP/rspathL3OutAtt-[topology/pod-1/paths-101/pathep-[eth1/48]]",
                  "l3extRsPathL3OutAtt", {"tDn": "topology/pod-1/paths-101/pathep-[eth1/48]", "encap": "vlan-302", "ifInstT": "ext-svi"})]
        with self.lock:
            for dn, cls, attrs in added:
                self.add(cls, dn, **attrs)
        return [dn for dn, _, _ in added]

    def objects(self, cls):
        return [(c, a) for c, a in self.mit.values() if c in cls]

    def upsert(self, cls, body, parent=""):
        attrs = body.get("attributes", {})
        dn = attrs.get("dn") or f"{parent}/{RN[cls](attrs)}"
        if attrs.get("status") == "deleted":   # the object and everything under it
            for key in [k for k in self.mit if k == dn or k.startswith(dn + "/")]:
                del self.mit[key]
            return
        old = self.mit.get(dn, (cls, {}))[1]
        modified = datetime.datetime.now().astimezone().isoformat(timespec="milliseconds")   # like APIC's modTs
        self.mit[dn] = (cls, {**old, **{k: v for k, v in attrs.items() if k != "status"}, "dn": dn, "modTs": modified})
        for child in body.get("children", []):
            for child_cls, child_body in child.items():
                self.upsert(child_cls, child_body, dn)

    # ---- token ----
    def issue(self, user):
        token = secrets.token_hex(16)
        with self.lock:
            self.tokens[token] = time.time() + self.refresh_timeout
        return {"imdata": [{"aaaLogin": {"attributes": {"token": token, "refreshTimeoutSeconds": str(self.refresh_timeout), "userName": user}}}]}

    def valid(self, token):
        with self.lock:
            return token in self.tokens and self.tokens[token] > time.time()

    def count(self, method, prefix):
        return sum(1 for m, p in self.requests if m == method and p.startswith(prefix))


class _Handler(BaseHTTPRequestHandler):
    apic = None

    def log_message(self, *args):
        pass

    def reply(self, code, body):
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def token(self):
        match = re.search(r"APIC-cookie=([^;]+)", self.headers.get("Cookie", ""))
        return match.group(1) if match else None

    def forbidden(self):
        self.reply(403, {"imdata": [{"error": {"attributes": {"code": "403", "text": "Token was invalid (Error: Token timeout)"}}}]})

    def listing(self, objs, query):
        objs = sorted(objs, key=lambda o: o[1]["dn"])
        size = int((query.get("page-size") or ["100000"])[0])
        page = int((query.get("page") or ["0"])[0])
        chunk = objs[page * size:(page + 1) * size]
        self.reply(200, {"totalCount": str(len(objs)), "imdata": [{c: {"attributes": a}} for c, a in chunk]})

    def do_POST(self):
        apic = self.apic
        path = unquote(urlparse(self.path).path)
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}") if length else {}
        apic.requests.append(("POST", path))
        if path == "/api/aaaLogin.json":
            user = body["aaaUser"]["attributes"]
            if apic.reject or user.get("pwd") != PASSWORD:
                return self.reply(401, {"imdata": [{"error": {"attributes": {"code": "401", "text": "Username or password is incorrect - FAILED local authentication"}}}]})
            return self.reply(200, apic.issue(user["name"]))
        if path == "/api/aaaLogout.json":
            with apic.lock:
                apic.tokens.pop(self.token(), None)
            return self.reply(200, {"imdata": []})
        if not apic.valid(self.token()):
            return self.forbidden()
        match = re.match(r"^/api/(?:node/)?mo/(.+)\.json$", path)
        if not match:
            return self.reply(404, {"imdata": []})
        if apic.fail_posts:
            return self.reply(400, {"imdata": [{"error": {"attributes": {"code": "400", "text": "Simulated APIC failure"}}}]})
        if apic.drop_posts:
            self.close_connection = True
            return
        with apic.lock:
            for cls, cls_body in body.items():
                apic.upsert(cls, cls_body, parent_dn(match.group(1)))
            apic.posts.append((match.group(1), body))
        self.reply(200, {"imdata": []})

    def do_GET(self):
        apic = self.apic
        url = urlparse(self.path)
        path, query = unquote(url.path), parse_qs(url.query)
        apic.requests.append(("GET", path))
        if path == "/api/aaaRefresh.json":
            if not apic.valid(self.token()):
                return self.forbidden()
            with apic.lock:
                apic.tokens.pop(self.token(), None)
            return self.reply(200, apic.issue("refresh"))
        if not apic.valid(self.token()):
            return self.forbidden()
        match = re.match(r"^/api/node/class/(\w+)\.json$", path)
        if match:
            objs = apic.objects({match.group(1)})
            # query-target-filter: eq(<class>.<attr>,"<value>") terms, alone or inside or(...), as used by the app.
            terms = re.findall(r'eq\((\w+)\.(\w+),"([^"]*)"\)', (query.get("query-target-filter") or [""])[0])
            if terms:
                objs = [o for o in objs if any(o[0] == c and o[1].get(k) == v for c, k, v in terms)]
            return self.listing(objs, query)
        match = re.match(r"^/api/node/mo/(.+)\.json$", path)
        if not match:
            return self.reply(404, {"imdata": []})
        dn = match.group(1)
        target = (query.get("query-target") or ["self"])[0]
        classes = set((query.get("target-subtree-class") or [""])[0].split(","))
        if target == "self":
            return self.listing([apic.mit[dn]] if dn in apic.mit else [], query)
        if target == "children":
            return self.listing([o for o in apic.mit.values() if parent_dn(o[1]["dn"]) == dn and o[0] in classes], query)
        return self.listing([o for o in apic.mit.values() if o[1]["dn"].startswith(dn + "/") and o[0] in classes], query)


if __name__ == "__main__":
    workdir = tempfile.mkdtemp()
    cert, key = make_cert(workdir)
    # MOCK_REJECT=DCC (several allowed, comma-separated) simulates a site that refuses the login.
    reject = {s.strip().upper() for s in os.environ.get("MOCK_REJECT", "").split(",") if s.strip()}
    sites = [MockApic(name, cert, key, port=port, reject=name in reject).start()
             for name, port in (("DCB", 9441), ("DCA", 9442), ("DCC", 9443))]
    for mock in sites:
        mock.add_vlan_users()   # demo: VLANs 300-302 are already used by another EPG / an L3Out
    print("Mock APICs are running. sites.yml of the portal:")
    print("sites:\n" + "".join(f"  {m.site}:\n    apic: {{host: \"{m.host}\"}}\n" for m in sites), end="")
    print(f"Password for any user: {PASSWORD}."
          + (f" Sites that refuse every login on purpose: {', '.join(sorted(reject))}." if reject else "")
          + " Ctrl+C to stop.")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass

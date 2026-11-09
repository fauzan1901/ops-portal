"""Tests of the read-only ACI access policy dump against the mock APIC of the portal tests (portal/tests/mock_apic.py).

    portal/.venv/bin/python -m unittest discover -s tools/aci-access-dump -v
"""
import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PORTAL = os.path.join(os.path.dirname(os.path.dirname(HERE)), "portal")
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(PORTAL, "tests"))

import aci_access_dump as dump  # noqa: E402
from mock_apic import PASSWORD, MockApic, make_cert  # noqa: E402


class DumpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="aci-access-dump-")
        cert, key = make_cert(cls.tmp)
        cls.mock = MockApic("DCB", cert, key).start()
        cls.mock.add("fvRsPathAtt", "uni/tn-CLOUD-1/ap-MGMT-InBand/epg-X/rspathAtt-[topology/pod-1/protpaths-118-119/pathep-[Openstack-Traffic-A-PG]]",
                     tDn="topology/pod-1/protpaths-118-119/pathep-[Openstack-Traffic-A-PG]", encap="vlan-1841")
        apic = dump.Apic(cls.mock.host)
        apic.login("svc_aci", PASSWORD)
        try:
            cls.folder, cls.a, cls.errors = dump.dump(apic, "DCB", cls.tmp, log=lambda m: None)
        finally:
            apic.logout()
        cls.requests = apic.requests

    @classmethod
    def tearDownClass(cls):
        cls.mock.stop()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_only_reads(self):
        posts = [path for method, path in self.requests if method != "GET"]
        self.assertEqual(posts, ["/api/aaaLogin.json", "/api/aaaLogout.json"])
        self.assertEqual(self.mock.posts, [])
        self.assertEqual({m for m, p in self.mock.requests if p not in dump.SIGN_IN}, {"GET"})
        with self.assertRaises(AssertionError):
            dump.Apic(self.mock.host)._request("POST", "/api/mo/uni/infra.json", {})

    def test_every_class_and_the_files(self):
        self.assertEqual(self.errors, {})
        for name in ("summary.md", "ports.csv", "policy_groups.csv", "selectors.csv", "raw/infraAccBndlGrp.json"):
            self.assertTrue(os.path.exists(os.path.join(self.folder, name)), name)
        with open(os.path.join(self.folder, "raw", "fabricExplicitGEp.json")) as f:
            self.assertEqual(len(json.load(f)), 4)

    def test_analysis(self):
        a = self.a
        self.assertIn({"name": "VPC-118-119", "id": "3", "nodes": [118, 119]}, a["pairs"])
        groups = {g["name"]: g for g in a["groups"]}
        vpc = groups["Openstack-Traffic-A-PG"]
        self.assertEqual((vpc["type"], vpc["aaep"], vpc["link"], vpc["lacp"], vpc["lldp"]), ("vPC", "DCB-OPENSTACK-AAEP", "25G", "LACP-ACTIVE", "LLDP-ON"))
        self.assertEqual({p.split(":")[0] for p in groups["Openstack-Traffic-B-PG"]["ports"]}, {"118", "119"}, "a vPC has a port on both leaves")
        self.assertEqual({p.split(":")[0] for p in vpc["ports"]}, {"103", "104", "118", "119"}, "one vPC policy group on two vPC pairs")
        self.assertEqual((groups["Po-Solarwinds"]["type"], groups["ESXi-25G-Access-PG"]["type"]), ("PC", "Access"))
        ports = {(p["node"], p["interface"]): p for p in a["ports"]}
        bound = next(p for p in a["ports"] if p["pg"] == "Openstack-Traffic-A-PG" and p["node"] == 118)
        self.assertEqual((bound["status"], bound["bindings"], bound["path_exists"]), ("configured, bound", 1, True))
        self.assertTrue(bound["neighbour"].startswith("dcb-openstack-traffic-a"))
        self.assertEqual(ports[(118, "eth1/49")]["status"], "fabric uplink")
        free = [p for p in a["ports"] if p["node"] == 118 and p["status"] == "free"]
        self.assertTrue(free and all(p["oper"] == "down" and not p["pg"] for p in free))
        self.assertEqual(ports[(118, "eth1/17")]["pg"], "ESXi-25G-Access-PG")
        self.assertEqual(a["warnings"], [])

    def test_overlap_and_missing_policy_group_are_findings(self):
        objs = {cls: [] for cls, _ in dump.CLASSES}
        objs["fabricNode"] = [{"dn": "topology/pod-1/node-101", "id": "101", "role": "leaf", "name": "L101"}]
        objs["infraNodeP"] = [{"dn": "uni/infra/nprof-L101", "name": "L101"}]
        objs["infraLeafS"] = [{"dn": "uni/infra/nprof-L101/leaves-L101-typ-range", "name": "L101"}]
        objs["infraNodeBlk"] = [{"dn": "uni/infra/nprof-L101/leaves-L101-typ-range/nodeblk-b", "from_": "101", "to_": "101"}]
        objs["infraRsAccPortP"] = [{"dn": "uni/infra/nprof-L101/rsaccPortP-[uni/infra/accportprof-A]", "tDn": "uni/infra/accportprof-A"}]
        objs["infraAccPortP"] = [{"dn": "uni/infra/accportprof-A", "name": "A"}, {"dn": "uni/infra/accportprof-B", "name": "B"}]
        objs["infraHPortS"] = [{"dn": f"uni/infra/accportprof-A/hports-{n}-typ-range", "name": n} for n in ("one", "two")] + \
                              [{"dn": "uni/infra/accportprof-B/hports-x-typ-range", "name": "x"}]
        objs["infraPortBlk"] = [{"dn": f"uni/infra/accportprof-A/hports-{n}-typ-range/portblk-b", "fromCard": "1", "toCard": "1", "fromPort": "5",
                                 "toPort": "5"} for n in ("one", "two")]
        objs["infraRsAccBaseGrp"] = [{"dn": "uni/infra/accportprof-A/hports-one-typ-range/rsaccBaseGrp", "tDn": "uni/infra/funcprof/accportgrp-GONE"}]
        objs["l1PhysIf"] = [{"dn": "topology/pod-1/node-101/sys/phys-[eth1/5]", "adminSt": "up", "usage": "discovery"}]
        a = dump.analyze(objs)
        text = "\n".join(a["warnings"])
        self.assertIn("Node 101 eth1/5 is in 2 selectors: A/one, A/two", text)
        self.assertIn("Selector A/one points to a missing policy group uni/infra/funcprof/accportgrp-GONE", text)
        self.assertIn("Selector A/two has no policy group", text)
        self.assertIn("Selector B/x: its interface profile is not attached to any leaf profile", text)
        self.assertEqual(a["ports"][0]["status"], "overlap")

    def test_summary(self):
        with open(os.path.join(self.folder, "summary.md")) as f:
            text = f.read()
        for part in ("# ACI access policies — DCB", "APIC version: **5.2(7g)**", "| 118 | DCB-LEAF-118 | N9K-C93180YC-FX | VPC-118-119 |",
                     "| Leaf118-119_SwProf | 118, 119 | Leaf118-119_IntProf |", "`Openstack-Traffic-*-PG`", "DCB-OPENSTACK-AAEP",
                     "Interface profiles: per leaf:", "`LACP-ACTIVE` (mode active)"):
            self.assertIn(part, text)
        with open(os.path.join(self.folder, "ports.csv")) as f:
            rows = list(csv.DictReader(f))
        self.assertEqual({r["Status"] for r in rows}, {"free", "configured, bound", "configured, no EPG binding", "fabric uplink"})

    def test_cli_reads_the_password_from_the_environment(self):
        env = {**os.environ, "APIC_USER": "svc_aci", "APIC_PASSWORD": PASSWORD}
        r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "aci_access_dump.py"), "--site", "DCB", "--apic", self.mock.host,
                            "--out", os.path.join(self.tmp, "cli")], env=env, capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.exists(os.path.join(r.stdout.strip(), "summary.md")))
        self.assertIn("read-only: GET only", r.stderr)
        bad = subprocess.run([sys.executable, "-I", os.path.join(HERE, "aci_access_dump.py"), "--site", "DCB", "--apic", self.mock.host,
                              "--out", os.path.join(self.tmp, "bad")], env={**env, "APIC_PASSWORD": "wrong"}, capture_output=True, text=True, timeout=60)
        self.assertEqual(bad.returncode, 2)
        self.assertIn("Sign-in to APIC", bad.stderr)


class PortalCredentialTest(unittest.TestCase):
    """portal_credential.py reads the host from sites.yml and the apic:<site> service account of the portal."""

    def test_reads_the_service_account(self):
        tmp = tempfile.mkdtemp(prefix="aci-access-cred-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        env = {**os.environ, "PORTAL_ETC": tmp, "PORTAL_DATA": tmp, "PORTAL_SITES": os.path.join(tmp, "sites.yml"),
               "PORTAL_CREDENTIALS_KEY": os.path.join(tmp, "credentials.key")}
        with open(env["PORTAL_SITES"], "w") as f:
            f.write('sites:\n  DCB:\n    apic: {host: "172.26.2.250"}\n  DCA:\n    apic: {host: "172.24.27.251"}\n')
        setup = ("import sys; sys.path.insert(0, sys.argv[1]); import portal_auth, settings; "
                 "portal_auth.Store(settings.DB_PATH).set_credential('apic:DCB', 'svc_aci', portal_auth.Vault(settings.CREDENTIALS_KEY).encrypt('s3cret'), 'test')")
        python = os.path.join(PORTAL, ".venv", "bin", "python")
        subprocess.run([python, "-I", "-c", setup, PORTAL], env=env, check=True, cwd=tmp)
        with open(os.path.join(HERE, "portal_credential.py")) as script:
            r = subprocess.run([python, "-I", "-", PORTAL, "dcb"], stdin=script, env=env, capture_output=True, text=True, cwd="/")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout), {"host": "172.26.2.250", "username": "svc_aci", "password": "s3cret"})
        with open(os.path.join(HERE, "portal_credential.py")) as script:
            r = subprocess.run([python, "-I", "-", PORTAL, "DCA"], stdin=script, env=env, capture_output=True, text=True, cwd="/")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("apic:DCA", r.stderr)


if __name__ == "__main__":
    unittest.main()

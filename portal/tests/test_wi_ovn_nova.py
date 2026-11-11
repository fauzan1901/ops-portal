"""Checks ovn-metadata, ovn-chassis-stale, compute-hypervisor-sync and placement-consistency (RISET-KNOWN-ISSUES 2.1 #4/#6,
2.3 #1-4), the memory steps ovn-db-cluster gained, and the wi_ops.py operation chassis-del: their reads answered by the
fake director (tests/fake_cloud.py), their read-only guard, their rating, and every guard of the fix.

Run from the portal folder:
    .venv/bin/python -m unittest tests.test_wi_ovn_nova -v
"""
import os
import shlex
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "modules", "wi"))
os.environ.pop("FAKE_CLOUD_STATE", None)   # the fixed cloud only; chassis-del keeps its deletions in memory

import fake_cloud  # noqa: E402
import wi_analysis  # noqa: E402
from wi_analysis import overcloud, wi_ops  # noqa: E402

NEW = ("ovn-metadata", "ovn-chassis-stale", "compute-hypervisor-sync", "placement-consistency")
CTL0 = "node overcloud-controller-0=192.168.253.10 user heat-admin"


def run(check, params=None, ctx=None):
    """The check as the playbook runs it: every phase planned on what was read before, every read answered by the fake
    director (an overcloud read as the director runs it: ssh <user>@<ctlplane address> '<command>')."""
    params, ctx, data, seen = params or {}, ctx or {"site": "DCC"}, {}, []
    for phase in range(1, wi_analysis.plan(check)["phases"] + 1):
        for src, items in wi_analysis.reads(check, phase, data, params, ctx).items():
            for key, cmd in items.items():
                shown = cmd
                if src == "overcloud":
                    _node, ip, user, shown = overcloud.parse(cmd)
                    cmd = f"{overcloud.SSH} {user}@{ip} {shlex.quote(shown)}"
                fake_cloud.UNDERCLOUD = src == "undercloud"
                rc, out = fake_cloud.answer(cmd)
                data[key] = {"rc": rc, "out": out}
                seen.append((src, key, shown))
    return wi_analysis.analyze(check, data, params, ctx), seen


def steps(result):
    return {s["key"]: s for s in result["steps"]}


class CatalogTest(unittest.TestCase):
    def setUp(self):
        fake_cloud.STATE.pop("chassis_del", None)

    def test_catalog_registry_and_params(self):
        from modules.wi import catalog
        for check in NEW:
            c = catalog.get(check)
            self.assertEqual((c["status"], c["activity"], c["basis"]), ("ready", "health", "platform"), check)
            self.assertIn(check, wi_analysis.CHECKS)
        self.assertTrue(catalog.get("ovn-chassis-stale")["fix"])
        self.assertFalse(catalog.get("placement-consistency")["fix"])
        symptoms = {s["id"]: s["checks"] for s in catalog.CATALOG["symptoms"]}
        self.assertIn("ovn-metadata", symptoms["vm-unreachable"])
        self.assertIn("placement-consistency", symptoms["cannot-create"])
        self.assertIn("compute-hypervisor-sync", symptoms["stuck"])
        self.assertIn("ovn-chassis-stale", symptoms["openstack-failing"])
        with self.assertRaises(ValueError):   # the compute is a host name, nothing else reaches a command
            catalog.clean_params(catalog.get("ovn-metadata"), {"compute": "x; reboot"}, "DCC", {})

    def test_reads_are_read_only(self):
        """OpenStack reads pass the read-only allowlist, overcloud reads are fixed commands; nothing deletes or heals."""
        for check in NEW:
            _res, seen = run(check)
            for src, _key, cmd in seen:
                if src == "openstack":
                    wi_analysis.assert_openstack_read(cmd)
                if src == "overcloud":
                    self.assertNotIn("--delete", cmd)
                    self.assertNotIn("chassis-del", cmd)
                    self.assertNotRegex(cmd, r"heal_allocations(?! --dry-run)")
        _res, seen = run("placement-consistency")
        audit = next(c for s, k, c in seen if k == "audit")
        self.assertIn("nova-manage placement audit --verbose", audit)
        self.assertIn("timeout 600", audit)


class OvnMetadataTest(unittest.TestCase):
    def test_missing_sidecar_and_errors(self):
        res, seen = run("ovn-metadata")
        st = steps(res)
        self.assertEqual(st["nodes"]["status"], "warn")   # overcloud-novacompute-3 is down
        self.assertIn("not reached: overcloud-novacompute-3", st["nodes"]["detail"])
        self.assertEqual(st["agent"]["status"], "ok")
        self.assertEqual(st["sidecars"]["status"], "fail", st["sidecars"])
        self.assertIn("overcloud-novacompute-9", st["sidecars"]["detail"])
        rows = {r[0]: r for r in st["sidecars"]["table"]["rows"]}
        self.assertEqual(rows["overcloud-novacompute-7"][3], "-")
        self.assertEqual(rows["overcloud-novacompute-9"][3], fake_cloud.META_NETS[2])
        self.assertEqual(rows["overcloud-novacompute-9"][4], fake_cloud.META_NETS[2])   # its sidecar exited
        self.assertEqual(st["errors"]["status"], "warn")
        self.assertEqual(st["errors"]["table"]["rows"][0][1], 2)
        self.assertNotIn("2026-11-11", st["errors"]["table"]["rows"][0][2])   # date, time and pid stripped
        self.assertTrue(any("tripleo_ovn_metadata_agent" in " ".join(r["commands"]) for r in res["recommendations"]))
        self.assertFalse(any(r.get("action") for r in res["recommendations"]))   # restarts stay with the engineer

    def test_one_compute(self):
        res, seen = run("ovn-metadata", {"compute": "compute-07"})
        self.assertEqual([k for s, k, c in seen if s == "overcloud"], ["meta_0"])
        self.assertEqual(steps(res)["sidecars"]["status"], "ok")
        res, _seen = run("ovn-metadata", {"compute": "compute-42"})
        self.assertEqual(steps(res)["nodes"]["status"], "fail")


class OvnChassisStaleTest(unittest.TestCase):
    def setUp(self):
        fake_cloud.STATE.pop("chassis_del", None)

    def test_stale_chassis_and_gateway(self):
        res, _seen = run("ovn-chassis-stale")
        st = steps(res)
        self.assertEqual(st["agents"]["status"], "warn")   # dead agents of compute-03 and compute-old-09
        self.assertEqual(st["chassis"]["status"], "fail", st["chassis"])   # a gateway on the removed controller-3
        self.assertIn("overcloud-controller-3", st["chassis"]["detail"])
        stale = {r[0] for r in st["chassis"]["table"]["rows"] if r[6] == "STALE"}
        self.assertEqual(stale, {fake_cloud.uid(3, "a9"), fake_cloud.uid(8, "a9"), fake_cloud.GONE_CTL})
        rec = next(r for r in res["recommendations"] if r.get("action"))
        items = {i["label"]: i for i in rec["action"]["select"]["items"]}
        self.assertEqual(rec["action"]["select"]["lock"], "ovn-chassis")
        gone = items[f"overcloud-controller-3.localdomain ({fake_cloud.GONE_CTL})"]
        self.assertEqual(gone["commands"], [f"chassis-del {fake_cloud.GONE_CTL} host overcloud-controller-3 {CTL0}"])
        old = items[f"compute-old-09.localdomain ({fake_cloud.uid(8, 'a9')})"]
        self.assertTrue(old["commands"] and not old.get("disabled"))
        bound = items[f"overcloud-novacompute-3.localdomain ({fake_cloud.uid(3, 'a9')})"]
        self.assertEqual(bound["commands"], [])
        self.assertIn("ports are still bound", bound["disabled"])
        for it in rec["action"]["select"]["items"]:
            for cmd in it["commands"]:
                self.assertTrue(wi_analysis.OPENSTACK_DELETE.search(cmd))   # the operator types what is deleted

    def test_chassis_del_operation(self):
        line = f"chassis-del {fake_cloud.GONE_CTL} host overcloud-controller-3 {CTL0}".split()
        rc, log = self.op(line)
        self.assertEqual(rc, wi_ops.OK, log)
        self.assertIn("deleted from the OVN Southbound", log[-1])
        self.assertIn(fake_cloud.GONE_CTL, fake_cloud.STATE["chassis_del"])
        rc, log = self.op(line)   # again: already gone
        self.assertEqual(rc, wi_ops.OK)
        self.assertIn("already gone", log[-1])
        st = steps(run("ovn-chassis-stale")[0])
        self.assertEqual(st["chassis"]["status"], "warn")   # the gateway of the removed controller went with it

    def test_chassis_del_guards(self):
        # binds a port now
        rc, log = self.op(f"chassis-del {fake_cloud.uid(3, 'a9')} host overcloud-novacompute-3 {CTL0}".split())
        self.assertEqual(rc, wi_ops.FAILED)
        self.assertIn("binds 1 port(s)", log[-1])
        # answered nb_cfg 20 s ago: alive
        rc, log = self.op(f"chassis-del {fake_cloud.uid(0, 'a9')} host overcloud-controller-0 {CTL0}".split())
        self.assertEqual(rc, wi_ops.FAILED)
        self.assertIn("binds 2 port(s)", log[-1])
        rc, log = self.op(f"chassis-del {fake_cloud.uid(7, 'a9')} host compute-08 {CTL0}".split())
        self.assertEqual(rc, wi_ops.FAILED)
        self.assertIn("is alive", log[-1])
        # another host than the check saw
        rc, log = self.op(f"chassis-del {fake_cloud.uid(8, 'a9')} host compute-99 {CTL0}".split())
        self.assertEqual(rc, wi_ops.FAILED)
        self.assertIn("not of compute-99", log[-1])
        self.assertNotIn("chassis_del", fake_cloud.STATE)
        # nothing outside the grammar
        for bad in (f"chassis-del not-a-uuid host compute-old-09 {CTL0}",
                    f"chassis-del {fake_cloud.uid(8, 'a9')} host x;reboot {CTL0}",
                    f"chassis-del {fake_cloud.uid(8, 'a9')} host compute-old-09 node overcloud-controller-0=192.168.253.10 user root"):
            self.assertFalse(any(rx.match(bad) for rx in wi_analysis.OPENSTACK_FIX), bad)

    def op(self, argv):
        log = []

        def runner(cmd, timeout):
            if cmd and cmd[0] == "ssh":
                user_ip, inner = cmd[-2], cmd[-1]
                return fake_cloud.answer(f"{overcloud.SSH} {user_ip} {shlex.quote(inner)}")
            return fake_cloud.answer(shlex.join(cmd))
        d = wi_ops.Director(runner=runner, clock=lambda: 1793125000, sleep=lambda x: None, write=log.append)
        return wi_ops.main(argv, d), log


class ComputeHypervisorSyncTest(unittest.TestCase):
    def test_domains_services_and_cells(self):
        res, _seen = run("compute-hypervisor-sync")
        st = steps(res)
        self.assertEqual(st["nodes"]["status"], "warn")   # overcloud-novacompute-3 is down
        self.assertEqual(st["services"]["status"], "ok")
        self.assertEqual(st["domains"]["status"], "fail", st["domains"])
        rows = {r[2]: r for r in st["domains"]["table"]["rows"]}
        legacy, batch = fake_cloud.uid(8, "5e"), fake_cloud.uid(6, "5e")
        self.assertEqual(rows[legacy][3:], ["ACTIVE in Nova", "no domain"])
        self.assertEqual(rows[batch][3:], ["SHUTOFF in Nova", "running"])
        self.assertEqual(rows[fake_cloud.ZOMBIE][3:], ["Nova places it on compute-03", "running"])   # two writers
        self.assertEqual(rows[fake_cloud.LEFTOVER][3:], ["no instance in Nova", "defined"])
        self.assertEqual(st["cells"]["status"], "fail")
        self.assertIn("compute-08", st["cells"]["detail"])
        self.assertFalse(any(r.get("action") for r in res["recommendations"]))   # every repair stays with a person

    def test_one_healthy_compute(self):
        res, seen = run("compute-hypervisor-sync", {"compute": "compute-09"})
        self.assertEqual(sorted(k for s, k, c in seen if s == "overcloud" and k.startswith("sync_")), ["sync_0"])
        st = steps(res)
        self.assertEqual((st["nodes"]["status"], st["services"]["status"], st["domains"]["status"]), ("ok", "ok", "ok"))


class PlacementTest(unittest.TestCase):
    def test_audit_and_heal(self):
        res, _seen = run("placement-consistency")
        st = steps(res)
        self.assertEqual(st["audit"]["status"], "warn")
        self.assertEqual(st["audit"]["table"]["rows"], [[fake_cloud.uid(77, "5e"), fake_cloud.uid(7, "bb")]])
        self.assertEqual(st["heal"]["status"], "ok")
        rec = res["recommendations"][0]
        self.assertIn("sudo podman exec nova_api nova-manage placement audit --verbose --delete", rec["commands"])
        self.assertIn("owner approval", rec["warning"])
        self.assertIsNone(rec.get("action"))

    def test_parsers(self):
        from wi_analysis.ovn_compute import parse_audit, parse_heal, sections
        self.assertEqual(parse_audit("Processed 0 allocations.\n@@rc 0"), (0, []))
        self.assertEqual(parse_heal("[dry-run] Update allocations for instance 11111111-0000-4000-8000-000000000001: {}\n"
                                    "Processed 1 instances.\n@@rc 4")[1], ["11111111-0000-4000-8000-000000000001"])
        self.assertEqual(sections("@@a x\nl1\n@@rc 3\n@@b\n")["rc:a"], 3)


class OvnDbClusterMemoryTest(unittest.TestCase):
    def test_neutron_rss_and_sb_memory(self):
        res, seen = run("ovn-db-cluster")
        st = steps(res)
        self.assertEqual(st["neutron"]["status"], "warn")   # 9 GiB on controller-0
        self.assertIn("9.0 GiB", st["neutron"]["detail"])
        self.assertIn("Most MAC_Binding rows: datapath", st["size"]["detail"])
        self.assertIn("ovsdb-server of the Southbound: cells:5212345", st["size"]["detail"])
        self.assertIn("MAC_Binding: 152,340 row(s); the biggest database file: 700 MB", st["size"]["detail"])


if __name__ == "__main__":
    unittest.main()

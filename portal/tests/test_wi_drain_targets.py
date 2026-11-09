"""Check compute-drain with several destinations named (comma separated), and the wi_ops.py side: the least used of the
named computes that fits, a live migration only to a compute with the CPU vendor of its source.

Run from the portal folder:
    .venv/bin/python -m unittest tests.test_wi_drain_targets -v
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
os.environ.pop("FAKE_CLOUD_STATE", None)

import fake_cloud  # noqa: E402
import wi_analysis  # noqa: E402
from wi_analysis import overcloud, wi_ops  # noqa: E402

CHECK = "compute-drain"


def run(params):
    ctx, data = {"site": "DCA"}, {}
    for phase in range(1, wi_analysis.plan(CHECK)["phases"] + 1):
        for src, items in wi_analysis.reads(CHECK, phase, data, params, ctx).items():
            for key, cmd in items.items():
                if src == "overcloud":
                    _node, ip, user, shown = overcloud.parse(cmd)
                    cmd = f"{overcloud.SSH} {user}@{ip} {shlex.quote(shown)}"
                fake_cloud.UNDERCLOUD = src == "undercloud"
                rc, out = fake_cloud.answer(cmd)
                data[key] = {"rc": rc, "out": out}
    return wi_analysis.analyze(CHECK, data, params, ctx)


class DrainTargetsTest(unittest.TestCase):
    def setUp(self):
        self.saved = fake_cloud.COMPUTE_SERVICES
        fake_cloud.COMPUTE_SERVICES = [x if x[1] != "compute-08" else ("nova-compute", "compute-08", "enabled", "up", 0)
                                       for x in self.saved]

    def tearDown(self):
        fake_cloud.COMPUTE_SERVICES = self.saved

    def test_several_destinations(self):
        from modules.wi import catalog
        c = catalog.get(CHECK)
        self.assertEqual(catalog.clean_params(c, {"compute": "compute-07", "target": "compute-09,compute-08"}, "DCA", {})[0]["target"],
                         "compute-09,compute-08")
        with self.assertRaises(ValueError):   # no spaces, nothing else than host names
            catalog.clean_params(c, {"compute": "compute-07", "target": "compute-09, compute-08"}, "DCA", {})
        res = run({"compute": "compute-07", "target": "compute-09,compute-08"})
        st = {s["key"]: s for s in res["steps"]}
        self.assertIn("Destinations: the least used of compute-09, compute-08 whose CPU and RAM stay under 70%", st["compute"]["detail"])
        live = next(r for r in res["recommendations"] if r.get("action") and r["action"]["label"] == "Live-migrate selected")
        cmd = live["action"]["select"]["items"][0]["commands"][0]
        self.assertIn(" to compute-09,compute-08 try - ", cmd)
        self.assertEqual(wi_analysis.openstack_fix_command(cmd), cmd)
        self.assertIn("least used of compute-09, compute-08 under 70%", live["action"]["select"]["items"][0]["label"])
        # a named destination that is down: nothing offered
        res = run({"compute": "compute-07", "target": "compute-09,compute-03"})
        st = {s["key"]: s for s in res["steps"]}
        self.assertEqual(st["target"]["status"], "fail")
        self.assertIn("compute-03 is enabled / down", st["target"]["detail"])

    def test_the_least_used_of_the_named_computes(self):
        total = 263731444
        use = {"192.168.253.28": (60, 50), "192.168.253.29": (20, 30), "192.168.253.30": (5, 10)}

        def runner(argv, timeout):
            ip = argv[-2].split("@")[1] if argv[0] == "ssh" else ""
            if ip in use:
                cpu, ram = use[ip]
                return 0, (f"cpu  1000 0 0 9000 0 0 0 0 0 0\nMemTotal: {total} kB\nMemAvailable: {total * (100 - ram) // 100} kB\n"
                           f"cpu  {1000 + cpu * 10} 0 0 {9000 + (100 - cpu) * 10} 0 0 0 0 0 0\nvendor_id\t: GenuineIntel")
            return 0, "vendor_id\t: GenuineIntel"
        log = []
        d = wi_ops.Director(runner=runner, write=log.append)
        a = wi_ops.parse(("live-migrate 5e5e5e5e-0000-4000-8000-000000000005 from compute-07 to compute-08,compute-09 try - "
                          "timeout 600 stall abort nodes compute-07=192.168.253.27,compute-08=192.168.253.28,compute-09=192.168.253.29,"
                          "compute-10=192.168.253.30 user heat-admin under 85 ram 4096").split())
        services = {h: ("enabled", "up") for h in ("compute-07", "compute-08", "compute-09", "compute-10")}
        # compute-10 is the least used of all, but not named: only compute-08 and compute-09 are measured
        self.assertEqual(wi_ops.destinations(d, a, "db-01", "compute-07", services), ["compute-09", "compute-08"])
        self.assertFalse(any("compute-10" in x for x in log))
        with self.assertRaises(ValueError):
            wi_ops.parse("live-migrate 5e5e5e5e-0000-4000-8000-000000000005 from compute-07 to compute-08;id try - timeout 600".split())

    def test_server_groups(self):
        """A real case: test-vm-21, the only member of an affinity server group, was refused on every
        destination (ServerGroupAffinityFilter, "No valid host was found") and the drain of iha-7 stopped there. Such an
        instance is not offered (it cannot move, why is said); one of an anti-affinity group, or of an affinity group with
        members elsewhere, carries its group so the migration reads where they run. Soft policies change nothing."""
        uid = fake_cloud.uid
        web, db, batch, legacy, far = uid(1, "5e"), uid(5, "5e"), uid(6, "5e"), uid(8, "5e"), uid(99, "5e")
        g_web, g_db, g_legacy, g_soft = uid(1, "6a"), uid(2, "6a"), uid(3, "6a"), uid(4, "6a")
        saved = fake_cloud.SERVER_GROUPS
        fake_cloud.SERVER_GROUPS = [
            {"ID": g_web, "Name": "test-server-group", "Policies": ["affinity"], "Members": [web], "Project Id": "p", "User Id": "u"},
            {"ID": g_db, "Name": "db-spread", "Policies": ["anti-affinity"], "Members": [db, far], "Project Id": "p", "User Id": "u"},
            {"ID": g_legacy, "Name": "legacy-pair", "Policy": "affinity", "Members": [legacy, far], "Project Id": "p", "User Id": "u"},
            {"ID": g_soft, "Name": "soft", "Policies": ["soft-affinity"], "Members": [batch], "Project Id": "p", "User Id": "u"}]
        try:
            res = run({"compute": "compute-07"})
        finally:
            fake_cloud.SERVER_GROUPS = saved
        live = next(r for r in res["recommendations"] if r.get("action") and r["action"]["label"] == "Live-migrate selected")
        cmds = {i["commands"][0].split()[1]: i["commands"][0] for i in live["action"]["select"]["items"]}
        self.assertNotIn(web, cmds)
        self.assertTrue(cmds[db].endswith(f" group {g_db}"), cmds[db])
        self.assertTrue(cmds[legacy].endswith(f" group {g_legacy}"), cmds[legacy])
        for c in cmds.values():
            self.assertEqual(wi_analysis.openstack_fix_command(c), c)
        cold = next(r for r in res["recommendations"] if r.get("action") and r["action"]["label"] == "Cold-migrate selected")
        self.assertNotIn(" group ", cold["action"]["select"]["items"][0]["commands"][0])   # soft-affinity: no rule
        stay = next(r for r in res["recommendations"] if "cannot be moved now" in r.get("title", r.get("text", "")) or
                    any(row[1] == web for row in (r.get("items") or {}).get("rows", [])))
        why = next(row[-1] for row in stay["items"]["rows"] if row[1] == web)
        self.assertEqual(why, "server group test-server-group (affinity): it is the only member; Nova accepts no compute but "
                              "compute-07 for it (No valid host on every other one). To move it, its owner deletes the group "
                              "(the instances keep running)")
        st = {s["key"]: s for s in res["steps"]}
        notes = {row[1]: row[-1] for row in st["instances"]["table"]["rows"]}
        self.assertIn("server group db-spread (anti-affinity): not to a compute of its 1 other member(s)", notes[db])
        self.assertIn("server group legacy-pair (affinity): only to the compute of its 1 member(s) elsewhere", notes[legacy])
        # the groups cannot be read: said, every instance offered as before
        fake_cloud.SERVER_GROUPS = None
        try:
            res = run({"compute": "compute-07"})
        finally:
            fake_cloud.SERVER_GROUPS = saved
        st = {s["key"]: s for s in res["steps"]}
        self.assertEqual(st["groups"]["status"], "warn")
        self.assertIn("The server groups could not be read (command failed (exit 1): Policy doesn't allow", st["groups"]["detail"])
        live = next(r for r in res["recommendations"] if r.get("action") and r["action"]["label"] == "Live-migrate selected")
        self.assertIn(web, [i["commands"][0].split()[1] for i in live["action"]["select"]["items"]])


class MigrationFailureTest(unittest.TestCase):
    """An instance that cannot be migrated is skipped and the run goes on (default "continue"), also one that needs a
    look; the run stops when the control plane fails (wi_ops exit 8) or after several in a row that need a look."""

    @staticmethod
    def item(rc, stops):
        return wi_analysis.item_result({"stdout": f"@@WI@@begin a1\nRESULT x: why\n@@WI@@end a1 {rc}"}, {"label": "web", "commands": ["x"]},
                                       0, stops)

    def test_continue_is_the_default_and_skips(self):
        res = run({"compute": "compute-07"})
        live = next(r for r in res["recommendations"] if r.get("action") and r["action"]["label"] == "Live-migrate selected")
        self.assertEqual(live["action"]["select"]["stop"], [])                    # nothing that only hurts this instance stops
        self.assertIn("An instance that cannot be migrated is skipped", live["text"] if "text" in live else str(live))
        res = run({"compute": "compute-07", "on_failure": "stop"})
        live = next(r for r in res["recommendations"] if r.get("action") and r["action"]["label"] == "Live-migrate selected")
        self.assertEqual(live["action"]["select"]["stop"], [5, 6])

    def test_which_results_stop_the_run(self):
        skip = []
        self.assertEqual((self.item(5, skip)["status"], self.item(5, skip)["stop"]), ("failed", False))
        self.assertEqual((self.item(6, skip)["status"], self.item(6, skip)["stop"]), ("attention", False))
        self.assertTrue(self.item(8, skip)["stop"])                  # the control plane fails: the next ones would too
        self.assertTrue(self.item(6, [6])["stop"])                   # other fixes: a person must look first (unchanged)
        self.assertTrue(self.item(5, [5, 6])["stop"])                # "stop at the first failure"
        look, ok = {"status": "attention", "stop": False}, {"status": "ok", "stop": False}
        self.assertFalse(wi_analysis.stop_next([look, look]))
        self.assertTrue(wi_analysis.stop_next([look, look, look]))   # three in a row: a wider problem
        self.assertFalse(wi_analysis.stop_next([look, look, ok, look]))

    def test_control_plane_failure_exits_8(self):
        saved = dict(wi_ops.OPS)

        def failing(d, a):
            raise wi_ops.Done(wi_ops.ATTENTION, f"the live migration was not started. {wi_ops.CONTROL_HINT}")

        def only_this(d, a):
            raise wi_ops.Done(wi_ops.ATTENTION, "web-01 is left in ERROR")
        said = []

        class Director:
            def say(self, text):
                said.append(text)

            def timing(self):
                return ""
        try:
            wi_ops.OPS["console-test"] = failing
            self.assertEqual(wi_ops.main(["console-test", "5e5e5e5e-0000-4000-8000-000000000001", "instance", "instance-0000002a"],
                                         Director()), 8)
            wi_ops.OPS["console-test"] = only_this
            self.assertEqual(wi_ops.main(["console-test", "5e5e5e5e-0000-4000-8000-000000000001", "instance", "instance-0000002a"],
                                         Director()), 6)
        finally:
            wi_ops.OPS.clear()
            wi_ops.OPS.update(saved)
        self.assertTrue(said[0].startswith("RESULT attention: "))


if __name__ == "__main__":
    unittest.main()

"""Check controller-reboot-readiness against the fake cloud: Pacemaker, Galera, clustercheck, Elastic Endpoint and the
kernel of the controllers, the verdict and the safe order.

Run from the portal folder:
    .venv/bin/python -m unittest tests.test_wi_reboot_readiness -v
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
from wi_analysis import overcloud, reboot_readiness  # noqa: E402

CHECK = "controller-reboot-readiness"


def run(params=None):
    ctx, data = {"site": "DCA"}, {}
    for phase in range(1, wi_analysis.plan(CHECK)["phases"] + 1):
        for src, items in wi_analysis.reads(CHECK, phase, data, params or {}, ctx).items():
            for key, cmd in items.items():
                if src == "overcloud":
                    _node, ip, user, shown = overcloud.parse(cmd)
                    cmd = f"{overcloud.SSH} {user}@{ip} {shlex.quote(shown)}"
                fake_cloud.UNDERCLOUD = src == "undercloud"
                rc, out = fake_cloud.answer(cmd)
                data[key] = {"rc": rc, "out": out}
    return wi_analysis.analyze(CHECK, data, params or {}, ctx)


class RebootReadinessTest(unittest.TestCase):
    def test_not_ready_while_resources_fail(self):
        res = run()
        st = {s["key"]: s for s in res["steps"]}
        self.assertEqual(st["nodes"]["status"], "ok")
        self.assertEqual(st["resources"]["status"], "fail")              # the fake cluster has failed resources
        self.assertEqual(st["galera"]["status"], "ok")
        self.assertEqual(st["clustercheck"]["status"], "ok")
        self.assertEqual(st["elastic"]["status"], "warn")
        self.assertIn("overcloud-controller-1", st["elastic"]["detail"])
        self.assertIn("Socat Reverse Shell", st["elastic"]["detail"])
        self.assertIn("overcloud-controller-0", st["kernel"]["detail"])     # a newer kernel starts there
        self.assertEqual(res["status"], "fail")
        texts = " ".join(r["text"] for r in res["recommendations"])
        self.assertIn("Do not reboot a controller now", texts)
        self.assertNotIn("Ready: reboot the controllers", texts)

    def test_ready_gives_the_order(self):
        clean = reboot_readiness.parse_pcs

        def healthy(text):
            v = clean(text)
            v.update(failed_actions=[], standby=[], offline=[], unclean=[])
            v["resources"] = [r for r in v["resources"] if reboot_readiness.resource_status(r)[0] == "ok"]
            return v
        reboot_readiness.parse_pcs = healthy
        try:
            res = run()
        finally:
            reboot_readiness.parse_pcs = clean
        st = {s["key"]: s for s in res["steps"]}
        self.assertEqual((st["cluster"]["status"], st["resources"]["status"]), ("ok", "ok"))
        ready = next(r for r in res["recommendations"] if r["text"].startswith("Ready: reboot the controllers"))
        cmds = ready["commands"]
        self.assertEqual(cmds.count("sudo reboot"), 3)                   # every controller, one after the other
        self.assertLess(cmds.index("# overcloud-controller-0: from the director, ssh heat-admin@<ctlplane of overcloud-controller-0>"),
                        cmds.index("# overcloud-controller-1: from the director, ssh heat-admin@<ctlplane of overcloud-controller-1>"))
        self.assertTrue(any("Elastic Endpoint must not stop clustercheck" in r["text"] for r in res["recommendations"]))

    def test_parsers(self):
        e = reboot_readiness.parse_elastic("unit elastic-agent  \nunit ElasticEndpoint  inactive\nopt-elastic absent")
        self.assertEqual((e["package"], e["units"]["ElasticEndpoint"], e["opt"]), ("", ("-", "inactive"), False))
        c = reboot_readiness.parse_clustercheck("container clustercheck|Up 2 days\nlisten 172.28.129.10:9200\nhttp 503")
        self.assertEqual((c["http"], c["listen"]), ("503", "172.28.129.10:9200"))
        k = reboot_readiness.parse_kernel("5.14.0-1.x86_64\nkernel-5.14.0-2.x86_64   Tue 03 Nov 2026\nneeds-restarting 1\nup since 2026-10-01 10:00:00")
        self.assertEqual((k["running"], k["newest"], k["reboot_needed"]), ("5.14.0-1.x86_64", "5.14.0-2.x86_64", True))


if __name__ == "__main__":
    unittest.main()

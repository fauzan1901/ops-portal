"""Check lun-map-audit (NetApp LUN mappings of the computes against Cinder): its reads answered by the fake director and
the fake ONTAP of tests/fake_cloud.py (an SVM where an instance runs on a FlexClone copy of its LUN after a live
migration, a real case), its read-only guard, the pages of an ONTAP list, and its rating of each section.

Run from the portal folder:
    .venv/bin/python -m unittest tests.test_wi_lun_maps -v
"""
import json
import os
import shlex
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "modules", "wi"))
os.environ.pop("FAKE_CLOUD_STATE", None)   # the fixed cloud only: this check changes nothing

import fake_cloud  # noqa: E402
import wi_analysis  # noqa: E402
from wi_analysis import overcloud  # noqa: E402

CHECK = "lun-map-audit"
V = fake_cloud.LM_V


def item(src, rc, out):
    """A read as the playbook records it: a REST answer as {"status", "json"}, a command as {"rc", "out"}."""
    if src != "ontap":
        return {"rc": rc, "out": out}
    return {"status": 200, "json": json.loads(out)} if rc == 0 else {"status": 404, "msg": out}


def run(ctx=None):
    """The check as the playbook runs it: every phase planned on what was read before, the next pages of the ONTAP lists
    read and merged after each phase, every read answered by the fake director or the fake ONTAP."""
    ctx, data, seen = ctx or {"site": "DCA"}, {}, []
    for phase in range(1, wi_analysis.plan(CHECK)["phases"] + 1):
        reads = wi_analysis.reads(CHECK, phase, data, {}, ctx)
        for src, items in reads.items():
            for key, cmd in items.items():
                shown = cmd
                if src == "overcloud":
                    _node, ip, user, shown = overcloud.parse(cmd)
                    cmd = f"{overcloud.SSH} {user}@{ip} {shlex.quote(shown)}"
                fake_cloud.UNDERCLOUD = src == "undercloud"
                data[key] = item(src, *fake_cloud.answer(cmd))
                seen.append((src, key, shown))
        for _round in range(9):
            pages = wi_analysis.next_pages(data, reads)
            if not any(pages.values()):
                break
            for src, items in pages.items():
                for key, path in items.items():
                    data[key] = item(src, *fake_cloud.answer(path))
                    seen.append((src, key, path))
        data = wi_analysis.merge_pages(data, reads)
    return wi_analysis.analyze(CHECK, data, {}, ctx), seen


def steps(result):
    return {s["key"]: s for s in result["steps"]}


def rows(step):
    return step.get("table", {}).get("rows") or []


class LunMapAuditTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        now = 1790856000   # 2026-10-01 12:00 UTC: the live migration of the volume "clone" was 11 h before
        cls.res, cls.seen = run({"site": "DCA", "now": now})
        cls.st = steps(cls.res)

    def test_catalog_and_registry(self):
        from modules.wi import catalog
        c = catalog.get(CHECK)
        self.assertEqual((c["status"], c["fix"], c["basis"], c["needs"]), ("ready", False, "platform", ["openstack", "ontap"]))
        self.assertIn(CHECK, wi_analysis.CHECKS)
        self.assertEqual(c["steps"], [s["title"] for s in self.res["steps"]])
        self.assertEqual(self.res["recommendations"], [])   # findings only: the owner decides

    def test_reads_are_read_only(self):
        """NetApp: GET of lists of the SVM Cinder uses (values encoded) and of single LUNs by UUID, never a search by serial;
        the database read selects only fields of connection_info (it holds the CHAP secret); the node read takes no
        argument."""
        self.assertEqual({s for s, _k, _c in self.seen}, {"openstack", "undercloud", "overcloud", "ontap"})
        for _s, _k, path in [x for x in self.seen if x[0] == "ontap"]:
            self.assertRegex(path, r"^/api/(storage/(luns|volumes)|storage/luns/[0-9a-f-]{36}|protocols/san/(igroups|lun-maps|iscsi/services))"
                                   r"\?[A-Za-z0-9_.,=&|%-]+$")
            self.assertNotIn("serial_number=", path)
        lists = [p for s, k, p in self.seen if s == "ontap" and k.startswith("na_maps_")]
        self.assertEqual(lists, ["/api/protocols/san/lun-maps?svm.name=SVM1&fields=lun.name,lun.uuid,logical_unit_number,igroup.name,"
                                 "svm.name&return_timeout=45"])   # only the SVM whose target the attachments use
        db = next(c for s, k, c in self.seen if k == "db")
        self.assertIn("JSON_VALUE(a.connection_info,'$.target_lun')", db)
        self.assertNotRegex(db, r"SELECT[^;]*[ ,(]connection_info[ ,)]")
        for word in ("UPDATE ", "DELETE ", "INSERT ", "auth_password"):
            self.assertNotIn(word, db.upper() if word.endswith(" ") else db)
        node = next(c for s, k, c in self.seen if k == "lmn_overcloud-novacompute-7")
        self.assertNotRegex(node, r"echo [0-9]+ >|/delete|rescan|multipath -f|iscsiadm")
        with self.assertRaises(ValueError):
            overcloud.parse("overcloud-novacompute-7|192.168.253.27|heat-admin|lm_node:1")

    def test_ontap_list_pages_are_merged(self):
        self.assertIn(("ontap", "na_luns_0:p2"), [(s, k) for s, k, _p in self.seen])
        self.assertIn("10 LUN(s)", self.st["sources"]["detail"])   # 5 + 5 of two pages

    def test_instance_on_a_flexclone_copy(self):
        s = self.st["clone_copies"]
        self.assertEqual(s["status"], "fail")
        (row,) = rows(s)
        self.assertEqual(row[0], V["clone"])
        self.assertIn(fake_cloud.LM_CLONE, row[6])
        self.assertIn("hourly.2025-06-24_0905", row[7])
        self.assertEqual((row[9][:14], row[10], row[11]), ("live migration", "after", "the COPY"))
        self.assertEqual(row[12], "novacompute-9 LUN 185")   # the original stays mapped to the source
        self.assertIn("novacompute-9 LUN 185", row[13])
        self.assertIn("novacompute-9 -> novacompute-7", row[14])
        self.assertIn("live migration 1", s["detail"])
        self.assertIn("1 of them attached in the last 24 hours, coming from: novacompute-9 1", s["detail"])
        later = wi_analysis.analyze(CHECK, {}, {}, {"site": "DCA"})   # no data: nothing compared, no error
        self.assertEqual(later["steps"][0]["status"], "fail")

    def test_mappings_without_attachment(self):
        s = self.st["orphans"]
        self.assertEqual(s["status"], "warn")
        got = {(r[0], r[1]): r[4] for r in rows(s)}
        self.assertEqual(got[("novacompute-7", 60)], "IN USE on novacompute-9")
        self.assertTrue(got[("novacompute-7", 61)].startswith("no live volume"))
        self.assertEqual(got[("novacompute-9", 185)], "IN USE on novacompute-7")
        self.assertNotIn(("novacompute-7", 28), got)   # the copy in use is section clone_copies, not an orphan

    def test_attachment_number_maps_another_lun(self):
        s = self.st["mismatch"]
        self.assertEqual(s["status"], "fail")
        got = {r[1]: r for r in rows(s)}
        self.assertEqual(got[40][2], V["wrong"])
        self.assertIn(f"volume-{V['other']}", got[40][4])
        self.assertEqual(got[50][4], "nothing")

    def test_devices_not_mapped(self):
        s = self.st["devices"]
        self.assertEqual(s["status"], "fail")   # LUN 70 on compute-7 is used by a running domain
        (row,) = rows(s)
        self.assertEqual((row[0], row[1]), ("novacompute-7", 70))
        self.assertIn("used by", row[2])

    def test_duplicates_and_igroups(self):
        s = self.st["duplicates"]
        self.assertEqual(s["status"], "warn")
        kinds = {r[0]: r[1] for r in rows(s)}
        self.assertEqual(kinds[fake_cloud.LM_CLONE], "FlexClone")
        self.assertEqual(kinds[fake_cloud.LM_P15], "Cinder pool")
        p = self.st["pools"]
        self.assertEqual(p["status"], "warn")
        self.assertIn("openstack-dead", p["detail"])
        self.assertIn("novacompute-3", p["detail"])   # not reached: no igroup can be named for it
        self.assertIn("novacompute-3", self.st["sources"]["detail"])

    def test_without_netapp(self):
        """Without the ONTAP account nothing is compared, and the step says why."""
        data = {}
        for phase in range(1, 5):
            for src, items in wi_analysis.reads(CHECK, phase, data, {}, {"site": "DCA"}).items():
                for key, cmd in items.items():
                    if src == "ontap":
                        data[key] = {"skipped": "no ONTAP account for this site"}
                        continue
                    if src == "overcloud":
                        _n, ip, user, shown = overcloud.parse(cmd)
                        cmd = f"{overcloud.SSH} {user}@{ip} {shlex.quote(shown)}"
                    fake_cloud.UNDERCLOUD = src == "undercloud"
                    data[key] = item(src, *fake_cloud.answer(cmd))
        res = wi_analysis.analyze(CHECK, data, {}, {"site": "DCA"})
        self.assertEqual([(s["key"], s["status"]) for s in res["steps"]], [("sources", "fail")])
        self.assertIn("NetApp was not read", res["steps"][0]["detail"])


if __name__ == "__main__":
    unittest.main()

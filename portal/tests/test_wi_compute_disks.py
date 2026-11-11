"""Check compute-disks (VM disks on a compute: lost paths, I/O errors, leftover directories): its reads answered by the
fake director (tests/fake_cloud.py), its read-only guard, its rating of a healthy compute and of the state the rollback of
a refused live migration left in production, its two fixes, and the wi_ops.py operations they run (rescan-luns,
move-leftover).

Run from the portal folder:
    .venv/bin/python -m unittest tests.test_wi_compute_disks -v
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
os.environ.pop("FAKE_CLOUD_STATE", None)   # the fixed cloud only: the check changes nothing

import fake_cloud  # noqa: E402
import wi_analysis  # noqa: E402
from wi_analysis import overcloud, wi_ops  # noqa: E402

CHECK = "compute-disks"
DB01, GPU06, LEGACY08 = fake_cloud.uid(5, "5e"), fake_cloud.uid(7, "5e"), fake_cloud.uid(8, "5e")
NODE7 = "node overcloud-novacompute-7=192.168.253.27 user heat-admin"


def run(params, ctx=None):
    """The check as the playbook runs it: every phase planned on what was read before, every read answered by the fake
    director (an overcloud read as the director runs it: ssh <user>@<ctlplane address> '<command>')."""
    ctx, data, seen = ctx or {"site": "DCC"}, {}, []
    for phase in range(1, wi_analysis.plan(CHECK)["phases"] + 1):
        for src, items in wi_analysis.reads(CHECK, phase, data, params, ctx).items():
            for key, cmd in items.items():
                shown = cmd
                if src == "overcloud":
                    _node, ip, user, shown = overcloud.parse(cmd)
                    cmd = f"{overcloud.SSH} {user}@{ip} {shlex.quote(shown)}"
                fake_cloud.UNDERCLOUD = src == "undercloud"
                rc, out = fake_cloud.answer(cmd)
                data[key] = {"rc": rc, "out": out}
                seen.append((src, key, shown))
    return wi_analysis.analyze(CHECK, data, params, ctx), seen


def steps(result):
    return {s["key"]: s for s in result["steps"]}


class ComputeDisksCheckTest(unittest.TestCase):
    def test_catalog_and_registry(self):
        from modules.wi import catalog
        c = catalog.get(CHECK)
        self.assertEqual((c["status"], c["activity"], c["fix"], c["basis"]), ("ready", "troubleshoot", True, "platform"))
        self.assertIn(CHECK, wi_analysis.CHECKS)
        self.assertIn(CHECK, next(s["checks"] for s in catalog.CATALOG["symptoms"] if s["id"] == "stuck"))
        with self.assertRaises(ValueError):   # the compute is a host name, nothing else reaches a command
            catalog.clean_params(c, {"compute": "x; reboot"}, "DCC", {})
        with self.assertRaises(ValueError):
            catalog.clean_params(c, {"compute": "compute-07", "hours": "500"}, "DCC", {})

    def test_reads_are_read_only(self):
        """The OpenStack reads pass the read-only allowlist; the overcloud read is a fixed command with a validated number
        of hours; nothing is read without a valid compute."""
        _res, seen = run({"compute": "compute-07", "hours": 24})
        self.assertEqual({s for s, _k, _c in seen}, {"openstack", "undercloud", "overcloud"})
        for src, _k, cmd in seen:
            if src == "openstack":
                wi_analysis.assert_openstack_read(cmd)
        disks = next(c for s, k, c in seen if k == "disks")
        self.assertIn("journalctl -k --since '-24h' --no-pager -o short-iso", disks)
        self.assertIn("@@kstat", disks)   # the totals of the whole window, not only of the 400 lines shown
        for word in (" mv ", "rm ", "/scan", "delete", "> /sys"):
            self.assertNotIn(word, disks)
        for bad in ("cd_disks:500", "cd_disks:0", "cd_disks:24;id", "cd_disks"):
            with self.assertRaises(ValueError):
                overcloud.parse(f"overcloud-novacompute-7|192.168.253.27|heat-admin|{bad}")
        self.assertEqual(wi_analysis.reads(CHECK, 1, {}, {"compute": "x'; reboot"}, {}), {s: {} for s in wi_analysis.SOURCES})
        # only the directories without a domain, and not of an instance Nova lists on the compute, are looked up in Nova
        shown = sorted(k for s, k, _c in seen if k.startswith("srv_"))
        self.assertEqual(shown, sorted([f"srv_{fake_cloud.CD_LEFT}", f"srv_{fake_cloud.CD_GONE}"]))

    def test_healthy_compute(self):
        res, _seen = run({"compute": "compute-09", "hours": 24})
        st = steps(res)
        self.assertEqual(res["status"], "ok", [(s["key"], s["status"], s["detail"]) for s in res["steps"]])
        self.assertEqual({k: st[k]["status"] for k in ("compute", "nopath", "failed", "kernel", "leftover")},
                         dict.fromkeys(("compute", "nopath", "failed", "kernel", "leftover"), "ok"))
        self.assertIn("1 running domain(s), 1 multipath map(s)", st["compute"]["detail"])
        self.assertEqual(res["recommendations"], [])

    def test_state_left_by_a_rollback(self):
        """compute-07 as compute-0 of DCC after the rollback of a refused live migration: db-01's disk without any path
        (the kernel removed 11:0:0:7 and 12:0:0:7, write I/O errors on dm-7), a failed path on legacy-08's disk, and three
        directories without a domain."""
        res, _seen = run({"compute": "compute-07", "hours": 24})
        st = steps(res)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(st["nopath"]["status"], "fail")
        self.assertIn("CRITICAL: 1 disk(s) of running VMs have no path at all", st["nopath"]["detail"])
        self.assertEqual(st["nopath"]["table"]["rows"], [["db-01", DB01, fake_cloud.OTHER, "vda", "dm-7", fake_cloud.cd_wwid(7)]])
        self.assertEqual(st["failed"]["status"], "warn")
        self.assertEqual(st["failed"]["table"]["rows"][0][2:], ["dm-9", fake_cloud.cd_wwid(9), 2, 1])
        self.assertEqual(st["kernel"]["status"], "fail")
        self.assertIn("2 I/O error line(s), 2 SCSI device(s) removed", st["kernel"]["detail"])
        self.assertIn("dm-7 (2x, db-01 (instance-00000005))", st["kernel"]["detail"])
        self.assertIn("compare the WWID before acting", st["kernel"]["detail"])
        self.assertEqual(st["leftover"]["status"], "fail")
        verdicts = {row[0]: row[4] for row in st["leftover"]["table"]["rows"]}
        self.assertEqual(verdicts, {fake_cloud.CD_LEFT: "SAFE", fake_cloud.CD_GONE: "SAFE",
                                    GPU06: "Nova has it HERE without a domain: check it"})
        self.assertIn("compute-09 (ACTIVE, task -)", next(r[2] for r in st["leftover"]["table"]["rows"] if r[0] == fake_cloud.CD_LEFT))
        self.assertEqual(next(r[2] for r in st["leftover"]["table"]["rows"] if r[0] == fake_cloud.CD_GONE), "deleted")
        # the fixes: the lost LUN scanned again (its removed addresses, its WWID), the two SAFE directories moved aside
        acts = [r for r in res["recommendations"] if r.get("action")]
        self.assertEqual(len(acts), 2)
        scan = acts[0]["action"]["select"]["items"]
        self.assertEqual(scan[0]["commands"], [f"rescan-luns {fake_cloud.cd_wwid(7)} addrs 11:0:0:7,12:0:0:7 keep "
                                               f"{fake_cloud.cd_wwid(7)} {NODE7}"])
        self.assertEqual(acts[0]["action"]["select"]["lock"], "compute-disks")
        moves = [i["commands"][0] for i in acts[1]["action"]["select"]["items"]]
        self.assertEqual(sorted(moves), sorted(f"move-leftover {u} {NODE7}" for u in (fake_cloud.CD_LEFT, fake_cloud.CD_GONE)))
        self.assertFalse(any(GPU06 in c for c in moves))   # Nova has it here: never offered
        for c in [i["commands"][0] for a in acts for i in a["action"]["select"]["items"]]:
            self.assertEqual(wi_analysis.openstack_fix_command(c), c)
        self.assertTrue(any("Volume connections of an instance" in r["text"] for r in res["recommendations"]))
        self.assertTrue(any("Knowledge Base" in r["text"] for r in res["recommendations"]))

    def test_no_removed_address_in_the_window(self):
        """A disk without any path but no removed SCSI address in the kernel window: shown, its scan item disabled."""
        saved = fake_cloud.CD_NODES["overcloud-novacompute-7"]["kernel"]
        fake_cloud.CD_NODES["overcloud-novacompute-7"]["kernel"] = []
        try:
            res, _seen = run({"compute": "compute-07", "hours": 1})
        finally:
            fake_cloud.CD_NODES["overcloud-novacompute-7"]["kernel"] = saved
        st = steps(res)
        self.assertEqual(st["nopath"]["status"], "fail")
        self.assertIn("No removed SCSI device is in the kernel log of the last 1 h", st["nopath"]["detail"])
        item = next(r for r in res["recommendations"] if r.get("action") and "LUN" in r["action"]["label"])["action"]["select"]["items"][0]
        self.assertEqual((item["commands"], item["disabled"]), ([], "no removed SCSI address in the kernel log of the last 1 h"))

    def test_nova_keeps_fqdn_host_names(self):
        """DCA keeps FQDNs: compute-07 given by its short name is listed as compute-07.example.net, its
        instances are listed and named by that name; when no nova-compute host matches, the directory of an instance Nova
        has here is still never offered (its server show names this compute)."""
        fqdn = "compute-07.example.net"
        saved_srv, saved_svc = dict(fake_cloud.SERVERS), list(fake_cloud.COMPUTE_SERVICES)
        try:
            for sid, s in list(fake_cloud.SERVERS.items()):
                if s[3] == "compute-07":
                    fake_cloud.SERVERS[sid] = s[:3] + (fqdn,) + s[4:]
            fake_cloud.COMPUTE_SERVICES[:] = [(b, fqdn if h == "compute-07" else h, st, state, m) for b, h, st, state, m in saved_svc]
            res, seen = run({"compute": "compute-07", "hours": 24})
            st = steps(res)
            self.assertIn(f"--host {fqdn} ", next(c for s, k, c in seen if k == "servers"))
            self.assertEqual(st["compute"]["status"], "ok")
            self.assertIn(f"instance(s) on {fqdn} (Nova's name of compute-07).", st["compute"]["detail"])
            self.assertIn("dm-7 (2x, db-01 (instance-00000005))", st["kernel"]["detail"])
            self.assertEqual({row[0]: row[4] for row in st["leftover"]["table"]["rows"]}[GPU06], "Nova has it HERE without a domain: check it")

            fake_cloud.COMPUTE_SERVICES[:] = [x for x in fake_cloud.COMPUTE_SERVICES if x[1] != fqdn]
            res, seen = run({"compute": "compute-07", "hours": 24})
            st = steps(res)
            self.assertEqual(st["compute"]["status"], "warn")
            self.assertIn("Nova lists 0 instance(s) on compute-07. compute-07 is not a nova-compute host", st["compute"]["detail"])
            self.assertIn(f"srv_{GPU06}", [k for _s, k, _c in seen])
            self.assertEqual({row[0]: row[4] for row in st["leftover"]["table"]["rows"]}[GPU06], "Nova has it HERE without a domain: check it")
            self.assertEqual(st["leftover"]["status"], "fail")
            offered = [c for r in res["recommendations"] if r.get("action") for i in r["action"]["select"]["items"] for c in i["commands"]]
            self.assertFalse(any(GPU06 in c for c in offered))
            self.assertTrue(any(fake_cloud.CD_LEFT in c for c in offered))
        finally:
            fake_cloud.SERVERS.clear()
            fake_cloud.SERVERS.update(saved_srv)
            fake_cloud.COMPUTE_SERVICES[:] = saved_svc

    def kstat_node(self, qemu_started):
        """compute-09 with the whole-window totals of the read (@@kstat): 2869 I/O errors on dm-3 until 15:23:37 of which
        the last 3 lines are shown, one SCSI address removed, its domain's QEMU started at <qemu_started>."""
        now = "2026-10-31T16:17:57+0700"
        lines = [f"2026-10-31T15:23:3{i}+0700 overcloud-novacompute-9 kernel: I/O error, dev dm-3, sector 9210320 op 0x0:(READ) flags 0x0"
                 for i in (5, 6, 7)]
        from wi_analysis.compute_disks import epoch
        return lines + ["@@kstat", "@@io dm-3 2869 2026-10-30T16:20:01+0700 2026-10-31T15:23:37+0700", "@@removed 13:0:0:46",
                        f"@@now {int(epoch(now))}", f"@@qemu instance-00000021 {int(epoch(now) - epoch(qemu_started))}"]

    def test_errors_of_an_earlier_disk_with_the_same_number(self):
        """A real case: a flushed map gave dm-23 I/O errors until 15:23, vm-004 came at 15:31 and its disk got
        dm-23. Errors that ended before the QEMU of every domain on that dm started are another disk's (warn, the VM not
        named as hit); the counts are those of the whole window, not of the lines shown."""
        node = fake_cloud.CD_NODES["overcloud-novacompute-9"]
        saved = node["kernel"]
        try:
            node["kernel"] = self.kstat_node("2026-10-31T15:31:41+0700")
            res, _seen = run({"compute": "compute-09", "hours": 24})
            st = steps(res)["kernel"]
            self.assertEqual(st["status"], "warn")
            self.assertIn("2869 I/O error line(s), 1 SCSI device(s) removed.", st["detail"])
            self.assertIn("The 2869 I/O error(s) of dm-3 ended before instance-00000021 started on this compute (8 min later): "
                          "they were another disk's that had the number dm-3 then", st["detail"])
            self.assertNotIn("I/O errors on disks of running VMs", st["detail"])
            self.assertEqual(st["evidence"].count("I/O error"), 3)

            node["kernel"] = self.kstat_node("2026-10-31T09:00:00+0700")   # its QEMU ran during the errors: its disk
            res, _seen = run({"compute": "compute-09", "hours": 24})
            st = steps(res)["kernel"]
            self.assertEqual(st["status"], "fail")
            self.assertIn("I/O errors on disks of running VMs: dm-3 (2869x, instance-00000021)", st["detail"])
            self.assertNotIn("ended before", st["detail"])
        finally:
            node["kernel"] = saved


class ComputeDisksOpsTest(unittest.TestCase):
    """wi_ops.py rescan-luns and move-leftover, with a fake director (the commands as they reach the compute)."""
    WWID, OTHER_WWID = "3600a09803831487a675d5549482d7531", "3600a0980383148000000000000000099"

    def director(self, answers):
        from wi_analysis import wi_ops as ops
        seen, log = [], []

        def runner(argv, timeout):
            cmd = " ".join(argv)
            seen.append(cmd)
            for key, value in answers:
                if key in cmd:
                    return value() if callable(value) else value
            return 0, "[]"
        return ops, ops.Director(runner=runner, clock=lambda: 1793125000, sleep=lambda x: None, write=log.append), seen, log

    def maps(self, paths):
        head = f"{self.WWID} dm-7 " + ("NETAPP,LUN C-Mode" if paths else "##,##")
        body = [f"| `- 11:0:0:7  sdlp  68:368  active ready running"] if paths else []
        return (0, "\n".join(["@@kernel", "@@maps", head, "size=100G features='2 pg_init_retries 50' hwhandler='0' wp=rw"] + body
                             + ["@@domains", "@@dom instance-00001b62 9b6e5f52-a030-40fb-b987-fe902aa01291", "@@disk /dev/dm-7"]))

    def test_rescan_luns(self):
        reads = [self.maps([]), self.maps(["x"])]
        line = (f"rescan-luns {self.WWID} addrs 11:0:0:7,12:0:0:7,13:0:0:7 keep {self.WWID},{self.OTHER_WWID} {NODE7}").split()
        ops, d, seen, log = self.director([
            ("@@kernel", lambda: reads.pop(0)),
            ("/scan", (0, f"@@kept 11:0:0:7 sdlp {self.WWID}\n@@deleted 12:0:0:7 sdlq 3600a0980383148000000000000000042\n"
                          "@@present 13:0:0:7"))])
        rc = ops.main(line, d)
        self.assertEqual(rc, ops.OK, log)
        self.assertIn("dm-7 (3600a09803831487a675d5549482d7531) on overcloud-novacompute-7 has no path; used by instance-00001b62 "
                      "(9b6e5f52-a030-40fb-b987-fe902aa01291)", log)
        self.assertIn(f"Automatic fix: 11:0:0:7 came back as sdlp (WWID {self.WWID}): kept, the disk of this map", log)
        self.assertTrue(any("12:0:0:7 came back as sdlq" in x and "deleted again" in x for x in log), log)
        self.assertTrue(log[-1].startswith("RESULT ok: dm-7 (3600a09803831487a675d5549482d7531) on overcloud-novacompute-7 has 1 path(s) again"))
        scan = next(c for c in seen if "/scan" in c)
        self.assertIn("@@present", scan)   # an address with a device now is never scanned
        self.assertIn(self.OTHER_WWID, scan)
        # still no path after the scan: attention; a map that has its paths already: nothing done
        reads[:] = [self.maps([]), self.maps([])]
        ops, d, seen, log = self.director([("@@kernel", lambda: reads.pop(0)), ("/scan", (0, "@@present 11:0:0:7"))])
        self.assertEqual(ops.main(line, d), ops.ATTENTION)
        self.assertIn("still has no path after the scan", log[-1])
        ops, d, seen, log = self.director([("@@kernel", self.maps(["x"]))])
        self.assertEqual(ops.main(line, d), ops.OK)
        self.assertIn("has 1 path(s) already", log[-1])
        self.assertFalse(any("/scan" in c for c in seen))
        with self.assertRaises(ValueError):
            ops.parse(f"rescan-luns {self.WWID} addrs 11:0:0:7;id keep {self.WWID} {NODE7}".split())

    def test_move_leftover(self):
        sid = fake_cloud.uid(40, "5e")
        line = f"move-leftover {sid} {NODE7}".split()

        def show(host, status="ACTIVE", task=None):
            return (0, json.dumps({"id": sid, "name": "db-left-01", "status": status, "OS-EXT-STS:task_state": task,
                                   "OS-EXT-SRV-ATTR:host": host}))

        def run_with(server, found):
            ops, d, seen, log = self.director([("server show", server), ("@@exists", found),
                                               (f"mv /var/lib/nova/instances/{sid} ", (0, "drwxr-xr-x. 2 x x 25 renamed"))])
            return ops, ops.main(line, d), seen, log
        ok = (0, "@@exists yes 2026-09-28 15:59:37\n@@fstype xfs\n@@domain no")
        ops, rc, seen, log = run_with(show("compute-09"), ok)
        self.assertEqual(rc, ops.OK, log)
        self.assertIn(f"renamed to /var/lib/nova/instances/{sid}.leftover-", log[-1])
        self.assertTrue(any(f"mv /var/lib/nova/instances/{sid} /var/lib/nova/instances/{sid}.leftover-" in c for c in seen))
        # a deleted instance: moved as well
        ops, rc, seen, log = run_with((1, f"No server with a name or ID of '{sid}' exists."), ok)
        self.assertEqual(rc, ops.OK, log)
        self.assertIn("deleted instance", log[-1])
        # never moved: a domain defined there, a shared filesystem, Nova has it on this compute, a migration of it runs
        for server, found, want, words in (
                (show("compute-09"), (0, "@@exists yes x\n@@fstype xfs\n@@domain yes"), ops.FAILED, "a domain of db-left-01 is defined"),
                (show("compute-09"), (0, "@@exists yes x\n@@fstype nfs4\n@@domain no"), ops.FAILED, "nfs4"),
                (show("overcloud-novacompute-7"), ok, ops.ATTENTION, "Nova has db-left-01 on overcloud-novacompute-7 itself"),
                (show("compute-09", "MIGRATING", "migrating"), ok, ops.FAILED, "a migration of it may use this directory")):
            ops, rc, seen, log = run_with(server, found)
            self.assertEqual(rc, want, log)
            self.assertIn(words, log[-1])
            self.assertFalse(any(" mv " in f" {c} " for c in seen), seen)
        # gone already: nothing to do
        ops, rc, seen, log = run_with(show("compute-09"), (0, "@@exists no\n@@fstype xfs\n@@domain no"))
        self.assertEqual(rc, ops.OK)
        self.assertIn("is no longer on overcloud-novacompute-7", log[-1])


if __name__ == "__main__":
    unittest.main()

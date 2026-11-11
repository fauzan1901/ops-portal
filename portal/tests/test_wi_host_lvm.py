"""Check host-lvm (guest LVs active on computes): its reads answered by the fake director (tests/fake_cloud.py), its
read-only guard, its rating of a compute with an LVM filter and of one without (the state of a real case), its fixes, and the wi_ops.py operations they run (release-lv, flush-map, delete-path).

Run from the portal folder:
    .venv/bin/python -m unittest tests.test_wi_host_lvm -v
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
os.environ.pop("FAKE_CLOUD_STATE", None)   # the fixed cloud only: the check changes nothing

import fake_cloud  # noqa: E402
import wi_analysis  # noqa: E402
from wi_analysis import overcloud, wi_ops  # noqa: E402

CHECK = "host-lvm"
DB01, GPU06, LEGACY08 = fake_cloud.uid(5, "5e"), fake_cloud.uid(7, "5e"), fake_cloud.uid(8, "5e")
NODE7 = "node overcloud-novacompute-7=192.168.253.27 user heat-admin"


def run(params, ctx=None):
    """The check as the playbook runs it: every phase planned on what was read before, every read answered by the fake
    director (an overcloud read as the director runs it: ssh <user>@<ctlplane address> '<command>')."""
    ctx, data, seen = ctx or {"site": "DCB"}, {}, []
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


class HostLvmCheckTest(unittest.TestCase):
    def test_catalog_and_registry(self):
        from modules.wi import catalog
        c = catalog.get(CHECK)
        self.assertEqual((c["status"], c["activity"], c["fix"], c["basis"]), ("ready", "troubleshoot", True, "platform"))
        self.assertIn(CHECK, wi_analysis.CHECKS)
        self.assertIn(CHECK, next(s["checks"] for s in catalog.CATALOG["symptoms"] if s["id"] == "stuck"))
        self.assertEqual(catalog.clean_params(c, {"compute": ""}, "DCB", {})[0], {})   # empty: every compute
        with self.assertRaises(ValueError):
            catalog.clean_params(c, {"compute": "x; reboot"}, "DCB", {})

    def test_reads_are_read_only(self):
        """One read per compute, all at once (parallel keys), a fixed command that changes nothing; one compute when one is
        named; nothing without a valid name."""
        _res, seen = run({"compute": ""})
        reads = [(k, c) for s, k, c in seen if s == "overcloud"]
        self.assertEqual(sorted(k for k, _c in reads), ["use_hl_0", "use_hl_1", "use_hl_2"])   # computes 3, 7 and 9
        for _k, cmd in reads:
            self.assertTrue(cmd.startswith("sudo -n sh -c "))
            for word in ("dmsetup remove", "multipath -f", "add path", "delete", "> /sys", " rm ", "vgchange", "lvchange"):
                self.assertNotIn(word, cmd)
        for src, _k, cmd in seen:
            if src == "openstack":
                wi_analysis.assert_openstack_read(cmd)
        _res, seen = run({"compute": "compute-07"})
        self.assertEqual([k for s, k, _c in seen if s == "overcloud"], ["use_hl_0"])
        self.assertIn("--host compute-07", next(c for s, k, c in seen if k == "servers"))
        with self.assertRaises(ValueError):
            overcloud.parse("overcloud-novacompute-7|192.168.253.27|heat-admin|hl_lvm:1")
        self.assertEqual(wi_analysis.reads(CHECK, 1, {}, {"compute": "x'; reboot"}, {}), {s: {} for s in wi_analysis.SOURCES})

    def test_a_compute_with_an_lvm_filter(self):
        res, _seen = run({"compute": "compute-09"})
        st = steps(res)
        self.assertEqual(res["status"], "ok", [(s["key"], s["status"], s["detail"]) for s in res["steps"]])
        self.assertEqual(st["computes"]["table"]["rows"][0][3:], ['["r|.*|"]', "1 absent", "yes", 0])
        self.assertEqual(res["recommendations"], [])

    def test_a_compute_without_an_lvm_filter(self):
        """compute-07 as az1-compute-2..5 of DCB: db-01 runs on a guest LV, legacy-08's map and gpu-06's one-path disk carry
        guest LVs, one LV and one map are left over, the host's own root LV is not a guest's."""
        res, _seen = run({"compute": ""})
        st = steps(res)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(st["computes"]["status"], "warn")
        self.assertIn("2 of 3 compute(s) read as heat-admin", st["computes"]["detail"])
        self.assertIn("The LVM of 1 compute(s) accepts guest volumes (overcloud-novacompute-7)", st["computes"]["detail"])
        rows = {r[0]: r for r in st["computes"]["table"]["rows"]}
        self.assertIn("No route to host", rows["overcloud-novacompute-3"][2])   # not reached: shown, not rated
        self.assertEqual(rows["overcloud-novacompute-7"][3:], ['["a|.*|"]', "1 absent", "NO", 4])
        self.assertEqual(st["no-path"]["status"], "fail")
        self.assertEqual(st["no-path"]["table"]["rows"], [["db-01 (instance-00000005)", DB01, "overcloud-novacompute-7", "vda", "dm-7",
                                                           fake_cloud.cd_wwid(7), "0 (none running)"]])
        self.assertEqual(st["runs-on"]["status"], "fail")
        self.assertEqual(st["runs-on"]["table"]["rows"], [["db-01 (instance-00000005)", DB01, "overcloud-novacompute-7", "vdb",
                                                           "dm-21 vg--db-lv--var", f"path sdm ({fake_cloud.cd_wwid(21)})"]])
        self.assertEqual(st["on-disks"]["status"], "warn")
        on = {r[3]: r for r in st["on-disks"]["table"]["rows"]}
        self.assertEqual(on["dm-20 vg_data-lv_data"][1:3], ["legacy-08 (instance-00000008)", "vda"])
        self.assertEqual(on["dm-22 vg_gpu-lv_scratch"][1:], ["gpu-06 (instance-00000007)", "vdb", "dm-22 vg_gpu-lv_scratch",
                                                             f"partition sdq1 of path sdq ({fake_cloud.cd_wwid(22)})"])
        self.assertEqual(st["one-path"]["table"]["rows"], [["overcloud-novacompute-7", "gpu-06 (instance-00000007)", "vdb", "sdq"]])
        self.assertEqual([r[1:3] for r in st["leftover"]["table"]["rows"]],
                         [["dm-23 vg_old-lv_old", "guest LV, nothing uses it"], ["dm-12", "multipath map without a running path"],
                          ["sdez", "iSCSI path device in no map (17:0:0:12, running, read failed)"],
                          ["sdfa", "iSCSI path device in no map (18:0:0:12, running, read failed)"],
                          # sdhh answers a read: a LUN still mapped there (DCA ha-0 LUN 58, fix #118), never a dead path
                          ["sdhh", "working iSCSI device in no map, LUN still mapped here (19:0:0:58, running)"]])
        # sdq: gpu-06's disk, never offered
        self.assertNotIn("rhel-root", str(res))
        # the fixes: the three LVs a running domain does not use as its disk released, the leftover map flushed
        acts = [r for r in res["recommendations"] if r.get("action")]
        self.assertEqual(len(acts), 4)
        rescan = [i["commands"][0] for i in acts[0]["action"]["select"]["items"]]
        self.assertEqual(rescan, [f"rescan-disk {DB01} wwid {fake_cloud.cd_wwid(7)} {NODE7}"])
        release = [i["commands"][0] for i in acts[1]["action"]["select"]["items"]]
        self.assertEqual(release, [f"release-lv {fake_cloud.hl_uuid(n)} {NODE7}" for n in (20, 22, 23)])
        self.assertEqual(acts[1]["action"]["select"]["lock"], "host-lvm")
        self.assertEqual([i["commands"][0] for i in acts[2]["action"]["select"]["items"]],
                         [f"flush-map {fake_cloud.cd_wwid(12)} {NODE7}"])
        paths = [i["commands"][0] for i in acts[3]["action"]["select"]["items"]]
        self.assertEqual(paths, [f"delete-path sdez addr 17:0:0:12 wwid {fake_cloud.cd_wwid(30)} {NODE7}",
                                 f"delete-path sdfa addr 18:0:0:12 wwid {fake_cloud.cd_wwid(30)} {NODE7}"])
        self.assertEqual(acts[3]["action"]["select"]["lock"], "host-lvm")
        mapped = next(r for r in res["recommendations"] if r["text"].startswith("Find the volume of each LUN still mapped"))
        self.assertFalse(mapped.get("action"))   # nothing to run on the compute
        self.assertEqual(mapped["items"]["rows"], [["overcloud-novacompute-7", "sdhh", "19:0:0:58", "3600a098038314255672b4f6b4c333454"]])
        self.assertIn("lun show -serial-hex 38314255672b4f6b4c333454 -fields path,mapped   # ONTAP: the LUN of that WWID",
                      mapped["commands"])
        for c in rescan + release + [f"flush-map {fake_cloud.cd_wwid(12)} {NODE7}"] + paths:
            self.assertEqual(wi_analysis.openstack_fix_command(c), c)
        for bad in ("delete-path sda1 addr 1:0:0:1 wwid - " + NODE7, "delete-path sdez addr 1:0:0 wwid - " + NODE7,
                    "delete-path sdez;reboot addr 1:0:0:1 wwid - " + NODE7):
            with self.assertRaises(ValueError):
                wi_analysis.openstack_fix_command(bad)
        self.assertFalse(any(fake_cloud.hl_uuid(21) in c for c in release))   # under a running domain: never offered
        texts = " ".join(r["text"] for r in res["recommendations"])
        self.assertIn("Stop each VM that runs on a guest LV", texts)
        self.assertIn("Set an LVM filter on overcloud-novacompute-7", texts)
        self.assertIn("Move each VM with a disk on one SCSI path", texts)


    def test_raw_disk_vm_with_copy_warns(self):
        """The VM to move off a one-path disk has a volume whose LUN has a FlexClone copy: the move is checked first."""
        move = "Move each VM with a disk on one SCSI path"
        res, _seen = run({}, {"site": "DCB", "netapp": True})
        rec = next(r for r in res["recommendations"] if r["text"].startswith(move))
        self.assertIn("lun-map-audit", rec["warning"])
        self.assertIn(GPU06, rec["warning"])
        res, _seen = run({})
        rec = next(r for r in res["recommendations"] if r["text"].startswith(move))
        self.assertNotIn("lun-map-audit", rec.get("warning") or "")

class HostLvmOpsTest(unittest.TestCase):
    """wi_ops.py release-lv and flush-map, with a fake director (the commands as they reach the compute)."""
    LV = "LVM-" + "Gx7Q" * 8 + "0" * 30 + "20"
    WWID = "3600a098038314d716224575347624344"

    def director(self, answer):
        seen, log = [], []

        def runner(argv, timeout):
            seen.append(" ".join(argv))
            return answer
        return wi_ops.Director(runner=runner, clock=lambda: 1793125000, sleep=lambda x: None, write=log.append), seen, log

    def test_release_lv(self):
        line = f"release-lv {self.LV} {NODE7}".split()
        d, seen, log = self.director((0, "@@lv dm-168 vg_nfsprod_drc-lv_kube 0 -\n@@removed dm-168 vg_nfsprod_drc-lv_kube\n"
                                         "@@added sdli dm-167 3\n"))
        self.assertEqual(wi_ops.main(line, d), wi_ops.OK)
        self.assertIn("Automatic fix: path sdli given back to its map dm-167 (3 path(s) now)", log)
        self.assertTrue(log[-1].startswith("RESULT ok: dm-168 vg_nfsprod_drc-lv_kube released on overcloud-novacompute-7"))
        cmd = seen[-1]
        self.assertIn("192.168.253.27", cmd)
        self.assertIn(f"U={self.LV}", cmd)
        for want in ("dmsetup remove", "@@refused", "iscsi_host", "virsh -c qemu:///system list --name"):
            self.assertIn(want, cmd)
        for answer, rc, words in (
                ((0, "@@lv dm-21 vg--db-lv--var 1 -\n@@refused opened 1 time(s) on the host"), wi_ops.FAILED, "opened 1 time(s)"),
                ((0, "@@lv dm-21 x 0 -\n@@refused the disk of running domain(s) instance-00000005"), wi_ops.FAILED, "running domain"),
                ((0, "@@gone"), wi_ops.OK, "is no longer active"),
                ((0, "@@lv dm-20 x 0 -\n@@failed dmsetup remove x"), wi_ops.ATTENTION, "could not be released"),
                ((0, "@@lv dm-22 x 0 -\n@@removed dm-22 x\n@@left sdq 3600a"), wi_ops.OK, "sdq has no multipath map here")):
            d, seen, log = self.director(answer)
            self.assertEqual(wi_ops.main(line, d), rc, log)
            self.assertIn(words, log[-1])
        with self.assertRaises(ValueError):
            wi_ops.parse(f"release-lv LVM-x;id {NODE7}".split())

    def test_flush_map(self):
        line = f"flush-map {self.WWID} {NODE7}".split()
        d, seen, log = self.director((0, "@@map dm-53 0 - 0\n@@flushed dm-53"))
        self.assertEqual(wi_ops.main(line, d), wi_ops.OK)
        self.assertIn(f"the leftover map dm-53 ({self.WWID}) flushed on overcloud-novacompute-7", log[-1])
        self.assertIn(f"W={self.WWID}", seen[-1])
        self.assertIn('multipath -f "$n"', seen[-1])   # its device-mapper name, not the WWID
        # multipath no longer takes it for a multipath device (a real case): dmsetup remove of that unused map
        d, seen, log = self.director((0, "@@map dm-149 0 - 0\n@@flushed dm-149 dmsetup remove 3600a098038314774652b53757a733047 "
                                         "(multipath -f: 16357044.877272 | x is not a multipath device; table multipath)"))
        self.assertEqual(wi_ops.main(line, d), wi_ops.OK)
        self.assertIn("flushed on overcloud-novacompute-7 (dmsetup remove 3600a098038314774652b53757a733047", log[-1])
        for guard in ('-o open "$n"', "/holders", "/slaves", 'dmsetup remove "$n"'):
            self.assertIn(guard, seen[-1])
        for answer, rc, words in (((0, "@@map dm-61 0 - 2\n@@refused 2 path(s) of it still run"), wi_ops.FAILED, "2 path(s)"),
                                  ((0, "@@gone"), wi_ops.OK, "has no map"),
                                  ((0, "@@map dm-53 0 - 0\n@@failed map in use"), wi_ops.ATTENTION, "map in use")):
            d, seen, log = self.director(answer)
            self.assertEqual(wi_ops.main(line, d), rc, log)
            self.assertIn(words, log[-1])

    def test_delete_path(self):
        """A path device in no map (a real case, sdez): read again on the compute, deleted only when no read of it
        answers; refused when in use or working, nothing to do when gone or its name now has another address."""
        line = f"delete-path sdez addr 17:0:0:12 wwid {self.WWID} {NODE7}".split()
        d, seen, log = self.director((0, f"@@path sdez 17:0:0:12 running {self.WWID}\n@@read exit 1\n@@deleted sdez 17:0:0:12"))
        self.assertEqual(wi_ops.main(line, d), wi_ops.OK, log)
        self.assertIn("the dead path device sdez (17:0:0:12, read: exit 1) deleted on overcloud-novacompute-7", log[-1])
        cmd = seen[-1]
        self.assertIn(f"D=sdez; A=17:0:0:12; W={self.WWID}", cmd)
        for guard in ("iscsi_host", "/holders/", "-lname", "/proc/mounts", "virsh -c qemu:///system list --name", "sleep 20",
                      "iflag=direct", "@@refused it answers a read", "echo 1 > $x/device/delete", "pgrep -x multipathd",
                      "multipathd del path /dev/$D"):
            self.assertIn(guard, cmd)
        # the address and the WWID read again after the 20 s (a name can be taken by a new device), before the read test
        self.assertEqual(cmd.count('[ "$a" = "$A" ]'), 2)
        self.assertGreater(cmd.rindex('[ "$a" = "$A" ]'), cmd.index("sleep 20"))
        self.assertLess(cmd.index("multipathd del path"), cmd.index("echo 1 > $x/device/delete"))
        self.assertLess(cmd.index("iflag=direct"), cmd.index("echo 1 > $x/device/delete"))   # the read first
        for answer, rc, words in (
                ((0, "@@refused open by process(es) 480314"), wi_ops.FAILED, "open by process(es) 480314"),
                ((0, "@@path sdez 17:0:0:12 running -\n@@refused it answers a read of its first block: a working device, "
                     "not a dead path"), wi_ops.FAILED, "a working device"),
                ((0, "@@refused the disk of domain(s) instance-00013885"), wi_ops.FAILED, "instance-00013885"),
                ((0, "@@gone sdez is now 20:0:0:3"), wi_ops.OK, "is now 20:0:0:3"),
                ((0, "@@gone"), wi_ops.OK, "nothing to do"),
                ((0, "@@path sdez x\n@@read no answer in 20 s\n@@failed still there after echo 1 > device/delete"),
                 wi_ops.ATTENTION, "could not be deleted")):
            d, seen, log = self.director(answer)
            self.assertEqual(wi_ops.main(line, d), rc, log)
            self.assertIn(words, log[-1])
        with self.assertRaises(ValueError):
            wi_ops.parse(f"delete-path sdez addr 17:0:0:12 wwid x {NODE7}".split())
        self.assertEqual(wi_ops.parse(f"delete-path sdez addr 17:0:0:12 wwid - {NODE7}".split())["wwid"], "-")

    def test_rescan_disk(self):
        """A disk without any path (its removal may be older than the kernel log): Nova's LUN of it scanned on its target's
        sessions, only where no device is; a new device kept only with the map's WWID."""
        sid, wwid = DB01, "3600a09803831384c6f5d557349465474"
        iqn = "iqn.1992-08.com.netapp:sn.e52b37756ab211eb86fc00a0984ef240:vs.14"

        def lvs(running, total=None):
            total = running if total is None else total
            return (0, '@@filter ["r|.*|"]\n@@devicesfile 1 absent\n'
                       f"@@map dm-178 {wwid} 1 - {running} {total} {'sdhl,sdhm' if total else '-'}\n"
                       f"@@domains\n@@dom instance-00013c9f {sid}\n@@disk vda dm-178\n")

        def director(reads, bdm=f"@@bdm /dev/vda\tc83ab890-e3bf-4bd6-9a51-b2afe385298c\t{iqn}\t258",
                     scan=f"@@kept 17:0:0:258 sdhl {wwid}\n@@kept 18:0:0:258 sdhm {wwid}\n@@present 14:0:0:258"):
            seen, log, reads = [], [], list(reads)

            def runner(argv, timeout):
                cmd = " ".join(argv)
                seen.append(cmd)
                if "@@devicesfile" in cmd and "echo @@domains" in cmd:
                    return reads.pop(0) if len(reads) > 1 else reads[0]
                if "@@bdm" in cmd:
                    return 0, bdm
                if "iscsi_session" in cmd:
                    return 0, "@@host 14\n@@host 17\n@@host 18"
                if "/scan" in cmd:
                    return 0, scan
                if "tripleo-ansible-inventory" in cmd:
                    return 0, "Controller:\n  hosts:\n    overcloud-controller-0:\n      ansible_host: 192.168.253.10\n"
                return 0, ""
            return wi_ops.Director(runner=runner, clock=lambda: 1793125000, sleep=lambda x: None, write=log.append), seen, log

        line = f"rescan-disk {sid} wwid {wwid} {NODE7}".split()
        d, seen, log = director([lvs(0), lvs(2)])
        self.assertEqual(wi_ops.main(line, d), wi_ops.OK, log)
        self.assertIn(f"dm-178 ({wwid}) on overcloud-novacompute-7 has no path: vda of instance-00013c9f, volume "
                      f"c83ab890-e3bf-4bd6-9a51-b2afe385298c, Nova's LUN 258 of {iqn}", log)
        self.assertIn(f"Automatic fix: 17:0:0:258 came back as sdhl (WWID {wwid}): kept, the disk of this map", log)
        self.assertIn("has 2 path(s) again (vda of instance-00013c9f)", log[-1])
        scan = next(c for c in seen if "/scan" in c)
        for addr in ("14:0:0:258", "17:0:0:258", "18:0:0:258"):
            self.assertIn(addr, scan)
        self.assertIn("@@present", scan)   # an address with a device now is never scanned nor deleted
        self.assertTrue(any("192.168.253.10" in c and "@@bdm" in c for c in seen))   # Nova's LUN on a controller
        # nothing scanned: a path already, path devices there but not running, not a disk of that instance, no Nova LUN
        for reads, kw, rc, words in (([lvs(1)], {}, wi_ops.OK, "has 1 path(s) already"),
                                     ([lvs(0, 2)], {}, wi_ops.ATTENTION, "none running: a session or storage problem"),
                                     ([(0, lvs(0)[1].replace(sid, DB01[:-1] + "9"))], {}, wi_ops.FAILED, "is not a disk of the running instance"),
                                     ([lvs(0)], {"bdm": ""}, wi_ops.FAILED, "Nova has no iSCSI target and LUN for vda")):
            d, seen, log = director(reads, **kw)
            self.assertEqual(wi_ops.main(line, d), rc, log)
            self.assertIn(words, log[-1])
            self.assertFalse(any("/scan" in c for c in seen))
        # the scan finds another LUN there (Nova's LUN stale): deleted again, still no path
        d, seen, log = director([lvs(0), lvs(0)], scan="@@deleted 17:0:0:258 sdzz 3600a0980383148000000000000000042")
        self.assertEqual(wi_ops.main(line, d), wi_ops.ATTENTION)
        self.assertIn("not this disk, deleted again", " ".join(log))
        self.assertIn("still has no path after the scan of LUN 258 on 3 session(s)", log[-1])

    def test_host_lvs_parse(self):
        """parse_host_lvs / guest_lvs / dead_maps on the lines the compute prints."""
        text = ('@@filter ["a|.*|"]\n@@devicesfile 1 absent\n'
                f"@@lv dm-0 rhel-root LVM-{'H' * 64} 1 - local:sda2:sda\n"
                f"@@lv dm-168 vg_nfsprod_drc-lv_kube {self.LV} 0 - map:dm-163:dm-163:{self.WWID}\n"
                "@@lv dm-12 vg--maintenance-lv--maintenance LVM-" + "A" * 64 + " 0 - path:sdz1:sdz:3600a09803831384c712b557361544371\n"
                f"@@map dm-163 {self.WWID} 1 dm-168 2 2 sdx,sdy\n@@map dm-53 3600a098038314d716224575347624345 0 - 0 0 -\n"
                # DCA ha-0: both devices run, multipath has none active (every read fails); not open: a dead map
                "@@map dm-177 3600a098038314255672b4f6b4b75564e 0 - 2 2 sdez,sdfa 0\n"
                "@@sd sdez 17:0:0:12 running 3600a098038314255672b4f6b4b75564e\n@@sd sdz 19:0:0:1 running -\n"
                "@@sd sdkk 20:0:0:5 running 3600a098038314255672b4f6b4b75564f\n"
                "@@domains\n@@dom instance-00003f8a 3f0bc84f-b72e-4ee4-b2fd-66b1edaa27c3\n@@disk vdb dm-163\n"
                "@@dom instance-00002222 36698df6-62dc-41bc-adea-5d40a08a4321\n@@disk vdc sdz\n")
        seen = wi_ops.parse_host_lvs(text)
        self.assertEqual(seen["filter"], '["a|.*|"]')
        lvs = {x["dm"]: x for x in wi_ops.guest_lvs(seen)}
        self.assertEqual(sorted(lvs), ["dm-12", "dm-168"])   # the host's root LV is left out
        self.assertEqual((lvs["dm-168"]["kind"], lvs["dm-168"]["users"]), ("disk", [("instance-00003f8a", "vdb")]))
        self.assertEqual((lvs["dm-12"]["kind"], lvs["dm-12"]["users"]), ("disk", [("instance-00002222", "vdc")]))
        self.assertEqual(wi_ops.dead_maps(seen), [("dm-53", "3600a098038314d716224575347624345"),
                                                  ("dm-177", "3600a098038314255672b4f6b4b75564e")])
        self.assertEqual(seen["maps"]["dm-163"]["running"], 2)   # no multipath count (older read): the device states
        # sdz is the disk of instance-00002222 (one SCSI path) and under an LV: never a loose path
        self.assertEqual(wi_ops.loose_paths(seen), [("sdez", "17:0:0:12", "3600a098038314255672b4f6b4b75564e", "running", ""),
                                                    ("sdkk", "20:0:0:5", "3600a098038314255672b4f6b4b75564f", "running", "")])
        # the read of each device (this read): 0 = it answers, a code = it failed, none = no answer in 5 s
        fresh = wi_ops.parse_host_lvs("@@sd sdhh 19:0:0:58 running 3600a098038314255672b4f6b4c333454 0\n"
                                     "@@sd sdez 17:0:0:12 running 3600a098038314255672b4f6b4b75564e 1\n"
                                     "@@sd sdfa 18:0:0:12 running 3600a098038314255672b4f6b4b75564e none\n@@domains")
        self.assertEqual({sd: x["read"] for sd, x in fresh["loose"].items()}, {"sdhh": "ok", "sdez": "failed", "sdfa": "none"})
        self.assertEqual([x["targets"] for x in wi_ops.lvs_of(seen, "instance-00003f8a")], [["vdb"]])


if __name__ == "__main__":
    unittest.main()

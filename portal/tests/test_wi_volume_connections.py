"""Check volume-connections (Volume connections of an instance, after a failed migration): its reads answered by the fake
director (tests/fake_cloud.py: OpenStack, the undercloud node list, the overcloud reads on a controller and a compute), its
read-only guard, and its rating of a healthy instance and of the state a failed live migration left in production.

Run from the portal folder:
    .venv/bin/python -m unittest tests.test_wi_volume_connections -v
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
os.environ.pop("FAKE_CLOUD_STATE", None)   # the fixed cloud only: this check changes nothing

import fake_cloud  # noqa: E402
import wi_analysis  # noqa: E402
from wi_analysis import overcloud  # noqa: E402

CHECK = "volume-connections"
HEALTHY = fake_cloud.uid(1, "5e")    # web-01: 3 volumes, one attachment each, the LUNs Nova keeps are its disks
INCIDENT = fake_cloud.VC_SID         # fw-pfsense-01: what a failed live migration left on DCB
OTHER = fake_cloud.uid(5, "5e")      # db-01: its disk is the LUN 21 Nova keeps for fw-pfsense-01


def run(params, ctx=None):
    """The check as the playbook runs it: every phase planned on what was read before, every read answered by the fake
    director (an overcloud read as the director runs it: ssh <user>@<ctlplane address> '<command>')."""
    ctx, data, seen = ctx or {"site": "DCB"}, {}, []
    for phase in range(1, wi_analysis.plan(CHECK)["phases"] + 1):
        for src, items in wi_analysis.reads(CHECK, phase, data, params, ctx).items():
            for key, cmd in items.items():
                shown = cmd
                if src == "overcloud":
                    _node, ip, user, shown = overcloud.parse(cmd)   # the command the node runs
                    cmd = f"{overcloud.SSH} {user}@{ip} {shlex.quote(shown)}"
                fake_cloud.UNDERCLOUD = src == "undercloud"
                rc, out = fake_cloud.answer(cmd)
                data[key] = {"rc": rc, "out": out}
                seen.append((src, key, shown))
    return wi_analysis.analyze(CHECK, data, params, ctx), seen


def steps(result):
    return {s["key"]: s for s in result["steps"]}


class VolumeConnectionsTest(unittest.TestCase):
    def test_catalog_and_registry(self):
        from modules.wi import catalog
        c = catalog.get(CHECK)
        self.assertEqual((c["status"], c["activity"], c["fix"], c["basis"]), ("ready", "troubleshoot", False, "platform"))
        self.assertIn(CHECK, wi_analysis.CHECKS)
        self.assertIn(CHECK, next(s["checks"] for s in catalog.CATALOG["symptoms"] if s["id"] == "stuck"))
        with self.assertRaises(ValueError):   # the instance is a UUID, nothing else reaches a command
            catalog.clean_params(c, {"instance": "x; rm -rf /"}, "DCB", {})

    def test_reads_are_read_only(self):
        """The OpenStack reads pass the read-only allowlist; the overcloud reads are fixed commands with validated
        arguments (an instance UUID, an instance name, a LUN number, hours), and the database read never selects the
        connection_info whole (it holds the CHAP secret), only fields of it."""
        _res, seen = run({"instance": INCIDENT})
        srcs = {s for s, _k, _c in seen}
        self.assertEqual(srcs, {"openstack", "undercloud", "overcloud", "ontap"})
        for _s, _k, path in [x for x in seen if x[0] == "ontap"]:   # NetApp: GET of /api paths only, values encoded
            self.assertRegex(path, r"^/api/(storage/luns/[0-9a-f-]{36}|protocols/san/(igroups|lun-maps))\?[A-Za-z0-9_.,=&|%-]+$")
        db = next(c for s, k, c in seen if k == "db")
        self.assertIn("JSON_VALUE(connection_info,'$.data.target_lun')", db)
        self.assertNotRegex(db.replace("IF(connection_info IS NULL", ""), r"SELECT[^;]*[ ,]connection_info[ ,]")
        self.assertNotIn("auth_password", db)
        self.assertNotIn("UPDATE", db.upper().replace("UPDATED", ""))
        for bad in ("vc_domain:instance-x", "vc_lun:21;id", "vc_log:500", "vc_db:5e5e"):
            with self.assertRaises(ValueError):
                overcloud.parse(f"overcloud-novacompute-7|192.168.253.27|heat-admin|{bad}")
        self.assertEqual(wi_analysis.reads(CHECK, 1, {}, {"instance": "x'; reboot"}, {}),
                         {s: {} for s in wi_analysis.SOURCES})

    def test_healthy_instance(self):
        res, _seen = run({"instance": HEALTHY})
        st = steps(res)
        self.assertEqual(res["status"], "ok", [(s["key"], s["status"], s["detail"]) for s in res["steps"]])
        self.assertEqual({k: st[k]["status"] for k in ("instance", "attachments", "bdm", "devices", "ports", "joblock", "log")},
                         {"instance": "ok", "attachments": "ok", "bdm": "ok", "devices": "ok", "ports": "ok", "joblock": "ok", "log": "ok"})
        self.assertIn("used by this instance only", st["devices"]["detail"])
        self.assertEqual(res["recommendations"], [])

    def test_state_left_by_a_failed_live_migration(self):
        """fw-pfsense-01, as pfsense on DCB: ERROR after its live migration failed (libvirt could not take its job), two
        attachments of its volume, Nova keeping the LUN number of the destination, which on its compute is the disk of
        db-01, and a port still saying migrating_to."""
        res, _seen = run({"instance": INCIDENT})
        st = steps(res)
        self.assertEqual(res["status"], "fail")
        self.assertEqual(st["instance"]["status"], "fail")
        self.assertIn("Its last migration (live-migration 8644, compute-07 -> compute-09) ended error", st["instance"]["detail"])
        self.assertEqual(st["attachments"]["status"], "fail")
        self.assertIn("duplicate connectors detected", st["attachments"]["detail"])
        self.assertEqual(st["bdm"]["status"], "fail")
        self.assertIn(f"{fake_cloud.VC_VOL}: its attachment is reserved, not attached", st["bdm"]["detail"])
        self.assertEqual(st["devices"]["status"], "fail")
        self.assertIn(f"CRITICAL: the LUN 21 of target {fake_cloud.VC_IQN} that Nova keeps for volume {fake_cloud.VC_VOL} is, "
                      f"on overcloud-novacompute-7, the disk dm-21", st["devices"]["detail"])
        self.assertIn(f"of ANOTHER instance: {OTHER} (domain instance-00000005)", st["devices"]["detail"])
        self.assertEqual(st["ports"]["status"], "warn")
        self.assertIn("still carry migrating_to", st["ports"]["detail"])
        self.assertEqual(st["joblock"]["status"], "fail")
        self.assertIn("cannot acquire state change lock", st["joblock"]["detail"])
        self.assertEqual(st["log"]["status"], "info")
        self.assertTrue(any("Live migration failed" in x for x in st["log"]["evidence"].splitlines()))
        self.assertTrue(any("Flushing" in x for x in st["log"]["evidence"].splitlines()))   # the flush of db-01's disk
        recs = {r["text"].split(":")[0]: r for r in res["recommendations"]}
        fix = next(r for r in res["recommendations"] if r["text"].startswith("Do not hard reboot, start, delete, rebuild or migrate"))
        cmds = "\n".join(fix["commands"])
        self.assertIn(f"openstack server stop {INCIDENT}", cmds)
        self.assertIn(f"\\\"serial\\\": \\\"{fake_cloud.VC_VOL}\\\"", cmds)
        self.assertIn(f"attachment_id='{fake_cloud.uid(35, 'a')}' AND deleted=0 LIMIT 1", cmds)
        self.assertIn(f"attachment-delete {fake_cloud.uid(34, 'a')}", cmds)
        self.assertIn(f"volume_attachment refresh {INCIDENT} {fake_cloud.VC_VOL} /tmp/connector.json", cmds)
        self.assertLess(cmds.index("server stop"), cmds.index("UPDATE nova.block_device_mapping"))
        self.assertLess(cmds.index("UPDATE nova.block_device_mapping"), cmds.index("volume_attachment refresh"))
        self.assertIn("fix libvirt first", fix["warning"])
        self.assertIn("not a bootable disk", fix["warning"])
        self.assertTrue(any(x["vendor"] == "Platform9" for x in fix["references"]))
        self.assertIn(f"openstack port unset --binding-profile migrating_to {fake_cloud.VC_PORT}   # was migrating_to compute-09",
                      next(r for r in res["recommendations"] if "migrating_to" in r["text"])["commands"])
        self.assertTrue(any(t.startswith("Fix libvirt on overcloud-novacompute-7") for t in recs))

    def test_a_volume_missing_in_cinder_while_the_domain_runs_on_its_migration_target(self):
        """vm-c3, 2026-11-02: Nova keeps volume 7a3c9e01, whose Cinder row was deleted; the target of a volume migration
        that never completed (8b4d0f12, named 7a3c9e01, migration target:7a3c9e01) is attached to the instance and is its
        disk (NetApp LUN volume-8b4d0f12, LUN 103); Nova's stored connection names LUN 33, where the compute has no device
        and its igroup maps nothing. One run names all of it, says not to stop or reboot it, and gives the repair onto the
        real volume (never a refresh of the missing one: Cinder would answer 404)."""
        res, seen = run({"instance": fake_cloud.VC3_SID})
        st = steps(res)
        vol, real, att = fake_cloud.VC3_VOL, fake_cloud.VC3_REAL, fake_cloud.VC3_ATT
        self.assertTrue(any(k == "na_map_33" and "igroup.name=openstack%2Dc07&logical_unit_number=33" in c for s, k, c in seen))
        # the disk's LUN: what the igroup maps at the LUN number of its paths, then that LUN by its UUID (a real case: a
        # search of every LUN by serial took over 60 s); its serial is compared with the disk's
        self.assertTrue(any(k == "na_dmap_dm-40" and "igroup.name=openstack%2Dc07&logical_unit_number=103&" in c for s, k, c in seen))
        self.assertIn(("ontap", "na_lun_dm-40_0", f"/api/storage/luns/{fake_cloud.VC3_LUN_UUID}"
                                                  "?fields=name,svm.name,serial_number,status.state,status.mapped,space.size"), seen)
        self.assertFalse([c for s, _k, c in seen if "serial_number=" in c])
        rec = st["records"]
        self.assertEqual(rec["status"], "fail")
        self.assertIn(f"Nova's volume {vol} (/dev/vda) is not in Cinder by its ID (its row was deleted 2026-10-10 16:01:07). The "
                      f"domain runs /dev/vda on dm-40 (LUN 103), NetApp LUN /vol/CINDER_25_vol/volume-{real}: Cinder volume {real}, "
                      f"in-use, migration target:{vol}, attached to this instance ({att})", rec["detail"])
        self.assertIn(f"Nova's stored connection of {vol} names LUN 33; the paths of the disk the domain runs on are LUN 103; on "
                      "NetApp the igroup openstack-c07 of this compute maps nothing at LUN 33", rec["detail"])
        self.assertIn("Do not stop / start, hard reboot, resize, migrate or evacuate it", rec["detail"])
        row = rec["table"]["rows"][0]
        self.assertEqual(row[1], "NO: deleted 2026-10-10 16:01:07")
        self.assertIn(f"{real} (in-use, attached, migration target:{vol})", row[2])
        self.assertEqual(row[6], "LUN 33: nothing mapped (igroup openstack-c07)")
        self.assertEqual(st["attachments"]["status"], "fail")
        self.assertIn("are not in Cinder by their ID", st["attachments"]["detail"])
        fix = next(r for r in res["recommendations"] if r["text"].startswith("Do not stop / start, hard reboot"))
        cmds = "\n".join(fix["commands"])
        self.assertIn(f"cinder reset-state --reset-migration-status {real}", cmds)
        self.assertIn(f"SET volume_id='{real}', attachment_id='{att}'", cmds)
        self.assertIn(f"volume_id='{vol}' AND attachment_id='{fake_cloud.uid(39, 'a')}' AND deleted=0 LIMIT 1", cmds)
        self.assertIn(f"volume_attachment refresh {fake_cloud.VC3_SID} {real} /tmp/connector.json", cmds)
        self.assertLess(cmds.index("server stop"), cmds.index("UPDATE nova.block_device_mapping"))
        self.assertNotIn(f"volume_attachment refresh {fake_cloud.VC3_SID} {vol} ", cmds)   # the missing one: 404
        self.assertFalse([r for r in res["recommendations"] if r["text"].startswith("Repoint Nova's connection")])

    def test_the_lun_mapped_at_a_disks_number_is_another_lun(self):
        """The paths of the domain's disk are LUN 103 on the compute, but the LUN NetApp maps there for the compute has
        another serial: the disk is not taken for that LUN (no repair onto its volume), and the stale paths are named."""
        fake_cloud.STATE["vc3_serial"] = "80Fq]UzD9Zz9"
        try:
            res, _seen = run({"instance": fake_cloud.VC3_SID})
        finally:
            fake_cloud.STATE.pop("vc3_serial", None)
        rec = steps(res)["records"]
        self.assertEqual(rec["status"], "fail")   # the volume is still missing in Cinder
        self.assertEqual(rec["table"]["rows"][0][4], f"no LUN with serial {fake_cloud.VC3_SERIAL} at LUN 103: mapped there "
                                                     f"/vol/CINDER_25_vol/volume-{fake_cloud.VC3_REAL}")
        self.assertEqual(rec["table"]["rows"][0][5], "-")
        self.assertIn(f"The paths of /dev/vda (dm-40, serial {fake_cloud.VC3_SERIAL}) are LUN 103 on the compute, but on NetApp: "
                      "no LUN with serial", rec["detail"])
        self.assertFalse([r for r in res["recommendations"] if "UPDATE nova.block_device_mapping SET volume_id" in
                          "\n".join(r["commands"])])

    def test_without_the_overcloud(self):
        """No node list from the undercloud: the database and compute steps are skipped with the reason, never rated ok."""
        import fake_cloud as fc
        saved = fc.answer

        def no_undercloud(cmd):
            if fc.UNDERCLOUD:
                return 1, "openstack: command failed (stackrc missing)"
            return saved(cmd)
        fc.answer = no_undercloud
        try:
            res, seen = run({"instance": INCIDENT})
        finally:
            fc.answer = saved
        st = steps(res)
        self.assertFalse(any(s == "overcloud" for s, _k, _c in seen))
        self.assertEqual((st["attachments"]["status"], st["bdm"]["status"], st["devices"]["status"]), ("skip", "skip", "skip"))
        self.assertEqual(st["instance"]["status"], "fail")


if __name__ == "__main__":
    unittest.main()

"""LUN copy guard (spec docs/superpowers/specs/2026-11-11-lun-copy-guard-design.md): a migration, a volume move or
retype and a detach become manual while the LUN of a volume also exists in another FlexVol of its SVM (a FlexClone copy,
A real case), is not in its pool, is not found, or cannot be read.

Run from the portal folder:
    .venv/bin/python -m unittest tests.test_wi_lun_guard -v
"""
import json
import os
import shlex
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "modules", "wi"))
os.environ.pop("FAKE_CLOUD_STATE", None)   # the fixed cloud only

import fake_cloud  # noqa: E402
import wi_analysis  # noqa: E402
from wi_analysis import lun_guard, overcloud  # noqa: E402
from wi_analysis.common import Result  # noqa: E402


def u(n):
    return f"{n:08x}-0000-4000-8000-{n:012x}"


V1, V2, V3, N1, I1 = u(1), u(2), u(3), u(9), u(21)
CTX = {"site": "DCA", "netapp": True}
COPY = "snap_DCA_CINDER_15_vol_clone_152"


def vol(vid, pool, name_id="", status="in-use"):
    return (vid, name_id, f"hostgroup@tripleo_netapp#{pool}" if pool else "hostgroup@tripleo_netapp", status)


def lun(svm, fv, vid):
    return {"name": f"/vol/{fv}/volume-{vid}", "svm": {"name": svm}}


def data(att=(), vols=(), luns=(), more="", db_rc=0, luns_status=200):
    rows = [("att",) + tuple(a) for a in att] + [("vol",) + tuple(v) for v in vols]
    out = {"lg_db": {"rc": db_rc, "out": "\n".join("\t".join(r) for r in rows) if db_rc == 0 else "ERROR 2002 (HY000)"}}
    out["lg_luns"] = ({"status": 200, "json": {"records": list(luns)}} if luns_status == 200
                      else {"status": luns_status, "msg": "Internal error"})
    if more:
        out["lg_luns"]["more"] = more
    return out


def index(**kw):
    return lun_guard.index(data(**kw), CTX)


class GuardIndexTest(unittest.TestCase):
    def test_ok(self):
        g = index(vols=[vol(V1, "P15")], luns=[lun("S1", "P15", V1)])
        self.assertEqual(g.state, "read")
        self.assertEqual(g.volumes[V1]["verdict"], "ok")
        self.assertEqual(lun_guard.reason_for_volume(g, V1), "")

    def test_copy_in_same_svm(self):
        g = index(vols=[vol(V1, "P15")], luns=[lun("S1", "P15", V1), lun("S1", COPY, V1)])
        self.assertEqual(g.volumes[V1]["verdict"], "copy")
        self.assertEqual(lun_guard.reason_for_volume(g, V1), f"LUN volume-{V1} also in {COPY}: check lun-map-audit, then tick it")

    def test_copy_in_other_svm_ignored(self):
        g = index(vols=[vol(V1, "P15")], luns=[lun("S1", "P15", V1), lun("DR", COPY, V1)])
        self.assertEqual(g.volumes[V1]["verdict"], "ok")

    def test_name_id_used(self):
        g = index(vols=[vol(V1, "P15", name_id=N1)], luns=[lun("S1", "P15", N1), lun("S1", COPY, N1), lun("S1", "P14", V1)])
        self.assertEqual((g.volumes[V1]["lun"], g.volumes[V1]["verdict"]), (f"volume-{N1}", "copy"))

    def test_not_in_pool(self):
        g = index(vols=[vol(V1, "P15")], luns=[lun("S1", COPY, V1), lun("S1", "P15", V2)])
        self.assertEqual(g.volumes[V1]["verdict"], "not-in-pool")
        self.assertEqual(lun_guard.reason_for_volume(g, V1),
                         f"LUN volume-{V1} is not in its pool P15 but in {COPY}: check lun-map-audit")

    def test_missing(self):
        g = index(vols=[vol(V1, "P15")], luns=[lun("S1", "P15", V2)])
        self.assertEqual(g.volumes[V1]["verdict"], "missing")
        self.assertEqual(lun_guard.reason_for_volume(g, V1), f"LUN volume-{V1} not found on NetApp: check lun-map-audit")

    def test_not_netapp_and_nfs_pool(self):
        g = index(vols=[vol(V1, "nfs_vol")], luns=[lun("S1", "P15", V2)])
        self.assertEqual(g.volumes[V1]["verdict"], "not-netapp")
        self.assertEqual(lun_guard.reason_for_volume(g, V1), "")

    def test_unread(self):
        g = index(vols=[vol(V1, "P15")], luns=[lun("S1", "P15", V1)], db_rc=1)
        self.assertEqual((g.state, g.why), ("unread", "Cinder database not read"))
        self.assertEqual(lun_guard.reason_for_volume(g, V1), "Cinder database not read: LUN copies unknown")
        self.assertEqual(lun_guard.reason_for_instance(g, I1), "Cinder database not read: LUN copies unknown")
        g = index(vols=[vol(V1, "P15")], luns_status=500)
        self.assertEqual((g.state, g.why), ("unread", "NetApp not read"))
        self.assertEqual(lun_guard.reason_for_volume(g, V1), "NetApp not read: LUN copies unknown")
        g = index(vols=[vol(V1, "P15")], luns=[lun("S1", "P15", V1)], more="lg_luns: 2000 more")
        self.assertEqual((g.state, g.why), ("unread", "NetApp list read only in part"))

    def test_partial_list_with_next_page_is_unread(self):
        """merge_pages leaves "next" set (and "more" empty) when the page rounds ran out: a copy may be on a page not read."""
        d = data(vols=[vol(V1, "P15")], luns=[lun("S1", "P15", V1)])
        d["lg_luns"].update(pages=9, next="/api/storage/luns?fields=name,svm.name&return_timeout=45&start.name=x", more="")
        g = lun_guard.index(d, CTX)
        self.assertEqual((g.state, g.why), ("unread", "NetApp list read only in part"))
        self.assertEqual(lun_guard.reason_for_volume(g, V1), "NetApp list read only in part: LUN copies unknown")

    def test_off_without_netapp(self):
        ctx = {"site": "DEV"}
        g = lun_guard.index(data(vols=[vol(V1, "P15")], luns=[lun("S1", "P15", V1), lun("S1", COPY, V1)]), ctx)
        self.assertEqual(g.state, "off")
        self.assertEqual((lun_guard.reason_for_volume(g, V1), lun_guard.reason_for_instance(g, I1)), ("", ""))
        self.assertEqual((lun_guard.reads(1, {}, ctx), lun_guard.reads(2, {}, ctx)), ({}, {}))

    def test_reads_by_phase(self):
        self.assertEqual(lun_guard.reads(1, {}, CTX), {"undercloud": dict(overcloud.INVENTORY_READS)})
        self.assertEqual(lun_guard.reads(2, {}, CTX), {"ontap": {"lg_luns": lun_guard.LUNS_PATH}})   # no controller known
        self.assertEqual(lun_guard.reads(3, {}, CTX), {})
        self.assertEqual(lun_guard.reads(2, {}, CTX, first=2), {"undercloud": dict(overcloud.INVENTORY_READS)})
        self.assertEqual(lun_guard.LUNS_PATH, "/api/storage/luns?fields=name,svm.name&return_timeout=45")

    def test_merge(self):
        self.assertEqual(lun_guard.merge({"openstack": {"a": "x"}, "ontap": {"b": "y"}}, {"ontap": {"c": "z"}}, {}),
                         {"openstack": {"a": "x"}, "ontap": {"b": "y", "c": "z"}})

    def test_instance_reason_names_flagged_volume(self):
        att = [(V1, I1, "attached"), (V2, I1, "attached"), (V3, I1, "attached")]
        g = index(att=att, vols=[vol(V1, "P15"), vol(V2, "P15"), vol(V3, "P15")],
                  luns=[lun("S1", "P15", V1), lun("S1", "P15", V2), lun("S1", "P15", V3), lun("S1", COPY, V3)])
        self.assertEqual(lun_guard.reason_for_instance(g, I1),
                         f"volume {V3[:8]}: LUN volume-{V3} also in {COPY}: check lun-map-audit, then tick it")
        long = "Clone_14oct_DCAOPNSTACK_CINDER_15_vol_clone_858_a_very_long_flexclone_name"
        g = index(att=att, vols=[vol(V1, "P15"), vol(V2, "P15"), vol(V3, "P15")],
                  luns=[lun("S1", "P15", V1), lun("S1", "P15", V2), lun("S1", long, V2), lun("S1", "P15", V3), lun("S1", COPY, V3)])
        reason = lun_guard.reason_for_instance(g, I1)
        self.assertTrue(reason.startswith(f"volume {V2[:8]}: LUN volume-{V2} also in"), reason)
        self.assertTrue(reason.endswith(" (+1 more)"), reason)
        self.assertLessEqual(len(reason), 160)

    def test_detached_attachment_ignored(self):
        g = index(att=[(V1, I1, "detached")], vols=[vol(V1, "P15")], luns=[lun("S1", "P15", V1), lun("S1", COPY, V1)])
        self.assertNotIn(I1, g.instances)
        self.assertEqual(lun_guard.reason_for_instance(g, I1), "")

    def test_host_without_pool(self):
        g = index(vols=[vol(V1, "")], luns=[lun("S1", COPY, V1)])
        self.assertEqual(g.volumes[V1]["verdict"], "not-in-pool")
        g = index(vols=[vol(V1, "")], luns=[lun("S1", "P15", V2)])
        self.assertEqual(g.volumes[V1]["verdict"], "not-netapp")

    def test_same_flexvol_name_in_two_svms(self):
        g = index(vols=[vol(V1, "P15")], luns=[lun("S1", "P15", V1), lun("DR", "P15", V1)])
        self.assertEqual(g.volumes[V1]["verdict"], "ok")

    def test_malformed_lun_records_ignored(self):
        luns = [{"name": None}, {"svm": {"name": "S1"}}, "x", {"name": f"/vol/{COPY}/volume-{V1}"}, lun("S1", "P15", V1)]
        g = index(vols=[vol(V1, "P15")], luns=luns)
        self.assertEqual((g.state, g.volumes[V1]["verdict"]), ("read", "ok"))


class GuardMarkTest(unittest.TestCase):
    SNAP = "its 1 snapshot(s) are deleted before it moves: an operator ticks it"

    def guard(self):
        return index(att=[(V1, I1, "attached")], vols=[vol(V1, "P15"), vol(V2, "P15")],
                     luns=[lun("S1", "P15", V1), lun("S1", COPY, V1), lun("S1", "P15", V2)])

    def test_mark(self):
        g = self.guard()
        items = [{"label": "a", "commands": [f"migrate-volume {V1} to x"], "default": True, "manual": self.SNAP},
                 {"label": "b", "commands": [f"migrate-volume {V2} to x"], "default": True}]
        self.assertEqual(lun_guard.mark(items, g, "volume"), 1)
        self.assertEqual(items[0]["manual"], f"{self.SNAP}; LUN volume-{V1} also in {COPY}: check lun-map-audit, then tick it")
        self.assertIs(items[0]["default"], False)
        self.assertEqual((items[1].get("manual", ""), items[1]["default"]), ("", True))
        self.assertEqual(len(g.hits), 1)

    def test_mark_instance(self):
        g = self.guard()
        items = [{"label": "vm", "commands": [f"live-migrate {I1} from compute-07 to auto"], "default": True}]
        self.assertEqual(lun_guard.mark(items, g, "instance"), 1)
        self.assertTrue(items[0]["manual"].startswith(f"volume {V1[:8]}: LUN volume-{V1} also in"))

    def test_mark_skips_items_without_commands(self):
        items = [{"label": "x", "commands": [], "disabled": "nothing to run"}, {"label": "y"}]
        self.assertEqual(lun_guard.mark(items, self.guard(), "volume"), 0)

    def test_step(self):
        g = self.guard()
        lun_guard.reason_for_volume(g, V1)
        r = Result("compute-drain")
        lun_guard.step(r, g)
        s = next(x for x in r.steps if x["key"] == "lun_copies")
        self.assertEqual((s["title"], s["status"]), ("LUN copies on NetApp (FlexClone)", "warn"))
        r = Result("compute-drain")
        lun_guard.step(r, index(vols=[vol(V2, "P15")], luns=[lun("S1", "P15", V2)]))
        self.assertEqual(next(x for x in r.steps if x["key"] == "lun_copies")["status"], "ok")
        r = Result("compute-drain")
        lun_guard.step(r, lun_guard.index({}, {"site": "DEV"}))
        self.assertEqual(next(x for x in r.steps if x["key"] == "lun_copies")["status"], "info")
        r = Result("compute-drain")
        lun_guard.step(r, index(vols=[vol(V1, "P15")], db_rc=1))
        self.assertEqual(next(x for x in r.steps if x["key"] == "lun_copies")["status"], "warn")

    def test_step_once_per_result(self):
        """A fix offered in a loop (one per attachment) calls step each time: the result gets one step."""
        g, r = self.guard(), Result("volume-attach")
        lun_guard.reason_for_volume(g, V1)
        lun_guard.step(r, g)
        lun_guard.step(r, g)
        self.assertEqual([x["key"] for x in r.steps].count("lun_copies"), 1)
        self.assertEqual(len(r.recommendations), 1)

    def test_lun_guard_db_command(self):
        cmd = overcloud.lun_guard_db_command()
        self.assertEqual(overcloud.COMMANDS["lun_guard_db"](""), cmd)
        for text in ("cinder.volume_attachment", "cinder.volumes", "galera-bundle", "_name_id"):
            self.assertIn(text, cmd)
        self.assertNotIn("connection_info", cmd)   # it holds the CHAP secret


class SingleFixTest(unittest.TestCase):
    """A fix without items (a live migration, a detach, a retype rollback) carries the guard's reason too."""
    CMDS = [f"openstack server remove volume {I1} {V1}"]

    def test_os_fix_manual(self):
        from wi_analysis.openstack import os_fix
        self.assertEqual(os_fix(self.CMDS, "vm", manual="m" * 200)["manual"], "m" * 160)
        self.assertNotIn("manual", os_fix(self.CMDS, "vm"))

    def test_state_carries_manual(self):
        import datetime as dt
        from modules.wi import fixes
        from wi_analysis.openstack import os_fix
        r = Result("volume-attach")
        r.step("attach", "Attachment", "fail", "stuck")
        r.recommend("Detach it.", action=os_fix(self.CMDS, "vm", manual="NetApp not read: LUN copies unknown"))
        res = r.done()
        now = dt.datetime.now().astimezone().isoformat(timespec="seconds")
        record = {"id": 1, "site": "DCA", "status": res["status"], "ts": now, "finished": now, "host": ""}
        st = fixes.state(record, 0, res["recommendations"][0], {"id": "volume-attach"}, {"mgmt": {"host": "m"},
                         "director": {"host": "d"}}, {"role": "admin", "modules": []}, lambda name: True)
        self.assertEqual(st["manual"], "NetApp not read: LUN copies unknown")


def answered(src, rc, out):
    """A read as the playbook records it: a REST answer as {"status", "json"}, a command as {"rc", "out"}."""
    if src != "ontap":
        return {"rc": rc, "out": out}
    return {"status": 200, "json": json.loads(out)} if rc == 0 else {"status": 404, "msg": out}


def run(check, params, ctx):
    """The check as the playbook runs it (tests/test_wi_lun_maps.py): every phase planned on what was read before, the
    next pages of the ONTAP lists merged, every read answered by the fake director or the fake ONTAP."""
    data, seen = {}, []
    for phase in range(1, wi_analysis.plan(check)["phases"] + 1):
        reads = wi_analysis.reads(check, phase, data, params, ctx)
        for src, items in reads.items():
            for key, cmd in items.items():
                shown = cmd
                if src == "overcloud":
                    _node, ip, user, shown = overcloud.parse(cmd)
                    cmd = f"{overcloud.SSH} {user}@{ip} {shlex.quote(shown)}"
                fake_cloud.UNDERCLOUD = src == "undercloud"
                data[key] = answered(src, *fake_cloud.answer(cmd))
                seen.append((src, key, shown))
        for _round in range(9):
            pages = wi_analysis.next_pages(data, reads)
            if not any(pages.values()):
                break
            for src, items in pages.items():
                for key, path in items.items():
                    data[key] = answered(src, *fake_cloud.answer(path))
                    seen.append((src, key, path))
        data = wi_analysis.merge_pages(data, reads)
    return wi_analysis.analyze(check, data, params, ctx), seen


def selected(res, label):
    """{instance or volume ID: item} of the fixes with that label (one per pool or project, say)."""
    out = {}
    for rec in res["recommendations"]:
        if (rec.get("action") or {}).get("label") == label:
            out.update({it["commands"][0].split()[1]: it for it in rec["action"]["select"]["items"] if it["commands"]})
    return out


def step_of(res, key="lun_copies"):
    return next((s for s in res["steps"] if s["key"] == key), None)


DCA = {"site": "DCA", "netapp": True}
DRAIN = {"compute": "compute-07"}


class DrainGuardTest(unittest.TestCase):
    def test_drain_copy_is_manual(self):
        res, seen = run("compute-drain", DRAIN, DCA)
        by = selected(res, "Live-migrate selected")
        copy, fine = by[fake_cloud.LG_SIDS[0]], by[fake_cloud.LG_SIDS[1]]
        self.assertTrue(copy["manual"].startswith("volume "), copy)
        self.assertIn("also in", copy["manual"])
        self.assertIn("snap_", copy["manual"])
        self.assertIs(copy["default"], False)
        self.assertNotIn("manual", fine)
        self.assertEqual(step_of(res)["status"], "warn")
        self.assertIn(("ontap", "lg_luns"), [(s, k) for s, k, _c in seen])
        self.assertIn(("overcloud", "lg_db"), [(s, k) for s, k, _c in seen])
        _res, off = run("compute-drain", DRAIN, {"site": "DCA"})
        self.assertEqual({k for s, k, _c in seen if s == "openstack"}, {k for s, k, _c in off if s == "openstack"})

    def test_drain_without_netapp_unchanged(self):
        res, seen = run("compute-drain", DRAIN, {"site": "DCA"})
        self.assertFalse([it for it in selected(res, "Live-migrate selected").values() if it.get("manual")])
        self.assertEqual(step_of(res)["status"], "info")
        self.assertFalse([k for _s, k, _c in seen if k.startswith("lg_")])

    def test_drain_ontap_failed_all_manual(self):
        real = fake_cloud.lm_ontap_answer

        def broken(path):
            return (1, "HTTP 500: internal error") if path == lun_guard.LUNS_PATH else real(path)
        with mock.patch.object(fake_cloud, "lm_ontap_answer", side_effect=broken):
            res, _seen = run("compute-drain", DRAIN, DCA)
        items = selected(res, "Live-migrate selected").values()
        self.assertTrue(items)
        self.assertEqual({it.get("manual") for it in items}, {"NetApp not read: LUN copies unknown"})

    def test_catalog_uses(self):
        from modules.wi import catalog
        c = catalog.get("compute-drain")
        self.assertEqual(c["needs"], ["openstack"])
        self.assertTrue({"undercloud", "ontap"} <= set(c["uses"]), c["uses"])
        self.assertIn("LUN copies on NetApp (FlexClone)", c.get("steps") or [])

    def test_run_context_netapp(self):
        from modules.wi import catalog, run_context
        check = catalog.get("compute-drain")
        self.assertIs(run_context(check, "DCA", {"ontap": {"host": "ontap.example"}}, {})["netapp"], True)
        self.assertIs(run_context(check, "DEV", {}, {})["netapp"], False)



POOL_VOL, SNAP_VOL = fake_cloud.uid(5, "1"), fake_cloud.uid(1, "1")   # app-02-root (CINDER_15), db-prod-data (snapshots)


class VolumeGuardTest(unittest.TestCase):
    def test_pool_usage_two_phases_same_items(self):
        self.assertEqual(wi_analysis.plan("cinder-pool-usage")["phases"], 2)
        res, seen = run("cinder-pool-usage", {}, {"site": "DCA"})
        items = selected(res, "Migrate selected")
        self.assertEqual(len(items), 5)
        # without NetApp the defaults stay: the biggest without snapshots that fits (web-01-root), never one with snapshots
        defaults = {fake_cloud.uid(n, "1"): items[fake_cloud.uid(n, "1")]["default"] for n in (2, 3, 4)}
        self.assertEqual(defaults, {fake_cloud.uid(2, "1"): True, fake_cloud.uid(3, "1"): False, fake_cloud.uid(4, "1"): False})
        self.assertFalse([it["manual"] for it in items.values() if "LUN" in it.get("manual", "")])
        self.assertEqual(step_of(res)["status"], "info")
        self.assertFalse([k for _s, k, _c in seen if k.startswith("lg_")])

    def test_pool_usage_copy_manual_keeps_snapshot_reason(self):
        res, _seen = run("cinder-pool-usage", {}, DCA)
        items = selected(res, "Migrate selected")
        self.assertIn("also in", items[POOL_VOL]["manual"])
        self.assertIs(items[POOL_VOL]["default"], False)
        snap = items[SNAP_VOL]["manual"]
        self.assertTrue(snap.startswith("its ") and "snapshot(s)" in snap, snap)
        self.assertIn(f"; LUN volume-{fake_cloud.LM_V['cloneN']} is not in its pool", snap)
        self.assertEqual(step_of(res)["status"], "warn")

    def test_retype_defaults_without_netapp(self):
        res, _seen = run("volume-type-legacy", {}, {"site": "DCA"})
        items = selected(res, "Change the type of the ticked volumes")
        self.assertEqual({v: it["default"] for v, it in items.items() if v in (POOL_VOL, SNAP_VOL)}, {POOL_VOL: True, SNAP_VOL: False})
        self.assertFalse([it for it in items.values() if it.get("manual")])

    def test_retype_copy_manual(self):
        res, _seen = run("volume-type-legacy", {}, DCA)
        item = selected(res, "Change the type of the ticked volumes")[POOL_VOL]
        self.assertIn("also in", item["manual"])
        self.assertIs(item["default"], False)
        self.assertEqual(step_of(res)["status"], "warn")

    def test_catalog_uses(self):
        from modules.wi import catalog
        for check, uses in (("cinder-pool-usage", {"ontap", "undercloud"}), ("volume-type-legacy", {"ontap", "undercloud"})):
            c = catalog.get(check)
            self.assertEqual(c["needs"], ["openstack"], check)
            self.assertTrue(uses <= set(c["uses"]), (check, c["uses"]))
            self.assertIn("LUN copies on NetApp (FlexClone)", c.get("steps") or [], check)



class SingleGuardTest(unittest.TestCase):
    """A fix without items: a detach, a retype rollback (with its detach), a live migration of one instance."""
    @staticmethod
    def fix(res, label):
        return next((r["action"] for r in res["recommendations"] if (r.get("action") or {}).get("label") == label), None)

    def test_volume_attach_detach_manual(self):
        res, _seen = run("volume-attach", {"volume": POOL_VOL}, DCA)
        self.assertIn("also in", self.fix(res, "Detach it")["manual"])
        self.assertEqual(step_of(res)["status"], "warn")
        res, _seen = run("volume-attach", {"volume": fake_cloud.uid(2, "1")}, DCA)   # web-01-root: no finding
        self.assertNotIn("manual", self.fix(res, "Detach it"))
        self.assertEqual(step_of(res)["status"], "ok")

    def test_stuck_rollback_manual(self):
        res, _seen = run("stuck-resources", {}, DCA)
        self.assertIn("also in", self.fix(res, "Roll back the retype")["manual"])
        self.assertNotIn("manual", self.fix(res, "Reset to available"))   # a reset-state moves and detaches nothing

    def test_stuck_step_counts_every_volume(self):
        """Two volumes stuck in detaching: the first (web-01-root) has no finding, the second (app-02-root) has a copy. The
        step is warn and names the second, not ok after the first."""
        vols = [v[:2] + ("detaching",) + v[3:] if v[0] in (POOL_VOL, fake_cloud.uid(2, "1")) else v for v in fake_cloud.VOLUMES]
        with mock.patch.object(fake_cloud, "VOLUMES", vols):
            res, _seen = run("stuck-resources", {}, DCA)
        st = step_of(res)
        self.assertEqual(st["status"], "warn", st)
        self.assertIn(POOL_VOL, [row[1] for row in st["table"]["rows"]])

    def test_stuck_stop_and_detach_manual(self):
        """app-02-root stuck in detaching: the fix stops the instance and detaches the volume, whose LUN has a copy."""
        vols = [v[:2] + ("detaching",) + v[3:] if v[0] == POOL_VOL else v for v in fake_cloud.VOLUMES]
        with mock.patch.object(fake_cloud, "VOLUMES", vols):
            res, _seen = run("stuck-resources", {}, DCA)
        self.assertIn("also in", self.fix(res, "Stop the instance and detach")["manual"])

    def test_instance_network_live_migrate_manual(self):
        res, _seen = run("instance-network", {"instance": fake_cloud.LG_SIDS[0]}, DCA)
        manual = self.fix(res, "Live-migrate it")["manual"]
        self.assertTrue(manual.startswith("volume ") and "also in" in manual, manual)
        res, _seen = run("instance-network", {"instance": fake_cloud.LG_SIDS[0]}, {"site": "DCA"})
        self.assertNotIn("manual", self.fix(res, "Live-migrate it"))

    def test_catalog_uses(self):
        from modules.wi import catalog
        for check in ("instance-network", "stuck-resources", "volume-attach", "host-lvm"):
            c = catalog.get(check)
            self.assertEqual(c["needs"], ["openstack"], check)
            self.assertTrue({"undercloud", "ontap"} <= set(c["uses"]), (check, c["uses"]))
            self.assertIn("LUN copies on NetApp (FlexClone)", c.get("steps") or [], check)


if __name__ == "__main__":
    unittest.main()

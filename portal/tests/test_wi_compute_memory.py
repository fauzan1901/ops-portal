"""Check compute-memory (memory errors, ECC, on the computes): its reads answered by the fake director (tests/fake_cloud.py:
overcloud-novacompute-7 as dccrhosp-compute-1 before its crash on 2026-10-30, overcloud-novacompute-9 healthy,
overcloud-novacompute-3 not reachable), its read-only command, and its rating.

Run from the portal folder:
    .venv/bin/python -m unittest tests.test_wi_compute_memory -v
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
from wi_analysis import compute_memory, overcloud  # noqa: E402

CHECK = "compute-memory"


def run(params, ctx=None):
    """The check as the playbook runs it, every read answered by the fake director."""
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


class ComputeMemoryCheckTest(unittest.TestCase):
    def test_catalog_and_registry(self):
        from modules.wi import catalog
        c = catalog.get(CHECK)
        self.assertEqual((c["status"], c["activity"], c["basis"]), ("ready", "health", "platform"))
        self.assertFalse(c.get("fix"))
        self.assertIn(CHECK, wi_analysis.CHECKS)
        self.assertIn(CHECK, next(s["checks"] for s in catalog.CATALOG["symptoms"] if s["id"] == "hardware"))
        self.assertFalse(any(wi_analysis.reads(CHECK, 1, {}, {"days": 31}, {}).values()))               # 1-30 days
        self.assertFalse(any(wi_analysis.reads(CHECK, 1, {}, {"compute": "x; reboot"}, {}).values()))   # a host name only
        with self.assertRaises(ValueError):
            overcloud.read("overcloud-novacompute-7", "192.168.253.27", "heat-admin", "mem_ecc", 31)

    def test_the_read_changes_nothing(self):
        """Only reads of the BMC event log and sensors: never a clear, a raw command, a reset or a setting."""
        cmd = overcloud.mem_ecc_command(7)
        for word in ("sel clear", "sel delete", " raw ", "chassis", "mc reset", "lan set", "user set", "sol ", "power ", "rm ", ">"
                     " /", "modprobe"):
            self.assertNotIn(word, cmd.replace("2>/dev/null", "").replace(">/dev/null", "").replace("2>&1", ""), word)
        for read in ("ipmitool sel time get", "ipmitool sel info", "ipmitool sel elist", "ipmitool sdr type Memory",
                     "journalctl _TRANSPORT=kernel --since '-7d'", "/sys/devices/system/edac/mc/", "ls -1 /var/crash",
                     "ipmitool lan print", "/sys/class/dmi/id/product_serial"):
            self.assertIn(read, cmd)

    def test_every_compute_of_the_site(self):
        result, seen = run({})
        reads = [k for src, k, _c in seen if src == "overcloud"]
        self.assertEqual(reads, ["use_mem_0", "use_mem_1", "use_mem_2"])   # read at once (PARALLEL)
        st = steps(result)
        self.assertEqual(st["computes"]["status"], "warn")
        self.assertIn("2 of 3 compute(s) read; not reachable: overcloud-novacompute-3", st["computes"]["detail"])
        clocks = {row[0]: row[5] for row in st["computes"]["table"]["rows"]}
        self.assertEqual((clocks["overcloud-novacompute-7"], clocks["overcloud-novacompute-9"]), ("UTC", "UTC+7 h"))
        bmcs = {row[0]: row[3] for row in st["computes"]["table"]["rows"]}   # which BMC web page is this compute's
        self.assertEqual(bmcs["overcloud-novacompute-7"], "172.24.156.27 / serial 221636007")
        self.assertIn("overcloud-novacompute-7: 30 (#48) |", st["sel"]["evidence"])   # the SEL ID also in decimal (BMC web page)

        sel = st["sel"]
        self.assertEqual(sel["status"], "fail")
        self.assertEqual(len(sel["table"]["rows"]), 1, sel["table"]["rows"])   # older and deasserted entries left out
        row = sel["table"]["rows"][0]
        self.assertEqual(row[:3], ["overcloud-novacompute-7", "CPU2_C3D0", "Correctable ECC logging limit reached x3"])
        self.assertEqual(row[5:], ["Presence Detected, Correctable ECC logging limit reached", "REPLACE SOON"])

        self.assertEqual(st["sensors"]["status"], "fail")
        self.assertEqual([r[:2] for r in st["sensors"]["table"]["rows"]], [["overcloud-novacompute-7", "CPU2_C3D0"]])

        kern = st["kernel"]
        self.assertEqual(kern["status"], "fail")
        self.assertEqual(kern["table"]["rows"][0][:2], ["overcloud-novacompute-7", "2 (max 2011.56 ms)"])
        self.assertTrue(kern["table"]["rows"][0][6].startswith("127.0.0.1-"))
        self.assertIn("took too long to run: 2011.556 msecs", kern["evidence"])
        self.assertNotIn("Giving out device", kern["evidence"])   # the EDAC lines of every boot are no evidence

        self.assertEqual(st["capacity"]["status"], "warn")
        self.assertEqual(st["capacity"]["table"]["rows"][0][0], "overcloud-novacompute-9")

        fix = result["recommendations"][0]
        self.assertIn('openstack compute service set --disable --disable-reason "DIMM ECC errors: replace" '
                      'overcloud-novacompute-7 nova-compute', fix["commands"])
        # booted after its crash dump, the DIMM not replaced: still rated fail, the boot named
        (host, why), = fix["items"]["rows"]
        self.assertEqual(host, "overcloud-novacompute-7")
        self.assertRegex(why, r"^CPU2_C3D0, kernel hardware errors \(the last \d{4}-\d\d-\d\d \d\d:\d\d, before the boot of "
                              r"\d{4}-\d\d-\d\d \d\d:\d\d\)$")
        sel = {row[0]: row[4] for row in st["computes"]["table"]["rows"]}
        self.assertRegex(sel["overcloud-novacompute-9"], r"^512 entries, 95% used, since \d{4}-\d\d-\d\d \d\d:\d\d$")

    def test_after_a_dimm_replacement_the_cleared_sel_and_the_old_signals_are_named(self):
        """A real case: its DIMM CPU2_C3D0 replaced, the SEL cleared at the swap (9 entries left),
        booted after it. No ECC event in that SEL covers hours, not the 7 days: said, rated warn. The NMIs and the crash
        dump of the old DIMM are all before the boot: still rated fail (the check cannot know the DIMM was replaced),
        each with its time and the boot, and how to read the new boot only."""
        fake_cloud.STATE["mem_replaced"] = True
        try:
            result, _seen = run({"compute": "overcloud-novacompute-7", "days": 7})
        finally:
            fake_cloud.STATE.pop("mem_replaced", None)
        st = steps(result)
        row = st["computes"]["table"]["rows"][0]
        self.assertRegex(row[4], r"^9 entries, 0% used, since (\S+ \S+) \(cleared \1\)$")
        self.assertRegex(row[6], r"^\d{4}-\d\d-\d\d \d\d:\d\d$")
        self.assertEqual(st["sel"]["status"], "warn")
        self.assertFalse((st["sel"].get("table") or {}).get("rows"))
        self.assertIn("No DIMM logged an ECC error in the BMC event log of the last 7 days that the logs hold. The BMC event "
                      "log of 1 compute(s) starts inside the window: overcloud-novacompute-7 (since", st["sel"]["detail"])
        self.assertEqual(st["sensors"]["status"], "ok")
        kern = st["kernel"]
        self.assertEqual(kern["status"], "fail")
        self.assertIn(f", before the boot of {row[6]}", kern["table"]["rows"][0][7])
        self.assertIn(f"Every signal of overcloud-novacompute-7 (booted {row[6]}) is from before its last boot: if a DIMM was "
                      "replaced at that boot, they are the old DIMM's history (run this check with days=1", kern["detail"])
        (host, why), = result["recommendations"][0]["items"]["rows"]
        self.assertEqual(host, "overcloud-novacompute-7")
        self.assertTrue(why.startswith("kernel hardware errors (the last ") and why.endswith(f", before the boot of {row[6]})"), why)

    def test_the_time_of_a_kernel_line_and_of_the_boot(self):
        seen = compute_memory.parse("@@now 2027-01-02 03:00:00\n@@boot 2027-01-02 09:30:00 +0700\n@@selinfo\n"
                                    "Last Del Time    : Not Available\n@@selfirst\n@@kernel\n"
                                    "Dec 30 06:28:34 h kernel: INFO: NMI handler (ghes_notify_nmi) took too long to run: 1.2 msecs\n"
                                    "@@edac\n@@crash\n@@end")
        self.assertEqual((str(seen["boot"]), str(seen["tz"])), ("2027-01-02 09:30:00", "7:00:00"))
        res = compute_memory.rate(seen, 7)
        self.assertEqual(str(res["kernel"]["last"]), "2026-12-30 06:28:34")   # no year in the line: the year before
        self.assertTrue(res["kernel"]["before_boot"])
        self.assertEqual((res["sel_since"], res["sel_cleared"], res["sel_short"]), (None, None, False))

    def test_one_healthy_compute(self):
        result, seen = run({"compute": "overcloud-novacompute-9", "days": 7})
        self.assertEqual([k for src, k, _c in seen if src == "overcloud"], ["use_mem_0"])
        st = steps(result)
        self.assertEqual([st[k]["status"] for k in ("computes", "sel", "sensors", "kernel")], ["ok", "ok", "ok", "ok"])
        self.assertEqual(st["capacity"]["status"], "warn")   # its SEL is 95% full

    def test_a_longer_window_finds_the_older_error(self):
        result, _seen = run({"compute": "overcloud-novacompute-9", "days": 30})
        st = steps(result)
        self.assertEqual(st["sel"]["status"], "warn")
        self.assertEqual(st["sel"]["table"]["rows"][0][1:3], ["CPU1_C2D1", "Correctable ECC x1"])
        self.assertEqual(st["sel"]["table"]["rows"][0][6], "watch")

    def test_kernel_error_records_are_counted_once_and_boot_lines_left_out(self):
        """A real case: one corrected memory error record of the firmware is a dozen kernel
        lines, and EDAC prints its controllers at every boot: one record, its DIMM named, no EDAC error."""
        k = "Oct 28 23:30:28 overcloud-computealt-1 kernel: "
        text = "\n".join(["@@now 2026-10-30 10:00:00", "@@noipmi ipmitool is not installed on this node", "@@kernel"] + [k + x for x in (
            "EDAC MC: UMC7 chip selects:", "EDAC amd64: MC: 2: 65536MB 3: 65536MB", "EDAC MC0: Giving out device to module skx_edac",
            "{1}[Hardware Error]: Hardware error from APEI Generic Hardware Error Source: 0",
            "{1}[Hardware Error]: It has been corrected by h/w and requires no further action",
            "{1}[Hardware Error]: event severity: corrected", "{1}[Hardware Error]:  Error 0, type: corrected",
            "{1}[Hardware Error]:  fru_text: DIMM Locate:  P1D0", "{1}[Hardware Error]:   section_type: memory error",
            "mce: [Hardware Error]: Machine check events logged")] + ["@@edac", "@@crash", "@@end"])
        res = compute_memory.rate(compute_memory.parse(text), 7)
        kern = res["kernel"]
        self.assertEqual((kern["hw"], kern["hw_fatal"], kern["dimms"], kern["mce"], kern["edac"]), (1, 0, ["P1D0"], 1, 0))
        self.assertEqual(res["status"], "warn")

    def test_a_limit_reached_before_the_window_is_kept(self):
        """DCC dccrhosp-compute-0: DIMM CPU2_C3D0 reached its logging limit on 2026-10-06, a reboot deasserted it on
        2026-10-27, nothing since. A reboot clears the state, not the DIMM: it is listed (watch), not left out."""
        text = "\n".join(["@@now 2026-10-30 10:21:41", "@@bmctime 10/30/2026 10:09:41", "@@sel",
                          "  25 | 10/06/2026 | 14:16:02 | Memory CPU2_C3D0 | Correctable ECC logging limit reached | Asserted",
                          "  29 | 10/27/2026 | 14:43:10 | Memory CPU2_C3D0 | Correctable ECC logging limit reached | Deasserted",
                          "  2a | 10/02/2026 | 01:00:00 | Memory CPU1_C0D0 | Correctable ECC | Asserted",
                          "@@sdr", "CPU2_C3D0        | ABh | ok  | 32.30 | Presence Detected", "@@kernel", "@@edac", "@@crash", "@@end"])
        res = compute_memory.rate(compute_memory.parse(text), 7)
        self.assertEqual(res["dimms"], {})
        self.assertEqual(list(res["history"]), ["CPU2_C3D0"])   # an old correctable error alone is not kept
        self.assertEqual(res["history"]["CPU2_C3D0"]["events"], {"Correctable ECC logging limit reached": 1})
        self.assertEqual(res["status"], "warn")
        self.assertEqual(res["offset"], -0.2)

    def test_a_compute_without_in_band_ipmi(self):
        seen = compute_memory.parse("@@now 2026-10-30 10:00:00\n@@noipmi ipmitool is not installed on this node\n@@kernel\n"
                                    "@@edac\n/sys/devices/system/edac/mc/mc0/ce_count:3\n@@crash\n@@end")
        self.assertEqual(seen["noipmi"], "ipmitool is not installed on this node")
        res = compute_memory.rate(seen, 7)
        self.assertEqual(res["kernel"]["edac_ce"], 3)
        self.assertEqual(res["status"], "warn")
        self.assertIsNone(res["offset"])


if __name__ == "__main__":
    unittest.main()

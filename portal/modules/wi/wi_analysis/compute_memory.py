"""Memory errors (ECC) on the computes (check compute-memory), read-only, every compute of the site or one: which DIMMs
log ECC errors in the BMC event log (SEL), which memory sensors are not normal now, and what the kernel logged about
hardware errors.

Why (a real case): DIMM CPU2_C3D0 of dccrhosp-compute-1 reached its "Correctable ECC logging limit" three times in
three days (its sensor 0x6080, the other DIMMs 0x4080), the firmware reported the errors to the kernel through NMIs
(ghes_notify_nmi took up to 2 s), then CPU 101 hit a hard lockup and the compute crashed with every VM on it. The BMC
had the warning three days before; nobody looked.

Where it reads: on each compute, as the other overcloud reads (through the director), in-band with ipmitool, as sosreport
does: the same SEL and sensors the BMC web page shows, without a BMC account, for every compute of the site at once. The
check "Server hardware (BMC)" (Redfish) stays the way to look at one server when its OS is down. Nothing is changed:
the SEL is never cleared.
"""
import datetime
import re

from . import overcloud
from .common import Result, director, source, unavailable, worst
from .openstack_ops import HOST, node_of
from .overcloud_checks import inventory

MAX_COMPUTES = 60
# a SEL line of ipmitool sel elist: "  30 | 10/27/2026 | 22:43:52 | Memory CPU2_C3D0 | Correctable ECC logging limit reached | Asserted"
SEL_RE = re.compile(r"^\s*([0-9a-fA-F]+)\s*\|\s*(\d{2}/\d{2}/\d{4})\s*\|\s*(\d{2}:\d{2}:\d{2})\s*\|\s*([^|]*?)\s*\|\s*([^|]*?)\s*"
                    r"(?:\|\s*([A-Za-z]+)\s*)?$")
# what an event or a sensor state means for the DIMM: fail = replace it soon (the compute can crash), warn = watch it
FAIL_EVENT = re.compile(r"uncorrectable|logging limit|device disabled|scrub failed|parity", re.I)
WARN_EVENT = re.compile(r"correctable ecc|configuration error|spare|throttl|over-?temp", re.I)
GHES = re.compile(r"NMI handler \(ghes_notify_nmi\) took too long to run: ([\d.]+) msecs")
# one hardware error record of the firmware (APEI / GHES) is many kernel lines: it is counted by its severity line
SEVERITY = re.compile(r"\[Hardware Error\]:\s+event severity: (\w+)")
FRU_DIMM = re.compile(r"DIMM Locate:\s*(\S+)")
MCE_LOGGED = re.compile(r"Machine check events logged|Machine Check Exception")
KERNEL_ERROR = re.compile(r"ghes_notify_nmi|\[Hardware Error\]|Machine check|Machine Check|Memory failure|CMCI storm|hard LOCKUP"
                          r"|Kernel panic|EDAC.*(\b\d+ [CU]E\b|MEMORY ERROR)")   # the lines shown as evidence
EDAC_ERROR = re.compile(r"EDAC.*(\b\d+ [CU]E\b|MEMORY ERROR|\bUE\b.*error|\bCE\b.*error)")   # not its boot lines
GHES_FAIL_MS = 1000   # a CPU held a second or more in the NMI of a hardware error (dccrhosp-compute-1: 2011 ms, 2 h before)
CRASH_RE = re.compile(r"(\d{4}-\d{2}-\d{2})-(\d{2}:\d{2}:\d{2})")
KLOG_TIME = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2}) (\d{2}:\d{2}:\d{2})")   # journalctl short: "Oct 30 06:28:34 host kernel: ..."


def parse(text):
    """The output of the mem_ecc read -> {"now": UTC datetime, "boot": its last boot on the compute's clock, "tz": that
    clock - UTC, "bmc": BMC clock datetime, "bmcip": its LAN address, "serial": the server's serial number, "noipmi": why,
    "selinfo": {}, "selfirst": the first SEL entry {"id", "at", "sensor", "dimm", "event", "dir"} or None,
    "sel": [{"id", "at", "sensor", "dimm", "event", "dir"}], "sdr": [{"name", "status", "state"}], "kernel": [lines],
    "edac": {"ce", "ue"}, "crash": [names], "end": bool}."""
    out = {"now": None, "boot": None, "tz": None, "bmc": None, "bmcip": "", "serial": "", "noipmi": "", "selinfo": {},
           "selfirst": None, "sel": [], "sdr": [], "kernel": [], "edac": {"ce": 0, "ue": 0}, "crash": [], "end": False}
    section = ""
    for line in str(text or "").splitlines():
        s = line.strip()
        if s.startswith("@@now "):
            out["now"] = _when(s[6:], "%Y-%m-%d %H:%M:%S")
            continue
        if s.startswith("@@boot"):   # "2026-11-02 10:12:33 +0700": uptime -s and the offset of the compute's clock
            m = re.match(r"@@boot (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?: ([+-])(\d{2})(\d{2}))?", s)
            if m:
                out["boot"] = _when(m.group(1), "%Y-%m-%d %H:%M:%S")
                if m.group(2):
                    tz = datetime.timedelta(hours=int(m.group(3)), minutes=int(m.group(4)))
                    out["tz"] = tz if m.group(2) == "+" else -tz
            continue
        if s.startswith("@@selfirst"):
            out["selfirst"] = _sel_entry(s[len("@@selfirst"):])
            continue
        if s.startswith("@@noipmi"):
            out["noipmi"] = s[8:].strip() or "ipmitool cannot read the BMC"
            continue
        if s.startswith("@@bmcip"):
            out["bmcip"] = s[7:].strip() if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s[7:].strip()) else ""
            continue
        if s.startswith("@@serial"):
            out["serial"] = re.sub(r"[^A-Za-z0-9_.-]", "", s[8:].strip())[:40]
            continue
        if s.startswith("@@bmctime"):
            out["bmc"] = _when(s[9:].strip(), "%m/%d/%Y %H:%M:%S")
            continue
        if s in ("@@selinfo", "@@sel", "@@sdr", "@@kernel", "@@edac", "@@crash"):
            section = s[2:]
            continue
        if s == "@@end":
            out["end"] = True
            continue
        if not s:
            continue
        if section == "selinfo" and ":" in s:
            k, v = s.split(":", 1)
            out["selinfo"][k.strip()] = v.strip()
        elif section == "sel":
            e = _sel_entry(line)
            if e:
                out["sel"].append(e)
        elif section == "sdr":
            p = [x.strip() for x in s.split("|")]
            if len(p) >= 3 and p[0]:
                out["sdr"].append({"name": p[0], "status": p[2].lower(), "state": p[-1] if len(p) >= 5 else ""})
        elif section == "kernel":
            out["kernel"].append(s)
        elif section == "edac":
            m = re.search(r"/(ce|ue)_count:(\d+)$", s)
            if m:
                out["edac"][m.group(1)] += int(m.group(2))
        elif section == "crash":
            out["crash"].append(s)
    return out


def _sel_entry(line):
    m = SEL_RE.match(str(line or ""))
    if not m:
        return None
    sensor = m.group(4)
    return {"id": m.group(1), "at": _when(f"{m.group(2)} {m.group(3)}", "%m/%d/%Y %H:%M:%S"), "sensor": sensor,
            "dimm": re.sub(r"^Memory\s+", "", sensor, flags=re.I) or sensor, "event": m.group(5),
            "dir": (m.group(6) or "Asserted").capitalize()}


def _klog_time(line, now):
    """The time of a kernel line (the compute's clock, journalctl short format has no year: the year of now, the one
    before when that would be in the future)."""
    m = KLOG_TIME.match(str(line or ""))
    if not m or not now:
        return None
    try:
        t = datetime.datetime.strptime(f"{now.year} {m.group(1)} {int(m.group(2)):02d} {m.group(3)}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    return t.replace(year=now.year - 1) if t > now + datetime.timedelta(days=1) else t


def _when(text, fmt):
    try:
        return datetime.datetime.strptime(str(text).strip()[:19], fmt)
    except ValueError:
        return None


def kind(text):
    """'fail', 'warn' or '' for an event or a sensor state of a DIMM."""
    return "fail" if FAIL_EVENT.search(text or "") else "warn" if WARN_EVENT.search(text or "") else ""


def rate(seen, days):
    """What one compute shows: {"dimms": {dimm: {"events": {event: n}, "first", "last", "status"}}, "history": {dimm:
    {"events", "last"}} (limit reached / uncorrectable before the window, nothing since), "sensors": [(name,
    state, status)], "kernel": {..., "last": the last signal, "before_boot": every signal before the last boot},
    "crashes": [...], "status", "notes": [...], "offset": hours BMC clock - UTC, "sel_since": the first SEL entry (else
    its last clear), "sel_cleared": its last clear, "sel_short": the SEL starts inside the window}.
    Both times matter after a DIMM replacement (a real case): its SEL was cleared (9 entries left),
    so no ECC event there covered hours, not the window; and the NMIs and the crash dump of the old DIMM, all before the
    boot after the swap, still rated the compute "fail"."""
    now_bmc = seen["bmc"] or seen["now"]
    since = now_bmc - datetime.timedelta(days=days) if now_bmc else None
    dimms, history = {}, {}
    for e in seen["sel"]:
        k = kind(e["event"])
        if not k or e["dir"].lower().startswith("deassert"):
            continue
        if since and e["at"] and e["at"] < since:
            # before the window: kept only when the DIMM reached its limit or failed then (a reboot deasserts the state, the
            # DIMM stays as it was: its limit reached, then deasserted at a reboot)
            if k == "fail":
                h = history.setdefault(e["dimm"], {"events": {}, "last": e["at"]})
                h["events"][e["event"]] = h["events"].get(e["event"], 0) + 1
                h["last"] = max(h["last"], e["at"])
            continue
        d = dimms.setdefault(e["dimm"], {"events": {}, "first": e["at"], "last": e["at"], "status": "warn"})
        d["events"][e["event"]] = d["events"].get(e["event"], 0) + 1
        if e["at"]:
            d["first"] = min(x for x in (d["first"], e["at"]) if x)
            d["last"] = max(x for x in (d["last"], e["at"]) if x)
        if k == "fail":
            d["status"] = "fail"
    sensors = []
    for x in seen["sdr"]:
        k = kind(x["state"])
        if k and x["status"] != "ns":
            sensors.append((x["name"], x["state"], k))
    ghes = [float(m.group(1)) for line in seen["kernel"] for m in [GHES.search(line)] if m]
    sev = [m.group(1).lower() for line in seen["kernel"] for m in [SEVERITY.search(line)] if m]
    kern = {"ghes": len(ghes), "ghes_max": max(ghes) if ghes else 0.0, "hw": len(sev),
            "hw_fatal": sum(1 for x in sev if x != "corrected"),
            "dimms": sorted({m.group(1) for line in seen["kernel"] for m in [FRU_DIMM.search(line)] if m}),
            "mce": sum(1 for line in seen["kernel"] if MCE_LOGGED.search(line)),
            "edac": sum(1 for line in seen["kernel"] if EDAC_ERROR.search(line)),
            "memfail": sum(1 for line in seen["kernel"] if "Memory failure" in line),
            "lockup": sum(1 for line in seen["kernel"] if re.search(r"hard LOCKUP|Kernel panic", line)),
            "edac_ce": seen["edac"]["ce"], "edac_ue": seen["edac"]["ue"]}
    now_utc = seen["now"]
    now_local = now_utc + seen["tz"] if now_utc and seen["tz"] is not None else now_utc
    crashes, times = [], []
    for name in seen["crash"]:
        m = CRASH_RE.search(name)
        when = _when(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S") if m else None
        # the dump folder is named in the compute's local time: one day of slack
        if when and now_utc and when >= now_utc - datetime.timedelta(days=days + 1):
            crashes.append(name)
            times.append(when)
    # the last hardware error signal (the compute's clock, as the kernel lines and the dump folders carry it)
    times += [t for line in seen["kernel"] if KERNEL_ERROR.search(line) for t in [_klog_time(line, now_local)] if t]
    kern["last"] = max(times) if times else None
    kern["before_boot"] = bool(kern["last"] and seen["boot"] and kern["last"] < seen["boot"])
    history = {d: h for d, h in history.items() if d not in dimms}
    states = [d["status"] for d in dimms.values()] + [k for _n, _s, k in sensors] + ["warn" for _h in history]
    if kern["hw_fatal"] or kern["memfail"] or kern["lockup"] or kern["edac_ue"] or kern["ghes_max"] >= GHES_FAIL_MS or crashes:
        states.append("fail")
    elif kern["ghes"] or kern["hw"] or kern["mce"] or kern["edac"] or kern["edac_ce"]:
        states.append("warn")
    notes = []
    used = seen["selinfo"].get("Percent Used", "")
    pct = re.match(r"(\d+)", used)
    if "true" in seen["selinfo"].get("Overflow", "").lower() or (pct and int(pct.group(1)) >= 90):
        notes.append(f"SEL {used or 'full'} used{', overflow' if 'true' in seen['selinfo'].get('Overflow', '').lower() else ''}: "
                     "new events may not be logged")
        states.append("warn")
    # what time the SEL covers: from its first entry (else its last clear); one that starts inside the window cannot say
    # that no DIMM logged an error in the whole window
    cleared = _when(seen["selinfo"].get("Last Del Time", ""), "%m/%d/%Y %H:%M:%S")
    first = (seen["selfirst"] or {}).get("at")
    sel_since = first or cleared
    sel_short = bool(since and sel_since and sel_since > since)
    if sel_short:
        states.append("warn")
    offset = round((seen["bmc"] - seen["now"]).total_seconds() / 3600, 1) if seen["bmc"] and seen["now"] else None
    return {"dimms": dimms, "history": history, "sensors": sensors, "kernel": kern, "crashes": crashes, "notes": notes, "offset": offset,
            "sel_since": sel_since, "sel_cleared": cleared, "sel_short": sel_short, "status": worst(*states) if states else "ok"}


def clock(offset):
    if offset is None:
        return "?"
    return "UTC" if abs(offset) < 0.2 else f"UTC{offset:+g} h"


def stamp(t):
    return t.strftime("%Y-%m-%d %H:%M") if t else "?"


class ComputeMemory:
    sources = ("undercloud", "overcloud")
    phases = 2

    @staticmethod
    def targets(data, params, ctx):
        """(computes to read, user, problem, how many computes there are)."""
        found, _controllers, user, _version, problem = inventory(data, ctx)
        want = str(params.get("compute") or "").strip()
        if not found:
            return [], user, problem, 0
        if want:
            node = node_of(want, found)
            if not node:
                return [], user, f"{want} is not in the overcloud node list of the undercloud (the name as in openstack compute service list).", 0
            return [node], user, "", 1
        computes = [n for n in found if n["role"] == "compute"]
        return computes[:MAX_COMPUTES], user, "" if computes else "No compute in the overcloud node list.", len(computes)

    @staticmethod
    def reads(phase, data, params, ctx):
        want = str(params.get("compute") or "").strip()
        days = int(params.get("days") or 7)
        if (want and not HOST.match(want)) or not 1 <= days <= 30:
            return {}
        if phase == 1:
            return {"undercloud": dict(overcloud.INVENTORY_READS)}
        targets, user, problem, _total = ComputeMemory.targets(data, params, ctx)
        if problem or not targets or user not in overcloud.USERS:
            return {}
        return {"overcloud": {f"use_mem_{i}": overcloud.read(n["name"], n["ip"], user, "mem_ecc", days)
                              for i, n in enumerate(targets)}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("compute-memory")
        days = int(params.get("days") or 7)
        targets, user, problem, total = ComputeMemory.targets(data, params, ctx)
        if problem or not targets:
            r.step("computes", "The computes", "fail", problem or "No compute to read.")
            return r.done()
        if user not in overcloud.USERS:
            r.step("computes", "The computes", "fail", "No overcloud user (heat-admin / tripleo-admin).")
            return r.done()

        rows, unread, noipmi, rated = [], [], [], []
        for i, n in enumerate(targets):
            item = source(data, f"use_mem_{i}")
            out = "" if unavailable(item) else str(item.get("out") or "")
            if unavailable(item) or "@@end" not in out:
                unread.append(n["name"])
                rows.append([n["name"], n["ip"], (unavailable(item) or "no answer")[:120], "-", "-", "-", "-"])
                continue
            seen = parse(out)
            res = rate(seen, days)
            rated.append((n, seen, res))
            if seen["noipmi"]:
                noipmi.append(n["name"])
            info = seen["selinfo"]
            rows.append([n["name"], n["ip"], f"in-band IPMI not readable: {seen['noipmi']}" if seen["noipmi"] else "read",
                         " / ".join(x for x in (seen["bmcip"], seen["serial"] and f"serial {seen['serial']}") if x) or "-",
                         (f"{info.get('Entries', '?')} entries, {info.get('Percent Used', '?')} used"
                          + (f", since {stamp(res['sel_since'])}" if res["sel_since"] else "")
                          + (f" (cleared {stamp(res['sel_cleared'])})" if res["sel_short"] and res["sel_cleared"] else "")) if info else "-",
                         clock(res["offset"]), stamp(seen["boot"]) if seen["boot"] else "-"])
        more = f" (the first {MAX_COMPUTES} of {total})" if total > len(targets) else ""
        st = "fail" if not rated else "warn" if unread or noipmi else "ok"
        r.step("computes", "The computes", st,
               f"{len(rated)} of {len(targets)} compute(s) read{more}"
               + (f"; not reachable: {', '.join(unread)}" if unread else "")
               + (f"; their BMC event log cannot be read in-band (check \"Server hardware (BMC)\" for each): {', '.join(noipmi)}"
                  if noipmi else "") + ". BMC clock: the time the SEL entries carry (compared with the UTC time of the compute). "
               "The health page of a BMC shows the state of its sensors now: an event that passed, or a DIMM at its "
               "correctable ECC logging limit (the BMC rates it \"ok\"), keeps it green; its event log keeps them. "
               "SEL since: its first entry, the time it covers. Booted: the last boot, on the compute's clock.",
               {"columns": ["Compute", "IP", "Read", "BMC (web page) / server", "BMC event log (SEL)", "BMC clock", "Booted"],
                "rows": rows},
               marks=unread + noipmi)

        # ---- 2. DIMMs with ECC events in the SEL of the window
        rows, bad, watch, earlier = [], [], [], []
        short = [f"{n['name']} (since {stamp(res['sel_since'])}" + (f", cleared {stamp(res['sel_cleared'])}" if res["sel_cleared"] else "")
                 + ")" for n, seen, res in rated if res["sel_short"]]
        for n, seen, res in rated:
            now_state = {name: state for name, state, _k in res["sensors"]}
            for dimm, d in sorted(res["dimms"].items()):
                rows.append([n["name"], dimm, "; ".join(f"{ev} x{c}" for ev, c in sorted(d["events"].items())),
                             stamp(d["first"]), stamp(d["last"]), now_state.get(dimm, "-"),
                             "REPLACE SOON" if d["status"] == "fail" else "watch"])
                (bad if d["status"] == "fail" else watch).append(f"{n['name']} {dimm}")
            for dimm, h in sorted(res["history"].items()):
                rows.append([n["name"], dimm, "; ".join(f"{ev} x{c}" for ev, c in sorted(h["events"].items())) + " (before the window)",
                             "-", stamp(h["last"]), now_state.get(dimm, "-"), "earlier: watch"])
                earlier.append(f"{n['name']} {dimm}")
        r.step("sel", f"DIMMs with ECC events in the BMC event log (last {days} days)",
               "fail" if bad else "warn" if watch or earlier or short else "ok",
               (f"{len(bad)} DIMM(s) reached the correctable ECC logging limit or logged an uncorrectable error: "
                f"{', '.join(bad)}. Replace them soon: dccrhosp-compute-1 crashed three days after the first such entry. " if bad else "")
               + (f"{len(watch)} DIMM(s) logged correctable ECC errors: {', '.join(watch)}; watch them (run this check again). "
                  if watch else "")
               + (f"{len(earlier)} DIMM(s) reached the limit or failed before the window and logged nothing since: "
                  f"{', '.join(earlier)}. A reboot clears that state, not the DIMM: include them in the hardware case. " if earlier else "")
               + ("" if bad or watch or earlier else f"No DIMM logged an ECC error in the BMC event log of the last {days} days"
                  + (" that the logs hold. " if short else "."))
               + (f"The BMC event log of {len(short)} compute(s) starts inside the window: {', '.join(short)}. It holds "
                  "nothing from before (it was cleared, e.g. at a DIMM replacement): for them \"no ECC event\" covers only the "
                  "time since, and their earlier DIMM errors are not in it. Run this check again over the next days." if short else ""),
               {"columns": ["Compute", "DIMM", "Events (asserted)", "First", "Last", "Sensor now", "Verdict"], "rows": rows},
               evidence=[f"{n['name']}: {e['id']} (#{int(e['id'], 16)}) | {stamp(e['at'])} | {e['sensor']} | {e['event']} | {e['dir']}"
                         for n, seen, res in rated for e in seen["sel"] if kind(e["event"])][-60:],
               marks=bad)

        # ---- 3. memory sensors not normal now
        rows = [[n["name"], name, state, "fail" if k == "fail" else "warn"] for n, seen, res in rated for name, state, k in res["sensors"]]
        r.step("sensors", "Memory sensors now", worst(*[x[3] for x in rows]) if rows else "ok",
               (f"{len(rows)} memory sensor(s) are not normal now (ipmitool sdr type Memory); \"logging limit reached\" is the "
                "state 0x6080 of ipmitool sensor (normal: 0x4080, presence detected)." if rows else
                "Every memory sensor read is normal now (presence detected only)."),
               {"columns": ["Compute", "Sensor", "State", "Rating"], "rows": rows}, marks=[x[1] for x in rows if x[3] == "fail"])

        # ---- 4. what the kernel logged about hardware errors
        rows, crit, old = [], [], []
        for n, seen, res in rated:
            k = res["kernel"]
            if not (k["ghes"] or k["hw"] or k["mce"] or k["edac"] or k["memfail"] or k["lockup"] or k["edac_ce"] or k["edac_ue"]
                    or res["crashes"]):
                continue
            hot = k["hw_fatal"] or k["memfail"] or k["lockup"] or k["edac_ue"] or k["ghes_max"] >= GHES_FAIL_MS or res["crashes"]
            if hot:
                crit.append(n["name"])
            rows.append([n["name"], f"{k['ghes']} (max {k['ghes_max']:g} ms)" if k["ghes"] else "-",
                         (f"{k['hw']} ({k['hw_fatal']} not corrected)" + (f", DIMM {', '.join(k['dimms'])}" if k["dimms"] else ""))
                         if k["hw"] else "-",
                         f"{k['edac']} line(s), CE {k['edac_ce']}, UE {k['edac_ue']}" if k["edac"] or k["edac_ce"] or k["edac_ue"] else "-",
                         k["mce"] or "-", k["lockup"] or "-", ", ".join(res["crashes"]) or "-",
                         (stamp(k["last"]) + (f", before the boot of {stamp(seen['boot'])}" if k["before_boot"] else "")) if k["last"] else "-"])
            if k["before_boot"]:
                old.append(f"{n['name']} (booted {stamp(seen['boot'])})")
        r.step("kernel", f"Kernel hardware error signals (last {days} days)", "fail" if crit else "warn" if rows else "ok",
               ((f"{len(crit)} compute(s) with an uncorrected error, a lockup / panic, a crash dump or a hardware-error NMI "
                 f"of {GHES_FAIL_MS} ms or more: {', '.join(crit)}. " if crit else "")
                + ("ghes_notify_nmi \"took too long\": the firmware reports a hardware error (APEI firmware first) and holds a "
                   "CPU meanwhile; on dccrhosp-compute-1 it grew from 1 ms to 2 s in two days, then the compute crashed."
                   if rows else f"No hardware error, machine check, lockup or crash dump in the kernel log of the last {days} days.")
                + (f" Every signal of {', '.join(old)} is from before its last boot: if a DIMM was replaced at that boot, "
                   "they are the old DIMM's history (run this check with days=1 a day after the boot to read the new boot "
                   "only); if nothing was replaced, the same DIMM is in it and the rating stands (a reboot clears the BMC "
                   "state, not the DIMM)." if old else "")),
               {"columns": ["Compute", "GHES NMI too long", "Hardware error records", "EDAC", "Machine checks logged",
                            "Lockup / panic", "Crash dumps", "Last signal (compute clock)"],
                "rows": rows},
               evidence=[f"{n['name']}: {line}" for n, seen, res in rated for line in seen["kernel"] if KERNEL_ERROR.search(line)][-60:],
               marks=crit)

        # ---- 5. the SEL itself: full logs lose new events
        notes = [[n["name"], note] for n, seen, res in rated for note in res["notes"]]
        r.step("capacity", "BMC event log capacity", "warn" if notes else "ok",
               ("A full BMC event log may not log new ECC events: export it (check \"Logs for a vendor support case\" / BMC) "
                "before it is cleared on the BMC." if notes else "No BMC event log read is full."),
               {"columns": ["Compute", "Note"], "rows": notes})

        # ---- what to do
        where = director(ctx)
        hosts = list(dict.fromkeys([x.split(" ")[0] for x in bad] + crit))
        kernel_why = {}
        for n, seen, res in rated:
            k = res["kernel"]
            kernel_why[n["name"]] = "kernel hardware errors" + (f" (the last {stamp(k['last'])}, before the boot of "
                                                                f"{stamp(seen['boot'])})" if k["before_boot"] else "")
        if hosts:
            r.recommend("Empty these computes and have their failing DIMMs replaced. Disable nova-compute there (no new VM is "
                        "placed on it), move its VMs with the check \"Live migrate instances of a compute\", then open a "
                        "hardware case with the BMC event log (export it first, never clear it).",
                        [f"openstack compute service set --disable --disable-reason \"DIMM ECC errors: replace\" {h} nova-compute"
                         for h in hosts[:6]],
                        warning="A compute whose DIMM reached its ECC logging limit can crash with every VM on it (dccrhosp-compute-1, "
                                "2026-10-30): empty it first, then the vendor replaces the DIMM; enable it again only after a "
                                "clean memory test and a day without new ECC entries.",
                        where=where, refs=["compute-memory", "compute-drain", "bmc-log-export"],
                        items={"columns": ["Compute", "Why"],
                               "rows": [[h, ", ".join([x.split(" ", 1)[1] for x in bad if x.split(" ")[0] == h]
                                                      + ([kernel_why.get(h, "kernel hardware errors")] if h in crit else []))]
                                        for h in hosts]})
        if watch or earlier:
            r.recommend("Watch the DIMMs with correctable errors or an earlier limit. Run this check again every day: when a "
                        "DIMM keeps logging, or reaches its logging limit again, plan its replacement after emptying the compute.",
                        [], where=where, refs=["compute-memory"],
                        items={"columns": ["Compute", "DIMM"], "rows": [x.split(" ", 1) for x in watch + earlier]})
        if noipmi:
            r.recommend("Read the BMC of the computes whose event log cannot be read in-band. Use the check \"Server hardware "
                        "(BMC)\" (Redfish) for each of them.", [], where="the portal", refs=["bmc-health"],
                        items={"columns": ["Compute"], "rows": [[x] for x in noipmi]})
        return r.done()

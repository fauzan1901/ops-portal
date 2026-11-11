"""Hardware health of one server through its BMC (page BMC): Redfish over HTTPS on the management IP, GET only, with the
BMC web account. Lenovo XClarity Controller (XCC, XCC2, XCC3) and Inspur BMCs, and any other Redfish BMC.

Every resource is found by following the links of the service (no fixed IDs: Lenovo uses Systems/1, Inspur Systems/1,
Self or system), because vendors and firmware differ:
  - Lenovo: event logs under Systems/1/LogServices (ActiveLog = alerts active now, PlatformLog = hardware events,
    StandardLog on older systems); entries carry the Lenovo event ID (Oem.Lenovo.CommonEventID, FQXSP...).
  - Inspur: event logs under Managers/1/LogServices (SEL, Alarms on newer firmware), 100 entries per page (the newest
    page is read with $skip / $top); Storage may be linked as .../Storages.
Health values outside OK / Warning / Critical ("NA", null) count as unknown. Power and thermal are read from the old
Power / Thermal resources (both vendors), with PowerSubsystem / ThermalSubsystem status when the BMC has them.
"""
import datetime
import re

from . import references
from .common import Result, json_of, source, unavailable, worst

ROOT = "/redfish/v1"
PATH_OK = re.compile(r"^/redfish/v1(/[A-Za-z0-9_\-.:]+)*$")   # the characters wi_analysis.REST_PATH allows
LOG_PREFER = ("activelog", "alarms", "platformlog", "standardlog", "sel", "log", "eventlog")
LOG_SKIP = ("auditlog", "maintenancelog", "salog", "diagnosticlog", "diaglog", "idl")
ACTIVE_LOGS = ("activelog",)   # Lenovo: the alerts active now; every other log is history (read for the last days)
MAX_DRIVES = 24
MAX_DIMMS = 96   # 4 sockets x 6 channels x 2 = 48 on an Inspur NF8260M5; room for larger boards
MAX_CPUS = 8
PAGE = 100
COMPONENTS = (  # component of a finding, from the text of a log entry or the resource: the vendor reference of each
    ("memory", re.compile(r"\bDIMM|memory|\bECC\b|\bPMEM|\bMEM\d", re.I)),
    ("power", re.compile(r"power supply|\bPSU|\bPS ?\d|\bAC lost|input power|power redundan|redundancy.*power", re.I)),
    ("cooling", re.compile(r"\bfan|temperature|thermal|overheat|cooling|inlet", re.I)),
    ("storage", re.compile(r"\bdrive|\bdisk|\bRAID|\bHDD|\bSSD|NVMe|backplane|\barray\b|\bvolume\b", re.I)),
    ("cpu", re.compile(r"processor|\bCPU|\bIERR|MCERR|machine check", re.I)),
)
TITLES = {"memory": "Memory (DIMM)", "power": "Power supplies", "cooling": "Fans and temperature", "storage": "Drives and RAID",
          "cpu": "Processors", "other": "Other hardware events"}
ADVICE = {
    "memory": ("A memory module (DIMM) reports errors. Correctable errors that keep coming announce a failure; an "
               "uncorrectable error stops the server. Move the workloads off the server (vMotion / live migration), then "
               "open a hardware case with the BMC service data so the vendor replaces the DIMM in the slot named below "
               "(see the DIMM slot map of the result)."),
    "power": ("A power supply lost its input or failed: with redundancy lost, one more failure powers the server off. "
              "Check the power cord and the PDU feed of that supply first, then open a hardware case when the supply "
              "itself failed."),
    "cooling": ("A fan failed or a temperature is above its threshold: the server throttles, then shuts down to protect "
                "itself. Check the fan named in the log, the airflow (blanks, cables) and the room / rack inlet temperature."),
    "storage": ("A drive or the RAID controller reports a problem: a degraded array keeps running without redundancy. "
                "Have the drive named in the log replaced (hot swap when the controller supports it) and watch the rebuild."),
    "cpu": ("A processor reports an error (machine check): the server can crash again. Open a hardware case with the "
            "BMC service data."),
    "other": "Read the events below on the BMC web page and open a hardware case with the BMC service data when they repeat.",
}


def oid(x):
    """The path of a link ({"@odata.id": ...} or, on some Inspur firmware, a plain string); "" when not a Redfish path."""
    path = x.get("@odata.id") if isinstance(x, dict) else x
    path = str(path or "").split("#")[0].rstrip("/")
    return path if PATH_OK.match(path) and ".." not in path else ""


def doc(data, key):
    item = source(data, key)
    if unavailable(item):
        return {}
    value = json_of(item)
    return value if isinstance(value, dict) else {}


def members(data, key):
    return [p for p in (oid(m) for m in doc(data, key).get("Members") or []) if p]


def link(obj, name):
    return oid((obj or {}).get(name))


def tail(path):
    return str(path).rstrip("/").split("/")[-1].lower()


def health(status):
    """Redfish Status -> ok | warn | fail | absent | unknown."""
    status = status if isinstance(status, dict) else {}
    if str(status.get("State") or "").lower() == "absent":
        return "absent"
    value = str(status.get("HealthRollup") or status.get("Health") or "").lower()
    return {"ok": "ok", "warning": "warn", "critical": "fail"}.get(value, "unknown")


def component(text):
    for name, pattern in COMPONENTS:
        if pattern.search(str(text or "")):
            return name
    return "other"


# Times of BMC logs: ISO 8601 (Redfish), and the local forms some firmware writes (Inspur SEL: "26-04-18 22:01:32" =
# YY-MM-DD), read in the time zone of the BMC when they carry none.
LOCAL_TIME_FORMATS = ("%Y-%m-%d %H:%M:%S", "%y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%d-%m-%Y %H:%M:%S")


def parse_time(text, tz=None):
    """A timestamp of the BMC -> aware datetime (tz: the BMC's own zone for times without one), or None."""
    raw = str(text or "").strip()
    try:
        value = datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        value = None
        m = re.match(r"^(\S+[ T]\d{1,2}:\d{2}:\d{2})(?:\.\d+)?\s*(?:(?:UTC|GMT)?\s*([+-]\d{2}):?(\d{2}))?", raw)
        if m:
            for fmt in LOCAL_TIME_FORMATS:
                try:
                    value = datetime.datetime.strptime(m.group(1).replace("T", " "), fmt)
                    break
                except ValueError:
                    continue
            if value and m.group(2):
                sign = 1 if m.group(2)[0] == "+" else -1
                value = value.replace(tzinfo=datetime.timezone(sign * datetime.timedelta(hours=int(m.group(2)[1:]), minutes=int(m.group(3)))))
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=tz or datetime.timezone.utc)


def flat(obj, skip=("@odata", "Links", "Actions", "RelatedItem"), limit=400):
    """The values of a Redfish object as "Key: value; ..." (nested OEM fields too, links left out): the detail a BMC
    gives about a part or an event, whatever the vendor calls it."""
    out = []

    def walk(x, path):
        if isinstance(x, dict):
            for k, v in x.items():
                if not any(str(k).startswith(sk) for sk in skip):
                    walk(v, f"{path}.{k}" if path else str(k))
        elif isinstance(x, list):
            for i, v in enumerate(x[:8]):
                walk(v, f"{path}[{i}]")
        elif x not in (None, "", [], {}):
            out.append(f"{path.split('.')[-1] if path.count('.') > 1 else path}: {x}")
    walk(obj or {}, "")
    text = "; ".join(out)
    return text if len(text) <= limit else text[:limit] + " …"


# Slot names of DIMMs: CPU2_CH2_DIMM0 (Inspur M5), CPU0_C1D0 (Inspur M6), CPU1_DIMM_A1, P1-DIMMA1 -> (CPU, channel, DIMM)
SLOT_PATTERNS = (
    re.compile(r"CPU\s*_?(\d+)[_\s-]*CH(?:ANNEL)?\s*_?([0-9A-Z]+)[_\s-]*DIMM\s*_?(\d+)", re.I),
    re.compile(r"CPU\s*_?(\d+)[_\s-]*C(\d+)\s*D(\d+)", re.I),
    re.compile(r"(?:CPU|P)\s*_?(\d+)[_\s-]*DIMM\s*_?([A-Z])(\d+)", re.I),
)


def slot_parts(name, loc=None):
    """(CPU, channel, DIMM) of a memory slot, from MemoryLocation or the slot name; None when not recognised."""
    loc = loc if isinstance(loc, dict) else {}
    if loc.get("Socket") is not None and loc.get("Channel") is not None:
        return str(loc["Socket"]), str(loc["Channel"]), str(loc.get("Slot") if loc.get("Slot") is not None else "")
    for rx in SLOT_PATTERNS:
        m = rx.search(str(name or ""))
        if m:
            return m.group(1), m.group(2).upper(), m.group(3)
    return None


def natural(value):
    return [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", str(value))]


def status_text(status):
    status = status if isinstance(status, dict) else {}
    return "/".join(str(status.get(k)) for k in ("State", "Health") if status.get(k)) or "-"


def num(value):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def vendor_of(data, ctx):
    names = " ".join(str(x or "") for x in (doc(data, "root").get("Vendor"), doc(data, "sys").get("Manufacturer"),
                                              ctx.get("bmc_vendor"))).lower()
    oem = doc(data, "root").get("Oem") or {}
    if "lenovo" in names or "Lenovo" in oem:
        return "lenovo"
    if "inspur" in names or "ieit" in names or "Inspur" in oem:
        return "inspur"
    return ctx.get("bmc_vendor") or ""


class BmcHealth:
    """Platform health of a server (not from a KB page): overall health, power supplies and their redundancy, fans and
    temperatures, RAID controllers and drives, the alerts active now and the hardware event log of the last days — from
    its BMC, with the vendor's documentation for what is found."""
    sources = ("redfish",)
    phases = 7

    @staticmethod
    def _logs(data):
        """The event log services worth reading: alerts active now first, then the hardware event log; one per store."""
        found = []
        for key in ("sys_logs", "mgr_logs"):
            for path in members(data, key):
                name = tail(path)
                if name in LOG_SKIP or name not in LOG_PREFER:
                    continue
                found.append(path)
        found.sort(key=lambda p: LOG_PREFER.index(tail(p)))
        return found[:4]

    @staticmethod
    def reads(phase, data, params, ctx):
        """One signed-in GET first (the systems): with a wrong password the BMC sees one failed sign-in per run, not a
        burst that locks the account (XCC locks it after a few failures)."""
        signed_in = phase == 1 or not unavailable(source(data, "systems"))
        if not signed_in:
            return {}
        if phase == 1:
            return {"redfish": {"root": ROOT, "systems": f"{ROOT}/Systems"}}
        if phase == 2:
            systems = members(data, "systems")
            out = {"chassis": f"{ROOT}/Chassis", "managers": f"{ROOT}/Managers"}
            if systems:
                out["sys"] = systems[0]
            return {"redfish": out}
        if phase == 3:
            out = {}
            chassis, managers = members(data, "chassis"), members(data, "managers")
            if chassis:   # the server chassis: Chassis/1 on Lenovo and Inspur, else the first one
                out["chas"] = next((c for c in chassis if tail(c) in ("1", "self", "system", "chassis")), chassis[0])
            if managers:
                out["mgr"] = managers[0]
            sys_ = doc(data, "sys")
            if link(sys_, "LogServices"):
                out["sys_logs"] = link(sys_, "LogServices")
            if link(sys_, "Memory"):          # every DIMM: slot, size, part, serial, health
                out["memory"] = link(sys_, "Memory")
            if link(sys_, "Processors"):
                out["procs"] = link(sys_, "Processors")
            storage = link(sys_, "Storage")
            if storage:
                out["storage"] = storage
                if storage.endswith("/Storages"):   # Inspur: some firmware link .../Storages, which answers 404
                    out["storage2"] = storage[:-1]
            return {"redfish": out}
        if phase == 4:
            out = {}
            chas, mgr = doc(data, "chas"), doc(data, "mgr")
            for key, obj, name in (("power", chas, "Power"), ("thermal", chas, "Thermal"), ("psub", chas, "PowerSubsystem"),
                                   ("tsub", chas, "ThermalSubsystem"), ("mgr_logs", mgr, "LogServices")):
                if link(obj, name):
                    out[key] = link(obj, name)
            stores = members(data, "storage") or members(data, "storage2")
            out.update({f"stor_{i}": p for i, p in enumerate(stores[:4])})
            return {"redfish": out}
        if phase == 5:
            out = {f"logsvc_{i}": p for i, p in enumerate(BmcHealth._logs(data))}
            out.update({f"dimm_{i}": p for i, p in enumerate(members(data, "memory")[:MAX_DIMMS])})
            out.update({f"cpu_{i}": p for i, p in enumerate(members(data, "procs")[:MAX_CPUS])})
            n = 0
            for i in range(4):
                for d in doc(data, f"stor_{i}").get("Drives") or []:
                    if oid(d) and n < MAX_DRIVES:
                        out[f"drive_{n}"] = oid(d)
                        n += 1
            return {"redfish": out}
        if phase == 6:
            out, seen = {}, set()
            for i in range(4):
                entries = link(doc(data, f"logsvc_{i}"), "Entries")
                if entries and entries not in seen:   # Inspur: Systems/1/LogServices/SEL entries are the Managers SEL
                    seen.add(entries)
                    out[f"entries_{i}"] = entries
            return {"redfish": out}
        out = {}   # phase 7: the newest page of a log longer than one page (Inspur: 100 per page, oldest first)
        for i in range(4):
            page = doc(data, f"entries_{i}")
            count = page.get("Members@odata.count")
            if isinstance(count, int) and count > len(page.get("Members") or []) and page.get("Members@odata.nextLink"):
                base = link(doc(data, f"logsvc_{i}"), "Entries")
                if base:
                    out[f"last_{i}"] = f"{base}?%24skip={max(count - PAGE, 0)}&%24top={PAGE}"
        return {"redfish": out}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("bmc-health")
        name = ctx.get("host_name") or "the server"
        days = int(params.get("days") or 7)
        if unavailable(source(data, "systems")):   # the service root answers without sign-in: the systems tell
            reason = unavailable(source(data, "systems"))
            hint = ""
            if "401" in reason or "403" in reason:
                hint = (" The BMC refused the account: check the username and password on the page BMC, and that the account "
                        "may log in to the web page (and is not locked after failed attempts).")
            elif "no answer" in reason or "timed out" in reason.lower() or "connection" in reason.lower() or "urlopen" in reason.lower():
                hint = (" The portal server gets no answer from the BMC on HTTPS: check that the management network of the BMC "
                        "is reachable from the bastion (route, firewall) and that Redfish / HTTPS is enabled on the BMC.")
            r.step("bmc", f"Read the BMC of {name}", "fail", reason + hint)
            return r.done()
        vendor = vendor_of(data, ctx)
        sys_, chas, mgr = doc(data, "sys"), doc(data, "chas"), doc(data, "mgr")
        model = str(sys_.get("Model") or "")

        def refs(comp, event_ids):
            if vendor == "lenovo":
                return references.lenovo(model, comp, event_ids)
            return [f"{vendor}-bmc"] if vendor else []
        where = f"BMC web page of {name} (https://{ctx.get('host_address') or ''})"

        # ---------------- the server ----------------
        r.step("bmc", "Server and BMC", "info",
               f"{sys_.get('Manufacturer') or vendor or '?'} {sys_.get('Model') or ''}, serial {sys_.get('SerialNumber') or '?'}, "
               f"power {sys_.get('PowerState') or '?'}, BMC firmware {mgr.get('FirmwareVersion') or '?'}"
               + (f", Redfish {doc(data, 'root').get('RedfishVersion')}" if doc(data, "root").get("RedfishVersion") else "") + ".")
        findings, event_ids = {}, {}   # component -> [text], [vendor event ID]

        # ---------------- overall health ----------------
        rows = [["Server", sys_.get("Status", {}).get("Health") if isinstance(sys_.get("Status"), dict) else "",
                 health(sys_.get("Status"))]]
        for label, key, comp in (("Memory", "MemorySummary", "memory"), ("Processors", "ProcessorSummary", "cpu")):
            st = (sys_.get(key) or {}).get("Status") if isinstance(sys_.get(key), dict) else None
            if st is not None:
                rows.append([label, (st or {}).get("HealthRollup") or (st or {}).get("Health") or "", health(st)])
                if health(st) in ("warn", "fail"):
                    findings.setdefault(comp, []).append(f"{label} health reported by the BMC: "
                                                         f"{(st or {}).get('HealthRollup') or (st or {}).get('Health')}")
        if chas:
            rows.append(["Chassis", (chas.get("Status") or {}).get("HealthRollup") or (chas.get("Status") or {}).get("Health") or "",
                         health(chas.get("Status"))])
        overall = worst(*[x[2] for x in rows if x[2] in ("ok", "warn", "fail")]) if any(x[2] in ("ok", "warn", "fail") for x in rows) else "skip"
        r.step("health", "Overall health", overall, "As the BMC rates it (OK / Warning / Critical).",
               {"columns": ["Part", "BMC value", "Status"], "rows": [[a, b, c.upper()] for a, b, c in rows]})

        # ---------------- power ----------------
        power = doc(data, "power")
        psus = [p for p in power.get("PowerSupplies") or [] if isinstance(p, dict)]
        redundancy = [x for x in power.get("Redundancy") or [] if isinstance(x, dict)]
        psub = doc(data, "psub")
        redundancy += [x for x in psub.get("PowerSupplyRedundancy") or [] if isinstance(x, dict)]
        prow, pst, absent_psu = [], [], 0
        for p in psus:
            h = health(p.get("Status"))
            if h == "absent":
                absent_psu += 1
                continue
            label = p.get("Name") or p.get("MemberId") or ""
            volts, watts_in = num(p.get("LineInputVoltage")), num(p.get("PowerInputWatts"))
            note = ""
            if volts == 0 and str((p.get("Status") or {}).get("State") or "").lower() == "enabled":
                note = "no input power now (cord / PDU feed)"
                h = worst(h, "warn") if h in ("ok", "warn", "fail") else "warn"
            pst.append(h)
            prow.append([label, p.get("Model") or "", p.get("SerialNumber") or "", p.get("FirmwareVersion") or "",
                         p.get("PowerCapacityWatts") or "", "" if volts is None else volts, "" if watts_in is None else watts_in,
                         status_text(p.get("Status")), h.upper(), note])
            if h in ("warn", "fail"):
                findings.setdefault("power", []).append(
                    [label, note or f"BMC health {(p.get('Status') or {}).get('Health')}", "now",
                     ", ".join(x for x in (p.get("Model"), f"serial {p.get('SerialNumber')}" if p.get("SerialNumber") else "") if x)])
        for x in redundancy:
            h = health(x.get("Status"))
            if h in ("warn", "fail"):
                pst.append(h)
                findings.setdefault("power", []).append(["Power redundancy", f"{x.get('Mode') or x.get('RedundancyType') or ''} "
                                                         f"{(x.get('Status') or {}).get('Health')}".strip(), "now", ""])
        if psus or redundancy:
            red = ", ".join(f"{x.get('Mode') or x.get('RedundancyType') or '?'} {(x.get('Status') or {}).get('Health') or ''}".strip()
                            for x in redundancy)
            r.step("power", "Power supplies", worst(*pst) if any(s in ("ok", "warn", "fail") for s in pst) else "skip",
                   f"{len(prow)} power supply(ies)" + (f", {absent_psu} empty bay(s)" if absent_psu else "")
                   + (f"; redundancy {red}" if red else "") + ".",
                   {"columns": ["Supply", "Model", "Serial", "Firmware", "Capacity W", "Input V", "Input W", "BMC state",
                                "Status", "Note"], "rows": prow},
                   marks=[x[0] for x in prow if x[8] in ("WARN", "FAIL")])
        else:
            r.skip("power", "Power supplies", unavailable(source(data, "power")) or "The BMC lists no power supplies.")

        # ---------------- cooling ----------------
        thermal = doc(data, "thermal")
        fans = [f for f in thermal.get("Fans") or [] if isinstance(f, dict)]
        temps = [t for t in thermal.get("Temperatures") or [] if isinstance(t, dict)]
        crow, cst, missing = [], [], []
        for f in fans:
            h = health(f.get("Status"))
            fname = f.get("Name") or f.get("FanName") or f.get("MemberId") or ""
            reading = num(f.get("Reading"))
            if h == "absent" or (h == "unknown" and not reading):
                missing.append(fname)
                continue
            low = num(f.get("LowerThresholdCritical")) or num(f.get("LowerThresholdFatal"))
            if reading is not None and low and reading <= low:
                h = "fail"
            cst.append(h)
            crow.append([fname, "fan", f"{reading:g} {f.get('ReadingUnits') or ''}".strip() if reading is not None else "",
                         f"critical ≤ {low:g}" if low else "", status_text(f.get("Status")), h.upper()])
            if h in ("warn", "fail"):
                findings.setdefault("cooling", []).append([fname, f"fan {reading if reading is not None else '?'} "
                                                           f"{f.get('ReadingUnits') or ''}, BMC {status_text(f.get('Status'))}", "now", ""])
        for t in temps:
            h = health(t.get("Status"))
            tname = t.get("Name") or t.get("MemberId") or ""
            reading = num(t.get("ReadingCelsius"))
            if h == "absent" or (h in ("unknown",) and not reading):
                missing.append(tname)   # not fitted (GPU, NVMe, OCP slot empty): no reading
                continue
            uw, uc = num(t.get("UpperThresholdNonCritical")), num(t.get("UpperThresholdCritical")) or num(t.get("UpperThresholdFatal"))
            lw, lc = num(t.get("LowerThresholdNonCritical")), num(t.get("LowerThresholdCritical")) or num(t.get("LowerThresholdFatal"))
            margin = "margin" in str(tname).lower()
            note = ""
            if margin:
                # the distance to the maximum temperature of the part (Tjmax): the larger, the cooler; only a small
                # margin is a problem. The BMC's own health of these sensors is shown, the reading decides.
                limits = f"margin critical ≤ {lc:g} °C" if lc else (f"margin warning ≤ {lw:g} °C" if lw else "")
                bmc_h = h
                h = ("fail" if reading is not None and lc is not None and reading <= lc else
                     "warn" if reading is not None and lw is not None and reading <= lw else
                     "ok" if reading is not None and reading >= 10 else bmc_h if bmc_h != "unknown" else "warn")
                if bmc_h in ("warn", "fail") and h == "ok":
                    note = f"the BMC reports {(t.get('Status') or {}).get('Health')}, but {reading:g} °C below the maximum is normal"
            else:
                limits = ", ".join(x for x in (f"warning ≥ {uw:g}" if uw else "", f"critical ≥ {uc:g}" if uc else "") if x)
                if reading is not None and uc and reading >= uc:
                    h = "fail"
                elif reading is not None and uw and reading >= uw and h == "ok":
                    h = "warn"
            cst.append(h)
            crow.append([tname, "temperature (margin)" if margin else "temperature",
                         f"{reading:g} °C" if reading is not None else "", limits, status_text(t.get("Status")),
                         h.upper() + (f" ({note})" if note else "")])
            if h in ("warn", "fail"):
                findings.setdefault("cooling", []).append([tname, f"{reading if reading is not None else '?'} °C"
                                                           + (f" ({limits})" if limits else ""), "now", ""])
        tsub = doc(data, "tsub")
        if tsub and health(tsub.get("Status")) in ("warn", "fail"):
            cst.append(health(tsub.get("Status")))
            crow.append(["Thermal subsystem", "rollup", "", "", status_text(tsub.get("Status")), health(tsub.get("Status")).upper()])
            findings.setdefault("cooling", []).append(["Thermal subsystem", status_text(tsub.get("Status")), "now", ""])
        if fans or temps or tsub:
            bad = [x for x in crow if not x[5].startswith("OK")]
            r.step("cooling", "Fans and temperatures", worst(*[s for s in cst if s in ("ok", "warn", "fail")]) if any(s in ("ok", "warn", "fail") for s in cst) else "skip",
                   (f"{len(fans)} fan(s), {len(temps)} temperature sensor(s): {len(bad)} not OK"
                    + (f"; {len(missing)} without a reading (not fitted: {', '.join(missing[:12])}{' …' if len(missing) > 12 else ''})" if missing else "")
                    + ". Margin sensors show the distance to the maximum temperature: the larger, the cooler.")
                   if fans or temps else "Thermal subsystem status only.",
                   {"columns": ["Sensor", "Kind", "Reading", "Thresholds", "BMC state", "Status"],
                    "rows": sorted(crow, key=lambda x: (x[5].startswith("OK"), x[1], x[0]))},
                   marks=[x[0] for x in crow if x[5].startswith(("FAIL", "WARN"))])
        else:
            r.skip("cooling", "Fans and temperatures", unavailable(source(data, "thermal")) or "The BMC lists no fans or sensors.")

        # ---------------- memory modules and processors ----------------
        dimms = []
        for i in range(MAX_DIMMS):
            d = doc(data, f"dimm_{i}")
            if d:
                dimms.append(d)
        mrow, mst, empty_slots = [], [], 0
        total_slots = len(members(data, "memory")) or len(dimms)
        slot_map = {}   # CPU -> {(channel, DIMM): cell}
        for k, d in enumerate(dimms, 1):
            h = health(d.get("Status"))
            size = num(d.get("CapacityMiB"))
            slot = d.get("DeviceLocator") or d.get("Name") or d.get("Id") or ""
            loc = d.get("MemoryLocation") if isinstance(d.get("MemoryLocation"), dict) else {}
            parts = slot_parts(slot, loc)
            empty = h == "absent" or size == 0
            if parts:
                slot_map.setdefault(parts[0], {})[parts[1:]] = ("empty" if empty else
                                                                f"{h.upper()} {size / 1024:g}G" if size else h.upper())
            if empty:
                empty_slots += 1
                continue
            where_ = (f"CPU {parts[0]} · channel {parts[1]} · DIMM {parts[2]}" if parts else "") + f" · slot {k} of {total_slots} in the BMC's list"
            mst.append(h)
            mrow.append([slot, where_, f"{size / 1024:g} GiB" if size else "",
                         " ".join(str(x) for x in (d.get("MemoryDeviceType"), f"{d.get('OperatingSpeedMhz')} MHz" if d.get("OperatingSpeedMhz") else "") if x),
                         d.get("Manufacturer") or "", d.get("PartNumber") or "", d.get("SerialNumber") or "",
                         status_text(d.get("Status")), h.upper(), flat(d.get("Oem"), limit=200)])
            if h in ("warn", "fail"):
                findings.setdefault("memory", []).append(
                    [f"DIMM {slot} ({where_})", f"BMC health {(d.get('Status') or {}).get('Health')}", "now",
                     ", ".join(x for x in (f"{size / 1024:g} GiB" if size else "", d.get("Manufacturer"), d.get("PartNumber"),
                                           f"serial {d.get('SerialNumber')}" if d.get("SerialNumber") else "") if x)])
        if mrow:
            r.step("memory", "Memory modules (DIMMs)", worst(*[s for s in mst if s in ("ok", "warn", "fail")]) if any(s in ("ok", "warn", "fail") for s in mst) else "skip",
                   f"{len(mrow)} DIMM(s) fitted" + (f", {empty_slots} empty slot(s)" if empty_slots else "")
                   + f"; {sum(1 for x in mrow if x[8] in ('WARN', 'FAIL'))} not OK.",
                   {"columns": ["Slot", "Location", "Size", "Type / speed", "Manufacturer", "Part number", "Serial", "BMC state",
                                "Status", "Vendor detail"], "rows": sorted(mrow, key=lambda x: (x[8] == "OK", x[0]))},
                   marks=[x[0] for x in mrow if x[8] in ("WARN", "FAIL")])
        if slot_map:   # every slot of the board at a glance: one row per CPU, one column per channel / DIMM
            cols = sorted({c for row in slot_map.values() for c in row}, key=lambda c: (natural(c[0]), natural(c[1])))
            grid = [[f"CPU {cpu}"] + [row.get(c, "-") for c in cols] for cpu, row in sorted(slot_map.items(), key=lambda x: natural(x[0]))]
            bad = [g[0] for g in grid if any(str(v).startswith(("WARN", "FAIL")) for v in g[1:])]
            r.step("slots", "DIMM slot map", "info",
                   f"{total_slots} slot(s) listed by the BMC, {total_slots - empty_slots} fitted: each cell is one slot "
                   "(CPU row, channel CH and DIMM D column): OK / WARN / FAIL and its size, or empty."
                   + (f" Not OK on {', '.join(bad)}." if bad else ""),
                   {"columns": ["CPU"] + [f"CH{c[0]} D{c[1]}" for c in cols], "rows": grid}, marks=bad)
        cpus = [doc(data, f"cpu_{i}") for i in range(MAX_CPUS)]
        prow2 = []
        for c in [c for c in cpus if c]:
            h = health(c.get("Status"))
            if h == "absent":
                continue
            prow2.append([c.get("Socket") or c.get("Name") or c.get("Id") or "", c.get("Id") or "", c.get("Model") or "",
                          " / ".join(str(x) for x in (c.get("TotalCores"), c.get("TotalThreads")) if x),
                          c.get("SerialNumber") or (flat(c.get("ProcessorId"), limit=80) if isinstance(c.get("ProcessorId"), dict) else ""),
                          status_text(c.get("Status")), h.upper(), flat(c.get("Oem"), limit=160)])
            if h in ("warn", "fail"):
                findings.setdefault("cpu", []).append([f"Processor {prow2[-1][0]} (BMC Id {prow2[-1][1]})",
                                                       f"BMC health {(c.get('Status') or {}).get('Health')}", "now", c.get("Model") or ""])
        if prow2:
            r.step("cpus", "Processors", worst(*[x[6].lower() for x in prow2 if x[6] in ("OK", "WARN", "FAIL")]) if any(x[6] in ("OK", "WARN", "FAIL") for x in prow2) else "skip",
                   f"{len(prow2)} processor(s); a processor in Warning often comes from its memory (machine check / ECC) or "
                   "its temperature: compare with the DIMM slot map and the event log.",
                   {"columns": ["Socket", "BMC Id", "Model", "Cores / threads", "Serial / ID", "BMC state", "Status", "Vendor detail"],
                    "rows": prow2},
                   marks=[x[0] for x in prow2 if x[6] in ("WARN", "FAIL")])

        # ---------------- storage ----------------
        srow, sst = [], []
        for i in range(4):
            s = doc(data, f"stor_{i}")
            if not s:
                continue
            for c in s.get("StorageControllers") or []:
                if isinstance(c, dict):
                    h = health(c.get("Status"))
                    if h != "absent":
                        sst.append(h)
                        srow.append([c.get("Name") or c.get("Model") or s.get("Name") or "", "controller", c.get("Model") or "",
                                     (c.get("Status") or {}).get("Health") or "", h.upper()])
            if not s.get("StorageControllers"):
                h = health(s.get("Status"))
                if h != "absent":
                    sst.append(h)
                    srow.append([s.get("Name") or s.get("Id") or "", "storage", "", (s.get("Status") or {}).get("Health") or "", h.upper()])
        for n in range(MAX_DRIVES):
            d = doc(data, f"drive_{n}")
            if not d:
                continue
            h = health(d.get("Status"))
            if h == "absent":
                continue
            sst.append(h)
            srow.append([d.get("Name") or d.get("Id") or "", "drive",
                         f"{d.get('MediaType') or ''} {round((d.get('CapacityBytes') or 0) / 1e9)} GB".strip() if d.get("CapacityBytes") else d.get("MediaType") or "",
                         (d.get("Status") or {}).get("Health") or "", h.upper()])
        for x in srow:
            if x[4] in ("WARN", "FAIL"):
                findings.setdefault("storage", []).append(f"{x[0]} ({x[1]}): {x[3]}")
        if srow:
            r.step("storage", "RAID controllers and drives", worst(*[s for s in sst if s in ("ok", "warn", "fail")]) if any(s in ("ok", "warn", "fail") for s in sst) else "skip",
                   f"{sum(1 for x in srow if x[1] == 'drive')} drive(s) read; {sum(1 for x in srow if x[4] not in ('OK', 'UNKNOWN'))} not OK.",
                   {"columns": ["Name", "Kind", "Detail", "BMC value", "Status"], "rows": srow},
                   marks=[x[0] for x in srow if x[4] == "FAIL"])
        else:
            r.skip("storage", "RAID controllers and drives",
                   "No RAID controller or drive reported by the BMC (direct-attached / M.2 / NVMe drives are not always listed).")

        # ---------------- event logs ----------------
        bmc_now = parse_time(mgr.get("DateTime"))
        tz = bmc_now.tzinfo if bmc_now else None
        now = bmc_now or datetime.datetime.now(datetime.timezone.utc)
        since = now - datetime.timedelta(days=days)
        dimm_names = sorted({str(x) for d in dimms for x in (d.get("DeviceLocator"), d.get("Name")) if x and len(str(x)) >= 3},
                            key=len, reverse=True)
        active_rows, recent_rows, levels_active, levels_recent = [], [], [], []
        older, undated, resolved_n = 0, 0, 0
        for i in range(4):
            svc = doc(data, f"logsvc_{i}")
            if not svc or not doc(data, f"entries_{i}"):
                continue
            log_name = tail(BmcHealth._logs(data)[i]) if i < len(BmcHealth._logs(data)) else str(svc.get("Id") or "")
            entries = {}
            for key in (f"entries_{i}", f"last_{i}"):
                for e in doc(data, key).get("Members") or []:
                    if isinstance(e, dict):
                        entries[str(e.get("Id") or e.get("@odata.id") or len(entries))] = e
            active = log_name in ACTIVE_LOGS
            # an assertion followed by its deassertion (same sensor, same event) is over: shown, not a finding
            timed = sorted(((parse_time(e.get("Created"), tz), e) for e in entries.values()),
                           key=lambda x: (x[0] is None, x[0] or now))
            cleared = {}
            for created, e in timed:
                text = str(e.get("Message") or "")
                deassert = str(e.get("EntryCode") or "").lower() == "deassert" or re.search(r"de-?asserted\s*$", text, re.I)
                base = re.sub(r"[-\s]*(de-?)?asserted\s*$", "", text, flags=re.I).strip().lower()
                k = (str(e.get("SensorType") or ""), str(e.get("SensorNumber") or ""), base)
                if deassert and created:
                    cleared[k] = max(cleared.get(k) or created, created)
            for created, e in reversed(timed):
                sev = str(e.get("Severity") or e.get("MessageSeverity") or "").lower()
                level = {"critical": "fail", "warning": "warn"}.get(sev)
                text = str(e.get("Message") or "")
                if not level or str(e.get("EntryCode") or "").lower() == "deassert" or re.search(r"de-?asserted\s*$", text, re.I):
                    continue
                if not active and created is None:
                    undated += 1
                    continue
                if not active and created < since:
                    older += 1
                    continue
                base = re.sub(r"[-\s]*(de-?)?asserted\s*$", "", text, flags=re.I).strip().lower()
                k = (str(e.get("SensorType") or ""), str(e.get("SensorNumber") or ""), base)
                over = cleared.get(k)
                resolved = bool(over and created and over >= created)
                event_id = str(((e.get("Oem") or {}).get("Lenovo") or {}).get("CommonEventID") or e.get("MessageId") or e.get("EventId") or "")
                detail = flat({k2: v for k2, v in e.items() if k2 not in ("Id", "Name", "Created", "Message", "Severity",
                                                                          "MessageSeverity", "EntryType", "MessageId")}, limit=300)
                comp = component(" ".join([text, str(e.get("SensorType") or ""), event_id]))
                sensor = " #".join(str(x) for x in (e.get("SensorType"), e.get("SensorNumber")) if x not in (None, ""))
                part = next((n for n in dimm_names if n.lower() in (text + " " + detail).lower()), "") if comp == "memory" else ""
                state = f"over: deasserted {over.strftime('%Y-%m-%d %H:%M')}" if resolved else "active (not deasserted)"
                when = created.astimezone(tz or datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if created else str(e.get("Created") or "")[:19]
                row = [when, e.get("Severity") or e.get("MessageSeverity"), TITLES[comp], event_id, text[:220],
                       sensor + (f" → DIMM {part}" if part else ""), state, detail]
                (active_rows if active else recent_rows).append(row)
                if resolved:
                    resolved_n += 1
                    continue
                (levels_active if active else levels_recent).append(level)
                findings.setdefault(comp, []).append([f"DIMM {part}" if part else (sensor or TITLES[comp]), text[:160], when, detail[:200]])
                if event_id:
                    event_ids.setdefault(comp, []).append(event_id)
        logs_read = [tail(p) for p in BmcHealth._logs(data)]
        cols = ["Time", "Severity", "Component", "Event ID", "Message", "Sensor / part", "State", "Detail from the BMC"]
        if any(n in ACTIVE_LOGS for n in logs_read):
            r.step("active", "Alerts active now", worst(*levels_active) if levels_active else "ok",
                   f"{len(active_rows)} active warning / critical alert(s)." if active_rows else "No active alert.",
                   {"columns": cols, "rows": active_rows[:100]},
                   marks=[x[3] or x[4][:40] for x in active_rows if x[1] and str(x[1]).lower() == "critical"])
        if any(n not in ACTIVE_LOGS for n in logs_read):
            extra = "; ".join(x for x in (f"{resolved_n} of them were deasserted later (over)" if resolved_n else "",
                                          f"{older} older warning / critical event(s) not counted" if older else "",
                                          f"{undated} with a time the BMC writes in an unknown form (not counted)" if undated else "") if x)
            r.step("events", f"Hardware event log (last {days} days)", worst(*levels_recent) if levels_recent else "ok",
                   (f"{len(recent_rows)} warning / critical event(s) since {since.strftime('%Y-%m-%d %H:%M')} (BMC time)."
                    if recent_rows else f"No warning or critical event since {since.strftime('%Y-%m-%d %H:%M')} (BMC time).")
                   + (f" {extra[0].upper() + extra[1:]}." if extra else "")
                   + " Every event, with all its fields, is in the export Collect BMC event logs.",
                   {"columns": cols, "rows": recent_rows[:150]})
        if not logs_read:
            r.skip("events", "Hardware event log", unavailable(source(data, "sys_logs")) or "The BMC lists no event log the account can read.")

        # ---------------- what to do, per component, with the vendor reference ----------------
        for comp in ("memory", "power", "cooling", "storage", "cpu", "other"):
            items = findings.get(comp)
            if not items:
                continue
            rows = list(dict.fromkeys(tuple(str(c) for c in (x if isinstance(x, list) else [TITLES[comp], x, "", ""])) for x in items))
            r.recommend(f"{TITLES[comp]} of {name}: {ADVICE[comp]}", [], where=where,
                        warning="Before a part is replaced, move the workloads off the server (vMotion / live migration) or "
                                "agree on a maintenance window: a hot swap is only safe for parts the vendor marks hot-swappable.",
                        refs=refs(comp, event_ids.get(comp, [])),
                        items={"columns": ["Part", "Finding", "When", "Detail"], "rows": [list(x) for x in rows[:40]]})
        return r.done()

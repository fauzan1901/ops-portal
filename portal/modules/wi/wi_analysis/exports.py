"""Full event logs to download (permission "collect logs"): the event logs of a server's BMC (Redfish, every log service,
every page), the EMS events of ONTAP and every event of vCenter for a time window. Read-only, with the accounts the
other checks use. The run page shows a summary and the newest entries; every entry is in the raw output of the run as
CSV (export/<name>.csv), made from the reads kept for 7 days (export()).
"""
import csv
import datetime
import io
import re
import urllib.parse

from . import hardware
from .common import Result, json_of, source, unavailable
from .logs import tz_of

MAX_BMC_ENTRIES = 5000
ONTAP_PAGE = 1000
ONTAP_PAGES = 10
SHOWN = 200


def csv_text(columns, rows):
    out = io.StringIO()
    out.write("﻿")   # Excel: UTF-8
    w = csv.writer(out)
    w.writerow(columns)
    for r in rows:
        w.writerow(["'" + c if isinstance(c, str) and c[:1] in ("=", "+", "-", "@") and not re.match(r"^-?\d", c) else c
                    for c in r])
    return out.getvalue()


def count_table(values, title):
    counts = {}
    for v in values:
        counts[v or "-"] = counts.get(v or "-", 0) + 1
    return {"columns": [title, "Entries"], "rows": sorted(([k, v] for k, v in counts.items()), key=lambda x: -x[1])}


def since_iso(params, ctx, unit="hours"):
    now = int(ctx.get("now") or 0) or int(datetime.datetime.now().timestamp())
    amount = int(params.get(unit) or (24 if unit == "hours" else 30))
    delta = datetime.timedelta(hours=amount) if unit == "hours" else datetime.timedelta(days=amount)
    return (datetime.datetime.fromtimestamp(now, datetime.timezone.utc) - delta).replace(microsecond=0)


# ---------------------------------------------------------------- BMC (Redfish)
class BmcLogs:
    """Every entry of every event log of one BMC (system event log, platform / active alerts, audit log), page by page."""
    sources = ("redfish",)
    phases = 7

    @staticmethod
    def reads(phase, data, params, ctx):
        signed_in = phase == 1 or not unavailable(source(data, "systems"))
        if not signed_in:
            return {}
        if phase == 1:
            return {"redfish": {"root": hardware.ROOT, "systems": f"{hardware.ROOT}/Systems"}}
        if phase == 2:
            systems = hardware.members(data, "systems")
            out = {"managers": f"{hardware.ROOT}/Managers"}
            if systems:
                out["sys"] = systems[0]
            return {"redfish": out}
        if phase == 3:
            out = {}
            managers = hardware.members(data, "managers")
            if managers:
                out["mgr"] = managers[0]
            if hardware.link(hardware.doc(data, "sys"), "LogServices"):
                out["sys_logs"] = hardware.link(hardware.doc(data, "sys"), "LogServices")
            return {"redfish": out}
        if phase == 4:
            logs = hardware.link(hardware.doc(data, "mgr"), "LogServices")
            return {"redfish": {"mgr_logs": logs}} if logs else {}
        if phase == 5:
            paths = list(dict.fromkeys(hardware.members(data, "sys_logs") + hardware.members(data, "mgr_logs")))[:8]
            return {"redfish": {f"logsvc_{i}": p for i, p in enumerate(paths)}}
        if phase == 6:
            out, seen = {}, set()
            for i in range(8):
                entries = hardware.link(hardware.doc(data, f"logsvc_{i}"), "Entries")
                if entries and entries not in seen:   # Inspur: the SEL of Systems and of Managers are the same entries
                    seen.add(entries)
                    out[f"entries_{i}"] = entries
            return {"redfish": out}
        out = {}   # phase 7: the other pages of a long log ($skip / $top, as the BMC's own next link)
        for i in range(8):
            page = hardware.doc(data, f"entries_{i}")
            count, first = page.get("Members@odata.count"), len(page.get("Members") or [])
            base = hardware.link(hardware.doc(data, f"logsvc_{i}"), "Entries")
            if isinstance(count, int) and first and count > first and page.get("Members@odata.nextLink") and base:
                for j, skip in enumerate(range(first, min(count, MAX_BMC_ENTRIES), first)):
                    out[f"page_{i}_{j}"] = f"{base}?%24skip={skip}&%24top={first}"
        return {"redfish": out}

    @staticmethod
    def entries(data):
        """[(log name, entry)] of every log read, and [(log name, entries read, total)]."""
        rows, logs = [], []
        for i in range(8):
            page = hardware.doc(data, f"entries_{i}")
            if not page:
                continue
            svc = hardware.doc(data, f"logsvc_{i}")
            name = ("Manager " if "/Managers/" in hardware.oid(svc) else "System ") + str(svc.get("Name") or svc.get("Id") or i)
            found = list(page.get("Members") or [])
            j = 0
            while f"page_{i}_{j}" in data:
                found += hardware.doc(data, f"page_{i}_{j}").get("Members") or []
                j += 1
            logs.append((str(name), len(found), page.get("Members@odata.count") or len(found)))
            rows += [(str(name), e) for e in found if isinstance(e, dict)]
        rows.sort(key=lambda x: str(x[1].get("Created") or ""), reverse=True)
        return rows, logs

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("bmc-log-export")
        bmc = ctx.get("host_name") or params.get("bmc") or "the BMC"
        if unavailable(source(data, "systems")):
            r.step("bmc", "Sign in to the BMC (Redfish)", "fail", unavailable(source(data, "systems")))
            return r.done()
        rows, logs = BmcLogs.entries(data)
        if not logs:
            r.step("logs", "Event logs of the BMC", "warn", "The BMC lists no event log with entries (LogServices).")
            return r.done()
        days = int(params.get("days") or 30)
        since = since_iso(params, ctx, "days")
        recent = [(n, e) for n, e in rows if (hardware.parse_time(e.get("Created")) or since) >= since]
        r.step("logs", "Event logs of the BMC", "ok", f"{len(rows)} entries read from {len(logs)} log(s) of {bmc}.",
               {"columns": ["Log", "Entries read", "Entries in the log"], "rows": [list(x) for x in logs]})
        r.step("severity", f"Entries of the last {days} days by severity", "info",
               f"{len(recent)} of {len(rows)} entries are from the last {days} days.",
               count_table([str(e.get("Severity") or "") for _n, e in recent], "Severity"))
        r.step("entries", "Newest entries", "info", f"The newest {min(SHOWN, len(recent))} of the last {days} days; every entry is "
               "in the raw output of this run (export/bmc-events.csv).",
               {"columns": ["Created", "Log", "Severity", "Message ID", "Message"],
                "rows": [[e.get("Created") or "", n, e.get("Severity") or "", e.get("MessageId") or "", str(e.get("Message") or "")[:400]]
                         for n, e in recent[:SHOWN]]})
        r.recommend("Download every entry with the button Raw output (.zip) at the top of this page: export/bmc-events.csv (one "
                    "line per entry, every log), with the Redfish answers under reads/redfish/.", where="this portal",
                    refs=["lenovo-bmc", "inspur-bmc"])
        return r.done(f"{len(rows)} BMC log entries of {bmc} ({len(recent)} in the last {days} days).")

    @staticmethod
    def export(data, params):
        rows, _logs = BmcLogs.entries(data)
        return {"bmc-events.csv": csv_text(
            ["Created", "Log", "Id", "Severity", "Message ID", "Entry type", "Sensor type", "Message"],
            [[e.get("Created") or "", n, e.get("Id") or "", e.get("Severity") or "", e.get("MessageId") or "",
              e.get("EntryType") or "", e.get("SensorType") or "", e.get("Message") or ""] for n, e in rows])}


# ---------------------------------------------------------------- ONTAP EMS
SEVERITIES = {"all": "", "notice": "emergency|alert|error|notice", "error": "emergency|alert|error"}
EMS_FIELDS = "time,node.name,message.severity,message.name,log_message,index,source"


def next_path(page):
    """The next page of an ONTAP answer (_links.next.href), with the characters wi_analysis.REST_PATH does not take
    percent-encoded."""
    href = str(((page or {}).get("_links") or {}).get("next", {}).get("href") or "")
    if not href.startswith("/api/"):
        return ""
    return re.sub(r"[^A-Za-z0-9_\-./:?=&|%,;]", lambda m: urllib.parse.quote(m.group(), safe=""), href)


class OntapEms:
    """Every EMS event of the cluster for a time window (newest first, page by page)."""
    sources = ("ontap",)
    phases = ONTAP_PAGES

    @staticmethod
    def first(params, ctx):
        since = since_iso(params, ctx).isoformat()
        sev = SEVERITIES.get(params.get("severity") or "all", "")
        return (f"/api/support/ems/events?fields={EMS_FIELDS}&time=%3E{urllib.parse.quote(since, safe='')}"
                + (f"&message.severity={sev}" if sev else "") + f"&order_by=time%20desc&max_records={ONTAP_PAGE}")

    @staticmethod
    def reads(phase, data, params, ctx):
        if phase == 1:
            return {"ontap": {"ems_0": OntapEms.first(params, ctx)}}
        prev = source(data, f"ems_{phase - 2}")
        nxt = "" if unavailable(prev) else next_path(json_of(prev))
        return {"ontap": {f"ems_{phase - 1}": nxt}} if nxt else {}

    @staticmethod
    def events(data):
        out, i = [], 0
        while f"ems_{i}" in data and not unavailable(source(data, f"ems_{i}")):
            out += [e for e in (json_of(source(data, f"ems_{i}")) or {}).get("records") or [] if isinstance(e, dict)]
            i += 1
        more = bool(i) and bool(next_path(json_of(source(data, f"ems_{i - 1}")))) and i >= ONTAP_PAGES
        return out, more

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("ontap-ems-export")
        first = source(data, "ems_0")
        if unavailable(first):
            r.step("events", "EMS events (REST API)", "fail", unavailable(first))
            return r.done()
        events, more = OntapEms.events(data)
        hours = int(params.get("hours") or 24)
        msg = lambda e: (e.get("message") or {}) if isinstance(e.get("message"), dict) else {}   # noqa: E731
        r.step("events", "EMS events of the window", "warn" if more else "ok",
               f"{len(events)} event(s) of the last {hours} hours ({params.get('severity') or 'all'} severities)"
               + (f"; more than {ONTAP_PAGE * ONTAP_PAGES} — choose a shorter window for the rest." if more else "."),
               count_table([msg(e).get("severity") for e in events], "Severity"))
        kinds = {}
        for e in events:
            k = msg(e).get("name") or "-"
            x = kinds.setdefault(k, [k, msg(e).get("severity") or "", 0, e.get("time") or "", (e.get("node") or {}).get("name") or "",
                                     str(e.get("log_message") or "")[:300]])
            x[2] += 1
        r.step("kinds", "Events by message", "info", f"{len(kinds)} different message(s), the most frequent first.",
               {"columns": ["Message", "Severity", "Events", "Newest", "Node", "Example"],
                "rows": sorted(kinds.values(), key=lambda x: -x[2])})
        r.step("newest", "Newest events", "info", f"The newest {min(SHOWN, len(events))}; every event is in the raw output of this "
               "run (export/ontap-ems.csv).",
               {"columns": ["Time", "Node", "Severity", "Message", "Log message"],
                "rows": [[e.get("time") or "", (e.get("node") or {}).get("name") or "", msg(e).get("severity") or "",
                          msg(e).get("name") or "", str(e.get("log_message") or "")[:400]] for e in events[:SHOWN]]})
        r.recommend("Download every event with the button Raw output (.zip) at the top of this page: export/ontap-ems.csv, with the "
                    "REST answers under reads/ontap/. The same events in the ONTAP CLI:",
                    [f"event log show -time >\"{since_iso(params, ctx).astimezone(tz_of(ctx)).strftime('%m/%d/%Y %H:%M:%S')}\""],
                    where=f"ONTAP CLI of {ctx.get('ontap_host') or 'the cluster'} (ssh admin@<cluster management>)")
        return r.done(f"{len(events)} EMS event(s) of the last {hours} hours.")

    @staticmethod
    def export(data, params):
        events, _more = OntapEms.events(data)
        msg = lambda e: (e.get("message") or {}) if isinstance(e.get("message"), dict) else {}   # noqa: E731
        return {"ontap-ems.csv": csv_text(["Time", "Node", "Severity", "Message", "Index", "Source", "Log message"],
                                          [[e.get("time") or "", (e.get("node") or {}).get("name") or "", msg(e).get("severity") or "",
                                            msg(e).get("name") or "", e.get("index") or "", e.get("source") or "", e.get("log_message") or ""]
                                           for e in events])}


# ---------------------------------------------------------------- vCenter events
class VcenterEvents:
    """Every vCenter event of a time window (info, user, warning, error), read with an event history collector."""
    sources = ("vsphere",)
    phases = 1

    @staticmethod
    def reads(phase, data, params, ctx):
        return {"vsphere": {"events": f"allevents@{int(params.get('hours') or 24)}"}}

    @staticmethod
    def events(data):
        inv = json_of(source(data, "events")) or {}
        return list(inv.get("allevents") or []), (inv.get("errors") or {}).get("allevents")

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("vcenter-events-export")
        item = source(data, "events")
        if unavailable(item):
            r.step("events", "Read vCenter", "fail", unavailable(item))
            return r.done()
        events, error = VcenterEvents.events(data)
        if error:
            r.step("events", "Events of the window", "fail", f"Not read: {error}")
            return r.done()
        hours = int(params.get("hours") or 24)
        full = len(events) >= 10000
        r.step("events", "Events of the window", "warn" if full else "ok",
               f"{len(events)} event(s) of the last {hours} hours" + (" (the limit of 10000: choose a shorter window)." if full else "."),
               count_table([e.get("severity") or "info" for e in events], "Category"))
        kinds = {}
        for e in events:
            x = kinds.setdefault(e.get("type") or "-", [e.get("type") or "-", e.get("severity") or "info", 0, "", ""])
            x[2] += 1
            if (e.get("time") or "") >= x[3]:
                x[3], x[4] = e.get("time") or "", str(e.get("message") or "")[:300]
        r.step("kinds", "Events by type", "info", f"{len(kinds)} event type(s), the most frequent first.",
               {"columns": ["Event type", "Category", "Events", "Newest", "Newest message"], "rows": sorted(kinds.values(), key=lambda x: -x[2])})
        newest = sorted(events, key=lambda e: e.get("time") or "", reverse=True)[:SHOWN]
        r.step("newest", "Newest events", "info", f"The newest {len(newest)}; every event is in the raw output of this run "
               "(export/vcenter-events.csv).",
               {"columns": ["Time", "Category", "Type", "Host", "VM", "User", "Message"],
                "rows": [[e.get("time") or "", e.get("severity") or "info", e.get("type") or "", e.get("host") or "", e.get("vm") or "",
                          e.get("user") or "", str(e.get("message") or "")[:400]] for e in newest]})
        r.recommend("Download every event with the button Raw output (.zip) at the top of this page: export/vcenter-events.csv. "
                    "The same events in PowerCLI:",
                    [f"Get-VIEvent -Start (Get-Date).AddHours(-{hours}) -MaxSamples 100000 | Select-Object CreatedTime, FullFormattedMessage, UserName "
                     "| Export-Csv vcenter-events.csv -NoTypeInformation"],
                    where=f"PowerShell with PowerCLI, after: Connect-VIServer -Server {ctx.get('vcenter_host') or '<vCenter>'}")
        return r.done(f"{len(events)} vCenter event(s) of the last {hours} hours.")

    @staticmethod
    def export(data, params):
        events, _error = VcenterEvents.events(data)
        return {"vcenter-events.csv": csv_text(["Time", "Category", "Type", "Datacenter", "Cluster", "Host", "VM", "Datastore", "User",
                                                "Message"],
                                               [[e.get("time") or "", e.get("severity") or "info", e.get("type") or "",
                                                 e.get("datacenter") or "", e.get("cluster") or "", e.get("host") or "", e.get("vm") or "",
                                                 e.get("datastore") or "", e.get("user") or "", e.get("message") or ""] for e in events])}

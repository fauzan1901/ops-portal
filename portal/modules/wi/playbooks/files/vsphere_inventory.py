#!/usr/bin/env python3
"""Read-only vCenter inventory for Operation Automation (pyVmomi, vSphere Web Services API).

    vsphere_inventory.py --host <vcenter[:port]> [--verify] --what hosts,vms,pools,clusters
    vsphere_inventory.py --host <vcenter[:port]> --what alarms,events@24,hosthealth,vmhealth,datastores

Only reads: the PropertyCollector (container views over the inventory, destroyed afterwards), the triggered alarms of
the root folder, and EventManager.QueryEvents for the error and warning events of the last <hours> (events@<hours>), or
every event of the last <hours> through an EventHistoryCollector (allevents@<hours>, the export Collect vCenter events).
No method that changes anything is called. The account and password come from the environment (WI_VCENTER_USER,
WI_VCENTER_PASSWORD), never from the command line. Prints one JSON document with the sets asked for:

    {"hosts": [...], "vms": [...], "pools": [...], "clusters": [...], "alarms": [...], "events": [...],
     "hosthealth": [...], "vmhealth": [...], "datastores": [...], "errors": {set: reason}}

A set that cannot be read (a property this vCenter does not know, no permission) is reported in "errors" and the
others are still read.
"""
import argparse
import json
import os
import ssl
import sys

WHAT = ("hosts", "vms", "pools", "clusters")
HEALTH = ("alarms", "events", "allevents", "hosthealth", "vmhealth", "datastores")
MAX_EVENTS = 1000
MAX_ALL_EVENTS = 10000
PROPS = {
    "HostSystem": ["name", "parent", "overallStatus", "runtime.connectionState", "runtime.inMaintenanceMode",
                   "runtime.powerState", "summary.quickStats.overallCpuUsage", "summary.quickStats.overallMemoryUsage",
                   "summary.hardware.cpuMhz", "summary.hardware.numCpuCores", "summary.hardware.memorySize"],
    "VirtualMachine": ["name", "parent", "resourcePool", "runtime.host", "runtime.powerState", "config.template",
                       "summary.quickStats.overallCpuUsage", "summary.quickStats.hostMemoryUsage",
                       "summary.quickStats.guestMemoryUsage", "summary.config.numCpu", "summary.config.memorySizeMB",
                       "summary.guest.ipAddress", "summary.guest.guestFullName"],
    "ResourcePool": ["name", "parent", "owner", "config.cpuAllocation.limit", "config.cpuAllocation.reservation",
                     "config.memoryAllocation.limit", "config.memoryAllocation.reservation", "runtime.cpu.overallUsage",
                     "runtime.memory.overallUsage"],
    # DRS through "configuration" (declared ClusterConfigInfo): the PropertyCollector validates paths against the declared
    # type, and configurationEx is declared as the base ComputeResourceConfigInfo, which has no drsConfig.
    "ClusterComputeResource": ["name", "configuration.drsConfig.enabled", "configuration.drsConfig.defaultVmBehavior"],
    "ComputeResource": ["name"],
    "Folder": ["name", "parent"],
    "Datacenter": ["name", "parent"],
}


def connect(host, user, password, verify):
    from pyVim.connect import SmartConnect
    name, _, port = host.replace("https://", "").partition(":")
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    return SmartConnect(host=name, port=int(port or 443), user=user, pwd=password, sslContext=ctx)


def collect(si):
    from pyVmomi import vmodl, vim
    content = si.RetrieveContent()
    types = [getattr(vim, t) for t in PROPS]
    view = content.viewManager.CreateContainerView(content.rootFolder, types, True)
    try:
        spec = vmodl.query.PropertyCollector.FilterSpec(
            objectSet=[vmodl.query.PropertyCollector.ObjectSpec(
                obj=view, skip=True,
                selectSet=[vmodl.query.PropertyCollector.TraversalSpec(name="view", path="view", skip=False,
                                                                       type=vim.view.ContainerView)])],
            propSet=[vmodl.query.PropertyCollector.PropertySpec(type=getattr(vim, t), pathSet=p) for t, p in PROPS.items()])
        objects = {}
        options = vmodl.query.PropertyCollector.RetrieveOptions(maxObjects=1000)
        result = content.propertyCollector.RetrievePropertiesEx([spec], options)
        while result:
            for o in result.objects:
                objects[o.obj._moId] = {"type": type(o.obj).__name__.split(".")[-1], **{p.name: plain(p.val) for p in o.propSet}}
            result = content.propertyCollector.ContinueRetrievePropertiesEx(result.token) if result.token else None
    finally:
        view.DestroyView()
    return objects


def plain(value):
    """Managed object references -> their moId; data objects -> str; everything else as it is."""
    if hasattr(value, "_moId"):
        return value._moId
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def shape(objects, what):
    """The raw property map -> compact lists with names instead of references."""
    def name(moid):
        return (objects.get(moid) or {}).get("name", moid or "")

    def path(moid):
        parts, seen = [], set()
        while moid and moid in objects and moid not in seen:
            seen.add(moid)
            o = objects[moid]
            if o["type"] in ("Datacenter",) or o.get("name") in ("vm", "host", "Datacenters") and o["type"] == "Folder":
                break
            parts.append(o.get("name", moid))
            moid = o.get("parent")
        return "/".join(reversed(parts))

    def cluster_of(moid):
        seen = set()
        while moid and moid in objects and moid not in seen:
            seen.add(moid)
            if objects[moid]["type"] in ("ClusterComputeResource", "ComputeResource"):
                return objects[moid].get("name", moid)
            moid = objects[moid].get("parent") or objects[moid].get("owner")
        return ""

    out = {}
    of = lambda t: [(k, v) for k, v in objects.items() if v["type"] == t]   # noqa: E731
    if "hosts" in what:
        out["hosts"] = [{"moid": k, "name": v.get("name"), "cluster": cluster_of(v.get("parent")),
                         "status": v.get("overallStatus"), "connection": v.get("runtime.connectionState"),
                         "maintenance": bool(v.get("runtime.inMaintenanceMode")), "power": v.get("runtime.powerState"),
                         "cpu_used_mhz": v.get("summary.quickStats.overallCpuUsage") or 0,
                         "cpu_total_mhz": (v.get("summary.hardware.cpuMhz") or 0) * (v.get("summary.hardware.numCpuCores") or 0),
                         "mem_used_mb": v.get("summary.quickStats.overallMemoryUsage") or 0,
                         "mem_total_mb": int((v.get("summary.hardware.memorySize") or 0) / 1024 / 1024)}
                        for k, v in of("HostSystem")]
    if "vms" in what:
        out["vms"] = [{"moid": k, "name": v.get("name"), "host": name(v.get("runtime.host")),
                       "cluster": cluster_of(v.get("runtime.host")), "pool": name(v.get("resourcePool")),
                       "pool_moid": v.get("resourcePool") or "", "folder": path(v.get("parent")),
                       "power": v.get("runtime.powerState"), "cpu_used_mhz": v.get("summary.quickStats.overallCpuUsage") or 0,
                       "mem_host_mb": v.get("summary.quickStats.hostMemoryUsage") or 0,
                       "mem_guest_mb": v.get("summary.quickStats.guestMemoryUsage") or 0,
                       "vcpu": v.get("summary.config.numCpu") or 0, "mem_mb": v.get("summary.config.memorySizeMB") or 0,
                       "ip": v.get("summary.guest.ipAddress") or "", "os": v.get("summary.guest.guestFullName") or ""}
                      for k, v in of("VirtualMachine") if not v.get("config.template")]
    if "pools" in what:
        out["pools"] = [{"moid": k, "name": v.get("name"), "path": path(k), "cluster": cluster_of(v.get("owner")),
                         "root": objects.get(v.get("parent"), {}).get("type") in ("ClusterComputeResource", "ComputeResource"),
                         "cpu_limit_mhz": v.get("config.cpuAllocation.limit"), "cpu_reservation_mhz": v.get("config.cpuAllocation.reservation"),
                         "mem_limit_mb": v.get("config.memoryAllocation.limit"), "mem_reservation_mb": v.get("config.memoryAllocation.reservation"),
                         "cpu_used_mhz": v.get("runtime.cpu.overallUsage") or 0,
                         "mem_used_mb": int((v.get("runtime.memory.overallUsage") or 0) / 1024 / 1024)}
                        for k, v in of("ResourcePool")]
    if "clusters" in what:
        out["clusters"] = [{"moid": k, "name": v.get("name"), "drs": bool(v.get("configuration.drsConfig.enabled")),
                            "drs_behavior": v.get("configuration.drsConfig.defaultVmBehavior") or ""}
                           for k, v in of("ClusterComputeResource")]
    return out


# ---------------------------------------------------------------- health sets (each read on its own)
def retrieve(content, objects_and_paths):
    """[(managed object, [paths])] -> {moId: {path: value}} in one PropertyCollector call (no traversal)."""
    from pyVmomi import vmodl
    by_type = {}
    for obj, paths in objects_and_paths:
        by_type.setdefault(type(obj), set()).update(paths)
    spec = vmodl.query.PropertyCollector.FilterSpec(
        objectSet=[vmodl.query.PropertyCollector.ObjectSpec(obj=obj, skip=False) for obj, _ in objects_and_paths],
        propSet=[vmodl.query.PropertyCollector.PropertySpec(type=t, pathSet=sorted(p)) for t, p in by_type.items()])
    out = {}
    result = content.propertyCollector.RetrievePropertiesEx([spec], vmodl.query.PropertyCollector.RetrieveOptions(maxObjects=1000))
    while result:
        for o in result.objects:
            out[o.obj._moId] = {p.name: p.val for p in o.propSet}
        result = content.propertyCollector.ContinueRetrievePropertiesEx(result.token) if result.token else None
    return out


def view_props(content, vimtype, paths):
    """{moId: {path: value}} of every object of one type in the inventory (container view, destroyed afterwards)."""
    from pyVmomi import vmodl
    view = content.viewManager.CreateContainerView(content.rootFolder, [vimtype], True)
    try:
        spec = vmodl.query.PropertyCollector.FilterSpec(
            objectSet=[vmodl.query.PropertyCollector.ObjectSpec(
                obj=view, skip=True,
                selectSet=[vmodl.query.PropertyCollector.TraversalSpec(name="view", path="view", skip=False, type=type(view))])],
            propSet=[vmodl.query.PropertyCollector.PropertySpec(type=vimtype, pathSet=paths)])
        out = {}
        result = content.propertyCollector.RetrievePropertiesEx([spec], vmodl.query.PropertyCollector.RetrieveOptions(maxObjects=1000))
        while result:
            for o in result.objects:
                out[o.obj._moId] = {p.name: p.val for p in o.propSet}
            result = content.propertyCollector.ContinueRetrievePropertiesEx(result.token) if result.token else None
        return out
    finally:
        view.DestroyView()


def iso(value):
    return value.isoformat() if hasattr(value, "isoformat") else (str(value) if value is not None else "")


def key_of(value):
    """ElementDescription (sensor health) or plain value -> its key ('green', 'yellow', 'red', 'unknown')."""
    return str(getattr(value, "key", value) or "")


def read_alarms(si, content):
    """Alarms triggered anywhere in the inventory (the root folder carries those of every descendant)."""
    from pyVmomi import vim
    states = list(content.rootFolder.triggeredAlarmState or [])
    objs = {}
    for st in states:
        if st.alarm is not None:
            objs[st.alarm._moId] = (st.alarm, ["info.name"])
        if st.entity is not None:
            objs[st.entity._moId] = (st.entity, ["name"])
    names = {}
    if objs:
        try:
            props = retrieve(content, list(objs.values()))
            names = {k: v.get("info.name") or v.get("name") for k, v in props.items()}
        except Exception:   # names are a convenience: keep the alarms with their ids
            names = {}
    out = []
    for st in states:
        entity = st.entity
        out.append({"alarm": names.get(st.alarm._moId) or st.alarm._moId if st.alarm is not None else "",
                    "entity": (names.get(entity._moId) or entity._moId) if entity is not None else "",
                    "entity_type": type(entity).__name__.split(".")[-1] if entity is not None else "",
                    "status": str(st.overallStatus or ""), "time": iso(st.time), "acknowledged": bool(st.acknowledged),
                    "acknowledged_by": str(st.acknowledgedByUser or "")})
    return out


def read_events(si, content, hours):
    """Error and warning events of the last hours (vCenter time), newest first, at most MAX_EVENTS."""
    import datetime
    from pyVmomi import vim
    now = si.CurrentTime()
    spec = vim.event.EventFilterSpec(time=vim.event.EventFilterSpec.ByTime(beginTime=now - datetime.timedelta(hours=hours)),
                                     category=["error", "warning"])
    try:   # maxCount: vSphere API 6.5 and later; without it vCenter applies its own maximum
        spec.maxCount = MAX_EVENTS
    except (AttributeError, TypeError):
        pass
    events = content.eventManager.QueryEvents(spec) or []
    out = [event_row(e) for e in events[:MAX_EVENTS]]
    out.sort(key=lambda x: x["time"], reverse=True)
    return out


def event_row(e, size=500):
    arg = lambda name: getattr(getattr(e, name, None), "name", "") or ""   # noqa: E731
    return {"type": str(getattr(e, "eventTypeId", "") or type(e).__name__.split(".")[-1]),
            "time": iso(e.createdTime), "message": str(e.fullFormattedMessage or "")[:size],
            "severity": str(getattr(e, "severity", "") or ""), "host": arg("host"), "vm": arg("vm"),
            "datastore": arg("ds"), "cluster": arg("computeResource"), "datacenter": arg("datacenter"),
            "user": str(getattr(e, "userName", "") or ""), "key": int(getattr(e, "key", 0) or 0)}


def read_all_events(si, content, hours):
    """Every event of the last hours (info, user, warning and error), oldest first, at most MAX_ALL_EVENTS: read page by
    page with an EventHistoryCollector (QueryEvents stops at 1000), which is destroyed afterwards."""
    import datetime
    from pyVmomi import vim
    now = si.CurrentTime()
    spec = vim.event.EventFilterSpec(time=vim.event.EventFilterSpec.ByTime(beginTime=now - datetime.timedelta(hours=hours)))
    try:   # the category (info, user, warning, error) of each event type; EventEx events carry their own severity
        cats = {str(d.key): str(d.category) for d in content.eventManager.description.eventInfo}
    except Exception:
        cats = {}
    collector = content.eventManager.CreateCollectorForEvents(spec)
    out = []
    try:
        collector.RewindCollector()
        while len(out) < MAX_ALL_EVENTS:
            page = collector.ReadNextEvents(1000) or []
            if not page:
                break
            for e in page:
                row = event_row(e, 2000)
                row["severity"] = row["severity"] or cats.get(row["type"]) or cats.get(type(e).__name__.split(".")[-1]) or "info"
                out.append(row)
    finally:
        collector.DestroyCollector()
    out.sort(key=lambda x: (x["time"], x["key"]))
    return out[:MAX_ALL_EVENTS]


def read_hosthealth(si, content):
    """Per ESXi host: connection, sensors and hardware status that are not green (CIM through vCenter), config issues."""
    from pyVmomi import vim
    props = view_props(content, vim.HostSystem, ["name", "runtime.connectionState", "runtime.inMaintenanceMode", "overallStatus",
                                                 "summary.hardware.vendor", "summary.hardware.model", "configIssue",
                                                 "runtime.healthSystemRuntime.systemHealthInfo.numericSensorInfo",
                                                 "runtime.healthSystemRuntime.hardwareStatusInfo"])
    out = []
    for moid, v in props.items():
        sensors = []
        for x in v.get("runtime.healthSystemRuntime.systemHealthInfo.numericSensorInfo") or []:
            state = key_of(getattr(x, "healthState", None)).lower()
            if state in ("yellow", "red"):
                sensors.append({"name": str(x.name or ""), "type": str(getattr(x, "sensorType", "") or ""), "state": state,
                                "reading": f"{x.currentReading * (10 ** (x.unitModifier or 0)):g} {x.baseUnits or ''}".strip()
                                if getattr(x, "currentReading", None) is not None else ""})
        hardware = []
        info = v.get("runtime.healthSystemRuntime.hardwareStatusInfo")
        for group, label in (("memoryStatusInfo", "memory"), ("cpuStatusInfo", "cpu"), ("storageStatusInfo", "storage")):
            for x in getattr(info, group, None) or []:
                state = key_of(getattr(x, "status", None)).lower()
                if state in ("yellow", "red"):
                    hardware.append({"name": str(x.name or ""), "type": label, "state": state})
        out.append({"moid": moid, "name": v.get("name"), "connection": str(v.get("runtime.connectionState") or ""),
                    "maintenance": bool(v.get("runtime.inMaintenanceMode")), "status": str(v.get("overallStatus") or ""),
                    "vendor": str(v.get("summary.hardware.vendor") or ""), "model": str(v.get("summary.hardware.model") or ""),
                    "sensors": sensors, "hardware": hardware,
                    "issues": [str(getattr(i, "fullFormattedMessage", "") or type(i).__name__)[:300] for i in v.get("configIssue") or []]})
    return out


def read_vmhealth(si, content):
    """VMs with snapshots, that need disk consolidation, or powered on without VMware Tools running."""
    from pyVmomi import vim
    props = view_props(content, vim.VirtualMachine, ["name", "runtime.host", "runtime.powerState", "config.template",
                                                     "runtime.consolidationNeeded", "snapshot.rootSnapshotList",
                                                     "guest.toolsRunningStatus"])
    hosts = view_props(content, vim.HostSystem, ["name"])
    out = []
    for moid, v in props.items():
        if v.get("config.template"):
            continue
        snaps, stack = [], list(v.get("snapshot.rootSnapshotList") or [])
        while stack:
            x = stack.pop()
            snaps.append({"name": str(x.name or ""), "created": iso(x.createTime)})
            stack.extend(x.childSnapshotList or [])
        power = str(v.get("runtime.powerState") or "")
        tools = str(v.get("guest.toolsRunningStatus") or "")
        consolidate = bool(v.get("runtime.consolidationNeeded"))
        if not snaps and not consolidate and not (power == "poweredOn" and tools == "guestToolsNotRunning"):
            continue
        host = v.get("runtime.host")
        out.append({"moid": moid, "name": v.get("name"), "host": (hosts.get(host._moId) or {}).get("name", "") if host is not None else "",
                    "power": power, "tools": tools, "consolidate": consolidate,
                    "snapshots": sorted(snaps, key=lambda x: x["created"])})
    return out


def read_datastores(si, content):
    from pyVmomi import vim
    props = view_props(content, vim.Datastore, ["name", "summary.accessible", "summary.capacity", "summary.freeSpace",
                                                "summary.type", "overallStatus"])
    return [{"moid": k, "name": v.get("name"), "accessible": bool(v.get("summary.accessible")),
             "capacity": int(v.get("summary.capacity") or 0), "free": int(v.get("summary.freeSpace") or 0),
             "type": str(v.get("summary.type") or ""), "status": str(v.get("overallStatus") or "")} for k, v in props.items()]


def health(si, sets):
    """{set: data} of the health sets, and {"errors": {set: reason}} for those that could not be read."""
    content = si.RetrieveContent()
    out, errors = {}, {}
    for name in sets:
        base, _, arg = name.partition("@")
        try:
            if base == "alarms":
                out["alarms"] = read_alarms(si, content)
            elif base == "events":
                out["events"] = read_events(si, content, max(1, min(int(arg or 24), 720)))
            elif base == "allevents":
                out["allevents"] = read_all_events(si, content, max(1, min(int(arg or 24), 720)))
            elif base == "hosthealth":
                out["hosthealth"] = read_hosthealth(si, content)
            elif base == "vmhealth":
                out["vmhealth"] = read_vmhealth(si, content)
            elif base == "datastores":
                out["datastores"] = read_datastores(si, content)
        except Exception as e:   # one set must not hide the others; the reason names the property or the fault
            detail = getattr(e, "msg", None) or (f"property {e.name!r}" if getattr(e, "name", None) else str(e).splitlines()[0] if str(e) else "")
            errors[base] = f"{type(e).__name__}: {detail}"[:300]
    if errors:
        out["errors"] = errors
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--what", required=True)
    a = ap.parse_args()
    what = [w for w in a.what.split(",") if w]
    if not what or any(w not in WHAT and w.partition("@")[0] not in HEALTH for w in what) \
            or any("@" in w and (w.partition("@")[0] not in ("events", "allevents") or not w.partition("@")[2].isdigit()) for w in what):
        print(f"--what must be a list of {', '.join(WHAT + HEALTH)} (events@<hours>)", file=sys.stderr)
        return 2
    user, password = os.environ.get("WI_VCENTER_USER", ""), os.environ.get("WI_VCENTER_PASSWORD", "")
    if not user or not password:
        print("No read-only vCenter account in the environment", file=sys.stderr)
        return 2
    try:
        import pyVmomi  # noqa: F401
    except ImportError:
        print("pyVmomi is not installed on the portal server (pip install pyvmomi)", file=sys.stderr)
        return 3
    from pyVim.connect import Disconnect
    try:
        si = connect(a.host, user, password, a.verify)
    except Exception as e:   # wrong password, unreachable, certificate
        print(f"vCenter {a.host}: {getattr(e, 'msg', None) or e}", file=sys.stderr)
        return 4
    try:
        base = [w for w in what if w in WHAT]
        out = shape(collect(si), base) if base else {}
        out.update(health(si, [w for w in what if w not in WHAT]))
        print(json.dumps(out, separators=(",", ":")))
    except Exception as e:   # the reason first (the portal shows the first lines), the traceback after it
        import traceback
        detail = getattr(e, "msg", None) or (f"property {e.name!r}" if getattr(e, "name", None) else str(e).splitlines()[0])
        print(f"vCenter {a.host}: reading the inventory failed: {type(e).__name__}: {detail}", file=sys.stderr)
        traceback.print_exc()
        return 5
    finally:
        Disconnect(si)
    return 0


if __name__ == "__main__":
    sys.exit(main())

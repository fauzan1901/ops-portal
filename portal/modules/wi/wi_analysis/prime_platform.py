"""Acme Prime platform beyond alarms (RISET-KNOWN-ISSUES.md 2.6-2.8): the HA of the NSX-T gateways and their BGP
neighbours (a short failover or BGP flap often raises no alarm, Broadcom 425005), the vCloud Director platform (cells,
the connection of each vCenter, edge gateways and networks that failed to realize in NSX) and the vCenter appliance
(health of the VCSA, its services, file-based backup). REST GET only, with the read-only accounts of the site: Acme
Prime stays read-only, so the results give the commands and the Broadcom documentation, never a fix.
"""
import datetime
import re

from .common import Result, json_of, source, unavailable

ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")
MAX_GATEWAYS = 8
FLAP_SECONDS = 3600   # a BGP session up for less than this has gone down recently
BKB = "https://knowledge.broadcom.com/external/article"
DEV = "https://developer.broadcom.com/xapis"


def bc(title, url):
    return {"vendor": "Broadcom", "title": title, "url": url}


REF_GATEWAY = [bc("APIs for NSX Edge and Tier-0 monitoring (KB 428449)", f"{BKB}/428449/apis-for-nsx-edge-and-tier0-monitoring.html"),
               bc("Missing alarms for transient edge failover or BGP flap events (KB 425005)",
                  f"{BKB}/425005/missing-alarms-for-transient-edge-failov.html"),
               bc("Get Tier0 state", f"{DEV}/nsx-t-data-center-rest-api/4.2/method_GetTier0State.html")]
REF_BGP = [bc("BGP neighborship is down alarm (KB 369185)", f"{BKB}/369185"),
           bc("NSX-T Manager alarms indicating BGP is down when using static routing (KB 322505)", f"{BKB}/322505"),
           bc("Get BGP neighbor status for the Tier0", f"{DEV}/nsx-t-data-center-rest-api/4.1.0/method_GetTier0BgpNeighborsStatus.html")]
REF_VCD = [bc("Cloud Director OpenAPI: cells", f"{DEV}/vmware-cloud-director-openapi/latest/cell/"),
           bc("Cloud Director OpenAPI: VCenterServer", f"{DEV}/vmware-cloud-director-openapi/latest/data-structures/VCenterServer/"),
           bc("Cloud Director OpenAPI: NetworkingObjectStatus", f"{DEV}/vmware-cloud-director-openapi/latest/data-structures/NetworkingObjectStatus/")]
REF_VCSA = [bc("vSphere Automation API: appliance health system", f"{DEV}/vsphere-automation-api/v7.0U3/appliance/health/system"),
            bc("vCenter log disk exhaustion or /storage/log full (KB 313077)", f"{BKB}/313077/vcenter-log-disk-exhaustion-or-storagelo.html"),
            bc("/storage/seat disk 100% full (KB 318931)", f"{BKB}/318931")]
REF_BACKUP = [bc("Scheduled vCenter file-based backup fails but manual backup jobs succeed (KB 425537)", f"{BKB}/425537"),
              bc("Scheduled file-based backup fails to start (KB 402458)", f"{BKB}/402458")]


def results(item):
    data = json_of(item)
    if isinstance(data, dict):
        return data.get("results") or data.get("values") or []
    return data if isinstance(data, list) else []


def find_key(data, key):
    """The first value of `key` anywhere in a JSON document (NSX nests the HA status a few levels down)."""
    if isinstance(data, dict):
        if key in data:
            return data[key]
        for v in data.values():
            found = find_key(v, key)
            if found is not None:
                return found
    elif isinstance(data, list):
        for v in data:
            found = find_key(v, key)
            if found is not None:
                return found
    return None


def ago(seconds):
    s = int(seconds or 0)
    return f"{s // 86400} d" if s >= 86400 else f"{s // 3600} h" if s >= 3600 else f"{s // 60} min"


# =========================================================================================== NSX-T gateways
class NsxtGatewayRouting:
    """HA of the Tier-0 gateways (and of one Tier-1 / VCD edge gateway when given), the edge clusters, and the BGP
    neighbours of the Tier-0s: state and how long each session has been up."""
    sources = ("nsxt",)
    phases = 3

    @staticmethod
    def reads(phase, data, params, ctx):
        t1 = str(params.get("tier1") or "")
        if phase == 1:
            out = {"t0s": "/policy/api/v1/infra/tier-0s", "clusters": "/api/v1/edge-clusters"}
            if t1 and ID_RE.match(t1):
                out["t1state"] = f"/policy/api/v1/infra/tier-1s/{t1}/state?type=GATEWAY_STATUS"
            return {"nsxt": out}
        t0s = [g for g in results(source(data, "t0s")) if ID_RE.match(str(g.get("id") or ""))][:MAX_GATEWAYS]
        if phase == 2:
            out = {}
            for i, g in enumerate(t0s):
                out[f"t0state_{i}"] = f"/policy/api/v1/infra/tier-0s/{g['id']}/state?type=GATEWAY_STATUS"
                out[f"t0ls_{i}"] = f"/policy/api/v1/infra/tier-0s/{g['id']}/locale-services"
            for i, c in enumerate([c for c in results(source(data, "clusters")) if ID_RE.match(str(c.get("id") or ""))][:MAX_GATEWAYS]):
                out[f"ecstate_{i}"] = f"/api/v1/edge-clusters/{c['id']}/state"
            return {"nsxt": out} if out else {}
        out = {}
        for i, g in enumerate(t0s):
            for j, ls in enumerate([x for x in results(source(data, f"t0ls_{i}")) if ID_RE.match(str(x.get("id") or ""))][:4]):
                out[f"bgp_{i}_{j}"] = f"/policy/api/v1/infra/tier-0s/{g['id']}/locale-services/{ls['id']}/bgp/neighbors/status"
        return {"nsxt": out} if out else {}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("nsxt-gateway-routing")
        nsx = ctx.get("nsxt_host") or "<NSX Manager>"
        t0s_item = source(data, "t0s")
        if unavailable(t0s_item):
            r.step("gateways", "Gateways: HA status", "fail", f"The Tier-0 gateways could not be read: {unavailable(t0s_item)}")
            return r.done()
        t0s = [g for g in results(t0s_item) if ID_RE.match(str(g.get("id") or ""))][:MAX_GATEWAYS]
        rows, bad, warn = [], [], []

        def gateway(name, mode, state_item):
            nodes = find_key(json_of(state_item) or {}, "per_node_status") or []
            states = [str(n.get("high_availability_status") or "UNKNOWN").upper() for n in nodes if isinstance(n, dict)]
            active = states.count("ACTIVE")
            if unavailable(state_item) or not states:
                warn.append(name)
                rows.append([name, mode or "-", "-", f"not read: {unavailable(state_item) or 'no node status'}"[:120]])
                return
            if (mode == "ACTIVE_ACTIVE" and not active) or (mode != "ACTIVE_ACTIVE" and active != 1):
                bad.append(name)
            elif any(s not in ("ACTIVE", "STANDBY") for s in states):
                warn.append(name)
            for n, s in zip(nodes, states):
                rows.append([name, mode or "-", str(n.get("transport_node_id") or n.get("service_router_id") or "-")[:40], s])
        for i, g in enumerate(t0s):
            gateway(str(g.get("display_name") or g.get("id")), str(g.get("ha_mode") or ""), source(data, f"t0state_{i}"))
        if params.get("tier1") and "t1state" in data:
            gateway(f"Tier-1 {params['tier1']}", "ACTIVE_STANDBY", source(data, "t1state"))
        r.step("gateways", "Gateways: HA status", "fail" if bad else "warn" if warn else "ok" if rows else "skip",
               (f"No ACTIVE or more than one ACTIVE (split brain) on: {', '.join(bad)}. " if bad else "")
               + (f"A node DOWN / UNKNOWN or the state not read on: {', '.join(warn)}." if warn else "")
               or (f"{len(t0s)} Tier-0 gateway(s): one ACTIVE each (active / standby), or ACTIVE on every node (active / active)."
                   if rows else "NSX Manager lists no Tier-0 gateway (and no Tier-1 was given)."),
               {"columns": ["Gateway", "HA mode", "Edge node", "HA status"], "rows": rows}, marks=bad + warn)
        if bad:
            r.recommend("A gateway has no ACTIVE service router, or two (split brain): north-south traffic, NAT and the "
                        "firewall of the tenants behind it stop or flap. Look at the edge nodes (status, BFD between them) and "
                        "at the alarms; a short failover often raises no alarm.",
                        ["get logical-routers   # on each edge node of the gateway (NSX CLI)", "get high-availability status",
                         "get bfd-sessions"], where=f"the edge nodes of the gateway (NSX CLI), or {nsx}", refs=REF_GATEWAY)
        # BGP neighbours of the Tier-0s
        brow, down, recent = [], [], []
        for i, g in enumerate(t0s):
            for key in sorted(k for k in data if k.startswith(f"bgp_{i}_")):
                for n in results(source(data, key)):
                    state = str(n.get("connection_state") or n.get("connection_status") or "UNKNOWN").upper()
                    up_ms = n.get("time_since_established")
                    up_s = int(up_ms) // 1000 if isinstance(up_ms, (int, float)) else None
                    who = f"{g.get('display_name') or g.get('id')} → {n.get('neighbor_address')}"
                    if state != "ESTABLISHED":
                        down.append(who)
                    elif up_s is not None and up_s < FLAP_SECONDS:
                        recent.append(who)
                    brow.append([str(g.get("display_name") or g.get("id")), str(n.get("neighbor_address") or "-"),
                                 str(n.get("remote_as_number") or "-"), state, ago(up_s) if up_s is not None else "-",
                                 str(n.get("connection_drop_count") if n.get("connection_drop_count") is not None else "-")])
        if brow:
            r.step("bgp", "BGP neighbours of the Tier-0 gateways", "fail" if down else "warn" if recent else "ok",
                   (f"Not ESTABLISHED: {', '.join(down)}. " if down else "")
                   + (f"Up for less than {FLAP_SECONDS // 60} minutes (went down recently, maybe without an alarm): "
                      f"{', '.join(recent)}." if recent else "") or f"{len(brow)} neighbour(s), all ESTABLISHED for an hour or more.",
                   {"columns": ["Gateway", "Neighbour", "Remote AS", "State", "Up for", "Drops"], "rows": brow}, marks=down + recent)
            if down or recent:
                r.recommend("A BGP neighbour of a Tier-0 is down or has flapped: routes of the tenants are withdrawn while it is "
                            "down. Check the session on the edge (state, last error) and the peer (ISP / core router).",
                            ["get logical-routers", "vrf <the SR vrf of the Tier-0>", "get bgp neighbor summary",
                             "get bgp neighbor <neighbour address>"], where="the edge nodes of the Tier-0 (NSX CLI)", refs=REF_BGP)
        else:
            r.step("bgp", "BGP neighbours of the Tier-0 gateways", "skip", "No BGP neighbour status was read (no Tier-0 with BGP).")
        clusters = [c for c in results(source(data, "clusters")) if ID_RE.match(str(c.get("id") or ""))][:MAX_GATEWAYS]
        erows = [[str(c.get("display_name") or c.get("id")),
                  str((json_of(source(data, f"ecstate_{i}")) or {}).get("state") or unavailable(source(data, f"ecstate_{i}")) or "-")]
                 for i, c in enumerate(clusters) if f"ecstate_{i}" in data]
        if erows:
            failed = [k for k, st in erows if st != "success"]
            r.step("clusters", "Edge clusters", "warn" if failed else "ok",
                   f"Not in state success: {', '.join(failed)}." if failed else f"{len(erows)} edge cluster(s) in state success.",
                   {"columns": ["Edge cluster", "State"], "rows": erows}, marks=failed)
        return r.done()


# =========================================================================================== vCloud Director
class VcdPlatform:
    """vCloud Director platform: cells (inactive, duplicate, versions), the connection of each vCenter, and the edge
    gateways and Org VDC networks that failed to realize in NSX."""
    sources = ("vcd",)
    phases = 1

    @staticmethod
    def reads(phase, data, params, ctx):
        return {"vcd": {"cells": "/cloudapi/1.0.0/cells?pageSize=128",
                        "vcs": "/cloudapi/1.0.0/virtualCenters?pageSize=128",
                        "edges": "/cloudapi/1.0.0/edgeGateways?pageSize=128",
                        "nets": "/cloudapi/1.0.0/orgVdcNetworks?pageSize=128"}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("vcd-platform")
        vcd = ctx.get("vcd_host") or "<vCloud Director>"
        cells_item = source(data, "cells")
        if unavailable(cells_item):
            r.step("cells", "Cells", "fail", f"The cells could not be read: {unavailable(cells_item)}")
            return r.done()
        cells = results(cells_item)
        inactive = [c for c in cells if not c.get("isActive", True) or str(c.get("status") or "").upper() in ("INACTIVE", "DOWN")]
        ips = [str(c.get("primaryIP") or c.get("primaryIp") or "") for c in cells]
        dup = sorted({ip for ip in ips if ip and ips.count(ip) > 1})
        versions = sorted({str(c.get("productVersion") or "") for c in cells if c.get("productVersion")})
        r.step("cells", "Cells", "fail" if inactive else "warn" if dup or len(versions) > 1 else "ok",
               (f"Inactive: {', '.join(str(c.get('name')) for c in inactive)}. " if inactive else "")
               + (f"Address used by more than one cell (an old cell still registered): {', '.join(dup)}. " if dup else "")
               + (f"Versions differ: {', '.join(versions)}." if len(versions) > 1 else "")
               or f"{len(cells)} cell(s) active, version {', '.join(versions) or '-'}.",
               {"columns": ["Cell", "Address", "Active", "Status", "Version"],
                "rows": [[c.get("name"), c.get("primaryIP") or c.get("primaryIp"), str(c.get("isActive")), c.get("status"),
                          c.get("productVersion")] for c in cells]}, marks=[str(c.get("name")) for c in inactive] + dup)
        vcs_item = source(data, "vcs")
        if not unavailable(vcs_item):
            vcs = results(vcs_item)
            # CONNECTED_SYNCING: connected, catching up the inventory (normal for a while after a reconnect or a cell restart)
            off = [v for v in vcs if not v.get("isConnected", True)
                   or str(v.get("listenerState") or "CONNECTED") not in ("CONNECTED", "CONNECTED_SYNCING")]
            sick = [v for v in vcs if v not in off and (str(v.get("clusterHealthStatus") or "GREEN") not in ("GREEN", "")
                                                       or str(v.get("listenerState")) == "CONNECTED_SYNCING")]
            r.step("vcenters", "vCenter Servers of vCloud Director", "fail" if off else "warn" if sick else "ok",
                   (f"Not connected / listener not CONNECTED: {', '.join(str(v.get('name')) for v in off)}: VM operations fail "
                    "and the inventory goes stale. " if off else "")
                   + (f"Cluster health not GREEN or the listener still syncing: {', '.join(str(v.get('name')) for v in sick)}."
                      if sick else "")
                   or f"{len(vcs)} vCenter Server(s) connected, listener CONNECTED.",
                   {"columns": ["vCenter", "Connected", "Listener", "Cluster health", "Version"],
                    "rows": [[v.get("name"), str(v.get("isConnected")), v.get("listenerState"), v.get("clusterHealthStatus"),
                              v.get("vcVersion")] for v in vcs]}, marks=[str(v.get("name")) for v in off + sick])
            if off:
                r.recommend("A vCenter Server is not connected to vCloud Director: reconnect it (Provider portal → Infrastructure "
                            "Resources → vCenter Server Instances → Reconnect) once vCenter itself answers.",
                            [f"curl -sk -H 'Accept: application/json;version=38.0' -H \"Authorization: Bearer $TOKEN\" "
                             f"https://{vcd}/cloudapi/1.0.0/virtualCenters"], where=f"{vcd} (provider portal)", refs=REF_VCD)
        for key, title, kind in (("edges", "Edge gateways realized in NSX", "edge gateway"), ("nets", "Org VDC networks realized in NSX", "network")):
            item = source(data, key)
            if unavailable(item):
                continue
            objs = results(item)
            failed = [o for o in objs if str(o.get("status") or "").upper() == "REALIZATION_FAILED"]
            pending = [o for o in objs if str(o.get("status") or "").upper() in ("PENDING", "CONFIGURING")]
            r.step(key, title, "fail" if failed else "warn" if pending else "ok",
                   (f"{len(failed)} {kind}(s) failed to realize in NSX: a change looks done in vCloud but does not work. " if failed else "")
                   + (f"{len(pending)} {kind}(s) pending or failed to update." if pending else "")
                   or f"{len(objs)} {kind}(s) read, none failed to realize" + (" (first page of 128)." if len(objs) >= 128 else "."),
                   {"columns": ["Name", "Organization / VDC", "Status"],
                    "rows": [[o.get("name"), (o.get("orgRef") or o.get("orgVdc") or {}).get("name"), o.get("status")] for o in failed + pending]},
                   marks=[str(o.get("name")) for o in failed + pending])
            if failed:
                r.recommend(f"Sync the {kind}s that failed to realize (vCloud Director → the object → Sync), and read the task "
                            "error: the NSX object it points to may be missing or changed outside vCloud.",
                            [f"https://{vcd}/cloudapi/1.0.0/{'edgeGateways' if key == 'edges' else 'orgVdcNetworks'}?filter=status==REALIZATION_FAILED"],
                            where=f"{vcd} (provider portal or API)", refs=REF_VCD)
        return r.done()


# =========================================================================================== vCenter appliance
HEALTH = ("system", "load", "mem", "swap", "storage", "database-storage", "software-packages", "applmgmt")
COLOR = {"green": "ok", "gray": "skip", "yellow": "warn", "orange": "fail", "red": "fail"}


def as_text(item):
    value = json_of(item)
    return str(value if not isinstance(value, dict) else value.get("value") or "").strip().strip('"').lower()


def parse_iso(value):
    try:
        return datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


class VcenterAppliance:
    """The vCenter Server Appliance itself: VAMI health (load, memory, swap, storage, database storage, packages), the
    services set to start automatically that are not running, and the file-based backup (last job, schedule)."""
    sources = ("vcenter",)
    phases = 1

    @staticmethod
    def reads(phase, data, params, ctx):
        out = {f"h_{h.replace('-', '_')}": f"/api/appliance/health/{h}" for h in HEALTH}
        out.update(services="/api/vcenter/services", backup="/api/appliance/recovery/backup/job/details",
                   schedules="/api/appliance/recovery/backup/schedules")
        return {"vcenter": out}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("vcenter-appliance")
        vc = ctx.get("vcenter_host") or "<vCenter>"
        rows, worst = [], []
        for h in HEALTH:
            item = source(data, f"h_{h.replace('-', '_')}")
            color = "not read" if unavailable(item) else as_text(item) or "-"
            rows.append([h, color])
            if COLOR.get(color) in ("warn", "fail"):
                worst.append((h, color))
        denied = all(unavailable(source(data, f"h_{h.replace('-', '_')}")) for h in HEALTH)
        if denied:
            why = unavailable(source(data, "h_system"))
            r.step("health", "Appliance health (VAMI)", "skip",
                   f"The appliance API did not answer ({why}): the read-only account may need the appliance read privilege.")
        else:
            st = "fail" if any(COLOR[c] == "fail" for _h, c in worst) else "warn" if worst else "ok"
            r.step("health", "Appliance health (VAMI)", st,
                   (", ".join(f"{h} {c}" for h, c in worst) + ".") if worst else "Every health area green.",
                   {"columns": ["Area", "Health"], "rows": rows}, marks=[h for h, _c in worst])
            if worst:
                r.recommend("The vCenter appliance reports a health problem: a full /storage/log is often old log bundles "
                            "(vc-support-*.tgz); a full /storage/seat (vpxd database) stops vpxd. Look at the partitions and "
                            "the top events before deleting anything.",
                            ["df -h /storage/log /storage/seat /storage/db   # on the VCSA (shell)", "ls -lh /storage/log/vmware/vc-support*"],
                            where=f"{vc} (VAMI https://{vc}:5480, or the VCSA shell)", refs=REF_VCSA)
        svc_item = source(data, "services")
        if not unavailable(svc_item):
            svcs = json_of(svc_item) or {}
            items = svcs.items() if isinstance(svcs, dict) else [(s.get("service") or s.get("key"), s.get("value") or s) for s in svcs]
            stopped = [k for k, v in items if isinstance(v, dict) and str(v.get("startup_type")).upper() == "AUTOMATIC"
                       and str(v.get("state")).upper() != "STARTED"]
            r.step("services", "Services set to start automatically", "fail" if stopped else "ok",
                   f"Not running: {', '.join(stopped)}." if stopped else f"Every automatic service of the {len(list(items))} read is running.",
                   marks=stopped)
            if stopped:
                r.recommend("A vCenter service set to start automatically is not running: start it from VAMI (Services) or "
                            "the VCSA shell, then read its log.", [f"service-control --start {s}" for s in stopped[:5]],
                            where=f"{vc} (VCSA shell)", refs=REF_VCSA)
        backup_item, sched_item = source(data, "backup"), source(data, "schedules")
        if not unavailable(backup_item):
            jobs = json_of(backup_item) or {}
            jobs = list(jobs.values()) if isinstance(jobs, dict) else jobs
            jobs = [j.get("value", j) if isinstance(j, dict) else {} for j in jobs]
            done = sorted([j for j in jobs if j.get("end_time")], key=lambda j: str(j.get("end_time")), reverse=True)
            last = done[0] if done else None
            ok = [j for j in done if str(j.get("status")).upper() == "SUCCEEDED"]
            now = datetime.datetime.fromtimestamp(int(ctx.get("now") or 0), datetime.timezone.utc) if ctx.get("now") else None
            last_ok = parse_iso(ok[0].get("end_time")) if ok else None
            age = (now - last_ok).total_seconds() if now and last_ok and last_ok.tzinfo else None
            schedules = json_of(sched_item) if not unavailable(sched_item) else None
            entries = list(schedules.values()) if isinstance(schedules, dict) else schedules if isinstance(schedules, list) else None
            # a schedule that exists but is disabled schedules nothing
            no_schedule = entries is not None and not any(isinstance(x, dict) and x.get("enable", True) for x in entries)
            failed = last is not None and str(last.get("status")).upper() == "FAILED"
            st = "fail" if failed else "warn" if no_schedule or not ok or (age is not None and age > 2 * 86400) else "ok"
            r.step("backup", "File-based backup of the appliance", st,
                   (f"Last job {str(last.get('status')).lower()} at {str(last.get('end_time'))[:16]}. " if last else "No backup job. ")
                   + (f"Last successful backup {ago(age)} ago. " if age is not None else "")
                   + ("No enabled backup schedule." if no_schedule else ""))
            if st != "ok":
                r.recommend("The vCenter file-based backup is failing or not scheduled: without it a broken VCSA cannot be "
                            "restored. Look at the last job (VAMI → Backup) and the target (space, credentials, a VM snapshot "
                            "of the VCSA blocks a full backup).", [f"https://{vc}:5480 → Backup → Activity"],
                            where=f"{vc} (VAMI)", refs=REF_BACKUP)
        return r.done()

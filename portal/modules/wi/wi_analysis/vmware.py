"""Operation Automation checks of Acme Prime (VMware), read with the site's read-only vCenter account (vSphere Automation REST API).

The fixes are PowerCLI commands with the datastores and VMs that were found, a target datastore that has the room, and
a dry run (-WhatIf) before the real run."""
import re

from .common import Result, human, json_of, source, unavailable

DATASTORE_ID = re.compile(r"^datastore-\d+$")
GIB = 1024 ** 3


def ps(value):
    """A PowerShell single-quoted string."""
    return "'" + str(value).replace("'", "''") + "'"


def tier(name):
    """'DCA-DS-SSD-01' -> 'DCA-DS-SSD' (datastores of one tier differ only in the number)."""
    return re.sub(r"[-_]?\d+$", "", str(name or ""))


class VcenterDatastore:
    """WI "Datastore Low Free Space": free space of every datastore and the VMs on the low ones (many VMs → Storage
    vMotion; few VMs → old snapshots)."""
    sources = ("vcenter",)
    phases = 2

    @staticmethod
    def reads(phase, data, params, ctx):
        if phase == 1:
            return {"vcenter": {"datastores": "/api/vcenter/datastore", "datacenters": "/api/vcenter/datacenter"}}
        low = VcenterDatastore._low(data, params)
        return {"vcenter": {f"vms_{d['datastore']}": f"/api/vcenter/vm?datastores={d['datastore']}" for d in low[:10]
                            if DATASTORE_ID.match(str(d.get("datastore")))}} if low else {}

    @staticmethod
    def _low(data, params):
        free_min = int(params.get("min_free") or 20)
        stores = json_of(source(data, "datastores")) or []
        out = []
        for d in stores if isinstance(stores, list) else []:
            cap, free = d.get("capacity") or 0, d.get("free_space") or 0
            pct_free = round(free * 100 / cap, 1) if cap else None
            if pct_free is not None and pct_free < free_min + 10:
                out.append(dict(d, pct_free=pct_free))
        return sorted(out, key=lambda d: d["pct_free"])

    @staticmethod
    def _target(stores, low, need, goal):
        """The datastore that can take `need` bytes and still stay above `goal` % free: same tier and type first,
        then the one with the most free space."""
        names = {d.get("name") for d in low}
        fits = [d for d in stores if d.get("name") not in names and d.get("capacity")
                and (d.get("free_space", 0) - need) * 100 / d["capacity"] >= goal]
        if not fits:
            return None
        return sorted(fits, key=lambda d: (tier(d.get("name")) != tier(low[0].get("name")), d.get("type") != low[0].get("type"),
                                           -(d.get("free_space") or 0)))[0]

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("vcenter-datastore")
        item = source(data, "datastores")
        if unavailable(item):
            r.step("datastores", "Free space of the datastores", "fail", unavailable(item))
            return r.done()
        free_min = int(params.get("min_free") or 20)
        goal = free_min + 10
        stores = [d for d in (json_of(item) or []) if isinstance(d, dict)]
        rows, worst_status = [], "ok"
        for d in sorted(stores, key=lambda d: (d.get("free_space") or 0) / (d.get("capacity") or 1)):
            cap, free = d.get("capacity") or 0, d.get("free_space") or 0
            pf = round(free * 100 / cap, 1) if cap else None
            st = "fail" if pf is not None and pf < free_min else "warn" if pf is not None and pf < goal else "ok"
            worst_status = st if {"fail": 2, "warn": 1, "ok": 0}[st] > {"fail": 2, "warn": 1, "ok": 0}[worst_status] else worst_status
            rows.append([d.get("name"), d.get("type"), human(cap), human(free), f"{pf}%" if pf is not None else "-", st.upper()])
        r.step("datastores", f"Datastores below {free_min}% free", worst_status,
               f"{sum(1 for x in rows if x[5] == 'FAIL')} below {free_min}%, {sum(1 for x in rows if x[5] == 'WARN')} below {goal}%.",
               {"columns": ["Datastore", "Type", "Capacity", "Free", "Free %", "Status"], "rows": rows})
        low = VcenterDatastore._low(data, params)
        vcenter = ctx.get("vcenter_host") or "<vCenter>"
        where = f"PowerShell with PowerCLI, after: Connect-VIServer -Server {vcenter}"
        vm_rows = []
        for d in low:
            vms = json_of(source(data, f"vms_{d['datastore']}")) or []
            vms = vms if isinstance(vms, list) else []
            names = [v.get("name", "") for v in vms if v.get("name")]
            vm_rows.append([d.get("name"), len(vms), ", ".join(names[:8]) + (" …" if len(names) > 8 else "")])
            cap, free = d.get("capacity") or 0, d.get("free_space") or 0
            need = max(int(cap * goal / 100 - free), 0)
            need_gb = -(-need // GIB)
            name = d.get("name")
            if len(vms) > 5:
                target = VcenterDatastore._target(stores, low, need, goal)
                if target is None:
                    r.recommend(f"{name}: {len(vms)} VMs and {human(need)} must move to reach {goal}% free, but no other datastore "
                                f"can take that and stay above {goal}% free: ask for capacity (new LUN / expand) and clean snapshots.",
                                [f"Get-Datastore | Sort-Object FreeSpaceGB -Descending | Select-Object Name, Type, "
                                 "@{N='FreeGB';E={[math]::Round($_.FreeSpaceGB)}}, @{N='CapacityGB';E={[math]::Round($_.CapacityGB)}}"],
                                where=where)
                    continue
                tname = target.get("name")
                after = round((target.get("free_space", 0) - need) * 100 / target["capacity"], 1)
                loop = (f"$moved = 0; foreach ($vm in (Get-VM -Datastore {ps(name)} | Sort-Object UsedSpaceGB -Descending)) "
                        f"{{ if ($moved -ge {need_gb}) {{ break }}; Move-VM -VM $vm -Datastore {ps(tname)} -DiskStorageFormat Thin"
                        "{WHATIF}; $moved += $vm.UsedSpaceGB }")
                r.recommend(f"{name}: {len(vms)} VMs — move about {need_gb} GB with Storage vMotion (no downtime) to {tname} "
                            f"({human(target.get('free_space'))} free, about {after}% free after). {name} then has {goal}% free. "
                            "Run the dry run (-WhatIf) first, then the same line without it, outside the busy hours.",
                            [f"Get-VM -Datastore {ps(name)} | Sort-Object UsedSpaceGB -Descending | Select-Object Name, PowerState, "
                             "@{N='UsedGB';E={[math]::Round($_.UsedSpaceGB,1)}} | Format-Table -AutoSize",
                             loop.replace("{WHATIF}", " -WhatIf"), loop.replace("{WHATIF}", ""),
                             f"Get-Datastore {ps(name)}, {ps(tname)} | Select-Object Name, @{{N='FreePct';E={{[math]::Round($_.FreeSpaceGB*100/$_.CapacityGB,1)}}}}"],
                            where=where,
                            warning=(f"{tname} is another tier ({tier(tname)}): check the storage policy of the VMs before moving. "
                                     if tier(tname) != tier(name) else "") + "Skip VMs with RDM disks or a running backup job.")
            else:
                vm_list = ", ".join(ps(n) for n in names) or "<VM names>"
                r.recommend(f"{name}: only {len(vms)} VM(s) ({', '.join(names) or '-'}) — free {need_gb} GB by deleting old snapshots "
                            "(older than 3 days, confirmed with the VM owner). List them, dry run, then delete.",
                            [f"Get-VM -Name {vm_list} | Get-Snapshot | Sort-Object Created | Select-Object VM, Name, Created, "
                             "@{N='SizeGB';E={[math]::Round($_.SizeGB,1)}} | Format-Table -AutoSize",
                             f"Get-VM -Name {vm_list} | Get-Snapshot | Where-Object {{ $_.Created -lt (Get-Date).AddDays(-3) }} | Remove-Snapshot -WhatIf",
                             f"Get-VM -Name {vm_list} | Get-Snapshot | Where-Object {{ $_.Created -lt (Get-Date).AddDays(-3) }} | Remove-Snapshot -Confirm:$false",
                             f"Get-Datastore {ps(name)} | Select-Object Name, @{{N='FreePct';E={{[math]::Round($_.FreeSpaceGB*100/$_.CapacityGB,1)}}}}"],
                            where=where,
                            warning="Deleting a large snapshot consolidates the disk (I/O load): not during critical work or a backup. "
                                    "If there are no old snapshots, move a VM away as above.")
        if low:
            r.step("vms", "VMs on the low datastores", "info", "Decides between migration and snapshot cleanup.",
                   {"columns": ["Datastore", "VMs", "Names"], "rows": vm_rows})
        return r.done()


# =========================================================================================== Host CPU / memory, pools
VCD_NAME = re.compile(r"^(.*) \(([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\)$")


def pct(used, total):
    return round(used * 100.0 / total, 1) if total else None


def load(h):
    """The higher of CPU % and memory % of a host (0 when unknown)."""
    return max(pct(h["cpu_used_mhz"], h["cpu_total_mhz"]) or 0, pct(h["mem_used_mb"], h["mem_total_mb"]) or 0)


def guest_commands(vm):
    """What to look at inside the busiest VM (WI: process, DDoS / brute force), by its OS."""
    if "windows" in str(vm.get("os") or "").lower():
        return ["Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Name, Id, CPU, WS",
                "Get-NetTCPConnection -State Established | Group-Object RemoteAddress | Sort-Object Count -Descending | Select-Object -First 10 Count, Name",
                "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddHours(-1)} | Measure-Object"]
    return ["top -b -n 1 | head -20", "ps aux --sort=-%cpu | head -10", "ps aux --sort=-%mem | head -10",
            "ss -Hnt state established | awk '{print $4}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -10",
            "sudo grep -c 'Failed password' /var/log/secure /var/log/auth.log 2>/dev/null"]


class VmwareHostUsage:
    """WIs "Host High CPU/Memory Usage" and "Check the VM Resource Pool Correctly": host load in the cluster, the VMs that
    cause it, where they can go (vMotion), DRS, and vCloud VMs that are not in their Org VDC resource pool."""
    sources = ("vsphere",)
    phases = 1

    @staticmethod
    def reads(phase, data, params, ctx):
        return {"vsphere": {"inventory": "hosts,vms,pools,clusters"}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("vmware-host-usage")
        item = source(data, "inventory")
        if unavailable(item):
            r.step("inventory", "Read the vCenter inventory", "fail", unavailable(item))
            return r.done()
        inv = json_of(item) or {}
        hosts, vms = inv.get("hosts") or [], inv.get("vms") or []
        pools, clusters = inv.get("pools") or [], {c["name"]: c for c in inv.get("clusters") or []}
        cpu_t, mem_t = int(params.get("cpu") or 85), int(params.get("memory") or 90)
        vcenter = ctx.get("vcenter_host") or "<vCenter>"
        where = f"PowerShell with PowerCLI, after: Connect-VIServer -Server {vcenter}"
        for h in hosts:
            h["cpu_pct"], h["mem_pct"] = pct(h["cpu_used_mhz"], h["cpu_total_mhz"]), pct(h["mem_used_mb"], h["mem_total_mb"])
            up = h.get("connection") == "connected" and not h.get("maintenance")
            hot = up and ((h["cpu_pct"] or 0) >= cpu_t or (h["mem_pct"] or 0) >= mem_t)
            near = up and ((h["cpu_pct"] or 0) >= cpu_t - 10 or (h["mem_pct"] or 0) >= mem_t - 10)
            h["state"] = "fail" if hot else "warn" if near else "ok" if up else "info"
            h["vm_count"] = sum(1 for v in vms if v["host"] == h["name"] and v["power"] == "poweredOn")
        wanted = str(params.get("host") or "").strip()
        focus = hosts
        if wanted:
            focus = [h for h in hosts if h["name"] == wanted or h["name"].startswith(wanted + ".") or wanted in h["name"]]
            if not focus:
                r.step("hosts", f"Host {wanted} in vCenter", "fail", f"No ESXi host named like {wanted} in {vcenter} "
                       f"({len(hosts)} hosts read).")
                return r.done()
        rows = sorted(hosts, key=lambda h: -max(h["cpu_pct"] or 0, h["mem_pct"] or 0))
        hot = [h for h in focus if h["state"] == "fail"]
        r.step("hosts", f"Hosts at or above CPU {cpu_t}% / memory {mem_t}%",
               "fail" if hot else "warn" if any(h["state"] == "warn" for h in focus) else "ok",
               (f"Above: {', '.join(h['name'] for h in hot)}." if hot else
                f"{wanted} is below the threshold now (CPU {focus[0]['cpu_pct']}%, memory {focus[0]['mem_pct']}%): the alert may "
                "have cleared; look at the trend in the host's Monitor → Performance." if wanted else "No host above the threshold."),
               {"columns": ["Host", "Cluster", "CPU %", "Memory %", "Running VMs", "State"],
                "rows": [[h["name"], h["cluster"], h["cpu_pct"], h["mem_pct"], h["vm_count"],
                          "maintenance" if h.get("maintenance") else h.get("connection")] for h in rows]})
        for h in hot[:3]:
            on = [v for v in vms if v["host"] == h["name"] and v["power"] == "poweredOn"]
            cpu_hot, mem_hot = (h["cpu_pct"] or 0) >= cpu_t, (h["mem_pct"] or 0) >= mem_t
            by = (lambda v: v["cpu_used_mhz"]) if cpu_hot else (lambda v: v["mem_host_mb"])
            top = sorted(on, key=by, reverse=True)[:8]
            r.step(f"top_{h['name']}", f"{h['name']}: VMs using the most {'CPU' if cpu_hot else 'memory'}", "info",
                   f"{len(on)} running VMs.",
                   {"columns": ["VM", "CPU MHz", "CPU % of host", "Host memory", "vCPU / memory", "Resource pool"],
                    "rows": [[v["name"], v["cpu_used_mhz"], pct(v["cpu_used_mhz"], h["cpu_total_mhz"]),
                              human(v["mem_host_mb"] * 1024 ** 2), f"{v['vcpu']} / {human(v['mem_mb'] * 1024 ** 2)}", v["pool"]] for v in top]})
            cl = clusters.get(h["cluster"]) or {}
            r.step(f"drs_{h['name']}", f"DRS of cluster {h['cluster']}", "ok" if cl.get("drs") and cl.get("drs_behavior") == "fullyAutomated"
                   else "warn", ("DRS off: nothing balances the hosts." if not cl.get("drs") else f"DRS on, {cl.get('drs_behavior')}."))
            # Plan: move the heaviest VMs to the coolest hosts of the same cluster until this host is 10 points below.
            peers = [dict(p) for p in hosts if p["cluster"] == h["cluster"] and p["name"] != h["name"]
                     and p.get("connection") == "connected" and not p.get("maintenance")]
            need_cpu = h["cpu_used_mhz"] - h["cpu_total_mhz"] * (cpu_t - 10) / 100 if cpu_hot else 0
            need_mem = h["mem_used_mb"] - h["mem_total_mb"] * (mem_t - 10) / 100 if mem_hot else 0
            moves = []
            for v in sorted(on, key=by, reverse=True):
                if (need_cpu <= 0 and need_mem <= 0) or len(moves) >= 6:
                    break
                fits = [p for p in peers if (pct(p["cpu_used_mhz"] + v["cpu_used_mhz"], p["cpu_total_mhz"]) or 100) < cpu_t - 10
                        and (pct(p["mem_used_mb"] + v["mem_host_mb"], p["mem_total_mb"]) or 100) < mem_t - 10]
                if not fits:
                    continue
                target = min(fits, key=load)
                target["cpu_used_mhz"] += v["cpu_used_mhz"]
                target["mem_used_mb"] += v["mem_host_mb"]
                need_cpu -= v["cpu_used_mhz"]
                need_mem -= v["mem_host_mb"]
                moves.append((v, target["name"]))
            if cl.get("drs") and cl.get("drs_behavior") in ("manual", "partiallyAutomated"):
                r.recommend(f"DRS of {h['cluster']} is {cl.get('drs_behavior')}: look at its recommendations and apply them first.",
                            [f"Get-DrsRecommendation -Cluster {ps(h['cluster'])} | Select-Object Priority, Reason, Recommendation | Format-Table -AutoSize",
                             f"Get-DrsRecommendation -Cluster {ps(h['cluster'])} | Invoke-DrsRecommendation"], where=where)
            if moves:
                after_cpu = pct(h["cpu_used_mhz"] - sum(v["cpu_used_mhz"] for v, _ in moves), h["cpu_total_mhz"])
                after_mem = pct(h["mem_used_mb"] - sum(v["mem_host_mb"] for v, _ in moves), h["mem_total_mb"])
                r.recommend(f"vMotion {len(moves)} VM(s) off {h['name']} to hosts of the same cluster with room (no downtime): "
                            + ", ".join(f"{v['name']} → {t}" for v, t in moves)
                            + f". {h['name']} then runs at about CPU {after_cpu}% / memory {after_mem}%. Dry run first.",
                            [f"Move-VM -VM {ps(v['name'])} -Destination (Get-VMHost {ps(t)}) -WhatIf" for v, t in moves]
                            + [f"Move-VM -VM {ps(v['name'])} -Destination (Get-VMHost {ps(t)})" for v, t in moves]
                            + ["Get-VMHost " + ", ".join(ps(x) for x in [h["name"]] + sorted({t for _, t in moves}))
                               + " | Select-Object Name, @{N='CPU%';E={[math]::Round($_.CpuUsageMhz*100/$_.CpuTotalMhz,1)}}, "
                               "@{N='Mem%';E={[math]::Round($_.MemoryUsageGB*100/$_.MemoryTotalGB,1)}}"],
                            where=where, warning="Stay inside the cluster: vCloud VMs keep their Org VDC resource pool. A VM with a "
                                                 "local disk, passthrough device or CPU affinity cannot move.")
            elif not peers or all(load(p) >= min(cpu_t, mem_t) - 10 for p in peers):
                r.recommend(f"No host of {h['cluster']} has room to take load from {h['name']}: the cluster is full. Escalate for "
                            "capacity (another host, or limits on the noisy VMs) and analyse the busiest VM below.", where=where)
            if top:
                v = top[0]
                r.recommend(f"Look inside {v['name']} ({v['ip'] or 'IP unknown'}, {v['os'] or 'OS unknown'}), the biggest consumer on "
                            f"{h['name']}: a runaway process, or an attack (DDoS / brute force) — stop the process or block the "
                            "sources with the customer's agreement.", guest_commands(v),
                            where=f"Inside the VM {v['name']} (console or SSH / RDP)")
        # Resource pools: a vCloud VM must sit in the pool of its Org VDC (the WI's "correct resource pool").
        by_name = {}
        for p in pools:
            by_name.setdefault((p["cluster"], p["name"]), p)
        wrong = []
        for v in vms:
            if not VCD_NAME.match(v["name"]):
                continue
            expected = next((by_name[(v["cluster"], part)] for part in reversed(str(v.get("folder") or "").split("/"))
                             if (v["cluster"], part) in by_name and VCD_NAME.match(part)), None)
            current = next((p for p in pools if p["moid"] == v.get("pool_moid")), None)
            if expected and v.get("pool_moid") != expected["moid"]:
                wrong.append((v, current, expected))
            elif not expected and current and current.get("root"):
                wrong.append((v, current, None))
        r.step("pools", "vCloud VMs in the resource pool of their Org VDC", "fail" if wrong else "ok",
               (f"{len(wrong)} VM(s) in the wrong pool: power on / changes from vCloud fail (\"Resource Pool not available\")."
                if wrong else "Every vCloud VM is in the pool of its Org VDC."),
               {"columns": ["VM", "Cluster", "Now in pool", "Must be in pool"],
                "rows": [[v["name"], v["cluster"], (c or {}).get("path") or v["pool"], (e or {}).get("name") or "?"] for v, c, e in wrong]})
        for v, c, e in wrong[:10]:
            if e:
                r.recommend(f"Move {v['name']} from {(c or {}).get('name') or v['pool']} into its Org VDC pool {e['name']} (cluster "
                            f"{v['cluster']}), then do the action again from vCloud.",
                            [f"Move-VM -VM {ps(v['name'])} -Destination (Get-ResourcePool -Name {ps(e['name'])} -Location (Get-Cluster {ps(v['cluster'])})) -WhatIf",
                             f"Move-VM -VM {ps(v['name'])} -Destination (Get-ResourcePool -Name {ps(e['name'])} -Location (Get-Cluster {ps(v['cluster'])}))",
                             f"Get-VM -Name {ps(v['name'])} | Select-Object Name, ResourcePool, VMHost"],
                            where=where, warning="Do not edit the pool's CPU / memory allocation in vCenter: vCloud manages it (Org VDC → Allocation).")
            else:
                r.recommend(f"{v['name']} is in the cluster root pool and its Org VDC pool was not found from its folder: find "
                            "the Org VDC of the VM in vCloud, then move it into the pool named '<Org VDC> (<id>)'.",
                            [f"Get-VM -Name {ps(v['name'])} | Select-Object Name, Folder, ResourcePool",
                             f"Get-ResourcePool -Location (Get-Cluster {ps(v['cluster'])}) | Where-Object Name -match '\\(' | Select-Object Name"],
                            where=where)
        full = [p for p in pools if VCD_NAME.match(p["name"]) and p.get("mem_limit_mb") not in (None, -1)
                and pct(p["mem_used_mb"], p["mem_limit_mb"]) and pct(p["mem_used_mb"], p["mem_limit_mb"]) >= 95]
        if full:
            r.step("pool_limits", "Org VDC pools at their memory limit", "warn",
                   "VMs in these pools are throttled even when the hosts have room; the allocation is changed in vCloud "
                   "(Organization VDC → Allocation), not in vCenter.",
                   {"columns": ["Pool", "Memory used", "Limit"],
                    "rows": [[p["name"], human(p["mem_used_mb"] * 1024 ** 2), human(p["mem_limit_mb"] * 1024 ** 2)] for p in full]})
        return r.done()


# =========================================================================================== vCenter health (platform)
# Error / warning events of vCenter by kind (event type id or class): what it means, how serious, the vendor reference.
EVENT_KINDS = (
    (r"esx\.problem\.storage\.apd|esx\.problem\.scsi\.device\.state\.permanentloss|esx\.problem\.storage\.connectivity\.(lost|pathstatechanges)",
     "Storage: all paths down / device lost", "fail", "vmw-apd-pdl"),
    (r"esx\.problem\.vmfs\.heartbeat\.timedout|esx\.problem\.vmfs\.heartbeat\.unrecoverable", "Storage: VMFS heartbeat timed out", "fail", "vmw-vmfs-heartbeat"),
    (r"esx\.problem\.scsi\.device\.io\.latency\.high", "Storage: I/O latency increased", "warn", "vmw-latency"),
    (r"esx\.problem\.storage\.redundancy\.(lost|degraded)|esx\.problem\.storage\.connectivity", "Storage: path redundancy lost", "warn", "vmw-apd-pdl"),
    (r"esx\.problem\.net\.(redundancy|dvport\.redundancy|vmnic\.linkstate|connectivity|dvport\.connectivity)", "Network: uplink down / redundancy lost", "warn", "vmw-uplink"),
    (r"com\.vmware\.vc\.ha|com\.vmware\.vc\.HA|^Das", "vSphere HA", "warn", "vmw-ha"),
    (r"VmFailedMigrateEvent|MigrationErrorEvent|VmFailedRelocateEvent|MigrationHostErrorEvent", "vMotion / migration failed", "warn", ""),
    (r"HostConnectionLostEvent|HostNotRespondingEvent|HostDisconnectedEvent|HostCnxFailed", "ESXi host connection lost", "fail", "vmw-host-not-responding"),
    (r"VmFailedToPowerOnEvent|VmFailedToPowerOffEvent|VmFailedToResetEvent|VmFailedToSuspendEvent", "VM power operation failed", "warn", ""),
    (r"AlarmStatusChangedEvent|AlarmEmailFailedEvent|AlarmSnmpFailedEvent", "Alarm status changes", "info", ""),
)


def event_kind(type_id):
    for pattern, label, level_, ref in EVENT_KINDS:
        if re.search(pattern, str(type_id or "")):
            return label, level_, ref
    return "Other error / warning events", "info", ""


def days_between(older, newer):
    from .openstack import minutes_since
    m = minutes_since(older, newer)
    return None if m is None else m / 1440


class VcenterHealth:
    """Platform health of Acme Prime (not from a KB page): the triggered alarms of vCenter, ESXi hosts that are not
    connected, hardware sensors (CIM through vCenter), datastores that are not accessible, the error / warning events
    of the last hours by kind (APD/PDL, VMFS heartbeat, uplinks, HA, vMotion), VMs that need disk consolidation or keep
    old snapshots. Read-only vCenter account; the fixes are PowerCLI / ESXi commands for an engineer."""
    sources = ("vsphere",)
    phases = 1

    @staticmethod
    def reads(phase, data, params, ctx):
        hours = int(params.get("hours") or 24)
        return {"vsphere": {"health": f"alarms,events@{hours},hosthealth,vmhealth,datastores"}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("vcenter-health")
        item = source(data, "health")
        if unavailable(item):
            r.step("alarms", "Read vCenter", "fail", unavailable(item))
            return r.done()
        inv = json_of(item) or {}
        errors = inv.get("errors") or {}
        hours, snap_days = int(params.get("hours") or 24), int(params.get("snapshot_days") or 3)
        vcenter = ctx.get("vcenter_host") or "<vCenter>"
        where = f"PowerShell with PowerCLI, after: Connect-VIServer -Server {vcenter}"
        newest = max([e.get("time") or "" for e in inv.get("events") or []] + [a.get("time") or "" for a in inv.get("alarms") or []] + [""])

        # ---------------- triggered alarms ----------------
        if "alarms" in errors:
            r.step("alarms", "Triggered alarms", "skip", f"Not read: {errors['alarms']}")
        else:
            alarms = sorted(inv.get("alarms") or [], key=lambda a: ({"red": 0, "yellow": 1}.get(a.get("status"), 2), a.get("time") or ""))
            red = [a for a in alarms if a.get("status") == "red" and not a.get("acknowledged")]
            yellow = [a for a in alarms if a.get("status") == "yellow" or (a.get("status") == "red" and a.get("acknowledged"))]
            r.step("alarms", "Triggered alarms", "fail" if red else "warn" if yellow else "ok",
                   f"{len(red)} critical, {len(yellow)} warning or acknowledged." if alarms else "No triggered alarm.",
                   {"columns": ["Severity", "Alarm", "Object", "Type", "Since (UTC)", "Acknowledged"],
                    "rows": [[{"red": "Critical", "yellow": "Warning"}.get(a.get("status"), a.get("status")), a.get("alarm"),
                              a.get("entity"), a.get("entity_type"), str(a.get("time") or "")[:19],
                              a.get("acknowledged_by") or ("yes" if a.get("acknowledged") else "")] for a in alarms]},
                   marks=[a.get("alarm") for a in red])
            if red:
                r.recommend(f"{len(red)} critical alarm(s) are not acknowledged. Open each one in the vSphere Client (Monitor → "
                            "Issues and Alarms → Triggered Alarms) and follow the steps below for its kind; acknowledge it only "
                            "once someone works on it.",
                            ["(Get-Folder -NoRecursion | Get-View).TriggeredAlarmState | Select-Object OverallStatus, Time, "
                             "@{N='Alarm';E={(Get-View $_.Alarm).Info.Name}}, @{N='Object';E={(Get-View $_.Entity).Name}} | "
                             "Sort-Object Time | Format-Table -AutoSize"],
                            where=where, refs=["vmw-alarms"],
                            items={"columns": ["Alarm", "Object", "Since (UTC)"],
                                   "rows": [[a.get("alarm"), a.get("entity"), str(a.get("time") or "")[:19]] for a in red]})

        # ---------------- hosts and hardware ----------------
        if "hosthealth" in errors:
            r.step("hosts", "ESXi hosts and hardware", "skip", f"Not read: {errors['hosthealth']}")
        else:
            hosts = inv.get("hosthealth") or []
            down = [h for h in hosts if h.get("connection") != "connected" and not h.get("maintenance")]
            r.step("hosts", "ESXi hosts connected", "fail" if down else "ok",
                   f"{len(down)} of {len(hosts)} host(s) not connected." if down else f"{len(hosts)} host(s), all connected or in maintenance.",
                   {"columns": ["Host", "Connection", "Maintenance", "Status", "Hardware"],
                    "rows": [[h.get("name"), h.get("connection"), "yes" if h.get("maintenance") else "no", h.get("status"),
                              f"{h.get('vendor')} {h.get('model')}".strip()] for h in sorted(hosts, key=lambda x: (x.get("connection") == "connected", x.get("name") or ""))]},
                   marks=[h.get("name") for h in down])
            for h in down:
                r.recommend(f"{h.get('name')} is {h.get('connection')} in vCenter: its VMs cannot be managed (and vSphere HA may "
                            "restart them elsewhere if the host is really down). Check whether the host answers (ping, DCUI / BMC "
                            "console); if it runs, restart its management agents from the DCUI or SSH, then reconnect it.",
                            [f"Get-VMHost {ps(h.get('name'))} | Select-Object Name, ConnectionState, PowerState",
                             "/etc/init.d/hostd restart", "/etc/init.d/vpxa restart",
                             f"Get-VMHost {ps(h.get('name'))} | Set-VMHost -State Connected"],
                            where=f"{where}; hostd / vpxa: on {h.get('name')} (DCUI or SSH)",
                            warning="Restarting the management agents does not stop VMs, but tasks running on the host fail; "
                                    "do not restart them during a vMotion or a backup.",
                            refs=["vmw-host-not-responding"])
            hw = [(h, x) for h in hosts for x in (h.get("sensors") or []) + (h.get("hardware") or [])]
            red_hw = [p for p in hw if p[1].get("state") == "red"]
            r.step("hardware", "Hardware sensors of the hosts (CIM)", "fail" if red_hw else "warn" if hw else "ok",
                   f"{len(hw)} sensor(s) or component(s) not green." if hw else "Every sensor reported is green.",
                   {"columns": ["Host", "Sensor / component", "Type", "State", "Reading"],
                    "rows": [[h.get("name"), x.get("name"), x.get("type"), x.get("state"), x.get("reading", "")] for h, x in hw]},
                   marks=[x.get("name") for _, x in red_hw])
            for name in sorted({h.get("name") for h, _ in hw}):
                parts = [x for h, x in hw if h.get("name") == name]
                r.recommend(f"{name}: {len(parts)} hardware sensor(s) or component(s) are not green. Read the event log of its "
                            "BMC (check Servers (BMC) when the BMC is on the page BMC) and open a case with the hardware vendor "
                            "with that log; move the VMs off the host first when a memory or power component is red.",
                            [f"(Get-VMHost {ps(name)} | Get-View).Runtime.HealthSystemRuntime.SystemHealthInfo.NumericSensorInfo | "
                             "Where-Object { $_.HealthState.Key -ne 'green' } | Select-Object Name, SensorType, "
                             "@{N='State';E={$_.HealthState.Key}}"],
                            where=where, refs=["vmw-hardware"],
                            items={"columns": ["Sensor / component", "Type", "State"],
                                   "rows": [[x.get("name"), x.get("type"), x.get("state")] for x in parts]})
            issues = [(h.get("name"), i) for h in hosts for i in h.get("issues") or []]
            if issues:
                r.step("issues", "Configuration issues of the hosts", "warn", f"{len(issues)} issue(s).",
                       {"columns": ["Host", "Issue"], "rows": [[n, i] for n, i in issues]})

        # ---------------- datastores ----------------
        if "datastores" in errors:
            r.step("datastores", "Datastores accessible", "skip", f"Not read: {errors['datastores']}")
        else:
            stores = inv.get("datastores") or []
            lost = [d for d in stores if not d.get("accessible")]
            r.step("datastores", "Datastores accessible", "fail" if lost else "ok",
                   f"{len(lost)} datastore(s) not accessible." if lost else f"{len(stores)} datastore(s), all accessible.",
                   {"columns": ["Datastore", "Type", "Status"], "rows": [[d.get("name"), d.get("type"), d.get("status")] for d in lost]},
                   marks=[d.get("name") for d in lost])
            if lost:
                r.recommend(f"{len(lost)} datastore(s) are not accessible: the VMs on them are stopped or hang. Look at the storage "
                            "paths of the hosts and at the array (LUN, zoning, NFS export) before rescanning.",
                            [f"Get-Datastore {', '.join(ps(d.get('name')) for d in lost[:10])} | Select-Object Name, State, Type",
                             "Get-VMHost | Get-ScsiLun -LunType disk | Get-ScsiLunPath | Where-Object State -eq 'Dead' | "
                             "Select-Object @{N='Host';E={$_.ScsiLun.VMHost}}, ScsiLun, Name, State"],
                            where=where, refs=["vmw-apd-pdl"])

        # ---------------- events of the last hours ----------------
        if "events" in errors:
            r.step("events", f"Error and warning events (last {hours} h)", "skip", f"Not read: {errors['events']}")
        else:
            events = inv.get("events") or []
            groups = {}
            for e in events:
                label, lvl, ref = event_kind(e.get("type"))
                g = groups.setdefault(label, {"level": lvl, "ref": ref, "count": 0, "last": "", "objects": set(), "sample": "", "types": set()})
                g["count"] += 1
                g["types"].add(e.get("type"))
                if (e.get("time") or "") > g["last"]:
                    g["last"], g["sample"] = e.get("time") or "", e.get("message") or ""
                for k in ("host", "datastore", "vm"):
                    if e.get(k):
                        g["objects"].add(e[k])
            order = sorted(groups.items(), key=lambda kv: ({"fail": 0, "warn": 1, "info": 2}[kv[1]["level"]], -kv[1]["count"]))
            status = "fail" if any(g["level"] == "fail" for g in groups.values()) else "warn" if any(g["level"] == "warn" for g in groups.values()) else "ok"
            r.step("events", f"Error and warning events (last {hours} h)", status,
                   f"{len(events)} event(s) in {len(groups)} kind(s)" + (" (vCenter returns at most 1000: shorten the period to see "
                                                                          "all of them)." if len(events) >= 1000 else ".")
                   if events else "No error or warning event.",
                   {"columns": ["Kind", "Events", "Last (UTC)", "Objects", "Last message"],
                    "rows": [[label, g["count"], g["last"][:19], ", ".join(sorted(g["objects"])[:6]) + (" …" if len(g["objects"]) > 6 else ""),
                              g["sample"][:200]] for label, g in order]},
                   marks=[label for label, g in order if g["level"] == "fail"])
            for label, g in order:
                if g["level"] == "info":
                    continue
                objs = sorted(g["objects"])[:10]
                hosts_ = [o for o in objs if o in {h.get("name") for h in inv.get("hosthealth") or []}]
                cmds = []
                if label.startswith("Storage"):
                    cmds = [f"Get-VMHost {', '.join(ps(h) for h in hosts_[:5])} | Get-ScsiLun -LunType disk | Get-ScsiLunPath | "
                            "Where-Object State -ne 'Active' | Select-Object @{N='Host';E={$_.ScsiLun.VMHost}}, ScsiLun, Name, State"] if hosts_ else []
                elif label.startswith("Network"):
                    cmds = [f"Get-VMHost {', '.join(ps(h) for h in hosts_[:5])} | Get-VMHostNetworkAdapter -Physical | "
                            "Select-Object VMHost, Name, BitRatePerSec, FullDuplex, Mac"] if hosts_ else []
                cmds.append(f"Get-VIEvent -Start (Get-Date).AddHours(-{hours}) -MaxSamples 5000 | Where-Object {{ $_.FullFormattedMessage }} | "
                            f"Where-Object {{ ($_.EventTypeId, $_.GetType().Name) -match '{'|'.join(sorted(t for t in g['types'] if t))[:200]}' }} | "
                            "Select-Object CreatedTime, FullFormattedMessage | Format-Table -AutoSize -Wrap")
                text = {"Storage: all paths down / device lost": "The hosts lost every path to a storage device (APD) or the array "
                        "reported it gone (PDL): VMs on it hang or stop. Check the array, its LUN mapping and the SAN / NFS network, "
                        "then the paths on the hosts below.",
                        "Storage: VMFS heartbeat timed out": "Hosts could not update the VMFS heartbeat: the storage answers too "
                        "slowly or not at all. Check the array latency and the paths.",
                        "Storage: I/O latency increased": "A device answered much slower than usual: look at the array load and "
                        "the paths; repeated events mean the array or the SAN is saturated.",
                        "Storage: path redundancy lost": "Hosts lost one of the paths to a storage device: one more failure stops "
                        "the VMs. Check the cable, the switch port and the array port of that path.",
                        "Network: uplink down / redundancy lost": "A physical uplink (vmnic) of the hosts went down: the port "
                        "groups run on fewer uplinks. Check the cable, the switch port and the NIC.",
                        "vSphere HA": "vSphere HA reported problems (agent, isolation, failover): look at the cluster's vSphere HA "
                        "monitoring and the configuration issues of the hosts.",
                        "vMotion / migration failed": "Migrations failed: read the messages (network of vMotion, CPU "
                        "compatibility, locked files).",
                        "ESXi host connection lost": "vCenter lost the connection to hosts: see ESXi hosts connected above.",
                        "VM power operation failed": "Power operations of VMs failed: read the messages (resources, locked "
                        "files, the resource pool of vCloud)."}.get(label, f"{label}: read the messages.")
                r.recommend(f"{label}: {g['count']} event(s), last at {g['last'][:19]} UTC. {text}", cmds, where=where,
                            refs=[g["ref"]] if g["ref"] else None,
                            items={"columns": ["Object"], "rows": [[o] for o in objs]} if objs else None)

        # ---------------- VMs: consolidation, old snapshots, tools ----------------
        if "vmhealth" in errors:
            r.step("vms", "VMs: disk consolidation and old snapshots", "skip", f"Not read: {errors['vmhealth']}")
        else:
            vms = inv.get("vmhealth") or []
            consolidate = [v for v in vms if v.get("consolidate")]
            old = []
            for v in vms:
                snaps = v.get("snapshots") or []
                if snaps:
                    age = days_between(snaps[0].get("created"), newest) if newest else None
                    if age is not None and age >= snap_days:
                        old.append((v, len(snaps), int(age)))
            r.step("vms", f"VMs: disk consolidation and snapshots older than {snap_days} days",
                   "warn" if consolidate or old else "ok",
                   f"{len(consolidate)} need consolidation, {len(old)} keep old snapshots." if consolidate or old else "None.",
                   {"columns": ["VM", "Host", "Consolidation needed", "Snapshots", "Oldest (days)"],
                    "rows": [[v.get("name"), v.get("host"), "yes" if v.get("consolidate") else "",
                              len(v.get("snapshots") or []), next((a for x, _, a in old if x is v), "")]
                             for v in sorted(vms, key=lambda x: x.get("name") or "") if v.get("consolidate") or any(x is v for x, _, _ in old)]})
            if consolidate:
                names = [v.get("name") for v in consolidate]
                r.recommend(f"{len(consolidate)} VM(s) need disk consolidation: a snapshot delete left delta disks behind, which "
                            "grow and slow the VM. Consolidate them outside busy hours (I/O load).",
                            [f"Get-VM {', '.join(ps(n) for n in names[:20])} | Select-Object Name, @{{N='Consolidate';E={{$_.ExtensionData.Runtime.ConsolidationNeeded}}}}"]
                            + [f"(Get-VM {ps(n)}).ExtensionData.ConsolidateVMDisks_Task()" for n in names[:20]],
                            where=where, warning="A consolidation fails while a backup holds the disks: check the backup jobs first.",
                            refs=["vmw-consolidate"], items={"columns": ["VM", "Host"], "rows": [[v.get("name"), v.get("host")] for v in consolidate]})
            if old:
                names = [v.get("name") for v, _, _ in old]
                r.recommend(f"{len(old)} VM(s) keep snapshots older than {snap_days} days: snapshots are not backups, they grow "
                            "and slow the VM, and fill the datastore. Confirm with the VM owner, then delete them (dry run first).",
                            [f"Get-VM {', '.join(ps(n) for n in names[:20])} | Get-Snapshot | Sort-Object Created | Select-Object VM, Name, Created, "
                             "@{N='SizeGB';E={[math]::Round($_.SizeGB,1)}} | Format-Table -AutoSize",
                             f"Get-VM {', '.join(ps(n) for n in names[:20])} | Get-Snapshot | Where-Object {{ $_.Created -lt (Get-Date).AddDays(-{snap_days}) }} | Remove-Snapshot -WhatIf"],
                            where=where, warning="Deleting a large snapshot consolidates the disk (I/O load): not during a backup.",
                            refs=["vmw-snapshots"],
                            items={"columns": ["VM", "Host", "Snapshots", "Oldest (days)"], "rows": [[v.get("name"), v.get("host"), n, a] for v, n, a in old]})
            tools = [v for v in vms if v.get("power") == "poweredOn" and v.get("tools") == "guestToolsNotRunning"]
            if tools:
                r.step("tools", "Powered-on VMs without VMware Tools running", "info",
                       f"{len(tools)} VM(s): no guest IP / heartbeat in vCenter, no quiesced backup.",
                       {"columns": ["VM", "Host"], "rows": [[v.get("name"), v.get("host")] for v in tools]})
        return r.done()

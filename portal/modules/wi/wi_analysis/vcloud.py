"""Operation Automation checks of Acme Prime in vCloud Director, read with the site's read-only provider account (REST GET only:
the legacy query service /api/query and the CloudAPI /cloudapi/1.0.0), plus vCenter (REST) where the WI compares both.

The fixes name the real objects that were read (VM, Org VDC, network, IPs, edge gateway, tunnel, rules) with the values
to enter; the portal never changes anything in vCloud Director or vCenter."""
import datetime
import ipaddress
import re
import urllib.parse

from .common import Result, human, json_of, source, unavailable

UUID_RE = re.compile(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")
URN = re.compile(r"^urn:vcloud:[A-Za-z]+:[0-9a-f-]{36}$")
IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
MAC_RE = re.compile(r"\b([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b", re.I)
STUCK_MINUTES = 30


def qv(value):
    """A value inside a query filter, URL-encoded (spaces, '=' and ';' of names cannot break the filter)."""
    return urllib.parse.quote(str(value), safe="")


def records(item):
    data = json_of(item) or {}
    return data.get("record") or [] if isinstance(data, dict) else []


def values(item):
    data = json_of(item) or {}
    return data.get("values") or [] if isinstance(data, dict) else []


def uuid_of(text):
    m = UUID_RE.search(str(text or ""))
    return m.group(1) if m else ""


def when(text):
    try:
        return datetime.datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except ValueError:
        return None


def age_minutes(start, now):
    a, b = when(start), when(now)
    if not a or not b:
        return None
    if a.tzinfo is None:
        a = a.replace(tzinfo=datetime.timezone.utc)
    return int((b - a).total_seconds() // 60)


def provider_ui(ctx, path):
    host = ctx.get("vcd_host") or "<vCloud Director>"
    return f"vCloud Director provider portal https://{host}/provider — {path}"


def classify(message):
    """The cause of a failed task, by the error texts of the WIs."""
    m = str(message or "").lower()
    if "already been used by running virtual machines" in m or "conflict ip" in m or "ip address conflict" in m:
        return "conflict"
    if "resource pool" in m:
        return "pool"
    if "quota" in m or "allocation" in m or "exceed" in m or "insufficient" in m or "not enough" in m:
        return "quota"
    if "name" in m and ("invalid" in m or "error" in m):
        return "name"
    return "other"


# =========================================================================================== VM power on / state / tasks
class VcdVmPower:
    """WIs "Error on VM Power On" (Org VDC quota, wrong resource pool), "Error on VM Power On (IP Address Conflict)",
    "Error on VM Power On after NIC Change", "VM in Inconsistent Status in vCloud" and "Action Power
    On/Off or Edit VM Takes a Long Time in vCloud" (stuck task on a cell)."""
    sources = ("vcd", "vcenter")
    phases = 4
    at = {"state": ["vcd", "vcenter"], "pool": ["vcenter"]}   # steps that read vCenter too

    @staticmethod
    def _vm(data, params):
        found = records(source(data, "vm"))
        return found[0] if found else {}

    @staticmethod
    def _error_task(data):
        tasks = records(source(data, "tasks"))
        return next((t for t in tasks if str(t.get("status")).lower() == "error"), None)

    @staticmethod
    def reads(phase, data, params, ctx):
        name = params["vm"]
        if phase == 1:
            return {"vcd": {"vm": f"/api/query?type=adminVM&format=records&pageSize=10&filter=name=={qv(name)};isVAppTemplate==false",
                            "tasks": f"/api/query?type=adminTask&format=records&pageSize=15&sortDesc=startDate&filter=objectName=={qv(name)}",
                            "running": "/api/query?type=adminTask&format=records&pageSize=50&sortDesc=startDate&filter=status==running",
                            "cells": "/api/query?type=cell&format=records&pageSize=25"}}
        vm = VcdVmPower._vm(data, params)
        if not vm:
            return {}
        err = VcdVmPower._error_task(data)
        cause = classify((err or {}).get("details")) if err else ""
        vdc_id = uuid_of(vm.get("vdc"))
        if phase == 2:
            out = {"vcd": {}, "vcenter": {}}
            if vdc_id:
                out["vcd"]["vdc"] = f"/api/admin/vdc/{vdc_id}"
            if cause == "conflict" and vm.get("networkName"):
                out["vcd"]["network"] = f"/cloudapi/1.0.0/orgVdcNetworks?filter=name=={qv(vm['networkName'])}&pageSize=10"
            vm_id = uuid_of(vm.get("href"))
            if vm_id:   # by its vCenter name "<name> (<uuid>)": unique across the vCenters of every site (morefs are not)
                out["vcenter"]["power"] = f"/api/vcenter/vm?names={qv(vm['name'] + ' (' + vm_id + ')')}"
                out["vcd"]["nics"] = f"/api/vApp/vm-{vm_id}/networkConnectionSection/"   # NICs, as on VM → Hardware → NICs
            return out
        if phase == 3:
            out = {"vcd": {}, "vcenter": {}}
            net = next((n for n in values(source(data, "network")) if URN.match(str(n.get("id") or ""))), None)
            if net:
                out["vcd"]["ips"] = f"/cloudapi/1.0.0/orgVdcNetworks/{net['id']}/allocatedIpAddresses?pageSize=128"
            vdc = json_of(source(data, "vdc")) or {}
            in_this_vcenter = bool(VcdVmPower._vcenter_vm(data))
            if vdc.get("name") and vdc_id and in_this_vcenter and (cause == "pool" or str(vm.get("status")) in ("UNRESOLVED", "INCONSISTENT_STATE", "UNRECOGNIZED")
                                                                   or VcdVmPower._inconsistent(vm, data)):
                out["vcenter"]["pool"] = f"/api/vcenter/resource-pool?names={qv(vdc['name'] + ' (' + vdc_id + ')')}"
            return out
        pools = json_of(source(data, "pool")) or []
        vm_id = uuid_of(vm.get("href"))
        if phase == 4 and pools and isinstance(pools, list) and vm_id:
            rp = pools[0].get("resource_pool")
            if re.match(r"^resgroup-\d+$", str(rp or "")):
                return {"vcenter": {"in_pool": f"/api/vcenter/vm?resource_pools={rp}&names={qv(vm['name'] + ' (' + vm_id + ')')}"}}
        return {}

    @staticmethod
    def _vcenter_vm(data):
        """The VM in the vCenter of the chosen site ({"vm", "name", "power_state"}), or None (not there, or not read)."""
        item = source(data, "power")
        found = json_of(item) if not unavailable(item) else None
        return found[0] if isinstance(found, list) and found else None

    @staticmethod
    def _inconsistent(vm, data):
        vc = (VcdVmPower._vcenter_vm(data) or {}).get("power_state")
        status = str(vm.get("status") or "")
        if not vc:
            return False
        return (vc == "POWERED_ON") != (status == "POWERED_ON")

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("vcd-vm-power")
        name = params["vm"]
        item = source(data, "vm")
        if unavailable(item):
            r.step("vm", "Find the VM in vCloud Director", "fail", unavailable(item))
            return r.done()
        found = records(item)
        if not found:
            r.step("vm", "Find the VM in vCloud Director", "fail", f"No VM named {name} (names are case sensitive; a VM in a "
                   "vApp template is not counted).")
            return r.done()
        vm = found[0]
        vm_id = uuid_of(vm.get("href"))
        vc_name = f"{vm.get('name')} ({vm_id})" if vm_id else vm.get("name")
        status = str(vm.get("status") or "")
        r.step("vm", "VM in vCloud Director", "ok" if status in ("POWERED_ON", "POWERED_OFF") else "warn",
               f"{vm.get('name')} is {status}" + (", busy (a task is running)" if vm.get("isBusy") else "")
               + f", vApp {vm.get('containerName') or '-'}, host {vm.get('hostName') or '-'}, network {vm.get('networkName') or '-'}"
               + (f" ({vm.get('ipAddress')})" if vm.get("ipAddress") else "") + "."
               + (f" {len(found)} VMs have this name: the first one is used." if len(found) > 1 else ""),
               {"columns": ["VM", "Status", "vApp", "Org VDC", "Memory", "vCPU", "In vCenter"],
                "rows": [[x.get("name"), x.get("status"), x.get("containerName"), x.get("vdcName") or uuid_of(x.get("vdc")),
                          human((x.get("memoryMB") or 0) * 1024 ** 2), x.get("numberOfCpus"), x.get("moref")] for x in found]})
        tasks = records(source(data, "tasks"))
        err = next((t for t in tasks if str(t.get("status")).lower() == "error"), None)
        r.step("tasks", "Recent tasks of the VM", "fail" if err and tasks and tasks[0] is err else "warn" if err else "ok" if tasks else "info",
               (f"Last failure: {err.get('operationFull') or err.get('name')} — {err.get('details') or 'no message'}" if err
                else "No failed task." if tasks else "No task found for this VM."),
               {"columns": ["Started", "Operation", "Status", "By", "Details"],
                "rows": [[t.get("startDate"), t.get("operationFull") or t.get("name"), t.get("status"), t.get("ownerName"),
                          str(t.get("details") or "")[:200]] for t in tasks]})
        cause = classify(err.get("details")) if err else ""
        ui = provider_ui
        power = source(data, "power")
        vc_vm = VcdVmPower._vcenter_vm(data)
        vc_state = (vc_vm or {}).get("power_state")
        elsewhere = "power" in (data or {}) and not unavailable(power) and not vc_vm   # read, but not in this vCenter
        # ---- quota of the Org VDC
        vdc = json_of(source(data, "vdc")) or {}
        if vdc:
            cap = vdc.get("computeCapacity") or {}
            mem, cpu = cap.get("memory") or {}, cap.get("cpu") or {}
            need_mb = int(vm.get("memoryMB") or 0) if "POWERED_ON" not in (status, vc_state) else 0
            mem_limit, mem_used = mem.get("limit") or 0, mem.get("used") or 0
            short = mem_limit > 0 and mem_used + need_mb > mem_limit
            r.step("quota", f"Allocation of Org VDC {vdc.get('name')}",
                   "fail" if short and cause in ("quota", "") else "warn" if short or cause == "quota" else "ok",
                   f"Memory used {mem_used} of {mem_limit or 'unlimited'} {mem.get('units') or 'MB'}; CPU used {cpu.get('used', 0)} of "
                   f"{cpu.get('limit') or 'unlimited'} {cpu.get('units') or 'MHz'} ({vdc.get('allocationModel') or '-'})."
                   + (f" Powering on {vm.get('name')} needs {need_mb} MB more: {mem_used + need_mb - mem_limit} MB over the limit." if short else ""))
            if short and cause in ("quota", ""):
                new_limit = -(-(mem_used + need_mb) // 1024) * 1024
                r.recommend(f"The Org VDC {vdc.get('name')} has no memory left for {vm.get('name')} ({need_mb} MB). After the "
                            f"customer agrees (administrative process for extra quota), raise the memory allocation from "
                            f"{mem_limit} MB to at least {new_limit} MB, then power the VM on again from vCloud. Or the customer "
                            "powers off / shrinks another VM of the same VDC.", [],
                            where=ui(ctx, f"Cloud Resources → Organization VDCs → {vdc.get('name')} → Configure → Allocation → Edit"))
        # ---- IP / MAC already used
        if cause == "conflict":
            text = str(err.get("details") or "")
            ips, macs = sorted(set(IP_RE.findall(text))), sorted(set(MAC_RE.findall(text)))
            nets = values(source(data, "network"))
            used = values(source(data, "ips"))
            clash = [u for u in used if u.get("ipAddress") in ips]
            r.step("conflict", f"IP Usage of network {vm.get('networkName') or '?'}", "fail",
                   f"IP {', '.join(ips) or '-'}" + (f" / MAC {', '.join(macs)}" if macs else "") + " is already used by a running VM"
                   + (": " + ", ".join(f"{u.get('entityName') or '?'} ({u.get('allocationType') or '-'})" for u in clash
                                       if u.get("entityName") != vm.get("name")) if clash else "") + ".",
                   {"columns": ["IP", "Used by", "Allocation", "Deployed"],
                    "rows": [[u.get("ipAddress"), u.get("entityName"), u.get("allocationType"), u.get("deployed")] for u in clash]})
            free = ""
            net = nets[0] if nets else {}
            taken = {u.get("ipAddress") for u in used}
            for sub in ((net.get("subnets") or {}).get("values") or []):
                for rng in ((sub.get("ipRanges") or {}).get("values") or []):
                    try:
                        a, b = ipaddress.ip_address(rng["startAddress"]), ipaddress.ip_address(rng["endAddress"])
                    except (KeyError, ValueError):
                        continue
                    while a <= b and not free:
                        if str(a) not in taken:
                            free = str(a)
                        a += 1
            other = ", ".join(sorted({u.get("entityName") for u in clash if u.get("entityName") and u.get("entityName") != vm.get("name")})) or "another VM"
            r.recommend(f"{ips[0] if ips else 'The IP'} is already used by {other}. Give {vm.get('name')} a free IP: remove its NIC "
                        "with that IP, add the NIC again" + (f" with IP {free} (free in the static pool of {vm.get('networkName')})" if free else
                                                             " with an IP that is free in IP Usage")
                        + ", then power on. If the VM really needs the same IP/MAC as the other VM, use Fence vApp instead.",
                        [], where=ui(ctx, (f"Organization {vm.get('orgName')} → " if vm.get("orgName") else "the organization → ")
                                     + f"Compute → Virtual Machines → {vm.get('name')} → Hardware → NICs → Edit (IP mode Static - Manual)"),
                        warning="Remove only the NIC with the conflicting IP; note its network and adapter type first.")
        # ---- vCloud and vCenter disagree (inconsistent status)
        inconsistent = bool(vc_state) and ((vc_state == "POWERED_ON") != (status == "POWERED_ON"))
        if vc_state or "power" in (data or {}):
            site = ctx.get("site") or "this site"
            r.step("state", f"Power state: vCloud Director vs vCenter {site}", "fail" if inconsistent else "ok" if vc_state else "skip",
                   (f"vCloud says {status}, vCenter says {vc_state}: the VM was powered on or off in vCenter, not from vCloud."
                    if inconsistent else f"Both {vc_state}." if vc_state else
                    f"{vc_name} is not in the vCenter of {site}: vCloud Director serves every site, the VM runs on another one. "
                    "Run the check again on the site of the VM to compare vCenter and its resource pool." if elsewhere
                    else unavailable(power)))
        in_pool = source(data, "in_pool")
        pools = json_of(source(data, "pool")) or []
        wrong_pool = "in_pool" in (data or {}) and not unavailable(in_pool) and not (json_of(in_pool) or [])
        if "pool" in (data or {}):
            pool_name = pools[0].get("name") if pools and isinstance(pools, list) else ""
            r.step("pool", "VM in the resource pool of its Org VDC (vCenter)", "fail" if wrong_pool else "ok" if pools else "warn",
                   (f"{vc_name} is not in {pool_name}." if wrong_pool else f"In {pool_name}." if pools and "in_pool" in (data or {})
                    else "The Org VDC resource pool was not found in vCenter." if not pools else "Not checked."))
            if wrong_pool:
                r.recommend(f"Move {vc_name} into its Org VDC pool {pool_name} (the WI's vMotion to the right resource pool), "
                            "then do the action again from vCloud.",
                            [f"Move-VM -VM '{vc_name}' -Destination (Get-ResourcePool -Name '{pool_name}') -WhatIf",
                             f"Move-VM -VM '{vc_name}' -Destination (Get-ResourcePool -Name '{pool_name}')",
                             f"Get-VM -Name '{vc_name}' | Select-Object Name, ResourcePool, PowerState"],
                            where=f"PowerShell with PowerCLI, after: Connect-VIServer -Server {ctx.get('vcenter_host') or '<vCenter>'}")
        if inconsistent and not wrong_pool:
            r.recommend(f"Sync the state the way the WI says: with the customer's permission power {vm.get('name')} off in vCenter "
                        "(shut down the guest), wait until it is off, then power it on from vCloud Director — never from vCenter.",
                        [f"Shutdown-VMGuest -VM '{vc_name}' -Confirm:$false",
                         f"while ((Get-VM -Name '{vc_name}').PowerState -ne 'PoweredOff') {{ Start-Sleep 10 }}",
                         f"Get-VM -Name '{vc_name}' | Select-Object Name, PowerState"],
                        where=f"PowerShell with PowerCLI, after: Connect-VIServer -Server {ctx.get('vcenter_host') or '<vCenter>'} "
                              f"— then {provider_ui(ctx, 'the VM → Power On')}",
                        warning="If VMware Tools is not running, Shutdown-VMGuest fails: use Stop-VM -Kill only after the customer agrees.")
        # ---- tasks stuck on a cell
        running = records(source(data, "running"))
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        stuck = [t for t in running if (age_minutes(t.get("startDate"), now) or 0) >= STUCK_MINUTES]
        cells = records(source(data, "cells"))
        mine = [t for t in stuck if t.get("objectName") == name]
        r.step("stuck", f"Tasks running for more than {STUCK_MINUTES} minutes", "fail" if mine else "info" if stuck else "ok",
               ((f"{len(mine)} on {name}, {len(stuck)} in total. vCenter usually finished them already; the vCloud cell that runs "
                 "them is stuck." if mine else f"None on {name}; {len(stuck)} on other objects (listed).") if stuck else "None."),
               {"columns": ["Started", "Minutes", "Operation", "Object", "Owner"],
                "rows": [[t.get("startDate"), age_minutes(t.get("startDate"), now), t.get("operationFull") or t.get("name"),
                          t.get("objectName"), t.get("ownerName")] for t in stuck]})
        r.step("cells", "vCloud Director cells", "ok" if cells and all(c.get("isActive") in (True, "true", 1) for c in cells) else "warn",
               f"{sum(1 for c in cells if c.get('isActive') in (True, 'true', 1))} of {len(cells)} active." if cells else "Cell list not readable.",
               {"columns": ["Cell", "Primary IP", "Active", "Version"],
                "rows": [[c.get("name"), c.get("primaryIp"), c.get("isActive"), c.get("productBuildNumber") or c.get("version")] for c in cells]})
        if mine:
            cell_names = ", ".join(c.get("name") for c in cells if c.get("name")) or "cell-01"
            r.recommend(f"Find the cell that runs the stuck task ({mine[0].get('operationFull') or mine[0].get('name')}, "
                        f"{age_minutes(mine[0].get('startDate'), now)} minutes): Monitor → Tasks → the task → Cell. On that cell ({cell_names}) "
                        "stop new work, wait until its active jobs are 0, then restart the service. If the cell does not answer, "
                        "restart the cell VM from vCenter Management (DCB).",
                        ["sudo /opt/vmware/vcloud-director/bin/cell-management-tool -u administrator cell --status",
                         "sudo /opt/vmware/vcloud-director/bin/cell-management-tool -u administrator cell --quiesce true",
                         "sudo /opt/vmware/vcloud-director/bin/cell-management-tool -u administrator cell --status   # until Job count = 0",
                         "sudo /opt/vmware/vcloud-director/bin/cell-management-tool -u administrator cell --shutdown",
                         "sudo systemctl start vmware-vcd", "sudo systemctl status vmware-vcd --no-pager"],
                        where="SSH to the vCloud Director cell that runs the task (cell-management-tool asks for the password)",
                        warning="Restart one cell at a time and never while other critical tasks still run on it.")
        if err and cause in ("other", "name") and not r.recommendations:
            r.recommend(f"The last failure of {vm.get('name')} is not one of the WI cases: read the full error of the task and "
                        "escalate with it.", [], where=provider_ui(ctx, f"Monitor → Tasks → {err.get('operationFull') or err.get('name')} on {name}"))
        return r.done()


# =========================================================================================== Edge gateway
def ip_in(ip, spec):
    """ip inside an address, a CIDR or a range 'a-b'."""
    try:
        addr = ipaddress.ip_address(ip)
        spec = str(spec).strip()
        if "-" in spec:
            a, b = spec.split("-", 1)
            return ipaddress.ip_address(a.strip()) <= addr <= ipaddress.ip_address(b.strip())
        return addr in ipaddress.ip_network(spec, strict=False)
    except ValueError:
        return False


def port_in_profile(profile, port, proto="TCP"):
    for app in profile.get("applicationPorts") or []:
        if str(app.get("protocol") or "").upper() not in (proto, "TCP_UDP", ""):
            continue
        for spec in app.get("destinationPorts") or []:
            lo, _, hi = str(spec).partition("-")
            if lo.strip().isdigit() and int(lo) <= port <= int(hi or lo):
                return True
        if not app.get("destinationPorts"):
            return True
    return False


class VcdEdge:
    """WIs "IPSec State Down in Statistics", "Service on a VM Cannot Be Accessed from Outside (Port Specific)" and "VM Cannot
    Connect to the Local/Internet Network" on an NSX-T backed edge gateway: IPsec tunnels and their status, NAT rules, and
    the firewall rule that decides a port to a VM."""
    sources = ("vcd",)
    phases = 3

    @staticmethod
    def _edge(data):
        found = [e for e in values(source(data, "edges")) if URN.match(str(e.get("id") or ""))]
        return found[0] if found else {}

    @staticmethod
    def reads(phase, data, params, ctx):
        if phase == 1:
            return {"vcd": {"edges": f"/cloudapi/1.0.0/edgeGateways?filter=name=={qv(params['edge'])}&pageSize=10"}}
        edge = VcdEdge._edge(data)
        if not edge:
            return {}
        base = f"/cloudapi/1.0.0/edgeGateways/{edge['id']}"
        if phase == 2:
            return {"vcd": {"ipsec": f"{base}/ipsec/tunnels?pageSize=50", "nat": f"{base}/nat/rules?pageSize=128",
                            "fw": f"{base}/firewall/rules"}}
        out = {}
        for t in values(source(data, "ipsec"))[:20]:
            if UUID_RE.fullmatch(str(t.get("id") or "")) or re.match(r"^[0-9a-f-]{36}$", str(t.get("id") or "")):
                out[f"tunnel_{t['id']}"] = f"{base}/ipsec/tunnels/{t['id']}/status"
        fw = json_of(source(data, "fw")) or {}
        groups, profiles = set(), set()
        for rule in (fw.get("userDefinedRules") or []) + (fw.get("defaultRules") or []):
            for g in (rule.get("sourceFirewallGroups") or []) + (rule.get("destinationFirewallGroups") or []):
                if URN.match(str(g.get("id") or "")):
                    groups.add(g["id"])
            for p in rule.get("applicationPortProfiles") or []:
                if URN.match(str(p.get("id") or "")):
                    profiles.add(p["id"])
        for g in sorted(groups)[:30]:
            out[f"group_{uuid_of(g)}"] = f"/cloudapi/1.0.0/firewallGroups/{g}"
        for p in sorted(profiles)[:30]:
            out[f"profile_{uuid_of(p)}"] = f"/cloudapi/1.0.0/applicationPortProfiles/{p}"
        return {"vcd": out}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("vcd-edge")
        name = params["edge"]
        item = source(data, "edges")
        if unavailable(item):
            r.step("edge", "Find the edge gateway", "fail", unavailable(item))
            return r.done()
        edge = VcdEdge._edge(data)
        if not edge:
            r.step("edge", "Find the edge gateway", "fail", f"No edge gateway named {name} (CloudAPI edgeGateways).")
            return r.done()
        backing = ((edge.get("gatewayBacking") or {}).get("gatewayType") or "")
        vdc = (edge.get("orgVdc") or {}).get("name") or (edge.get("ownerRef") or {}).get("name") or "-"
        org = (edge.get("orgRef") or {}).get("name") or ""
        uplink_ips = [s.get("primaryIp") for u in edge.get("edgeGatewayUplinks") or []
                      for s in ((u.get("subnets") or {}).get("values") or []) if s.get("primaryIp")]
        r.step("edge", "Edge gateway", "ok" if backing in ("NSXT_BACKED", "") else "warn",
               f"{edge.get('name')} of {org + ' / ' if org else ''}{vdc}, {backing or 'NSX-T'}, uplink {', '.join(uplink_ips) or '-'}."
               + (" NSX-V edge: IPsec/NAT/firewall are read only for NSX-T backed edges." if backing == "NSXV_BACKED" else ""))
        where = provider_ui(ctx, f"Networking → Edge Gateways → {edge.get('name')}")
        # ---- IPsec
        tunnels = values(source(data, "ipsec"))
        rows, down = [], []
        for t in tunnels:
            st = json_of(source(data, f"tunnel_{t.get('id')}")) or {}
            ts = str(st.get("tunnelStatus") or "?")
            ike = st.get("ikeStatus") or {}
            reason = ike.get("failReason") or st.get("failReason") or ""
            rows.append([t.get("name"), t.get("localEndpoint", {}).get("localAddress"), t.get("remoteEndpoint", {}).get("remoteAddress"),
                         "yes" if t.get("active", t.get("enabled", True)) else "no", ts, ike.get("ikeServiceStatus") or "-", reason])
            if t.get("active", t.get("enabled", True)) and ts.upper() != "UP":
                down.append((t, ts, reason))
        if tunnels or "ipsec" in (data or {}):
            r.step("ipsec", "IPsec tunnels (Statistics)", "fail" if down else "ok" if tunnels else "info",
                   (f"Down: {', '.join(t.get('name') for t, _, _ in down)}." if down else f"{len(tunnels)} tunnel(s), all up." if tunnels
                    else "No IPsec tunnel on this edge."),
                   {"columns": ["Tunnel", "Local", "Remote (customer)", "Enabled", "Tunnel", "IKE", "Reason"], "rows": rows})
        for t, ts, reason in down:
            remote = (t.get("remoteEndpoint") or {}).get("remoteAddress") or "the customer endpoint"
            hint = ("The peer does not answer: check that " + remote + " is up and reachable, and UDP 500/4500 is open on the customer side."
                    if re.search(r"respon|timeout|unreachable", reason, re.I) else
                    "Phase 1/2 proposals or the pre-shared key differ: compare the IKE/IPsec profile with the customer's device."
                    if re.search(r"proposal|auth|psk|mismatch|no proposal", reason, re.I) else
                    f"Check the customer's VPN device ({remote}).")
            r.recommend(f"Tunnel {t.get('name')} to {remote} is {ts}" + (f" ({reason})" if reason else "") + ": disable it, save, enable "
                        "it again, save, wait 1-2 minutes and look at Statistics. Still down → " + hint,
                        [], where=f"{where} → IPSec VPN → {t.get('name')} → Edit → State off → Save; again State on → Save")
        # ---- NAT
        vm_ip, port, public_ip, src = params.get("vm_ip") or "", params.get("port"), params.get("public_ip") or "", params.get("source") or ""
        nat = values(source(data, "nat"))
        nat_rows = [[x.get("name"), x.get("type") or x.get("ruleType"), x.get("externalAddresses"), x.get("dnatExternalPort") or "",
                     x.get("internalAddresses"), x.get("internalPort") or "", "yes" if x.get("enabled", True) else "NO",
                     x.get("firewallMatch") or ""] for x in nat]
        snat = [x for x in nat if (x.get("type") or x.get("ruleType")) == "SNAT"]
        dnat = [x for x in nat if (x.get("type") or x.get("ruleType")) == "DNAT"]
        nat_status, nat_detail = ("ok" if nat else "info"), f"{len(snat)} SNAT, {len(dnat)} DNAT."
        snat_hit = [x for x in snat if vm_ip and ip_in(vm_ip, x.get("internalAddresses") or "")]
        dnat_hit = []
        if vm_ip:
            dnat_hit = [x for x in dnat if ip_in(vm_ip, x.get("internalAddresses") or "")
                        and (not public_ip or ip_in(public_ip, x.get("externalAddresses") or ""))
                        and (not port or str(port) in str(x.get("dnatExternalPort") or "") or not x.get("dnatExternalPort"))]
            off = [x for x in snat_hit + dnat_hit if not x.get("enabled", True)]
            parts = []
            parts.append(f"SNAT for {vm_ip}: " + (", ".join(f"{x.get('name')} → {x.get('externalAddresses')}" for x in snat_hit) or "none (no internet)"))
            if port or public_ip:
                parts.append(f"DNAT to {vm_ip}{':' + str(port) if port else ''}: " + (", ".join(x.get("name") for x in dnat_hit) or "none"))
            nat_status = "fail" if off or not snat_hit or ((port or public_ip) and not dnat_hit) else "ok"
            nat_detail = "; ".join(parts) + "." + (f" Disabled: {', '.join(x.get('name') for x in off)}." if off else "")
            for x in off:
                r.recommend(f"NAT rule {x.get('name')} for {vm_ip} is disabled: enable it (or, when it is enabled but traffic still "
                            "fails, disable and enable it to push it again — the WI's refresh).", [],
                            where=f"{where} → NAT → {x.get('name')} → Edit → State on → Save")
            if not snat_hit:
                ext = uplink_ips[0] if uplink_ips else "<public IP of the edge>"
                r.recommend(f"No SNAT covers {vm_ip}: the VM cannot reach the internet. Add an SNAT rule: name snat-{vm_ip}, "
                            f"external IP {ext}, internal IP {vm_ip} (or its subnet), state on.", [], where=f"{where} → NAT → New")
            if (port or public_ip) and not dnat_hit:
                ext = public_ip or (uplink_ips[0] if uplink_ips else "<public IP>")
                r.recommend(f"No DNAT sends {ext}{':' + str(port) if port else ''} to {vm_ip}. Add a DNAT rule: name dnat-{port or 'all'}-{vm_ip}, "
                            f"external IP {ext}, application TCP {port or 'any'}, internal IP {vm_ip}, firewall match "
                            "'Match internal address', state on.", [], where=f"{where} → NAT → New")
        if nat or "nat" in (data or {}):
            r.step("nat", "NAT rules", nat_status, nat_detail,
                   {"columns": ["Rule", "Type", "External", "Ext. port", "Internal", "Int. port", "Enabled", "Firewall match"],
                    "rows": nat_rows})
        # ---- firewall for the port
        fw = json_of(source(data, "fw")) or {}
        rules = [x for x in (fw.get("userDefinedRules") or []) + (fw.get("defaultRules") or [])]
        if vm_ip and port and rules:
            match = (dnat_hit[0].get("firewallMatch") if dnat_hit else "") or "MATCH_INTERNAL_ADDRESS"
            dest_ip = (public_ip or (dnat_hit[0].get("externalAddresses") if dnat_hit else vm_ip)) if match == "MATCH_EXTERNAL_ADDRESS" else vm_ip

            def group_ips(refs):
                out = []
                for g in refs or []:
                    body = json_of(source(data, f"group_{uuid_of(g.get('id'))}")) or {}
                    out += [str(a) for a in body.get("ipAddresses") or []]
                return out

            def matches(rule):
                if not rule.get("enabled", True):
                    return False
                dst = rule.get("destinationFirewallGroups") or []
                if dst and not any(ip_in(dest_ip, a) for a in group_ips(dst)):
                    return False
                srcs = rule.get("sourceFirewallGroups") or []
                if src and srcs and not any(ip_in(src, a) for a in group_ips(srcs)):
                    return False
                profs = rule.get("applicationPortProfiles") or []
                if profs and not any(port_in_profile(json_of(source(data, f"profile_{uuid_of(p.get('id'))}")) or {}, int(port)) for p in profs):
                    return False
                return True
            first = next((x for x in rules if matches(x)), None)
            action = str((first or {}).get("actionValue") or (first or {}).get("action") or "").upper()
            allowed = action == "ALLOW"
            r.step("firewall", f"Edge firewall for TCP {port} to {dest_ip}" + (f" from {src}" if src else ""),
                   "ok" if allowed else "fail",
                   (f"Allowed by rule {first.get('name')}." if allowed else
                    f"Blocked by rule {first.get('name')} ({action})." if first else "No rule matches: the default action drops it."),
                   {"columns": ["#", "Rule", "Source", "Destination", "Applications", "Action", "Enabled"],
                    "rows": [[i + 1, x.get("name"), ", ".join(g.get("name", "") for g in x.get("sourceFirewallGroups") or []) or "Any",
                              ", ".join(g.get("name", "") for g in x.get("destinationFirewallGroups") or []) or "Any",
                              ", ".join(p.get("name", "") for p in x.get("applicationPortProfiles") or []) or "Any",
                              x.get("actionValue") or x.get("action"), "yes" if x.get("enabled", True) else "no"] for i, x in enumerate(rules)]})
            if not allowed:
                known = next((json_of(source(data, f"profile_{uuid_of(p.get('id'))}")) or {} for x in rules
                              for p in x.get("applicationPortProfiles") or []
                              if port_in_profile(json_of(source(data, f"profile_{uuid_of(p.get('id'))}")) or {}, int(port))), {})
                profile = known.get("name") or f"TCP-{port}"
                steps = []
                if not known:
                    steps.append(f"Security → Application Port Profiles → New: name TCP-{port}, protocol TCP, port {port}")
                steps.append(f"Security → IP Sets → New: name {dest_ip}, IP {dest_ip}" + (f"; and IP set {src}, IP {src}" if src else ""))
                steps.append(f"Edge Gateways → {edge.get('name')} → Firewall → New ABOVE {first.get('name') if first else 'the default rule'}: "
                             f"name allow-tcp-{port}-{dest_ip}, source {src or 'Any'}, destination IP set {dest_ip}, applications {profile}, "
                             "action Allow, state on → Save")
                r.recommend(f"Allow TCP {port} to {dest_ip} on {edge.get('name')} (NSX-T: port profile and IP set first, as the WI says): "
                            + " · ".join(steps) + ". Then test from outside and check the firewall inside the VM.",
                            [f"nc -vz {public_ip or (dnat_hit[0].get('externalAddresses') if dnat_hit else dest_ip)} {port}   # from outside"],
                            where=provider_ui(ctx, f"Networking → Edge Gateways → {edge.get('name')}"),
                            warning="Use the customer's source IP instead of Any when only they need the port. Inside the VM run the "
                                    "check \"Port blocked on a Linux VM\" (or Windows Firewall) when the edge allows it.")
        elif (vm_ip or port) and not rules and "fw" in (data or {}):
            r.step("firewall", "Edge firewall", "warn", unavailable(source(data, "fw")) or "No firewall rule read.")
        return r.done()

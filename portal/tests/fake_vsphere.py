#!/usr/bin/env python3
"""Fake vCenter inventory for Operation Automation in test mode: answers like
modules/wi/playbooks/files/vsphere_inventory.py (sites.yml vcenter.inventory_command).

    fake_vsphere.py --what hosts,vms,pools,clusters

Cluster DCA-CL-PRIME-01 (DRS partially automated): esxi-dca-02 runs at 94% CPU because of render-farm-01; esxi-dca-03
has room; esxi-dca-04 is in maintenance. app-04 (vCloud, Org VDC CUST-A-VDC) sits in the cluster root pool instead of
its Org VDC pool (the vCloud power-on error "Resource Pool not available").
"""
import argparse
import json
import sys

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.abspath(__file__)))
import mock_vmware  # noqa: E402

CLUSTER = "DCA-CL-PRIME-01"
CPU_TOTAL, MEM_TOTAL = 64 * 2600, 1048576
VDC_POOL = f"CUST-A-VDC ({mock_vmware.VCD_VDC})"
VDC_FOLDER = f"vcd-dca/cust-a ({mock_vmware.VCD_ORG})/{VDC_POOL}"
HOSTS = [  # name, CPU MHz used, memory MB used, maintenance
    ("esxi-dca-01", 70000, 600000, False), ("esxi-dca-02", 156000, 930000, False),
    ("esxi-dca-03", 50000, 450000, False), ("esxi-dca-04", 0, 0, True),
]


def vcd(name, n):
    return f"{name} ({mock_vmware.vcd_uuid(n)})"


VMS = [  # name, host, pool moid, folder, power, CPU MHz, host memory MB, vCPU, memory MB, IP, OS
    ("render-farm-01", "esxi-dca-02", "resgroup-8", "Customers/render", "poweredOn", 42000, 64000, 32, 65536, "10.249.10.40", "Ubuntu Linux (64-bit)"),
    (vcd("db-03", 3), "esxi-dca-02", "resgroup-501", f"{VDC_FOLDER}/vapp-db-03", "poweredOn", 30000, 16000, 8, 16384, "11.15.66.103", "Red Hat Enterprise Linux 8 (64-bit)"),
    (vcd("report-05", 5), "esxi-dca-02", "resgroup-501", f"{VDC_FOLDER}/vapp-report-05", "poweredOn", 21000, 8100, 4, 8192, "11.15.66.105", "Microsoft Windows Server 2019 (64-bit)"),
    ("erp-db-01", "esxi-dca-02", "resgroup-8", "Customers/erp", "poweredOn", 18000, 32000, 8, 32768, "10.249.20.11", "Red Hat Enterprise Linux 8 (64-bit)"),
    ("erp-app-01-legacy", "esxi-dca-02", "resgroup-8", "Customers/erp", "poweredOn", 15000, 16000, 4, 16384, "10.249.20.12", "Red Hat Enterprise Linux 8 (64-bit)"),
    (vcd("app-04", 4), "esxi-dca-02", "resgroup-8", f"{VDC_FOLDER}/vapp-app-04", "poweredOff", 0, 0, 2, 4096, "", ""),
    ("k8s-node-01", "esxi-dca-01", "resgroup-8", "Platform/k8s", "poweredOn", 24000, 64000, 16, 65536, "10.246.0.11", "Ubuntu Linux (64-bit)"),
    ("k8s-node-02", "esxi-dca-03", "resgroup-8", "Platform/k8s", "poweredOn", 22000, 64000, 16, 65536, "10.246.0.12", "Ubuntu Linux (64-bit)"),
    (vcd("web-03", 6), "esxi-dca-01", "resgroup-501", f"{VDC_FOLDER}/vapp-web-03", "poweredOn", 6000, 4000, 2, 4096, "11.15.66.102", "Ubuntu Linux (64-bit)"),
]
POOLS = [  # moid, name, path, root, memory limit MB, memory used MB
    ("resgroup-8", "Resources", f"{CLUSTER}/Resources", True, -1, 0),
    ("resgroup-501", VDC_POOL, f"{CLUSTER}/Resources/System vDC/{VDC_POOL}", False, 65536, 57344),
    ("resgroup-502", f"CUST-B-VDC ({mock_vmware.vcd_uuid(902)})", f"{CLUSTER}/Resources/System vDC/CUST-B-VDC", False, 131072, 40000),
]


NOW = "2026-10-11T08:00:00+00:00"


def health(what):
    """The health sets (alarms, events@<h>, hosthealth, vmhealth, datastores): esxi-dca-03 lost a path to its LUN and a
    memory DIMM is red, esxi-dca-05 is not responding, datastore DCA-DS-OLD is inaccessible, report-05 keeps a 10-day
    snapshot and db-03 needs consolidation."""
    out = {}
    if "alarms" in what:
        out["alarms"] = [
            {"alarm": "Host connection and power state", "entity": "esxi-dca-05", "entity_type": "HostSystem", "status": "red",
             "time": "2026-10-11T06:40:00+00:00", "acknowledged": False, "acknowledged_by": ""},
            {"alarm": "Host hardware memory status", "entity": "esxi-dca-03", "entity_type": "HostSystem", "status": "red",
             "time": "2026-10-11T05:12:00+00:00", "acknowledged": False, "acknowledged_by": ""},
            {"alarm": "Datastore usage on disk", "entity": "DCA-DS-SSD-02", "entity_type": "Datastore", "status": "yellow",
             "time": "2026-10-10T22:00:00+00:00", "acknowledged": True, "acknowledged_by": "VSPHERE.LOCAL\\noc"}]
    if any(w.startswith("events") for w in what):
        out["events"] = [
            {"type": "esx.problem.storage.redundancy.lost", "time": "2026-10-11T05:10:00+00:00", "severity": "warning",
             "message": "Lost path redundancy to storage device naa.600a098038314d2f. Path vmhba2:C0:T1:L4 is down.",
             "host": "esxi-dca-03", "vm": "", "datastore": "", "cluster": CLUSTER, "datacenter": "DCA-DC"},
            {"type": "esx.problem.net.vmnic.linkstate.down", "time": "2026-10-11T04:02:00+00:00", "severity": "warning",
             "message": "Physical NIC vmnic3 linkstate is down", "host": "esxi-dca-03", "vm": "", "datastore": "",
             "cluster": CLUSTER, "datacenter": "DCA-DC"},
            {"type": "HostConnectionLostEvent", "time": "2026-10-11T06:39:00+00:00", "severity": "",
             "message": "Host esxi-dca-05 in DCA-DC is not responding", "host": "esxi-dca-05", "vm": "", "datastore": "",
             "cluster": CLUSTER, "datacenter": "DCA-DC"},
            {"type": "VmFailedMigrateEvent", "time": "2026-10-11T03:00:00+00:00", "severity": "",
             "message": "Cannot migrate erp-db-01 from esxi-dca-02 to esxi-dca-03", "host": "esxi-dca-02", "vm": "erp-db-01",
             "datastore": "", "cluster": CLUSTER, "datacenter": "DCA-DC"},
            {"type": "AlarmStatusChangedEvent", "time": "2026-10-11T06:40:00+00:00", "severity": "",
             "message": "Alarm 'Host connection and power state' on esxi-dca-05 changed from Green to Red", "host": "esxi-dca-05",
             "vm": "", "datastore": "", "cluster": CLUSTER, "datacenter": "DCA-DC"}]
    if any(w.startswith("allevents") for w in what):   # every event: 1200 info / user events and the warnings above
        out["allevents"] = [
            {"type": "VmPoweredOnEvent" if i % 3 else "UserLoginSessionEvent", "time": f"2026-10-11T{i % 24:02d}:{i % 60:02d}:00+00:00",
             "severity": "info" if i % 3 else "user", "message": f"Event {i}", "host": "esxi-dca-02", "vm": "erp-db-01" if i % 3 else "",
             "datastore": "", "cluster": CLUSTER, "datacenter": "DCA-DC", "user": "" if i % 3 else "VSPHERE.LOCAL\\noc", "key": i}
            for i in range(1200)] + [
            {"type": "esx.problem.storage.redundancy.lost", "time": "2026-10-11T05:10:00+00:00", "severity": "warning",
             "message": "Lost path redundancy to storage device naa.600a098038314d2f.", "host": "esxi-dca-03", "vm": "",
             "datastore": "", "cluster": CLUSTER, "datacenter": "DCA-DC", "user": "", "key": 5000}]
    if "hosthealth" in what:
        out["hosthealth"] = [
            {"moid": f"host-{i + 10}", "name": n, "connection": "connected", "maintenance": m, "status": "red" if n == "esxi-dca-03" else "green",
             "vendor": "Lenovo", "model": "ThinkSystem SR650 V2", "issues": [],
             "sensors": [], "hardware": [{"name": "DIMM 12", "type": "memory", "state": "red"}] if n == "esxi-dca-03" else []}
            for i, (n, _c, _m, m) in enumerate(HOSTS)] + [
            {"moid": "host-20", "name": "esxi-dca-05", "connection": "notResponding", "maintenance": False, "status": "gray",
             "vendor": "Inspur", "model": "NF5280M6", "issues": [], "sensors": [], "hardware": []}]
    if "vmhealth" in what:
        out["vmhealth"] = [
            {"moid": "vm-4002", "name": vcd("report-05", 5), "host": "esxi-dca-02", "power": "poweredOn", "tools": "guestToolsRunning",
             "consolidate": False, "snapshots": [{"name": "before-upgrade", "created": "2026-10-01T02:00:00+00:00"}]},
            {"moid": "vm-4001", "name": vcd("db-03", 3), "host": "esxi-dca-02", "power": "poweredOn", "tools": "guestToolsRunning",
             "consolidate": True, "snapshots": []},
            {"moid": "vm-4007", "name": "k8s-node-02", "host": "esxi-dca-03", "power": "poweredOn", "tools": "guestToolsNotRunning",
             "consolidate": False, "snapshots": [{"name": "daily", "created": "2026-10-11T01:00:00+00:00"}]}]
    if "datastores" in what:
        out["datastores"] = [{"moid": "datastore-11", "name": "DCA-DS-SSD-01", "accessible": True, "capacity": 10 * 2 ** 40,
                              "free": 4 * 2 ** 40, "type": "VMFS", "status": "green"},
                             {"moid": "datastore-19", "name": "DCA-DS-OLD", "accessible": False, "capacity": 0, "free": 0,
                              "type": "NFS", "status": "gray"}]
    return out


def inventory(what):
    pool_name = {moid: name for moid, name, *_ in POOLS}
    out = {}
    if "hosts" in what:
        out["hosts"] = [{"moid": f"host-{i + 10}", "name": n, "cluster": CLUSTER, "status": "green", "connection": "connected",
                         "maintenance": m, "power": "poweredOn", "cpu_used_mhz": c, "cpu_total_mhz": CPU_TOTAL,
                         "mem_used_mb": mem, "mem_total_mb": MEM_TOTAL} for i, (n, c, mem, m) in enumerate(HOSTS)]
    if "vms" in what:
        out["vms"] = [{"moid": f"vm-{4000 + i}", "name": n, "host": h, "cluster": CLUSTER, "pool": pool_name[p], "pool_moid": p,
                       "folder": f, "power": pw, "cpu_used_mhz": c, "mem_host_mb": hm, "mem_guest_mb": int(hm * 0.8), "vcpu": v,
                       "mem_mb": m, "ip": ip, "os": os_} for i, (n, h, p, f, pw, c, hm, v, m, ip, os_) in enumerate(VMS)]
    if "pools" in what:
        out["pools"] = [{"moid": moid, "name": n, "path": path, "cluster": CLUSTER, "root": root, "cpu_limit_mhz": -1,
                         "cpu_reservation_mhz": 0, "mem_limit_mb": lim, "mem_reservation_mb": 0, "cpu_used_mhz": 0,
                         "mem_used_mb": used} for moid, n, path, root, lim, used in POOLS]
    if "clusters" in what:
        out["clusters"] = [{"moid": "domain-c7", "name": CLUSTER, "drs": True, "drs_behavior": "partiallyAutomated"}]
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--what", required=True)
    sets = ap.parse_args().what.split(",")
    out = inventory(sets)
    out.update(health(sets))
    print(json.dumps(out))

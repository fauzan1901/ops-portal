"""The products of the Status module and the read-only checks of Runbook Automation each one runs, in order.

check     a check of modules/wi/catalog.yml that only reads (ready, no parameter it needs, no fix runs from a round)
params    its parameters in a round (the rest: the defaults of the check)
next      the checks an operator runs next when it is not safe (Runbook Automation → Checks), most useful first
per       (a product) the check runs once for each target of this kind on the site: "bmc" = every BMC of the page BMC
          of Runbook Automation; param names the parameter that gets the target (bmc-health bmc=<name>)

The owner chose OpenStack, NetApp ONTAP and VMware Cloud (read only) on 11 Nov 2026, then the hardware of every BMC. A product of a site without its
configuration (no ONTAP, no vCenter) is "not configured" there and runs nothing. tests/test_health.py checks every entry.
"""

PRODUCTS = [
    {"id": "openstack", "title": "OpenStack", "icon": "server", "checks": [
        {"check": "openstack-services", "next": ["overcloud-logs", "pacemaker-health"]},
        {"check": "pacemaker-health", "next": ["galera-wsrep", "rabbitmq-queues", "controller-reboot-readiness"]},
        {"check": "galera-wsrep", "next": ["pacemaker-health", "overcloud-logs"]},
        {"check": "rabbitmq-queues", "next": ["pacemaker-health", "overcloud-logs"]},
        {"check": "ovn-db-cluster", "next": ["pacemaker-health", "overcloud-logs"]},
        {"check": "ovn-metadata", "next": ["ovn-chassis-stale", "ovn-db-cluster"]},
        {"check": "ovn-chassis-stale", "next": ["ovn-db-cluster", "openstack-services"]},
        {"check": "compute-hypervisor-sync", "next": ["placement-consistency", "compute-capacity"]},
        {"check": "placement-consistency", "next": ["compute-hypervisor-sync", "compute-capacity"]},
        {"check": "overcloud-node-health", "params": {"role": "all"}, "next": ["compute-memory", "compute-disks", "host-lvm"]},
        {"check": "compute-capacity", "next": ["compute-memory", "project-quota"]},
        {"check": "cinder-pool-usage", "next": ["lun-map-audit", "ontap-capacity"]},
        {"check": "certmonger-status", "params": {"role": "all"}, "next": ["cert-expiry"]},
        {"check": "ironic-nodes", "next": ["bmc-health"]},
    ]},
    {"id": "ontap", "title": "NetApp ONTAP", "icon": "database", "checks": [
        {"check": "ontap-cluster-health", "next": ["ontap-ha-redundancy"]},
        {"check": "ontap-capacity", "next": ["cinder-pool-usage", "lun-map-audit"]},
        {"check": "ontap-volume-lun-state", "next": ["lun-map-audit", "volume-connections"]},
        {"check": "ontap-ha-redundancy", "next": ["ontap-cluster-health"]},
    ]},
    {"id": "prime", "title": "VMware Cloud", "icon": "cubes", "read_only": True, "checks": [
        {"check": "vcenter-health", "next": ["vcenter-datastore", "vmware-host-usage"]},
        {"check": "vcenter-appliance", "next": ["vcenter-health"]},
        {"check": "vcd-platform", "next": ["vcd-vm-power", "vcd-edge"]},
        {"check": "nsxt-health", "next": ["nsxt-gateway-routing"]},
        {"check": "cert-inventory", "next": ["cert-expiry"]},
    ]},
    {"id": "hardware", "title": "Hardware (BMC)", "icon": "tool", "per": "bmc", "checks": [
        {"check": "bmc-health", "param": "bmc", "next": ["ironic-nodes", "overcloud-node-health"]},
    ]},
]

# worst first: what a product shows from the statuses of its checks in the last round
RANK = {"fail": 0, "warn": 1, "error": 2, "unknown": 2, "skip": 2, "stopped": 2, "running": 3, "waiting": 3, "ok": 4}
PRODUCT_STATUS = {0: "problem", 1: "warn", 2: "unknown", 3: "running", 4: "ok"}
METRIC_VALUE = {"ok": 0, "warn": 1, "problem": 2, "unknown": 3, "running": 3}


def get(product_id):
    return next((p for p in PRODUCTS if p["id"] == product_id), None)


def check_ids():
    return [c["check"] for p in PRODUCTS for c in p["checks"]]

#!/usr/bin/env python3
"""Fake OpenStack director for Operation Automation in test mode. Called like the director command, with one argument:

    fake_cloud.py '<script>'

A Operation Automation script (lines "echo '@@WI@@begin <key>'; <command> 2>&1; echo \"@@WI@@end <key> $?\"") is answered here
with a small fixed cloud: Cinder pools near full, volumes on old types, instances in BUILD / ERROR / SHUTOFF, security
groups, quotas. Any other script (ONTAP Restore) is handed to fake_director.py (env FAKE_DIRECTOR_PY), unchanged.

Env FAKE_POOL_PREFIX: pool / backend prefix of the site (e.g. DCAOPNSTACK), like fake_director.py.
Env FAKE_CLOUD_STATE: JSON file with the changes made by fixes (Run this fix: migrate, retype, reset-state, snapshot
delete, quota set, server start/stop/delete, detach, security group rule create); later reads show them, so the
check run again after a fix sees the result. Without it, changes are refused.
"""
import base64
import copy
import datetime
import gzip
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

PREFIX = os.environ.get("FAKE_POOL_PREFIX", "DCAOPNSTACK")
BACKEND = f"{PREFIX.lower()}_faas500f"
HOST = f"hostgroup@{BACKEND}"
NOW = datetime.datetime.now(datetime.timezone.utc)
CUSTOMER, OTHER = "c0ffee00000000000000000000000001", "c0ffee00000000000000000000000002"
ADMIN = "ad000000000000000000000000000000"
PROJECTS = {CUSTOMER: "customer-a80", OTHER: "customer-other", ADMIN: "admin"}


def ago(minutes):
    return (NOW - datetime.timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S.000000")


def uid(n, kind="a"):
    """A fixed UUID: kind (hex) repeated as the first block, n as the last."""
    return f"{(kind * 8)[:8]}-0000-4000-8000-{n:012x}"


# ---------------- Cinder pools (GiB) ----------------
POOLS = [  # pool, total, allocated (overcommitted 2:1), free (Cinder view); the same FlexVols as tests/mock_ontap.py
    (f"{PREFIX}_CINDER_14_vol", 10000.0, 16400.0, 1800.0),
    (f"{PREFIX}_CINDER_15_vol", 10000.0, 19800.0, 100.0),
    (f"{PREFIX}_CINDER_16_vol", 10000.0, 15800.0, 5900.0),   # allocated 79% of total x 2, but only 41% used
    (f"{PREFIX}_CINDER_17_vol", 10000.0, 10200.0, 4900.0),
    (f"{PREFIX}_CINDER_TEST50_vol", 10000.0, 2000.0, 9000.0),
]
# ---------------- volumes ----------------
VOLUMES = [  # id, name, status, size, type, pool, project, migstat, updated minutes ago
    (uid(1, "1"), "db-prod-data", "in-use", 2000, "standard", 0, CUSTOMER, "", 600),
    (uid(2, "1"), "web-01-root", "in-use", 100, "fas500f-standard", 0, CUSTOMER, "", 900),
    (uid(3, "1"), "archive-2024", "available", 3000, "basic", 0, OTHER, "", 3000),
    (uid(4, "1"), "logs-old", "available", 1500, "fas500f-basic", 0, OTHER, "", 4000),
    (uid(5, "1"), "app-02-root", "in-use", 80, "premium", 1, CUSTOMER, "", 400),
    (uid(6, "1"), "app-02-data", "attaching", 500, "fas500f-standard", 1, CUSTOMER, "", 140),
    (uid(7, "1"), "report-db", "reserved", 400, "standard", 1, CUSTOMER, "migrating", 95),
    (uid(8, "1"), "build-03-root", "error", 50, "fas500f-standard", 2, CUSTOMER, "", 200),
    (uid(9, "1"), "backup-target", "available", 1200, "fas500f-standard", 2, OTHER, "", 7000),
    (uid(10, "1"), "erp-data", "in-use", 900, "affa-premium", 3, CUSTOMER, "", 800),
    # old failed migrations, rolled back by Cinder: the volumes work, only migration_status "error" stays
    (uid(12, "1"), "", "in-use", 250, "fas500f-standard", 3, OTHER, "error", 1605913),
    (uid(13, "1"), "files-old", "available", 120, "fas500f-standard", 3, OTHER, "error", 305888),
    # the temporary copy of the failed retype of report-db (cinder names it after the original volume)
    (uid(11, "1"), "report-db", "available", 400, "fas500f-standard", 2, CUSTOMER, f"target:{uid(7, '1')}", 95),
]
# Volume attachments in OpenStack: volume -> (server, device). app-02-data is "attaching" without one (stuck attach).
ATTACHED = {uid(1, "1"): (uid(1, "5e"), "/dev/vdb"), uid(2, "1"): (uid(1, "5e"), "/dev/vda"),
            uid(5, "1"): (uid(2, "5e"), "/dev/vda"), uid(7, "1"): (uid(2, "5e"), "/dev/vdb"),
            uid(10, "1"): (uid(1, "5e"), "/dev/vdc")}
# id, name, size, volume, age in days (only those older than 2 weeks are offered for deletion)
SNAPSHOTS = [(uid(20 + i, "5"), f"daily-{i}", 2000 if i < 4 else 1500, VOLUMES[0 if i < 4 else 3][0], (45, 21, 6, 1, 30, 15, 3)[i])
             for i in range(7)]
TYPES = ["standard", "basic", "premium", "fas500f-standard", "fas500f-basic", "affa-premium"]

# ---------------- instances, ports, security groups ----------------
NET_APP, SUB_APP = uid(1, "0"), uid(1, "5b")
SG_DEFAULT, SG_WEB, SG_OTHER = uid(1, "56"), uid(2, "56"), uid(3, "56")
SERVERS = {  # id: name, status, power, host, project, created minutes ago, fault, ports, security groups
    uid(1, "5e"): ("web-01", "ACTIVE", "Running", "compute-07", CUSTOMER, 20000, "", [uid(1, "9")], ["default", "web"]),
    uid(2, "5e"): ("app-02", "SHUTOFF", "Shutdown", "compute-03", CUSTOMER, 30000, "", [uid(2, "9")], ["default"]),
    uid(3, "5e"): ("build-03", "BUILD", "NOSTATE", "", CUSTOMER, 185, "", [], ["default"]),
    uid(4, "5e"): ("err-04", "ERROR", "NOSTATE", "", OTHER, 400, "No valid host was found. There are not enough hosts available.", [], ["default"]),
    # compute-07, emptied with the check "Move instances off a compute": db-01 is refused once (CPU), batch-05 is shut off
    # (cold migration), gpu-06 has a PCI passthrough flavor (cannot live-migrate), legacy-08 ends in ERROR (reset after virsh)
    uid(5, "5e"): ("db-01", "ACTIVE", "Running", "compute-07", OTHER, 50000, "", [], ["default"]),
    uid(6, "5e"): ("batch-05", "SHUTOFF", "Shutdown", "compute-07", CUSTOMER, 40000, "", [], ["default"]),
    uid(7, "5e"): ("gpu-06", "ACTIVE", "Running", "compute-07", OTHER, 30000, "", [], ["default"]),
    uid(8, "5e"): ("legacy-08", "ACTIVE", "Running", "compute-07", OTHER, 90000, "", [], ["default"]),
}
# id: flavor, image (empty: boots from a volume), config drive
SERVER_EXTRA = {uid(1, "5e"): ("m1.large", "", False), uid(2, "5e"): ("m1.medium", "", False), uid(3, "5e"): ("m1.small", "", False),
                uid(4, "5e"): ("m1.small", "", False), uid(5, "5e"): ("m1.xlarge", "", False), uid(6, "5e"): ("m1.medium", uid(1, "1a"), True),
                uid(7, "5e"): ("g1.gpu", uid(1, "1a"), False), uid(8, "5e"): ("m1.large", uid(7, "1a"), False)}
FLAVORS = {"m1.small": (uid(1, "f0"), 2, 4096, 20, {}), "m1.medium": (uid(2, "f0"), 4, 8192, 40, {}),
           "m1.large": (uid(3, "f0"), 8, 16384, 80, {}), "m1.xlarge": (uid(4, "f0"), 16, 32768, 0, {"hw:cpu_policy": "dedicated"}),
           "g1.gpu": (uid(5, "f0"), 8, 65536, 100, {"pci_passthrough:alias": "a100:1"})}
DELETED_PROJECT = "dead0000000000000000000000000001"
# id, name, status, size, visibility, protected, owner, age in days, properties
IMAGES = [
    (uid(1, "1a"), "ubuntu-24.04", "active", 2684354560, "public", False, ADMIN, 300, {}),
    (uid(2, "1a"), "upload-win2022", "queued", None, "private", False, CUSTOMER, 40, {}),
    (uid(3, "1a"), "snap-db-prod-2026-09", "active", 0, "private", False, CUSTOMER, 30,
     {"block_device_mapping": json.dumps([{"boot_index": 0, "source_type": "snapshot", "snapshot_id": uid(20, "5"),
                                           "volume_size": 2000, "device_name": "/dev/vda"}]), "bdm_v2": "True"}),
    (uid(4, "1a"), "centos7-import", "killed", 0, "private", False, OTHER, 90, {}),
    (uid(5, "1a"), "golden-template", "active", 0, "public", True, ADMIN, 200, {}),
    (uid(6, "1a"), "old-orphan-image", "active", 10737418240, "private", False, DELETED_PROJECT, 400, {}),
    (uid(7, "1a"), "rhel9-empty", "active", 0, "private", False, OTHER, 120, {}),
]
OSC_VERSION = os.environ.get("FAKE_OSC_VERSION", "4.0.2")   # RHOSP 16.2 ships python-openstackclient 4.0.2, 17.1 5.5.2
LIVE_REFUSED = uid(5, "5e")    # db-01: the compute the scheduler picks refuses it (CPU); an explicit destination accepts it
# server group list --all-projects --long (rows as python-openstackclient prints them); a test sets its own
SERVER_GROUPS = []
LIVE_ERROR = uid(8, "5e")      # legacy-08: ends in ERROR while its domain keeps running on compute-07
VOLUME_MIGRATE_FAILS = uid(3, "1")   # archive-2024: the first migration fails and leaves a temporary copy
PORTS = {  # id: name, server, ip, security group ids, floating IP
    uid(1, "9"): ("web-01-eth0", uid(1, "5e"), "10.249.1.15", [SG_DEFAULT, SG_WEB], "203.0.113.10"),
    uid(2, "9"): ("app-02-eth0", uid(2, "5e"), "10.249.1.16", [SG_DEFAULT], ""),
}
SG_RULES = {
    SG_DEFAULT: ("default", [("ingress", "tcp", "22:22", "0.0.0.0/0"), ("ingress", "icmp", "", "0.0.0.0/0"),
                             ("egress", "", "", "0.0.0.0/0")]),
    SG_WEB: ("web", [("ingress", "tcp", "443:443", "0.0.0.0/0"), ("ingress", "tcp", "80:80", "0.0.0.0/0")]),
    SG_OTHER: ("default", [("egress", "", "", "0.0.0.0/0")]),
}
QUOTA = {CUSTOMER: {"instances": 10, "cores": 40, "ram": 81920, "volumes": 10, "gigabytes": 4000, "snapshots": 10,
                    "ports": 50, "floating-ips": 5},
         OTHER: {"instances": 20, "cores": 80, "ram": 163840, "volumes": 50, "gigabytes": 20000, "snapshots": 50,
                 "ports": 100, "floating-ips": 10}}
USAGE = {CUSTOMER: {"totalInstancesUsed": 10, "totalCoresUsed": 38, "totalRAMUsed": 65536, "totalVolumesUsed": 9,
                    "totalGigabytesUsed": 3630, "totalSnapshotsUsed": 4},
         OTHER: {"totalInstancesUsed": 3, "totalCoresUsed": 12, "totalRAMUsed": 24576, "totalVolumesUsed": 4,
                 "totalGigabytesUsed": 6100, "totalSnapshotsUsed": 3}}


# ---------------- platform health: services, agents, external pools, bare metal nodes ----------------
CONTROLLERS = ["controller-0.localdomain", "controller-1.localdomain", "controller-2.localdomain"]
COMPUTE_SERVICES = (  # binary, host, status, state, last report minutes ago
    [("nova-scheduler", h, "enabled", "up", 0) for h in CONTROLLERS]
    + [("nova-conductor", h, "enabled", "down" if h.startswith("controller-1") else "up", 25 if h.startswith("controller-1") else 0)
       for h in CONTROLLERS]
    + [("nova-compute", "compute-03", "enabled", "down", 35), ("nova-compute", "compute-07", "enabled", "up", 0),
       ("nova-compute", "compute-08", "disabled", "up", 0), ("nova-compute", "compute-old-09", "enabled", "down", 57600),
       ("nova-compute", "compute-09", "enabled", "up", 0)])
VOLUME_SERVICES = ([("cinder-scheduler", h, "enabled", "up", 0) for h in CONTROLLERS]
                   + [("cinder-volume", HOST, "enabled", "up", 0), ("cinder-volume", "hostgroup@tripleo_netapp_old", "enabled", "down", 86400)])
AGENTS = (  # agent type, host, alive, admin up
    [("OVN Controller Gateway agent", h, True, True) for h in CONTROLLERS]
    + [("OVN Controller agent", "compute-03", False, True), ("OVN Metadata agent", "compute-03", False, True),
       ("OVN Controller agent", "compute-07", True, True), ("OVN Metadata agent", "compute-07", True, True),
       ("OVN Controller agent", "compute-08", True, True), ("OVN Controller agent", "compute-old-09", False, True),
       ("OVN Controller agent", "compute-09", True, True), ("OVN Metadata agent", "compute-09", True, True)])
PUBLIC_NET = uid(9, "e")

# ---------------- WI "FDB Learning Issue": instances mdt01-04 on DataGrid-Network, port security disabled (OVN) ----------------
# Kept apart from SERVERS / PORTS (not in server lists): only server show, port list --server, port show, network show.
NET_DG, DP_DG, DP_KEY = uid(2, "0"), uid(1, "d0"), 225
MDT = {  # server: name, host, port, MAC, IP, OVN tunnel key of the port
    uid(1, "3d"): ("mdt01", "compute-09", uid(1, "7a"), "fa:16:3e:0b:cc:31", "10.249.11.39", 3),
    uid(2, "3d"): ("mdt02", "compute-07", uid(2, "7a"), "fa:16:3e:35:1f:e7", "10.249.11.40", 4),
    uid(3, "3d"): ("mdt03", "compute-09", uid(3, "7a"), "fa:16:3e:2f:2a:25", "10.249.11.41", 5),
    uid(4, "3d"): ("mdt04", "compute-07", uid(4, "7a"), "fa:16:3e:38:ae:44", "10.249.11.7", 6),
}
OUTSIDE_MAC = "10:70:fd:29:c7:fe"    # the host 10.249.11.27 on the physical network (VLAN 1670)
MDT_VIP = (uid(30, "7a"), "mdt-vip", "fa:16:3e:77:00:50", "10.249.11.50")   # a reserved port without a device (the VIP of the HA pair)
PS_SG = uid(1, "5e")   # the security group port-security-allow-all made by the port security fix
FDB = [  # uuid, mac, port key: 1 = the localnet port (physical network)
    (uid(1, "fdb"), OUTSIDE_MAC, 3),               # poisoned: the outside host recorded on the port of mdt01
    (uid(2, "fdb"), "fa:16:3e:38:ae:44", 4),        # poisoned: mdt04 recorded on the port of mdt02
    (uid(3, "fdb"), "10:70:fd:29:c7:01", 1),        # right: another outside host on the localnet port
    (uid(4, "fdb"), "fa:16:3e:0b:cc:31", 3),        # right: mdt01 on its own port
]
IP_AVAILABILITY = [(PUBLIC_NET, f"public-{PREFIX[:3].lower()}", 508, 462), (NET_APP, "vpc-app", 253, 251)]
FLOATING = [("203.0.113.10", uid(1, "9"), CUSTOMER), ("203.0.113.44", None, CUSTOMER), ("203.0.113.45", None, OTHER),
            ("203.0.113.46", None, OTHER)]
BAREMETAL = (  # name, power, provision, maintenance, reason, fault, last error
    [(f"overcloud-controller-{i}", "power on", "active", False, None, None, None) for i in range(3)]
    + [("overcloud-novacompute-3", None, "active", True, "During sync_power_state, max retries exceeded for node "
        f"{uid(3, 'b')}, node state None does not match expected state 'power on'. Updating DB state to 'None' Switching "
        "node to maintenance mode. Error: IPMI call failed: power status.", "power failure",
        "IPMI call failed: power status.")]
    + [("overcloud-novacompute-7", "power on", "active", False, None, None, None),
       ("spare-r640-11", "power off", "available", False, None, None, None)])


# ---------------- the overcloud nodes, as the undercloud lists them and as they answer over SSH ----------------
UC_NODES = [("overcloud-controller-0", "192.168.253.10"), ("overcloud-controller-1", "192.168.253.11"),
            ("overcloud-controller-2", "192.168.253.12"), ("overcloud-novacompute-3", "192.168.253.23"),
            ("overcloud-novacompute-7", "192.168.253.27"), ("overcloud-novacompute-9", "192.168.253.29")]
NODE_DOWN = "overcloud-novacompute-3"   # its BMC does not answer (ironic power failure): no SSH either
NODE_USAGE = {"overcloud-novacompute-7": (80, 85), "overcloud-novacompute-9": (30, 40)}   # real CPU %, RAM % of the computes
REQ = "req-0b1c2d3e-0000-4000-8000-000000000001"
PCS_STATUS = """Cluster name: tripleo_cluster
Cluster Summary:
  * Stack: corosync
  * Current DC: overcloud-controller-1 (version 2.0.5-9.el8_4.5-ba59be7122) - partition with quorum
  * Last updated: Sun Oct 11 08:00:00 2026
  * 3 nodes configured
  * 46 resource instances configured

Node List:
  * Node overcloud-controller-0 (1): online, feature set 3.7.1
  * Node overcloud-controller-1 (2): online, feature set 3.7.1
  * Node overcloud-controller-2 (3): online, feature set 3.7.1

Full List of Resources:
  * ip-192.168.253.5	(ocf::heartbeat:IPaddr2):	 Started overcloud-controller-0
  * ip-10.253.0.5	(ocf::heartbeat:IPaddr2):	 Started overcloud-controller-1
  * Container bundle set: galera-bundle [cluster.common.tag/rhosp16-openstack-mariadb:pcmklatest]:
    * Replica[0]
      * galera-bundle-podman-0	(ocf::heartbeat:podman):	 Started overcloud-controller-0
      * galera-bundle-0	(ocf::pacemaker:remote):	 Started overcloud-controller-0
      * galera	(ocf::heartbeat:galera):	 Master galera-bundle-0
    * Replica[1]
      * galera-bundle-podman-1	(ocf::heartbeat:podman):	 Started overcloud-controller-1
      * galera-bundle-1	(ocf::pacemaker:remote):	 Started overcloud-controller-1
      * galera	(ocf::heartbeat:galera):	 Master galera-bundle-1
    * Replica[2]
      * galera-bundle-podman-2	(ocf::heartbeat:podman):	 Started overcloud-controller-2
      * galera-bundle-2	(ocf::pacemaker:remote):	 Started overcloud-controller-2
      * galera	(ocf::heartbeat:galera):	 Master galera-bundle-2
  * Container bundle set: rabbitmq-bundle [cluster.common.tag/rhosp16-openstack-rabbitmq:pcmklatest]:
    * Replica[0]
      * rabbitmq-bundle-podman-0	(ocf::heartbeat:podman):	 Started overcloud-controller-0
      * rabbitmq	(ocf::heartbeat:rabbitmq-cluster):	 Started rabbitmq-bundle-0
    * Replica[1]
      * rabbitmq-bundle-podman-1	(ocf::heartbeat:podman):	 Started overcloud-controller-1
      * rabbitmq	(ocf::heartbeat:rabbitmq-cluster):	 FAILED rabbitmq-bundle-1
  * Container bundle set: openstack-cinder-volume [cluster.common.tag/rhosp16-openstack-cinder-volume:pcmklatest]:
    * openstack-cinder-volume-podman-0	(ocf::heartbeat:podman):	 Started overcloud-controller-2
  * stonith-fence_ipmilan-525400aa0000	(stonith:fence_ipmilan):	 Started overcloud-controller-1
  * stonith-fence_ipmilan-525400aa0001	(stonith:fence_ipmilan):	 Started overcloud-controller-2
  * stonith-fence_ipmilan-525400aa0002	(stonith:fence_ipmilan):	 Stopped

Failed Resource Actions:
  * rabbitmq_monitor_10000 on rabbitmq-bundle-1 'not running' (7): call=86, status='complete', exitreason='', last-rc-change='2026-10-11 07:40:00 +07:00', queued=0ms, exec=0ms
  * stonith-fence_ipmilan-525400aa0002_start_0 on overcloud-controller-0 'error' (1): call=40, status='Timed Out', exitreason='Unable to obtain correct plug status or plug is not available', last-rc-change='2026-10-11 07:20:00 +07:00', queued=0ms, exec=20004ms

Failed Fencing Actions:
  * reboot of overcloud-controller-2 failed: delegate=overcloud-controller-1, client=pacemaker-controld.2412, origin=overcloud-controller-1, last-failed='2026-10-11 07:21:00 +07:00'

Daemon Status:
  corosync: active/enabled
  pacemaker: active/enabled
  pcsd: active/enabled
"""
RABBIT = """Cluster status of node rabbit@overcloud-controller-0 ...
Basics

Cluster name: rabbit@overcloud-controller-0.localdomain

Disk Nodes

rabbit@overcloud-controller-0
rabbit@overcloud-controller-1
rabbit@overcloud-controller-2

Running Nodes

rabbit@overcloud-controller-0
rabbit@overcloud-controller-2

Versions

rabbit@overcloud-controller-0: RabbitMQ 3.8.3 on Erlang 11.1.4.1

Alarms

(none)

Network Partitions

(none)
"""


def console_ppm(lines):
    """The console of an instance as QEMU's screendump gives it (PPM): 64 x 48, black, a white line of 64 x 10 pixels per
    Enter key pressed (a login prompt printed again), at most four."""
    rows = [b"\xff\xff\xff" * 64 if y // 12 < min(lines, 4) and y % 12 < 10 else b"\x00\x00\x00" * 64 for y in range(48)]
    return b"P6\n64 48\n255\n" + b"".join(rows)


# ---------------- volume connections of an instance (check volume-connections) ----------------
# web-01: its 3 volumes, each with one attached Cinder attachment for compute-07; the LUN Nova keeps is the disk its domain
# uses. fw-pfsense-01 (VC_SID, on compute-07; not in SERVERS, so the lists of the other checks do not change) is what a
# failed live migration to compute-09 left in production: two attachments of its volume (the old one of compute-07
# its domain still runs on, the one of the migration Nova now keeps), the BDM with the LUN number the volume had on
# compute-09 (21), which on compute-07 is the disk of db-01; its port still says migrating_to; libvirt cannot take its job.
VC_SID, VC_VOL, VC_PORT = uid(9, "5e"), uid(30, "1"), uid(9, "9")
VC_IQN = "iqn.1992-08.com.netapp:sn.4f2a9c1e000000000000000000000001:vs.9"
VC_BDM = {  # instance: [(volume, device, attachment, lun)]
    uid(1, "5e"): [(uid(2, "1"), "/dev/vda", uid(31, "a"), 3), (uid(1, "1"), "/dev/vdb", uid(32, "a"), 4),
                   (uid(10, "1"), "/dev/vdc", uid(33, "a"), 5)],
    VC_SID: [(VC_VOL, "/dev/vda", uid(35, "a"), 21)]}
VC_ATT = {  # volume: [(attachment, status, attached host, connector host, connected)]
    uid(2, "1"): [(uid(31, "a"), "attached", "compute-07", "compute-07", 1)],
    uid(1, "1"): [(uid(32, "a"), "attached", "compute-07", "compute-07", 1)],
    uid(10, "1"): [(uid(33, "a"), "attached", "compute-07", "compute-07", 1)],
    VC_VOL: [(uid(34, "a"), "attached", "compute-07", "compute-07", 1), (uid(35, "a"), "reserved", "", "", 0)]}
VC_MIG = {VC_SID: [(8644, "live-migration", "error", "compute-07", "compute-09", "2026-10-27 14:31:44")]}
VC_DOMAINS = {  # domains on compute-07: name, uuid, state, [(target, dm)], job
    "instance-00000001": (uid(1, "5e"), "running (booted)", [("vda", "dm-3"), ("vdb", "dm-4"), ("vdc", "dm-5")], "Job type:         None"),
    "instance-00000005": (uid(5, "5e"), "running (booted)", [("vda", "dm-21")], "Job type:         None"),
    "instance-00000009": (VC_SID, "running (booted)", [("vda", "dm-30")],
                          "error: Timed out during operation: cannot acquire state change lock (held by monitor=init-instance-00000009)")}
VC_LUNS = {3: "dm-3", 4: "dm-4", 5: "dm-5", 21: "dm-21", 30: "dm-30"}   # LUN number on compute-07 -> its multipath device
# vm-3 (VC3_SID, on compute-07) is vm-c3 of 2026-11-02: Nova keeps volume VC3_VOL, whose Cinder row was deleted; the
# target of a volume migration that never completed, VC3_REAL (named VC3_VOL, migration target:VC3_VOL), is attached to it
# and is the disk its domain runs on (dm-40, LUN 103, NetApp LUN volume-VC3_REAL); Nova's stored connection names LUN 33,
# where compute-07 has no device and its igroup maps nothing
VC3_SID, VC3_VOL, VC3_REAL, VC3_ATT = uid(3, "73"), uid(40, "1"), uid(41, "1"), uid(40, "a")
VC3_SERIAL = "80Fq]UzD4Or1"
VC3_WWID = "3600a0980" + VC3_SERIAL.encode().hex()
VC3_IQN = "iqn.1994-05.com.redhat:fake0007"
VC3_IGROUP = "openstack-c07"
VC3_LUN_UUID = uid(43, "1")   # the NetApp LUN volume-VC3_REAL
VC_BDM[VC3_SID] = [(VC3_VOL, "/dev/vda", uid(39, "a"), 33)]
VC_ATT[VC3_REAL] = [(VC3_ATT, "attached", "compute-07", "compute-07", 1)]
VC_DOMAINS["instance-00007303"] = (VC3_SID, "running (migrated)", [("vda", "dm-40")], "Job type:         None")
VC_VOLROWS = {  # volume Nova keeps: the Cinder rows naming it (id, deleted, deleted_at, name_id, name, status, attach, migstat)
    VC3_VOL: [(VC3_VOL, 1, "2026-10-10 16:01:07", uid(42, "1"), VC3_VOL, "deleted", "detached", ""),
              (VC3_REAL, 0, "", "", VC3_VOL, "in-use", "attached", f"target:{VC3_VOL}")]}


def vc_wwid(dm):
    return VC3_WWID if dm == "dm-40" else f"3600a0980383030303030303030{int(dm.split('-')[1]):04x}"


def vc_lun_number(dm):
    return 103 if dm == "dm-40" else next((n for n, d in VC_LUNS.items() if d == dm), 0)


def vc_ontap_answer(path):
    """NetApp (ONTAP REST) reads of the check volume-connections (None for any other path)."""
    import urllib.parse as up
    query = dict(up.parse_qsl(up.urlsplit(path).query))
    if path.startswith("/api/storage/luns?") and "serial_number" in query:   # a search of every LUN: too slow on DCA
        return 1, "HTTP -1: Status code was -1 and not [200]: Connection failure: The read operation timed out"
    if path.startswith("/api/storage/luns/"):   # one LUN by its UUID
        if up.urlsplit(path).path != f"/api/storage/luns/{VC3_LUN_UUID}":
            return 1, "HTTP 404: entry doesn't exist"
        return 0, json.dumps({"uuid": VC3_LUN_UUID, "name": f"/vol/CINDER_25_vol/volume-{VC3_REAL}", "svm": {"name": "SVM1"},
                              "serial_number": STATE.get("vc3_serial", VC3_SERIAL), "status": {"state": "online", "mapped": True}})
    if path.startswith("/api/protocols/san/igroups?"):
        hit = query.get("initiators.name") == VC3_IQN
        return 0, json.dumps({"records": [{"name": VC3_IGROUP, "svm": {"name": "SVM1"}}] if hit else [], "num_records": int(hit)})
    if path.startswith("/api/protocols/san/lun-maps?"):   # compute-07's igroup maps volume-VC3_REAL at LUN 103, nothing at 33
        hit = VC3_IGROUP in query.get("igroup.name", "").split("|") and "103" in query.get("logical_unit_number", "").split("|")
        recs = [{"lun": {"name": f"/vol/CINDER_25_vol/volume-{VC3_REAL}", "uuid": VC3_LUN_UUID}, "logical_unit_number": 103,
                 "igroup": {"name": VC3_IGROUP}, "svm": {"name": "SVM1"}}] if hit else []
        return 0, json.dumps({"records": recs, "num_records": len(recs)})
    return None


def vc_answer(args):
    """OpenStack reads of fw-pfsense-01, its volume and its port (None for anything else)."""
    text = " ".join(args)
    if text.startswith("openstack server show") and args[3] == VC_SID:
        return 0, json.dumps({"id": VC_SID, "name": "fw-pfsense-01", "status": "ERROR", "OS-EXT-STS:vm_state": "error",
                              "OS-EXT-STS:power_state": "Running", "OS-EXT-STS:task_state": None, "OS-EXT-SRV-ATTR:host": "compute-07",
                              "OS-EXT-SRV-ATTR:instance_name": instance_name(VC_SID), "project_id": CUSTOMER, "fault": None,
                              "volumes_attached": [{"id": VC_VOL}], "image": "", "flavor": "m1.small"})
    if text.startswith("openstack port list") and "--server" in args and args[args.index("--server") + 1] == VC_SID:
        return 0, json.dumps([{"ID": VC_PORT, "Name": "fw-pfsense-01-wan", "Status": "ACTIVE"}])
    if text.startswith("openstack port show") and args[3] == VC_PORT:
        return 0, json.dumps({"id": VC_PORT, "name": "fw-pfsense-01-wan", "status": "ACTIVE", "device_id": VC_SID,
                              "binding_host_id": "compute-07", "binding_vif_type": "ovs", "binding_profile": {"migrating_to": "compute-09"}})
    if text.startswith("openstack server show") and args[3] == VC3_SID:
        return 0, json.dumps({"id": VC3_SID, "name": "vm-3", "status": "ACTIVE", "OS-EXT-STS:vm_state": "active",
                              "OS-EXT-STS:power_state": "Running", "OS-EXT-STS:task_state": None, "OS-EXT-SRV-ATTR:host": "compute-07",
                              "OS-EXT-SRV-ATTR:instance_name": "instance-00007303", "project_id": CUSTOMER, "fault": None,
                              "volumes_attached": [{"id": VC3_VOL}], "image": "", "flavor": "m1.large"})
    if text.startswith("openstack port list") and "--server" in args and args[args.index("--server") + 1] == VC3_SID:
        return 0, "[]"
    if text.startswith("openstack volume show") and args[3] in (VC3_VOL, VC3_REAL):   # by name: the target named after it
        return 0, json.dumps({"id": VC3_REAL, "name": VC3_VOL, "status": "in-use", "size": 100, "multiattach": False,
                              "migration_status": f"target:{VC3_VOL}", "attachments": [{"server_id": VC3_SID, "device": "/dev/vda"}]})
    if text.startswith("openstack volume show") and args[3] == VC_VOL:
        return 0, json.dumps({"id": VC_VOL, "name": "fw-pfsense-01-root", "status": "in-use", "size": 20, "multiattach": False,
                              "bootable": "true", "attachments": [{"server_id": VC_SID, "device": "/dev/vda"}]})
    return None


# ---------------- check lun-map-audit: an SVM where an instance runs on a FlexClone copy of its LUN (a real case)
LM_IQN = "iqn.1992-08.com.netapp:sn.4f2a9c1e000000000000000000000002:vs.14"
LM_INIT = {"overcloud-controller-0": "iqn.1994-05.com.redhat:c0", "overcloud-controller-1": "iqn.1994-05.com.redhat:c1",
           "overcloud-controller-2": "iqn.1994-05.com.redhat:c2", "overcloud-novacompute-7": "iqn.1994-05.com.redhat:c07",
           "overcloud-novacompute-9": "iqn.1994-05.com.redhat:c09"}
LM_V = {k: uid(i, "7") for i, k in enumerate(["ok", "clone", "cloneN", "away", "gone", "wrong", "other", "nomap"], 1)}
LM_CLONE, LM_CLONE2 = f"snap_{PREFIX}_CINDER_15_vol_clone_152", f"Clone_14oct_{PREFIX}_CINDER_15_vol_clone_858"
LM_P15, LM_P14 = f"{PREFIX}_CINDER_15_vol", f"{PREFIX}_CINDER_14_vol"


def lm_path(fv, k):
    return f"/vol/{fv}/volume-{LM_V[k]}"


LM_MAPS = [  # igroup, LUN number, path
    ("openstack-0707", 5, lm_path(LM_P14, "ok")),
    ("openstack-0707", 28, lm_path(LM_CLONE, "cloneN")),   # the copy compute-7 runs the volume "clone" on
    ("openstack-0909", 185, lm_path(LM_P15, "cloneN")),    # its original, left mapped to the source of the live migration
    ("openstack-0909", 3, lm_path(LM_P15, "away")),
    ("openstack-0707", 60, lm_path(LM_P15, "away")),       # left on compute-7: in use on compute-9
    ("openstack-0707", 61, lm_path(LM_P15, "gone")),       # a LUN whose volume Cinder deleted
    ("openstack-0707", 40, lm_path(LM_P15, "other")),      # Cinder attached the volume "wrong" at 40
    ("openstack-dead", 1, lm_path(LM_P15, "gone")),        # an igroup of no node
]
LM_LUNS = list(dict.fromkeys([p for _g, _l, p in LM_MAPS] + [lm_path(LM_CLONE, "away"), lm_path(LM_CLONE2, "cloneN"),
                                                              lm_path(LM_P14, "wrong"), lm_path(LM_P14, "nomap")]))
LM_SERIAL = {lm_path(LM_CLONE, "cloneN"): "818Lo]UsIHNz", lm_path(LM_P15, "cloneN"): "818Lo]UsIBNR"}
LM_ATT = [  # attachment, volume, compute, LUN, created (UTC)
    (uid(1, "a7"), "ok", "overcloud-novacompute-7", 5, "2025-01-01 00:00:00"),
    (uid(2, "a7"), "clone", "overcloud-novacompute-7", 28, "2026-10-01 00:59:00"),
    (uid(3, "a7"), "away", "overcloud-novacompute-9", 3, "2026-09-01 10:00:00"),
    (uid(4, "a7"), "wrong", "overcloud-novacompute-7", 40, "2026-08-01 10:00:00"),
    (uid(5, "a7"), "nomap", "overcloud-novacompute-7", 50, "2026-08-02 10:00:00"),
]
LM_VOL = {"ok": ("", LM_P14, "in-use"), "clone": ("cloneN", LM_P15, "in-use"), "away": ("", LM_P15, "in-use"),
          "wrong": ("", LM_P14, "in-use"), "other": ("", LM_P15, "available"), "nomap": ("", LM_P14, "in-use")}


def lm_wwid(serial):
    return "3600a0980" + serial.encode().hex()


def lm_ontap_answer(path):
    """NetApp reads of the check lun-map-audit (None for any other path): lists of SVM1 with return_timeout, the iSCSI
    services, and a LUN's serial by its UUID. The LUN list comes in two pages (_links.next)."""
    import urllib.parse as up
    parts = up.urlsplit(path)
    query = dict(up.parse_qsl(parts.query))
    uuid_of = {p: uid(i, "e") for i, p in enumerate(LM_LUNS, 1)}
    if parts.path == "/api/protocols/san/iscsi/services":
        return 0, json.dumps({"records": [{"svm": {"name": "SVM1"}, "target": {"name": LM_IQN}},
                                          {"svm": {"name": "SVM_NFS"}, "target": {"name": "iqn.1992-08.com.netapp:sn.0:vs.2"}}]})
    if parts.path.startswith("/api/storage/luns/") and query.get("fields") == "name,serial_number":
        p = next((p for p, u in uuid_of.items() if parts.path.endswith(u)), None)
        if not p:
            return 1, "HTTP 404: entry doesn't exist"
        return 0, json.dumps({"uuid": uuid_of[p], "name": p, "serial_number": LM_SERIAL.get(p, "818Lo]UsIxxx")})
    if "return_timeout" not in query:
        return None
    if query.get("svm.name") != "SVM1":
        return 0, json.dumps({"records": [], "num_records": 0})
    if parts.path == "/api/protocols/san/lun-maps":
        return 0, json.dumps({"records": [{"svm": {"name": "SVM1"}, "lun": {"name": p, "uuid": uuid_of[p]}, "logical_unit_number": n,
                                           "igroup": {"name": g}} for g, n, p in LM_MAPS]})
    if parts.path == "/api/storage/luns":
        recs = [{"uuid": uuid_of[p], "name": p, "svm": {"name": "SVM1"}} for p in LM_LUNS]
        if "start.name" not in query:
            return 0, json.dumps({"records": recs[:5], "num_records": 5,
                                  "_links": {"next": {"href": f"/api/storage/luns?svm.name=SVM1&fields=name,svm.name&return_timeout=45"
                                                              f"&start.name={recs[5]['name']}"}}})
        return 0, json.dumps({"records": recs[5:], "num_records": len(recs) - 5})
    if parts.path == "/api/storage/volumes":
        return 0, json.dumps({"records": [
            {"name": LM_P14, "svm": {"name": "SVM1"}, "create_time": "2022-01-10T10:00:00+07:00", "clone": {"is_flexclone": False}},
            {"name": LM_P15, "svm": {"name": "SVM1"}, "create_time": "2022-01-10T10:00:00+07:00", "clone": {"is_flexclone": False}},
            {"name": LM_CLONE, "svm": {"name": "SVM1"}, "create_time": "2025-06-26T08:35:21+07:00",
             "clone": {"is_flexclone": True, "parent_volume": {"name": LM_P15}, "parent_snapshot": {"name": "hourly.2025-06-24_0905"}}},
            {"name": LM_CLONE2, "svm": {"name": "SVM1"}, "create_time": "2025-10-14T08:00:00+07:00",
             "clone": {"is_flexclone": True, "parent_volume": {"name": LM_P15}, "parent_snapshot": {"name": "hourly.2025-10-14_0705"}}}]})
    if parts.path == "/api/protocols/san/igroups":
        groups = {"openstack-0707": [LM_INIT["overcloud-novacompute-7"]], "openstack-0909": [LM_INIT["overcloud-novacompute-9"]],
                  "openstack-dead": ["iqn.1994-05.com.redhat:gone"], "openstack-ctl0": [LM_INIT["overcloud-controller-0"]]}
        return 0, json.dumps({"records": [{"name": g, "svm": {"name": "SVM1"}, "initiators": [{"name": i} for i in inits]}
                                          for g, inits in groups.items()]})
    return None


def lm_node_answer(name, cmd):
    """The reads of the check lun-map-audit on a node (None for any other command)."""
    if "SELECT 'org'" in cmd and "controller" in name:   # lm_db
        rows = [f"att\t{a}\t{LM_V[v]}\t{uid(i, 'd7')}\tattached\t{h}.localdomain\t{LM_INIT[h]}\t{LM_IQN}\t{n}\t{c}\t{c}"
                for i, (a, v, h, n, c) in enumerate(LM_ATT, 1)]
        rows += [f"vol\t{LM_V[k]}\t{LM_V[nid] if nid else ''}\t{st}\t{HOST}#{p}\t50\t\t{k}-disk" for k, (nid, p, st) in LM_VOL.items()]
        rows += [f"org\t{a}\t\t\t" for a, v, *_x in LM_ATT if v != "clone"]
        rows.append(f"org\t{uid(2, 'a7')}\tlive-migration|{REQ}|2026-10-01 00:58:00\t"
                    "live-migration|completed|overcloud-novacompute-9.localdomain|overcloud-novacompute-7.localdomain|2026-10-01 00:58:00\t"
                    f"{uid(9, 'a7')}|overcloud-novacompute-9.localdomain|185|2024-05-01 00:00:00|2026-10-01 01:04:00|2026-10-01 01:05:00")
        rows.append("min\t2026-09-01 00:00:00")
        return 0, "\n".join(rows)
    if "@@node" in cmd and "@@dev" in cmd and "@@use" in cmd:   # lm_node
        out = [f"@@node {name} {LM_INIT.get(name, '')}"]
        devs = {"overcloud-novacompute-7": [(5, "818Lq]UzD6Ka", "dm-1"), (28, LM_SERIAL[lm_path(LM_CLONE, 'cloneN')], "dm-2"),
                                            (40, "818Lq]UzD6K3", "dm-4"), (70, "818Lq]UzD7Kb", "dm-7")],
                "overcloud-novacompute-9": [(3, "818Lq]UzD8Kc", "dm-3")]}.get(name, [])
        for i, (lun, ser, dm) in enumerate(devs):
            for p in (0, 1):
                out.append(f"@@dev sd{chr(97 + 2 * i + p)} {7 + p}:0:0:{lun} running {LM_IQN} {lm_wwid(ser)} {dm}")
        if name.endswith("-7"):
            out += [f"@@use dm-1 {uid(1, 'd7')} instance-00000001 vda", f"@@use dm-2 {uid(2, 'd7')} instance-00000002 vda",
                    f"@@use dm-7 {uid(7, 'd7')} instance-00000007 vdb"]
        return 0, "\n".join(out)
    return None


def vc_node_answer(name, cmd):
    """The reads of the check volume-connections on a node (None for any other command)."""
    if "nova.block_device_mapping" in cmd and "controller" in name:   # vc_db: SELECT on the galera container
        sid = re.search(r"instance_uuid='([0-9a-f-]{36})'", cmd).group(1)
        rows = [f"bdm\t{v}\t{a}\t{dev}\tiscsi\t{VC_IQN}\t{lun}\t[{lun}, {lun}]\t/dev/{VC_LUNS.get(lun, 'sdzz')}" for v, dev, a, lun in VC_BDM.get(sid, [])]
        vols = [v for v, _d, _a, _l in VC_BDM.get(sid, [])]
        named = [r[0] for v in vols for r in VC_VOLROWS.get(v, []) if r[0] != v and not r[1]]
        rows += [f"att\t{v}\t{a}\t{st}\t{h}\t{c}\t{n}\t{sid}" for v in vols + named for a, st, h, c, n in VC_ATT.get(v, [])]
        rows += ["vol\t" + "\t".join(str(x) for x in r) + "\tcompute@backend#POOL\t2025-11-04 20:59:05" for v in vols
                 for r in VC_VOLROWS.get(v, [(v, 0, "", "", f"{v[:8]}-disk", "in-use", "attached", "")])]
        rows += [f"mig\t{i}\t{t}\t{st}\t{s}\t{d}\t{c}" for i, t, st, s, d, c in VC_MIG.get(sid, [])]
        return 0, "\n".join(rows)
    on07 = name.endswith("-7")
    if "@@state" in cmd and "@@job" in cmd:   # vc_domain
        inst = re.search(r"domstate (instance-[0-9a-f]{8})", cmd).group(1)
        d = VC_DOMAINS.get(inst) if on07 else None
        if not d:
            return 0, f"@@state error: failed to get domain '{inst}'\n@@uuid \n@@job error: failed to get domain '{inst}'"
        return 0, "\n".join([f"@@state {d[1]}", f"@@uuid {d[0]}"]
                            + [f"@@disk {t} /dev/{dm} {dm} {vc_wwid(dm)} {vc_lun_number(dm)}" for t, dm in d[2]]
                            + [f"@@initiator {VC3_IQN}", f"@@job {d[3]}"])
    if "@@path" in cmd and "@@use" in cmd:   # vc_lun
        lun = int(re.search(r"-lun-(\d+)\$", cmd).group(1))
        out = []
        if on07 and lun in VC_LUNS:
            dm = VC_LUNS[lun]
            out = [f"@@path ip-10.237.1.{p}:3260-iscsi-{VC_IQN}-lun-{lun} sd{chr(97 + lun % 20)}{p} {dm} {vc_wwid(dm)}" for p in (2, 3)]
        if on07:
            out += [f"@@use {x} {d[0]} /dev/{dm}" for x, d in VC_DOMAINS.items() for _t, dm in d[2]]
        return 0, "\n".join(out)
    if "Pre live migration failed" in cmd and "nova-compute.log" in cmd:   # vc_log
        if not on07:
            return 0, ""
        at = "2026-10-27 21:32:58.276 2"
        return 0, "\n".join([
            f"{at} ERROR nova.compute.manager [-] [instance: {VC_SID}] Live migration failed.: libvirt.libvirtError: Timed out "
            "during operation: cannot acquire state change lock (held by monitor=init-instance-00000009)",
            f"2026-10-28 07:50:59.551 2 WARNING os_brick.exception [req-13889dac-0000-4000-8000-000000000001 - - - - -] Flushing "
            f"{vc_wwid('dm-21')} failed: oslo_concurrency.processutils.ProcessExecutionError: Unexpected error while running command."])
    return None


# ---------------- VM disks on a compute (check compute-disks) ----------------
# overcloud-novacompute-9 (compute-09) is healthy: one domain, its disk with two active paths. overcloud-novacompute-7
# (compute-07) is what the rollback of a refused live migration left in production: db-01's disk (dm-7, LUN 7) has
# no path any more ("##,##"), the kernel removed 11:0:0:7 and 12:0:0:7 and logged write I/O errors on dm-7; legacy-08's
# disk has one failed path; three instance directories have no domain: one of an instance Nova has on compute-09 (SAFE),
# one of a deleted instance (SAFE, empty), and gpu-06's, which Nova has on compute-07 itself (check it, never moved).
CD_LEFT = uid(40, "5e")   # an instance on compute-09, its old directory still on compute-07
CD_GONE = uid(41, "5e")   # a deleted instance, its empty directory still on compute-07


def cd_wwid(n):
    return f"3600a0980383148{n:018x}"


def cd_map(dm, n, paths):
    """multipath -ll of one map: paths [(h:c:t:l, sd, state)] (none: the map lost them all, ##,##)."""
    head = f"{cd_wwid(n)} {dm} " + ("NETAPP,LUN C-Mode" if paths else "##,##")
    lines = [head, f"size=20G features='{'3 queue_if_no_path pg_init_retries 50' if paths else '2 pg_init_retries 50'}' "
                   f"hwhandler='{'1 alua' if paths else '0'}' wp=rw"]
    for i, (addr, sd, st) in enumerate(paths):
        lines += [f"{'|' if i == 0 else '`'}-+- policy='service-time 0' prio={50 if i == 0 else 10} status={'active' if i == 0 else 'enabled'}",
                  f"{'|' if i == 0 else ' '} `- {addr}  {sd}  8:{i * 16}  {st}"]
    return lines


CD_NODES = {
    "overcloud-novacompute-9": {
        "kernel": [],
        "maps": cd_map("dm-3", 3, [("11:0:0:3", "sdc", "active ready running"), ("12:0:0:3", "sdd", "active ready running")]),
        "domains": [("instance-00000021", uid(21, "5e"), [("vda", "/dev/dm-3")])],
        "dirs": [(uid(21, "5e"), "yes", 500, "console.log")]},
    "overcloud-novacompute-7": {
        "kernel": ["Oct 28 08:16:28 overcloud-novacompute-7 kernel: scsi 11:0:0:7: alua: Detached",
                   "Oct 28 08:16:28 overcloud-novacompute-7 kernel: scsi 12:0:0:7: alua: Detached",
                   "Oct 28 08:16:29 overcloud-novacompute-7 kernel: I/O error, dev dm-7, sector 2337672 op 0x1:(WRITE) flags 0x8800",
                   "Oct 28 08:16:30 overcloud-novacompute-7 kernel: I/O error, dev dm-7, sector 2179936 op 0x1:(WRITE) flags 0x8800"],
        "maps": cd_map("dm-3", 3, [("11:0:0:3", "sdc", "active ready running"), ("12:0:0:3", "sdd", "active ready running")])
                + cd_map("dm-7", 7, [])
                + cd_map("dm-9", 9, [("11:0:0:9", "sdk", "active ready running"), ("12:0:0:9", "sdl", "failed faulty running")]),
        "domains": [("instance-00000001", uid(1, "5e"), [("vda", "/dev/dm-3")]),
                    ("instance-00000005", uid(5, "5e"), [("vda", "/dev/dm-7")]),
                    ("instance-00000008", uid(8, "5e"), [("vda", "/dev/dm-9")])],
        "dirs": [(uid(1, "5e"), "yes", 20000, "console.log"), (uid(5, "5e"), "yes", 50000, "console.log"),
                 (uid(8, "5e"), "yes", 90000, "console.log"), (CD_LEFT, "no", 43500, "console.log"),
                 (CD_GONE, "no", 1285829, ""), (uid(7, "5e"), "no", 30000, "console.log")]},
}


def cd_answer(args):
    """OpenStack reads of the check compute-disks that the fixed cloud has no answer for (None for anything else)."""
    text = " ".join(args)
    if text.startswith("openstack server show") and args[3] == CD_LEFT:
        return 0, json.dumps({"id": CD_LEFT, "name": "db-left-01", "status": "ACTIVE", "OS-EXT-STS:task_state": None,
                              "OS-EXT-SRV-ATTR:host": "compute-09", "OS-EXT-SRV-ATTR:instance_name": instance_name(CD_LEFT)})
    return None


def cd_node_answer(name, cmd):
    """The cd_disks read of the check compute-disks on a compute (None for any other command)."""
    if not ("echo @@kernel" in cmd and "echo @@dirs" in cmd):
        return None
    n = CD_NODES.get(name)
    if not n:
        return 0, "@@kernel\n@@maps\n@@domains\n@@dirs\n@@fs xfs"
    out = ["@@kernel"] + n["kernel"] + ["@@maps"] + n["maps"] + ["@@domains"]
    for dom, u, disks in n["domains"]:
        out += [f"@@dom {dom} {u}"] + [f"@@disk {t} {src}" for t, src in disks]
    out += ["@@dirs", "@@fs xfs"] + [f"@@dir {u} {d} {age} {files}" for u, d, age, files in n["dirs"]]
    return 0, "\n".join(out)


# ---------------- guest LVs active on computes (check host-lvm; wi_ops release-lv / flush-map / delete-path) ----------
# overcloud-novacompute-9 keeps guest volumes off (global_filter r|.*|), nothing active. overcloud-novacompute-7 accepts
# every device (as az1-compute-2..5): db-01 runs on a guest LV (its vdb is dm-21, the LV the host
# activated on path sdm), legacy-08's map dm-9 carries an LV of its guest (dm-20), gpu-06's vdb runs on one SCSI device
# (sdq) with an LV on its partition sdq1 (dm-22), an LV is left on a map nothing uses (dm-23 on dm-11), a map without any
# path is left (dm-12), the host's own root LV (dm-0 on sda2) is not a guest's, and two iSCSI path devices are left in
# no map (sdez, sdfa: a disconnect that did not finish, as in a real case; delete-path).
def hl_uuid(n):
    return f"LVM-{'Gx7Q' * 8}{n:032d}"


HL_NODES = {
    "overcloud-novacompute-9": {"filter": '["r|.*|"]', "lvs": [], "maps": [("dm-3", cd_wwid(3), "1", "-", 2, 2, "sdc,sdd")],
                                "domains": [("instance-00000021", uid(21, "5e"), [("vda", "dm-3")])]},
    "overcloud-novacompute-7": {
        "filter": '["a|.*|"]',
        "lvs": [("dm-0", "rhel-root", f"LVM-{'H' * 64}", "1", "-", "local:sda2:sda"),
                ("dm-20", "vg_data-lv_data", hl_uuid(20), "0", "-", f"map:dm-9:dm-9:{cd_wwid(9)}"),
                ("dm-21", "vg--db-lv--var", hl_uuid(21), "1", "-", f"path:sdm:sdm:{cd_wwid(21)}"),
                ("dm-22", "vg_gpu-lv_scratch", hl_uuid(22), "0", "-", f"path:sdq1:sdq:{cd_wwid(22)}"),
                ("dm-23", "vg_old-lv_old", hl_uuid(23), "0", "-", f"map:dm-11:dm-11:{cd_wwid(11)}")],
        "maps": [("dm-3", cd_wwid(3), "1", "-", 2, 2, "sdc,sdd"), ("dm-7", cd_wwid(7), "1", "-", 0, 0, "-"),
                 ("dm-9", cd_wwid(9), "1", "dm-20", 1, 2, "sdk,sdl"),
                 ("dm-11", cd_wwid(11), "1", "dm-23", 2, 2, "sdn,sdo"), ("dm-12", cd_wwid(12), "0", "-", 0, 0, "-")],
        "domains": [("instance-00000001", uid(1, "5e"), [("vda", "dm-3")]),
                    ("instance-00000005", uid(5, "5e"), [("vda", "dm-7"), ("vdb", "dm-21")]),
                    ("instance-00000008", uid(8, "5e"), [("vda", "dm-9")]),
                    ("instance-00000007", uid(7, "5e"), [("vdb", "sdq")])],
        "loose": [("sdez", "17:0:0:12", cd_wwid(30), "running", "1"), ("sdfa", "18:0:0:12", cd_wwid(30), "running", "1"),
                  ("sdq", "19:0:0:22", cd_wwid(22), "running", "1"),
                  ("sdhh", "19:0:0:58", "3600a098038314255672b4f6b4c333454", "running", "0")]},
}


HL_IQN = "iqn.1992-08.com.netapp:sn.fake0001:vs.7"
HL_BDM = {uid(5, "5e"): [("/dev/vda", uid(5, "b0"), HL_IQN, "7"), ("/dev/vdb", uid(6, "b0"), HL_IQN, "21")]}


# check compute-memory: overcloud-novacompute-7 is dccrhosp-compute-1 of 2026-10-30 (DIMM CPU2_C3D0 at its correctable ECC
# logging limit three times in three days, NMIs of hardware errors up to 2 s, a crash dump, booted after it; its BMC
# clock in UTC); with STATE["mem_replaced"] the same compute on 2026-11-02, after its DIMM was replaced (SEL cleared, 9
# entries, sensors normal, booted 2 h ago, the NMIs and the dump of the old DIMM before that boot);
# overcloud-novacompute-9 is healthy (an old correctable error 20 days ago, its BMC clock in WIB, UTC+7)
def mem_node_answer(name, cmd):
    if "ipmitool sel elist" not in cmd or "@@crash" not in cmd:
        return None
    now = NOW.replace(tzinfo=None, microsecond=0)
    def at(days, hours=0, offset=0):   # noqa: E306  a time on the BMC clock
        return (now - datetime.timedelta(days=days, hours=hours) + datetime.timedelta(hours=offset)).strftime("%m/%d/%Y | %H:%M:%S")
    dimms = [f"CPU{c}_C{ch}D{d}        | {0x80 + c * 16 + ch * 2 + d:02X}h | ok  | 32.{c} | Presence Detected" for c in (1, 2)
             for ch in range(6) for d in (0, 1)]
    if name == "overcloud-novacompute-7":
        dimms = [x.replace("Presence Detected", "Presence Detected, Correctable ECC logging limit reached") if x.startswith("CPU2_C3D0") else x
                 for x in dimms]
        sel = [f"  30 | {at(3, 1)} | Memory CPU2_C3D0 | Correctable ECC logging limit reached | Asserted",
               f"  33 | {at(2, 2)} | Memory CPU2_C3D0 | Correctable ECC logging limit reached | Asserted",
               f"  35 | {at(0, 8)} | Memory CPU2_C3D0 | Correctable ECC logging limit reached | Deasserted",
               f"  37 | {at(0, 7)} | Memory CPU2_C3D0 | Correctable ECC logging limit reached | Asserted",
               f"  12 | {at(25)} | Memory CPU1_C0D0 | Correctable ECC | Asserted"]   # outside a window of 7 days
        kernel = ["Oct 28 05:45:56 overcloud-novacompute-7 kernel: EDAC MC3: Giving out device to module skx_edac controller Skylake",
                  "Oct 29 02:59:39 overcloud-novacompute-7 kernel: INFO: NMI handler (ghes_notify_nmi) took too long to run: 1.234 msecs",
                  "Oct 30 06:28:34 overcloud-novacompute-7 kernel: INFO: NMI handler (ghes_notify_nmi) took too long to run: 2011.556 msecs"]
        crash = ["127.0.0.1-" + (now - datetime.timedelta(hours=1)).strftime("%Y-%m-%d-%H:%M:%S")]
        bmc, info = now, ["Entries          : 38", "Percent Used     : 1%", "Overflow         : false",
                          f"Last Del Time    : {at(40).replace(' | ', ' ')}"]
        first, boot = f"   1 | {at(40)} | Event Logging Disabled SEL | Log area reset/cleared | Asserted", now - datetime.timedelta(minutes=50)
        if STATE.get("mem_replaced"):
            dimms = [x.replace(", Correctable ECC logging limit reached", "") for x in dimms]
            sel = [f"   1 | {at(0, 3)} | Event Logging Disabled SEL | Log area reset/cleared | Asserted"]
            first = sel[0]
            crash = ["127.0.0.1-" + (now - datetime.timedelta(days=3)).strftime("%Y-%m-%d-%H:%M:%S")]
            info = ["Entries          : 9", "Percent Used     : 0%", "Overflow         : false",
                    f"Last Del Time    : {at(0, 3).replace(' | ', ' ')}"]
            boot = now - datetime.timedelta(hours=2)
    else:
        sel = [f"   4 | {at(20, 0, 7)} | Memory CPU1_C2D1 | Correctable ECC | Asserted"]
        kernel, crash = [], []
        bmc, info = now + datetime.timedelta(hours=7), ["Entries          : 512", "Percent Used     : 95%", "Overflow         : false"]
        first, boot = f"   1 | {at(60, 0, 7)} | System Event | OEM System boot event | Asserted", now - datetime.timedelta(days=30)
    bmcip, serial = ("172.24.28.27", "221636007") if name == "overcloud-novacompute-7" else ("172.24.28.29", "221636009")
    return 0, "\n".join([f"@@now {now:%Y-%m-%d %H:%M:%S}", f"@@boot {boot:%Y-%m-%d %H:%M:%S} +0000", f"@@serial {serial}",
                          f"@@bmctime {bmc:%m/%d/%Y %H:%M:%S}", f"@@bmcip {bmcip}", "@@selinfo"] + info
                        + [f"@@selfirst {first}", "@@sel"] + sel + ["@@sdr"] + dimms + ["@@kernel"] + kernel
                        + ["@@edac", "@@crash"] + crash + ["@@end"])


def hl_node_answer(name, cmd):
    """The guest-LV reads and releases on a compute (None for any other command): HOST_LVS, RELEASE_LV, FLUSH_MAP, and
    for rescan-disk Nova's connection (controller), the iSCSI sessions of a target and the scan of a LUN (compute)."""
    gone = set(STATE.get("hl_released") or [])
    back = set(STATE.get("hl_rescanned") or [])
    if "@@bdm" in cmd and "nova.block_device_mapping" in cmd:
        m = re.search(r"instance_uuid = \W*([0-9a-f]{8}-[0-9a-f-]{27})", cmd)
        return 0, "\n".join(f"@@bdm {dev}\t{vol}\t{iqn}\t{lun}" for dev, vol, iqn, lun in HL_BDM.get(m.group(1) if m else "", []))
    if "iscsi_session" in cmd and "@@host" in cmd:
        return 0, "@@host 11\n@@host 12" if HL_IQN in cmd and name in HL_NODES else ""
    if "/scan" in cmd and "@@kept" in cmd and name == "overcloud-novacompute-7":
        if cd_wwid(7) not in cmd:
            return 0, ""
        STATE.setdefault("hl_rescanned", []).append(cd_wwid(7))
        if STATE_FILE:
            save_state()
        return 0, f"@@kept 11:0:0:7 sdlp {cd_wwid(7)}\n@@kept 12:0:0:7 sdlq {cd_wwid(7)}"
    if "@@devicesfile" in cmd and "echo @@domains" in cmd:
        n = HL_NODES.get(name)
        if not n:
            return 0, '@@filter ["r|.*|"]\n@@devicesfile 1 absent\n@@domains'
        out = [f"@@filter {n['filter']}", "@@devicesfile 1 absent"]
        out += [f"@@lv {dm} {nm} {u} {o} {h} {on}" for dm, nm, u, o, h, on in n["lvs"] if u not in gone]
        out += [f"@@map {dm} {w} {o} {'-' if h != '-' and any(x[2] in gone for x in n['lvs'] if x[0] == h) else h} "
                + ("2 2 sdlp,sdlq" if w in back else f"{r} {t} {p}")
                for dm, w, o, h, r, t, p in n["maps"] if w not in gone]
        out += [f"@@sd {sd} {a} {st} {w} {rd}" for sd, a, w, st, rd in n.get("loose", []) if sd not in gone]
        out.append("@@domains")
        for dom, u, disks in n["domains"]:
            out += [f"@@dom {dom} {u}"] + [f"@@disk {t} {dev}" for t, dev in disks]
        return 0, "\n".join(out)
    m = re.search(r"D=(sd[a-z]+); A=(\S+); W=\S+\n", cmd)
    if m and "device/delete" in cmd:
        p = next((x for x in (HL_NODES.get(name) or {}).get("loose", []) if x[0] == m.group(1)), None)
        if not p or p[0] in gone or p[1] != m.group(2):
            return 0, "@@gone"
        STATE.setdefault("hl_released", []).append(p[0])
        if STATE_FILE:
            save_state()
        return 0, f"@@path {p[0]} {p[1]} running {p[2]}\n@@read exit 1\n@@deleted {p[0]} {p[1]}"
    m = re.search(r"U=(LVM-[A-Za-z0-9]{64})\n", cmd)
    if m and "dmsetup remove" in cmd:
        lv = next((x for x in (HL_NODES.get(name) or {}).get("lvs", []) if x[2] == m.group(1)), None)
        if not lv or lv[2] in gone:
            return 0, "@@gone"
        dm, nm, _u, o, h, on = lv
        if o != "0":
            return 0, f"@@lv {dm} {nm} {o} {h}\n@@refused opened {o} time(s) on the host"
        STATE.setdefault("hl_released", []).append(lv[2])
        if STATE_FILE:
            save_state()
        return 0, f"@@lv {dm} {nm} 0 -\n@@removed {dm} {nm}" + ("\n@@left sdq " + cd_wwid(22) if "sdq1" in on else "")
    m = re.search(r"W=(3[0-9a-f]{32})\n", cmd)
    if m and "multipath -f" in cmd:
        mp = next((x for x in (HL_NODES.get(name) or {}).get("maps", []) if x[1] == m.group(1)), None)
        if not mp or mp[1] in gone:
            return 0, "@@gone"
        if mp[4] or mp[2] != "0":
            return 0, f"@@map {mp[0]} {mp[2]} {mp[3]} {mp[4]}\n@@refused {mp[4]} path(s) of it still run"
        STATE.setdefault("hl_released", []).append(mp[1])
        if STATE_FILE:
            save_state()
        return 0, f"@@map {mp[0]} 0 - 0\n@@flushed {mp[0]}"
    return None


def node_answer(name, cmd):
    """(rc, output) of a fixed read command on an overcloud node."""
    if name == NODE_DOWN:
        return 255, f"ssh: connect to host {dict(UC_NODES)[name]} port 22: No route to host"
    if name in (STATE.get("ssh_down") or []):   # a node the director cannot reach over SSH (as compute-0 of DCB)
        return 255, f"ssh: connect to host {dict(UC_NODES)[name]} port 22: Connection timed out"
    lm = lm_node_answer(name, cmd)
    if lm is not None:
        return lm
    hl = hl_node_answer(name, cmd)
    if hl is not None:
        return hl
    mem = mem_node_answer(name, cmd)
    if mem is not None:
        return mem
    vc = vc_node_answer(name, cmd)
    if vc is not None:
        return vc
    cd = cd_node_answer(name, cmd)   # before the read of wi_ops' disk_paths below: cd_disks also starts with @@kernel
    if cd is not None:
        return cd
    # ---- wi_ops live migration: a directory of the instance left on the destination, and what a rollback did there
    # (STATE["leftover_dir"]: {instance UUID: compute number} where it is left; nothing removed by default)
    m = re.search(r"d=/var/lib/nova/instances/([0-9a-f-]{36}); .*@@exists", cmd)
    if m:
        on = (STATE.get("leftover_dir") or {}).get(m.group(1))
        here = on is not None and name.endswith("-" + str(on))
        return 0, f"@@exists {'yes 2026-10-28 08:14:59' if here else 'no'}\n@@fstype xfs\n@@domain no"
    m = re.search(r"mv /var/lib/nova/instances/([0-9a-f-]{36}) ", cmd)
    if m:
        (STATE.get("leftover_dir") or {}).pop(m.group(1), None)
        if STATE_FILE:
            save_state()
        return 0, f"drwxr-xr-x. 2 42436 42436 25 2026-10-28 08:14 /var/lib/nova/instances/{m.group(1)}.leftover"
    if "echo @@kernel" in cmd:
        return 0, "@@kernel\n@@maps\n@@domains"
    m = re.search(r"virsh -c qemu:///system (screenshot|send-key) (instance-[0-9a-f]{8})", cmd)
    if m:   # the console of an instance (wi_ops: screenshots around a change; the console test: one Enter key)
        sid = next((x for x in SERVERS if instance_name(x) == m.group(2)), None)
        if not sid or SERVERS[sid][1] != "ACTIVE":
            return 1, f"error: Requested operation is not valid: domain is not running"
        keys = (STATE.get("enter") or {}).get(sid, 0)
        if m.group(1) == "send-key":
            STATE.setdefault("enter", {})[sid] = keys + 1
            if STATE_FILE:
                save_state()
            return 0, ""
        return 0, base64.b64encode(console_ppm(keys)).decode()
    m = re.search(r"date -d \W*-(\d+) seconds.*\(ERROR\|CRITICAL\) \.\*([0-9a-f]{8}-[0-9a-f-]{27})\W* /var/log/containers/nova/nova-compute\.log", cmd)
    if m:   # ERROR lines of an instance in nova-compute since a time (wi_ops: why a live migration left it in ERROR)
        since = (datetime.datetime.now() - datetime.timedelta(seconds=int(m.group(1)))).strftime("%Y-%m-%d %H:%M:%S")
        lines = next((v for h, v in (STATE.get("nova_log") or {}).items() if name.endswith("-" + str(int(h.split("-")[-1])))), [])
        return 0, "\n".join(x for x in lines if m.group(2) in x and x[:19] >= since)
    m = re.search(r"virsh -c qemu:///system domjobinfo (instance-[0-9a-f]{8})", cmd)
    if m:   # can libvirt take a job on the domain (wi_ops before a migration); STATE["lock_stuck"]: held by a reconnect
        sid = next((x for x in SERVERS if instance_name(x) == m.group(1)), None)
        if sid in (STATE.get("lock_stuck") or []):
            return 1, (f"error: Timed out during operation: cannot acquire state change lock (held by monitor=init-{m.group(1)})")
        return 0, "Job type:         None"
    m = re.search(r"virsh -c qemu:///system domstate (instance-[0-9a-f]{8})", cmd)
    if m:   # where the domain of an instance runs (wi_ops checks it before a reset to ACTIVE)
        sid = next((x for x in SERVERS if instance_name(x) == m.group(1)), None)
        host = (STATE.get("domain_on") or {}).get(sid) or (SERVERS[sid][3] if sid else "")
        if sid and host and name.endswith("-" + str(int(host.split("-")[-1]))):
            return 0, "shut off" if SERVERS[sid][1] == "SHUTOFF" else "running"
        return 1, f"error: failed to get domain '{m.group(1)}'"
    if "ovn_controller ovn-sbctl" in cmd or "ovn-controller --version" in cmd:
        return ovn_answer(name, cmd)
    if "tcpdump -nnei tap" in cmd:   # mdt01 sends frames with the MAC of the outside host (what OVN learns on its port)
        tap = re.search(r"tcpdump -nnei (tap\S+)", cmd).group(1)
        if tap == f"tap{MDT[uid(1, '3d')][2][:11]}":
            return 0, (f"01:17:23.352183 {OUTSIDE_MAC} > ff:ff:ff:ff:ff:ff, ethertype ARP (0x0806), length 42: Request who-has 10.249.11.39 tell 10.249.11.27\n"
                       f"01:17:24.372186 {OUTSIDE_MAC} > fa:16:3e:35:1f:e7, ethertype IPv4 (0x0800), length 98: 10.249.11.27 > 10.249.11.40: ICMP echo request\n"
                       "2 packets captured")
        return 0, "0 packets captured"
    m = re.search(r"getcert resubmit -i ([A-Za-z0-9_.-]+)$", cmd)
    if m:   # the fix (wi_ops.py getcert-resubmit): certmonger takes the request again
        if not any(r[0] == m.group(1) for r in GETCERT.get(name) or []):
            return 1, f"No request found that matched arguments."
        STATE.setdefault("getcert", {})[f"{name}:{m.group(1)}"] = True
        if STATE_FILE:
            save_state()
        ca = next(r[2] for r in GETCERT[name] if r[0] == m.group(1))
        return 0, f'Resubmitting "{m.group(1)}" to "{ca}".'
    m = re.search(r"getcert list -i ([A-Za-z0-9_.-]+)$", cmd)
    if m:
        return getcert_list(name, m.group(1))
    if "getcert list" in cmd:
        return getcert_list(name)
    control = control_answer(name, cmd)
    if control is not None:
        return control
    if cmd == "hostname -s":
        return 0, name
    if "MemAvailable" in cmd and cmd.startswith("head -n 1 /proc/stat"):   # real CPU / RAM use (Live migrate destinations)
        cpu, ram = NODE_USAGE.get(name, (20, 50))
        total = 263731444
        return 0, (f"cpu  100000 0 0 900000 0 0 0 0 0 0\nMemTotal:       {total} kB\nMemAvailable:   {total * (100 - ram) // 100} kB\n"
                   f"cpu  {100000 + cpu * 10} 0 0 {900000 + (100 - cpu) * 10} 0 0 0 0 0 0")
    if cmd.startswith("rpm -q sos"):   # overcloud-novacompute-9 has no sos package
        return (0, "sos is not installed") if name.endswith("novacompute-9") else (0, "sos-4.5.6-1.el9.noarch")
    if cmd == "sudo -n pcs status --full":
        return 0, PCS_STATUS
    if cmd == "sudo -n pcs stonith history":
        return 0, ("reboot of overcloud-controller-2 failed: delegate=overcloud-controller-1, client=pacemaker-controld.2412, "
                   "origin=overcloud-controller-1, last-failed='2026-10-11 07:21:00 +07:00'\n"
                   "reboot of overcloud-controller-1 successful: delegate=overcloud-controller-0, client=pacemaker-controld.2410, "
                   "origin=overcloud-controller-0, completed='2026-10-09 22:10:00 +07:00'\n2 events found")
    if cmd == "sudo -n pcs property":
        return 0, "Cluster Properties:\n cluster-infrastructure: corosync\n cluster-name: tripleo_cluster\n stonith-enabled: true\n"
    if cmd == "sudo -n corosync-quorumtool -s":
        return 0, "Quorum information\n------------------\nNodes:            3\nQuorate:          Yes\n"
    if "rabbitmqctl cluster_status" in cmd:
        return 0, RABBIT
    if cmd.startswith("df -Pk "):
        root = "95% /" if name.endswith("controller-0") else "40% /"
        used = 95 if name.endswith("controller-0") else 40
        return 0, ("Filesystem 1024-blocks Used Available Capacity Mounted on\n"
                   f"/dev/vda2 104857600 {104857600 * used // 100} {104857600 * (100 - used) // 100} {root}\n"
                   "/dev/vda3 52428800 20971520 31457280 40% /var/lib/mysql")
    if cmd.startswith("df -Pi "):
        return 0, "Filesystem Inodes IUsed IFree IUse% Mounted on\n/dev/vda2 6553600 655360 5898240 10% /\n/dev/vda3 3276800 1000 3275800 1% /var/lib/mysql"
    if cmd == "free -k":
        return 0, ("               total        used        free      shared  buff/cache   available\n"
                   "Mem:       263731444   180000000    20000000     1000000    63731444    70000000\nSwap:              0           0           0")
    if cmd == "nproc; cat /proc/loadavg":
        return 0, "48\n12.10 11.80 11.50 9/2210 512345"
    if cmd.startswith("head -n 1 /proc/stat"):
        return 0, "cpu  100000 0 50000 800000 1000 0 0 0 0 0\ncpu  100500 0 50300 801500 1010 0 0 0 0 0"
    if cmd.startswith("systemctl --failed"):
        return 0, "tripleo_nova_api_cron.service loaded failed failed nova_api_cron container" if name.endswith("controller-1") else ""
    if cmd.startswith("ps -eo pid,user,pmem"):
        return 0, "    PID USER     %MEM %CPU   RSS COMMAND\n  4242 42439    18.1 25.0 47800000 beam.smp\n  5100 42434     9.0  4.0 23700000 mysqld"
    if cmd.startswith("ps -eo pid,user,pcpu"):
        return 0, "    PID USER     %CPU %MEM COMMAND\n  4242 42439    25.0 18.1 beam.smp"
    if "podman ps -a --format" in cmd:
        rows = ["nova_api|Up 12 days ago (healthy)", "nova_api_db_sync|Exited (0) 12 days ago", "keystone|Up 12 days ago (healthy)",
                "rabbitmq-bundle-podman-1|Up 3 hours ago", "nova_metadata|Up 12 days ago (healthy)", "glance_api_init|Exited (1) 12 days ago"]
        if name.endswith("controller-1"):
            rows += ["neutron_api|Up 2 hours ago (unhealthy)", "heat_engine|Exited (1) 1 hour ago"]
        return 0, "\n".join(rows)
    if cmd == "chronyc tracking":
        off = "1.204511" if name.endswith("controller-2") else "0.000012"
        return 0, f"Reference ID    : C0A81801 (ntp.example)\nSystem time     : {off} seconds slow of NTP time\nLeap status     : Normal\n"
    if "/var/log/containers/" in cmd or "journalctl" in cmd:
        lines = []
        ctrl = "controller" in name
        if "nova-api.log" in cmd:   # the nova log read (controllers: conductor / scheduler; computes: nova-compute)
            if name.endswith("controller-0"):
                lines += [f"/var/log/containers/nova/nova-conductor.log: 2026-10-11 07:42:01.112 21 ERROR oslo.messaging._drivers.impl_rabbit "
                          "[-] Connection failed: [Errno 111] ECONNREFUSED (retrying in 2.0 seconds): AMQP server on "
                          "overcloud-controller-1.internalapi.localdomain:5672 is unreachable",
                          f"/var/log/containers/nova/nova-conductor.log: 2026-10-11 07:43:10.001 21 ERROR nova.conductor "
                          f"[{REQ} admin admin] Failed to schedule instances: No valid host was found."]
            elif not ctrl:
                lines += [f"/var/log/containers/nova/nova-compute.log: 2026-10-11 07:43:05.555 7 ERROR nova.compute.manager "
                          f"[{REQ} 6d1 c0f] [instance: {uid(1, '5e')}] Instance failed to spawn: "
                          "nova.exception.VirtualInterfaceCreateException: Virtual Interface creation failed"]
        if "server.log" in cmd and name.endswith("controller-1"):
            lines += ["/var/log/containers/neutron/server.log: 2026-10-11 07:43:02.010 30 ERROR neutron.plugins.ml2.managers "
                      f"[{REQ} - - - - -] Failed to bind port 99999999-0000-4000-8000-000000000001 on host overcloud-novacompute-7 "
                      "for vnic_type normal using segments [...]",
                      "/var/log/containers/neutron/server.log: 2026-10-11 07:50:00.000 30 ERROR neutron.db.agents_db [-] "
                      "Message rabbit://guest:S3cretRabbit@overcloud-controller-1:5672 failed"]
        if "journalctl -u pacemaker" in cmd and name.endswith("controller-0"):
            lines += ["2026-10-11T07:20:20+0700 overcloud-controller-0 pacemaker-fenced[2401]: error: Operation 'reboot' "
                      "targeting overcloud-controller-2 by overcloud-controller-1: Unable to obtain correct plug status or plug is not available"]
        if "journalctl -k" in cmd and name.endswith("controller-1"):
            lines += ["2026-10-11T06:10:00+0700 overcloud-controller-1 kernel: Out of memory: Killed process 4242 (beam.smp) "
                      "total-vm:12000000kB"]
        ids = re.findall(r"-e (\S+)", cmd)
        if ids:
            lines = [l for l in lines if any(i in l for i in ids)]
        return 0, "\n".join(lines)
    return 127, f"fake overcloud node: command not emulated: {cmd}"


def overcloud_answer(cmd):
    """An overcloud read as the director runs it: ssh <options> <user>@<ip> '<command>'."""
    args = shlex.split(cmd)
    target = next((a for a in args if "@" in a and not a.startswith("-")), "")
    user, _, ip = target.partition("@")
    name = next((n for n, a in UC_NODES if a == ip), None)
    if user not in ("heat-admin", "tripleo-admin") or name is None:
        return 255, f"ssh: connect to host {ip} port 22: Connection refused"
    return node_answer(name, args[-1])


# ---------------- changes made by fixes (FAKE_CLOUD_STATE) ----------------
STATE_FILE = os.environ.get("FAKE_CLOUD_STATE", "")


def load_state():
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


ORIGINAL = copy.deepcopy((VOLUMES, SNAPSHOTS, POOLS, ATTACHED, SERVERS, QUOTA, SG_RULES))


def apply_state(st):
    """The fixed cloud above, changed as the fixes so far left it (always from the original data)."""
    global VOLUMES, SNAPSHOTS, POOLS
    VOLUMES, SNAPSHOTS, POOLS = copy.deepcopy(ORIGINAL[:3])
    for target, orig in zip((ATTACHED, SERVERS, QUOTA, SG_RULES), copy.deepcopy(ORIGINAL[3:])):
        target.clear()
        target.update(orig)
    vols = {v[0]: list(v) for v in VOLUMES}
    for vid, ch in (st.get("volumes") or {}).items():
        if vid in vols:
            if ch.get("deleted"):
                del vols[vid]
                continue
            for k, i in (("status", 2), ("type", 4), ("pool", 5), ("migstat", 7)):
                if k in ch:
                    vols[vid][i] = ch[k]
            vols[vid][8] = 1
    VOLUMES = [tuple(v) for v in vols.values()]
    SNAPSHOTS = [x for x in SNAPSHOTS if x[0] not in set(st.get("snapshots_deleted") or [])]
    POOLS = [(n, t, a, f + float((st.get("pool_free") or {}).get(n, 0))) for n, t, a, f in POOLS]
    for vid in st.get("detached") or []:
        ATTACHED.pop(vid, None)
    for sid, ch in (st.get("servers") or {}).items():
        if sid in SERVERS:
            if ch.get("deleted"):
                del SERVERS[sid]
                continue
            s = list(SERVERS[sid])
            for k, i in (("status", 1), ("power", 2), ("host", 3)):
                if k in ch:
                    s[i] = ch[k]
            SERVERS[sid] = tuple(s)
    for pid, q in (st.get("quota") or {}).items():
        QUOTA.setdefault(pid, {}).update(q)
    for sg, rules in (st.get("sg_rules") or {}).items():
        if sg in SG_RULES:
            SG_RULES[sg] = (SG_RULES[sg][0], SG_RULES[sg][1] + [tuple(r) for r in rules])
    for v in st.get("new_volumes") or []:   # temporary copies of failed migrations
        if not (st.get("volumes") or {}).get(v[0], {}).get("deleted"):
            VOLUMES.append(tuple(v))


STATE = load_state()
apply_state(STATE)


def save_state():
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(STATE, f)


def instance_name(sid):
    return f"instance-{int(sid[-12:], 16):08x}"


def server_task(sid):
    return ((STATE.get("servers") or {}).get(sid) or {}).get("task") or None


def migrations_of(sid):
    return [m for m in STATE.get("migrations") or [] if m["sid"] == sid]


def add_migration(sid, kind, source, dest, status):
    mig = STATE.setdefault("migrations", [])
    m = {"id": len(mig) + 1, "sid": sid, "type": kind, "source": source, "dest": dest, "status": status, "created": ago(0)}
    mig.append(m)
    return m


def add_event(sid, action, error=""):
    req = f"req-{uid(len(STATE.get('events') or []) + 7, 'e0')}"
    STATE.setdefault("events", []).append({"sid": sid, "req": req, "action": action, "start": ago(0), "error": error})
    return req


def tick_server(sid):
    """A migration that is running moves on each time the instance is read (the fake has no clock)."""
    run = (STATE.get("running") or {}).get(sid)
    if not run:
        return
    run["polls"] -= 1
    if run["polls"] > 0:
        save_state()
        return
    ch = STATE.setdefault("servers", {}).setdefault(sid, {})
    m = next(x for x in STATE["migrations"] if x["id"] == run["mid"])
    if run["kind"] == "cold":
        ch.update(status="VERIFY_RESIZE", host=run["target"], task=None)
        m["status"] = "finished"
    elif sid == LIVE_ERROR:   # as on DCB: the libvirt migration itself fails, Nova records no fault, only nova-compute says why
        ch.update(status="ERROR", task=None, fault="")
        STATE.setdefault("domain_on", {})[sid] = SERVERS[sid][3]
        m["status"] = "error"
        add_event(sid, "live-migration")
        at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.111") + " 7 ERROR nova.compute.manager"
        p, lock = f"[instance: {sid}]", f"Timed out during operation: cannot acquire state change lock (held by monitor=init-{instance_name(sid)})"
        STATE.setdefault("nova_log", {})[SERVERS[sid][3]] = [   # its own thread: no request ID ([-])
            f"2026-10-20 03:00:00.000 7 ERROR nova.compute.manager [req-{uid(1, 'e1')} - - - - -] {p} an old error: "
            "nova.exception.OldError: not this migration",
            f"{at} [-] {p} Live migration failed.: libvirt.libvirtError: {lock}",
            f"{at} {p} Traceback (most recent call last):",
            f'{at} {p}   File "/usr/lib/python3.9/site-packages/nova/compute/manager.py", line 8560, in _do_live_migration',
            f"{at} {p}     stats = self._domain.jobStats()",
            f"{at} {p} libvirt.libvirtError: {lock}",
            f"{at} {p} "]
    else:
        ch.update(status="ACTIVE", host=run["target"], task=None)
        m["status"] = "completed"
    del STATE["running"][sid]
    save_state()
    apply_state(STATE)


def value_of(kind, oid, field):
    """What wi_value prints on the director: openstack volume|server show -f value -c <field>, attachments, snapshots."""
    if kind == "volume":
        v = next((x for x in VOLUMES if x[0] == oid), None)
        if not v:
            return "missing"
        if field == "snapshots":
            return str(sum(1 for x in SNAPSHOTS if x[3] == oid))
        if field == "attachments":
            return "attached" if oid in ATTACHED else "none"
        return {"status": v[2], "migration_status": v[7] or "None"}.get(field, "")
    srv = SERVERS.get(oid)
    return srv[1] if srv and field == "status" else "missing"


def change(cmd):
    """(exit code, output) of one change a fix may make, or None when cmd is not a change."""
    args = shlex.split(cmd)
    text = " ".join(args)
    vol = lambda vid: next((v for v in VOLUMES if v[0] == vid), None)
    if text.startswith("sleep "):
        return 0, ""
    if text.startswith(("wi_require ", "wi_wait ")):   # the checks of a fix (wi_analysis.OS_FUNCTIONS)
        kind, oid, field, want = args[1:5]
        have = value_of(kind, oid, field)
        if have in want.split(","):
            return 0, f"{kind} {oid} {field}: {have}" + (" (as expected)" if args[0] == "wi_require" else "")
        return (3, f"{kind} {oid} {field} is now '{have}', not {want}: nothing was changed") if args[0] == "wi_require" else \
            (4, f"{kind} {oid} {field} is still '{have}' after {args[5]} s (expected {want})")
    if text.startswith("wi_ops "):   # an operation of wi_analysis/wi_ops.py, run here with this fake cloud
        return run_ops(args[1:])
    mdt = mdt_change(text, args)
    if mdt is not None:
        return mdt
    # The compute API version flag does not change what the fake does.
    text = re.sub(r"^(openstack|nova) --os-compute-api-version [0-9.]+ ", r"\1 ", text)
    args = shlex.split(text)
    writes = ("cinder migrate", "cinder retype", "cinder reset-state", "openstack volume snapshot delete",
              "cinder delete", "openstack quota set", "openstack server start", "openstack server stop", "openstack server reboot",
              "openstack server remove volume", "openstack server delete", "openstack server migrate",
              "openstack security group rule create", "nova live-migration", "nova migrate", "openstack server resize",
              "openstack server set --state", "openstack compute service set", "openstack image delete",
              "openstack server migration abort", "nova live-migration-abort")
    if not text.startswith(writes) or text.startswith(("nova live-migration-force", "openstack server migration force")):
        return None
    if not STATE_FILE:
        return 1, "fake_cloud: changes need FAKE_CLOUD_STATE"
    vols, servers = STATE.setdefault("volumes", {}), STATE.setdefault("servers", {})
    if text.startswith("cinder migrate"):
        v, host = vol(args[2]), args[3]
        pool = next((i for i, p in enumerate(POOLS) if host.endswith("#" + p[0])), None)
        if not v or pool is None:
            return 1, "No volume or pool"
        if v[0] == VOLUME_MIGRATE_FAILS and not STATE.get("failed_once"):   # the copy fails: the temporary copy stays
            STATE["failed_once"] = True
            vols.setdefault(v[0], {})["migstat"] = "error"
            STATE.setdefault("new_volumes", []).append([uid(99, "1"), v[1], "error", v[3], v[4], pool, v[6], f"target:{v[0]}", 1])
            save_state()
            apply_state(STATE)
            return 0, ""
        free = STATE.setdefault("pool_free", {})
        free[POOLS[v[5]][0]] = free.get(POOLS[v[5]][0], 0) + v[3]
        free[POOLS[pool][0]] = free.get(POOLS[pool][0], 0) - v[3]
        vols.setdefault(v[0], {}).update(pool=pool, migstat="success")
    elif text.startswith("cinder retype"):
        if not vol(args[-2]):
            return 1, "No volume"
        if any(x[3] == args[-2] for x in SNAPSHOTS):   # a retype that needs a migration refuses a volume with snapshots
            return 1, "ERROR: Invalid volume: Volume must not have snapshots. (HTTP 400)"
        vols.setdefault(args[-2], {}).update(type=args[-1], migstat="success")
    elif text.startswith("cinder reset-state"):
        if not vol(args[-1]):
            return 1, f"ERROR: No volume with a name or ID of '{args[-1]}' exists."
        ch = vols.setdefault(args[-1], {})
        ch["status"] = args[args.index("--state") + 1]
        if "--reset-migration-status" in args:
            ch["migstat"] = ""
        if "--attach-status" in args and args[args.index("--attach-status") + 1] == "detached":
            STATE.setdefault("detached", []).append(args[-1])
    elif text.startswith("openstack volume snapshot delete"):
        if not any(x[0] == args[-1] for x in SNAPSHOTS):
            return 1, f"Failed to delete snapshot with name or ID '{args[-1]}'"
        STATE.setdefault("snapshots_deleted", []).append(args[-1])
    elif text.startswith("cinder delete"):
        if not vol(args[-1]):
            return 1, "No volume"
        vols.setdefault(args[-1], {})["deleted"] = True
        save_state()
        apply_state(STATE)
        return 0, f"Request to delete volume {args[-1]} has been accepted."
    elif text.startswith("openstack quota set"):
        pid = args[-1]
        q = STATE.setdefault("quota", {}).setdefault(pid, {})
        for opt, val in zip(args[3:-1:2], args[4:-1:2]):
            q[opt.lstrip("-")] = int(val)
    elif text.startswith(("openstack server start", "openstack server stop", "openstack server reboot")):
        if args[-1] not in SERVERS:
            return 1, "No server"
        on = args[2] != "stop"
        servers.setdefault(args[-1], {}).update(status="ACTIVE" if on else "SHUTOFF", power="Running" if on else "Shutdown")
    elif text.startswith("openstack server remove volume"):
        sid, vid = args[4], args[5]
        if ATTACHED.get(vid, ("",))[0] != sid:
            return 1, f"Volume {vid} is not attached to server {sid}"
        STATE.setdefault("detached", []).append(vid)
        vols.setdefault(vid, {})["status"] = "available"
    elif text.startswith("openstack server delete"):
        if args[-1] not in SERVERS:
            return 1, "No server"
        servers.setdefault(args[-1], {})["deleted"] = True
    elif text.startswith(("openstack server migrate", "nova live-migration", "nova migrate")):
        live = "--live-migration" in args or text.startswith("nova live-migration")
        sid = args[-1] if text.startswith("openstack") or "nova migrate" in text else args[2]
        host = args[args.index("--host") + 1] if "--host" in args else (args[3] if text.startswith("nova live-migration") and len(args) > 3 else None)
        if sid not in SERVERS:
            return 1, f"No server with a name or ID of '{sid}' exists."
        if "--os-compute-api-version" not in cmd and not text.startswith("nova"):
            servers.setdefault(sid, {})["host"] = host or "compute-09"   # a plain fix (Instance network): moved at once
            save_state()
            apply_state(STATE)
            return 0, ""
        source = SERVERS[sid][3]
        if host and host not in [h for b, h, st, state, _m in COMPUTE_SERVICES if b == "nova-compute" and st == "enabled" and state == "up"]:
            return 1, f"Compute host {host} could not be found. (HTTP 400)"
        if live and sid == LIVE_REFUSED and not host:   # the scheduler's choice refuses it; nothing moves
            add_migration(sid, "live-migration", source, "compute-08", "error")
            add_event(sid, "live-migration", "Traceback (most recent call last):\n  File \"/usr/lib/python3.9/site-packages/nova/conductor/"
                      "tasks/live_migrate.py\", line 92, in _execute\nnova.exception.MigrationPreCheckError: Migration pre-check "
                      "error: CPU doesn't have compatibility.")
            save_state()
            return 0, ""
        target = host or "compute-09"
        m = add_migration(sid, "live-migration" if live else "migration", source, target, "running" if live else "migrating")
        servers.setdefault(sid, {}).update(status="MIGRATING" if live else "RESIZE", task="migrating" if live else "resize_migrating")
        STATE.setdefault("running", {})[sid] = {"polls": 2, "target": target, "mid": m["id"], "kind": "live" if live else "cold"}
    elif text.startswith("openstack server resize"):   # resize confirm / resize --confirm of a cold migration
        sid = args[-1]
        if SERVERS.get(sid, ("",) * 2)[1] != "VERIFY_RESIZE":
            return 1, f"Cannot 'confirmResize' instance {sid} while it is in vm_state {SERVERS.get(sid, ('', '?'))[1].lower()} (HTTP 409)"
        servers.setdefault(sid, {}).update(status="SHUTOFF", task=None)
    elif text.startswith("openstack server set --state"):
        sid = args[-1]
        servers.setdefault(sid, {}).update(status=args[4].upper(), task=None, fault="")
    elif text.startswith(("openstack server migration abort", "nova live-migration-abort")):
        sid = args[-2]
        add_event(sid, "live_migration_cancel")
        STATE.get("running", {}).pop(sid, None)
        for m in migrations_of(sid):
            if m["status"] == "running":
                m["status"] = "cancelled"
        servers.setdefault(sid, {}).update(status="ACTIVE", task=None)
    elif text.startswith("openstack compute service set"):
        STATE.setdefault("svc", {})[args[-2]] = "disabled" if "--disable" in args else "enabled"
    elif text.startswith("openstack image delete"):
        if not any(i[0] == args[-1] for i in IMAGES) or args[-1] in (STATE.get("images_deleted") or []):
            return 1, f"Failed to delete image with name or ID '{args[-1]}': No Image found"
        STATE.setdefault("images_deleted", []).append(args[-1])
    elif text.startswith("openstack security group rule create"):
        sg = args[-1]
        if sg not in SG_RULES:
            return 1, "No security group"
        proto = args[args.index("--protocol") + 1]
        rng = args[args.index("--dst-port") + 1] if "--dst-port" in args else ""
        rng = f"{rng}:{rng}" if rng and ":" not in rng else rng
        STATE.setdefault("sg_rules", {}).setdefault(sg, []).append(["ingress", proto, rng, args[args.index("--remote-ip") + 1]])
    save_state()
    apply_state(STATE)
    return 0, ""


def run_ops(argv):
    """An operation of wi_ops.py with this fake cloud as its director: every command it runs is answered here, its sleeps
    take no time."""
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules", "wi", "wi_analysis"))
    import wi_ops
    lines, now = [], [NOW.timestamp()]

    def runner(cmd_argv, timeout):
        command = " ".join(shlex.quote(a) for a in cmd_argv)
        return change(command) or answer(command)

    def sleep(seconds):
        now[0] += seconds
    rc = wi_ops.main(argv, wi_ops.Director(runner=runner, clock=lambda: now[0], sleep=sleep, write=lines.append))
    return rc, "\n".join(lines)


def table(headers, rows):
    widths = [max(len(str(h)), *(len(str(r[i])) for r in rows)) if rows else len(str(h)) for i, h in enumerate(headers)]
    line = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    out = [line, "| " + " | ".join(str(h).ljust(w) for h, w in zip(headers, widths)) + " |", line]
    out += ["| " + " | ".join(str(c).ljust(w) for c, w in zip(r, widths)) + " |" for r in rows]
    return "\n".join(out + [line])


def project_id(value):
    for pid, name in PROJECTS.items():
        if value in (pid, name):
            return pid
    return None


UNDERCLOUD = False   # the script sourced stackrc (main): openstack server list lists the overcloud nodes


def mdt_port_state(pid):
    """Port security of a port of the FDB scenario: off, until the port security fix turned it on."""
    return (STATE.get("port_sec") or {}).get(pid) or {"enabled": False, "sg": [], "aap": []}


def mdt_change(text, args):
    """The changes of the port security fix (wi_ops.py port-security) on the ports of the FDB scenario (None: not one)."""
    if text.startswith("openstack security group create port-security-allow-all"):
        if not STATE_FILE:
            return 1, "fake_cloud: changes need FAKE_CLOUD_STATE"
        project = args[args.index("--project") + 1]
        STATE["ps_sg"] = {"id": PS_SG, "project": project, "rules": []}
        save_state()
        return 0, json.dumps({"id": PS_SG, "name": "port-security-allow-all", "project_id": project})
    if text.startswith("openstack security group rule create") and args[-1] == PS_SG and "ps_sg" in STATE:
        rule = [args[5].lstrip("-"), args[args.index("--ethertype") + 1], args[args.index("--remote-ip") + 1]]
        if rule in STATE["ps_sg"]["rules"]:
            return 1, f"Security group rule already exists. Rule id is {uid(len(STATE['ps_sg']['rules']), '5f')}. (HTTP 409)"
        STATE["ps_sg"]["rules"].append(rule)
        save_state()
        return 0, ""
    if text.startswith("openstack port set") and any(v[2] == args[-1] for v in MDT.values()):
        st = dict(mdt_port_state(args[-1]))
        if "--enable-port-security" in args:
            st["enabled"] = True
            st["sg"] = [args[args.index("--security-group") + 1]]
        st["aap"] = st["aap"] + [a.split("=", 1)[1] for i, a in enumerate(args) if i and args[i - 1] == "--allowed-address"]
        STATE.setdefault("port_sec", {})[args[-1]] = st
        save_state()
        return 0, ""
    return None


def mdt_answer(text, args):
    """The commands about the instances of the WI "FDB Learning Issue" (None: not about them)."""
    if text.startswith("openstack server show") and args[3] in MDT:
        name, host, pid, mac, ip, _k = MDT[args[3]]
        return 0, json.dumps({"id": args[3], "name": name, "status": "ACTIVE", "OS-EXT-STS:power_state": "Running",
                              "OS-EXT-SRV-ATTR:host": host, "project_id": CUSTOMER,
                              "OS-EXT-SRV-ATTR:hypervisor_hostname": f"overcloud-novacompute-{int(host.split('-')[1])}.localdomain",
                              "addresses": {"DataGrid-Network": [ip]}})
    if text.startswith("openstack port list") and "--server" in args and args[args.index("--server") + 1] in MDT:
        name, _h, pid, mac, ip, _k = MDT[args[args.index("--server") + 1]]
        return 0, json.dumps([{"ID": pid, "Name": "", "MAC Address": mac, "Status": "ACTIVE",
                               "Fixed IP Addresses": [{"subnet_id": uid(2, "5b"), "ip_address": ip}]}])
    if text.startswith("openstack port show"):
        m = next((v for v in MDT.values() if v[2] == args[3]), None)
        if m:
            st = mdt_port_state(m[2])
            return 0, json.dumps({"id": m[2], "name": "", "mac_address": m[3], "network_id": NET_DG, "device_id": next(k for k, v in MDT.items() if v is m),
                                  "fixed_ips": [{"subnet_id": uid(2, "5b"), "ip_address": m[4]}], "port_security_enabled": st["enabled"],
                                  "security_group_ids": st["sg"], "project_id": CUSTOMER,
                                  "allowed_address_pairs": [{"ip_address": a, "mac_address": m[3]} for a in st["aap"]],
                                  "binding_host_id": f"overcloud-novacompute-{int(m[1].split('-')[1])}.localdomain"})
    if text.startswith("openstack network show") and args[3] == NET_DG:
        return 0, json.dumps({"id": NET_DG, "name": "DataGrid-Network", "provider:network_type": "vlan",
                              "provider:physical_network": "datacentre", "provider:segmentation_id": 1670, "mtu": 1500})
    if text.startswith("openstack port list") and "--fixed-ip ip-address=10.249.11.27" in text:
        return 0, "[]"   # the destination is outside OpenStack
    if text.startswith("openstack port list") and "--network" in args and args[args.index("--network") + 1] == NET_DG:
        rows = [{"ID": v[2], "Name": "", "MAC Address": v[3], "Status": "ACTIVE", "Device Owner": "compute:nova",
                 "Fixed IP Addresses": [{"subnet_id": uid(2, "5b"), "ip_address": v[4]}]} for v in MDT.values()]
        rows += [{"ID": MDT_VIP[0], "Name": MDT_VIP[1], "MAC Address": MDT_VIP[2], "Status": "DOWN", "Device Owner": "",
                  "Fixed IP Addresses": [{"subnet_id": uid(2, "5b"), "ip_address": MDT_VIP[3]}]},
                 {"ID": uid(31, "7a"), "Name": "", "MAC Address": "fa:16:3e:77:00:02", "Status": "ACTIVE", "Device Owner": "network:dhcp",
                  "Fixed IP Addresses": [{"subnet_id": uid(2, "5b"), "ip_address": "10.249.11.2"}]}]
        return 0, json.dumps(rows)
    if text.startswith("openstack security group list") and "--project" in args:
        sg = STATE.get("ps_sg")
        return 0, json.dumps([{"ID": sg["id"], "Name": "port-security-allow-all", "Project": sg["project"]}]
                             if sg and sg["project"] == args[args.index("--project") + 1] else [])
    return None


def ovsdb_json(headings, rows):
    """ovn-sbctl --format=json: uuids as ["uuid", ..], several values as ["set", [..]], maps as ["map", [[k, v]]]."""
    def cell(v):
        if isinstance(v, dict):
            return ["map", [[k, x] for k, x in v.items()]]
        if isinstance(v, list):
            return v[0] if len(v) == 1 else ["set", v]
        if isinstance(v, str) and re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-", v):
            return ["uuid", v]
        return v
    return json.dumps({"headings": headings, "data": [[cell(x) for x in r] for r in rows]})


def fdb_now():
    return [e for e in FDB if e[0] not in set(STATE.get("fdb_gone") or [])]


# ---------------- control plane beyond pcs status: OVN RAFT (a removed controller is still a member of the SB
# cluster, the SB file is 700 MB, MAC_Binding 152340 rows), RabbitMQ (notification queues without a consumer, FD 93% on
# controller-0) and Galera (controller-2 in flow control, its connections at 95%)
RAFT_SID = {"overcloud-controller-0": "a1b2", "overcloud-controller-1": "c3d4", "overcloud-controller-2": "e5f6"}


def raft_status(name, db):
    if name not in RAFT_SID:
        return 125, "Error: no container with name or ID \"ovn_cluster_south_db_server\" found: no such container"
    leader = "overcloud-controller-0" if db == "Northbound" else "overcloud-controller-1"
    members = list(RAFT_SID.values()) + ([] if db == "Northbound" else ["7f80"])
    lines = [f"{s} ({s} at ssl:172.28.1.{10 + i}:{6643 if db == 'Northbound' else 6644})" + (" (self)" if s == RAFT_SID[name] else "")
             for i, s in enumerate(members)]
    return 0, (f"{RAFT_SID[name]}\nName: OVN_{db}\nCluster ID: 9d0e (9d0e1f20-0000-4000-8000-000000000001)\n"
               f"Server ID: {RAFT_SID[name]} ({RAFT_SID[name]}0000-0000-4000-8000-000000000001)\nAddress: ssl:172.28.1.10:6644\n"
               "Status: cluster member\n" + f"Role: {'leader' if name == leader else 'follower'}\nTerm: {3 if db == 'Northbound' else 7}\n"
               f"Leader: {'self' if name == leader else RAFT_SID[leader]}\nVote: {RAFT_SID[leader]}\n\nLog: [2, 120]\n"
               "Servers:\n" + "\n".join(f"    {l}" for l in lines))


# certmonger (check certmonger certificates): on the director the undercloud certificate of its local CA expires in 12
# days; on overcloud-controller-0 IdM is unreachable for the internal API certificate (5 days left); on
# overcloud-controller-1 a certificate expires in 20 days; the computes are healthy.
GETCERT = {
    "director": [("20240101000001", "MONITORING", "local", "CN=director.ctlplane.localdomain", 12, "/etc/pki/tls/certs/undercloud-front.crt", "")],
    "overcloud-controller-0": [
        ("20240101000010", "CA_UNREACHABLE", "IPA", "CN=overcloud-controller-0.internalapi.prime.local,O=PRIME.LOCAL", 5,
         "/etc/pki/tls/certs/haproxy/overcloud-haproxy-internal_api.crt", "Server at https://idm-01.prime.local/ipa/xml failed request"),
        ("20240101000011", "MONITORING", "IPA", "CN=overcloud-controller-0.internalapi.prime.local,O=PRIME.LOCAL", 400,
         "/etc/pki/tls/certs/rabbitmq.crt", "")],
    "overcloud-controller-1": [
        ("20240101000020", "MONITORING", "IPA", "CN=overcloud-controller-1.internalapi.prime.local,O=PRIME.LOCAL", 20,
         "/etc/pki/tls/certs/haproxy/overcloud-haproxy-internal_api.crt", ""),
        ("20240101000021", "MONITORING", "IPA", "CN=overcloud-controller-1.internalapi.prime.local,O=PRIME.LOCAL", 400,
         "/etc/pki/tls/certs/rabbitmq.crt", "")],
}


def getcert_list(name, only=None):
    """`getcert list` of a machine, or of one request (`getcert list -i <id>`), every field as certmonger prints them.
    A request the fix resubmitted (FAKE_CLOUD_STATE "getcert") is MONITORING with a new certificate for two years, unless
    its CA is unreachable (it stays CA_UNREACHABLE)."""
    reqs = GETCERT.get(name) or [(f"2024010100{90 + i}", "MONITORING", "IPA", f"CN={name}.internalapi.prime.local,O=PRIME.LOCAL", 400,
                                  f, "") for i, f in enumerate(["/etc/pki/tls/certs/libvirt-vnc-server-cert.pem", "/etc/pki/tls/certs/ovn_controller.crt"])]
    renewed = STATE.get("getcert") or {}
    reqs = [(rid, st, ca, sub, 730, cert, "") if renewed.get(f"{name}:{rid}") and st != "CA_UNREACHABLE" else (rid, st, ca, sub, days, cert, err)
            for rid, st, ca, sub, days, cert, err in reqs]
    lines = [f"Number of certificates and requests being tracked: {len(reqs)}."]
    for rid, status, ca, subject, days, cert, err in reqs:
        if only is not None and rid != only:
            continue
        expires = (NOW + datetime.timedelta(days=days, hours=2)).strftime("%Y-%m-%d %H:%M:%S UTC")
        lines += [f"Request ID '{rid}':", f"\tstatus: {status}"] + ([f"\tca-error: {err}"] if err else []) + [
            "\tstuck: no", f"\tkey pair storage: type=FILE,location='{cert.replace('certs', 'private').replace('.crt', '.key')}'",
            f"\tcertificate: type=FILE,location='{cert}'", f"\tCA: {ca}", "\tissuer: CN=Certificate Authority,O=PRIME.LOCAL",
            f"\tsubject: {subject}", f"\tissued: {(NOW - datetime.timedelta(days=365)).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"\texpires: {expires}", f"\tdns: {subject.split(',')[0][3:]}", "\tkey usage: digitalSignature,keyEncipherment",
            "\teku: id-kp-serverAuth,id-kp-clientAuth", "\tpre-save command: ", "\tpost-save command: /usr/bin/certmonger-haproxy-refresh.sh",
            "\ttrack: yes", "\tauto-renew: yes"]
    return 0, "\n".join(lines)


def control_answer(name, cmd):
    """The reads of the checks OVN database cluster, RabbitMQ queues and Galera replication (None: not one)."""
    ctl = name.startswith("overcloud-controller")
    if "head -c 13 /var/lib/openvswitch/ovn/ovnnb_db.db" in cmd:   # the header of a clustered (RAFT) database file
        return 0, "OVSDB CLUSTER\n" if ctl else "\n"
    if "cluster/status OVN_Northbound" in cmd:
        return raft_status(name, "Northbound")
    if "cluster/status OVN_Southbound" in cmd:
        return raft_status(name, "Southbound")
    if "ovn-appctl -t ovn-northd status" in cmd:
        return (0, "Status: active" if name.endswith("-0") else "Status: standby") if ctl else (1, "")
    if "grep -E 'ovn(nb|sb)_db.db$'" in cmd:
        return 0, ("-rw-r--r--. 1 root root 12582912 Oct 11 08:00 ovnnb_db.db\n"
                   "-rw-r--r--. 1 root root 734003200 Oct 11 08:00 ovnsb_db.db")
    if "rabbitmqctl -q list_queues name messages consumers" in cmd:
        return 0, "\n".join(f"{q}\t{m}\t{c}" for q, m, c in [
            ("notifications.info", 25000, 0), ("versioned_notifications.info", 1200, 0), ("conductor", 0, 3),
            ("q-agent-notifier-port-update_fanout_8d2c", 1500, 0), ("compute.compute-07", 0, 1), ("scheduler", 12, 3)])
    if "rabbitmqctl -q status" in cmd:
        used = 61000 if name.endswith("-0") else 2100
        return 0, (f"Status of node rabbit@{name}\nRuntime\n\nOS PID: 51\n\nFile Descriptors\n\nTotal: {used}, limit: 65439\n"
                   f"Sockets: {used - 40}, limit: 58893\n")
    # Controller reboot readiness: Elastic on controller-1 (as can happen), an older kernel running on controller-0
    if cmd.startswith("rpm -q elastic-agent"):
        if name.endswith("controller-1"):
            return 0, ("elastic-agent-7.17.4-1.x86_64\nunit elastic-agent enabled active\nunit ElasticEndpoint enabled active\n"
                       "opt-elastic present")
        return 0, "unit elastic-agent  \nunit ElasticEndpoint  inactive\nopt-elastic absent"
    if "--filter name=clustercheck" in cmd:
        ip = {"0": "172.28.1.10", "1": "172.28.1.11", "2": "172.28.1.12"}.get(name[-1], "172.28.1.13")
        return 0, f"container clustercheck|Up 3 days ago\nlisten {ip}:9200\nhttp 200"
    if cmd.startswith("uname -r;"):
        old = name.endswith("controller-0")
        return 0, ("5.14.0-284.30.1.el9_2.x86_64\n" if old else "5.14.0-284.199.1.el9_2.x86_64\n") \
            + "kernel-5.14.0-284.199.1.el9_2.x86_64                Tue 03 Nov 2026 10:12:00 AM WIB\n" \
            + f"needs-restarting {1 if old else 0}\nup since 2026-10-0{1 if old else 3} 10:00:00"
    if "mysql -B -N -e" in cmd:
        hot = name.endswith("-2")
        return 0, "\n".join(f"{k}\t{v}" for k, v in [
            ("Max_used_connections", 3900 if hot else 900), ("Threads_connected", 3100 if hot else 400),
            ("wsrep_cluster_size", 3), ("wsrep_cluster_status", "Primary"), ("wsrep_flow_control_paused", "0.250000" if hot else "0.000000"),
            ("wsrep_local_recv_queue_avg", "4.5" if hot else "0.0"), ("wsrep_local_state_comment", "Synced"), ("wsrep_ready", "ON"),
            ("max_connections", 4096)])
    return None


def ovn_answer(name, cmd):
    """ovn-sbctl in the ovn_controller container of a node (reads, and the destroy of the fix)."""
    if "list MAC_Binding | grep -c ." in cmd:
        return 0, "152340"
    if "--bare --columns=_uuid list SB_Global" in cmd:
        return 0, uid(1, "5b0")
    if f"find datapath_binding external_ids:name=neutron-{NET_DG}" in cmd:
        return 0, ovsdb_json(["_uuid", "tunnel_key", "external_ids"],
                             [[DP_DG, DP_KEY, {"name": f"neutron-{NET_DG}", "name2": "DataGrid-Network"}]])
    if "find datapath_binding" in cmd:
        return 0, ovsdb_json(["_uuid", "tunnel_key", "external_ids"], [])
    if f"find port_binding datapath={DP_DG}" in cmd:
        rows = [[uid(1, "b1"), f"provnet-{uid(1, 'b2')}", ["unknown"], [], 1, "localnet", [], [True]],
                [uid(2, "b1"), uid(9, "7a"), ["fa:16:3e:aa:00:01 10.249.11.1"], [], 2, "patch", [], [True]]]
        rows += [[uid(10 + v[5], "b1"), v[2], [f"{v[3]} {v[4]}"] + ([] if mdt_port_state(v[2])["enabled"] else ["unknown"]), [], v[5], "",
                  [uid(1, "c4")], [True]] for v in MDT.values()]
        return 0, ovsdb_json(["_uuid", "logical_port", "mac", "port_security", "tunnel_key", "type", "chassis", "up"], rows)
    m = re.search(rf"find port_binding logical_port=({'|'.join(v[2] for v in MDT.values())})", cmd)
    if m:   # the port security fix: is the address "unknown" gone
        v = next(x for x in MDT.values() if x[2] == m.group(1))
        return 0, ovsdb_json(["mac"], [[[f"{v[3]} {v[4]}"] + ([] if mdt_port_state(v[2])["enabled"] else ["unknown"])]])
    m = re.search(rf"--bare --columns=_uuid find fdb dp_key={DP_KEY} port_key=(\d+)", cmd)
    if m:   # the FDB entries recorded on one port
        return 0, "\n".join(u for u, _m, k in fdb_now() if k == int(m.group(1)))
    if f"find fdb dp_key={DP_KEY}" in cmd:
        return 0, ovsdb_json(["_uuid", "mac", "dp_key", "port_key"], [[u, m, DP_KEY, k] for u, m, k in fdb_now()])
    m = re.search(r"list fdb ([0-9a-f-]{36})", cmd)
    if m:   # wi_ops clear-fdb reads the entry again
        e = next((x for x in fdb_now() if x[0] == m.group(1)), None)
        if not e:
            return 1, f'ovn-sbctl: no row "{m.group(1)}" in table FDB'
        return 0, ovsdb_json(["mac", "dp_key", "port_key"], [[e[1], DP_KEY, e[2]]])
    m = re.search(r"destroy fdb ([0-9a-f-]{36})", cmd)
    if m:
        if "--no-leader-only" in cmd:
            return 1, "ovn-sbctl: transaction error: a write needs the leader"
        STATE.setdefault("fdb_gone", []).append(m.group(1))
        if STATE_FILE:
            save_state()
        return 0, ""
    if "--columns=dp_key list fdb" in cmd:
        return 0, f"{len(fdb_now()):7d} {DP_KEY}\n     81 300"
    if "--columns=logical_port,mac,type list port_binding" in cmd:
        return 0, "\n".join([f"provnet-{uid(1, 'b2')}|localnet"] + [f"{v[2]}|" for v in MDT.values()]
                            + [f"{uid(20, '7a')}|", f"{uid(21, '7a')}|"])
    if "ovn-controller --version" in cmd:
        return 0, "ovn-controller 23.09.4\nOpen vSwitch Library 3.2.3"
    return 127, f"fake ovn: not emulated: {cmd}"


def answer(cmd):
    """(exit code, output) of one read-only command."""
    if cmd.startswith("/api/"):   # NetApp (ONTAP REST)
        na = lm_ontap_answer(cmd)
        na = na if na is not None else vc_ontap_answer(cmd)
        return na if na is not None else (1, f"HTTP 404: no fake answer for {cmd}")
    if cmd.startswith("ssh "):
        return overcloud_answer(cmd)
    if cmd == "cat /etc/rhosp-release":
        return 0, "Red Hat OpenStack Platform release 16.2.4 (Train)"
    if cmd.startswith("sh -c ") and "tripleo-ansible-inventory.yaml" in cmd:   # wi_ops: the address of a compute
        return 0, "\n".join(["Compute:", "  hosts:"] + [f"    compute-{n.split('-')[-1].zfill(2)}:\n      ctlplane_ip: {a}\n"
                                                        f"      ansible_ssh_user: heat-admin"
                                                        for n, a in UC_NODES if "novacompute" in n]
                             + ["Controller:", "  hosts:"] + [f"    {n}:\n      ctlplane_ip: {a}\n      ansible_ssh_user: heat-admin"
                                                              for n, a in UC_NODES if "controller" in n])
    if cmd == "sudo -n getcert list":
        return getcert_list("director")
    if cmd == "metalsmith -f json list":
        return 1, "metalsmith: error: no instances (RHOSP 16.2 deploys the nodes with nova on the undercloud)"
    if UNDERCLOUD and cmd == "openstack server list -f json":
        return 0, json.dumps([{"ID": uid(i, "0c"), "Name": n, "Status": "ACTIVE", "Networks": f"ctlplane={a}", "Image": "overcloud-full",
                               "Flavor": "baremetal"} for i, (n, a) in enumerate(UC_NODES)])
    if cmd.startswith("date -u"):
        return 0, NOW.strftime("%Y-%m-%dT%H:%M:%SZ")
    if cmd.startswith("openstack "):
        mdt = mdt_answer(cmd, shlex.split(cmd))
        if mdt is not None:
            return mdt
        vc = vc_answer(shlex.split(cmd))
        if vc is not None:
            return vc
        cd = cd_answer(shlex.split(cmd))
        if cd is not None:
            return cd
    if cmd == "openstack --version":   # RHOSP 16.2 ships python-openstackclient 4.0.2 (FAKE_OSC_VERSION: 17.1)
        return 0, f"openstack {OSC_VERSION}"
    text = re.sub(r"^(openstack|nova|cinder) --os-(compute|volume)-api-version [0-9.]+ ", r"\1 ", " ".join(shlex.split(cmd)))
    args = shlex.split(text)
    if text.startswith(("openstack server migration list", "nova migration-list")):
        sid = args[args.index("--server") + 1] if "--server" in args else \
            args[args.index("--instance-uuid") + 1] if "--instance-uuid" in args else None   # None: the whole site
        rows = [(m["id"], m["source"], m["dest"], m["status"], m["sid"], m["type"], m["created"])
                for m in (migrations_of(sid) if sid else STATE.get("migrations") or [])]
        if text.startswith("nova"):
            return 0, table(["Id", "Source Compute", "Dest Compute", "Status", "Instance UUID", "Type", "Created At"], rows)
        return 0, json.dumps([{"Id": r[0], "Source Compute": r[1], "Dest Compute": r[2], "Status": r[3], "Server UUID": r[4],
                               "Type": r[5], "Created At": r[6]} for r in rows])
    if text.startswith(("openstack server migration show", "nova server-migration-show")):
        left = 734003200 if (STATE.get("running") or {}).get(args[-2]) else 0
        if text.startswith("nova"):
            return 0, table(["Property", "Value"], [("memory_remaining_bytes", left), ("status", "running")])
        return 0, json.dumps({"ID": int(args[-1]), "Status": "running", "Memory Remaining Bytes": left})
    if text.startswith("openstack server group list"):   # SERVER_GROUPS None: the API refuses
        if SERVER_GROUPS is None:
            return 1, "Policy doesn't allow os_compute_api:os-server-groups:index:all_projects to be performed. (HTTP 403)"
        return 0, json.dumps(SERVER_GROUPS)
    if text.startswith("openstack server event show"):
        ev = next((e for e in STATE.get("events") or [] if e["sid"] == args[4] and e["req"] == args[5]), None)
        if not ev:
            return 1, f"No event {args[5]}"
        return 0, json.dumps({"request_id": ev["req"], "action": ev["action"], "message": "Error" if ev["error"] else None,
                              "events": [{"event": "conductor_live_migrate_instance", "result": "Error" if ev["error"] else "Success",
                                          "traceback": ev["error"] or None}]})
    if text.startswith("openstack image list"):
        gone = set(STATE.get("images_deleted") or [])
        return 0, json.dumps([{"ID": i[0], "Name": i[1], "Disk Format": "qcow2", "Container Format": "bare", "Size": i[3],
                               "Checksum": None, "Status": i[2], "Visibility": i[4], "Protected": i[5], "Project": i[6], "Tags": []}
                              for i in IMAGES if i[0] not in gone])
    if text.startswith("openstack image show"):
        i = next((x for x in IMAGES if x[0] == args[3] and x[0] not in (STATE.get("images_deleted") or [])), None)
        if not i:
            return 1, f"No Image found for {args[3]}"
        return 0, json.dumps({"id": i[0], "name": i[1], "status": i[2], "size": i[3], "visibility": i[4], "protected": i[5],
                              "owner": i[6], "created_at": ago(i[7] * 1440).split(".")[0] + "Z", "properties": i[8]})
    if text.startswith("openstack flavor list"):   # --all --long: properties of every flavor (dict, as client 5.x)
        return 0, json.dumps([{"ID": v[0], "Name": n, "RAM": v[2], "Disk": v[3], "Ephemeral": 0, "VCPUs": v[1], "Is Public": True,
                               "Swap": 0, "RXTX Factor": 1.0, "Properties": v[4]} for n, v in FLAVORS.items()])
    if text.startswith("openstack flavor show"):
        f = next(((n, v) for n, v in FLAVORS.items() if args[3] in (n, v[0])), None)
        if not f:
            return 1, f"No flavor with a name or ID of '{args[3]}' exists."
        return 0, json.dumps({"id": f[1][0], "name": f[0], "vcpus": f[1][1], "ram": f[1][2], "disk": f[1][3], "properties": f[1][4]})
    if text.startswith("openstack volume snapshot show"):
        x = next((x for x in SNAPSHOTS if x[0] == args[4]), None)
        return (0, json.dumps({"id": x[0], "name": x[1], "status": "available", "size": x[2], "volume_id": x[3]})) if x else \
            (1, f"No snapshot with a name or ID of '{args[4]}' exists.")
    if text.startswith("cinder message-list"):
        return 0, table(["ID", "Resource Type", "Resource UUID", "Event ID", "User Message", "Created At"], [])
    if text.startswith("openstack hypervisor list"):
        hvs = [("compute-03", "down", 64, 60, 515000, 500000), ("compute-07", "up", 64, 230, 515000, 480000),
               ("compute-08", "up", 64, 40, 515000, 120000), ("compute-09", "up", 64, 20, 515000, 100000)]
        return 0, json.dumps([{"ID": i + 1, "Hypervisor Hostname": f"{h}.localdomain", "Hypervisor Type": "QEMU", "Host IP": f"172.28.1.{i + 20}",
                               "State": st, "vCPUs Used": vu, "vCPUs": v, "Memory MB Used": mu, "Memory MB": m}
                              for i, (h, st, v, vu, m, mu) in enumerate(hvs)])
    if text.startswith("openstack compute service list") and "--service" in args:
        only = args[args.index("--host") + 1] if "--host" in args else None
        return 0, json.dumps([{"ID": i + 1, "Binary": b, "Host": h, "Zone": "nova", "Status": (STATE.get("svc") or {}).get(h, st),
                               "State": state, "Updated At": ago(m)}
                              for i, (b, h, st, state, m) in enumerate(COMPUTE_SERVICES) if b == "nova-compute" and (not only or h == only)])
    if text.startswith("openstack aggregate list"):
        return 0, json.dumps([{"ID": 1, "Name": "agg-gold", "Availability Zone": "nova"}, {"ID": 2, "Name": "agg-gpu", "Availability Zone": "nova"}])
    if text.startswith("openstack aggregate show"):
        hosts = {"1": ["compute-07", "compute-08"], "2": ["compute-03"]}.get(args[3])
        if hosts is None:
            return 1, f"No aggregate with a name or ID of '{args[3]}' exists."
        return 0, json.dumps({"id": int(args[3]), "name": {"1": "agg-gold", "2": "agg-gpu"}[args[3]], "availability_zone": "nova", "hosts": hosts})
    if text.startswith("openstack compute service list"):
        return 0, json.dumps([{"ID": i + 1, "Binary": b, "Host": h, "Zone": "nova" if b == "nova-compute" else "internal",
                               "Status": st, "State": state, "Updated At": ago(m), "Disabled Reason": "capacity reserve" if st == "disabled" else None}
                              for i, (b, h, st, state, m) in enumerate(COMPUTE_SERVICES)])
    if text.startswith("openstack volume service list"):
        return 0, json.dumps([{"Binary": b, "Host": h, "Zone": "nova", "Status": st, "State": state, "Updated At": ago(m),
                               "Disabled Reason": None} for b, h, st, state, m in VOLUME_SERVICES])
    if text.startswith("openstack network agent list"):
        return 0, json.dumps([{"ID": uid(i, "a9"), "Agent Type": t, "Host": h, "Availability Zone": "", "Alive": alive, "State": up,
                               "Binary": "ovn-controller" if "Controller" in t else "networking-ovn-metadata-agent"}
                              for i, (t, h, alive, up) in enumerate(AGENTS)])
    if text.startswith("openstack ip availability list"):
        return 0, json.dumps([{"Network ID": n, "Network Name": name, "Total IPs": t, "Used IPs": u} for n, name, t, u in IP_AVAILABILITY])
    if text.startswith("openstack ip availability show"):
        n = next((x for x in IP_AVAILABILITY if x[0] == args[4]), None)
        if not n:
            return 1, f"No Network found for {args[4]}"
        return 0, json.dumps({"network_id": n[0], "network_name": n[1], "total_ips": n[2], "used_ips": n[3],
                              "subnet_ip_availability": [{"cidr": "203.0.113.0/24", "ip_version": 4, "subnet_id": uid(9, "5b"),
                                                          "subnet_name": "public-sub-1", "total_ips": 253, "used_ips": 250},
                                                         {"cidr": "198.51.100.0/24", "ip_version": 4, "subnet_id": uid(10, "5b"),
                                                          "subnet_name": "public-sub-2", "total_ips": 255, "used_ips": 212}]})
    if text.startswith("openstack network list") and "--external" in args:
        return 0, json.dumps([{"ID": PUBLIC_NET, "Name": f"public-{PREFIX[:3].lower()}", "Subnets": [uid(9, "5b")]}])
    if text.startswith("openstack floating ip list") and "--network" in args:
        return 0, json.dumps([{"ID": uid(i, "f1"), "Floating IP Address": ip, "Fixed IP Address": PORTS[p][2] if p else None,
                               "Port": p, "Floating Network": PUBLIC_NET, "Project": proj} for i, (ip, p, proj) in enumerate(FLOATING)])
    if text.startswith("openstack baremetal node list"):
        return 0, json.dumps([{"UUID": uid(i, "b"), "Name": n, "Power State": pw, "Provisioning State": prov, "Maintenance": m,
                               "Maintenance Reason": reason, "Fault": fault, "Last Error": err,
                               "Instance UUID": uid(i, "bb") if prov == "active" else None, "Driver": "ipmi"}
                              for i, (n, pw, prov, m, reason, fault, err) in enumerate(BAREMETAL)])
    if text.startswith("cinder get-pools"):
        return 0, "\n".join(table(["Property", "Value"], [
            ("name", f"{HOST}#{p}"), ("pool_name", p), ("volume_backend_name", BACKEND), ("total_capacity_gb", t),
            ("allocated_capacity_gb", a), ("free_capacity_gb", f), ("max_over_subscription_ratio", "2.0")]) for p, t, a, f in POOLS)
    if text.startswith("cinder list"):
        tenant = args[args.index("--tenant") + 1] if "--tenant" in args else None
        rows = [(v[0], v[1], v[2], v[3], v[4], f"{HOST}#{POOLS[v[5]][0]}", v[6], v[7] or "None", ago(v[8] + 60), ago(v[8]))
                for v in VOLUMES if not tenant or v[6] == tenant]
        return 0, table(["ID", "Name", "Status", "Size", "volume_type", "os-vol-host-attr:host", "os-vol-tenant-attr:tenant_id",
                         "os-vol-mig-status-attr:migstat", "created_at", "updated_at"], rows)
    if text.startswith("openstack volume snapshot list"):
        only = args[args.index("--volume") + 1] if "--volume" in args else None
        return 0, json.dumps([{"ID": s[0], "Name": s[1], "Status": "available", "Size": s[2], "Volume": s[3],
                               "Created At": ago(s[4] * 1440)} for s in SNAPSHOTS if not only or s[3] == only])
    if text.startswith("cinder attachment-list") and "--volume-id" in args:   # volume API 3.27: whatever their status
        vid = args[args.index("--volume-id") + 1]
        att = ATTACHED.get(vid)
        rows = ([(uid(30, "a"), vid, "attached", att[0])] if att else []) + \
            [(a["id"], vid, a["status"], a["server"]) for a in (STATE.get("extra_attachments") or {}).get(vid, [])]
        return 0, table(["ID", "Volume ID", "Status", "Server ID"], rows)
    if text.startswith("openstack volume show"):
        v = next((x for x in VOLUMES if x[0] == args[3]), None)
        if not v:
            return 1, f"No volume with a name or ID of '{args[3]}' exists."
        att = ATTACHED.get(v[0])
        return 0, json.dumps({"id": v[0], "name": v[1], "status": v[2], "size": v[3], "type": v[4],
                              "os-vol-host-attr:host": f"{HOST}#{POOLS[v[5]][0]}", "os-vol-tenant-attr:tenant_id": v[6],
                              "migration_status": v[7] or None, "updated_at": ago(v[8]), "multiattach": False,
                              "group_id": None, "replication_status": None,
                              "attachments": [{"server_id": att[0], "device": att[1], "attachment_id": uid(30, "a")}] if att else []})
    if text.startswith("openstack network list"):
        return 0, json.dumps([{"ID": uid(9, "e"), "Name": f"public-{PREFIX[:3].lower()}", "Subnets": [uid(9, "5b")]}])
    if text.startswith("openstack volume type list"):
        return 0, json.dumps([{"ID": uid(i, "7e"), "Name": t, "Is Public": True} for i, t in enumerate(TYPES)])
    if text.startswith("openstack project list"):
        return 0, json.dumps([{"ID": pid, "Name": name} for pid, name in PROJECTS.items()])
    if text.startswith("openstack project show"):
        pid = project_id(args[3])
        if not pid:
            return 1, f"No project with a name or ID of '{args[3]}' exists."
        return 0, json.dumps({"id": pid, "name": PROJECTS[pid], "enabled": True})
    if text.startswith("openstack quota show"):
        pid = project_id(args[3])
        return (0, json.dumps(QUOTA[pid])) if pid in QUOTA else (1, "No project")
    if text.startswith("openstack limits show"):
        pid = project_id(args[args.index("--project") + 1])
        q, u = QUOTA.get(pid, {}), USAGE.get(pid, {})
        limits = {"maxTotalInstances": q.get("instances"), "maxTotalCores": q.get("cores"), "maxTotalRAMSize": q.get("ram"),
                  "maxTotalVolumes": q.get("volumes"), "maxTotalVolumeGigabytes": q.get("gigabytes"),
                  "maxTotalSnapshots": q.get("snapshots"), **u}
        return 0, json.dumps([{"Name": k, "Value": v} for k, v in limits.items()])
    if text.startswith("openstack server list"):
        only = project_id(args[args.index("--project") + 1]) if "--project" in args else None
        host = args[args.index("--host") + 1] if "--host" in args else None
        image = args[args.index("--image") + 1] if "--image" in args else None
        return 0, json.dumps([{"ID": sid, "Name": s[0], "Status": s[1], "Power State": s[2], "Host": s[3], "Project ID": s[4],
                               "Task State": server_task(sid), "Image ID": SERVER_EXTRA[sid][1] or "",
                               "Flavor Name": SERVER_EXTRA[sid][0], "Flavor ID": FLAVORS[SERVER_EXTRA[sid][0]][0]}
                              for sid, s in SERVERS.items() if (not only or s[4] == only) and (not host or s[3] == host)
                              and (not image or SERVER_EXTRA[sid][1] == image)])
    if text.startswith("openstack server event list"):
        if args[4] not in SERVERS:
            return 1, f"No server with a name or ID of '{args[4]}' exists."
        return 0, json.dumps([{"Request ID": REQ, "Server ID": args[4], "Action": "create", "Start Time": "2026-10-11T00:42:58.000000"}]
                             + [{"Request ID": e["req"], "Server ID": e["sid"], "Action": e["action"], "Start Time": e["start"]}
                                for e in STATE.get("events") or [] if e["sid"] == args[4]])
    if text.startswith("openstack server show"):
        tick_server(args[3])
        s = SERVERS.get(args[3])
        if not s:
            return 1, f"No server with a name or ID of '{args[3]}' exists."
        fl, img, drive = SERVER_EXTRA[args[3]]
        ch = (STATE.get("servers") or {}).get(args[3]) or {}
        fault = ch["fault"] if "fault" in ch else s[6]
        s = s[:6] + (fault,) + s[7:]
        return 0, json.dumps({"id": args[3], "name": s[0], "status": s[1], "OS-EXT-STS:power_state": s[2],
                              "OS-EXT-STS:task_state": server_task(args[3]), "OS-EXT-SRV-ATTR:instance_name": instance_name(args[3]),
                              "flavor": f"{fl} ({FLAVORS[fl][0]})", "image": f"ubuntu ({img})" if img else "",
                              "config_drive": "True" if drive else "", "volumes_attached": [],
                              "OS-EXT-SRV-ATTR:host": s[3] or None,
                              "OS-EXT-SRV-ATTR:hypervisor_hostname": f"overcloud-novacompute-{int(s[3].split('.')[0].split('-')[1])}.localdomain" if s[3] else None, "project_id": s[4], "created": ago(s[5]).split(".")[0] + "Z",
                              "fault": {"message": s[6]} if s[6] else None, "security_groups": [{"name": g} for g in s[8]],
                              "addresses": {"vpc-app": [PORTS[p][2] for p in s[7]]}})
    if text.startswith("openstack port list"):
        if "--server" in args:
            sid = args[args.index("--server") + 1]
            return 0, json.dumps([{"ID": pid, "Name": p[0], "Status": "ACTIVE", "Fixed IP Addresses": [{"subnet_id": SUB_APP, "ip_address": p[2]}]}
                                  for pid, p in PORTS.items() if p[1] == sid])
        m = re.search(r"--fixed-ip ip-address=(\S+)", text)
        if m:
            return 0, json.dumps([{"ID": pid, "Name": p[0]} for pid, p in PORTS.items() if p[2] == m.group(1)])
        pid = project_id(args[args.index("--project") + 1]) if "--project" in args else None
        return 0, json.dumps([{"ID": uid(i, "8")} for i in range(12 if pid == CUSTOMER else 4)])
    if text.startswith("openstack port show"):
        p = PORTS.get(args[3])
        if not p:
            return 1, "No port"
        return 0, json.dumps({"id": args[3], "name": p[0], "status": "ACTIVE", "device_id": p[1], "network_id": NET_APP,
                              "security_group_ids": p[3], "fixed_ips": [{"subnet_id": SUB_APP, "ip_address": p[2]}]})
    if text.startswith("openstack floating ip list"):
        if "--port" in args:
            pid = args[args.index("--port") + 1]
            p = PORTS.get(pid)
            return 0, json.dumps([{"ID": uid(1, "f1"), "Floating IP Address": p[4], "Fixed IP Address": p[2], "Port": pid}] if p and p[4] else [])
        if "--floating-ip-address" in args:
            ip = args[args.index("--floating-ip-address") + 1]
            return 0, json.dumps([{"ID": uid(1, "f1"), "Floating IP Address": ip, "Fixed IP Address": p[2], "Port": pid}
                                  for pid, p in PORTS.items() if p[4] == ip])
        pid = project_id(args[args.index("--project") + 1]) if "--project" in args else None
        return 0, json.dumps([{"ID": uid(i, "f1")} for i in range(3 if pid == CUSTOMER else 1)])
    if text.startswith("openstack subnet show"):
        return 0, json.dumps({"id": args[3], "name": "vpc-app-subnet", "cidr": "10.249.1.0/24", "gateway_ip": "10.249.1.1",
                              "allocation_pools": [{"start": "10.249.1.2", "end": "10.249.1.254"}]})
    if text.startswith("openstack security group rule list"):
        sg = SG_RULES.get(args[5])
        if not sg:
            return 1, "No security group"
        return 0, json.dumps([{"ID": uid(i, "51"), "IP Protocol": proto or None, "Ethertype": "IPv4", "IP Range": cidr,
                               "Port Range": rng, "Direction": d, "Remote Security Group": None}
                              for i, (d, proto, rng, cidr) in enumerate(sg[1])])
    if text.startswith("openstack security group show"):
        sg = SG_RULES.get(args[4])
        return (0, json.dumps({"id": args[4], "name": sg[0]})) if sg else (1, "No security group")
    return 1, f"fake_cloud: command not emulated: {cmd}"


# ---------------- log collection (wi_collect.py on a node, through ssh from the director) ----------------
FAKE_SOS = r"""#!/usr/bin/env python3
import io, lzma, os, sys, tarfile
a = sys.argv[1:]
tmp, label = a[a.index("--tmp-dir") + 1], a[a.index("--label") + 1]
case = a[a.index("--case-id") + 1] + "-" if "--case-id" in a else ""
print("sos report (fake) " + " ".join(a))
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w") as t:
    data = b"fake sos report of " + os.environ["FAKE_NODE"].encode() + b"\n"
    info = tarfile.TarInfo("sosreport/version.txt"); info.size = len(data); t.addfile(info, io.BytesIO(data))
name = os.path.join(tmp, "sosreport-" + os.environ["FAKE_NODE"] + "-" + label + "-" + case + "2026-10-19-abcdefg.tar.xz")
with open(name, "wb") as f:
    f.write(lzma.compress(buf.getvalue()))
open(name + ".sha256", "w").write("x\n")
print("Your sosreport has been generated and saved in:\n\t" + name)
"""


def fake_logs(root, name):
    """Log files of a node: lines 30 minutes, 3 hours and 30 hours ago (local time), a traceback, secrets to mask."""
    now = datetime.datetime.now()

    def at(minutes):
        return (now - datetime.timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    ctrl = "controller" in name
    files = {"nova/nova-compute.log": "nova.compute.manager"} if not ctrl else \
        {"nova/nova-api.log": "nova.api", "nova/nova-conductor.log": "nova.conductor", "keystone/keystone.log": "keystone",
         "haproxy/haproxy.log": None}
    files["neutron/ovn-metadata-agent.log" if not ctrl else "neutron/server.log"] = "neutron"
    for rel, logger in files.items():
        path = os.path.join(root, "var/log/containers", rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            for m in (1800, 180, 30):
                if logger is None:
                    t = (now - datetime.timedelta(minutes=m)).strftime("%b %d %H:%M:%S")
                    f.write(f"{t} {name} haproxy[12]: Server nova_osapi/{name} is DOWN, reason: Layer4 timeout\n")
                    continue
                f.write(f"{at(m)} 12 ERROR {logger} [req-0b1c2d3e-0000-4000-8000-00000000000{m % 7}] failed {m} minutes ago: "
                        f"transport_url=rabbit://guest:FakeRabbitPass@{name}:5672/ password=FakeSecret1\n")
                f.write("Traceback (most recent call last):\n  File \"/usr/lib/python3.9/site-packages/x.py\", line 1\n")
    rotated = os.path.join(root, "var/log/containers", "neutron/ovn-metadata-agent.log" if not ctrl else "neutron/server.log")
    with gzip.open(rotated + ".1.gz", "wt") as f:
        f.write(f"{at(200)} 12 INFO neutron rotated line X-Auth-Token: gAAAAABfaketokenvalue0123456789abcdefghijklmn\n")


def collect(script):
    """A Collect logs / sos report read: the real wi_collect.py (from the base64 in the command) runs here on fake log files
    of the node, or with a fake sos command; its archive goes to stdout, its messages to stderr, like on a node."""
    args = shlex.split(script)
    target = next((a for a in args if "@" in a and not a.startswith("-")), "")
    user, _, ip = target.partition("@")
    name = next((n for n, a in UC_NODES if a == ip), None)
    if user not in ("heat-admin", "tripleo-admin") or name is None or name == NODE_DOWN:
        print(f"ssh: connect to host {ip} port 22: No route to host", file=sys.stderr)
        return 255
    m = re.search(r"echo (\S+) \| base64 -d \| sudo -n \"\$PY\" - (.*?)( \| gzip -c)?$", args[-1])
    if not m:
        print("fake_cloud: not a wi_collect command", file=sys.stderr)
        return 127
    work = tempfile.mkdtemp(prefix="fake-node-")
    try:
        code = os.path.join(work, "wi_collect.py")
        with open(code, "wb") as f:
            f.write(base64.b64decode(m.group(1)))
        cargs = shlex.split(m.group(2))
        env = dict(os.environ, FAKE_NODE=name)
        if cargs[0] == "logs":
            fake_logs(os.path.join(work, "root"), name)
            cargs += ["--root", os.path.join(work, "root"), "--tmp", work]
        else:
            os.makedirs(os.path.join(work, "bin"))
            with open(os.path.join(work, "bin", "sos"), "w") as f:
                f.write(f"#!{sys.executable}\n" + FAKE_SOS.split("\n", 1)[1])
            os.chmod(os.path.join(work, "bin", "sos"), 0o755)
            env["PATH"] = os.path.join(work, "bin") + os.pathsep + env.get("PATH", "")
            cargs[cargs.index("--min-free-gb") + 1] = "0"
            cargs += ["--tmp", work]
        proc = subprocess.run([sys.executable, code] + cargs, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        sys.stderr.write(proc.stderr.decode(errors="replace"))
        sys.stdout.buffer.write(gzip.compress(proc.stdout) if m.group(3) else proc.stdout)
        sys.stdout.buffer.flush()
        return proc.returncode
    finally:
        shutil.rmtree(work, ignore_errors=True)


def live(script):
    """The live output of a fix item (wi_analysis.live_start / live_poll / live_wait / live_end): the item runs at once,
    here, its output kept in a folder named like the director's."""
    kind = script.split("\n", 1)[0][len("# wi-live "):].strip()
    if kind == "start":
        inner = gzip.decompress(base64.b64decode(re.search(r"printf %s '([A-Za-z0-9+/=]*)'", script).group(1))).decode()
        folder = "/tmp/wi-live." + os.urandom(6).hex()
        os.makedirs(folder, mode=0o700)
        # the item again through main(), packed as the director gets it: Linux takes one argument of 128 KiB at most
        repacked = "# wi packed\nprintf %s '" + base64.b64encode(gzip.compress(inner.encode())).decode() + "'\n"
        done = subprocess.run([sys.executable, os.path.abspath(__file__), repacked], capture_output=True, text=True)
        with open(os.path.join(folder, "out"), "w") as f:
            f.write(done.stdout + done.stderr)
        with open(os.path.join(folder, "rc"), "w") as f:
            f.write(f"{done.returncode}\n")
        print(f"@@WI@@live {folder}")
        return 0
    folder = re.search(r"^d=(/tmp/wi-live\.[0-9a-f]+)", script, re.M).group(1)
    try:
        with open(os.path.join(folder, "out")) as f:
            lines = f.read().split("\n")[:-1]   # complete lines only
        with open(os.path.join(folder, "rc")) as f:
            rc = f.read().strip()
    except OSError:
        lines, rc = [], ""
    if kind == "poll":
        seen = int(re.search(r"; n=(\d+)", script).group(1))
        for line in lines[seen:]:
            print(line)
        print(f"@@WI@@live-at {len(lines)} {rc}")
    elif kind == "wait":
        print(f"@@WI@@live-at 0 {rc}")
    elif kind == "end":
        print("\n".join(lines))
        shutil.rmtree(folder, ignore_errors=True)
        return int(rc or 98)
    return 0


def main():
    script = sys.argv[1] if len(sys.argv) > 1 else ""
    if script.startswith("# wi packed\n"):   # wi_analysis.packed: the script itself, as bash runs it from its file
        script = gzip.decompress(base64.b64decode(re.search(r"printf %s '([A-Za-z0-9+/=]*)'", script).group(1))).decode()
    if script.startswith("# wi-live "):
        return live(script)
    if ": wi-collect;" in script:
        return collect(script)
    if "@@WI@@begin" not in script:
        target = os.environ.get("FAKE_DIRECTOR_PY")
        if not target:
            print("fake_cloud: not an Operation Automation script and FAKE_DIRECTOR_PY is not set", file=sys.stderr)
            return 1
        os.execv(sys.executable, [sys.executable, target, *sys.argv[1:]])
    global UNDERCLOUD
    UNDERCLOUD = "source ~/stackrc" in script
    together = {}   # reads run on their nodes at once (overcloud.PARALLEL): answered when their output is printed
    lines, i = script.splitlines(), 0
    while i < len(lines):
        line, i = lines[i], i + 1
        if line.startswith("( ssh ") and not line.endswith(") &"):   # a read of several lines (quoted, as bash reads it)
            while i < len(lines) and not lines[i].endswith(") &"):
                line, i = line + "\n" + lines[i], i + 1
            if i < len(lines):
                line, i = line + "\n" + lines[i], i + 1
        m = re.match(r"^\( (ssh .*) > \"\$WI_OC_TMP/(\S+)\" 2>&1; echo \$\? > \"\$WI_OC_TMP/\2\.rc\" \) &$", line, re.S)
        if m:
            together[m.group(2)] = m.group(1)
            continue
        m = re.match(r"^echo '@@WI@@begin (\S+)'; cat \"\$WI_OC_TMP/\1\"; ", line)
        if m:
            rc, out = answer(together[m.group(1)])
            print(f"@@WI@@begin {m.group(1)}")
            if out:
                print(out)
            print(f"@@WI@@end {m.group(1)} {rc}")
            continue
        m = (re.match(r"^echo '@@WI@@begin (\S+)'; (.*) 2>&1; echo \"@@WI@@end \1 \$\?\"$", line)
             or re.match(r"^echo '@@WI@@begin (\S+)'; (.*) 2>&1; rc=\$\?; echo \"@@WI@@end \1 \$rc\"; .*$", line))
        if not m:
            continue
        key, cmd = m.group(1), m.group(2)
        print(f"@@WI@@begin {key}", flush=True)
        rc, out = change(cmd) or answer(cmd)
        if out:
            print(out)
        print(f"@@WI@@end {key} {rc}")
        if rc and "; rc=$?;" in line:   # a fix stops at the first command that fails
            return rc
    return 0


if __name__ == "__main__":
    sys.exit(main())

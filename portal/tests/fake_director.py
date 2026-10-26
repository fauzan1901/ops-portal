#!/usr/bin/env python3
"""Fake OpenStack director for tests. Called like ssh to the director, with one command argument:

    fake_director.py 'source ~/overcloudrc && openstack volume show <id> -f json'

Emulates the openstack/cinder commands used by the playbooks, including volume transfers and roles. State is kept
in a JSON file (env FAKE_DIRECTOR_STATE). Env FAKE_DIRECTOR_FAIL=<text> makes commands containing that text fail.
Env FAKE_ONTAP_URL makes `cinder manage` rename the LUN in the mock ONTAP like the real NetApp driver.
"""
import fcntl
import json
import os
import re
import shlex
import ssl
import sys
import urllib.request
import uuid

ADMIN_USER = "a0000000000000000000000000000001"
ADMIN_PROJECT = "ad000000000000000000000000000000"
CUSTOMER_PROJECT = "c0ffee00000000000000000000000001"   # admin has no role here yet
OTHER_PROJECT = "c0ffee00000000000000000000000002"      # admin already has the member role
VOLUME_ID = "a80a1a07-06b8-489b-a984-b046981f68b9"
FULL_VOLUME_ID = "22222222-2222-4222-8222-222222222222"
NAMEID_VOLUME_ID = "33333333-3333-4333-8333-333333333333"    # retyped before: the backend name uses name_id
NAMEID_BACKEND_ID = "44444444-4444-4444-8444-444444444444"
# Volume types as on the real sites: each tier has its own volume_backend_name, QoS via netapp:qos_policy_group.
TYPE_STANDARD = "7e000000-0000-4000-8000-000000000001"   # netapp-iscsi, backend faas500f (type of the test volume)
TYPE_BASIC = "7e000000-0000-4000-8000-000000000002"      # netapp-basic, backend faas500f (selectable)
TYPE_NVME = "7e000000-0000-4000-8000-000000000003"       # nvme-premium, another backend (no match)
TYPE_PRIVATE = "7e000000-0000-4000-8000-000000000004"    # standard-old, private without a backend
TYPE_ARCHIVE = "7e000000-0000-4000-8000-000000000005"    # archive, another backend whose FlexVol is in another SVM (not possible)
BOOT_VOLUME_ID = "55555555-5555-4555-8555-555555555555"   # boot disk (vda) of vm-01; VOLUME_ID is its extended disk (vdb)
# Instances: vm-01 (customer project, boots from BOOT_VOLUME_ID, VOLUME_ID as vdb, 2 network interfaces), vm-02 (SHUTOFF)
# and vm-03 (ERROR) in the customer project, other-vm in the other project.
SERVER_ID = "5e000000-0000-4000-8000-000000000001"
SERVER2_ID = "5e000000-0000-4000-8000-000000000002"
SERVER3_ID = "5e000000-0000-4000-8000-000000000003"
OTHER_SERVER_ID = "5e000000-0000-4000-8000-000000000004"
FLAVOR_ID = "f1000000-0000-4000-8000-000000000001"
NET_APP, NET_DB = "0e000000-0000-4000-8000-00000000000a", "0e000000-0000-4000-8000-00000000000b"
SUBNET_APP, SUBNET_DB = "5b000000-0000-4000-8000-00000000000a", "5b000000-0000-4000-8000-00000000000b"
# The VPCs of the other project: vpc-other (one subnet) and vpc-other-db (two subnets).
NET_VPC1, NET_VPC2 = "0e000000-0000-4000-8000-00000000000c", "0e000000-0000-4000-8000-00000000000d"
SUBNET_VPC1, SUBNET_VPC2A, SUBNET_VPC2B = ("5b000000-0000-4000-8000-00000000000c", "5b000000-0000-4000-8000-00000000000d",
                                          "5b000000-0000-4000-8000-00000000000e")
SG_DEFAULT, SG_WEB = "56000000-0000-4000-8000-000000000001", "56000000-0000-4000-8000-000000000002"
SG_OTHER_DEFAULT = "56000000-0000-4000-8000-000000000003"
PORT_APP, PORT_DB = "90000000-0000-4000-8000-00000000000a", "90000000-0000-4000-8000-00000000000b"


def default_state(prefix="DCAOPNSTACK"):
    backend, nvme, archive = f"{prefix.lower()}_faas500f", f"{prefix.lower()}_nvme_premium", f"{prefix.lower()}_archive"

    def volume(vid, pool, name, status="available", attached_to="", device="", bootable="false"):
        vol = {"id": vid, "name": name, "size": 100, "status": status, "type": "netapp-iscsi", "bootable": bootable,
               "availability_zone": "nova", "os-vol-host-attr:host": f"hostgroup@{backend}#{pool}",
               "os-vol-tenant-attr:tenant_id": CUSTOMER_PROJECT, "attachments": []}
        if attached_to:
            vol["attachments"] = [{"id": str(uuid.uuid5(uuid.NAMESPACE_URL, vid)), "attachment_id": str(uuid.uuid5(uuid.NAMESPACE_URL, vid)),
                                   "volume_id": vid, "server_id": attached_to, "host_name": "compute-0", "device": device}]
        return vol

    def volume_type(tid, name, public, description, specs):
        return {"ID": tid, "Name": name, "Is Public": public, "Description": description, "Properties": specs}

    def pool(vbn, name, total=20480.0, free=4096.0, allocated=None):
        # Like the NetApp driver: capacity of the FlexVol (GiB); utilization is performance (not capacity). allocated:
        # what Cinder allocated on the pool (default total - free, so 1:1 sites see the same fullness either way).
        return {"QoS_support": True, "multiattach": True, "netapp_disk_type": ["SSD"], "netapp_mirrored": "false",
                "pool_name": name, "storage_protocol": "iSCSI", "thin_provisioning_support": True, "volume_backend_name": vbn,
                "total_capacity_gb": total, "free_capacity_gb": free, "provisioned_capacity_gb": round(total * 1.3, 1),
                "allocated_capacity_gb": round(total - free if allocated is None else allocated, 1),
                "max_over_subscription_ratio": "20.0", "reserved_percentage": 0, "utilization": 30.0,
                "filter_function": "capabilities.utilization < 70"}

    def server(sid, name, project, status, flavor=FLAVOR_ID, **extra):
        return dict({"id": sid, "name": name, "status": status, "project_id": project, "flavor_id": flavor,
                     "image": "N/A (booted from volume)", "key_name": None, "OS-EXT-AZ:availability_zone": "nova",
                     "OS-EXT-SRV-ATTR:host": "compute-0", "config_drive": "", "created": "2025-10-01T08:00:00Z",
                     "properties": {}, "security_groups": [{"name": "default"}]}, **extra)

    def port(pid, network, subnet, ip, groups, device, project=CUSTOMER_PROJECT, security=True):
        return {"id": pid, "name": "", "network_id": network, "fixed_ips": [{"subnet_id": subnet, "ip_address": ip}],
                "mac_address": "fa:16:3e:00:" + pid[-4:-2] + ":" + pid[-2:], "security_group_ids": groups,
                "port_security_enabled": security, "binding_vnic_type": "normal", "device_id": device,
                "device_owner": "compute:nova" if device else "", "project_id": project, "status": "ACTIVE" if device else "DOWN"}
    return {
        "types": [
            volume_type(TYPE_STANDARD, "netapp-iscsi", True, "Standard Volume SSD with 750 - 2250 IOPS",
                        {"volume_backend_name": backend, "netapp:qos_policy_group": "standard-volume", "netapp_mirrored": "false"}),
            volume_type(TYPE_BASIC, "netapp-basic", True, "Basic Volume",
                        {"volume_backend_name": backend, "netapp:qos_policy_group": "basic-volume", "netapp_mirrored": "false"}),
            volume_type(TYPE_NVME, "nvme-premium", True, "Premium Volume nvme with 10000 - 15000 IOPS",
                        {"volume_backend_name": nvme, "netapp:qos_policy_group": "nvme-premium", "netapp_mirrored": "false"}),
            volume_type(TYPE_PRIVATE, "standard-old", False, None,
                        {"netapp:qos_policy_group": "standard-volume", "netapp_mirrored": "false"}),
            volume_type(TYPE_ARCHIVE, "archive", True, "Archive Volume",
                        {"volume_backend_name": archive, "netapp:qos_policy_group": "archive", "netapp_mirrored": "false"}),
        ],
        # Pools of the standard backend (faas500f): 14 (LUN pool, 80% used), 15 (full), 16 (room), 17 (FlexVol in another
        # SVM), TEST50 (test pool); plus pools of other tiers that a standard volume must never be offered.
        "pools": {f"hostgroup@{backend}#{prefix}_CINDER_14_vol": pool(backend, f"{prefix}_CINDER_14_vol", 10240.0, 2048.0),
                  f"hostgroup@{backend}#{prefix}_CINDER_15_vol": pool(backend, f"{prefix}_CINDER_15_vol", 10240.0, 10.0),
                  f"hostgroup@{backend}#{prefix}_CINDER_16_vol": pool(backend, f"{prefix}_CINDER_16_vol", 10240.0, 6000.0),
                  f"hostgroup@{backend}#{prefix}_CINDER_17_vol": pool(backend, f"{prefix}_CINDER_17_vol", 10240.0, 5000.0),
                  f"hostgroup@{backend}#{prefix}_CINDER_TEST50_vol": pool(backend, f"{prefix}_CINDER_TEST50_vol", 10240.0, 9000.0),
                  f"hostgroup@{nvme}#{prefix}_NVME_01_vol": pool(nvme, f"{prefix}_NVME_01_vol"),
                  f"hostgroup@{nvme}#{prefix}_NVME_TEST99_vol": pool(nvme, f"{prefix}_NVME_TEST99_vol"),
                  f"hostgroup@{nvme}#{prefix}_NVME_01_vol_clone_7": pool(nvme, f"{prefix}_NVME_01_vol_clone_7"),
                  f"hostgroup@{archive}#{prefix}_ARCHIVE_01_vol": pool(archive, f"{prefix}_ARCHIVE_01_vol")},
        "admin": {"user_id": ADMIN_USER, "project_id": ADMIN_PROJECT},
        "projects": {ADMIN_PROJECT: {"id": ADMIN_PROJECT, "name": "admin", "enabled": True},
                     CUSTOMER_PROJECT: {"id": CUSTOMER_PROJECT, "name": "customer-a80", "enabled": True},
                     OTHER_PROJECT: {"id": OTHER_PROJECT, "name": "customer-other", "enabled": True}},
        "roles": [[ADMIN_USER, ADMIN_PROJECT, "admin"], [ADMIN_USER, OTHER_PROJECT, "member"]],
        "volumes": {VOLUME_ID: volume(VOLUME_ID, f"{prefix}_CINDER_14_vol", "vm-01-data", "in-use", SERVER_ID, "/dev/vdb"),
                    BOOT_VOLUME_ID: dict(volume(BOOT_VOLUME_ID, f"{prefix}_CINDER_14_vol", "vm-01-root", "in-use", SERVER_ID,
                                                "/dev/vda", "true"),
                                         volume_image_metadata={"image_name": "ubuntu-24.04", "hw_firmware_type": "uefi",
                                                                "hw_disk_bus": "virtio", "os_type": "linux", "min_disk": "20"}),
                    FULL_VOLUME_ID: volume(FULL_VOLUME_ID, f"{prefix}_CINDER_15_vol", "vm-02-data"),
                    NAMEID_VOLUME_ID: dict(volume(NAMEID_VOLUME_ID, f"{prefix}_CINDER_14_vol", "vm-03-retype"),
                                           **{"os-vol-mig-status-attr:migstat": "success",
                                              "os-vol-mig-status-attr:name_id": NAMEID_BACKEND_ID})},
        "servers": {SERVER_ID: server(SERVER_ID, "vm-01", CUSTOMER_PROJECT, "ACTIVE", key_name="ops-key", properties={"env": "prod"},
                                      security_groups=[{"name": "default"}, {"name": "web"}]),
                    SERVER2_ID: server(SERVER2_ID, "vm-02", CUSTOMER_PROJECT, "SHUTOFF"),
                    SERVER3_ID: server(SERVER3_ID, "vm-03", CUSTOMER_PROJECT, "ERROR"),
                    OTHER_SERVER_ID: server(OTHER_SERVER_ID, "other-vm", OTHER_PROJECT, "ACTIVE")},
        "ports": {PORT_APP: port(PORT_APP, NET_APP, SUBNET_APP, "10.249.0.15", [SG_DEFAULT, SG_WEB], SERVER_ID),
                  PORT_DB: port(PORT_DB, NET_DB, SUBNET_DB, "10.248.0.8", [], SERVER_ID, security=False)},
        "networks": {NET_APP: {"id": NET_APP, "name": "net-app", "shared": False, "project_id": CUSTOMER_PROJECT,
                               "router:external": False, "port_security_enabled": True, "subnets": [SUBNET_APP]},
                     NET_DB: {"id": NET_DB, "name": "net-db", "shared": True, "project_id": ADMIN_PROJECT,
                              "router:external": False, "port_security_enabled": True, "subnets": [SUBNET_DB]},
                     NET_VPC1: {"id": NET_VPC1, "name": "vpc-other", "shared": False, "project_id": OTHER_PROJECT,
                                "router:external": False, "port_security_enabled": True, "subnets": [SUBNET_VPC1]},
                     NET_VPC2: {"id": NET_VPC2, "name": "vpc-other-db", "shared": False, "project_id": OTHER_PROJECT,
                                "router:external": False, "port_security_enabled": True, "subnets": [SUBNET_VPC2A, SUBNET_VPC2B]}},
        "subnets": {SUBNET_APP: {"network_id": NET_APP, "prefix": "10.249.0.", "next": 100, "name": "app-subnet"},
                    SUBNET_DB: {"network_id": NET_DB, "prefix": "10.248.0.", "next": 100, "name": "db-subnet"},
                    SUBNET_VPC1: {"network_id": NET_VPC1, "prefix": "10.246.0.", "next": 100, "name": "vpc-other-subnet"},
                    SUBNET_VPC2A: {"network_id": NET_VPC2, "prefix": "10.245.0.", "next": 100, "name": "db-a"},
                    SUBNET_VPC2B: {"network_id": NET_VPC2, "prefix": "10.244.0.", "next": 100, "name": "db-b"}},
        "flavors": {FLAVOR_ID: {"id": FLAVOR_ID, "name": "m1.medium", "vcpus": 2, "ram": 4096, "disk": 40,
                                "os-flavor-access:is_public": True, "properties": {}}},
        "security_groups": {SG_DEFAULT: {"id": SG_DEFAULT, "name": "default", "project_id": CUSTOMER_PROJECT},
                            SG_WEB: {"id": SG_WEB, "name": "web", "project_id": CUSTOMER_PROJECT},
                            SG_OTHER_DEFAULT: {"id": SG_OTHER_DEFAULT, "name": "default", "project_id": OTHER_PROJECT}},
        "transfers": {},
        "calls": [],
    }


class CommandError(Exception):
    def __init__(self, message, rc=1):
        super().__init__(message)
        self.rc = rc


def option(words, name, default=None):
    return words[words.index(name) + 1] if name in words else default


WITH_VALUE = ("--auth-key", "-f", "-c", "--name", "--volume-type", "--id-type", "--user", "--project", "--network", "--fixed-ip",
              "--vnic-type", "--security-group", "--description", "--flavor", "--volume", "--nic", "--availability-zone",
              "--config-drive", "--property", "--image-property", "--server", "--os-compute-api-version", "--block-device-mapping")


def parse(words, with_value=WITH_VALUE):
    """({option: [values]}, positionals); flags get the value True."""
    opts, args, i = {}, [], 0
    while i < len(words):
        word = words[i]
        if word in with_value:
            opts.setdefault(word, []).append(words[i + 1] if i + 1 < len(words) else "")
            i += 2
            continue
        if word.startswith("--"):
            opts.setdefault(word, []).append(True)
        else:
            args.append(word)
        i += 1
    return opts, args


def positionals(words, with_value=WITH_VALUE):
    """Positional arguments (without options and their values)."""
    return parse(words, with_value)[1]


def ontap_helper(path, body):
    """Test helper call to the mock ONTAP (like the NetApp driver changing the LUN of a volume)."""
    base = os.environ.get("FAKE_ONTAP_URL")
    if not base:
        return
    req = urllib.request.Request(base + path, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"},
                                 method="POST")
    try:
        urllib.request.urlopen(req, context=ssl._create_unverified_context(), timeout=10).close()
    except Exception:
        pass


def rename_lun(old, new):
    ontap_helper("/__rename", {"from": old, "to": new})


def delete_lun(vol):
    """cinder delete: the NetApp driver deletes LUN volume-<name_id or ID> in the pool of the volume."""
    pool = vol["os-vol-host-attr:host"].split("#")[-1]
    ontap_helper("/__delete", {"name": f"/vol/{pool}/volume-{vol.get('os-vol-mig-status-attr:name_id') or vol['id']}"})


def columns(data, words):
    """-c <column> (repeatable) like the OpenStack CLI: only those columns."""
    wanted = parse(words)[0].get("-c")
    return {k: v for k, v in data.items() if k in wanted} if wanted else data


def server_view(state, sid):
    srv = state["servers"][sid]
    flavor = state["flavors"].get(srv["flavor_id"]) or {"name": "deleted-flavor"}
    shown = {k: v for k, v in srv.items() if k != "flavor_id" and not k.startswith("_")}
    shown["flavor"] = f"{flavor['name']} ({srv['flavor_id']})"
    addresses = {}
    for port in state["ports"].values():
        if port["device_id"] == sid:
            net = state["networks"][port["network_id"]]["name"]
            addresses.setdefault(net, []).extend(ip["ip_address"] for ip in port["fixed_ips"])
    shown["addresses"] = addresses
    # compute API 2.3 and later: delete_on_termination of each volume (set per attachment in the state)
    shown["volumes_attached"] = [{"id": v["id"], "delete_on_termination": any(a.get("delete_on_termination") for a in v["attachments"]
                                                                              if a["server_id"] == sid)}
                                 for v in state["volumes"].values() if any(a["server_id"] == sid for a in v.get("attachments") or [])]
    return shown


def next_device(state, sid):
    used = {a["device"] for v in state["volumes"].values() for a in v.get("attachments") or [] if a["server_id"] == sid}
    return next(f"/dev/vd{c}" for c in "bcdefghijklmnop" if f"/dev/vd{c}" not in used)


def attach(vol, sid, device):
    att = str(uuid.uuid4())
    vol["attachments"] = [{"id": att, "attachment_id": att, "volume_id": vol["id"], "server_id": sid, "host_name": "compute-0",
                           "device": device}]
    vol["status"] = "in-use"


def run(words, env, state):
    if words[1:2] == ["--os-compute-api-version"]:   # openstack --os-compute-api-version <v> <command>
        words = words[:1] + words[3:]
    scope = env.get("OS_PROJECT_ID", state["admin"]["project_id"])
    admin_scope = scope == state["admin"]["project_id"]
    volumes, projects, transfers = state["volumes"], state["projects"], state["transfers"]
    servers, ports, networks = state.setdefault("servers", {}), state.setdefault("ports", {}), state.setdefault("networks", {})
    head = " ".join(words[:5])
    opts, args = parse(words)

    if words[:3] == ["openstack", "volume", "show"]:
        vol = volumes.get(words[3])
        if not vol:
            raise CommandError(f"No volume with a name or ID of '{words[3]}' exists.")
        shown = {k: v for k, v in vol.items() if not k.startswith("_")}
        if vol["status"] == "creating":
            # The scheduler rejects a type that does not match the pool: the volume becomes error_managing, the LUN is untouched.
            vol["status"] = "error_managing" if vol.pop("_manage_error", False) else "available"
            return json.dumps(dict(shown, status="creating"))
        if vol["status"] == "deleting":   # Cinder finishes the deletion (and the driver deletes the LUN)
            del volumes[words[3]]
            delete_lun(vol)
            return json.dumps(dict(shown, status="deleting"))
        if vol["status"] == "attaching":   # Nova finishes the attachment
            attach(vol, vol.pop("_attach_to"), next_device(state, vol["_attach_device_for"]))
            vol.pop("_attach_device_for", None)
            return json.dumps(dict(shown, status="attaching"))
        return json.dumps(shown)
    if words[:4] == ["openstack", "volume", "snapshot", "list"]:
        vid = option(words, "--volume")
        snaps = [snap for snap in state.get("snapshots", []) if snap.get("Volume") == vid]
        for snap in snaps:   # Cinder finishes a deletion: gone at the next look (or error_deleting when _stuck)
            if snap.get("Status") == "deleting":
                snap["Status"] = "error_deleting" if snap.get("_stuck") else "gone"
        state["snapshots"] = [snap for snap in state.get("snapshots", []) if snap.get("Status") != "gone"]
        return json.dumps([{k: v for k, v in snap.items() if not k.startswith("_")} for snap in state["snapshots"]
                           if snap.get("Volume") == vid])
    if words[:4] == ["openstack", "volume", "snapshot", "delete"]:
        sid = args[4]
        snap = next((x for x in state.get("snapshots", []) if x.get("ID") == sid), None)
        if not snap:
            raise CommandError(f"Failed to delete snapshot with name or ID '{sid}': No snapshot with a name or ID of '{sid}' exists.")
        if snap.get("Status") not in ("available", "error"):
            raise CommandError("Invalid snapshot: Snapshot status must be available or error. (HTTP 400)")
        snap["Status"] = "deleting"
        return ""
    if words[:3] == ["openstack", "volume", "delete"]:
        vol = volumes.get(args[3])
        if not vol:
            raise CommandError(f"Failed to delete volume with name or ID '{args[3]}': No volume with a name or ID of '{args[3]}' exists.")
        if vol["status"] not in ("available", "error", "error_restoring", "error_extending", "error_managing") or vol.get("attachments"):
            raise CommandError(f"Invalid volume: Volume status must be available or error or error_restoring or error_extending or "
                               f"error_managing and must not be migrating, attached, belong to a group, have snapshots or be "
                               f"disassociated from snapshots after volume transfer. (HTTP 400)")
        if any(snap.get("Volume") == vol["id"] for snap in state.get("snapshots", [])):
            raise CommandError("Invalid volume: Volume still has 1 dependent snapshots. (HTTP 400)")
        vol["status"] = "deleting"
        return ""
    if words[:3] == ["openstack", "volume", "set"]:
        vol = volumes.get(args[-1])
        if not vol:
            raise CommandError(f"No volume with a name or ID of '{args[-1]}' exists.")
        for item in opts.get("--image-property", []):
            key, _, value = item.partition("=")
            vol.setdefault("volume_image_metadata", {})[key] = value
        return ""
    if words[:4] == ["openstack", "volume", "type", "list"]:
        return json.dumps(state.get("types", []))
    if words[:2] == ["cinder", "get-pools"]:
        # Format print_dict cinderclient: satu tabel Property/Value per pool, key urut abjad.
        tables = []
        for name, caps in state.get("pools", {}).items():
            rows = sorted(dict(caps, name=name).items())
            tables.append("\n".join(["+----------+-------+", "| Property | Value |", "+----------+-------+"]
                                    + [f"| {k} | {v} |" for k, v in rows] + ["+----------+-------+"]))
        return "\n".join(tables)
    if words[:3] == ["openstack", "project", "show"]:
        if words[3] not in projects:
            raise CommandError(f"No project with a name or ID of '{words[3]}' exists.")
        return json.dumps(projects[words[3]])
    if words[:3] == ["openstack", "token", "issue"]:
        token = {"id": "gAAAAA-token-secret", "project_id": scope, "user_id": state["admin"]["user_id"],
                 "expires": "2030-01-01T00:00:00+0000"}
        return token[option(words, "-c")] if option(words, "-f") == "value" else json.dumps(columns(token, words))
    if words[:2] == ["cinder", "--version"]:
        return "9.6.0"
    if words[:4] == ["openstack", "role", "assignment", "list"]:
        user, project = option(words, "--user"), option(words, "--project")
        return json.dumps([{"Role": r, "User": "admin@Default", "Project": projects[p]["name"] + "@Default"}
                           for u, p, r in state["roles"] if u == user and p == project])
    if words[:3] == ["openstack", "role", "add"]:
        state["roles"].append([option(words, "--user"), option(words, "--project"), words[-1]])
        return ""
    if words[:3] == ["openstack", "role", "remove"]:
        entry = [option(words, "--user"), option(words, "--project"), words[-1]]
        if entry not in state["roles"]:
            raise CommandError("Role assignment not found")
        state["roles"].remove(entry)
        return ""
    if words[:2] == ["cinder", "manage"]:
        host, identifier = words[-2], words[-1]
        if option(words, "--id-type") != "source-name":
            raise CommandError("--id-type must be source-name")
        pools = set(state.get("pools", {})) | {v["os-vol-host-attr:host"] for v in volumes.values()}
        if host not in pools:
            raise CommandError(f"ERROR: Host {host} is not valid (HTTP 400)")
        type_ref = option(words, "--volume-type", "")
        vtype = next((t for t in state.get("types", []) if type_ref in (t["ID"], t["Name"])), None)
        if type_ref and not vtype:
            raise CommandError(f"ERROR: Volume type with name {type_ref} could not be found. (HTTP 404)")
        backend = (vtype or {}).get("Properties", {}).get("volume_backend_name")
        manage_error = bool(backend and backend != state.get("pools", {}).get(host, {}).get("volume_backend_name", backend))
        new_id = str(uuid.uuid4())
        pool = host.split("#")[1]
        volumes[new_id] = {"id": new_id, "name": option(words, "--name", ""), "size": 100, "status": "creating",
                           "type": vtype["Name"] if vtype else "", "bootable": "true" if "--bootable" in words else "false",
                           "availability_zone": "nova", "os-vol-host-attr:host": host, "os-vol-tenant-attr:tenant_id": scope,
                           "attachments": [], "_manage_error": manage_error}
        if not manage_error:
            rename_lun(identifier, f"/vol/{pool}/volume-{new_id}")
        rows = [("id", new_id), ("name", volumes[new_id]["name"]), ("status", "creating"), ("size", "100")]
        line = "+--------------------------------+--------------------------------------+"
        return "\n".join([line, "| Property                       | Value                                |", line]
                         + [f"| {k:<30} | {v:<36} |" for k, v in rows] + [line])
    if head == "openstack volume transfer request create":
        vol = volumes[words[5]]
        if vol["status"] != "available":
            raise CommandError(f"Invalid volume: status must be available, but current status is: {vol['status']}")
        tid, key = str(uuid.uuid4()), uuid.uuid4().hex[:16]
        transfers[tid] = {"volume_id": words[5], "auth_key": key}
        vol["status"] = "awaiting-transfer"
        return json.dumps({"id": tid, "auth_key": key, "volume_id": words[5], "name": None})
    if head == "openstack volume transfer request accept":
        tid, key = positionals(words[5:])[0], option(words, "--auth-key")
        transfer = transfers.get(tid)
        if not transfer or transfer["auth_key"] != key:
            raise CommandError("Transfer not found or invalid auth key (HTTP 404)")
        if not any(u == state["admin"]["user_id"] and p == scope for u, p, _ in state["roles"]):
            raise CommandError(f"The request you have made requires authentication (HTTP 401): no role on project {scope}")
        vol = volumes[transfer.pop("volume_id")]
        del transfers[tid]
        vol.update({"status": "available", "os-vol-tenant-attr:tenant_id": scope})
        return json.dumps({"id": tid, "volume_id": vol["id"], "name": None})
    if head == "openstack volume transfer request delete":
        transfer = transfers.pop(words[5], None)
        if transfer:
            volumes[transfer["volume_id"]]["status"] = "available"
        return ""

    # ---------------- Nova / Neutron ----------------
    if words[:3] == ["openstack", "server", "show"]:
        sid = args[3]
        if sid not in servers:
            raise CommandError(f"No server with a name or ID of '{sid}' exists.")
        srv = servers[sid]
        if srv["status"] == "BUILD":   # build finishes on the next read
            srv["status"] = "ERROR" if srv.get("_fail") else "ACTIVE"
            if srv.get("_fail"):
                srv["fault"] = {"code": 500, "message": "No valid host was found. There are not enough hosts available."}
            return json.dumps(dict(server_view(state, sid), status="BUILD"))
        return json.dumps(server_view(state, sid))
    if words[:3] == ["openstack", "server", "list"]:
        project = option(words, "--project")
        rows = []
        for sid, srv in servers.items():
            if project and srv["project_id"] != project:
                continue
            view = server_view(state, sid)
            rows.append({"ID": sid, "Name": srv["name"], "Status": srv["status"], "Networks": view["addresses"],
                         "Image": view["image"], "Flavor": view["flavor"].split(" (")[0]})
        return json.dumps(rows)
    if words[:4] == ["openstack", "server", "volume", "list"]:
        sid = args[4]
        if sid not in servers:
            raise CommandError(f"No server with a name or ID of '{sid}' exists.")
        return json.dumps([{"ID": a["id"], "Device": a["device"], "Server ID": sid, "Volume ID": v["id"]}
                           for v in volumes.values() for a in v.get("attachments") or [] if a["server_id"] == sid])
    if words[:3] == ["openstack", "port", "list"]:
        sid = option(words, "--server")
        return json.dumps([{"ID": pid, "Name": port["name"], "MAC Address": port["mac_address"],
                            "Fixed IP Addresses": port["fixed_ips"], "Status": port["status"],
                            "Security Groups": port["security_group_ids"], "Device Owner": port["device_owner"], "Tags": []}
                           for pid, port in ports.items() if port["device_id"] == sid])
    if words[:3] == ["openstack", "port", "show"]:
        if args[3] not in ports:
            raise CommandError(f"No Port found for {args[3]}")
        return json.dumps(ports[args[3]])
    if words[:3] == ["openstack", "network", "list"]:   # --project <id> (its own networks) or --share, with --long
        project = option(words, "--project")
        return json.dumps([{"ID": n["id"], "Name": n["name"], "Status": "ACTIVE", "Project": n["project_id"], "State": "UP",
                            "Shared": n["shared"], "Subnets": n["subnets"], "Network Type": "vxlan",
                            "Router Type": "External" if n.get("router:external") else "Internal", "Availability Zones": [],
                            "Tags": []}
                           for n in networks.values()
                           if (not project or n["project_id"] == project) and ("--share" not in words or n["shared"])])
    if words[:3] == ["openstack", "subnet", "list"]:   # --project <id>, with --long
        project = option(words, "--project")
        return json.dumps([{"ID": sid, "Name": s.get("name", ""), "Network": s["network_id"], "Subnet": s["prefix"] + "0/24",
                            "Project": networks[s["network_id"]]["project_id"], "DHCP": True, "Name Servers": [],
                            "Allocation Pools": [{"start": s["prefix"] + "100", "end": s["prefix"] + "200"}], "Host Routes": [],
                            "IP Version": 4, "Gateway": s["prefix"] + "1", "Service Types": [], "Tags": []}
                           for sid, s in state["subnets"].items()
                           if not project or networks[s["network_id"]]["project_id"] == project])
    if words[:3] == ["openstack", "network", "show"]:
        if args[3] not in networks:
            raise CommandError(f"No Network found for {args[3]}")
        return json.dumps({k: v for k, v in networks[args[3]].items()})
    if words[:3] == ["openstack", "flavor", "show"]:
        ref = args[3]
        flavor = state["flavors"].get(ref) or next((f for f in state["flavors"].values() if f["name"] == ref), None)
        if not flavor:
            raise CommandError(f"No flavor with a name or ID of '{ref}' exists.")
        return json.dumps(flavor)
    if words[:4] == ["openstack", "security", "group", "list"]:
        project = option(words, "--project")
        return json.dumps([{"ID": g["id"], "Name": g["name"], "Description": "", "Project": g["project_id"], "Tags": []}
                           for g in state["security_groups"].values() if not project or g["project_id"] == project])
    if words[:3] == ["openstack", "port", "create"]:
        net_id = (opts.get("--network") or [""])[0]
        net = networks.get(net_id)
        if not net or not (net["shared"] or net["project_id"] == scope or admin_scope):
            raise CommandError(f"ResourceNotFound: 404: Unable to find network with name or id '{net_id}'")
        groups = [] if "--no-security-group" in opts else opts.get("--security-group", [])
        for gid in groups:
            if gid not in state["security_groups"] or state["security_groups"][gid]["project_id"] != scope:
                raise CommandError(f"ResourceNotFound: 404: Unable to find security_group with name or id '{gid}'")
        fixed = []
        for spec in opts.get("--fixed-ip", []):
            subnet_id = spec.split("=", 1)[1]
            subnet = state["subnets"].get(subnet_id)
            if not subnet or subnet["network_id"] != net_id:
                raise CommandError(f"Invalid input for operation: subnet {subnet_id} is not on network {net_id}")
            subnet["next"] += 1
            fixed.append({"subnet_id": subnet_id, "ip_address": subnet["prefix"] + str(subnet["next"])})
        if not fixed:
            subnet_id = net["subnets"][0]
            state["subnets"][subnet_id]["next"] += 1
            fixed.append({"subnet_id": subnet_id, "ip_address": state["subnets"][subnet_id]["prefix"] + str(state["subnets"][subnet_id]["next"])})
        if os.environ.get("FAKE_PORT_FAIL") and os.environ["FAKE_PORT_FAIL"] == net["name"]:
            raise CommandError("BadRequest: No more IP addresses available on network " + net_id)
        pid = str(uuid.uuid4())
        ports[pid] = {"id": pid, "name": args[-1], "network_id": net_id, "fixed_ips": fixed,
                      "mac_address": "fa:16:3e:" + pid[:2] + ":" + pid[2:4] + ":" + pid[4:6],
                      "security_group_ids": groups if "--enable-port-security" in opts else [],
                      "port_security_enabled": "--disable-port-security" not in opts,
                      "binding_vnic_type": (opts.get("--vnic-type") or ["normal"])[0], "device_id": "", "device_owner": "",
                      "project_id": scope, "status": "DOWN", "description": (opts.get("--description") or [""])[0]}
        return json.dumps(ports[pid])
    if words[:3] == ["openstack", "port", "delete"]:
        for pid in args[3:]:
            if pid not in ports:
                raise CommandError(f"Failed to delete port with name or ID '{pid}'")
            del ports[pid]
        return ""
    if words[:3] == ["openstack", "server", "create"]:
        flavor_ref = (opts.get("--flavor") or [""])[0]
        if flavor_ref not in state["flavors"]:
            raise CommandError(f"No flavor with a name or ID of '{flavor_ref}' exists.")
        vol = volumes.get((opts.get("--volume") or [""])[0])
        if not vol or vol["os-vol-tenant-attr:tenant_id"] != scope:
            raise CommandError("Volume could not be found (HTTP 404)")
        if vol["status"] != "available" or vol["bootable"] != "true":
            raise CommandError(f"Block Device Mapping is Invalid: volume {vol['id']} is {vol['status']} (bootable {vol['bootable']}) (HTTP 400)")
        nic_ports = [n.split("=", 1)[1] for n in opts.get("--nic", []) if n.startswith("port-id=")]
        for pid in nic_ports:
            if pid not in ports or ports[pid]["project_id"] != scope or ports[pid]["device_id"]:
                raise CommandError(f"Port {pid} is not usable for instance (HTTP 400)")
        # --block-device-mapping vdb=<volume ID>:volume::false: more volumes, attached when the instance is built.
        extra = []
        for mapping in opts.get("--block-device-mapping", []):
            device, _, spec = mapping.partition("=")
            parts = spec.split(":")
            other = volumes.get(parts[0])
            if len(parts) != 4 or parts[1] != "volume" or not other or other["os-vol-tenant-attr:tenant_id"] != scope:
                raise CommandError(f"Block Device Mapping is Invalid: {mapping} (HTTP 400)")
            if other["status"] != "available":
                raise CommandError(f"Invalid volume: volume {parts[0]} status must be available (HTTP 400)")
            extra.append((other, f"/dev/{device}"))
        sid = str(uuid.uuid4())
        props = dict(item.split("=", 1) for item in opts.get("--property", []))
        servers[sid] = {"id": sid, "name": args[-1], "status": "BUILD", "project_id": scope, "flavor_id": flavor_ref,
                        "image": "N/A (booted from volume)", "key_name": None,
                        "OS-EXT-AZ:availability_zone": (opts.get("--availability-zone") or ["nova"])[0],
                        "OS-EXT-SRV-ATTR:host": "compute-1", "config_drive": "True" if opts.get("--config-drive") else "",
                        "created": "2025-12-18T01:00:00Z", "properties": props, "security_groups": [{"name": "default"}],
                        "_fail": bool(os.environ.get("FAKE_SERVER_ERROR"))}
        for pid in nic_ports:
            ports[pid].update(device_id=sid, device_owner="compute:nova", status="ACTIVE")
        attach(vol, sid, "/dev/vda")
        for other, device in extra:
            attach(other, sid, device)
        return json.dumps({"id": sid, "name": args[-1], "status": "BUILD"})
    if words[:3] == ["openstack", "server", "delete"]:
        sid = args[3]
        if sid not in servers or (not admin_scope and servers[sid]["project_id"] != scope):
            raise CommandError(f"No server with a name or ID of '{sid}' exists.")
        del servers[sid]
        for vid, vol in list(volumes.items()):   # Nova: a volume with delete_on_termination goes with the instance
            att = next((a for a in vol.get("attachments") or [] if a["server_id"] == sid), None)
            if not att:
                continue
            if att.get("delete_on_termination"):
                delete_lun(vol)
                del volumes[vid]
            else:
                vol["attachments"] = [a for a in vol["attachments"] if a["server_id"] != sid]
                vol["status"] = "in-use" if vol["attachments"] else "available"
        for port in ports.values():
            if port.get("device_id") == sid:
                port["device_id"] = ""
        return ""
    if words[:4] == ["openstack", "server", "remove", "volume"]:
        sid, vid = args[4], args[5]
        srv, vol = servers.get(sid), volumes.get(vid)
        if not srv:
            raise CommandError(f"No server with a name or ID of '{sid}' exists.")
        att = next((a for a in (vol or {}).get("attachments") or [] if a["server_id"] == sid), None)
        if not vol or not att:
            raise CommandError(f"Volume {vid} is not attached to server {sid} (HTTP 404)")
        if att["device"] == "/dev/vda" and "booted from volume" in str(srv.get("image") or ""):
            raise CommandError("Invalid volume: Can't detach root device volume (HTTP 403)")
        vol["attachments"] = [a for a in vol["attachments"] if a["server_id"] != sid]
        vol["status"] = "in-use" if vol["attachments"] else "available"
        return ""
    if words[:4] == ["openstack", "server", "add", "volume"]:
        sid, vid = args[4], args[5]
        srv, vol = servers.get(sid), volumes.get(vid)
        if not srv:
            raise CommandError(f"No server with a name or ID of '{sid}' exists.")
        if not admin_scope and srv["project_id"] != scope:
            raise CommandError(f"No server with a name or ID of '{sid}' exists.")
        if not vol or vol["os-vol-tenant-attr:tenant_id"] != srv["project_id"]:
            raise CommandError(f"Volume {vid} could not be found. (HTTP 404)")
        if vol["status"] != "available":
            raise CommandError(f"Invalid volume: volume {vid} status must be available (HTTP 400)")
        vol.update(status="attaching", _attach_to=sid, _attach_device_for=sid)
        return ""
    raise CommandError("Unknown command: " + " ".join(words), 2)


BATCH_PART_RE = re.compile(r"\( (.*?) \) 2>&1; printf '\\n@@OSB rc=%s@@\\n' \"\$\?\";")


def run_line(command, state):
    """One command line as the playbooks send it: parts joined with &&, `export`/`unset` for the project scope."""
    env, out = {}, ""
    if os.environ.get("FAKE_DIRECTOR_FAIL") and os.environ["FAKE_DIRECTOR_FAIL"] in command:
        raise CommandError("Simulated failure: " + os.environ["FAKE_DIRECTOR_FAIL"])
    for part in command.split(" && "):
        words = shlex.split(part)
        if words and words[0] == "export":
            env.update(w.split("=", 1) for w in words[1:])
        elif words and words[0] != "unset":
            out = run(words, env, state)
    return out


def main():
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    rc_path = os.environ.get("FAKE_DIRECTOR_RC", "~/overcloudrc")
    prefix = f"source {rc_path} && "
    if not command.startswith(prefix):
        print("overcloudrc has not been sourced", file=sys.stderr)
        return 97
    state_file = os.environ["FAKE_DIRECTOR_STATE"]
    rest = command[len(prefix):]
    with open(state_file, "a+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.seek(0)
        text = f.read()
        state = json.loads(text) if text.strip() else default_state(os.environ.get("FAKE_POOL_PREFIX", "DCAOPNSTACK"))
        rc, out = 0, ""
        if rest.startswith("{ ") or rest == "true":
            # tasks/openstack_batch.yml: every command in its own subshell, followed by its exit code.
            chunks = []
            for part in BATCH_PART_RE.findall(rest):
                state["calls"].append(part)
                try:
                    result, code = run_line(part, state), 0
                except CommandError as e:
                    result, code = str(e), e.rc
                chunks.append(f"{result}\n@@OSB rc={code}@@\n" if result else f"\n@@OSB rc={code}@@\n")
            out = "".join(chunks).rstrip("\n")
        else:
            state["calls"].append(rest)
            try:
                out = run_line(rest, state)
            except CommandError as e:
                print(str(e), file=sys.stderr)
                rc = e.rc
        f.seek(0)
        f.truncate()
        json.dump(state, f)
    if out:
        print(out)
    return rc


if __name__ == "__main__":
    sys.exit(main())

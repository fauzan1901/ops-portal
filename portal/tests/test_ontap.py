"""ONTAP Restore module of the Ops Portal (/ontap/): playbook filters (unit) and the full flow module -> Ansible ->
mock ONTAP + fake director, with the portal sign-in (fake Active Directory over LDAPS, fake Duo), module access per
account, and the ONTAP service accounts per site (Administration -> Credentials of the portal).

Run from the portal folder:

    .venv/bin/python -m unittest tests.test_ontap -v
"""
import json
import os
import re
import shlex
import shutil
import sqlite3
import ssl
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
import uuid
import warnings

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)   # portal/
MODULE_DIR = os.path.join(ROOT, "modules", "ontap")
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(MODULE_DIR, "playbooks", "filter_plugins"))

import fake_director  # noqa: E402
import fake_duo  # noqa: E402
import fake_sso  # noqa: E402
import fake_ldap  # noqa: E402
from mock_ontap import BOOT_VOLUME_ID, FULL_VOLUME_ID, NAMEID_BACKEND_ID, NAMEID_VOLUME_ID, VOLUME_ID, MockOntap, make_cert  # noqa: E402

TMP = tempfile.mkdtemp()
# Set before the portal is imported (settings.py reads them once). Only this module is loaded.
os.environ.update(PORTAL_SITES=os.path.join(TMP, "sites.yml"), PORTAL_DATA=os.path.join(TMP, "data"),
                  PORTAL_DB=os.path.join(TMP, "data", "portal.db"), PORTAL_AUTH=os.path.join(TMP, "auth.yml"),
                  PORTAL_CREDENTIALS_KEY=os.path.join(TMP, "credentials.key"), PORTAL_MODULES="ontap")
# AD accounts in the fake directory: admin is an administrator in auth.yml, operator2 is added on the Users page with
# the ONTAP Restore module, nora is added with another module only, outsider has a valid AD password but is not on the
# user list.
AD_USERS = {"admin": {"password": "secret", "display_name": "Test Admin"},
            "operator2": {"password": "secret", "display_name": "Olga Operator"},
            "nora": {"password": "secret", "display_name": "Nora Nomodule"},
            "outsider": {"password": "secret", "display_name": "Otto Outsider"}}
# A restore that was running when the portal stopped (written before the portal starts): reported as interrupted.
INTERRUPTED_VOLUME_ID = "99999999-9999-4999-8999-999999999999"
# ONTAP service accounts (Administration -> Credentials). Their names differ from the AD accounts, so the tests can tell who
# is recorded where; the mocks only accept these names. Site DCC has none.
SERVICE_ACCOUNTS = {"DCA": ("svc_restore", "secret"), "TKS": ("svc_restore", "secret"), "TKD": ("svc_restore", "secret"),
                    "TKR": ("svc_restore", "secret"), "DCB": ("svc_dcb", "dcb-secret")}


class FilterTest(unittest.TestCase):
    def test_filters(self):
        import restore_filters as f
        choices = f.snapshot_choices([{"name": "a", "create_time": "2025-12-17T12:05:00Z"},
                                      {"name": "b", "create_time": "2025-12-17T20:05:00+07:00"}], "2025-12-17 19:30", "+07:00")
        self.assertEqual([s["name"] for s in choices["snapshots"]], ["b", "a"])
        self.assertEqual(choices["snapshots"][1]["local_time"], "2025-12-17 19:05")
        self.assertEqual(choices["recommended"], "a")
        self.assertEqual(f.extract_json('Warning: {deprecated}\n{"id": 1}\ndone'), {"id": 1})
        table = "| Property | Value |\n| id       | 0f8e0bbc-ac30-4047-b974-b358acfacf62 |\n"
        self.assertEqual(f.cinder_table_id(table), "0f8e0bbc-ac30-4047-b974-b358acfacf62")
        # name_id: used only when present, different from the volume ID, and a UUID.
        self.assertEqual(f.volume_name_id({"id": VOLUME_ID, "os-vol-mig-status-attr:name_id": NAMEID_BACKEND_ID.upper()}), NAMEID_BACKEND_ID)
        self.assertEqual(f.volume_name_id({"id": VOLUME_ID, "name_id": NAMEID_BACKEND_ID}), NAMEID_BACKEND_ID)
        self.assertEqual(f.volume_name_id({"id": VOLUME_ID, "os-vol-mig-status-attr:name_id": VOLUME_ID}), "")
        self.assertEqual(f.volume_name_id({"id": VOLUME_ID, "os-vol-mig-status-attr:name_id": None}), "")
        self.assertEqual(f.volume_name_id({"id": VOLUME_ID, "os-vol-mig-status-attr:name_id": "x; rm -rf /"}), "")
        self.assertEqual(f.volume_name_id("not a dict"), "")
        # LUNs in clone/reclaimed FlexVols are ignored; if more than one remains, the one in the Cinder pool wins.
        lun = lambda vol: {"name": f"/vol/{vol}/volume-x", "location": {"volume": {"name": vol}}}
        found = [lun("CINDER_14_vol"), lun("CINDER_14_vol_clone_1"), lun("CINDER_14_Reclaimed_2")]
        self.assertEqual([l["name"] for l in f.lun_candidates(found, "CINDER_14_vol")], ["/vol/CINDER_14_vol/volume-x"])
        self.assertEqual(len(f.lun_candidates([lun("A"), lun("B")], "B")), 1)
        self.assertEqual(len(f.lun_candidates([lun("A"), lun("B")], "C")), 2)   # none in the pool: rejected later
        self.assertEqual(f.lun_candidates([lun("X_clone")], "X"), [])

    def test_pool_choices_same_type_with_capacity(self):
        import restore_filters as f

        def table(name, backend, total=None, free=None, **caps):
            rows = [("name", f"hostgroup@{backend}#{name}"), ("pool_name", name), ("volume_backend_name", backend),
                    ("netapp_mirrored", caps.pop("mirrored", "false")), ("QoS_support", "True"),
                    ("filter_function", "capabilities.utilization < 70"), ("utilization", caps.pop("utilization", "40"))]
            if total is not None:
                rows += [("total_capacity_gb", total), ("free_capacity_gb", free), ("provisioned_capacity_gb", total * 2),
                         ("max_over_subscription_ratio", "20.0")]
            return "\n".join(["+----------+-------+", "| Property | Value |", "+----------+-------+"]
                             + [f"| {k} | {v} |" for k, v in rows] + ["+----------+-------+"])
        pools = "\n".join([table("VOL_05", "ssd_standard", 10000.0, 3000.0),      # LUN pool, 70% used
                           table("VOL_06", "ssd_standard", 10000.0, 500.0),       # 95%: full
                           table("VOL_07", "ssd_standard", 10000.0, 8000.0, utilization="85"),
                           table("VOL_08", "ssd_standard", 10000.0, 9000.0),      # FlexVol in another SVM
                           table("VOL_09", "ssd_standard"),                       # no Cinder capacity: ONTAP is used
                           table("VOL_TEST50", "ssd_standard", 10000.0, 9900.0),  # test pool
                           table("VOL_05_clone_1", "ssd_standard", 10000.0, 9900.0),
                           table("VOL_10", "ssd_standard", 10000.0, 9000.0, mirrored="true"),   # fails the type specs
                           table("VOL_19", "nvme_premium", 10000.0, 9900.0)])     # another tier: never offered
        types = [{"ID": "T1", "Name": "standard", "Properties": {"volume_backend_name": "ssd_standard", "netapp_mirrored": "false",
                                                                 "netapp:qos_policy_group": "standard-volume"}},
                 {"ID": "T2", "Name": "old", "Properties": "netapp:qos_policy_group='x'"}]   # older OSC format, no backend
        vol = lambda name, svm, gib, size=10000, state="online": {"name": name, "svm": {"name": svm}, "state": state,
                                                                  "space": {"available": gib * GIB, "size": size * GIB}}
        GIB = 1024 ** 3
        flexvols = [vol("VOL_05", "SVM1", 3000), vol("VOL_06", "SVM1", 500), vol("VOL_07", "SVM1", 8000), vol("VOL_08", "SVM2", 9000),
                    vol("VOL_09", "SVM1", 1000, 10000), vol("VOL_TEST50", "SVM1", 9900), vol("VOL_10", "SVM1", 9000)]
        result = f.pool_choices(types, pools, "hostgroup@ssd_standard#VOL_05", "standard", flexvols, "SVM1", 50 * GIB)
        by = {p["flexvol"]: p for p in result["pools"]}
        self.assertEqual((result["pool_found"], result["backend"], result["max_used_percent"]), (True, "ssd_standard", 85.0))
        self.assertEqual([p["flexvol"] for p in result["pools"]], ["VOL_05", "VOL_06", "VOL_07", "VOL_08", "VOL_09", "VOL_TEST50"])
        self.assertTrue(by["VOL_05"]["current"] and by["VOL_05"]["selectable"])
        self.assertEqual((by["VOL_05"]["used_pct"], by["VOL_05"]["free_gb"], by["VOL_05"]["total_gb"]), (70.0, 3000.0, 10000.0))
        self.assertEqual(by["VOL_06"]["reason"], "full: 95.0% used (limit 85%)")
        self.assertTrue(by["VOL_07"]["selectable"])
        self.assertFalse(by["VOL_07"]["filter_ok"])   # NetApp filter_function (performance utilization) shown, not blocking
        self.assertEqual(by["VOL_08"]["reason"], "FlexVol is in another SVM (SVM2)")
        self.assertEqual((by["VOL_09"]["used_pct"], by["VOL_09"]["selectable"]), (90.0, False))   # from ONTAP: 9000 of 10000 GiB used
        self.assertEqual(by["VOL_TEST50"]["reason"], "test or unnumbered pool, not a restore target")
        self.assertEqual(result["selectable"], 2)
        # Not enough room for the LUN data; offline FlexVol; a limit from sites.yml.
        tight = f.pool_choices(types, pools, "hostgroup@ssd_standard#VOL_05", "standard",
                               flexvols[:2] + [vol("VOL_07", "SVM1", 20)], "SVM1", 50 * GIB)
        self.assertEqual(next(p for p in tight["pools"] if p["flexvol"] == "VOL_07")["reason"],
                         "not enough free space (20.0 GiB free, the LUN has 50.0 GiB of data)")
        offline = f.pool_choices(types, pools, "hostgroup@ssd_standard#VOL_05", "standard", [vol("VOL_05", "SVM1", 3000, state="offline")], "SVM1")
        self.assertEqual(offline["pools"][0]["reason"], "FlexVol is offline")
        strict = f.pool_choices(types, pools, "hostgroup@ssd_standard#VOL_05", "standard", flexvols, "SVM1", 0, 60)
        self.assertEqual(strict["pools"][0]["reason"], "full: 70.0% used (limit 60%)")
        # A type without volume_backend_name still stays in the backend of the LUN pool.
        loose = f.pool_choices(types, pools, "hostgroup@ssd_standard#VOL_05", "old", flexvols, "SVM1")
        self.assertNotIn("VOL_19", [p["flexvol"] for p in loose["pools"]])
        self.assertIn("VOL_10", [p["flexvol"] for p in loose["pools"]])   # no mirrored requirement in this type
        # The LUN pool itself is always listed (even a test pool: no lun move); unreadable capabilities: only that pool.
        in_test = f.pool_choices(types, pools, "hostgroup@ssd_standard#VOL_TEST50", "standard", flexvols, "SVM1")
        self.assertTrue(in_test["pools"][0]["current"] and in_test["pools"][0]["selectable"] and in_test["pools"][0]["test"])
        unknown = f.pool_choices(types, "", "hostgroup@ssd_standard#VOL_05", "standard", flexvols, "SVM1", 50 * GIB)
        self.assertEqual((unknown["pool_found"], [p["flexvol"] for p in unknown["pools"]]), (False, ["VOL_05"]))
        self.assertEqual((unknown["pools"][0]["used_pct"], unknown["pools"][0]["selectable"]), (70.0, True))

    def test_type_choices_and_allocated_capacity(self):
        import restore_filters as f
        GIB = 1024 ** 3

        def table(name, backend, total, free, allocated):
            rows = [("name", f"hostgroup@{backend}#{name}"), ("pool_name", name), ("volume_backend_name", backend),
                    ("netapp_mirrored", "false"), ("total_capacity_gb", total), ("free_capacity_gb", free),
                    ("allocated_capacity_gb", allocated), ("max_over_subscription_ratio", "20.0")]
            return "\n".join(["+----------+-------+", "| Property | Value |", "+----------+-------+"]
                             + [f"| {k} | {v} |" for k, v in rows] + ["+----------+-------+"])
        pools = "\n".join([table("SSD_05", "ssd", 10000.0, 3000.0, 15000.0),       # LUN pool: 150% allocated at 1:1
                           table("SSD_06", "ssd", 10000.0, 6000.0, 5000.0),
                           table("NVME_01", "nvme", 10000.0, 8000.0, 4000.0),      # another tier, same SVM
                           table("ARCH_01", "archive", 10000.0, 8000.0, 1000.0)])  # another tier, another SVM
        types = [{"ID": "T1", "Name": "standard", "Is Public": True, "Properties": {"volume_backend_name": "ssd"}},
                 {"ID": "T2", "Name": "basic", "Is Public": True, "Properties": {"volume_backend_name": "ssd", "netapp:qos_policy_group": "basic"}},
                 {"ID": "T3", "Name": "nvme-premium", "Is Public": True, "Properties": {"volume_backend_name": "nvme"}},
                 {"ID": "T4", "Name": "archive", "Is Public": True, "Properties": {"volume_backend_name": "archive"}},
                 {"ID": "T5", "Name": "premium", "Is Public": True, "Description": "[Old Configuration - Dont use this volume type again]",
                  "Properties": {"netapp:qos_policy_group": "new-premium-volume", "netapp_mirrored": "false"}},
                 {"ID": "T6", "Name": "old-standard", "Is Public": False, "Properties": {"netapp_mirrored": "false"}},
                 {"ID": "T7", "Name": "__DEFAULT__", "Is Public": True, "Properties": {}}]
        vol = lambda name, svm, gib: {"name": name, "svm": {"name": svm}, "state": "online", "space": {"available": gib * GIB, "size": 10000 * GIB}}
        flexvols = [vol("SSD_05", "SVM1", 3000), vol("SSD_06", "SVM1", 6000), vol("NVME_01", "SVM1", 8000), vol("ARCH_01", "SVM2", 8000)]
        host = "hostgroup@ssd#SSD_05"
        self.assertEqual(f.pool_flexvols(pools, host), ["SSD_05", "SSD_06", "NVME_01", "ARCH_01"])
        # 1:1 (DCB, DCC): used = allocated / total, so the LUN pool is full although ONTAP still has room.
        one = f.type_choices(types, pools, host, "standard", flexvols, "SVM1", 50 * GIB, hidden=["premium"])
        self.assertEqual([(o["name"], o["original"], o["selectable"]) for o in one],
                         [("standard", True, 1), ("archive", False, 0), ("basic", False, 1), ("nvme-premium", False, 1)])
        std = {p["flexvol"]: p for p in one[0]["pools"]["pools"]}
        self.assertEqual((std["SSD_05"]["basis"], std["SSD_05"]["used_pct"], std["SSD_05"]["capacity_gb"]), ("allocated", 150.0, 10000.0))
        self.assertEqual(std["SSD_05"]["reason"], "full: 150.0% used (limit 85%)")
        self.assertEqual((std["SSD_06"]["used_pct"], std["SSD_06"]["selectable"]), (50.0, True))
        # 2:1 (DCA): capacity = total x 2.
        two = f.type_choices(types, pools, host, "standard", flexvols, "SVM1", 50 * GIB, overcommit_ratio=2, hidden=["premium"])
        lun_pool = two[0]["pools"]["pools"][0]
        self.assertEqual((lun_pool["current"], lun_pool["capacity_gb"], lun_pool["used_pct"], lun_pool["selectable"]), (True, 20000.0, 75.0, True))
        # Another type: only its own backend, reached with lun move (the LUN pool is not offered), same SVM only.
        nvme = next(o for o in two if o["name"] == "nvme-premium")["pools"]
        self.assertEqual(([p["flexvol"] for p in nvme["pools"]], nvme["same_type"], nvme["backend"]), (["NVME_01"], False, "nvme"))
        self.assertFalse(nvme["pools"][0]["current"])
        archive = next(o for o in two if o["name"] == "archive")["pools"]["pools"][0]
        self.assertEqual(archive["reason"], "FlexVol is in another SVM (SVM2)")
        # Without the hidden list the old public type (no backend) is offered with every pool that fits its rules.
        loose = [o["name"] for o in f.type_choices(types, pools, host, "standard", flexvols, "SVM1")]
        self.assertIn("premium", loose)
        self.assertNotIn("old-standard", loose)   # private
        self.assertNotIn("__DEFAULT__", loose)
        # A volume of a hidden type keeps its own type.
        self.assertEqual(f.type_choices(types, pools, host, "premium", flexvols, "SVM1", hidden=["premium"])[0]["name"], "premium")

    def test_site_settings_are_added_without_touching_the_rest(self):
        import importlib.util
        # deploy/site-settings.py of the portal; until it is there, the copy of ONTAP Restore (read only).
        path = next((p for p in (os.path.join(ROOT, "deploy", "site-settings.py"),
                                 os.path.join(os.path.dirname(ROOT), "ontap_restore", "deploy", "site-settings.py"))
                     if os.path.exists(p)), None)
        if not path:
            self.skipTest("deploy/site-settings.py not found")
        spec = importlib.util.spec_from_file_location("site_settings", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        wanted = {"overcommit_ratio": 2, "hidden_volume_types": ["premium", "standard"]}
        head = "# sites\nsites:\n  DCB:\n    ontap: {host: 10.253.0.1}\n    openstack: {transfer_role: member}\n\n"
        tail = "\n  DCC:\n    ontap: {host: 10.253.0.3}   # keep me\n"
        one_line = head + ("  DCA:\n    ontap: {host: 10.253.0.2}\n    # old types\n"
                           "    openstack: {transfer_role: member, hidden_volume_types: [premium, standard]}\n") + tail
        text, added = mod.add_settings(one_line, "DCA", wanted)
        self.assertEqual(added, ["overcommit_ratio"])   # an existing value is never changed
        self.assertIn("    openstack: {transfer_role: member, hidden_volume_types: [premium, standard], overcommit_ratio: 2}\n", text)
        self.assertEqual(text.replace(", overcommit_ratio: 2", ""), one_line)
        self.assertEqual(mod.add_settings(text, "DCA", wanted), (text, []))   # a second run changes nothing
        block = head + "  DCA:\n    openstack:\n      transfer_role: member\n    ontap: {host: 10.253.0.2}\n" + tail
        text, added = mod.add_settings(block, "DCA", wanted)
        self.assertIn("    openstack:\n      overcommit_ratio: 2\n      hidden_volume_types: [premium, standard]\n      transfer_role: member\n", text)
        without = head + "  DCA:\n    ontap: {host: 10.253.0.2}\n" + tail
        text, added = mod.add_settings(without, "DCA", wanted)
        self.assertIn("  DCA:\n    ontap: {host: 10.253.0.2}\n    openstack: {overcommit_ratio: 2, hidden_volume_types: [premium, standard]}\n\n  DCC:", text)
        self.assertTrue(text.endswith("# keep me\n") and text.startswith("# sites\n"))
        with self.assertRaises(SystemExit):
            mod.add_settings(without, "XYZ", wanted)

    def test_instance_parsers_for_old_and_new_openstack_cli(self):
        import restore_filters as f
        vid, boot, sid = "a80a1a07-06b8-489b-a984-b046981f68b9", "55555555-5555-4555-8555-555555555555", "5e000000-0000-4000-8000-000000000001"
        # Newer OSC: lists and dicts. Older OSC: text.
        new_server = {"id": sid, "name": "vm-01", "status": "ACTIVE", "project_id": "p1", "flavor": {"id": "f1", "links": []},
                      "image": "N/A (booted from volume)", "addresses": {"net-app": ["10.249.0.15"]},
                      "security_groups": [{"name": "default"}, {"name": "web"}], "volumes_attached": [{"id": boot}, {"id": vid}],
                      "properties": {"env": "prod"}, "OS-EXT-AZ:availability_zone": "az1", "key_name": "ops", "config_drive": "True"}
        old_server = dict(new_server, flavor="m1.medium (f1)", image="", addresses="net-app=10.249.0.15; net-db=10.248.0.8, fd00::8",
                          security_groups="name='default'\nname='web'", volumes_attached=f"id='{boot}'\nid='{vid}'",
                          properties="env='prod', owner='ops team'", config_drive="")
        ports = [{"ID": "pa", "Name": "", "MAC Address": "fa:16:3e:00:00:0a",
                  "Fixed IP Addresses": "ip_address='10.249.0.15', subnet_id='sa'", "Security Groups": "g1, g2"}]
        details = {"pa": {"network_id": "na", "fixed_ips": [{"subnet_id": "sa", "ip_address": "10.249.0.15"}], "mac_address": "fa:16:3e:00:00:0a",
                          "security_group_ids": ["g1", "g2"], "port_security_enabled": True, "binding_vnic_type": "normal"}}
        volume = {"id": vid, "attachments": [{"server_id": sid, "device": "/dev/vdb"}]}
        for server in (new_server, old_server):
            inst = f.instance_summary(server, ports, details, {"id": "f1", "name": "m1.medium", "vcpus": 2, "ram": 4096, "disk": 40},
                                      {"na": {"name": "net-app"}}, volume, [], [{"ID": "g1", "Name": "default"}, {"ID": "g2", "Name": "web"}])
            self.assertEqual((inst["flavor"]["id"], inst["flavor"]["vcpus"], inst["availability_zone"]), ("f1", 2, "az1"))
            self.assertTrue(inst["booted_from_volume"])
            self.assertEqual(inst["security_groups"], ["default", "web"])
            self.assertEqual(inst["ports"][0]["network_name"], "net-app")
            self.assertEqual(inst["ports"][0]["security_groups"], ["default", "web"])
            self.assertEqual([v["id"] for v in inst["volumes"]], [vid, boot])   # devices known first
            self.assertEqual(inst["properties"]["env"], "prod")
            self.assertEqual(f.volume_role(volume, inst), {"role": "extended", "device": "/dev/vdb", "server_id": sid})
        self.assertEqual(f.instance_summary(old_server)["addresses"], {"net-app": ["10.249.0.15"], "net-db": ["10.248.0.8", "fd00::8"]})
        self.assertEqual(f.instance_summary(old_server)["properties"], {"env": "prod", "owner": "ops team"})
        self.assertTrue(f.instance_summary(new_server)["config_drive"])
        # Text port data without port show: IPs and security groups from the port list row.
        bare = f.instance_summary(new_server, ports)
        self.assertEqual((bare["ports"][0]["ips"], bare["ports"][0]["security_group_ids"]), (["10.249.0.15"], ["g1", "g2"]))
        # Boot disk: vda of an instance booted from volume. An image-booted instance never has a boot volume.
        root = {"id": boot, "attachments": [{"server_id": sid, "device": "/dev/vda"}]}
        self.assertEqual(f.volume_role(root, f.instance_summary(new_server))["role"], "boot")
        self.assertEqual(f.volume_role(root, f.instance_summary(dict(new_server, image="cirros (i1)")))["role"], "extended")
        self.assertEqual(f.volume_role({"id": vid, "attachments": []})["role"], "detached")
        self.assertEqual(f.volume_attachment({"attachments": f"server_id='{sid}', device='/dev/vdc'"}), [sid, "/dev/vdc"])
        # server volume list gives the device of every volume.
        listed = f.instance_summary(new_server, volume=volume, server_volumes=[{"Volume ID": boot, "Device": "/dev/vda"}])
        self.assertEqual([(v["device"], v["role"]) for v in listed["volumes"]], [("/dev/vda", "boot"), ("/dev/vdb", "extended")])
        # Instances for "attach to an instance".
        choices = f.server_choices([{"ID": "s2", "Name": "b", "Status": "SHUTOFF"}, {"ID": sid, "Name": "a", "Status": "ERROR"}], sid)
        self.assertEqual([(c["name"], c["attachable"], c["original"]) for c in choices], [("a", False, True), ("b", True, False)])
        self.assertEqual(f.image_properties({"volume_image_metadata": {"hw_firmware_type": "uefi", "checksum": "", "bad key": "x"}}),
                         {"hw_firmware_type": "uefi"})
        self.assertEqual(f.image_property_args({"os_type": "linux", "hw_disk_bus": "virtio"}),
                         "--image-property hw_disk_bus=virtio --image-property os_type=linux")
        # Batch output: markers per command, optional commands may fail.
        cmds = [{"key": "a", "cmd": "x"}, {"key": "b", "cmd": "y", "optional": True}, {"key": "c", "cmd": "z", "label": "zeta"}]
        res = f.batch_results('{"id": 1}\n\n@@OSB rc=0@@\nboom\n\n@@OSB rc=1@@\nNo such thing\n\n@@OSB rc=2@@\n', cmds)
        self.assertEqual((res["complete"], res["failed"]), (True, ["zeta: No such thing"]))
        self.assertEqual(f.batch_json(res["results"]["a"]), {"id": 1})
        self.assertFalse(f.batch_results("ssh: connect to host refused", cmds)["complete"])
        self.assertEqual(f.batch_script([]), "true")

    def test_new_instance_plan_copies_the_existing_instance(self):
        import restore_filters as f
        inst = {"id": "s1", "name": "vm-01", "project_id": "p1", "availability_zone": "nova", "key_name": "ops", "config_drive": True,
                "flavor": {"id": "f1", "name": "m1.medium", "found": True, "public": True}, "properties": {"env": "prod"},
                "ports": [{"id": "pa", "network_id": "na", "network_name": "net-app", "subnet_ids": ["sa"], "ips": ["10.253.0.5"],
                           "security_group_ids": ["g1", "g2"], "security_groups": ["default", "web"], "port_security": True,
                           "vnic_type": "normal"},
                          {"id": "pb", "network_id": "nb", "network_name": "net-db", "subnet_ids": ["sb"], "ips": ["10.252.0.5"],
                           "security_group_ids": [], "security_groups": [], "port_security": False, "vnic_type": "normal"}]}
        nets = {"na": {"name": "net-app", "shared": False, "project_id": "p1"}, "nb": {"name": "net-db", "shared": True, "project_id": "adm"}}
        plan = f.new_instance_plan(inst, "boot", "p1", nets, "vm-01-restore")
        self.assertTrue(plan["possible"], plan["reason"])
        self.assertEqual([(p["network_id"], p["port_security"], [g["name"] for g in p["security_groups"]]) for p in plan["ports"]],
                         [("na", True, ["default", "web"]), ("nb", True, [])])
        self.assertIn("port 2 (net-db): port security is off on the original port", plan["warnings"][0])
        self.assertIn("key pair ops is not set again", plan["notes"][-1])
        args = f.port_create_args(plan["ports"][0], "vm-01-restore", "restore of port pa")
        self.assertEqual(args, "--network na --fixed-ip subnet=sa --enable-port-security --security-group g1 --security-group g2 "
                               "--description 'restore of port pa' vm-01-restore-port1")
        create = f.server_create_args(plan, "vol-1", ["p1", "p2"], "vm-01-restore", {"restore_snapshot": "hourly.1"})
        self.assertEqual(create, "--flavor f1 --volume vol-1 --nic port-id=p1 --nic port-id=p2 --availability-zone nova "
                                 "--config-drive True --property env=prod --property restore_snapshot=hourly.1 vm-01-restore")
        # Another project: default security group there, a network of the original project that is not shared is a warning.
        other = f.new_instance_plan(inst, "boot", "p2", nets, "x")
        self.assertTrue(other["possible"])
        self.assertEqual(other["ports"][0]["security_groups"], [])
        self.assertTrue(any("network net-app belongs to another project and is not shared" in w for w in other["warnings"]))
        # Not possible: not a boot volume, flavor deleted, no network interface.
        self.assertEqual(f.new_instance_plan(inst, "extended", "p1", nets)["reason"], "the volume is not the boot disk of an instance")
        gone = dict(inst, flavor={"id": "f1", "name": "m1.old", "found": False})
        self.assertEqual(f.new_instance_plan(gone, "boot", "p1", nets)["reason"], "flavor m1.old no longer exists")
        self.assertEqual(f.new_instance_plan(dict(inst, ports=[]), "boot", "p1", nets)["reason"],
                         "the existing instance has no network interface to copy")
        self.assertEqual(f.instance_name("vm 01/(x)", "restore-20251217-1905"), "vm-01-x-restore-20251217-1905")
        self.assertEqual(len(f.instance_name("v" * 80, "restore-20251217-1905")), 63)

    def test_parallel_batch_gives_the_same_results_as_one_after_the_other(self):
        """Read-only batches may run several commands at the same time (sites.yml openstack.parallel_reads): in a real
        shell the results must be exactly those of the commands one after the other, in the same order."""
        import subprocess
        import restore_filters as f
        cmds = [{"key": "a", "cmd": "echo one"}, {"key": "b", "cmd": "echo two >&2; exit 3"},
                {"key": "c", "cmd": "sleep 0.4; echo three"}, {"key": "d", "cmd": "export X=1 && echo \"x=$X\""},
                {"key": "e", "cmd": "echo \"x=${X:-unset}\" 'quoted arg'"}, {"key": "g", "cmd": "sleep 0.4; printf 'no newline'"},
                {"key": "h", "cmd": "sleep 0.4"}, {"key": "i", "cmd": "sleep 0.4; echo last"}]
        work = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, work, True)

        def run(width, shell="/bin/bash", **env):
            start = time.time()
            out = subprocess.run([shell, "-c", f.batch_script(cmds, width)], capture_output=True, text=True,
                                 env=dict(os.environ, TMPDIR=work, **env), timeout=30).stdout
            return f.batch_results(out, cmds), time.time() - start
        sequential, slow = run(1)
        self.assertEqual({k: (v["rc"], v["out"]) for k, v in sequential["results"].items()},
                         {"a": (0, "one\n"), "b": (3, "two\n"), "c": (0, "three\n"), "d": (0, "x=1\n"), "e": (0, "x=unset quoted arg\n"),
                          "g": (0, "no newline"), "h": (0, ""), "i": (0, "last\n")})
        for shell in ("/bin/bash", "/bin/sh"):
            parallel, fast = run(4, shell)
            self.assertEqual(parallel, sequential, shell)
            self.assertLess(fast, slow - 0.4, shell)   # 4 sleeps of 0.4 s in 2 rounds instead of one after the other
        self.assertEqual(os.listdir(work), [])   # the temporary folder is removed
        # Without a temporary folder (mktemp fails) the commands run one after the other, with the same results.
        fake_bin = os.path.join(work, "bin")
        os.mkdir(fake_bin)
        with open(os.path.join(fake_bin, "mktemp"), "w") as fh:
            fh.write("#!/bin/sh\nexit 1\n")
        os.chmod(os.path.join(fake_bin, "mktemp"), 0o755)
        fallback, took = run(4, PATH=fake_bin + os.pathsep + os.environ["PATH"])
        self.assertEqual(fallback, sequential)
        self.assertGreater(took, 1.5)
        # One command, or width 1: exactly the script of before.
        self.assertEqual(f.batch_script(cmds[:1], 4), "{ ( echo one ) 2>&1; printf '\\n@@OSB rc=%s@@\\n' \"$?\"; }")
        self.assertEqual([f.parallel_width(v) for v in (None, True, False, 0, 1, 3, 20, "true", "false", "x")],
                         [4, 4, 1, 1, 1, 3, 8, 4, 1, 1])

    def test_new_instance_uses_the_networks_of_the_target_project(self):
        import restore_filters as f
        inst = {"id": "s1", "name": "vm-01", "project_id": "p1", "flavor": {"id": "f1", "name": "m1", "found": True, "public": True},
                "ports": [{"id": "pa", "network_id": "na", "network_name": "vpc-test", "subnet_ids": ["sa"], "ips": ["10.253.0.5"],
                           "security_group_ids": ["g1"], "security_groups": ["web"], "port_security": True, "vnic_type": "normal"},
                          {"id": "pb", "network_id": "nb", "network_name": "net-db", "subnet_ids": ["sb"], "ips": ["10.252.0.5"],
                           "security_group_ids": ["g1"], "security_groups": ["web"], "port_security": True, "vnic_type": "normal"}]}
        nets = {"na": {"name": "vpc-test", "shared": False, "project_id": "p1"}, "nb": {"name": "net-db", "shared": True, "project_id": "adm"}}
        entry = lambda rows: {"rc": 0, "out": json.dumps(rows), "ok": True}
        net = lambda nid, name, project, subnets, shared=False: {"ID": nid, "Name": name, "Status": "ACTIVE", "Project": project,
                                                                 "State": "UP", "Shared": shared, "Subnets": subnets, "Router Type": "Internal"}
        osb = {"results": {"tnets": entry([net("v1", "vpc-b", "p2", ["s1"]), net("v2", "vpc-a", "p2", ["s2", "s3"])]),
                           "tsubnets": entry([{"ID": "s1", "Name": "b", "Subnet": "10.246.0.0/24", "IP Version": 4},
                                              {"ID": "s2", "Name": "a6", "Subnet": "fd00::/64", "IP Version": 6},
                                              {"ID": "s3", "Name": "a4", "Subnet": "10.245.0.0/24", "IP Version": 4}]),
                           "snets": entry([net("nb", "net-db", "adm", ["sb"], True)])}}
        options = f.network_options(osb, "p2")
        # Own networks (VPCs) first, IPv4 subnets first; subnets of a shared network are only known by ID.
        self.assertEqual([(n["id"], n["own"], [s["cidr"] for s in n["subnets"]]) for n in options["networks"]],
                         [("v2", True, ["10.245.0.0/24", "fd00::/64"]), ("v1", True, ["10.246.0.0/24"]), ("nb", False, [""])])
        self.assertEqual(f.network_options({"results": {"tnets": {"rc": 1, "out": "denied", "ok": False}}}, "p2"),
                         {"read": False, "networks": []})
        # Review: vpc-test cannot be used in p2 and p2 has two VPCs: the operator chooses; the shared net-db stays.
        plan = f.new_instance_plan(inst, "boot", "p2", nets, "x", options)
        self.assertTrue(plan["possible"], plan["reason"])
        self.assertEqual((plan["choose"], plan["same_project"], plan["networks_read"]), ([1], False, True))
        self.assertEqual([(p["network_id"], p["original_usable"], p["subnet_ids"], p["security_groups"]) for p in plan["ports"]],
                         [("", False, [], []), ("nb", True, ["sb"], [])])
        # One VPC only: it is taken.
        single = f.new_instance_plan(inst, "boot", "p2", nets, "x", dict(options, networks=options["networks"][1:]))
        self.assertEqual([(p["network_id"], p["subnet_ids"]) for p in single["ports"]], [("v1", ["s1"]), ("nb", ["sb"])])
        # Restore run (strict): the choices are checked again.
        run = lambda choices: f.new_instance_plan(inst, "boot", "p2", nets, "x", options, choices, True)
        self.assertEqual(run([])["reason"], "network interface 1 (vpc-test): choose a network of the target project")
        self.assertIn("network na is not a network of the target project", run([{"network_id": "na"}])["reason"])
        self.assertIn("subnet s1 is not on network vpc-a", run([{"network_id": "v2", "subnet_id": "s1"}])["reason"])
        chosen = run([{"network_id": "v2"}, {}])
        self.assertTrue(chosen["possible"], chosen["reason"])
        self.assertEqual([(p["network_id"], p["network_name"], p["subnet_ids"], p["port_security"]) for p in chosen["ports"]],
                         [("v2", "vpc-a", ["s3"], True), ("nb", "net-db", ["sb"], True)])   # the IPv4 subnet by default
        self.assertEqual(run([{"network_id": "v2", "subnet_id": "s2"}, {}])["ports"][0]["subnet_ids"], ["s2"])
        self.assertEqual(f.port_create_args(chosen["ports"][0], "x"), "--network v2 --fixed-ip subnet=s3 --enable-port-security x-port1")
        # No network at all in the target project: not possible.
        none = f.new_instance_plan(inst, "boot", "p2", nets, "x", {"read": True, "networks": []})
        self.assertFalse(none["possible"])
        self.assertIn("vpc-test cannot be used in the target project, and the project has no network", none["reason"])
        # Same project: the original networks, subnets and security groups.
        same = f.new_instance_plan(inst, "boot", "p1", nets, "x", {"read": True, "networks": [
            {"id": "na", "name": "vpc-test", "own": True, "subnets": [{"id": "sa", "cidr": "10.253.0.0/24", "ip_version": "4"}]},
            options["networks"][2]]})
        self.assertEqual([(p["network_id"], p["subnet_ids"], [g["name"] for g in p["security_groups"]]) for p in same["ports"]],
                         [("na", ["sa"], ["web"]), ("nb", ["sb"], ["web"])])


class WebUiTest(unittest.TestCase):
    auth_writes = 0

    @classmethod
    def setUpClass(cls):
        # ldap3 tries ::1 first for "localhost" (the fake AD listens on 127.0.0.1 only) and does not close that refused
        # socket. Only that third-party warning is hidden; the runner restores the filters after the run.
        warnings.filterwarnings("ignore", message=r"unclosed <socket\.socket .*laddr=\('::1'", category=ResourceWarning)
        cert, key = make_cert(TMP)
        cls.dca = MockOntap("DCA-ONTAP", cert, key, user="svc_restore").start()
        cls.dcb = MockOntap("DCB-ONTAP", cert, key, user="svc_dcb", password="dcb-secret").start()   # own account per site
        # Fake Active Directory (LDAPS) and Duo, with a certificate valid for localhost.
        cls.ad_cert, ad_key = fake_ldap.make_cert(TMP)
        cls.ldap = fake_ldap.FakeLdap(cls.ad_cert, ad_key, AD_USERS).start()
        cls.duo = fake_duo.FakeDuo(cls.ad_cert, ad_key).start()
        cls.sso = fake_sso.FakeSso(cls.ad_cert, ad_key, approve_as="operator2").start()
        cls.write_auth()
        director = f"{sys.executable} {os.path.join(HERE, 'fake_director.py')}"
        # A director that refuses the login (like ssh admin@director when the user is stack): ssh stderr, exit code 255.
        denied = os.path.join(TMP, "denied.sh")
        with open(denied, "w") as f:
            f.write("echo \"Warning: Permanently added 'director.test' (ED25519) to the list of known hosts.\" >&2\n"
                    "echo 'admin@director.test: Permission denied (publickey,gssapi-keyex,password).' >&2\nexit 255\n")
        # Site TKR: like DCA, but the batch scripts run in a real bash, as `ssh stack@director '<script>'` does on the
        # sites. openstack and cinder are shims that pass each command to the fake director and log when it ran.
        shims, cls.shim_log = os.path.join(TMP, "shims"), os.path.join(TMP, "shims.log")
        os.makedirs(shims, exist_ok=True)
        for name in ("openstack", "cinder"):
            path = os.path.join(shims, name)
            with open(path, "w") as f:
                f.write(f"""#!{sys.executable}
import os, shlex, subprocess, sys, time
parts = ["source " + os.environ.get("FAKE_DIRECTOR_RC", "~/overcloudrc")]
if os.environ.get("OS_PROJECT_ID"):
    parts.append("export OS_PROJECT_ID=" + shlex.quote(os.environ["OS_PROJECT_ID"]))
parts.append(shlex.join([{name!r}] + sys.argv[1:]))
start = time.time()
rc = subprocess.call([sys.executable, {os.path.join(HERE, 'fake_director.py')!r}, " && ".join(parts)])
with open({cls.shim_log!r}, "a") as log:
    log.write(f"{{start:.3f}} {{time.time():.3f}} {name} {{' '.join(sys.argv[1:3])}}\\n")
sys.exit(rc)
""")
            os.chmod(path, 0o755)
        overcloudrc = os.path.join(TMP, "overcloudrc")
        with open(overcloudrc, "w") as f:
            f.write("export OS_CLOUD=fake\n")
        with open(os.environ["PORTAL_SITES"], "w") as f:
            f.write(f"""sites:
  TKR:
    timezone: "+07:00"
    ontap: {{host: "{cls.dca.host}", validate_certs: false}}
    mgmt: {{host: localhost, connection: local}}
    director: {{host: director.test, user: stack, overcloudrc: "{overcloudrc}", command: "env PATH={shims}:$PATH bash -c"}}
  DCA:
    timezone: "+07:00"
    ontap: {{host: "{cls.dca.host}", validate_certs: false, used_poll_seconds: 1, used_stable_seconds: 3, used_wait_seconds: 60,
             move_poll_seconds: 1, move_retry_delay_seconds: 1, move_settle_seconds: 2, move_patch_timeout_seconds: 1}}
    mgmt: {{host: localhost, connection: local}}
    director: {{host: director.test, user: stack, command: "{director}"}}
  TKS:
    ontap: {{host: "{cls.dca.host}", used_poll_seconds: 1, used_stable_seconds: 0, used_wait_seconds: 4}}
    mgmt: {{host: localhost, connection: local}}
    director: {{host: director.test, user: stack, command: "{director}"}}
    openstack: {{transfer_role: member, overcommit_ratio: 2, hidden_volume_types: [netapp-basic]}}
  DCB:
    ontap: {{host: "{cls.dcb.host}"}}
    mgmt: {{host: localhost, connection: local}}
    director: {{host: director.test, user: stack, command: "{director}"}}
  TKD:
    ontap: {{host: "{cls.dca.host}"}}
    mgmt: {{host: localhost, user: admin, connection: local}}
    director: {{host: director.test, user: admin, command: "sh {denied}"}}
  DCC:
    ontap: {{host: "{cls.dcb.host}"}}
    mgmt: {{host: localhost, connection: local}}
    director: {{host: director.test, user: stack, command: "{director}"}}
  ACI1:
    apic: {{host: apic.test}}
""")
        cls.state_file = os.path.join(TMP, "director.json")
        os.environ.update(FAKE_DIRECTOR_STATE=cls.state_file, FAKE_ONTAP_URL=f"https://{cls.dca.host}")
        # A restore of the previous run of the portal that never finished (the process stopped during the restore).
        os.makedirs(os.path.join(TMP, "data"), exist_ok=True)
        with sqlite3.connect(os.environ["PORTAL_DB"]) as db:
            db.execute("""CREATE TABLE restores (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, finished TEXT, username TEXT NOT NULL, site TEXT NOT NULL,
                volume_id TEXT NOT NULL, volume_name TEXT, snapshot TEXT NOT NULL, snapshot_time TEXT, project_id TEXT,
                project_name TEXT, restore_path TEXT, new_volume_id TEXT, new_volume_name TEXT, transfer_id TEXT,
                status TEXT NOT NULL, error TEXT, log TEXT, client_ip TEXT)""")
            db.execute("INSERT INTO restores (ts, username, site, volume_id, snapshot, status, client_ip) VALUES (?,?,?,?,?,?,?)",
                       ("2025-12-17T19:00:00+07:00", "operator2", "DCA", INTERRUPTED_VOLUME_ID, "hourly.2025-12-17_1805",
                        "running", "10.252.2.3"))
        import app as portal_app
        from modules.ontap import views
        cls.portal = portal_app
        cls.webapp = views   # the module (its PORTAL is the portal's)
        cls.app = portal_app.app
        # The administrator from auth.yml enters the ONTAP service accounts (each one is tested against ONTAP right
        # away), adds operator2 with the ONTAP Restore module, and nora with another module only.
        admin = cls.app.test_client()
        r = admin.post("/api/login", json={"username": "admin", "password": "secret"})
        if r.status_code != 200:
            raise AssertionError(f"AD sign-in failed: {r.get_json()}")
        for site, (user, password) in SERVICE_ACCOUNTS.items():
            r = admin.post(f"/api/admin/credentials/ontap:{site}", json={"username": user, "password": password})
            if r.status_code != 200 or r.get_json()["test"]["ok"] is not True:
                raise AssertionError(f"Service account for {site} not saved: {r.get_json()}")
        r = admin.post("/api/admin/users", json={"username": "operator2", "role": "operator", "modules": ["ontap"]})
        if r.status_code != 200:
            raise AssertionError(f"operator2 not added: {r.get_json()}")
        # Only ONTAP Restore is loaded (PORTAL_MODULES=ontap): another module, so nora can be an operator without it.
        import core
        core.register("other", "Other module", "A module of the tests.", "/other/", "checklist")
        r = admin.post("/api/admin/users", json={"username": "nora", "role": "operator", "modules": ["other"]})
        if r.status_code != 200:
            raise AssertionError(f"nora not added: {r.get_json()}")

    @classmethod
    def tearDownClass(cls):
        cls.dca.stop()
        cls.dcb.stop()
        cls.ldap.stop()
        cls.duo.stop()
        cls.sso.stop()
        shutil.rmtree(TMP, ignore_errors=True)

    @classmethod
    def write_auth(cls, duo=False, sso=False):
        """auth.yml with the fake AD (and the fake Duo when duo=True); admin is the administrator from the file.
        sso=True: AD accounts sign in only through the fake Duo SSO (no ldap.url)."""
        cfg = {"ldap": {"url": [] if sso else [cls.ldap.url], "user_format": "{username}@example.local", "ca_file": cls.ad_cert,
                        "base_dn": "DC=example,DC=local", "timeout_seconds": 5},
               "duo": {"enabled": duo, "client_id": fake_duo.CLIENT_ID, "client_secret": fake_duo.CLIENT_SECRET,
                       "api_host": cls.duo.api_host, "ca_file": cls.ad_cert,
                       "redirect_uri": "https://restoreui.example.local:8081/auth/duo/callback"},
               "sso": {"enabled": sso, "issuer": cls.sso.issuer, "client_id": fake_sso.CLIENT_ID,
                       "client_secret": fake_sso.CLIENT_SECRET, "ca_file": cls.ad_cert,
                       "redirect_uri": "https://restoreui.example.local:8081/auth/sso/callback"},
               "admins": ["admin"]}
        path = os.environ["PORTAL_AUTH"]
        with open(path, "w") as f:
            json.dump(cfg, f)   # JSON is valid YAML
        cls.auth_writes += 1   # auth.yml is re-read when its modification time changes: give every write a new one
        stamp = time.time() + cls.auth_writes
        os.utime(path, (stamp, stamp))

    def setUp(self):
        if os.path.exists(self.state_file):
            os.remove(self.state_file)
        os.environ.pop("FAKE_DIRECTOR_FAIL", None)

    # ---- helper ----
    def client(self, username="admin", password="secret"):
        """A browser signed in with an AD account (Duo is off unless a test turns it on)."""
        client = self.app.test_client()
        r = client.post("/api/login", json={"username": username, "password": password})
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertNotIn("redirect", r.get_json())
        return client

    def follow_duo(self, url):
        """The browser part of Duo: open the authorize URL and return where Duo sends the browser back to."""
        ctx = ssl.create_default_context(cafile=self.ad_cert)

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None

        opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx), urllib.request.ProxyHandler({}))
        try:
            opener.open(url, timeout=10).close()
        except urllib.error.HTTPError as e:
            with e:
                if e.code == 302:
                    return e.headers["Location"]
            raise
        self.fail("Duo did not redirect back")

    def wait(self, client, job_id, timeout=180):
        deadline, lines = time.time() + timeout, []
        while time.time() < deadline:
            data = client.get(f"/ontap/api/jobs/{job_id}?since={len(lines)}").get_json()
            lines += data["lines"]
            if data["status"] != "running":
                data["all_lines"] = lines
                return data
            time.sleep(0.5)
        self.fail(f"Job {job_id} did not finish within {timeout}s")

    def plan(self, client, volume_id=VOLUME_ID, snapshot="hourly.2025-12-17_1905", project_id="", site="DCA"):
        r = client.post("/ontap/api/plan", json={"site": site, "volume_id": volume_id, "snapshot": snapshot, "project_id": project_id})
        self.assertEqual(r.status_code, 200, r.get_json())
        job_id = r.get_json()["job_id"]
        return job_id, self.wait(client, job_id)

    def director_state(self):
        with open(self.state_file) as f:
            return json.load(f)

    @staticmethod
    def pool(number, prefix="DCAOPNSTACK"):
        """Cinder host of a pool of the standard backend in the fake director (14 = the pool of the test LUNs)."""
        return f"hostgroup@{prefix.lower()}_faas500f#{prefix}_CINDER_{number}_vol"

    def restore(self, client, plan_id, **body):
        """POST /api/restore with the pool of the LUN unless another one is given."""
        return client.post("/ontap/api/restore", json=dict({"plan_job_id": plan_id, "confirm": True, "target_pool": self.pool(14)}, **body))

    def restore_events(self, history_id, until="restore.done", timeout=10):
        """Activity log entries of one restore, newest first (the finish entry is written right after the job ends)."""
        admin, deadline = self.client(), time.time() + timeout
        while True:
            events = admin.get("/api/admin/events?kinds=restore&limit=500").get_json()["events"]
            mine = [e for e in events if e["detail"].startswith(f"restore #{history_id},")]
            if any(e["action"] == until for e in mine) or time.time() > deadline:
                return mine
            time.sleep(0.2)

    # ---- login & page ----
    def test_page_and_ui_version(self):
        browser = self.app.test_client()
        r = browser.get("/ontap/")
        self.assertEqual(r.status_code, 200)   # the page itself needs no session: without one it opens the portal sign-in
        html = r.data.decode()
        version = re.search(r'<meta name="ui-version" content="([0-9a-f]{12})">', html).group(1)
        self.assertIn(f'src="/ontap/static/app.js?v={version}"', html)
        self.assertIn(f'href="/ontap/static/app.css?v={version}"', html)
        self.assertEqual(browser.get("/ontap/api/session").get_json()["ui_version"], version)
        # The module version is its own (its page, script and style), not the one of the portal pages.
        self.assertNotEqual(version, self.portal.UI_VERSION)
        # Application launcher of the portal in the masthead, just before the user menu; no sign-in form of its own.
        self.assertIn('<div id="portalLauncher" data-current="ontap"></div>\n      <div class="pf-masthead__user" id="userMenuWrap">', html)
        self.assertIn('<link rel="stylesheet" href="/static/switcher.css">', html)
        self.assertIn('<script src="/static/switcher.js"></script>', html)
        for gone in ('id="loginView"', 'id="loginForm"', 'id="page-users"', 'id="page-credentials"', 'id="addUserDialog"',
                     'id="credDialog"'):
            self.assertNotIn(gone, html)
        # Administration lives on the portal; "No access" is an empty state of the module page.
        self.assertIn('href="/#/users"', html)
        self.assertIn('href="/#/credentials"', html)
        self.assertIn("No access to ONTAP Restore", html)
        self.assertEqual(browser.get("/ontap").status_code, 308)   # /ontap -> /ontap/
        # Module files under /ontap/static/, fonts and the launcher from the portal.
        css = browser.get(f"/ontap/static/app.css?v={version}")
        self.assertEqual(css.status_code, 200)
        self.assertIn('url("/static/fonts/red-hat-text-latin-400-normal.woff2")', css.data.decode())
        self.assertNotIn('url("fonts/', css.data.decode())
        css.close()
        r = browser.get("/ontap/static/app.js")
        js = r.data.decode()
        r.close()
        self.assertIn("const BASE = '/ontap';", js)
        for gone in ("'/api/login'", "#loginForm", "'/api/admin/", "`/api/admin/"):   # the portal signs in, has Users and Credentials
            self.assertNotIn(gone, js)
        for path in ("/static/fonts/red-hat-text-latin-400-normal.woff2", "/static/switcher.js", "/static/switcher.css"):
            r = browser.get(path)
            self.assertEqual(r.status_code, 200, path)
            r.close()

    def test_module_access_per_account(self):
        """An operator without the ONTAP Restore module: the session says so (never 403), everything else is 403."""
        nora = self.client("nora")
        r = nora.get("/ontap/api/session")
        self.assertEqual(r.status_code, 200)
        status = r.get_json()
        self.assertEqual((status["user"]["username"], status["user"]["modules"], status["allowed"], status["sites"]),
                         ("nora", ["other"], False, []))   # no ONTAP addresses either
        for method, url, body in (("get", f"/ontap/api/snapshots?site=DCA&volume_id={VOLUME_ID}", None),
                                  ("post", "/ontap/api/volume_info", {"site": "DCA", "volume_id": VOLUME_ID}),
                                  ("post", "/ontap/api/plan", {"site": "DCA", "volume_id": VOLUME_ID, "snapshot": "x"}),
                                  ("post", "/ontap/api/restore", {"plan_job_id": "x", "confirm": True}),
                                  ("post", "/ontap/api/restore_group", {"volumes": [], "confirm": True}),
                                  ("get", "/ontap/api/restore_groups/1", None), ("get", "/ontap/api/jobs/x", None),
                                  ("get", "/ontap/api/history", None), ("get", "/ontap/api/history/1", None),
                                  ("get", "/ontap/api/deletions", None), ("get", "/ontap/api/deletions/summary", None),
                                  ("get", "/ontap/api/deletions/1", None), ("post", "/ontap/api/deletions/1/check", {}),
                                  ("get", "/ontap/export/jobs.csv", None)):
            r = getattr(nora, method)(url, json=body) if body is not None else getattr(nora, method)(url)
            self.assertEqual(r.status_code, 403, (method, url, r.get_json()))
            self.assertEqual(r.get_json()["error"],
                             "Your account has no access to ONTAP Restore. Ask an administrator to give it on the Users page.")
        # Administrators always use every module; operator2 was given this one.
        self.assertTrue(self.client().get("/ontap/api/session").get_json()["allowed"])
        self.assertTrue(self.client("operator2").get("/ontap/api/session").get_json()["allowed"])
        # An administrator ticks ONTAP Restore for nora: it works at once, without a new sign-in; and is taken away again.
        admin = self.client()
        try:
            self.assertEqual(admin.post("/api/admin/users/nora", json={"modules": ["other", "ontap"]}).status_code, 200)
            self.assertTrue(nora.get("/ontap/api/session").get_json()["allowed"])
            self.assertEqual(nora.get("/ontap/api/history").status_code, 200)
            self.assertIn("DCA", [s["name"] for s in nora.get("/ontap/api/session").get_json()["sites"]])
        finally:
            self.assertEqual(admin.post("/api/admin/users/nora", json={"modules": ["other"]}).status_code, 200)
        self.assertEqual(nora.get("/ontap/api/history").status_code, 403)
        self.assertFalse(nora.get("/ontap/api/session").get_json()["allowed"])
        # Not signed in at all: 401 with the session (no user), so the page opens the portal sign-in.
        r = self.app.test_client().get("/ontap/api/history")
        self.assertEqual(r.status_code, 401)
        self.assertEqual((r.get_json()["session"]["user"], r.get_json()["session"]["allowed"]), (None, False))

    def test_interrupted_restore_is_reported(self):
        """A restore that was running when the portal stopped: status unknown, and an activity entry for its user."""
        self.assertEqual([r["volume_id"] for r in self.webapp.INTERRUPTED], [INTERRUPTED_VOLUME_ID])
        client = self.client()
        item = client.get(f"/ontap/api/history/{self.webapp.INTERRUPTED[0]['id']}").get_json()["item"]
        self.assertEqual((item["status"], item["username"], item["site"]), ("unknown", "operator2", "DCA"))
        events = client.get("/api/admin/events?kinds=restore&limit=500").get_json()["events"]
        mine = [e for e in events if e["target"] == INTERRUPTED_VOLUME_ID]
        self.assertEqual([(e["action"], e["actor"], e["client_ip"]) for e in mine], [("restore.unknown", "operator2", "10.252.2.3")])
        self.assertIn("the web app stopped while the restore was running", mine[0]["detail"])

    def test_registered_with_the_portal(self):
        """The module on the portal home and its service accounts on Administration -> Credentials."""
        home = self.client().get("/api/session").get_json()
        ontap = next(m for m in home["modules"] if m["id"] == "ontap")
        self.assertEqual((ontap["title"], ontap["url"], ontap["icon"], ontap["allowed"]), ("ONTAP Restore", "/ontap/", "database", True))
        self.assertFalse(next(m for m in self.client("nora").get("/api/session").get_json()["modules"] if m["id"] == "ontap")["allowed"])
        credentials = self.client().get("/api/admin/credentials").get_json()["credentials"]
        ontap_targets = [c for c in credentials if c["module"] == "ontap"]
        # One per site with an ONTAP cluster; ACI1 (APIC only) is not an ONTAP Restore site.
        self.assertEqual([c["name"] for c in ontap_targets], [f"ontap:{s}" for s in ("TKR", "DCA", "TKS", "DCB", "TKD", "DCC")])
        self.assertEqual({k: ontap_targets[0][k] for k in ("label", "host", "kind", "site", "module_title")},
                         {"label": "ONTAP TKR", "host": self.dca.host, "kind": "ontap", "site": "TKR", "module_title": "ONTAP Restore"})
        # The updater asks /healthz how many jobs a restart would break: the ONTAP jobs count.
        health = self.client().get("/healthz").get_json()
        self.assertEqual((health["status"], health["running"]), ("ok", len(self.webapp.JOBS.running())))

    def test_service_accounts_per_site(self):
        # Signed out: no user and no site list (ONTAP addresses are only shown after sign-in).
        anonymous = self.app.test_client().get("/ontap/api/session").get_json()
        self.assertEqual((anonymous["user"], anonymous["allowed"], anonymous["sites"], anonymous["auth"]),
                         (None, False, [], {"method": "Active Directory", "duo": False, "local_accounts": False, "sso": False, "sso_label": "Sign in with Duo SSO", "ad_password": True, "ad_push": False, "problems": []}))
        client = self.client()
        status = client.get("/ontap/api/session").get_json()
        self.assertEqual({k: status["user"][k] for k in ("username", "display_name", "role", "mfa", "source")},
                         {"username": "admin", "display_name": "Test Admin", "role": "admin", "mfa": "none", "source": "ad"})
        self.assertTrue(status["allowed"])
        sites = {s["name"]: s for s in status["sites"]}   # sites with an ONTAP cluster only (not ACI1)
        self.assertEqual({name: s["configured"] for name, s in sites.items()},
                         {"TKR": True, "DCA": True, "TKS": True, "DCB": True, "TKD": True, "DCC": False})
        self.assertEqual(sites["DCB"]["host"], self.dcb.host)
        # A site without a service account: a clear message instead of an ONTAP error (HTTP 400).
        r = client.get(f"/ontap/api/snapshots?site=DCC&volume_id={VOLUME_ID}")
        self.assertEqual(r.status_code, 400)
        self.assertIn("The ONTAP DCC service account is not set", r.get_json()["error"])
        r = client.post("/ontap/api/plan", json={"site": "DCC", "volume_id": VOLUME_ID, "snapshot": "hourly.2025-12-17_1905"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("service account is not set", r.get_json()["error"])
        try:
            # A wrong stored password: the connection test says so, and ONTAP's 401 reaches the operator as an error.
            r = client.post("/api/admin/credentials/ontap:DCC", json={"username": "svc_dcb", "password": "wrong"})
            self.assertEqual(r.get_json()["test"], {"ok": False, "message": "wrong ONTAP username or password"})
            r = client.get(f"/ontap/api/snapshots?site=DCC&volume_id={VOLUME_ID}")
            self.assertEqual(r.status_code, 502)
            self.assertIn("ONTAP DCC refused the service account svc_dcb (wrong ONTAP username or password)", r.get_json()["error"])
            self.assertIn("Administration → Credentials", r.get_json()["error"])
        finally:
            self.assertEqual(client.delete("/api/admin/credentials/ontap:DCC").status_code, 200)
        try:
            # DCB only works with its own account: the DCA account is refused there.
            r = client.post("/api/admin/credentials/ontap:DCB", json={"username": "svc_restore", "password": "secret"})
            self.assertEqual(r.get_json()["test"]["ok"], False)
            self.assertEqual(client.get(f"/ontap/api/snapshots?site=DCB&volume_id={VOLUME_ID}").status_code, 502)
        finally:
            r = client.post("/api/admin/credentials/ontap:DCB", json={"username": "svc_dcb", "password": "dcb-secret"})
        self.assertEqual(r.get_json()["test"], {"ok": True, "message": "Connected to cluster DCB-ONTAP (NetApp Release 9.14.1P3)"})
        # One sign-in, every site: each with its own service account.
        self.assertEqual(client.get(f"/ontap/api/snapshots?site=DCB&volume_id={VOLUME_ID}").status_code, 200)
        self.assertEqual(client.get(f"/ontap/api/snapshots?site=DCA&volume_id={VOLUME_ID}").status_code, 200)
        listing = client.get("/api/admin/credentials").get_json()
        self.assertEqual({c["name"]: (c["username"], c["configured"]) for c in listing["credentials"]}["ontap:DCB"], ("svc_dcb", True))
        self.assertNotIn("dcb-secret", json.dumps(listing))   # passwords are never shown again

    def test_operators_and_accounts_not_on_the_list(self):
        operator = self.client("operator2")
        status = operator.get("/ontap/api/session").get_json()
        self.assertEqual((status["user"]["role"], status["user"]["display_name"]), ("operator", "Olga Operator"))
        self.assertEqual(operator.get(f"/ontap/api/snapshots?site=DCA&volume_id={VOLUME_ID}").status_code, 200)
        for method, url, body in (("get", "/api/admin/users", None), ("post", "/api/admin/users", {"username": "outsider"}),
                                  ("post", "/api/admin/users/operator2", {"role": "admin"}), ("get", "/api/admin/events", None),
                                  ("get", "/api/admin/credentials", None),
                                  ("post", "/api/admin/credentials/ontap:DCA", {"username": "x", "password": "y"}),
                                  ("post", "/api/admin/credentials/ontap:DCA/test", {}),
                                  ("delete", "/api/admin/credentials/ontap:DCA", None)):
            r = getattr(operator, method)(url, json=body) if body is not None else getattr(operator, method)(url)
            self.assertEqual(r.status_code, 403, (method, url, r.get_json()))
            self.assertEqual(r.get_json()["error"], "Only administrators can do this.")
        self.assertTrue(self.webapp.PORTAL.credential_configured("ontap:DCA"))
        # A valid AD password is not enough: the account must be on this application's user list.
        r = self.app.test_client().post("/api/login", json={"username": "outsider", "password": "secret"})
        self.assertEqual(r.status_code, 403)
        self.assertIn("not allowed to use Ops Portal", r.get_json()["error"])
        r = self.app.test_client().post("/api/login", json={"username": "operator2", "password": "wrong"})
        self.assertEqual((r.status_code, r.get_json()["error"]), (401, "Invalid username or password."))
        events = self.client().get("/api/admin/events").get_json()["events"]
        self.assertIn(("login.denied", "outsider"), [(e["action"], e["actor"]) for e in events])

    def test_activity_log_filters_and_client_address(self):
        forwarded = {"X-Portal-Client": "rdp=10.248.30.40;user=INTRANET%5Cjdoe"}
        bastion = {"REMOTE_ADDR": "172.26.0.100"}
        browser = self.app.test_client()
        # Without nginx in front (trusted_proxy off) the header is ignored: a browser cannot choose its own address.
        self.assertEqual(browser.get("/ontap/api/session", headers=forwarded, environ_base=bastion).get_json()["client"], "172.26.0.100")
        self.webapp.PORTAL.trusted_proxy = True
        try:
            # A browser on the bastion itself: the forwarder names its Remote Desktop session (via nginx).
            status = browser.get("/ontap/api/session", headers=forwarded, environ_base=bastion).get_json()
            self.assertEqual(status["client"], "172.26.0.100 (RDP 10.248.30.40, INTRANET\\jdoe)")
            r = browser.post("/api/login", json={"username": "operator2", "password": "secret"}, headers=forwarded, environ_base=bastion)
            self.assertEqual(r.status_code, 200, r.get_json())
            # Another computer: just its address.
            self.assertEqual(browser.get("/ontap/api/session", environ_base={"REMOTE_ADDR": "10.251.8.7"}).get_json()["client"], "10.251.8.7")
        finally:
            self.webapp.PORTAL.trusted_proxy = False
        admin = self.client()
        data = admin.get("/api/admin/events?actor=operator2&kinds=login&limit=1").get_json()
        self.assertEqual([(e["action"], e["actor"], e["client_ip"]) for e in data["events"]],
                         [("login.success", "operator2", "172.26.0.100 (RDP 10.248.30.40, INTRANET\\jdoe)")])
        self.assertTrue({"admin", "operator2"} <= set(data["actors"]))
        # Newest first, in pages: "before" continues below the last one shown.
        page1 = admin.get("/api/admin/events?limit=2").get_json()
        self.assertEqual((len(page1["events"]), page1["more"]), (2, True))
        page2 = admin.get(f"/api/admin/events?limit=2&before={page1['events'][-1]['id']}").get_json()
        self.assertLess(page2["events"][0]["id"], page1["events"][-1]["id"])
        only = admin.get("/api/admin/events?kinds=login,logout&limit=500").get_json()["events"]
        self.assertTrue(only and all(e["action"].startswith("login.") or e["action"] == "logout" for e in only))
        # Anything else than plain kind names is ignored.
        weird = admin.get("/api/admin/events?kinds=x%27)%20OR%201=1--&limit=3").get_json()
        self.assertEqual(len(weird["events"]), 3)
        # Administrators export the activity log with the same filters (CSV, for an audit); operators cannot.
        csv_text = admin.get("/export/events.csv?actor=operator2&kinds=login").data.decode()
        self.assertTrue(csv_text.startswith("ID,Time,User,Action,Target,Details,Client IP"), csv_text[:80])
        self.assertIn(",operator2,login.success,", csv_text)
        self.assertIn("172.26.0.100 (RDP 10.248.30.40, INTRANET\\jdoe)", csv_text)
        self.assertEqual(self.client("operator2").get("/export/events.csv").status_code, 403)

    def test_requires_login_and_json(self):
        client = self.app.test_client()
        r = client.get(f"/ontap/api/snapshots?site=DCA&volume_id={VOLUME_ID}")
        self.assertEqual(r.status_code, 401)
        self.assertIsNone(r.get_json()["session"]["user"])   # the page switches to the sign-in form
        self.assertEqual(client.post("/api/login", data={"username": "admin", "password": "secret"}).status_code, 400)
        client = self.client()
        self.assertEqual(client.get("/ontap/api/history").status_code, 200)
        self.assertEqual(client.post("/api/logout").status_code, 200)
        self.assertEqual(client.get("/ontap/api/history").status_code, 401)

    def test_duo_sign_in_through_this_app(self):
        self.write_auth(duo=True)
        try:
            client = self.app.test_client()
            self.assertTrue(client.get("/ontap/api/session").get_json()["auth"]["duo"])
            r = client.post("/api/login", json={"username": "operator2", "password": "secret"})
            self.assertEqual(r.status_code, 200, r.get_json())
            url = r.get_json()["redirect"]
            self.assertTrue(url.startswith(f"https://{self.duo.api_host}/oauth/v1/authorize?"), url)
            self.assertEqual(client.get("/ontap/api/history").status_code, 401)   # no session before Duo approves
            back = urllib.parse.urlsplit(self.follow_duo(url))
            self.assertEqual(back.path, "/auth/duo/callback")
            r = client.get(f"/auth/duo/callback?{back.query}")
            self.assertEqual((r.status_code, urllib.parse.urlsplit(r.headers["Location"]).path), (302, "/"))
            user = client.get("/ontap/api/session").get_json()["user"]
            self.assertEqual((user["username"], user["role"], user["mfa"]), ("operator2", "operator", "duo"))
            self.assertEqual(client.get(f"/ontap/api/snapshots?site=DCA&volume_id={VOLUME_ID}").status_code, 200)
            # Denied in Duo: back to the sign-in page with auth_error, and no session.
            self.duo.deny = True
            other = self.app.test_client()
            url = other.post("/api/login", json={"username": "admin", "password": "secret"}).get_json()["redirect"]
            r = other.get("/auth/duo/callback?" + urllib.parse.urlsplit(self.follow_duo(url)).query)
            location = urllib.parse.urlsplit(r.headers["Location"])
            self.assertEqual(location.path, "/")
            self.assertIn("Duo did not approve the sign-in", urllib.parse.parse_qs(location.query)["auth_error"][0])
            self.assertIsNone(other.get("/ontap/api/session").get_json()["user"])
        finally:
            self.duo.deny = False
            self.write_auth(duo=False)

    def test_duo_sso_sign_in_through_this_app(self):
        self.write_auth(sso=True)
        try:
            client = self.app.test_client()
            auth = client.get("/ontap/api/session").get_json()["auth"]
            self.assertEqual((auth["sso"], auth["ad_password"]), (True, False))
            r = client.post("/api/login", json={"username": "operator2", "password": "secret"})   # AD accounts: SSO only
            self.assertEqual(r.status_code, 400)
            self.assertIn("Duo SSO", r.get_json()["error"])
            r = client.get("/auth/sso/login")   # opened by another name: first moved to the host of redirect_uri
            self.assertEqual((r.status_code, r.headers["Location"]), (302, "https://restoreui.example.local:8081/auth/sso/login"))
            r = client.get("/auth/sso/login", base_url="https://restoreui.example.local:8081")
            self.assertEqual(r.status_code, 302)
            back = urllib.parse.urlsplit(self.follow_duo(r.headers["Location"]))
            self.assertEqual(back.path, "/auth/sso/callback")
            r = client.get(f"/auth/sso/callback?{back.query}", base_url="https://restoreui.example.local:8081")
            self.assertEqual((r.status_code, urllib.parse.urlsplit(r.headers["Location"]).path), (302, "/"))
            user = client.get("/ontap/api/session", base_url="https://restoreui.example.local:8081").get_json()["user"]   # the session cookie is per host
            self.assertEqual((user["username"], user["role"], user["mfa"]), ("operator2", "operator", "sso"))
            self.assertEqual(client.get(f"/ontap/api/snapshots?site=DCA&volume_id={VOLUME_ID}",
                                        base_url="https://restoreui.example.local:8081").status_code, 200)
        finally:
            self.write_auth()

    # ---- snapshot list (ONTAP API directly) ----
    def test_snapshots_listed_from_ontap(self):
        client = self.client()
        data = client.get(f"/ontap/api/snapshots?site=DCA&volume_id={VOLUME_ID.upper()}").get_json()
        self.assertTrue(data["ok"], data)
        # The LUN copy in FlexVol DCAOPNSTACK_CINDER_14_vol_clone_1 (a clone, not a Cinder pool) is ignored.
        self.assertEqual(data["lun"]["name"], f"/vol/DCAOPNSTACK_CINDER_14_vol/volume-{VOLUME_ID}")
        self.assertEqual(data["snapshots"][0], {"name": "hourly.2025-12-17_2005", "create_time": "2025-12-17T20:05:00+07:00",
                                                "local_time": "2025-12-17 20:05", "schedule": "hourly"})
        self.assertEqual(len(data["snapshots"]), 6)
        self.assertFalse(data["restore_path_exists"])
        r = client.get("/ontap/api/snapshots?site=DCA&volume_id=11111111-1111-4111-8111-111111111111")
        self.assertEqual(r.status_code, 400)
        self.assertIn("was not found in ONTAP DCA", r.get_json()["error"])
        self.assertEqual(client.get(f"/ontap/api/snapshots?site=DCC&volume_id={VOLUME_ID}").status_code, 400)   # no service account
        self.assertEqual(client.get("/ontap/api/snapshots?site=DCA&volume_id=not-a-uuid").status_code, 400)

    def test_snapshots_fall_back_to_name_id(self):
        client = self.client()
        # Regular volume: LUN volume-<ID> is found directly, OpenStack is not called at all.
        self.assertTrue(client.get(f"/ontap/api/snapshots?site=DCA&volume_id={VOLUME_ID}").get_json()["ok"])
        self.assertFalse(os.path.exists(self.state_file))
        # Retyped volume: LUN volume-<ID> does not exist, so name_id comes from openstack volume show.
        data = client.get(f"/ontap/api/snapshots?site=DCA&volume_id={NAMEID_VOLUME_ID}").get_json()
        self.assertTrue(data["ok"], data)
        self.assertEqual(data["name_id"], NAMEID_BACKEND_ID)
        self.assertEqual(data["lun"]["name"], f"/vol/DCAOPNSTACK_CINDER_14_vol/volume-{NAMEID_BACKEND_ID}")
        self.assertEqual(data["restore_path"], f"/vol/DCAOPNSTACK_CINDER_14_vol/volume-{NAMEID_BACKEND_ID}-restore")
        self.assertEqual(len(data["snapshots"]), 6)
        self.assertEqual(self.director_state()["calls"], [f"openstack volume show {NAMEID_VOLUME_ID} -f json"])

    # ---- full flow ----
    def test_plan_and_restore_use_name_id_lun(self):
        client = self.client()
        plan_id, plan = self.plan(client, volume_id=NAMEID_VOLUME_ID)
        self.assertEqual(plan["status"], "success", plan["error"] + "\n" + "\n".join(plan["all_lines"][-30:]))
        result = plan["result"]
        self.assertTrue(result["ready"], result["checks"])
        self.assertEqual((result["name_id"], result["lun"]["ref_id"]), (NAMEID_BACKEND_ID, NAMEID_BACKEND_ID))
        self.assertEqual(result["restore_path"], f"/vol/DCAOPNSTACK_CINDER_14_vol/volume-{NAMEID_BACKEND_ID}-restore")
        self.assertIn("TASK [Find LUN by OpenStack name_id]", "\n".join(plan["all_lines"]))
        r = self.restore(client, plan_id)
        self.assertEqual(r.status_code, 200, r.get_json())
        job = self.wait(client, r.get_json()["job_id"])
        self.assertEqual(job["status"], "success", job["error"] + "\n" + "\n".join(job["all_lines"][-30:]))
        call = self.dca.state()["cli_calls"][-1]
        self.assertEqual((call["path"], call["restore-path"]),
                         (f"/vol/DCAOPNSTACK_CINDER_14_vol/volume-{NAMEID_BACKEND_ID}",
                          f"/vol/DCAOPNSTACK_CINDER_14_vol/volume-{NAMEID_BACKEND_ID}-restore"))
        new_id = job["result"]["new_volume"]["id"]
        self.assertEqual(job["result"]["lun_path"], f"/vol/DCAOPNSTACK_CINDER_14_vol/volume-{new_id}")
        self.assertEqual(self.director_state()["volumes"][new_id]["os-vol-tenant-attr:tenant_id"], fake_director.CUSTOMER_PROJECT)

    def test_plan_then_restore_moves_volume_to_project(self):
        client = self.client()
        plan_id, plan = self.plan(client)
        self.assertEqual(plan["status"], "success", plan["error"] + "\n" + "\n".join(plan["all_lines"][-30:]))
        result = plan["result"]
        self.assertTrue(result["ready"])
        self.assertEqual(result["project"]["name"], "customer-a80")
        self.assertEqual(result["transfer"], {"needed": True, "temporary_role": "member"})
        self.assertEqual(result["default_new_name"], "vm-01-data-restore-20251217-1905")
        # volume show -> instance: VOLUME_ID is the extended disk (vdb) of vm-01.
        self.assertEqual(result["role"], {"role": "extended", "device": "/dev/vdb", "server_id": fake_director.SERVER_ID})
        self.assertEqual((result["instance"]["name"], result["instance"]["flavor"]["name"]), ("vm-01", "m1.medium"))
        self.assertFalse(result["after_restore"]["new_instance"]["possible"])   # not a boot volume
        # A pool must be chosen by the operator; none is picked automatically.
        self.assertEqual(self.restore(client, plan_id, target_pool="").get_json()["error"], "Select a Cinder pool first.")

        self.assertEqual(client.post("/ontap/api/restore", json={"plan_job_id": plan_id}).status_code, 400)   # without confirmation
        # The plan belongs to the portal session that made it: not another user, not even another session of admin.
        for other in (self.client("operator2"), self.client()):
            r = self.restore(other, plan_id)
            self.assertEqual((r.status_code, r.get_json()["error"]), (400, "Plan not found. Open the Review step again."))

        r = self.restore(client, plan_id, new_volume_name="vm-01-data-recovered")
        self.assertEqual(r.status_code, 200, r.get_json())
        body = r.get_json()
        job = self.wait(client, body["job_id"])
        self.assertEqual(job["status"], "success", job["error"] + "\n" + "\n".join(job["all_lines"][-30:]))
        new_id = job["result"]["new_volume"]["id"]
        self.assertEqual(job["result"]["lun_path"], f"/vol/DCAOPNSTACK_CINDER_14_vol/volume-{new_id}")
        # cinder manage only runs after the -restore LUN used space matches the existing LUN (30 GiB in the mock).
        self.assertEqual(job["result"]["used_wait"]["reason"], "match")
        self.assertEqual(job["result"]["used_wait"]["used"], job["result"]["used_wait"]["target"])
        progress = [l for l in job["all_lines"] if l.startswith("PROGRESS used=")]
        self.assertTrue(progress and progress[-1].startswith("PROGRESS used=32212254720 target=32212254720"), progress)

        state = self.director_state()
        self.assertEqual(state["volumes"][new_id]["os-vol-tenant-attr:tenant_id"], fake_director.CUSTOMER_PROJECT)
        self.assertEqual(state["volumes"][new_id]["name"], "vm-01-data-recovered")
        # cinder manage in the pool of the LUN with the original volume type; only transferred (no action after the restore).
        self.assertEqual((state["volumes"][new_id]["type"], job["result"]["new_volume"]["type"]), ("netapp-iscsi", "netapp-iscsi"))
        self.assertEqual(state["volumes"][new_id]["os-vol-host-attr:host"], self.pool(14))
        self.assertEqual((state["volumes"][new_id]["status"], job["result"]["after_restore"]), ("available", {}))
        self.assertNotIn([fake_director.ADMIN_USER, fake_director.CUSTOMER_PROJECT, "member"], state["roles"])
        calls = self.dca.state()["cli_calls"]
        self.assertEqual(calls[-1]["restore-path"], f"/vol/DCAOPNSTACK_CINDER_14_vol/volume-{VOLUME_ID}-restore")

        # Secrets (password, token, transfer auth key) never appear in the log.
        auth_key = re.search(r"--auth-key (\S+)", next(c for c in state["calls"] if "accept" in c)).group(1)
        log_text = "\n".join(job["all_lines"])
        for secret in ("secret", "gAAAAA-token-secret", auth_key):
            self.assertNotIn(secret, log_text)

        # The history names the AD user who launched it; ONTAP only saw the site's service account (svc_restore).
        item = client.get(f"/ontap/api/history/{body['history_id']}").get_json()["item"]
        self.assertEqual((item["status"], item["new_volume_id"], item["username"]), ("success", new_id, "admin"))
        self.assertEqual((item["volume_type"], item["cinder_pool"], item["move_flexvol"], item["post_action"]),
                         ("netapp-iscsi", self.pool(14), "", ""))
        self.assertEqual(item["job_id"], body["job_id"])   # the job page can follow a restore from history
        self.assertTrue(item["transfer_id"])
        self.assertNotIn(auth_key, item["log"])
        listing = client.get("/ontap/api/history?status=success").get_json()
        self.assertIn(body["history_id"], [x["id"] for x in listing["items"]])
        self.assertIn("admin", listing["users"])
        self.assertNotIn("svc_restore", listing["users"])
        # CSV export of the Jobs page with the same filters, for an audit.
        r = client.get("/ontap/export/jobs.csv", query_string={"status": "success", "q": new_id})
        self.assertEqual(r.status_code, 200)
        self.assertRegex(r.headers["Content-Disposition"], r'filename="ONTAP_Restore_Jobs_\d{8}-\d{4}\.csv"')
        lines = r.data.decode().splitlines()
        self.assertTrue(lines[0].startswith("ID,Started,Finished,User,Client IP,Site,Status,Volume ID,"), lines[0])
        self.assertEqual(len(lines), 2, lines)
        self.assertIn(f",{new_id},vm-01-data-recovered,netapp-iscsi,{self.pool(14)},", lines[1])
        self.assertEqual(self.app.test_client().get("/ontap/export/jobs.csv").status_code, 401)
        self.assertEqual(client.get("/ontap/export/jobs.csv?status=weird").status_code, 400)

    def test_plan_lists_same_type_pools_with_capacity(self):
        client = self.client("operator2")   # operators run restores too
        plan_id, plan = self.plan(client)
        self.assertEqual(plan["status"], "success", plan["error"] + "\n" + "\n".join(plan["all_lines"][-30:]))
        pools = plan["result"]["pools"]
        self.assertEqual((pools["pool_found"], pools["backend"], pools["type"], pools["selectable"]),
                         (True, "dcaopnstack_faas500f", "netapp-iscsi", 2))
        # Only pools of the standard backend (never nvme/archive); the LUN pool first; clones are not Cinder pools.
        by = {p["flexvol"]: p for p in pools["pools"]}
        self.assertEqual(list(by), ["DCAOPNSTACK_CINDER_14_vol", "DCAOPNSTACK_CINDER_15_vol", "DCAOPNSTACK_CINDER_16_vol",
                                    "DCAOPNSTACK_CINDER_17_vol", "DCAOPNSTACK_CINDER_TEST50_vol"])
        self.assertEqual((by["DCAOPNSTACK_CINDER_14_vol"]["current"], by["DCAOPNSTACK_CINDER_14_vol"]["used_pct"]), (True, 80.0))
        self.assertEqual(by["DCAOPNSTACK_CINDER_15_vol"]["reason"], "full: 99.9% used (limit 85%)")
        self.assertTrue(by["DCAOPNSTACK_CINDER_16_vol"]["selectable"])
        self.assertEqual(by["DCAOPNSTACK_CINDER_17_vol"]["reason"], "FlexVol is in another SVM (SVM_ARCHIVE)")
        self.assertEqual(by["DCAOPNSTACK_CINDER_TEST50_vol"]["reason"], "test or unnumbered pool, not a restore target")
        self.assertIn("2 of 5 Cinder pools of volume type netapp-iscsi can take the volume",
                      next(c["detail"] for c in plan["result"]["checks"] if c["key"] == "pool_available"))
        # Refused before anything runs: a full pool, a pool of another tier (without choosing that type), an unknown pool,
        # nothing selected.
        cli_before = len(self.dca.state()["cli_calls"])
        for pool, message in ((self.pool(15), "full: 99.9% used"),
                              ("hostgroup@dcaopnstack_nvme_premium#DCAOPNSTACK_NVME_01_vol", "not in the plan for this volume type"),
                              (self.pool(99), "not in the plan"), ("", "Select a Cinder pool first")):
            r = self.restore(client, plan_id, target_pool=pool)
            self.assertEqual(r.status_code, 400, r.get_json())
            self.assertIn(message, r.get_json()["error"])
        self.assertEqual(len(self.dca.state()["cli_calls"]), cli_before)

    def test_unreadable_pools_offer_only_the_lun_pool(self):
        client = self.client()
        os.environ["FAKE_DIRECTOR_FAIL"] = "cinder get-pools"
        plan_id, plan = self.plan(client)
        self.assertEqual(plan["status"], "success", plan["error"])
        self.assertTrue(plan["result"]["ready"], plan["result"]["checks"])   # restore into the LUN pool still works
        pools = plan["result"]["pools"]
        self.assertEqual((pools["pool_found"], [p["host"] for p in pools["pools"]]), (False, [self.pool(14)]))
        self.assertTrue(pools["pools"][0]["selectable"])
        r = self.restore(client, plan_id, target_pool=self.pool(16))
        self.assertEqual(r.status_code, 400)
        self.assertIn("not in the plan", r.get_json()["error"])

    def test_restore_playbook_refuses_pool_before_ontap(self):
        import subprocess
        cli_before = len(self.dca.state()["cli_calls"])
        env = dict(os.environ, ANSIBLE_CONFIG=os.path.join(MODULE_DIR, "playbooks", "ansible.cfg"), ANSIBLE_NOCOLOR="1",
                   ONTAP_USER="svc_restore", ONTAP_PASSWORD="secret")
        for extra, reason in (([], "No Cinder pool selected"),
                              (["-e", f"target_pool={self.pool(15)}"], "cannot take the volume: full: 99.9% used"),
                              (["-e", "target_pool=hostgroup@dcaopnstack_nvme_premium#DCAOPNSTACK_NVME_01_vol"],
                               "is not a Cinder pool of volume type netapp-iscsi"),
                              (["-e", f"target_pool={self.pool(14)}", "-e", "post_action=attach",
                                "-e", f"attach_server_id={fake_director.OTHER_SERVER_ID}"], "is not in project customer-a80")):
            run = subprocess.run([os.path.join(os.path.dirname(sys.executable), "ansible-playbook"), "restore.yml",
                                  "-e", "@" + os.environ["PORTAL_SITES"], "-e", "site=DCA", "-e", f"volume_id={VOLUME_ID}",
                                  "-e", "snapshot=hourly.2025-12-17_1905"] + extra,
                                 cwd=os.path.join(MODULE_DIR, "playbooks"), env=env, capture_output=True, text=True, timeout=180)
            self.assertNotEqual(run.returncode, 0)
            self.assertIn("Restore prerequisites are not met", run.stdout)
            self.assertIn(reason, run.stdout)
        self.assertEqual(len(self.dca.state()["cli_calls"]), cli_before)   # restore-file was not run
        self.assertFalse(any(c.startswith("cinder manage") for c in self.director_state()["calls"]))

    def test_restore_with_another_volume_type(self):
        client = self.client()
        plan_id, plan = self.plan(client)
        self.assertEqual(plan["status"], "success", plan["error"] + "\n" + "\n".join(plan["all_lines"][-30:]))
        result = plan["result"]
        options = {o["name"]: o for o in result["type_options"]}
        # The original type first; private types are not offered; a tier in another SVM is listed but cannot be used.
        self.assertEqual(result["type_options"][0]["name"], "netapp-iscsi")
        self.assertEqual(sorted(options), ["archive", "netapp-basic", "netapp-iscsi", "nvme-premium"])
        self.assertEqual(options["archive"]["selectable"], 0)
        nvme = options["nvme-premium"]["pools"]["pools"]
        self.assertEqual([p["flexvol"] for p in nvme], ["DCAOPNSTACK_NVME_01_vol", "DCAOPNSTACK_NVME_TEST99_vol"])
        self.assertEqual([p["selectable"] for p in nvme], [True, False])   # the test pool is never a target
        nvme_host = nvme[0]["host"]
        # A pool of the original type does not belong to another type; unknown, private and unusable types are refused.
        self.assertEqual(self.restore(client, plan_id, target_type="nvme-premium").get_json()["error"],
                         "The Cinder pool is not in the plan for this volume type. Click Check again in the Review step.")
        self.assertIn("cannot be used for this volume", self.restore(client, plan_id, target_type="standard-old").get_json()["error"])
        self.assertEqual(self.restore(client, plan_id, target_type="archive").get_json()["error"],
                         "No Cinder pool of volume type archive can take this volume.")
        r = self.restore(client, plan_id, target_type="nvme-premium", target_pool=nvme_host, new_volume_name="vm-01-data-nvme")
        self.assertEqual(r.status_code, 200, r.get_json())
        body = r.get_json()
        job = self.wait(client, body["job_id"])
        self.assertEqual(job["status"], "success", job["error"] + "\n" + "\n".join(job["all_lines"][-30:]))
        new_id = job["result"]["new_volume"]["id"]
        # lun move to the FlexVol of the other tier (same SVM), then cinder manage with the chosen type into that pool.
        self.assertEqual(job["result"]["lun_path"], f"/vol/DCAOPNSTACK_NVME_01_vol/volume-{new_id}")
        vol = self.director_state()["volumes"][new_id]
        self.assertEqual((vol["type"], vol["os-vol-host-attr:host"], job["result"]["new_volume"]["type"]),
                         ("nvme-premium", nvme_host, "nvme-premium"))
        self.assertTrue(any("--volume-type nvme-premium" in c for c in self.director_state()["calls"] if "cinder manage" in c))
        item = client.get(f"/ontap/api/history/{body['history_id']}").get_json()["item"]
        self.assertEqual((item["volume_type"], item["move_flexvol"]), ("nvme-premium", "DCAOPNSTACK_NVME_01_vol"))
        start = next(e["detail"] for e in self.restore_events(body["history_id"]) if e["action"] == "restore.start")
        self.assertIn("-> new volume vm-01-data-nvme (volume type changed to nvme-premium) in project", start)
        # Per site (sites.yml): TKS overcommits 2:1 and hides netapp-basic.
        _, tks = self.plan(client, site="TKS")
        self.assertEqual(tks["status"], "success", tks["error"])
        self.assertNotIn("netapp-basic", [o["name"] for o in tks["result"]["type_options"]])
        lun_pool = tks["result"]["pools"]["pools"][0]
        self.assertEqual((lun_pool["ratio"], lun_pool["capacity_gb"], lun_pool["allocated_gb"], lun_pool["used_pct"]),
                         (2.0, 20480.0, 8192.0, 40.0))

    def test_restore_moves_lun_to_the_selected_pool(self):
        client = self.client()
        source = f"/vol/DCAOPNSTACK_CINDER_14_vol/volume-{VOLUME_ID}-restore"
        target = f"/vol/DCAOPNSTACK_CINDER_16_vol/volume-{VOLUME_ID}-restore"
        # ONTAP stops the first attempt without creating the destination LUN (as seen on DCB); the plugin retries.
        # The PATCH is also slow to return (over the 1s limit): the plugin still checks the move status.
        self.dca.stop_moves, self.dca.patch_delay = 1, 2
        try:
            plan_id, plan = self.plan(client)
            self.assertTrue(plan["result"]["ready"], plan["error"])
            r = self.restore(client, plan_id, target_pool=self.pool(16))
            self.assertEqual(r.status_code, 200, r.get_json())
            body = r.get_json()
            job = self.wait(client, body["job_id"])
        finally:
            self.dca.stop_moves, self.dca.patch_delay = 0, 0
        self.assertEqual(job["status"], "success", job["error"] + "\n" + "\n".join(job["all_lines"][-30:]))
        self.assertTrue(any("did not respond within 1s; checking whether the lun move is already running" in l for l in job["all_lines"]))
        self.assertTrue(any(l.startswith("   used space stable at 30.0 GiB for 2s") for l in job["all_lines"]))   # wait for restore-file to finish
        self.assertEqual([c["name"] for c in self.dca.state()["move_calls"]][-2:], [target, target])   # PATCH of the LUN name, 2 attempts
        self.assertTrue(any("ONTAP stopped the lun move without moving the LUN" in l for l in job["all_lines"]))
        self.assertIn("PROGRESS move pct=100 status=complete | lun move complete 100%", job["all_lines"])
        self.assertFalse(any("WARNING" in l for l in job["all_lines"]), [l for l in job["all_lines"] if "WARNING" in l])
        self.assertEqual(job["result"]["lun_move"]["from"], source)
        new_id = job["result"]["new_volume"]["id"]
        state = self.director_state()
        # Same volume type (no tier change), in the selected pool.
        self.assertEqual((state["volumes"][new_id]["type"], state["volumes"][new_id]["os-vol-host-attr:host"]),
                         ("netapp-iscsi", self.pool(16)))
        manage = next(c for c in state["calls"] if c.startswith("cinder manage"))
        self.assertEqual(shlex.split(manage)[-2:], [self.pool(16), target])
        self.assertIn("--volume-type netapp-iscsi", manage)
        self.assertEqual(job["result"]["lun_path"], f"/vol/DCAOPNSTACK_CINDER_16_vol/volume-{new_id}")
        self.assertEqual((job["result"]["lun_move"]["flexvol"], job["result"]["cinder_pool"]), ("DCAOPNSTACK_CINDER_16_vol", self.pool(16)))
        item = client.get(f"/ontap/api/history/{body['history_id']}").get_json()["item"]
        self.assertEqual((item["volume_type"], item["move_flexvol"], item["cinder_pool"], item["restore_path"]),
                         ("netapp-iscsi", "DCAOPNSTACK_CINDER_16_vol", self.pool(16), target))
        events = {e["action"]: e["detail"] for e in self.restore_events(body["history_id"])}
        self.assertIn(f"Cinder pool {self.pool(16)} (lun move from DCAOPNSTACK_CINDER_14_vol to DCAOPNSTACK_CINDER_16_vol)",
                      events["restore.start"])
        self.assertIn("after the restore: only moved to project customer-a80", events["restore.start"])
        self.assertIn(f"Cinder pool {self.pool(16)}; only moved to project customer-a80", events["restore.done"])

    def test_volume_info_shows_the_instance_and_the_role_of_the_volume(self):
        client = self.client()
        expected = ((VOLUME_ID, "extended", "/dev/vdb"), (BOOT_VOLUME_ID, "boot", "/dev/vda"), (FULL_VOLUME_ID, "detached", ""))
        for volume_id, role, device in expected:
            r = client.post("/ontap/api/volume_info", json={"site": "DCA", "volume_id": volume_id})
            self.assertEqual(r.status_code, 200, r.get_json())
            job = self.wait(client, r.get_json()["job_id"])
            self.assertEqual(job["status"], "success", job["error"] + "\n" + "\n".join(job["all_lines"][-20:]))
            result = job["result"]
            self.assertEqual((result["role"]["role"], result["role"]["device"]), (role, device))
            if role == "detached":
                self.assertEqual(result["instance"], {})
                continue
            inst = result["instance"]
            self.assertEqual((inst["name"], inst["status"], inst["availability_zone"], inst["key_name"]), ("vm-01", "ACTIVE", "nova", "ops-key"))
            self.assertEqual((inst["flavor"]["name"], inst["flavor"]["vcpus"], inst["flavor"]["ram_mb"]), ("m1.medium", 2, 4096))
            self.assertEqual([(p["network_name"], p["ips"], p["security_groups"]) for p in inst["ports"]],
                             [("net-app", ["10.249.0.15"], ["default", "web"]), ("net-db", ["10.248.0.8"], [])])
            self.assertEqual([(v["device"], v["role"], v["this"]) for v in inst["volumes"]],
                             [("/dev/vda", "boot", volume_id == BOOT_VOLUME_ID), ("/dev/vdb", "extended", volume_id == VOLUME_ID)])
        # Three connections to the director for an attached volume: volume show, then two batches and the networks.
        self.assertIn(f"openstack server show {fake_director.SERVER_ID} -f json", self.director_state()["calls"])
        self.assertEqual(client.post("/ontap/api/volume_info", json={"site": "DCA", "volume_id": "nope"}).status_code, 400)

    def test_restore_attaches_the_volume_to_an_instance(self):
        client = self.client()
        plan_id, plan = self.plan(client)
        self.assertTrue(plan["result"]["ready"], plan["error"])
        servers = {x["name"]: x for x in plan["result"]["after_restore"]["servers"]}
        self.assertEqual(sorted(servers), ["vm-01", "vm-02", "vm-03"])   # instances of the target project only
        self.assertTrue(servers["vm-01"]["original"] and servers["vm-02"]["attachable"])
        self.assertFalse(servers["vm-03"]["attachable"])
        for body, message in (({"attach_server_id": fake_director.SERVER3_ID}, "vm-03 is ERROR"),
                              ({"attach_server_id": fake_director.OTHER_SERVER_ID}, "is not in project customer-a80"),
                              ({"attach_server_id": "vm-02"}, "must be an OpenStack UUID"),
                              ({"post_action": "instance"}, "A new instance cannot be created: the volume is not the boot disk")):
            r = self.restore(client, plan_id, **dict({"post_action": "attach"}, **body))
            self.assertEqual(r.status_code, 400, r.get_json())
            self.assertIn(message, r.get_json()["error"])
        r = self.restore(client, plan_id, post_action="attach", attach_server_id=fake_director.SERVER2_ID.upper())
        self.assertEqual(r.status_code, 200, r.get_json())
        body = r.get_json()
        job = self.wait(client, body["job_id"])
        self.assertEqual(job["status"], "success", job["error"] + "\n" + "\n".join(job["all_lines"][-30:]))
        after = job["result"]["after_restore"]
        self.assertEqual((after["action"], after["ok"], after["server_name"], after["device"]), ("attach", True, "vm-02", "/dev/vdb"))
        new_id = job["result"]["new_volume"]["id"]
        state = self.director_state()
        vol = state["volumes"][new_id]
        self.assertEqual((vol["status"], vol["attachments"][0]["server_id"]), ("in-use", fake_director.SERVER2_ID))
        # Transfer and attach in one temporary role window, scoped to the target project; the role is removed again.
        attach = next(c for c in state["calls"] if "server add volume" in c)
        self.assertTrue(attach.startswith(f"export OS_PROJECT_ID={fake_director.CUSTOMER_PROJECT} && unset OS_PROJECT_NAME"), attach)
        self.assertEqual(sum(1 for c in state["calls"] if c.startswith("openstack role add")), 1)
        self.assertNotIn([fake_director.ADMIN_USER, fake_director.CUSTOMER_PROJECT, "member"], state["roles"])
        self.assertIn("attached to instance vm-02 as /dev/vdb", job["result"]["summary"])
        item = client.get(f"/ontap/api/history/{body['history_id']}").get_json()["item"]
        self.assertEqual((item["post_action"], item["post_result"]),
                         (f"attach {fake_director.SERVER2_ID}", "ok: attached to vm-02 as /dev/vdb"))
        # Activity log: what was asked for (pool, project, action after it) and what came out of it.
        events = self.restore_events(body["history_id"])
        self.assertEqual([(e["action"], e["actor"], e["target"]) for e in events],
                         [("restore.done", "admin", VOLUME_ID), ("restore.start", "admin", VOLUME_ID)])
        done, start = events[0]["detail"], events[1]["detail"]
        for part in (f"restore #{body['history_id']}, site DCA: vm-01-data (", "from snapshot hourly.2025-12-17_1905 (2025-12-17 19:05)",
                     f"-> new volume {item['new_volume_name']} in project customer-a80 ({fake_director.CUSTOMER_PROJECT})",
                     f"Cinder pool {self.pool(14)} (pool of the LUN, no lun move)",
                     f"after the restore: attach to instance vm-02 ({fake_director.SERVER2_ID})",
                     "original volume: not scheduled for deletion"):
            self.assertIn(part, start)
        self.assertIn(f"new volume {item['new_volume_name']} ({new_id}) in project customer-a80, Cinder pool {self.pool(14)}; "
                      "attached to vm-02 as /dev/vdb", done)
        self.assertEqual(events[0]["client_ip"], events[1]["client_ip"])   # where the restore was launched from

    def test_restore_boot_volume_creates_an_identical_instance(self):
        client = self.client()
        plan_id, plan = self.plan(client, volume_id=BOOT_VOLUME_ID)
        self.assertEqual(plan["status"], "success", plan["error"] + "\n" + "\n".join(plan["all_lines"][-30:]))
        result = plan["result"]
        self.assertEqual(result["role"]["role"], "boot")
        new = result["after_restore"]["new_instance"]
        self.assertTrue(new["possible"], new["reason"])
        self.assertEqual(new["default_name"], "vm-01-restore-20251217-1905")
        self.assertEqual([(p["network_name"], p["port_security"], [g["name"] for g in p["security_groups"]]) for p in new["ports"]],
                         [("net-app", True, ["default", "web"]), ("net-db", True, [])])
        self.assertIn("port security is off on the original port", " ".join(new["warnings"]))
        self.assertEqual(result["image_properties"]["hw_firmware_type"], "uefi")
        r = self.restore(client, plan_id, post_action="instance", new_instance_name="bad name!")
        self.assertIn("The instance name may only contain", r.get_json()["error"])
        r = self.restore(client, plan_id, post_action="instance", new_instance_name="vm-01-restored")
        self.assertEqual(r.status_code, 200, r.get_json())
        body = r.get_json()
        job = self.wait(client, body["job_id"])
        self.assertEqual(job["status"], "success", job["error"] + "\n" + "\n".join(job["all_lines"][-30:]))
        after = job["result"]["after_restore"]
        self.assertEqual((after["action"], after["ok"], after["server_name"], after["status"]), ("instance", True, "vm-01-restored", "ACTIVE"))
        state = self.director_state()
        new_id = job["result"]["new_volume"]["id"]
        vol = state["volumes"][new_id]
        # Bootable, image properties of the original volume, boot disk (vda) of the new instance.
        self.assertEqual(vol["bootable"], "true")
        self.assertEqual(vol["volume_image_metadata"]["hw_firmware_type"], "uefi")
        self.assertEqual(job["result"]["image_properties"], {"count": 5, "ok": True, "error": ""})
        server = state["servers"][after["server_id"]]
        self.assertEqual((server["project_id"], server["flavor_id"], server["OS-EXT-AZ:availability_zone"], server["status"]),
                         (fake_director.CUSTOMER_PROJECT, fake_director.FLAVOR_ID, "nova", "ACTIVE"))
        self.assertEqual(server["properties"], {"env": "prod", "restore_source_server": fake_director.SERVER_ID,
                                                "restore_source_volume": BOOT_VOLUME_ID, "restore_snapshot": "hourly.2025-12-17_1905"})
        self.assertEqual((vol["attachments"][0]["server_id"], vol["attachments"][0]["device"]), (after["server_id"], "/dev/vda"))
        # One new port per original port, in order, same network/subnet and security groups, port security on, new IPs.
        new_ports = [state["ports"][pid] for pid in after["ports"]]
        self.assertEqual([(p["network_id"], p["security_group_ids"], p["port_security_enabled"], p["name"]) for p in new_ports],
                         [(fake_director.NET_APP, [fake_director.SG_DEFAULT, fake_director.SG_WEB], True, "vm-01-restored-port1"),
                          (fake_director.NET_DB, [], True, "vm-01-restored-port2")])
        self.assertNotIn("10.249.0.15", [ip["ip_address"] for p in new_ports for ip in p["fixed_ips"]])
        self.assertEqual(after["addresses"], {"net-app": ["10.249.0.101"], "net-db": ["10.248.0.101"]})
        item = client.get(f"/ontap/api/history/{body['history_id']}").get_json()["item"]
        self.assertEqual(item["post_result"], f"ok: instance vm-01-restored ({after['server_id']}) ACTIVE")
        events = {e["action"]: e["detail"] for e in self.restore_events(body["history_id"])}
        self.assertIn("(100 GB, type netapp-iscsi, bootable)", events["restore.start"])
        self.assertIn("after the restore: new instance vm-01-restored", events["restore.start"])
        self.assertIn(f"; instance vm-01-restored ({after['server_id']}) ACTIVE", events["restore.done"])

    def test_plan_through_a_real_shell_is_the_same(self):
        """Site TKR runs the batch scripts in a real bash with openstack/cinder shims, like `ssh stack@director` on the
        sites: the read-only batches run 4 commands at a time there. Its plan must equal the plan of DCA (same fake
        director, whose batches are parsed one command after the other)."""
        client = self.client()
        results = {}
        for site in ("DCA", "TKR"):
            if os.path.exists(self.state_file):
                os.remove(self.state_file)
            if os.path.exists(self.shim_log):
                os.remove(self.shim_log)
            _, plan = self.plan(client, volume_id=BOOT_VOLUME_ID, project_id=fake_director.OTHER_PROJECT, site=site)
            self.assertEqual(plan["status"], "success", plan["error"] + "\n" + "\n".join(plan["all_lines"][-30:]))
            results[site] = plan["result"]
        for key in ("ready", "checks", "volume", "role", "instance", "project", "transfer", "pools", "type_options", "after_restore"):
            self.assertEqual(results["TKR"].get(key), results["DCA"].get(key), key)
        self.assertTrue(results["TKR"]["after_restore"]["new_instance"]["networks_read"])
        # The shims ran every OpenStack command of the plan, and commands of one batch overlapped in time.
        with open(self.shim_log) as f:
            runs = [line.split(" ", 3) for line in f.read().splitlines()]
        names = [r[3] for r in runs]
        for expected in ("token issue", "project show", "--detail", "network list", "subnet list", "server show", "flavor show"):
            self.assertTrue(any(expected in n for n in names), (expected, names))
        spans = sorted((float(r[0]), float(r[1])) for r in runs)
        self.assertTrue(any(later[0] < earlier[1] for earlier, later in zip(spans, spans[1:])), spans)

    def test_new_instance_in_another_project_uses_its_networks(self):
        client = self.client()
        plan_id, plan = self.plan(client, volume_id=BOOT_VOLUME_ID, project_id=fake_director.OTHER_PROJECT)
        self.assertEqual(plan["status"], "success", plan["error"] + "\n" + "\n".join(plan["all_lines"][-30:]))
        new = plan["result"]["after_restore"]["new_instance"]
        self.assertTrue(new["possible"], new["reason"])
        self.assertEqual((new["same_project"], new["networks_read"], new["choose"]), (False, True, [1]))
        # The VPCs of the target project, then the shared network; net-app of the original project is not offered.
        self.assertEqual([(n["name"], n["own"], [s["cidr"] for s in n["subnets"]]) for n in new["network_options"]],
                         [("vpc-other", True, ["10.246.0.0/24"]), ("vpc-other-db", True, ["10.245.0.0/24", "10.244.0.0/24"]),
                          ("net-db", False, [""])])
        self.assertEqual([(p["original_network_name"], p["original_usable"], p["network_id"]) for p in new["ports"]],
                         [("net-app", False, ""), ("net-db", True, fake_director.NET_DB)])
        r = self.restore(client, plan_id, post_action="instance")
        self.assertEqual(r.status_code, 400)
        self.assertIn("Choose a network of project customer-other for network interface 1 (net-app)", r.get_json()["error"])
        r = self.restore(client, plan_id, post_action="instance", new_port_networks=[{"network_id": fake_director.NET_APP}])
        self.assertIn(f"Network {fake_director.NET_APP} cannot be used for network interface 1", r.get_json()["error"])
        r = self.restore(client, plan_id, post_action="instance", new_port_networks=[
            {"network_id": fake_director.NET_VPC2, "subnet_id": fake_director.SUBNET_VPC1}])
        self.assertIn("is not on network vpc-other-db", r.get_json()["error"])
        r = self.restore(client, plan_id, post_action="instance", new_instance_name="vm-01-other", new_port_networks=[
            {"network_id": fake_director.NET_VPC2, "subnet_id": fake_director.SUBNET_VPC2B}, {"network_id": fake_director.NET_DB}])
        self.assertEqual(r.status_code, 200, r.get_json())
        body = r.get_json()
        job = self.wait(client, body["job_id"])
        self.assertEqual(job["status"], "success", job["error"] + "\n" + "\n".join(job["all_lines"][-30:]))
        after = job["result"]["after_restore"]
        self.assertEqual((after["action"], after["ok"], after["status"]), ("instance", True, "ACTIVE"), after)
        state = self.director_state()
        self.assertEqual(state["servers"][after["server_id"]]["project_id"], fake_director.OTHER_PROJECT)
        ports = [state["ports"][pid] for pid in after["ports"]]
        self.assertEqual([(p["network_id"], [ip["subnet_id"] for ip in p["fixed_ips"]], p["security_group_ids"], p["project_id"])
                          for p in ports],
                         [(fake_director.NET_VPC2, [fake_director.SUBNET_VPC2B], [], fake_director.OTHER_PROJECT),
                          (fake_director.NET_DB, [fake_director.SUBNET_DB], [], fake_director.OTHER_PROJECT)])
        self.assertEqual(after["addresses"], {"vpc-other-db": ["10.244.0.101"], "net-db": ["10.248.0.101"]})
        events = {e["action"]: e["detail"] for e in self.restore_events(body["history_id"])}
        self.assertIn("after the restore: new instance vm-01-other on networks vpc-other-db 10.244.0.0/24, net-db", events["restore.start"])

    def wait_group(self, client, group_id, timeout=300):
        deadline = time.time() + timeout
        while time.time() < deadline:
            group = client.get(f"/ontap/api/restore_groups/{group_id}").get_json()["group"]
            if group["status"] != "running":
                return group
            time.sleep(0.5)
        self.fail(f"Group {group_id} did not finish within {timeout}s")

    def test_group_restores_the_whole_instance_into_a_new_instance(self):
        client = self.client()
        data_plan, data = self.plan(client)                            # vdb of vm-01
        boot_plan, boot = self.plan(client, volume_id=BOOT_VOLUME_ID)  # vda of vm-01
        for p in (data, boot):
            self.assertEqual(p["status"], "success", p["error"] + "\n" + "\n".join(p["all_lines"][-30:]))
        vols = [{"plan_job_id": data_plan, "target_pool": self.pool(14), "new_volume_name": "vm-01-data-g"},
                {"plan_job_id": boot_plan, "target_pool": self.pool(14), "new_volume_name": "vm-01-root-g"}]

        def post(**body):
            return client.post("/ontap/api/restore_group", json=dict({"volumes": vols, "post_action": "instance",
                                                                "new_instance_name": "vm-01-group", "confirm": True}, **body))
        # Checked before anything runs.
        self.assertIn("2 to 8 volumes", post(volumes=vols[:1]).get_json()["error"])
        self.assertEqual(post(volumes=[vols[0], vols[0]]).get_json()["error"], "A volume is in the list twice.")
        self.assertEqual(post(volumes=[vols[0], dict(vols[1], new_volume_name="vm-01-data-g")]).get_json()["error"],
                         "Each new volume needs its own name.")
        self.assertEqual(post(confirm=False).get_json()["error"], "Tick the confirmation first.")
        self.assertEqual(post(volumes=[vols[0], dict(vols[1], target_pool="")]).get_json()["error"], "Select a Cinder pool first.")
        self.assertEqual(self.client("operator2").post("/ontap/api/restore_group", json={"volumes": vols, "confirm": True}).get_json()["error"],
                         "Plan not found. Open the Review step again.")   # plans belong to the session that made them
        r = post()
        self.assertEqual(r.status_code, 200, r.get_json())
        group = self.wait_group(client, r.get_json()["group_id"])
        self.assertEqual(group["status"], "success", group)
        # The data volume first, then the boot volume: its new instance gets the new data volume when it is created.
        self.assertEqual([(m["device"], m["status"]) for m in group["members"]], [("/dev/vdb", "success"), ("/dev/vda", "success")])
        data_rec, boot_rec = (client.get(f"/ontap/api/history/{m['restore_id']}").get_json()["item"] for m in group["members"])
        self.assertEqual((data_rec["group_id"], boot_rec["group_id"]), (group["id"], group["id"]))
        self.assertEqual((data_rec["post_action"], boot_rec["post_action"]), ("", "instance vm-01-group"))
        match = re.fullmatch(r"ok: instance vm-01-group \(([0-9a-f-]{36})\) ACTIVE, with 1 more volume attached", boot_rec["post_result"])
        self.assertTrue(match, boot_rec["post_result"])
        state = self.director_state()
        attached = {a["device"]: vid for vid, v in state["volumes"].items() for a in v.get("attachments") or []
                    if a["server_id"] == match.group(1)}
        self.assertEqual(attached, {"/dev/vda": boot_rec["new_volume_id"], "/dev/vdb": data_rec["new_volume_id"]})
        self.assertEqual([m["new_volume_id"] for m in group["members"]], [data_rec["new_volume_id"], boot_rec["new_volume_id"]])
        # Activity log: the group and each of its restores.
        events = self.client().get("/api/admin/events?kinds=restore&limit=100").get_json()["events"]
        mine = [e for e in events if e["detail"].startswith(f"restore group #{group['id']},")]
        self.assertEqual([e["action"] for e in mine], ["restore.group_done", "restore.group_start"])
        self.assertIn("2 volumes of instance vm-01 (vdb vm-01-data, vda vm-01-root) from snapshot hourly.2025-12-17_1905", mine[1]["detail"])
        self.assertIn("new instance vm-01-group with all new volumes", mine[1]["detail"])
        self.assertIn(f"2 of 2 volumes restored (restore #{data_rec['id']}, restore #{boot_rec['id']})", mine[0]["detail"])
        starts = [e["detail"] for e in events if e["action"] == "restore.start" and f"(group #{group['id']})" in e["detail"]]
        self.assertEqual(len(starts), 2)
        self.assertIn("after the restore: new instance vm-01-group on networks net-app, net-db with 1 more new volume of the group", starts[0])
        # The Jobs export names the group.
        lines = client.get("/ontap/export/jobs.csv", query_string={"q": boot_rec["new_volume_id"]}).data.decode().splitlines()
        self.assertIn(f",{group['id']},", lines[1])

    def test_group_attaches_every_new_volume_to_an_instance(self):
        client = self.client()
        data_plan, data = self.plan(client)
        boot_plan, boot = self.plan(client, volume_id=BOOT_VOLUME_ID)
        self.assertEqual((data["status"], boot["status"]), ("success", "success"))
        vols = [{"plan_job_id": data_plan, "target_pool": self.pool(14), "new_volume_name": "vm-01-data-a"},
                {"plan_job_id": boot_plan, "target_pool": self.pool(14), "new_volume_name": "vm-01-root-a"}]
        body = {"volumes": vols, "post_action": "attach", "confirm": True}
        self.assertEqual(client.post("/ontap/api/restore_group", json=dict(body, attach_server_id="not-an-id")).get_json()["error"],
                         "The instance ID must be an OpenStack UUID")
        r = client.post("/ontap/api/restore_group", json=dict(body, attach_server_id=fake_director.SERVER2_ID))
        self.assertEqual(r.status_code, 200, r.get_json())
        group = self.wait_group(client, r.get_json()["group_id"])
        self.assertEqual(group["status"], "success", group)
        # Device order (vda first); each new volume is attached right after its restore.
        self.assertEqual([m["device"] for m in group["members"]], ["/dev/vda", "/dev/vdb"])
        self.assertEqual([m["note"].split(" as ")[0] for m in group["members"]], ["ok: attached to vm-02"] * 2)
        state = self.director_state()
        on_vm02 = sorted(a["device"] for v in (state["volumes"][m["new_volume_id"]] for m in group["members"]) for a in v["attachments"])
        self.assertEqual(len(on_vm02), 2)
        self.assertTrue(all(a["server_id"] == fake_director.SERVER2_ID
                            for m in group["members"] for a in state["volumes"][m["new_volume_id"]]["attachments"]))

    def test_group_stops_at_a_failed_restore(self):
        client = self.client()
        data_plan, data = self.plan(client)
        boot_plan, boot = self.plan(client, volume_id=BOOT_VOLUME_ID)
        self.assertEqual((data["status"], boot["status"]), ("success", "success"))
        os.environ["FAKE_DIRECTOR_FAIL"] = "cinder manage"   # the first restore (vda) fails at cinder manage
        try:
            r = client.post("/ontap/api/restore_group", json={"volumes": [
                {"plan_job_id": data_plan, "target_pool": self.pool(14), "new_volume_name": "vm-01-data-f"},
                {"plan_job_id": boot_plan, "target_pool": self.pool(14), "new_volume_name": "vm-01-root-f"}],
                "post_action": "none", "confirm": True})
            self.assertEqual(r.status_code, 200, r.get_json())
            group = self.wait_group(client, r.get_json()["group_id"])
        finally:
            os.environ.pop("FAKE_DIRECTOR_FAIL", None)
            self.dca.luns.pop(f"/vol/DCAOPNSTACK_CINDER_14_vol/volume-{BOOT_VOLUME_ID}-restore", None)   # left by the failed restore
        self.assertEqual(group["status"], "failed")
        # Without a new instance the boot volume goes first; the volume after the failed one is not restored.
        self.assertEqual([(m["device"], m["status"]) for m in group["members"]], [("/dev/vda", "failed"), ("/dev/vdb", "skipped")])
        self.assertIsNone(group["members"][1]["restore_id"])
        self.assertRegex(group["error"], r"^restore #\d+ failed: ")
        events = self.client().get("/api/admin/events?kinds=restore&limit=50").get_json()["events"]
        done = next(e for e in events if e["detail"].startswith(f"restore group #{group['id']},") and e["action"] != "restore.group_start")
        self.assertEqual(done["action"], "restore.group_failed")
        self.assertIn("0 of 2 volumes restored", done["detail"])

    def test_failed_new_instance_keeps_the_restored_volume(self):
        client = self.client()
        # 1) The second port cannot be created: the first one is deleted again, no instance, the restore itself succeeds.
        plan_id, plan = self.plan(client, volume_id=BOOT_VOLUME_ID)
        os.environ["FAKE_PORT_FAIL"] = "net-db"
        try:
            r = self.restore(client, plan_id, post_action="instance")
            job = self.wait(client, r.get_json()["job_id"])
        finally:
            os.environ.pop("FAKE_PORT_FAIL", None)
        self.assertEqual(job["status"], "success", job["error"])
        after = job["result"]["after_restore"]
        self.assertEqual((after["action"], after["ok"]), ("instance", False))
        self.assertIn("port 2 (net-db): BadRequest: No more IP addresses available", after["error"])
        self.assertIn("The ports created for it were deleted", after["error"])
        self.assertIn("WARNING: creating the new instance failed", job["result"]["summary"])
        state = self.director_state()
        self.assertEqual(sorted(state["ports"]), sorted([fake_director.PORT_APP, fake_director.PORT_DB]))   # no leftover port
        self.assertEqual(len(state["servers"]), 4)
        new_id = job["result"]["new_volume"]["id"]
        self.assertEqual((state["volumes"][new_id]["status"], state["volumes"][new_id]["os-vol-tenant-attr:tenant_id"]),
                         ("available", fake_director.CUSTOMER_PROJECT))
        self.assertNotIn([fake_director.ADMIN_USER, fake_director.CUSTOMER_PROJECT, "member"], state["roles"])
        item = client.get(f"/ontap/api/history/{r.get_json()['history_id']}").get_json()["item"]
        self.assertEqual(item["status"], "success")
        self.assertTrue(item["post_result"].startswith("failed: Creating the ports failed: port 2 (net-db)"), item["post_result"])
        # 2) The instance goes to ERROR: it is kept for troubleshooting with the fault message.
        os.remove(self.state_file)
        plan_id, plan = self.plan(client, volume_id=BOOT_VOLUME_ID)
        os.environ["FAKE_SERVER_ERROR"] = "1"
        try:
            r = self.restore(client, plan_id, post_action="instance")
            job = self.wait(client, r.get_json()["job_id"])
        finally:
            os.environ.pop("FAKE_SERVER_ERROR", None)
        self.assertEqual(job["status"], "success", job["error"])
        after = job["result"]["after_restore"]
        self.assertFalse(after["ok"])
        self.assertIn("is ERROR: No valid host was found", after["error"])
        self.assertIn("It is kept for troubleshooting", after["error"])
        self.assertTrue(after["server_id"])

    def put_lun_back(self, volume_ref, flexvol="DCAOPNSTACK_CINDER_14_vol"):
        """The mock ONTAP is shared by all tests: give back a LUN that a test deleted."""
        path = f"/vol/{flexvol}/volume-{volume_ref}"
        if path not in self.dca.luns:
            self.dca._add_lun(path, next(u for u, v in self.dca.volumes.items() if v["name"] == flexvol), mapped=True)

    def make_due(self, deletion_id):
        import datetime
        from modules.ontap import deletions
        past = (datetime.datetime.now().astimezone() - datetime.timedelta(minutes=1)).isoformat(timespec="seconds")
        with deletions._db() as db:
            db.execute("UPDATE deletions SET due=? WHERE id=?", (past, deletion_id))

    def restore_with_deletion(self, client, volume_id):
        plan_id, plan = self.plan(client, volume_id=volume_id)
        self.assertEqual(plan["status"], "success", plan["error"])
        r = self.restore(client, plan_id, schedule_delete=True)
        self.assertEqual(r.status_code, 200, r.get_json())
        job = self.wait(client, r.get_json()["job_id"])
        self.assertEqual(job["status"], "success", job["error"])
        return job, client.get(f"/ontap/api/history/{r.get_json()['history_id']}").get_json()["deletion"]

    def check_deletion(self, client, deletion_id):
        r = client.post(f"/ontap/api/deletions/{deletion_id}/check", json={})
        self.assertEqual(r.status_code, 200, r.get_json())
        job = self.wait(client, r.get_json()["job_id"])
        self.assertEqual(job["status"], "success", job["error"] + "\n" + "\n".join(job["all_lines"][-20:]))
        return job["result"]

    def approve_deletion(self, client, deletion_id, **body):
        r = client.post(f"/ontap/api/deletions/{deletion_id}/approve", json=dict({"confirm": True}, **body))
        self.assertEqual(r.status_code, 200, r.get_json())
        job = self.wait(client, r.get_json()["job_id"])
        return job, client.get(f"/ontap/api/deletions/{deletion_id}").get_json()["item"]

    def test_original_volume_is_deleted_only_after_admin_approval(self):
        import datetime
        admin, operator = self.client(), self.client("operator2")
        lun = f"/vol/DCAOPNSTACK_CINDER_14_vol/volume-{VOLUME_ID}"
        try:
            job, d = self.restore_with_deletion(admin, VOLUME_ID)
            new_id = job["result"]["new_volume"]["id"]
            self.assertEqual((d["state"], d["volume_id"], d["project_id"], d["new_volume_id"], d["restored_by"], d["lun_path"]),
                             ("scheduled", VOLUME_ID, fake_director.CUSTOMER_PROJECT, new_id, "admin", lun))
            hours = (datetime.datetime.fromisoformat(d["due"]) - datetime.datetime.fromisoformat(d["created"])).total_seconds() / 3600
            self.assertAlmostEqual(hours, 72, places=2)
            self.assertEqual(admin.get("/ontap/api/deletions/summary").get_json()["summary"]["scheduled"], 1)
            # Not due yet: nothing can be approved.
            r = admin.post(f"/ontap/api/deletions/{d['id']}/approve", json={"confirm": True})
            self.assertEqual(r.status_code, 400)
            self.assertIn("cannot be approved before that", r.get_json()["error"])
            # 72 hours later: the administrators are notified (badge / Approvals) and decide.
            self.make_due(d["id"])
            summary = admin.get("/ontap/api/deletions/summary").get_json()["summary"]
            self.assertEqual((summary["awaiting"], summary["needs_decision"]), (1, 1))
            listing = operator.get("/ontap/api/deletions?view=awaiting").get_json()   # operators see it ...
            self.assertEqual([(i["id"], i["state"]) for i in listing["items"]], [(d["id"], "awaiting")])
            self.assertEqual(operator.post(f"/ontap/api/deletions/{d['id']}/approve", json={"confirm": True}).status_code, 403)   # ... but cannot decide
            self.assertEqual(admin.post(f"/ontap/api/deletions/{d['id']}/approve", json={}).status_code, 400)   # no confirmation
            self.assertEqual(admin.post(f"/ontap/api/deletions/{d['id']}/approve", json={"confirm": True, "detach": True,
                                                                                  "detach_servers": ["vm-01"]}).status_code, 400)
            # Check (read-only) in OpenStack AND NetApp: the old volume is still vdb of vm-01 and its LUN still exists.
            check = self.check_deletion(operator, d["id"])
            self.assertEqual((check["can_delete"], check["can_detach"], check["gone"]), (False, True, False))
            self.assertEqual([(a["server_name"], a["device"], a["detachable"]) for a in check["attachments"]], [("vm-01", "/dev/vdb", True)])
            self.assertEqual([l["name"] for l in check["luns"]], [lun])   # the copy in the clone FlexVol is not counted
            self.assertIn(f"LUN {lun} (SVM SVM_ISCSI_OPENSTACK): 100.0 GiB, 30.0 GiB used, online, mapped",
                          next(c["detail"] for c in check["checks"] if c["key"] == "netapp"))
            self.assertIn(VOLUME_ID, self.director_state()["volumes"])
            # Approved without detaching: the playbook checks again and refuses; nothing is deleted.
            refused, item = self.approve_deletion(admin, d["id"])
            self.assertEqual(refused["status"], "failed")
            self.assertEqual((item["state"], item["decided_by"]), ("failed", "admin"))
            self.assertIn("Nothing was deleted: Volume " + VOLUME_ID + " is attached to vm-01 (ACTIVE) as /dev/vdb; it can be detached", item["error"])
            # Detach and delete with other instances than the ones attached: refused before anything happens.
            wrong, item = self.approve_deletion(admin, d["id"], detach=True, detach_servers=[fake_director.SERVER2_ID])
            self.assertEqual(wrong["status"], "failed")
            self.assertIn("not to the instance(s) shown when it was approved", item["error"])
            self.assertFalse(any("server remove volume" in c or c.startswith("openstack volume delete") for c in self.director_state()["calls"]))
            # Detach and delete: removed from vm-01, deleted (no --force / --cascade), LUN gone from NetApp.
            done, item = self.approve_deletion(admin, d["id"], detach=True, detach_servers=[fake_director.SERVER_ID])
            self.assertEqual(done["status"], "success", done["error"] + "\n" + "\n".join(done["all_lines"][-20:]))
            state = self.director_state()
            self.assertIn(f"openstack server remove volume {fake_director.SERVER_ID} {VOLUME_ID}", state["calls"])
            self.assertIn(f"openstack volume delete {VOLUME_ID}", state["calls"])
            self.assertNotIn(VOLUME_ID, state["volumes"])
            self.assertIn(new_id, state["volumes"])   # the restored volume stays
            self.assertNotIn(lun, self.dca.state()["luns"])
            self.assertEqual(item["state"], "deleted")
            self.assertEqual(item["note"], "detached from vm-01 as /dev/vdb; LUN removed from NetApp")
            self.assertEqual(admin.post(f"/ontap/api/deletions/{d['id']}/keep", json={}).status_code, 400)
            actions = [e["action"] for e in admin.get("/api/admin/events").get_json()["events"]]
            for action in ("deletion.schedule", "deletion.approve", "deletion.failed", "deletion.done"):
                self.assertIn(action, actions)
        finally:
            self.put_lun_back(VOLUME_ID)

    def test_deletion_check_finds_volumes_deleted_outside_the_portal(self):
        admin = self.client()
        try:
            # 1) The team already deleted the old volume in OpenStack (the driver removed its LUN): nothing to delete.
            job, d1 = self.restore_with_deletion(admin, NAMEID_VOLUME_ID)
            self.assertEqual((d1["lun_ref_id"], d1["lun_path"]),
                             (NAMEID_BACKEND_ID, f"/vol/DCAOPNSTACK_CINDER_14_vol/volume-{NAMEID_BACKEND_ID}"))
            self.make_due(d1["id"])
            state = self.director_state()
            del state["volumes"][NAMEID_VOLUME_ID]
            with open(self.state_file, "w") as f:
                json.dump(state, f)
            self.dca.luns.pop(d1["lun_path"])
            check = self.check_deletion(admin, d1["id"])
            self.assertEqual((check["gone"], check["orphan"], check["can_delete"]), (True, False, False))
            self.assertIn("it was already deleted (for example by the team that ran the restore)", check["summary"])
            done, item = self.approve_deletion(admin, d1["id"])
            self.assertEqual(done["status"], "success", done["error"])
            self.assertEqual((item["state"], item["note"]), ("deleted", "already deleted in OpenStack and NetApp (outside this portal)"))
            self.assertFalse(any(c.startswith("openstack volume delete") for c in self.director_state()["calls"]))
            # 2) The boot disk of a running instance is never detached; 3) no OpenStack volume but the LUN is still in
            # NetApp (for example cinder unmanage): an orphan LUN is reported, never deleted.
            os.remove(self.state_file)
            job, d2 = self.restore_with_deletion(admin, BOOT_VOLUME_ID)
            self.make_due(d2["id"])
            check = self.check_deletion(admin, d2["id"])
            self.assertEqual((check["can_delete"], check["can_detach"], check["can_delete_instance"]), (False, False, True))
            self.assertIn("is the boot disk (/dev/vda) of instance vm-01 (ACTIVE): the instance can be deleted first", check["summary"])
            refused, item = self.approve_deletion(admin, d2["id"], detach=True, detach_servers=[fake_director.SERVER_ID])
            self.assertEqual(refused["status"], "failed")
            self.assertIn("boot disk (/dev/vda) of instance vm-01", item["error"])
            self.assertFalse(any("server remove volume" in c for c in self.director_state()["calls"]))
            state = self.director_state()
            del state["volumes"][BOOT_VOLUME_ID]
            with open(self.state_file, "w") as f:
                json.dump(state, f)
            check = self.check_deletion(admin, d2["id"])
            self.assertEqual((check["gone"], check["orphan"]), (False, True))
            self.assertIn(f"but its LUN is still in NetApp (LUN /vol/DCAOPNSTACK_CINDER_14_vol/volume-{BOOT_VOLUME_ID}", check["summary"])
            refused, item = self.approve_deletion(admin, d2["id"])
            self.assertEqual((refused["status"], item["state"]), ("failed", "failed"))
            self.assertIn("This portal does not delete LUNs", item["error"])
            self.assertIn(f"/vol/DCAOPNSTACK_CINDER_14_vol/volume-{BOOT_VOLUME_ID}", self.dca.state()["luns"])
            item = admin.post(f"/ontap/api/deletions/{d2['id']}/keep", json={"note": "orphan LUN handled in ONTAP"}).get_json()["item"]
            self.assertEqual(item["state"], "kept")
        finally:
            self.put_lun_back(NAMEID_BACKEND_ID)
            self.put_lun_back(BOOT_VOLUME_ID)

    def test_boot_disk_volume_deletes_its_instance_first(self):
        """The original volume is the boot disk (vda) of an instance: after approval (the instance name typed), the instance
        is deleted first, then the volume; with delete on termination, Nova deletes the volume with the instance and the
        portal only checks that the volume and its LUN are gone. Other disks of the instance are only detached."""
        admin = self.client()
        try:
            os.remove(self.state_file) if os.path.exists(self.state_file) else None
            job, d = self.restore_with_deletion(admin, BOOT_VOLUME_ID)
            self.make_due(d["id"])
            check = self.check_deletion(admin, d["id"])
            self.assertTrue(check["can_delete_instance"], check)
            att = check["attachments"][0]
            self.assertEqual((att["server_id"], att["server_name"], att["device"], att["delete_on_termination"]),
                             (fake_director.SERVER_ID, "vm-01", "/dev/vda", False))
            self.assertIn(VOLUME_ID, att["other_volumes"])
            self.assertTrue(any("--os-compute-api-version 2.3 server show" in c for c in self.director_state()["calls"]))
            # the API needs the instance from the check and its name; never detach and delete the instance together
            for bad in ({"delete_instance": True, "delete_server_name": "vm-01"},
                        {"delete_instance": True, "delete_server": fake_director.SERVER_ID},
                        {"delete_instance": True, "delete_server": fake_director.SERVER_ID, "delete_server_name": "vm-01",
                         "detach": True, "detach_servers": [fake_director.SERVER_ID]}):
                r = admin.post(f"/ontap/api/deletions/{d['id']}/approve", json=dict({"confirm": True}, **bad))
                self.assertEqual(r.status_code, 400, (bad, r.get_json()))
            # a wrong name: the playbook refuses, nothing is deleted
            refused, item = self.approve_deletion(admin, d["id"], delete_instance=True, delete_server=fake_director.SERVER_ID,
                                                  delete_server_name="vm-02")
            self.assertEqual(refused["status"], "failed")
            self.assertIn("not of the instance confirmed when it was approved (vm-02", item["error"])
            self.assertIn(fake_director.SERVER_ID, self.director_state()["servers"])
            # the right name: instance deleted, then the volume (now available) deleted, its LUN removed; vdb stays
            done, item = self.approve_deletion(admin, d["id"], delete_instance=True, delete_server=fake_director.SERVER_ID,
                                               delete_server_name="vm-01")
            self.assertEqual(done["status"], "success", done["error"] + "\n" + "\n".join(done["all_lines"][-30:]))
            state = self.director_state()
            self.assertNotIn(fake_director.SERVER_ID, state["servers"])
            self.assertNotIn(BOOT_VOLUME_ID, state["volumes"])
            self.assertEqual(state["volumes"][VOLUME_ID]["status"], "available")
            calls = state["calls"]
            self.assertLess(calls.index(f"openstack server delete {fake_director.SERVER_ID}"),
                            calls.index(f"openstack volume delete {BOOT_VOLUME_ID}"))
            self.assertEqual(item["state"], "deleted")
            self.assertTrue(item["note"].startswith(f"instance vm-01 ({fake_director.SERVER_ID}) deleted; LUN removed from NetApp"), item["note"])
            self.assertIn(f"Instance vm-01 was deleted, then volume {BOOT_VOLUME_ID} was deleted", done["result"]["summary"])
            self.assertNotIn(f"/vol/DCAOPNSTACK_CINDER_14_vol/volume-{BOOT_VOLUME_ID}", self.dca.state()["luns"])

            # delete on termination: Nova deletes the volume with the instance; the portal only verifies it
            self.put_lun_back(BOOT_VOLUME_ID)
            os.remove(self.state_file)
            job, d = self.restore_with_deletion(admin, BOOT_VOLUME_ID)
            self.make_due(d["id"])
            state = self.director_state()
            for a in state["volumes"][BOOT_VOLUME_ID]["attachments"]:
                a["delete_on_termination"] = True
            with open(self.state_file, "w") as f:
                json.dump(state, f)
            check = self.check_deletion(admin, d["id"])
            self.assertTrue(check["attachments"][0]["delete_on_termination"], check)
            self.assertIn("delete on termination: Nova deletes the volume with the instance", check["summary"])
            done, item = self.approve_deletion(admin, d["id"], delete_instance=True, delete_server=fake_director.SERVER_ID,
                                               delete_server_name="vm-01")
            self.assertEqual(done["status"], "success", done["error"] + "\n" + "\n".join(done["all_lines"][-30:]))
            calls = self.director_state()["calls"]
            self.assertIn(f"openstack server delete {fake_director.SERVER_ID}", calls)
            self.assertFalse(any(c.startswith("openstack volume delete") for c in calls))
            self.assertIn(f"Nova deleted volume {BOOT_VOLUME_ID} with it (delete on termination); LUN removed from NetApp",
                          done["result"]["summary"])
            self.assertNotIn(f"/vol/DCAOPNSTACK_CINDER_14_vol/volume-{BOOT_VOLUME_ID}", self.dca.state()["luns"])
        finally:
            self.put_lun_back(BOOT_VOLUME_ID)
            if os.path.exists(self.state_file):
                os.remove(self.state_file)

    def test_deletion_can_be_postponed_or_kept(self):
        import datetime
        from modules.ontap import deletions
        admin, operator = self.client(), self.client("operator2")
        plan_id, plan = self.plan(admin, volume_id=NAMEID_VOLUME_ID)
        r = self.restore(admin, plan_id, schedule_delete=True)
        job = self.wait(admin, r.get_json()["job_id"])
        self.assertEqual(job["status"], "success", job["error"])
        d = admin.get(f"/ontap/api/history/{r.get_json()['history_id']}").get_json()["deletion"]
        self.assertEqual(operator.post(f"/ontap/api/deletions/{d['id']}/postpone", json={"hours": 24}).status_code, 403)
        self.assertEqual(admin.post(f"/ontap/api/deletions/{d['id']}/postpone", json={"hours": 5}).status_code, 400)
        item = admin.post(f"/ontap/api/deletions/{d['id']}/postpone", json={"hours": 24}).get_json()["item"]
        moved = (datetime.datetime.fromisoformat(item["due"]) - datetime.datetime.fromisoformat(d["due"])).total_seconds() / 3600
        self.assertAlmostEqual(moved, 24, places=2)
        self.assertIn("postponed by admin", item["note"])
        item = admin.post(f"/ontap/api/deletions/{d['id']}/keep", json={"note": "customer keeps the old disk"}).get_json()["item"]
        self.assertEqual((item["state"], item["decided_by"], item["note"]), ("kept", "admin", "customer keeps the old disk"))
        self.assertEqual(admin.post(f"/ontap/api/deletions/{d['id']}/approve", json={"confirm": True}).status_code, 400)
        self.assertIn(NAMEID_VOLUME_ID, self.director_state()["volumes"])
        # Without the choice in Review, nothing is scheduled.
        plan_id, plan = self.plan(admin)
        r = self.restore(admin, plan_id)
        self.wait(admin, r.get_json()["job_id"])
        self.assertIsNone(admin.get(f"/ontap/api/history/{r.get_json()['history_id']}").get_json()["deletion"])

    def test_failed_lun_move_stops_before_cinder_manage(self):
        client = self.client()
        target = f"/vol/DCAOPNSTACK_CINDER_16_vol/volume-{VOLUME_ID}-restore"
        self.dca.fail_move = "Insufficient space in destination volume"
        try:
            plan_id, plan = self.plan(client)
            r = self.restore(client, plan_id, target_pool=self.pool(16))
            job = self.wait(client, r.get_json()["job_id"])
            self.assertEqual(job["status"], "failed")
            self.assertTrue(job["result"]["step"].startswith("ONTAP: lun move "), job["result"]["step"])
            self.assertIn("failed: failed: Insufficient space in destination volume", job["error"])
            self.assertFalse(any(c.startswith("cinder manage") for c in self.director_state()["calls"]))
            events = {e["action"]: e["detail"] for e in self.restore_events(r.get_json()["history_id"], until="restore.failed")}
            self.assertEqual(sorted(events), ["restore.failed", "restore.start"])
            self.assertIn("Insufficient space in destination volume", events["restore.failed"])
        finally:
            self.dca.fail_move = None
            self.dca.luns.pop(target, None)

    def test_plan_rejects_low_space_and_restore_is_blocked(self):
        client = self.client()
        plan_id, plan = self.plan(client, volume_id=FULL_VOLUME_ID)
        self.assertEqual(plan["status"], "success", plan["error"])
        checks = {c["key"]: c["ok"] for c in plan["result"]["checks"]}
        self.assertFalse(checks["space"])
        self.assertFalse(plan["result"]["ready"])
        r = self.restore(client, plan_id)
        self.assertEqual(r.status_code, 400)
        self.assertIn("prerequisites", r.get_json()["error"])

    def test_plan_fails_for_unknown_snapshot_and_project(self):
        client = self.client()
        _, plan = self.plan(client, snapshot="hourly.2020-01-01_0005")
        self.assertEqual(plan["status"], "success")
        self.assertFalse(plan["result"]["ready"])
        _, plan = self.plan(client, project_id="ffffffffffffffffffffffffffffffff")
        self.assertEqual(plan["status"], "failed")
        self.assertIn("No project", plan["error"])

    def test_transfer_failure_cancels_transfer_and_revokes_role(self):
        client = self.client()
        plan_id, plan = self.plan(client)
        self.assertTrue(plan["result"]["ready"], plan["error"])
        os.environ["FAKE_DIRECTOR_FAIL"] = "transfer request accept"
        r = self.restore(client, plan_id)
        job = self.wait(client, r.get_json()["job_id"])
        self.assertEqual(job["status"], "failed")
        self.assertIn("stays in the admin project and the transfer request was canceled", job["error"])
        new_id = job["result"]["new_volume"]["id"]
        state = self.director_state()
        self.assertEqual(state["transfers"], {})
        self.assertEqual(state["volumes"][new_id]["status"], "available")
        self.assertEqual(state["volumes"][new_id]["os-vol-tenant-attr:tenant_id"], fake_director.ADMIN_PROJECT)
        self.assertNotIn([fake_director.ADMIN_USER, fake_director.CUSTOMER_PROJECT, "member"], state["roles"])
        self.assertTrue(job["result"]["transfer"]["role_removed"])
        item = client.get(f"/ontap/api/history/{r.get_json()['history_id']}").get_json()["item"]
        self.assertEqual((item["status"], item["new_volume_id"]), ("failed", new_id))

    def test_used_stops_below_existing_then_continues_as_stable(self):
        # Volume data changed after the snapshot: restored used space stops at 90% of the existing LUN.
        client = self.client()
        self.dca.used_ratio = 0.9
        try:
            plan_id, plan = self.plan(client)
            r = self.restore(client, plan_id)
            job = self.wait(client, r.get_json()["job_id"])
        finally:
            self.dca.used_ratio = 1.0
        self.assertEqual(job["status"], "success", job["error"])
        self.assertEqual(job["result"]["used_wait"]["reason"], "stable")
        self.assertIn("stopped growing at 27.0 GiB (existing 30.0 GiB)", job["result"]["used_wait"]["note"])

    def test_strict_site_fails_when_used_never_matches(self):
        # Site TKS: used_stable_seconds 0 (strict mode) and a 4 second wait limit.
        client = self.client()
        self.dca.used_ratio = 0.9
        path = f"/vol/DCAOPNSTACK_CINDER_14_vol/volume-{VOLUME_ID}-restore"
        try:
            plan_id, plan = self.plan(client, site="TKS")
            r = self.restore(client, plan_id)
            job = self.wait(client, r.get_json()["job_id"])
            self.assertEqual(job["status"], "failed")
            self.assertIn("wait for restored LUN used space", job["result"]["step"])
            self.assertIn("The -restore LUN remains in ONTAP", job["error"])
            self.assertIn(path, self.dca.state()["luns"])
            self.assertFalse(any(c.startswith("cinder manage") for c in self.director_state()["calls"]))
        finally:
            self.dca.used_ratio = 1.0
            self.dca.luns.pop(path, None)
            self.dca.growing.pop(path, None)

    def test_check_playbook_verifies_access_without_changes(self):
        import subprocess
        restores_before = len(self.dca.state()["cli_calls"])
        env = dict(os.environ, ANSIBLE_CONFIG=os.path.join(MODULE_DIR, "playbooks", "ansible.cfg"), ANSIBLE_NOCOLOR="1")
        run = subprocess.run([os.path.join(os.path.dirname(sys.executable), "ansible-playbook"), "check.yml",
                              "-e", "@" + os.environ["PORTAL_SITES"], "-e", "site=DCA"],
                             cwd=os.path.join(MODULE_DIR, "playbooks"), env=env, capture_output=True, text=True, timeout=120)
        self.assertEqual(run.returncode, 0, run.stdout[-2000:])
        self.assertIn("Site DCA access OK", run.stdout)
        self.assertIn(fake_director.ADMIN_PROJECT, run.stdout)
        self.assertEqual(len(self.dca.state()["cli_calls"]), restores_before)   # no restore-file
        calls = self.director_state()["calls"]
        self.assertEqual(calls, ["openstack token issue -f value -c project_id", "cinder --version"])

    def test_check_playbook_reports_director_login_denied(self):
        import subprocess
        env = dict(os.environ, ANSIBLE_CONFIG=os.path.join(MODULE_DIR, "playbooks", "ansible.cfg"), ANSIBLE_NOCOLOR="1")
        run = subprocess.run([os.path.join(os.path.dirname(sys.executable), "ansible-playbook"), "check.yml",
                              "-e", "@" + os.environ["PORTAL_SITES"], "-e", "site=TKD"],
                             cwd=os.path.join(MODULE_DIR, "playbooks"), env=env, capture_output=True, text=True, timeout=120)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("login to director admin@director.test was denied (Permission denied)", run.stdout)
        self.assertIn("usually use the stack user", run.stdout)
        self.assertNotIn("management host not reachable", run.stdout)

    def test_existing_restore_lun_blocks_restore(self):
        client = self.client()
        path = f"/vol/DCAOPNSTACK_CINDER_14_vol/volume-{VOLUME_ID}-restore"
        vol_uuid = next(u for u, v in self.dca.volumes.items() if v["name"] == "DCAOPNSTACK_CINDER_14_vol")
        self.dca._add_lun(path, vol_uuid)
        try:
            self.assertTrue(client.get(f"/ontap/api/snapshots?site=DCA&volume_id={VOLUME_ID}").get_json()["restore_path_exists"])
            _, plan = self.plan(client)
            self.assertFalse({c["key"]: c["ok"] for c in plan["result"]["checks"]}["restore_path_free"])
        finally:
            self.dca.luns.pop(path, None)


if __name__ == "__main__":
    unittest.main()

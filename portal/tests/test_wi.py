"""Operation Automation tests: the read-only guard, the catalog, parameter validation, and checks run end to end through Ansible
against the fake cloud (OpenStack director), fake hosts (SSH) and the mock vCenter / NSX-T.

Run from the portal folder:
    .venv/bin/python -m unittest tests.test_wi -v
"""
import datetime
import io
import json
import os
import re
import shutil
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "modules", "wi"))

import fake_ldap  # noqa: E402
import mock_ontap  # noqa: E402
import mock_redfish  # noqa: E402
import mock_vmware  # noqa: E402

TMP = tempfile.mkdtemp()


def new_key():
    """A real (throw-away) OpenSSH private key: the portal reads it to show its fingerprint."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    return ed25519.Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                                              serialization.NoEncryption()).decode()

PY = sys.executable
FAKE_HOSTS = f"FAKE_HOSTS_STATE={TMP}/hosts-state.json {PY} {os.path.join(HERE, 'fake_hosts.py')} {{name}}"
CERT, KEY = fake_ldap.make_cert(TMP, "wi-test")
VMWARE = mock_vmware.MockVmware(CERT, KEY).start()
ONTAP_RO = ("wi-readonly", "demo-ro-dca")
ONTAP = mock_ontap.MockOntap("DCA-ONTAP", CERT, KEY, readonly=ONTAP_RO, mgmt_not_home=True).start()
XCC = mock_redfish.MockBmc("lenovo", CERT, KEY).start()
INSPUR = mock_redfish.MockBmc("inspur", CERT, KEY).start()
with open(os.path.join(TMP, "sites.yml"), "w") as f:
    f.write(f"""vcd: {{host: "127.0.0.1:{VMWARE.port}"}}
sites:
  DCA:
    mgmt: {{host: localhost, connection: local}}
    director: {{host: director.demo, user: stack, command: "FAKE_CLOUD_STATE={TMP}/cloud-state.json FAKE_POOL_PREFIX=DCAOPNSTACK {PY} {os.path.join(HERE, 'fake_cloud.py')}"}}
    openstack: {{overcommit_ratio: 1}}
    vcenter: {{host: "127.0.0.1:{VMWARE.port}", inventory_command: "{PY} {os.path.join(HERE, 'fake_vsphere.py')}"}}
    nsxt: {{host: "127.0.0.1:{VMWARE.port}"}}
    ontap: {{host: "{ONTAP.host}", validate_certs: false}}
    wi: {{siem_collector: "172.26.0.40:541", esxi_collector: "172.26.80.73:514", tcp_probe: false, test_ssh_command: "{FAKE_HOSTS}",
         vyos_poll_seconds: 1}}
    hosts:
      cdn: {{user: wi-ro, connection: local, command: "{FAKE_HOSTS}", members: {{dca-cdn-lb-01: 172.31.10.67, dca-cdn-lb-02: 172.31.10.68}}}}
      vyos: {{connection: local, command: "{FAKE_HOSTS}", members: {{dca-natgw-01: 11.7.101.238}}}}
      linux: {{connection: local, command: "{FAKE_HOSTS}", sudo: true, members: {{app-vm-01: 10.249.1.20}}}}
  DCC:
    hosts: {{}}
""")
with open(os.path.join(TMP, "auth.yml"), "w") as f:
    f.write("admins: []\n")
os.environ.update(PORTAL_SITES=os.path.join(TMP, "sites.yml"), PORTAL_DATA=os.path.join(TMP, "data"),
                  PORTAL_DB=os.path.join(TMP, "data", "portal.db"), PORTAL_AUTH=os.path.join(TMP, "auth.yml"),
                  PORTAL_CREDENTIALS_KEY=os.path.join(TMP, "credentials.key"), PORTAL_MODULES="wi,ontap,aci")

import wi_analysis  # noqa: E402


class GuardTest(unittest.TestCase):
    """Only read-only OpenStack commands reach the director."""

    def test_allowlist(self):
        for ok in ("openstack server list --all-projects --long -f json", "openstack quota show 'abc' -f json",
                   "cinder get-pools --detail", "openstack security group rule list 'x' --long -f json",
                   "date -u +%Y-%m-%dT%H:%M:%SZ"):
            self.assertEqual(wi_analysis.assert_openstack_read(ok), ok)
        for bad in ("openstack server delete abc", "openstack volume set --type x abc", "cinder reset-state abc",
                    "openstack server list; rm -rf /", "openstack server list | sh", "openstack server list $(id)",
                    "nova delete abc", "bash -c 'openstack server list'", "openstack server show `id`"):
            with self.assertRaises(ValueError, msg=bad):
                wi_analysis.assert_openstack_read(bad)
        with self.assertRaises(ValueError):
            wi_analysis.os_script({"x": "openstack server delete abc"})

    def test_every_check_reads_only_allowed_commands(self):
        """Phase 1 of every check, with empty data, only produces allowed commands and REST paths."""
        params = {"project": "customer-a80", "instance": "5e5e5e5e-0000-4000-8000-000000000001", "ip": "203.0.113.10",
                  "port": 6600, "prefix": "11.5.244.0/23", "tier1": "t1", "host": "x", "threshold": 80,
                  "volume": "11111111-0000-4000-8000-000000000006", "vm": "web 02 (copy)", "edge": "CUST-A-EDGE",
                  "compute": "compute-07", "instances": "5e5e5e5e-0000-4000-8000-000000000001,3d3d3d3d-0000-4000-8000-000000000001"}
        for check_id in wi_analysis.CHECKS:
            reads = wi_analysis.reads(check_id, 1, {}, params, {"vcenter_host": "vc.example"})
            self.assertTrue(any(reads.values()), check_id)

    def test_screens_mask_secrets(self):
        from wi_analysis import screens
        text = screens.redact("set system login user vyos authentication encrypted-password '$6$abcdefgh$XYZ1234567890'\n"
                              "set vpn ipsec authentication psk PEER1 secret 'SuperSecret123'\n"
                              " local-user admin password irreversible-cipher $1c$Ab12CdEf34$xyz\n"
                              "Oct 10 host sshd[1]: Failed password for root from 1.2.3.4\nDB_PASSWORD=hunter2")
        for secret in ("$6$abcdefgh", "SuperSecret123", "$1c$Ab12", "hunter2"):
            self.assertNotIn(secret, text)
        self.assertIn("Failed password for root", text)   # log lines stay readable
        table = screens.cli_table('[{"ID": "a", "Name": "web-01"}]')
        self.assertIn("| ID | Name   |", table)

    def test_selectable_fix_lists_every_item_and_runs_from_an_ok_result(self):
        """An operation the operator ticks (migrations, clean-ups) shows every item to tick, also past the 200 rows of a
        table, and can run from a result without a problem (every instance of the compute can move)."""
        import datetime as dt
        from modules.wi import fixes
        from wi_analysis.common import Result
        from wi_analysis.openstack import os_select
        sid = "5e5e5e5e-0000-4000-8000-000000000001"
        items = [{"label": f"vm-{n}", "commands": [f"cold-migrate {sid} from compute-07 to auto try - timeout 600"]} for n in range(250)]
        r = Result("compute-drain")
        r.step("compute", "Compute", "ok", "all can move")
        r.recommend("Move them.", items={"columns": ["Instance"], "rows": [[f"vm-{n}"] for n in range(250)]},
                    action=os_select(items, "compute-07", "Cold-migrate selected", "instances"))
        r.recommend("Read more.", items={"columns": ["x"], "rows": [[n] for n in range(250)]})
        res = r.done()
        self.assertEqual(len(res["recommendations"][0]["items"]["rows"]), 250)    # every item can be ticked
        self.assertEqual(res["recommendations"][1]["items"]["more"], 50)           # a plain table stays at 200
        now = dt.datetime.now().astimezone().isoformat(timespec="seconds")
        record = {"id": 1, "site": "DCA", "status": res["status"], "ts": now, "finished": now, "host": ""}
        cfg = {"mgmt": {"host": "m"}, "director": {"host": "d"}}
        st = fixes.state(record, 0, res["recommendations"][0], {"id": "compute-drain"}, cfg, {"role": "admin", "modules": []},
                         lambda name: True)
        self.assertEqual(res["status"], "ok")
        self.assertTrue(st["available"] and st["selectable"], st)
        self.assertEqual(len(st["items"]), 250)

    def test_progress_of_items_does_not_depend_on_the_log(self):
        """The run page shows the items of a fix from a progress file (complete after the page was reopened, whatever the
        length of the names), not from the Ansible log, which wraps long lines."""
        sys.path.insert(0, os.path.join(os.path.dirname(HERE), "modules", "wi", "playbooks", "filter_plugins"))
        import wi_filters
        items = [{"label": f"tenantpod-{n:08d}-aaaa-4bbb-8ccc-{n:012d} -> dcbrhosp-az1-compute-5.example.net"} for n in range(3)]
        done = [{"index": 0, "status": "ok", "label": items[0]["label"], "summary": "is on compute-5"},
                {"index": 1, "status": "skipped", "label": items[1]["label"], "summary": "not moved: " + "x" * 300}]
        p = wi_filters.wi_progress(done, items, 2)
        self.assertEqual((p["of"], p["current"]["n"], [d["status"] for d in p["done"]]), (3, 3, ["ok", "skipped"]))
        self.assertEqual(p["done"][1]["label"], items[1]["label"])
        self.assertIsNone(wi_filters.wi_progress(done, items, -1)["current"])

    def test_batch_parsing(self):
        out = "noise\n@@WI@@begin a\nline 1\nline 2\n@@WI@@end a 0\n@@WI@@begin b\n@@WI@@end b 3\n"
        parsed = wi_analysis.batch(out, ["a", "b", "c"])
        self.assertEqual(parsed["a"], {"rc": 0, "out": "line 1\nline 2"})
        self.assertEqual(parsed["b"]["rc"], 3)
        self.assertIn("skipped", parsed["c"])
        script = wi_analysis.host_script({"a": "SUDO du -sk /x"}, sudo=True)
        self.assertIn("sudo -n du -sk /x", script)
        self.assertNotIn("SUDO", wi_analysis.host_script({"a": "SUDO du -sk /x"}, sudo=False))


class OpsTest(unittest.TestCase):
    """wi_ops.py, the operations that run on the director: only exact command lines, and the same lines pass the
    allowlist of OpenStack fixes; run with the fake cloud as director (python-openstackclient 5.5 of RHOSP 17.1 here, the
    end-to-end tests use 4.0 of 16.2 with the nova client)."""
    SID = "5e5e5e5e-0000-4000-8000-000000000001"

    def test_parse_and_allowlist(self):
        from wi_analysis import wi_ops
        ok = [f"live-migrate {self.SID} from compute-07 to auto try compute-09 timeout 3600 stall abort "
              "nodes compute-07=192.168.253.27,compute-09=192.168.253.29 user heat-admin",
              f"cold-migrate {self.SID} from compute-07 to compute-09 try - timeout 600",
              f"migrate-volume {self.SID} to hostgroup@be#POOL_1 try hostgroup@be#POOL_2 timeout 14400 snapshots -",
              f"delete-image {self.SID} expect size0 snapshots {self.SID}"]
        for line in ok:
            self.assertEqual(wi_analysis.openstack_fix_command(line), line)
            self.assertEqual(wi_ops.parse(line.split())["id"], self.SID)
        for bad in (f"live-migrate {self.SID} from compute-07 to auto try - timeout 3600 stall abort nodes - user root",
                    f"live-migrate {self.SID} from compute-07; rm -rf / to auto try - timeout 60 stall abort nodes - user -",
                    f"delete-image {self.SID} expect size0 snapshots $(id)",
                    f"migrate-volume {self.SID} to pool timeout 60 snapshots -",
                    f"cold-migrate {self.SID} from compute-07 to auto try - timeout 5"):
            with self.assertRaises(ValueError, msg=bad):
                wi_analysis.openstack_fix_command(bad)
                wi_ops.parse(bad.split())
        self.assertTrue(wi_analysis.OPENSTACK_DELETE.match(ok[3]))
        self.assertFalse(wi_analysis.OPENSTACK_DELETE.match(ok[2]))          # migrates without deleting snapshots
        self.assertTrue(wi_analysis.OPENSTACK_DELETE.match(ok[2].replace("snapshots -", f"snapshots {self.SID}")))
        script = wi_analysis.os_action_script([ok[1]])
        self.assertIn("wi_ops cold-migrate", script)
        self.assertIn("WI_OPS_EOF", script)
        self.assertNotIn("WI_OPS_EOF", wi_analysis.os_action_script([f"openstack server start {self.SID}"]))

    def test_stalled_live_migration_is_aborted(self):
        """A live migration still running after its time limit is aborted: the instance keeps running on its source."""
        from wi_analysis import wi_ops
        state = {"status": "ACTIVE", "task": None}
        mig = [{"Id": 4, "Status": "running", "Type": "live-migration", "Dest Compute": "compute-09"}]

        def runner(argv, timeout):
            cmd = " ".join(argv)
            if cmd == "openstack --version":
                return 0, "openstack 5.5.2"
            if "server show" in cmd:
                return 0, json.dumps({"name": "web-01", "status": state["status"], "OS-EXT-STS:task_state": state["task"],
                                      "OS-EXT-SRV-ATTR:host": "compute-07"})
            if "compute service list" in cmd:
                return 0, json.dumps([{"Host": "compute-09", "Status": "enabled", "State": "up"}])
            if "migrate --live-migration" in cmd:
                state.update(status="MIGRATING", task="migrating")
                return 0, ""
            if "migration list" in cmd:
                return 0, json.dumps(mig)
            if "migration show" in cmd:
                return 0, json.dumps({"Memory Remaining Bytes": 1073741824})
            if "migration abort" in cmd:
                state.update(status="ACTIVE", task=None)
                mig[0]["Status"] = "cancelled"
                return 0, ""
            return 0, "[]"
        now, log = [0.0], []
        d = wi_ops.Director(runner=runner, clock=lambda: now[0], sleep=lambda x: now.__setitem__(0, now[0] + x), write=log.append)
        rc = wi_ops.main(f"live-migrate {self.SID} from compute-07 to auto try - timeout 600 stall abort nodes - user -".split(), d)
        self.assertEqual(rc, wi_ops.FAILED)
        self.assertIn("Automatic fix: not finished after 10 min 0 s: abort (the instance stays on its source)", log)
        self.assertTrue(log[-1].startswith("RESULT failed: aborted after 10 min 0 s (timeout); web-01 keeps running on compute-07"))

    def test_destination_under_the_usage_limit(self):
        """The destination of a migration: the least used compute whose real CPU and RAM (with the instance) stay under the
        limit, read on the computes right before; none: not moved (exit 7, the next item still runs). Old command lines
        without the limit still parse."""
        from wi_analysis import wi_ops
        total = 263731444
        use = {"192.168.253.28": (60, 65), "192.168.253.29": (20, 30), "192.168.253.30": (10, 10)}   # CPU %, RAM %

        def runner(argv, timeout):
            cmd = " ".join(argv)
            if "compute service list" in cmd:
                return 0, json.dumps([{"Host": f"compute-0{n}.localdomain", "Status": st, "State": "up"}
                                      for n, st in ((7, "enabled"), (8, "enabled"), (9, "enabled"))]
                                     + [{"Host": "compute-10.localdomain", "Status": "disabled", "State": "up"}])
            if argv[0] == "ssh":
                cpu, ram = use[argv[-2].split("@")[1]]
                return 0, (f"cpu  1000 0 0 9000 0 0 0 0 0 0\nMemTotal: {total} kB\nMemAvailable: {total * (100 - ram) // 100} kB\n"
                           f"cpu  {1000 + cpu * 10} 0 0 {9000 + (100 - cpu) * 10} 0 0 0 0 0 0")
            return 1, "unexpected"
        log = []
        d = wi_ops.Director(runner=runner, write=log.append)
        line = (f"live-migrate {self.SID} from compute-07 to auto try - timeout 600 stall abort "
                "nodes compute-07=192.168.253.27,compute-08=192.168.253.28,compute-09=192.168.253.29,compute-10=192.168.253.30 "
                "user heat-admin under 70 ram 16384")
        self.assertEqual(wi_analysis.openstack_fix_command(line), line)
        a = wi_ops.parse(line.split())
        services = d.computes()
        # compute-08: 65 % RAM + 16 GiB of the instance > 70 %; compute-10 is disabled; compute-07 is the source
        self.assertEqual(wi_ops.destinations(d, a, "web-01", "compute-07", services), ["compute-09.localdomain"])
        self.assertIn("  compute-08: CPU 60%, RAM 71.4% -> over the limit", log)
        with self.assertRaises(wi_ops.Done) as no:
            wi_ops.destinations(d, dict(a, under=25), "web-01", "compute-07", services)
        self.assertEqual(no.exception.rc, wi_ops.SKIPPED)
        self.assertIn("not moved: no compute stays under 25% CPU and RAM with web-01", no.exception.message)
        old = wi_ops.parse(f"cold-migrate {self.SID} from compute-07 to auto try - timeout 600".split())
        self.assertEqual((old["under"], old["nodes"]), (0, {}))
        with self.assertRaises(ValueError):   # a limit needs the computes to measure
            wi_ops.parse(f"cold-migrate {self.SID} from compute-07 to auto try - timeout 600 nodes - user - under 70 ram 1".split())
        res = wi_analysis.item_result({"stdout": "@@WI@@begin a1\nRESULT skipped: not moved\n@@WI@@end a1 7\n"},
                                      {"label": "web-01", "commands": [line]}, 0, [5, 6])
        self.assertEqual((res["status"], res["stop"]), ("skipped", False))   # never stops the run

    def test_vyos_wait_keeps_trying_an_unreachable_vyos(self):
        """After the reboot the VyOS is unreachable for minutes: the wait keeps trying until the time limit (Ansible's
        until/retries ended at the first unreachable attempt: Project-D failed right after its reboot)."""
        import re
        import subprocess
        work = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, work, True)
        wi_dir = os.path.join(os.path.dirname(HERE), "modules", "wi", "playbooks")
        with open(os.path.join(work, "inv.ini"), "w") as f:   # nothing listens on port 1: connection refused, unreachable
            f.write("[all]\nwi_target ansible_host=127.0.0.1 ansible_port=1 ansible_connection=ssh ansible_user=nobody "
                    "ansible_ssh_common_args='-o ConnectTimeout=2 -o StrictHostKeyChecking=no -o BatchMode=yes'\n")
        with open(os.path.join(work, "wait.yml"), "w") as f:
            f.write(f"""- hosts: localhost
  gather_facts: false
  vars:
    vu: {{wait: 5, poll: 1}}
    vu_boot_id: before
    vu_up: false
    vu_attempts: 0
    vu_last: ""
  tasks:
    - ansible.builtin.set_fact:
        vu_wait_start: "{{{{ now(fmt='%s') | int }}}}"
    - ansible.builtin.include_tasks: {wi_dir}/tasks/vyos_wait.yml
      loop: "{{{{ range(0, 7) | list }}}}"
    - ansible.builtin.debug:
        msg: "RESULT up={{{{ vu_up | bool }}}} attempts={{{{ vu_attempts }}}}"
""")
        bin_ = os.path.join(os.path.dirname(PY), "ansible-playbook")
        env = dict(os.environ, ANSIBLE_FILTER_PLUGINS=os.path.join(wi_dir, "filter_plugins"), ANSIBLE_NOCOLOR="1",
                   ANSIBLE_HOST_KEY_CHECKING="False")
        start = time.time()
        out = subprocess.run([bin_ if os.path.exists(bin_) else "ansible-playbook", "-i", os.path.join(work, "inv.ini"),
                              os.path.join(work, "wait.yml")], env=env, capture_output=True, text=True, timeout=120).stdout
        m = re.search(r"RESULT up=(\w+) attempts=(\d+)", out)
        self.assertTrue(m, out[-2000:])
        self.assertEqual(m.group(1), "False")
        self.assertGreaterEqual(int(m.group(2)), 3, out[-2000:])   # kept trying, one attempt a second
        self.assertGreaterEqual(time.time() - start, 4)              # until the time limit, not the first refusal

    def test_vyos_image_prompts_are_answered_by_what_they_ask(self):
        """wi_vyos.py (runs on the VyOS): add system image answered by the text of each question (never by order); an
        unknown question stops it without an answer; the jump host command forwards only the VyOS key, for one command."""
        import subprocess
        work = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, work, True)
        wrapper = os.path.join(work, "wrapper.py")
        with open(wrapper, "w") as f:
            f.write(f"#!{PY}\nimport os, sys\n"
                    "a = input('Do you want to continue without signature check? (yes/no) [yes] ')\n"
                    "print('Copying files to the image store:')\n"
                    "n = input('What would you like to name this image? [2026.03]: ')\n"
                    "print('An image named 2026.03 is already installed on this system.')\n"
                    "r = input('Do you want to replace it? (Yes/No) [No]: ')\n"
                    "c = input('Would you like to save the current configuration\\ndirectory and config file? (Yes/No) [Yes]: ')\n"
                    "k = input('Would you like to save the SSH host keys from your current configuration? (Yes/No) [Yes]: ')\n"
                    "if os.environ.get('WEIRD'):\n    input('Which disk should be used? ')\n"
                    "d = input('Would you like to set the new image as the default one for boot? [Y/n] ')\n"
                    "print('answers', repr((a, n, r, c, k, d)))\n")
        os.chmod(wrapper, 0o755)
        iso = "/tmp/wi-test-" + os.path.basename(work) + ".iso"
        open(iso, "w").close()
        self.addCleanup(os.remove, iso)
        script = os.path.join(os.path.dirname(HERE), "modules", "wi", "wi_analysis", "wi_vyos.py")
        env = dict(os.environ, WI_VYOS_WRAPPER=wrapper, WI_VYOS_QUIET="0.4", WI_VYOS_TIMEOUT="60")
        ok = subprocess.run([PY, script, "install", iso], env=env, capture_output=True, text=True)
        self.assertEqual(ok.returncode, 0, ok.stdout)
        self.assertIn("answers ('Yes', '', 'Yes', 'Yes', 'Yes', 'Yes')", ok.stdout)   # Yes to every yes/no, the proposed name
        self.assertTrue(ok.stdout.strip().endswith("RESULT ok"))
        weird = subprocess.run([PY, script, "install", iso], env=dict(env, WEIRD="1"), capture_output=True, text=True)
        self.assertEqual(weird.returncode, 6)
        self.assertIn("unknown question, stopped without answering: Which disk should be used?", weird.stdout)
        self.assertEqual(subprocess.run([PY, script, "install", "/etc/passwd"], env=env, capture_output=True).returncode, 5)
        # copy on the jump host for a VyOS that logs in with a password: typed once into the prompt of scp (stdin)
        scp = os.path.join(work, "scp.py")
        with open(scp, "w") as f:
            f.write(f"#!{PY}\nimport getpass, sys\n"
                    "p = getpass.getpass(sys.argv[-1].split(':')[0] + \"'s password: \")\n"
                    "print('received', 'right' if p == 'Vy0s-pass' else 'wrong'); sys.exit(0 if p == 'Vy0s-pass' else 1)\n")
        os.chmod(scp, 0o755)
        for password, rc_expected in (("Vy0s-pass", 0), ("bad", 5)):
            res = subprocess.run([PY, script, "copy", "/home/vyos/vyos-2026.03-generic-amd64.iso", "vyos@11.0.2.185", "6022"],
                                 input=password + "\n", env=dict(env, WI_VYOS_SCP=scp), capture_output=True, text=True)
            if rc_expected == 0:
                self.assertEqual(res.returncode, 0, res.stdout)
                self.assertIn("received right", res.stdout)
                self.assertNotIn("Vy0s-pass", res.stdout)                    # the password is never printed
            else:
                self.assertNotEqual(res.returncode, 0, res.stdout)
        from wi_analysis import vyos_upgrade as vu
        target_pw = {"name": "edge", "address": "11.0.2.185", "user": "vyos", "port": 6022, "auth": "password",
                     "jump": {"name": "jump", "address": "11.6.215.125", "user": "vyos", "port": 22, "auth": "password"}}
        cmd = vu.jump_command(target_pw, vu.jump_script("copy", target_pw, iso="/home/vyos/vyos-2026.03-generic-amd64.iso"),
                              password_stdin=True)
        self.assertTrue(cmd.startswith("set -o pipefail; printf '%s\\n' \"$WI_SSH_SECRET\" | sshpass -e ssh "), cmd)
        self.assertIn("copy /home/vyos/vyos-2026.03-generic-amd64.iso vyos@11.0.2.185 6022", cmd)
        self.assertNotIn("ssh-agent", cmd)
        # the configuration backup: fetched by the jump host into its backup folder (mode 600), the password as for copy
        fetch = os.path.join(work, "backup", "config.boot.x")
        os.makedirs(os.path.dirname(fetch))
        res = subprocess.run([PY, script, "fetch", "vyos@11.0.2.185", "6022", fetch], input="Vy0s-pass\n",
                             env=dict(env, WI_VYOS_SCP=scp), capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stdout)
        self.assertIn("received right", res.stdout)
        self.assertEqual(subprocess.run([PY, script, "fetch", "vyos@11.0.2.185", "6022", "/tmp/../etc/x"], input=b"x\n",
                                        env=env, capture_output=True).returncode, 5)
        cmd = vu.jump_command(target_pw, vu.jump_script("backup", target_pw, iso="/home/vyos/vyos-2026.03-generic-amd64.iso",
                                                        backup_dir="/home/vyos/config-backup", name="Tenant-A", version="2026.03"),
                              password_stdin=True)
        self.assertIn("fetch vyos@11.0.2.185 6022 \"$b\"", cmd)
        self.assertIn("umask 077; mkdir -p /home/vyos/config-backup/Tenant-A", cmd)
        self.assertIn("config.boot.$(date +%Y%m%d-%H%M%S).before-2026.03", cmd)
        with self.assertRaises(ValueError):
            vu.jump_script("backup", target_pw, iso="/home/vyos/x.iso", backup_dir="/home/vyos/../../etc", name="e", version="1")
        self.assertNotIn("cp ", vu.step_script("backup"))
        target = {"name": "edge", "address": "10.246.0.11", "user": "vyos", "port": 22,
                  "jump": {"name": "jump", "address": "11.6.215.125", "user": "vyos", "port": 22, "auth": "key"}}
        cmd = vu.jump_command(target, vu.jump_script("backup", target, iso="/home/vyos/vyos-2026.03-generic-amd64.iso",
                                                     backup_dir="/home/vyos/config-backup", name="edge", version="2026.03"),
                              "/tmp/jump.key", "/tmp/edge.key", agent=True)
        self.assertIn("vyos@10.246.0.11:/config/config.boot", cmd)
        self.assertIn("ssh-add -q /tmp/edge.key", cmd)
        cmd = vu.jump_command(target, vu.jump_script("copy", target, iso="/home/vyos/vyos-2026.03-generic-amd64.iso"),
                              "/tmp/jump.key", "/tmp/edge.key", agent=True)
        self.assertIn("ssh-add -q /tmp/edge.key", cmd)
        self.assertIn("-i /tmp/jump.key -o IdentitiesOnly=yes -o BatchMode=yes -A vyos@11.6.215.125", cmd)
        self.assertIn("trap 'ssh-agent -k", cmd)
        self.assertIn("vyos@10.246.0.11:/tmp/vyos-2026.03-generic-amd64.iso", cmd)

    def test_live_migration_with_the_new_client(self):
        import subprocess
        work = tempfile.mkdtemp()   # its own folder: FlowTest removes TMP when it ends
        self.addCleanup(shutil.rmtree, work, True)
        state = os.path.join(work, "ops-state.json")
        line = (f"live-migrate {self.SID} from compute-07 to auto try compute-09 timeout 3600 stall abort nodes - user -")
        script = wi_analysis.os_action_script([line])
        env = dict(os.environ, FAKE_CLOUD_STATE=state, FAKE_OSC_VERSION="5.5.2")
        out = subprocess.run([PY, os.path.join(HERE, "fake_cloud.py"), script], env=env, capture_output=True, text=True).stdout
        self.assertIn("openstack --os-compute-api-version 2.30 server migrate --live-migration", out)
        self.assertIn("RESULT ok: web-01 is on compute-09", out)


class VsphereReaderTest(unittest.TestCase):
    """The health sets of playbooks/files/vsphere_inventory.py on real pyVmomi objects (the types vCenter returns)."""

    def setUp(self):
        sys.path.insert(0, os.path.join(ROOT, "modules", "wi", "playbooks", "files"))
        import vsphere_inventory
        self.vi = vsphere_inventory

    def test_health_sets(self):
        import datetime
        from pyVmomi import vim
        vi = self.vi
        now = datetime.datetime(2026, 10, 11, 8, 0, tzinfo=datetime.timezone.utc)
        host = vim.HostSystem("host-10")
        sensor = vim.host.NumericSensorInfo(name="Power Supply 2", healthState=vim.ElementDescription(key="red", label="Red", summary=""),
                                            currentReading=0, unitModifier=0, baseUnits="Watts", sensorType="power")
        ok_sensor = vim.host.NumericSensorInfo(name="Fan 1", healthState=vim.ElementDescription(key="green", label="Green", summary=""),
                                               currentReading=640000, unitModifier=-2, baseUnits="RPM", sensorType="fan")
        hw = vim.host.HardwareStatusInfo(memoryStatusInfo=[vim.host.HardwareStatusInfo.HardwareElementInfo(
            name="DIMM 12", status=vim.ElementDescription(key="Red", label="Red", summary=""))])   # capitalised key
        snap = vim.vm.SnapshotTree(name="old", createTime=now - datetime.timedelta(days=9), childSnapshotList=[
            vim.vm.SnapshotTree(name="newer", createTime=now - datetime.timedelta(days=1), childSnapshotList=[])])

        def view_props(content, vimtype, paths):
            if vimtype is vim.HostSystem and "configIssue" in paths:
                return {"host-10": {"name": "esxi-1", "runtime.connectionState": "connected", "runtime.inMaintenanceMode": False,
                                    "overallStatus": "red", "summary.hardware.vendor": "Lenovo", "summary.hardware.model": "SR650 V2",
                                    "configIssue": [], "runtime.healthSystemRuntime.systemHealthInfo.numericSensorInfo": [sensor, ok_sensor],
                                    "runtime.healthSystemRuntime.hardwareStatusInfo": hw},
                        "host-11": {"name": "esxi-2", "runtime.connectionState": "notResponding"}}   # no health of a lost host
            if vimtype is vim.HostSystem:
                return {"host-10": {"name": "esxi-1"}}
            if vimtype is vim.VirtualMachine:
                return {"vm-1": {"name": "app-01", "runtime.host": host, "runtime.powerState": "poweredOn", "config.template": False,
                                 "runtime.consolidationNeeded": True, "snapshot.rootSnapshotList": [snap],
                                 "guest.toolsRunningStatus": "guestToolsRunning"},
                        "vm-2": {"name": "clean", "runtime.host": host, "runtime.powerState": "poweredOn", "config.template": False,
                                 "runtime.consolidationNeeded": False, "guest.toolsRunningStatus": "guestToolsRunning"}}
            if vimtype is vim.Datastore:
                return {"datastore-1": {"name": "DS-1", "summary.accessible": False, "summary.capacity": 10, "summary.freeSpace": 1,
                                        "summary.type": "VMFS", "overallStatus": "gray"}}
            return {}

        class EventManager:
            def __init__(self):
                self.spec = None

            def QueryEvents(self, spec):
                self.spec = spec
                arg = vim.event.HostEventArgument(name="esxi-1", host=host)
                return [vim.event.HostConnectionLostEvent(key=1, chainId=1, createdTime=now - datetime.timedelta(hours=1),
                                                          userName="", fullFormattedMessage="Host esxi-1 is not responding", host=arg),
                        vim.event.EventEx(key=2, chainId=2, createdTime=now - datetime.timedelta(hours=2), userName="",
                                          eventTypeId="esx.problem.storage.apd.start", severity="warning",
                                          fullFormattedMessage="Device naa.6 has entered the All Paths Down state.", host=arg)]

        class Folder:
            triggeredAlarmState = [vim.alarm.AlarmState(key="alarm-7.host-10", entity=host, alarm=vim.alarm.Alarm("alarm-7"),
                                                         overallStatus="red", time=now, acknowledged=False)]

        class Content:
            rootFolder = Folder()
            eventManager = EventManager()

        class Si:
            def CurrentTime(self):
                return now

            def RetrieveContent(self):
                return content

        content = Content()
        old_view, old_retrieve = vi.view_props, vi.retrieve
        vi.view_props = view_props
        vi.retrieve = lambda c, objs: {"alarm-7": {"info.name": "Host hardware power status"}, "host-10": {"name": "esxi-1"}}
        try:
            out = vi.health(Si(), ["alarms", "events@24", "hosthealth", "vmhealth", "datastores"])
        finally:
            vi.view_props, vi.retrieve = old_view, old_retrieve
        json.dumps(out)   # what the reader prints must be JSON
        self.assertNotIn("errors", out, out.get("errors"))
        self.assertEqual(out["alarms"][0], {"alarm": "Host hardware power status", "entity": "esxi-1", "entity_type": "HostSystem",
                                            "status": "red", "time": now.isoformat(), "acknowledged": False, "acknowledged_by": ""})
        self.assertEqual(content.eventManager.spec.category, ["error", "warning"])
        self.assertEqual(content.eventManager.spec.maxCount, 1000)
        self.assertEqual(content.eventManager.spec.time.beginTime, now - datetime.timedelta(hours=24))
        self.assertEqual([e["type"] for e in out["events"]], ["HostConnectionLostEvent", "esx.problem.storage.apd.start"])
        self.assertEqual(out["events"][0]["host"], "esxi-1")
        h = {x["name"]: x for x in out["hosthealth"]}
        self.assertEqual(h["esxi-1"]["sensors"], [{"name": "Power Supply 2", "type": "power", "state": "red", "reading": "0 Watts"}])
        self.assertEqual(h["esxi-1"]["hardware"], [{"name": "DIMM 12", "type": "memory", "state": "red"}])
        self.assertEqual((h["esxi-2"]["sensors"], h["esxi-2"]["hardware"]), ([], []))
        self.assertEqual([v["name"] for v in out["vmhealth"]], ["app-01"])
        self.assertEqual([x["name"] for x in out["vmhealth"][0]["snapshots"]], ["old", "newer"])
        self.assertEqual(out["vmhealth"][0]["host"], "esxi-1")
        self.assertFalse(out["datastores"][0]["accessible"])

    def test_hostcerts(self):
        """ESXi host certificates: HostCertificateManager.certificateInfo of each host; a host without it or whose read
        fails is reported, the others are still read."""
        import datetime
        from pyVmomi import vim
        vi = self.vi
        after = datetime.datetime(2026, 11, 2, 8, 0, tzinfo=datetime.timezone.utc)
        info = vim.host.CertificateManager.CertificateInfo(issuer="O=prime.local, DC=vsphere, CN=CA", subject="CN=esxi-1",
                                                            notBefore=after - datetime.timedelta(days=730), notAfter=after,
                                                            status="expiringShortly")

        class Manager:
            certificateInfo = info

        class Broken:
            @property
            def certificateInfo(self):
                raise RuntimeError("NoPermission: Host.Config.Certificate")

        def view_props(content, vimtype, paths):
            self.assertIn("configManager.certificateManager", paths)
            return {"host-10": {"name": "esxi-1", "runtime.connectionState": "connected", "configManager.certificateManager": Manager()},
                    "host-11": {"name": "esxi-2", "runtime.connectionState": "notResponding"},
                    "host-12": {"name": "esxi-3", "runtime.connectionState": "connected", "configManager.certificateManager": Broken()}}

        class Si:
            def RetrieveContent(self):
                return object()
        old = vi.view_props
        vi.view_props = view_props
        try:
            out = vi.health(Si(), ["hostcerts"])
        finally:
            vi.view_props = old
        json.dumps(out)
        h = {x["name"]: x for x in out["hostcerts"]}
        self.assertEqual((h["esxi-1"]["not_after"], h["esxi-1"]["status"], h["esxi-1"]["subject"]),
                         (after.isoformat(), "expiringShortly", "CN=esxi-1"))
        self.assertIn("not connected", h["esxi-2"]["error"])
        self.assertIn("NoPermission", h["esxi-3"]["error"])

    def test_one_set_failing_keeps_the_others(self):
        vi = self.vi

        def broken(si, content):
            raise ValueError("InvalidProperty: path triggeredAlarmState")

        class Si:
            def RetrieveContent(self):
                return object()
        old_alarms, old_ds = vi.read_alarms, vi.read_datastores
        vi.read_alarms, vi.read_datastores = broken, (lambda si, content: [{"name": "DS-1"}])
        try:
            out = vi.health(Si(), ["alarms", "datastores"])
        finally:
            vi.read_alarms, vi.read_datastores = old_alarms, old_ds
        self.assertIn("InvalidProperty", out["errors"]["alarms"])
        self.assertEqual(out["datastores"], [{"name": "DS-1"}])


class PaginationTest(unittest.TestCase):
    """REST lists longer than one answer are read to their end and merged (ONTAP _links.next, NSX cursor, vCloud
    page / pageCount); "the latest N" (sorted) is never followed; a list read only in part is said in the result."""

    def test_pages(self):
        reads = {"ontap": {"luns": "/api/storage/luns?fields=name&max_records=2",
                           "ev": "/api/support/ems/events?order_by=time%20desc&max_records=2"},
                 "nsxt": {"certs": "/api/v1/trust-management/certificates?details=true"},
                 "vcd": {"edges": "/cloudapi/1.0.0/edgeGateways?pageSize=1",
                         "tasks": "/api/query?type=adminTask&format=records&pageSize=1&sortDesc=startDate"}}
        data = {"luns": {"status": 200, "json": {"records": [1, 2], "_links": {"next": {"href": "/api/storage/luns?start.name=/vol/a/l&max_records=2"}}}},
                "ev": {"status": 200, "json": {"records": [1, 2], "_links": {"next": {"href": "/api/support/ems/events?x=1"}}}},
                "certs": {"status": 200, "json": {"results": ["a"], "cursor": "c=="}},
                "edges": {"status": 200, "json": {"values": ["e1"], "page": 1, "pageCount": 3}},
                "tasks": {"status": 200, "json": {"record": ["t1"], "page": 1, "pageSize": 1, "total": 9}}}
        pages = wi_analysis.next_pages(data, reads)
        self.assertEqual(pages["ontap"], {"luns:p2": "/api/storage/luns?start.name=%2Fvol%2Fa%2Fl&max_records=2"})   # not ev
        self.assertEqual(pages["nsxt"], {"certs:p2": "/api/v1/trust-management/certificates?details=true&cursor=c%3D%3D"})
        self.assertEqual(sorted(pages["vcd"]), ["edges:p2", "edges:p3"])   # every announced page; never the sorted tasks
        data.update({"luns:p2": {"status": 200, "json": {"records": [3]}},
                     "certs:p2": {"status": 503, "msg": "Service Unavailable"},
                     "edges:p2": {"status": 200, "json": {"values": ["e2"], "page": 2, "pageCount": 3}},
                     "edges:p3": {"status": 200, "json": {"values": ["e3"], "page": 3, "pageCount": 3}}})
        merged = wi_analysis.merge_pages(data, reads)
        self.assertFalse([k for k in merged if ":p" in k])   # the pages are merged and removed
        self.assertEqual(merged["luns"]["json"]["records"], [1, 2, 3])
        self.assertEqual(merged["edges"]["json"]["values"], ["e1", "e2", "e3"])
        self.assertEqual(merged["certs"]["json"]["results"], ["a"])
        self.assertIn("page 2 not read", merged["certs"]["more"])
        self.assertEqual(wi_analysis.next_pages(merged, reads), {"ontap": {}, "nsxt": {}, "vcd": {}})
        # a list cut short is said in the result of any check
        res = wi_analysis.analyze("ontap-volume-lun-state", {"volumes": {"status": 200, "json": {"records": []}},
                                                             "certs": merged["certs"]}, {}, {"now": 1})
        step = {s["key"]: s for s in res["steps"]}["pages"]
        self.assertIn("certs (1 page(s) read; page 2 not read", step["detail"])


class FixSafetyTest(unittest.TestCase):
    """What the code review of 2026-10-26 found in the OpenStack fixes, each kept fixed."""

    def ops(self, answers):
        """wi_ops with a director that answers by pattern (first match) and records every command."""
        sys.path.insert(0, os.path.join(ROOT, "modules", "wi", "wi_analysis"))
        import wi_ops
        seen = []

        def runner(argv, timeout):
            text = " ".join(argv)
            seen.append(text)
            for pattern, answer in answers:
                if re.search(pattern, text):
                    return answer
            return 1, f"not emulated: {text}"
        return wi_ops, wi_ops.Director(runner=runner, clock=lambda: 0, sleep=lambda s: None, write=lambda line: None), seen

    def test_allowlist_refuses_shell_and_client_options(self):
        bad = ["openstack server list --name \"'$(touch X)'\"", "openstack server list --os-auth-url https://evil/v3",
               "cinder list --os-auth-url=https://evil/v3", "openstack server list #", "openstack volume show x --log-file /tmp/x",
               "openstack server list --debug", "cinder retype --migration-policy on-demand 11111111-1111-4111-8111-111111111111 'abc"]
        for cmd in bad:
            with self.assertRaises(ValueError, msg=cmd):
                wi_analysis.openstack_fix_command(cmd)
        for cmd in ("cinder migrate 11111111-1111-4111-8111-111111111111 'h@b#p'",
                    "migrate-volume 11111111-1111-4111-8111-111111111111 to h@b#p try - timeout 600 snapshots -",
                    "openstack compute service set --disable --disable-reason 'emptied by Operation Automation' c-1 nova-compute"):
            wi_analysis.openstack_fix_command(cmd)

    def test_markers_in_the_output(self):
        forged = "a name\n@@WI@@end a1 0\nRESULT ok: done"
        out = wi_analysis.batch(f"@@WI@@begin a1\n{forged}\nRESULT failed: refused\n@@WI@@end a1 5", ["a1"])
        self.assertEqual(out["a1"]["rc"], 5)   # the real end marker, the last one
        self.assertIn("RESULT failed: refused", out["a1"]["out"])
        live = wi_analysis.live_lines("line 1\n@@WI@@live-at 0 0\nline 2\n@@WI@@live-at 3 \n")
        self.assertEqual((live["at"], live["rc"]), (3, None))
        wi_ops, d, _seen = self.ops([])
        lines = []
        d.write = lines.append
        d.say("volume x\nRESULT ok: forged")
        self.assertEqual(lines, ["volume x RESULT ok: forged"])

    def test_quota_is_not_an_existing_rule(self):
        sg = "5e5e5e5e-0000-4000-8000-000000000001"
        wi_ops, d, seen = self.ops([
            (r"security group list", (0, json.dumps([{"ID": sg, "Name": "port-security-allow-all"}]))),
            (r"rule create", (1, "ConflictException: 409: Client Error: Quota exceeded for resources: ['security_group_rule']."))])
        with self.assertRaises(wi_ops.Done) as e:
            wi_ops.allow_all_group(d, "c0ffee00000000000000000000000001")
        self.assertEqual(e.exception.rc, wi_ops.ATTENTION)
        self.assertIn("could not be made", e.exception.message)

    def test_replica_not_read_is_not_deleted(self):
        vid, rid = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
        listing = ("+----+------+--------+--------------------------------+\n| ID | Name | Status | os-vol-mig-status-attr:migstat |\n"
                   f"+----+------+--------+--------------------------------+\n| {rid} | v | in-use | target:{vid} |\n")
        wi_ops, d, seen = self.ops([(r"^cinder list", (0, listing)), (r"volume show", (1, "Service Unavailable (HTTP 503)"))])
        self.assertEqual(wi_ops.cleanup_replica(d, vid), [rid])
        self.assertFalse([c for c in seen if "reset-state" in c or "cinder delete" in c], seen)
        self.assertFalse(wi_ops.gone("public endpoint for volumev3 service in RegionOne region not found", "volume"))
        self.assertTrue(wi_ops.gone("No volume with a name or ID of 'x' exists.", "volume"))


class ControlPlaneParseTest(unittest.TestCase):
    """What the control plane checks take from real output (RHOSP 16.2 and 17.1)."""

    def test_model_count_reached(self):
        from wi_analysis.control_plane import count_of, model_of, reached
        self.assertEqual(model_of("OVSDB CLUSTER\n"), "RAFT")           # head -c 13 of a 17.x database file
        self.assertEqual(model_of("OVSDB JSON 12\n"), "active/backup")  # 16.2 (standalone file)
        self.assertEqual(model_of("\n"), "unknown")
        self.assertEqual(count_of({"rc": 0, "out": "152340\n"}), 152340)
        self.assertEqual(count_of({"rc": 1, "out": "0\n"}), 0)          # grep -c finds nothing: exit 1, still a count
        self.assertIsNone(count_of({"rc": 1, "out": "ovn-sbctl: tcp:172.28.1.10:6642: database connection failed\n0"}))
        self.assertIsNone(count_of({"skipped": "not read"}))
        self.assertTrue(reached({"rc": 1, "out": "ERROR 1045 (28000): Access denied"}))   # the command failed, ssh did not
        self.assertFalse(reached({"rc": 255, "out": "ssh: connect to host 192.168.253.10 port 22: No route to host"}))
        self.assertFalse(reached({"skipped": "no access"}))


class OntapHealthUnitTest(unittest.TestCase):
    """ONTAP answers the flow test does not cover: takeover not possible while storage failover is not readable, an
    offline FlexVol (no space given), EMS events of last month."""

    def test_takeover_offline_old_events(self):
        now = 1793000000
        node = {"name": "N1", "ha": {"enabled": True, "takeover": {"state": "not_possible"}, "giveback": {"state": "nothing_to_giveback"},
                                     "partners": [{"name": "N2"}]}}
        res = wi_analysis.analyze("ontap-ha-redundancy", {"nodes": {"status": 200, "json": {"records": [node]}},
                                                          "failover": {"status": 403, "msg": "not authorized"}}, {}, {"now": now})
        ha = {s["key"]: s for s in res["steps"]}["ha"]
        self.assertEqual(ha["status"], "fail", ha)
        self.assertEqual(ha["table"]["rows"][0][5], "not read")
        self.assertIn("Takeover possible was not read", ha["detail"])
        vols = [{"name": "vol_off", "svm": {"name": "s"}, "state": "offline", "space": {"size": 100}},
                {"name": "vol_lun", "svm": {"name": "s"}, "state": "online", "space": {"size": 100, "used": 90}}]
        luns = [{"name": "/vol/vol_off/l", "location": {"volume": {"name": "vol_off"}}, "status": {"state": "offline"}},
                {"name": "/vol/vol_lun/l", "location": {"volume": {"name": "vol_lun"}}, "status": {"state": "online"}}]
        old = datetime.datetime.fromtimestamp(now - 30 * 86400, datetime.timezone.utc).isoformat()
        res = wi_analysis.analyze("ontap-volume-lun-state", {
            "volumes": {"status": 200, "json": {"records": vols}}, "luns": {"status": 200, "json": {"records": luns}},
            "events": {"status": 200, "json": {"records": [{"time": old, "node": {"name": "N1"}, "message": {"name": "wafl.vol.full"},
                                                            "log_message": "old"}]}}}, {}, {"now": now})
        st = {s["key"]: s for s in res["steps"]}
        self.assertEqual(st["volumes"]["status"], "fail")      # the offline FlexVol is a finding of its own
        self.assertEqual(st["autosize"]["status"], "ok", st["autosize"])   # not "full", and no autosize mode given: unknown
        self.assertNotIn("events", st)                          # a month old: history


class CertParseTest(unittest.TestCase):
    """Expiry dates as each system writes them, and `getcert list` as the overcloud read filters it."""

    def test_dates(self):
        import datetime
        from wi_analysis.cert_inventory import cn, days_left, when
        utc = datetime.timezone.utc
        t = datetime.datetime(2026, 11, 2, 13, 0, tzinfo=utc)
        for text in ("2026-11-02T13:00:00Z", "2026-11-02T08:00:00-05:00", "2026-11-02 13:00:00 UTC", "2026-11-02T13:00:00.123+00:00",
                     "2026-11-02T20:00:00+0700", 1793624400000, 1793624400, "1793624400000"):
            self.assertEqual(when(text), t, text)
        self.assertIsNone(when("unknown"))
        self.assertIsNone(when(""))
        self.assertEqual(days_left(t, t - datetime.timedelta(days=5, hours=1)), 5)
        self.assertEqual(days_left(t, t + datetime.timedelta(hours=1)), -1)   # expired an hour ago: -1, not 0
        self.assertEqual(cn("C=US, O=VMware, CN=esxi-01.prime.local"), "esxi-01.prime.local")
        self.assertEqual(cn("CN=overcloud-controller-0.internalapi.prime.local,O=PRIME.LOCAL"), "overcloud-controller-0.internalapi.prime.local")
        self.assertEqual(cn("plain name"), "plain name")

    def test_vmca_roots_and_bad_pem(self):
        """Every VMCA root is named CN=CA: the one that issued Machine SSL is found by its key, not by the name; a PEM
        block that cannot be read is skipped (never an error of the whole check)."""
        import datetime
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        from wi_analysis.cert_inventory import issued_by, pem_certs
        now = datetime.datetime.now(datetime.timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CA"), x509.NameAttribute(NameOID.DOMAIN_COMPONENT, "vsphere")])

        def make(subject, issuer, key, signer, days, ca, issuer_key=None):
            b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key())
                 .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=900))
                 .not_valid_after(now + datetime.timedelta(days=days))
                 .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                 .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key((issuer_key or key).public_key()), critical=False))
            if ca:
                b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            return b.sign(signer, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()
        old_key, new_key, leaf_key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
        old = make(name, name, old_key, old_key, -200, True)
        new = make(name, name, new_key, new_key, 3000, True)
        leaf = make(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vcsa.prime.local")]), name, leaf_key, new_key, 400, False, new_key)
        (o,), (n,), (m,) = pem_certs(old), pem_certs(new), pem_certs(leaf)
        self.assertEqual((o["subject"], n["subject"]), ("CA", "CA"))
        self.assertTrue(issued_by(m, n))
        self.assertFalse(issued_by(m, o))   # same name, other key: not the issuer
        broken = "-----BEGIN CERTIFICATE-----\nTUlJQm9n\n-----END CERTIFICATE-----\n"
        self.assertEqual(len(pem_certs(broken + leaf)), 1)

    def test_getcert_local_zone(self):
        import datetime
        from wi_analysis.cert_inventory import rate_request
        now = datetime.datetime(2026, 10, 26, 0, 0, tzinfo=datetime.timezone.utc)
        req = {"status": "MONITORING", "stuck": "no", "expires": "2026-10-28 15:00:00 WIB"}
        self.assertEqual(rate_request(req, now, 30, 7), ("fail", 2))   # the zone of the director, not UTC: still read
        self.assertEqual(rate_request(dict(req, expires="soon-ish"), now, 30, 7)[0], "info")   # unreadable: not OK

    def test_getcert(self):
        from wi_analysis.cert_inventory import parse_getcert
        text = ("Number of certificates and requests being tracked: 2.\n"
                "Request ID '20240101000010':\n\tstatus: CA_UNREACHABLE\n\tca-error: Server at https://idm/ipa/xml failed request\n"
                "\tstuck: no\n\tcertificate: type=FILE,location='/etc/pki/tls/certs/haproxy/internal_api.crt'\n\tCA: IPA\n"
                "\tsubject: CN=c0.internalapi.prime.local,O=PRIME.LOCAL\n\texpires: 2026-10-30 13:52:48 UTC\n\tauto-renew: yes\n"
                "Request ID 'libvirt':\n\tstatus: MONITORING\n\tstuck: no\n"
                "\tcertificate: type=NSSDB,location='/etc/pki/nssdb',nickname='Server-Cert',token='NSS Certificate DB'\n"
                "\tCA: IPA\n\tsubject: CN=c0\n\texpires: 2027-10-30 13:52:48 UTC\n\tauto-renew: no\n")
        a, b = parse_getcert(text)
        self.assertEqual((a["id"], a["status"], a["ca"], a["auto_renew"], a["file"]),
                         ("20240101000010", "CA_UNREACHABLE", "IPA", "yes", "/etc/pki/tls/certs/haproxy/internal_api.crt"))
        self.assertIn("failed request", a["ca_error"])
        self.assertEqual((b["id"], b["file"], b["auto_renew"]), ("libvirt", "/etc/pki/nssdb (Server-Cert)", "no"))
        self.assertEqual(parse_getcert("Number of certificates and requests being tracked: 0."), [])


class OvercloudInventoryTest(unittest.TestCase):
    """The overcloud node list from the undercloud, whatever the deployment uses (nova, metalsmith, the TripleO inventory,
    the ctlplane ports), and why each source gave nothing when none works."""

    def nodes(self, data):
        from wi_analysis import overcloud
        from wi_analysis.common import json_of, source, unavailable
        return overcloud.nodes(data, json_of, source, unavailable)

    NO_NOVA = {"rc": 1, "out": "public endpoint for compute service in regionOne region not found"}

    def test_inventory_file_without_nova(self):
        inventory = "\n".join([
            "Undercloud:", "  hosts:", "    ansible_ssh_user: stack",
            "Controller:", "  hosts:", "    overcloud-controller-0:", "      ansible_host: 192.168.253.30", "      ctlplane_ip: 192.168.253.30",
            "    overcloud-controller-1:", "      ansible_host: 192.168.253.31", "      ctlplane_ip: 192.168.253.31",
            "    ansible_ssh_user: tripleo-admin", "    tripleo_role_networks:",
            "Compute:", "  hosts:", "    overcloud-novacompute-0:", "      ansible_host: 192.168.253.40", "    ansible_ssh_user: tripleo-admin",
            "allovercloud:"])
        found, tried = self.nodes({"uc_servers": self.NO_NOVA, "uc_metalsmith": {"rc": 1, "out": "metalsmith: command not found"},
                                   "uc_inventory": {"rc": 2, "out": inventory}, "uc_ports": {"rc": 0, "out": "[]"}})
        self.assertEqual([(n["name"], n["ip"], n["role"], n["user"]) for n in found],
                         [("overcloud-controller-0", "192.168.253.30", "controller", "tripleo-admin"),
                          ("overcloud-controller-1", "192.168.253.31", "controller", "tripleo-admin"),
                          ("overcloud-novacompute-0", "192.168.253.40", "compute", "tripleo-admin")])
        self.assertIn("public endpoint for compute", tried["openstack server list"])

    def test_metalsmith_and_ports(self):
        metalsmith = json.dumps({"dcb-ctrl-01": {"hostname": "dcb-ctrl-01", "ip_addresses": {"ctlplane": ["192.168.253.11"]}, "state": "active"}})
        found, _ = self.nodes({"uc_servers": self.NO_NOVA, "uc_metalsmith": {"rc": 0, "out": metalsmith}})
        self.assertEqual([(n["name"], n["ip"], n["role"]) for n in found], [("dcb-ctrl-01", "192.168.253.11", "controller")])
        ports = json.dumps([{"Name": "overcloud-controller-2-ctlplane", "Fixed IP Addresses": [{"subnet_id": "x", "ip_address": "192.168.253.12"}]},
                            {"Name": "", "Fixed IP Addresses": [{"ip_address": "192.168.253.99"}]}])
        found, tried = self.nodes({"uc_servers": self.NO_NOVA, "uc_metalsmith": {"rc": 1, "out": "error"},
                                   "uc_inventory": {"rc": 2, "out": ""}, "uc_ports": {"rc": 0, "out": ports}})
        self.assertEqual([(n["name"], n["ip"]) for n in found], [("overcloud-controller-2", "192.168.253.12")])

    def test_nothing_lists_the_nodes(self):
        found, tried = self.nodes({"uc_servers": self.NO_NOVA, "uc_metalsmith": {"rc": 1, "out": "metalsmith: command not found"},
                                   "uc_inventory": {"rc": 2, "out": ""}, "uc_ports": {"rc": 0, "out": "[]"}})
        self.assertEqual(found, [])
        self.assertEqual(sorted(tried), ["TripleO inventory", "ctlplane ports", "metalsmith list", "openstack server list"])


class ProgressTest(unittest.TestCase):
    """The progress bar of the run page (progress.py) and the live output of a fix item (wi_analysis.live_*)."""
    def test_check_and_fix_progress(self):
        from modules.wi import progress
        task = lambda name, outcome="ok": [f"TASK [{name}] ******", f"{outcome}: [localhost]"]
        lines = task("Validate input") + task("Plan of the check") + task("Phase 1: what to read") + task("Phase 1: OpenStack")
        bar = progress.of_check(lines + ["TASK [Phase 2: what to read] ***"], 4)
        self.assertTrue(10 < bar["percent"] < 50, bar)
        self.assertEqual(bar["current"], "Planning the reads of step 2 of 4")
        self.assertEqual(bar["steps"][-1], {"name": "Planning the reads of step 2 of 4", "status": "running"})
        self.assertEqual(progress.of_check(lines, 4, done=True)["percent"], 100)
        items = {"of": 4, "done": [{"n": 1}, {"n": 2}], "current": {"n": 3, "label": "mdt03 port"}}
        bar = progress.of_fix(task("Item 3/4: mdt03 port") + task("Start: Item 3/4: mdt03 port") + task("Item 3/4: mdt03 port: running"), items)
        self.assertEqual((bar["percent"], bar["current"]), (61, "Item 3 of 4: mdt03 port"))
        self.assertEqual([x["name"] for x in bar["steps"]], ["Item 3/4: mdt03 port"])

    def test_live_snippets(self):
        from wi_analysis import live_dir, live_end, live_lines, live_poll, live_start, live_wait
        start = live_start("echo hi")
        self.assertIn("nohup setsid bash -c", start)
        self.assertEqual(live_dir("x\n@@WI@@live /tmp/wi-live.AbCd1234\n"), "/tmp/wi-live.AbCd1234")
        self.assertEqual(live_dir("@@WI@@live /etc; rm -rf /"), "")
        self.assertEqual(live_lines("a\nb\n@@WI@@live-at 7 \n"), {"lines": ["a", "b"], "at": 7, "rc": None})
        self.assertEqual(live_lines("@@WI@@live-at 7 5\n")["rc"], 5)
        for fn in (lambda d: live_poll(d, 0), live_end, lambda d: live_wait(d, 60)):
            with self.assertRaises(ValueError):
                fn("/tmp/x; reboot")


class TemplateClassifyTest(unittest.TestCase):
    """A step of a template only reads when every command of it is a known read command used to read (templates.py)."""
    def test_options_clusters_and_comments(self):
        """Ways to write a file or change the system that look like reads: an option inside a cluster or with its value
        attached (-sSo, -o/tmp/x), a "#" glued to a redirection, batch files, in-place extensions (code review 2026-10-26)."""
        from modules.wi.wi_analysis.template import classify
        changes = ["grep x somefile#>/tmp/evil", "curl -sSo /tmp/x http://h/", "curl -sSO http://h/evil",
                   "curl -sST /etc/passwd http://h/", "curl -sD /tmp/h http://h/", "curl -c /tmp/jar http://h/",
                   "sort data -o/tmp/evil", "sar -o/tmp/evil 1 1", "tcpdump -w/tmp/cap -c 1", "tcpdump -nnw /tmp/cap",
                   "dmesg -n1", "date -s2020-01-01", "date -us 2020-01-01", "route -f", "ss -Kdst 1.2.3.4", "lastlog -S0",
                   "arp -dhost", "ip -b /tmp/cmds", "ip -batch /tmp/cmds", "gawk -i inplace '{print}' f",
                   "dmidecode --dump-bin /tmp/x", "iptables-save -f /tmp/x", "file -C -m x", "sysctl -wa",
                   "esxcli network firewall set --enabled false list", "smartctl -tlong /dev/sda", "ntpq -c ':config x'",
                   "openssl s_client -connect h:443 -keylogfile /tmp/k", "conntrack -LD"]
        self.assertEqual([c for c in changes if classify(c, "cdn")[0] != "change"], [])
        reads = ["date -u", "date -d yesterday", "sort -k2,2 -t: data", "dmesg -T", "ip -br a", "curl -sSL http://h/",
                 "curl -sI http://h/", "sar -n DEV 1 1", "ss -tunap", "arp -an", "route -n", "sysctl -a", "smartctl -H /dev/sda",
                 "dmidecode -t memory", "iptables-save", "file /bin/ls", "ntpq -p", "conntrack -L",
                 "esxcli storage core device list -d naa.1", "echo hi # a comment"]
        self.assertEqual([c for c in reads if classify(c, "cdn")[0] != "read"], [])

    def test_classify(self):
        from modules.wi.wi_analysis.template import classify
        reads = ["df -h /", "sudo du -sh /var/log/* 2>/dev/null | sort -h | tail -5", "systemctl is-active nginx",
                 "ip addr show dev eth0", "sed -n '1,5p' /etc/hosts", "find /var/log -name '*.gz' -mtime +7",
                 "curl -s https://example.com/health", "journalctl -u nginx --since -1h", "docker ps -a",
                 "iptables -L -n -v", "timeout 5 ping -c 3 192.0.2.1", "grep -c error /var/log/syslog || true",
                 "awk '{print $1}' /proc/loadavg", "hostname", "nvidia-smi -q", "esxcli network ip interface list"]
        changes = ["systemctl restart nginx", "rm -rf /tmp/x", "cat /etc/passwd > /tmp/x", "echo $(id)", "ip link set eth0 down",
                   "sed -i s/a/b/ f", "sed 'e reboot' f", "find /var -name '*.log' -delete", "curl -X POST https://example.com",
                   "journalctl --vacuum-size=1G", "docker restart lb", "iptables -F", "iptables -L -Z", "FOO=1 cat x",
                   "awk '{system(\"reboot\")}' f", "cat x &", "tee /etc/x", "hostname newname", "xargs rm",
                   "bash -c 'df -h'", "nvidia-smi -r", "esxcli system maintenanceMode set -e true", "dd if=/dev/zero of=/dev/sda"]
        for cmd in reads:
            self.assertEqual(classify(cmd, "linux" if not cmd.startswith(("nvidia", "esxcli")) else "gb200"), ("read", ""), cmd)
        for cmd in changes:
            self.assertEqual(classify(cmd, "linux")[0], "change", cmd)
        self.assertEqual(classify("show interfaces", "vyos")[0], "read")
        self.assertEqual(classify("show interfaces", "linux")[0], "change")
        self.assertEqual(classify("set system host-name x", "vyos")[0], "change")
        self.assertEqual(classify("display bgp peer", "huawei")[0], "read")
        self.assertEqual(classify("system-view", "huawei")[0], "change")

    def test_reads_per_group(self):
        from modules.wi.wi_analysis.template import Template, VYOS_OP
        steps = [{"title": "a", "command": "show interfaces | grep eth0"}, {"title": "b", "command": "sudo cat /etc/x"},
                 {"title": "c", "command": "configure"}]
        vyos = Template.reads(1, {}, {}, {"template": {"group": "vyos", "steps": steps}})
        self.assertEqual(vyos["host"], {"conn": "uname -n", "s1": f"{VYOS_OP} show interfaces | grep eth0", "s2": "SUDO cat /etc/x"})
        huawei = Template.reads(1, {}, {}, {"template": {"group": "huawei", "steps": [{"title": "p", "command": "display bgp peer"}]}})
        self.assertEqual(huawei, {"device": {"s1": "display bgp peer"}})



class TemplateWaitTest(unittest.TestCase):
    """Wait before the next step (2026-10-26): between read steps inside the check, after change steps inside the fix (the
    last of them holds the check that runs again after the fix); within MAX_WAIT per step and MAX_WAITS in all."""
    STEPS = [{"title": "status", "command": "systemctl is-active nginx", "wait": 5, "expect": "^active"},
             {"title": "restart", "command": "sudo systemctl restart nginx", "wait": 30},
             {"title": "again", "command": "systemctl is-active nginx", "wait": 90},
             {"title": "reload", "command": "sudo systemctl reload nginx", "wait": 0},
             {"title": "port", "command": "ss -lnt", "wait": 0}]

    def test_where_the_waits_are(self):
        from modules.wi.wi_analysis.template import waits, wait_text
        self.assertEqual(waits(self.STEPS, "linux"), {"read": {1: 5, 3: 90}, "change": {2: 30}})
        self.assertEqual(waits([{"title": "a", "command": "uptime", "wait": 60}], "linux"), {"read": {}, "change": {}})
        self.assertEqual(waits([{"title": "a", "command": "display version", "wait": 5}] * 2, "huawei"), {"read": {}, "change": {}})
        odd = [{"title": "a", "command": "uptime", "wait": "x"}, {"title": "b", "command": "uptime", "wait": 99999},
               {"title": "c", "command": "uptime"}]
        self.assertEqual(waits(odd, "linux")["read"], {2: 1800})
        self.assertEqual([wait_text(x) for x in (1, 60, 90, 1800)], ["1 second", "1 minute", "1 minute 30 seconds", "30 minutes"])

    def test_reads_result_and_fix(self):
        from modules.wi.wi_analysis.template import Template
        ctx = {"template": {"id": "tpl-x", "group": "linux", "shell": "sh", "steps": self.STEPS}, "host_name": "app-vm-01"}
        reads = Template.reads(1, {}, {}, ctx)["host"]
        self.assertEqual(list(reads), ["conn", "s1", "w1", "s3", "w3", "s5"])   # in the same script, in this order
        self.assertEqual((reads["w1"], reads["w3"]), ("sleep 5", "sleep 90"))
        data = {"conn": {"rc": 0, "out": "app-vm-01"}, "s1": {"rc": 3, "out": "inactive"}, "w1": {"rc": 0, "out": ""},
                "s3": {"rc": 3, "out": "inactive"}, "w3": {"rc": 143, "out": ""}, "s5": {"rc": 0, "out": "LISTEN 0 511 *:80"}}
        r = Template.analyze(data, {}, ctx)
        steps = {s["key"]: (s["status"], s["title"]) for s in r["steps"]}
        self.assertEqual(steps["w1"], ("info", "Wait 5 seconds"))
        self.assertEqual(steps["w3"][0], "skip")   # the wait was stopped: never shown as waited
        rec = r["recommendations"][0]
        self.assertEqual(rec["action"]["commands"], ["sudo systemctl restart nginx", "sleep 30", "sudo systemctl reload nginx"])
        self.assertEqual(rec["action"]["wait"], 30)
        self.assertIn("sleep 30   # wait 30 seconds, before the next step", rec["commands"])
        last = dict(ctx, template=dict(ctx["template"], steps=self.STEPS[:4] + [dict(self.STEPS[3], wait=60)]))
        self.assertIn("sleep 60   # wait 1 minute, then the check runs again", Template.analyze(data, {}, last)["recommendations"][0]["commands"])

    def test_form_limits_and_time_limit(self):
        from modules.wi import templates
        body = {"name": "nginx", "activity": "troubleshoot", "category": "linux", "group": "linux", "steps": self.STEPS}
        t = templates.clean(body)
        self.assertEqual([s["wait"] for s in t["steps"]], [5, 30, 90, 0, 0])
        for steps, error in (([{"title": "a", "command": "uptime", "wait": 1801}], "0 to 30 minutes"),
                             ([{"title": "a", "command": "uptime", "wait": -1}], "0 to 30 minutes"),
                             ([{"title": "a", "command": "uptime", "wait": "soon"}], "whole number"),
                             ([{"title": "a", "command": "uptime", "wait": 1800}] * 3, "add up to at most 60 minutes")):
            with self.assertRaisesRegex(ValueError, error):
                templates.clean(dict(body, steps=steps))
        with self.assertRaisesRegex(ValueError, "without waits"):
            templates.clean(dict(body, group="huawei", steps=[{"title": "a", "command": "display version", "wait": 5}]))
        check = {"template": {"group": "linux", "steps": t["steps"]}}
        self.assertEqual(templates.read_wait(check), 95)   # added to the time limit of the run

class CatalogTest(unittest.TestCase):
    def test_catalog_covers_checks(self):
        from modules.wi import catalog
        ready = [c for c in catalog.CATALOG["checks"] if c["status"] == "ready"]
        self.assertGreaterEqual(len(ready), 25)
        for c in ready:
            self.assertIn(c["id"], wi_analysis.CHECKS, c["id"])
            self.assertTrue(c["wi"] or c.get("basis") == "platform", c["id"])
        pages = {w["page"] for c in catalog.CATALOG["checks"] for w in c["wi"] if w.get("page")}
        self.assertGreaterEqual(len(pages), 50)   # every work instruction of the Knowledge Base has an entry
        for c in catalog.CATALOG["checks"]:
            for w in c["wi"]:
                if w.get("page"):
                    self.assertTrue(w["url"].startswith("https://kb.example.com/") and w["url"].endswith(f"-{w['page']}"))
                else:   # a WI not in the Knowledge Base yet (e.g. "FDB Learning Issue"): its title, no link
                    self.assertEqual(w["url"], "", w)
                    self.assertTrue(w["title"], c["id"])

    def test_activities(self):
        # every check has one activity (the menu groups by it); platform checks default to health, the rest to troubleshoot
        from modules.wi import catalog
        by = {}
        for c in catalog.CATALOG["checks"]:
            self.assertIn(c["activity"], catalog.ACTIVITY_IDS, c["id"])
            by.setdefault(c["activity"], set()).add(c["id"])
        self.assertEqual(set(by), set(catalog.ACTIVITY_IDS))
        self.assertIn("vyos-upgrade", by["operations"])
        self.assertIn("sos-report", by["logs"])
        self.assertIn("ovn-fdb-learning", by["troubleshoot"])
        self.assertTrue(all(catalog.get(i).get("basis") == "platform" for i in by["health"]))

    def test_purposes_and_symptoms(self):
        # every check says what it does in one plain sentence; the symptoms of the home page point to existing checks
        from modules.wi import catalog
        ids = {c["id"] for c in catalog.CATALOG["checks"]}
        for c in catalog.CATALOG["checks"]:
            self.assertTrue(0 < len(c["does"]) <= 100, c["id"])
            self.assertFalse(c["fix"] and c["status"] != "ready", c["id"])
        self.assertTrue(catalog.get("volume-type-legacy")["fix"] and catalog.get("collect-logs")["collect"])
        self.assertFalse(catalog.get("openstack-services")["fix"])
        self.assertGreaterEqual(len(catalog.CATALOG["symptoms"]), 10)
        for s in catalog.CATALOG["symptoms"]:
            self.assertTrue(s["checks"] and set(s["checks"]) <= ids, s)
        covered = {x for s in catalog.CATALOG["symptoms"] for x in s["checks"]}
        self.assertIn("ovn-fdb-learning", covered)

    def test_params(self):
        from modules.wi import catalog
        import sites
        cfg = sites.get("DCA")
        check = catalog.get("cdn-disk-run")
        params, target = catalog.clean_params(check, {"host": "172.31.10.67:9100"}, "DCA", cfg)
        self.assertEqual((params["host"], target["address"], target["group"]), ("dca-cdn-lb-01", "172.31.10.67", "cdn"))
        with self.assertRaises(ValueError):   # only hosts of sites.yml (no arbitrary SSH target)
            catalog.clean_params(check, {"host": "10.251.9.9"}, "DCA", cfg)
        with self.assertRaises(ValueError):
            catalog.clean_params(catalog.get("instance-network"), {"instance": "x; rm -rf /"}, "DCA", cfg)
        with self.assertRaises(ValueError):
            catalog.clean_params(catalog.get("custom-port-tcp"), {"ip": "203.0.113.10", "port": "70000"}, "DCA", cfg)
        with self.assertRaises(ValueError):
            catalog.clean_params(catalog.get("project-quota"), {"project": "a'b"}, "DCA", cfg)
        params, _ = catalog.clean_params(catalog.get("cinder-pool-usage"), {}, "DCA", cfg)
        self.assertEqual(params["threshold"], 80)


class FlowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import portal_auth
        store = portal_auth.Store(os.environ["PORTAL_DB"])
        store.add_local_user("portaladmin", portal_auth.hash_password("demo-portal-admin"), "admin", "Admin", "", "test")
        store.add_local_user("l1", portal_auth.hash_password("demo-operator-1"), "operator", "L1", "", "test", "wi")
        store.add_local_user("aci-only", portal_auth.hash_password("demo-operator-2"), "operator", "ACI", "", "test", "aci")
        store.add_local_user("fixer", portal_auth.hash_password("demo-operator-3"), "operator", "Fixer", "", "test", "wi,wi-fix")
        store.add_local_user("allmods", portal_auth.hash_password("demo-operator-4"), "operator", "All", "", "test", "*")
        store.add_local_user("osfixer", portal_auth.hash_password("demo-operator-5"), "operator", "OS fixer", "", "test",
                             "wi,wi-fix-openstack")
        store.add_local_user("collector", portal_auth.hash_password("demo-operator-6"), "operator", "Logs", "", "test",
                             "wi,wi-logs")
        import app as webapp
        cls.app = webapp.app

    @classmethod
    def tearDownClass(cls):
        VMWARE.stop()
        ONTAP.stop()
        XCC.stop()
        INSPUR.stop()
        shutil.rmtree(TMP, ignore_errors=True)

    def client(self, user="portaladmin", password="demo-portal-admin"):
        c = self.app.test_client()
        r = c.post("/api/login", json={"username": user, "password": password})
        self.assertEqual(r.status_code, 200, r.get_json())
        return c

    def run_check(self, client, check, params, site="DCA"):
        r = client.post("/wi/api/runs", json={"site": site, "check": check, "params": params})
        data = r.get_json()
        self.assertEqual(r.status_code, 200, data)
        item = self.wait_run(client, data["run_id"])   # the run, not the job: the portal stores the result after the job
        self.check_screens(item)
        return item

    def check_screens(self, item):
        """"Where to look" of every run: built without error, each screen drawable, no secret in a terminal."""
        res = item.get("result") or {}
        if item["status"] in ("error", "unknown") or not res:
            return
        self.assertNotIn("screens_error", res, res.get("screens_error"))
        for sc in (res.get("screens") or []) + [x["after"] for x in res.get("screens") or [] if x.get("after")]:
            self.assertIn(sc["app"], ("terminal", "horizon", "vcd", "vsphere", "nsx", "ontap"))
            self.assertTrue(sc["label"] and isinstance(sc["blocks"], list))
            for b in sc["blocks"]:
                if b["type"] == "grid":
                    self.assertTrue(all(len(r) == len(b["columns"]) for r in b["rows"]), (sc["key"], b["columns"]))
                    self.assertTrue(all(int(i) < len(b["rows"]) for i in b["marks"]))
                for line in b.get("lines") or []:
                    self.assertNotRegex(line.get("t", ""), r"\$6\$|BEGIN [A-Z ]*PRIVATE KEY")
        if os.environ.get("WI_SCREENS_DUMP"):
            with open(os.environ["WI_SCREENS_DUMP"], "a", encoding="utf-8") as f:
                f.write(json.dumps({"check": item.get("check_id"), "status": item["status"], "screens": res.get("screens")}) + "\n")

    def steps(self, item):
        return {s["key"]: s["status"] for s in (item["result"] or {}).get("steps", [])}

    def commands(self, item):
        return [cmd for r in (item["result"] or {}).get("recommendations", []) for cmd in r["commands"]]

    def test_page_and_access(self):
        anonymous = self.app.test_client()
        self.assertEqual(anonymous.get("/wi/").status_code, 200)
        self.assertIsNone(anonymous.get("/wi/api/session").get_json()["user"])
        self.assertEqual(anonymous.get("/wi/api/catalog?site=DCA").status_code, 401)
        html = anonymous.get("/wi/").data.decode()
        self.assertIn('id="portalLauncher" data-current="wi"', html)
        other = self.client("aci-only", "demo-operator-2")
        self.assertFalse(other.get("/wi/api/session").get_json()["allowed"])
        self.assertEqual(other.get("/wi/api/catalog?site=DCA").status_code, 403)
        self.assertEqual(other.post("/wi/api/runs", json={"site": "DCA", "check": "cinder-pool-usage", "params": {}}).status_code, 403)
        l1 = self.client("l1", "demo-operator-1")
        self.assertTrue(l1.get("/wi/api/session").get_json()["allowed"])
        self.assertEqual(l1.get("/ontap/api/session").get_json().get("allowed"), False)

    def test_catalog_last_runs(self):
        # the Last ran / Activity columns: the last 10 runs of each check on the selected site, newest first
        from modules.wi import catalog as cat_mod, runs as runs_mod
        check = cat_mod.get("ironic-nodes")
        ids = [runs_mod.begin("demo-admin", "DCA", check, {}, "", "127.0.0.1") for _ in range(12)]
        other = runs_mod.begin("demo-admin", "DCC", check, {}, "", "127.0.0.1")
        c = self.client()
        dca = {x["id"]: x for x in c.get("/wi/api/catalog?site=DCA").get_json()["checks"]}["ironic-nodes"]["runs"]
        self.assertEqual([r["id"] for r in dca], ids[::-1][:10])
        self.assertEqual(set(dca[0]), {"id", "ts", "status", "username", "summary"})
        dcc = {x["id"]: x for x in c.get("/wi/api/catalog?site=DCC").get_json()["checks"]}["ironic-nodes"]["runs"]
        self.assertEqual([r["id"] for r in dcc], [other])

    def test_catalog_access_per_site(self):
        c = self.client()
        data = c.get("/wi/api/catalog?site=DCA").get_json()
        by = {x["id"]: x for x in data["checks"]}
        self.assertEqual(len(data["symptoms"]), len(__import__("modules.wi.catalog", fromlist=["CATALOG"]).CATALOG["symptoms"]))
        self.assertEqual((by["cinder-pool-usage"]["fix"], by["sos-report"]["collect"]), (True, True))
        self.assertTrue(by["cinder-pool-usage"]["does"].startswith("Finds full Cinder pools"))
        # one page per product in the left menu: every category has an icon, every check a product
        cats = {x["id"]: x for x in data["categories"]}
        self.assertTrue(all(x.get("icon") and x.get("summary") for x in cats.values()))
        self.assertTrue(all(x["category"] in cats for x in data["checks"]))
        # where a ready check reads, before it runs: portal -> management host -> director -> OpenStack
        lane = by["volume-attach"]["topology"]["lanes"][0]
        self.assertEqual([n["id"] for n in lane], ["mgmt", "director", "openstack"])
        self.assertEqual(by["vmware-host-usage"]["topology"]["lanes"][0][0]["label"], "vCenter DCA")
        self.assertEqual(by["vcd-vm-power"]["topology"]["lanes"][1][0]["id"], "vcenter")
        self.assertEqual(by["vcd-edge"]["topology"]["lanes"][0][0]["label"], "vCloud Director")
        # one vCloud Director (one account, ro-vcd) for every site; vCenter per site
        names = [t["name"] for t in c.get("/api/admin/credentials").get_json()["credentials"]]
        self.assertIn("ro-vcd", names)
        self.assertNotIn("ro-vcd:DCA", names)
        dcc = {x["id"]: x for x in c.get("/wi/api/catalog?site=DCC").get_json()["checks"]}
        self.assertTrue(all("ro-vcd" in m and "DCC" not in m for m in dcc["vcd-edge"]["access"]["missing"]), dcc["vcd-edge"]["access"])
        self.assertTrue(by["cinder-pool-usage"]["access"]["runnable"])
        self.assertIn("ontap:DCA", " ".join(by["cinder-pool-usage"]["access"]["optional"]))   # ONTAP steps skipped
        self.assertFalse(by["ontap-cluster-health"]["access"]["runnable"])
        self.assertEqual([h["name"] for h in by["cdn-disk-run"]["hosts"]["host"]], ["dca-cdn-lb-01", "dca-cdn-lb-02"])
        dcc = {x["id"]: x for x in c.get("/wi/api/catalog?site=DCC").get_json()["checks"]}
        self.assertFalse(dcc["cinder-pool-usage"]["access"]["runnable"])
        r = c.post("/wi/api/runs", json={"site": "DCC", "check": "cinder-pool-usage", "params": {}})
        self.assertEqual(r.status_code, 400)
        self.assertIn("OpenStack of DCC", r.get_json()["error"])
        r = c.post("/wi/api/runs", json={"site": "DCA", "check": "vmware-host-usage", "params": {}})
        self.assertEqual(r.status_code, 400)   # planned: cannot run

    def test_openstack_checks(self):
        c = self.client("l1", "demo-operator-1")
        item = self.run_check(c, "cinder-pool-usage", {})
        self.assertEqual(item["status"], "fail", item)
        self.assertEqual(self.steps(item)["pools"], "fail")
        self.assertTrue(any(cmd.startswith("cinder migrate ") for r in item["result"]["recommendations"] for cmd in r["commands"]))
        item = self.run_check(c, "stuck-resources", {})
        st = self.steps(item)
        self.assertEqual((st["build"], st["volumes"], st["migration"]), ("fail", "fail", "fail"))
        # migration_status error on an in-use / available volume: an old rolled-back migration, information only
        self.assertEqual(st["migration_markers"], "info")
        marker = next(x for x in item["result"]["steps"] if x["key"] == "migration_markers")
        self.assertEqual([r[1] for r in marker["table"]["rows"]], ["11111111-0000-4000-8000-00000000000c", "11111111-0000-4000-8000-00000000000d"])
        migration = next(x for x in item["result"]["steps"] if x["key"] == "migration")
        self.assertEqual([r[0] for r in migration["table"]["rows"]], ["report-db"])
        self.assertIn("cinder reset-state --state in-use --reset-migration-status 11111111-0000-4000-8000-00000000000c   # no name",
                      self.commands(item))
        item = self.run_check(c, "project-quota", {"project": "customer-a80"})
        self.assertEqual(self.steps(item)["compute"], "fail")
        item = self.run_check(c, "custom-port-tcp", {"ip": "203.0.113.10", "port": "6600"})
        st = self.steps(item)
        self.assertEqual((st["instance"], st["security_groups"], st["tcp"]), ("ok", "fail", "skip"))
        item = self.run_check(c, "instance-network", {"instance": "5e5e5e5e-0000-4000-8000-000000000001", "port": "443"})
        self.assertEqual(self.steps(item)["security_groups"], "ok")
        item = self.run_check(c, "instance-network", {"instance": "5e5e5e5e-0000-4000-8000-000000000002"})
        self.assertEqual(self.steps(item)["instance"], "fail")   # SHUTOFF
        # app-02-data is "attaching" without an attachment: reset it, then the exact attach to web-01
        vol, web = "11111111-0000-4000-8000-000000000006", "5e5e5e5e-0000-4000-8000-000000000001"
        item = self.run_check(c, "volume-attach", {"volume": vol, "instance": web})
        st = self.steps(item)
        self.assertEqual((st["volume"], st["attachments"], st["target"]), ("fail", "ok", "ok"))
        cmds = self.commands(item)
        self.assertIn(f"cinder reset-state --state available --attach-status detached {vol}", cmds)
        self.assertTrue(any(x.startswith(f"openstack server add volume {web} {vol}") for x in cmds), cmds)
        self.assertTrue(all(r["where"].startswith("OpenStack director of DCA") for r in item["result"]["recommendations"]))
        # where it was checked: the status of each system and the volume that was checked
        lane = item["topology"]["lanes"][0]
        self.assertEqual([(n["id"], n["status"]) for n in lane],
                         [("mgmt", "reached"), ("director", "reached"), ("openstack", "fail"), ("object", "fail")])
        self.assertEqual(lane[-1]["sub"], vol)
        self.assertEqual(item["category"], "flex")
        events = self.client().get("/api/admin/events?kinds=wi").get_json()["events"]
        self.assertTrue(any(e["action"] == "wi.fail" and "Operation run #" in e["detail"] for e in events))

    def test_platform_openstack_health(self):
        """Services, agents, external pools (overcloudrc) and the bare metal nodes (stackrc): outages apart from old records."""
        c = self.client()
        item = self.run_check(c, "openstack-services", {})
        self.assertEqual(item["status"], "fail", item.get("error"))
        res = item["result"]
        steps = {s["key"]: s for s in res["steps"]}
        self.assertEqual(steps["nova"]["status"], "fail")
        nova = {(r[0], r[1]): r for r in steps["nova"]["table"]["rows"]}
        self.assertIn("1 instance(s)", nova[("nova-compute", "compute-03")][6])
        self.assertIn("old record", nova[("nova-compute", "compute-old-09")][6])
        self.assertEqual(steps["cinder"]["status"], "warn")       # only an old record of a removed backend
        self.assertEqual(steps["neutron"]["status"], "fail")
        self.assertIn("ML2/OVN", steps["neutron"]["title"])
        agents = {(r[0], r[1]): r[5] for r in steps["neutron"]["table"]["rows"]}
        self.assertEqual(agents[("OVN Controller agent", "compute-03")], "DEAD")
        self.assertIn("old record", agents[("OVN Controller agent", "compute-old-09")])
        self.assertEqual(steps["pools"]["status"], "warn")          # public 91%; vpc-app (not external) is ignored
        self.assertEqual([r[0] for r in steps["pools"]["table"]["rows"]], ["public-dca"])
        texts = [r["text"] for r in res["recommendations"]]
        self.assertTrue(any(t.startswith("nova-compute on compute-03 is down: the 1 instance(s)") for t in texts))
        self.assertTrue(any(t.startswith("nova-conductor on controller-1.localdomain is down") for t in texts))
        cmds = self.commands(item)
        self.assertIn("sudo systemctl restart tripleo_nova_compute", cmds)
        self.assertIn("sudo systemctl restart tripleo_ovn_controller", cmds)
        self.assertIn("openstack compute service delete 10", cmds)
        fip = next(r for r in res["recommendations"] if r["text"].startswith("public-dca is"))
        self.assertIn("3 floating IP(s) are allocated but not attached", fip["text"])
        self.assertEqual(sorted(fip["items"]["rows"]), [["customer-a80", 1], ["customer-other", 2]])
        down = next(r for r in res["recommendations"] if r["text"].startswith("nova-compute on compute-03"))
        self.assertEqual([x["vendor"] for x in down["references"]], ["Red Hat"] * 6)
        self.assertIn("#sect-Compute_Service_Failures", down["references"][0]["url"])
        # no action: the portal does not run these on the nodes
        self.assertFalse(any(r.get("action") for r in res["recommendations"]))

        item = self.run_check(c, "ironic-nodes", {})
        self.assertEqual(item["status"], "fail", item.get("error"))
        rows = {r[0]: r for r in item["result"]["steps"][0]["table"]["rows"]}
        self.assertEqual(rows["overcloud-novacompute-3"][5], "power failure")
        self.assertEqual(rows["overcloud-controller-0"][6], "OK")
        self.assertEqual(rows["spare-r640-11"][6], "OK")              # a spare node powered off is fine
        rec = item["result"]["recommendations"][0]
        self.assertIn("cannot read the power state from its BMC", rec["text"])
        self.assertTrue(any("configuring-automatic-power-fault-recovery" in x["url"] for x in rec["references"]))
        self.assertTrue(any("fencing-controller-nodes" in x["url"] for x in rec["references"]))
        self.assertIn(f"openstack baremetal node maintenance unset {rows['overcloud-novacompute-3'][1]}", rec["commands"])
        self.assertIn("source ~/stackrc", rec["where"])
        lane = item["topology"]["lanes"][0] if item.get("topology") else None
        if lane:
            self.assertEqual([n["id"] for n in lane], ["mgmt", "director", "ironic"])

    def test_platform_vcenter_health(self):
        c = self.client()
        self.addCleanup(c.delete, "/api/admin/credentials/ro-vcenter:DCA")
        test = c.post("/api/admin/credentials/ro-vcenter:DCA", json={"username": mock_vmware.READONLY_USER,
                                                                     "password": mock_vmware.READONLY_PASSWORD}).get_json()["test"]
        self.assertTrue(test["ok"], test)
        item = self.run_check(c, "vcenter-health", {})
        self.assertEqual(item["status"], "fail", item.get("error"))
        steps = {s["key"]: s for s in item["result"]["steps"]}
        self.assertEqual(steps["alarms"]["status"], "fail")
        self.assertEqual(steps["hosts"]["status"], "fail")
        self.assertEqual(steps["hardware"]["status"], "fail")
        self.assertEqual(steps["datastores"]["status"], "fail")
        self.assertEqual(steps["events"]["status"], "fail")
        kinds = {r[0]: r for r in steps["events"]["table"]["rows"]}
        self.assertEqual(kinds["Storage: path redundancy lost"][1], 1)
        self.assertIn("esxi-dca-03", kinds["Network: uplink down / redundancy lost"][3])
        self.assertEqual(steps["vms"]["status"], "warn")
        vms = {r[0]: r for r in steps["vms"]["table"]["rows"]}
        self.assertEqual(vms[[n for n in vms if n.startswith("report-05")][0]][4], 10)
        texts = [r["text"] for r in item["result"]["recommendations"]]
        self.assertTrue(any(t.startswith("esxi-dca-05 is notResponding in vCenter") for t in texts))
        self.assertTrue(any(t.startswith("esxi-dca-03: 1 hardware sensor(s)") for t in texts))
        self.assertFalse(any("Alarm status changes" in t for t in texts))   # info only
        self.assertIn("/etc/init.d/hostd restart", self.commands(item))
        refs = {x["url"] for r in item["result"]["recommendations"] for x in r.get("references", [])}
        self.assertIn("https://knowledge.broadcom.com/external/article?legacyId=1003409", refs)   # host not responding
        self.assertIn("https://knowledge.broadcom.com/external/article?legacyId=1025279", refs)   # snapshots

    def test_platform_nsxt_health(self):
        c = self.client()
        self.addCleanup(c.delete, "/api/admin/credentials/ro-nsxt:DCA")
        test = c.post("/api/admin/credentials/ro-nsxt:DCA", json={"username": mock_vmware.READONLY_USER,
                                                                  "password": mock_vmware.READONLY_PASSWORD}).get_json()["test"]
        self.assertTrue(test["ok"], test)
        item = self.run_check(c, "nsxt-health", {})
        self.assertEqual(item["status"], "fail", item.get("error"))
        st = self.steps(item)
        self.assertEqual((st["cluster"], st["alarms"], st["nodes"]), ("ok", "fail", "fail"))
        recs = item["result"]["recommendations"]
        bgp = next(r for r in recs if r["text"].startswith("Routing: BGP Down (CRITICAL"))
        self.assertIn("get logical-routers", bgp["warning"])          # NSX's own recommended action
        self.assertFalse(any("Edge Disk Usage High" in r["text"] for r in recs))   # LOW: listed, no recommendation
        nodes = next(s for s in item["result"]["steps"] if s["key"] == "nodes")
        self.assertEqual(nodes["table"]["rows"][0][0], "edge-dca-01")
        self.assertNotIn(mock_vmware.READONLY_PASSWORD, item["log"])

    def test_bmc_page_and_health(self):
        """BMCs with their web account (page BMC), read with Redfish over HTTPS: Lenovo XCC and Inspur."""
        c = self.client()
        l1 = self.client("l1", "demo-operator-1")
        self.assertEqual(l1.get("/wi/api/bmc").status_code, 403)          # administrators only
        r = c.post("/wi/api/bmc/credentials", json={"name": "bmc-ro", "username": mock_redfish.USER, "secret": mock_redfish.PASSWORD})
        cred = r.get_json()["id"]
        listing = c.get("/wi/api/bmc").get_json()
        self.assertNotIn(mock_redfish.PASSWORD, json.dumps(listing))
        # the URL of the BMC web page can be pasted; a bad address is refused
        r = c.post("/wi/api/bmc", json={"site": "DCA", "name": "dca-compute-07", "address": f"https://127.0.0.1:{XCC.port}/#/login",
                                        "vendor": "lenovo", "credential_id": cred})
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertEqual(c.post("/wi/api/bmc", json={"site": "DCA", "name": "bad", "address": "10.0.0.300", "credential_id": cred}).status_code, 400)
        r = c.post("/wi/api/bmc/bulk", json={"site": "DCA", "vendor": "inspur", "credential_id": cred,
                                             "lines": f"dca-storage-02 127.0.0.1:{INSPUR.port}"})
        self.assertEqual(r.get_json()["added"], 1)
        rows = {b["name"]: b for b in c.get("/wi/api/bmc").get_json()["bmcs"]}
        self.assertEqual((rows["dca-compute-07"]["address"], rows["dca-compute-07"]["port"]), ("127.0.0.1", XCC.port))
        catalog = {x["id"]: x for x in c.get("/wi/api/catalog?site=DCA").get_json()["checks"]}
        self.assertTrue(catalog["bmc-health"]["access"]["runnable"])
        self.assertEqual(sorted(h["name"] for h in catalog["bmc-health"]["hosts"]["bmc"]), ["dca-compute-07", "dca-storage-02"])
        self.assertFalse({x["id"]: x for x in c.get("/wi/api/catalog?site=DCC").get_json()["checks"]}["bmc-health"]["access"]["runnable"])

        # Lenovo XCC: active DIMM alert, PSU2 failed with redundancy lost, a degraded drive; the audit log is not read
        item = self.run_check(c, "bmc-health", {"bmc": "dca-compute-07"})
        self.assertEqual(item["status"], "fail", item.get("error"))
        st = self.steps(item)
        self.assertEqual((st["health"], st["power"], st["cooling"], st["storage"], st["active"], st["events"]),
                         ("fail", "fail", "ok", "fail", "fail", "fail"))
        steps = {s["key"]: s for s in item["result"]["steps"]}
        self.assertEqual(steps["active"]["table"]["rows"][0][3], "FQXSPMA2010N")
        events = steps["events"]["table"]["rows"]
        self.assertEqual([e[3] for e in events], ["FQXSPPW0007L", "FQXSPMA0010M"])      # newest first, window, no OK, no audit
        recs = {r["text"].split(" of ")[0]: r for r in item["result"]["recommendations"]}
        self.assertEqual(sorted(recs), ["Drives and RAID", "Memory (DIMM)", "Power supplies"])
        mem_refs = recs["Memory (DIMM)"]["references"]           # the vendor's own pages for the model and the event IDs
        self.assertEqual(mem_refs[0]["url"], "https://pubs.lenovo.com/sr650-v2/memory_problems")
        self.assertIn("FQXSPMA0010M, FQXSPMA2010N", mem_refs[1]["title"])
        self.assertEqual(mem_refs[1]["url"], "https://pubs.lenovo.com/sr650-v2/xcc_error_messages")
        self.assertTrue(all(x["vendor"] == "Lenovo" for x in mem_refs))
        self.assertFalse(any("/AuditLog/Entries" in x for x in XCC.calls))
        self.assertNotIn(mock_redfish.PASSWORD, item["log"])

        # Inspur: plain-string members, Storage linked as .../Storages (404), SEL paged: the newest page is read
        item = self.run_check(c, "bmc-health", {"bmc": "dca-storage-02"})
        self.assertNotEqual(item["status"], "error", item.get("error"))
        st = self.steps(item)
        self.assertEqual((st["power"], st["storage"], st["events"], st["memory"], st["cooling"], st["cpus"]),
                         ("warn", "ok", "warn", "warn", "ok", "ok"))
        self.assertNotIn("active", st)
        steps = {s["key"]: s for s in item["result"]["steps"]}
        events = {e[4]: e for e in steps["events"]["table"]["rows"]}
        # "YY-MM-DD" times of the BMC are read in its time zone; the DIMM is named from the OEM fields
        ecc = events["Correctable ECC Logging Limit Reached-Asserted"]
        self.assertEqual((ecc[0], ecc[5], ecc[6]), ("2026-10-11 06:00:00", "Memory #82 → DIMM CPU1_CH1_DIMM0", "active (not deasserted)"))
        self.assertIn("Description: CPU1_CH1_DIMM0 ECC", ecc[7])
        # an assertion with its deassertion is over (listed, not a finding); old and undated events are not counted
        self.assertTrue(events["Power Supply Input Lost (AC/DC)-Asserted"][6].startswith("over: deasserted 2026-10-11 07:05"))
        self.assertTrue(events["Fan_FAN3_F Speed Lower Critical going low"][6].startswith("over: deasserted"))
        self.assertFalse(any(m in events for m in ("Redundancy Lost-Asserted", "Old critical event on PSU0 (outside the window)",
                                                   "Event with a time in an unknown form")))
        self.assertIn("2 of them were deasserted later (over); 2 older warning / critical event(s) not counted; 1 with a time",
                      steps["events"]["detail"])
        dimms = {r[0]: r for r in steps["memory"]["table"]["rows"]}
        self.assertEqual(sorted(dimms), ["CPU0_CH0_DIMM0", "CPU0_CH1_DIMM0", "CPU1_CH0_DIMM0", "CPU1_CH1_DIMM0"])   # empty ones out
        bad = dimms["CPU1_CH1_DIMM0"]
        self.assertEqual((bad[1], bad[6], bad[8]), ("CPU 1 · channel 1 · DIMM 0 · slot 7 of 8 in the BMC's list", "S1100000", "WARN"))
        self.assertIn("4 empty slot(s)", steps["memory"]["detail"])
        # every slot of the board: one row per CPU, one column per channel / DIMM
        self.assertEqual(steps["slots"]["table"]["columns"], ["CPU", "CH0 D0", "CH0 D1", "CH1 D0", "CH1 D1"])
        self.assertEqual(steps["slots"]["table"]["rows"], [["CPU 0", "OK 64G", "empty", "OK 64G", "empty"],
                                                          ["CPU 1", "OK 64G", "empty", "WARN 64G", "empty"]])
        self.assertIn("Not OK on CPU 1", steps["slots"]["detail"])
        psu = {r[0]: r for r in steps["power"]["table"]["rows"]}
        self.assertEqual((psu["PSU1"][5], psu["PSU1"][8], psu["PSU1"][9]), (0, "WARN", "no input power now (cord / PDU feed)"))
        sensors = {r[0]: r for r in steps["cooling"]["table"]["rows"]}
        self.assertTrue(sensors["CPU0_Margin_Temp"][5].startswith("OK (the BMC reports Critical"), sensors["CPU0_Margin_Temp"])
        self.assertNotIn("GPU0_Temp", sensors)                                          # not fitted: no reading
        self.assertIn("2 without a reading (not fitted: FAN7_R, GPU0_Temp)", steps["cooling"]["detail"])
        mem = next(r for r in item["result"]["recommendations"] if r["text"].startswith("Memory (DIMM)"))
        parts = [row[0] for row in mem["items"]["rows"]]
        self.assertIn("DIMM CPU1_CH1_DIMM0 (CPU 1 · channel 1 · DIMM 0 · slot 7 of 8 in the BMC's list)", parts)
        self.assertIn("DIMM CPU1_CH1_DIMM0", parts)   # the ECC event of the log names the same slot
        self.assertFalse(any(r["text"].startswith("Fans and temperature") for r in item["result"]["recommendations"]))
        self.assertTrue(any("%24skip=150&%24top=100" in x or "$skip=150" in x for x in INSPUR.calls), INSPUR.calls)
        self.assertTrue(all(r["references"][0]["vendor"] == "Inspur" for r in item["result"]["recommendations"]))
        self.assertEqual(len([x for x in INSPUR.calls if x.startswith("/redfish/v1/Managers/1/LogServices/SEL/Entries")]), 2)
        self.assertNotIn(mock_redfish.PASSWORD, item["log"])
        # wrong password: a readable reason
        c.put(f"/wi/api/bmc/credentials/{cred}", json={"name": "bmc-ro", "username": mock_redfish.USER, "secret": "wrong-password-1"})
        before = len(XCC.failed)
        item = self.run_check(c, "bmc-health", {"bmc": "dca-compute-07"})
        self.assertIn("refused the account", item["result"]["steps"][0]["detail"])
        self.assertEqual(XCC.failed[before:], ["/redfish/v1/Systems"])   # one failed sign-in per run (no lock-out burst)
        # an account in use cannot be removed
        self.assertEqual(c.delete(f"/wi/api/bmc/credentials/{cred}").status_code, 400)

    def test_pacemaker_and_overcloud_logs(self):
        """Read on the overcloud nodes through the director: node list from the undercloud, one ssh per fixed command."""
        c = self.client()
        item = self.run_check(c, "pacemaker-health", {})
        self.assertEqual(item["status"], "fail", item.get("error"))
        st = self.steps(item)
        self.assertEqual((st["nodes"], st["quorum"], st["resources"], st["failed"], st["fencing"], st["rabbitmq"], st["time"], st["daemons"]),
                         ("ok", "ok", "fail", "warn", "fail", "warn", "warn", "ok"))
        steps = {s["key"]: s for s in item["result"]["steps"]}
        self.assertIn("heat-admin (RHOSP 16.2.4)", steps["nodes"]["detail"])        # user from /etc/rhosp-release
        self.assertEqual([r[0] for r in steps["nodes"]["table"]["rows"]],
                         ["overcloud-controller-0", "overcloud-controller-1", "overcloud-controller-2"])   # controllers only
        bad = {r[1]: r for r in steps["resources"]["table"]["rows"]}
        self.assertEqual(bad["rabbitmq"][3], "FAILED")
        self.assertNotIn("galera", bad)                                               # Master everywhere
        self.assertIn("1 not started", steps["fencing"]["detail"])
        cmds = self.commands(item)
        self.assertIn("sudo pcs resource cleanup rabbitmq-bundle", cmds)
        self.assertIn("sudo pcs resource cleanup stonith-fence_ipmilan-525400aa0002", cmds)
        recs = item["result"]["recommendations"]
        fence = next(r for r in recs if r["text"].startswith("Fencing failed or a stonith device is not running"))
        self.assertTrue(any("fencing-controller-nodes" in x["url"] for x in fence["references"]))
        self.assertFalse(any(r.get("action") for r in recs))                          # read-only: nothing runs from here

        item = self.run_check(c, "overcloud-logs", {"hours": "6"})
        self.assertEqual(item["status"], "fail", item.get("error"))
        steps = {s["key"]: s for s in item["result"]["steps"]}
        known = {r[0]: r for r in steps["known"]["table"]["rows"]}
        for label in ("RabbitMQ unreachable / message timeouts", "Port binding failed", "Fencing failed", "Out of memory (OOM killer)",
                      "No valid host (scheduler)"):
            self.assertIn(label, known)
        self.assertNotIn("S3cretRabbit", json.dumps(item["result"]))                  # passwords in URLs are masked
        rabbit = next(r for r in item["result"]["recommendations"] if r["text"].startswith("RabbitMQ unreachable"))
        self.assertTrue(any("checking-bundle-status" in x["url"] for x in rabbit["references"]))

        # one instance: its compute is read too and its request IDs are followed (timeline)
        item = self.run_check(c, "overcloud-logs", {"instance": "5e5e5e5e-0000-4000-8000-000000000001"})
        self.assertNotEqual(item["status"], "error", item.get("error"))
        steps = {s["key"]: s for s in item["result"]["steps"]}
        self.assertIn("overcloud-novacompute-7", [r[0] for r in steps["nodes"]["table"]["rows"]])
        timeline = steps["timeline"]["table"]["rows"]
        self.assertEqual([r[2] for r in timeline], ["server.log", "nova-compute.log", "nova-conductor.log"])
        self.assertIn("Instance network not plugged in time (network-vif-plugged)", [r[0] for r in steps["known"]["table"]["rows"]])
        # a node that does not answer SSH is reported, the others are still read
        item = self.run_check(c, "overcloud-logs", {"node": "overcloud-novacompute-3"})
        self.assertIn("No route to host", json.dumps(item["result"]["steps"][0]))
        with self.assertRaises(ValueError):   # only fixed commands with validated arguments reach a node
            wi_analysis.overcloud.parse("n1|192.168.253.10|heat-admin|log:nova:6:x; rm -rf /")
        with self.assertRaises(ValueError):
            wi_analysis.overcloud.parse("n1|8.8.8.8|heat-admin|reach")
        with self.assertRaises(ValueError):
            wi_analysis.overcloud.parse("n1|192.168.253.10|root|reach")

    def test_export_result_csv_and_report(self):
        """A threshold result (Cinder pools) exported as CSV (every table) and as a printable report (Save as PDF)."""
        c = self.client()
        item = self.run_check(c, "cinder-pool-usage", {"threshold": "80"})
        run_id = item["id"]
        r = c.get(f"/wi/export/runs/{run_id}.csv")
        self.assertEqual(r.status_code, 200)
        self.assertIn(f'filename="Run_{run_id}_cinder_pool_usage_DCA.csv"', r.headers["Content-Disposition"])
        import csv as csvmod
        import io as iomod
        text = r.data.decode("utf-8-sig")
        rows = list(csvmod.reader(iomod.StringIO(text)))
        self.assertEqual(rows[0], ["Operation Automation run", f"#{run_id}"])
        self.assertIn(["Parameters", "snapshot_days=14; threshold=80"], rows)
        pools = next(i for i, x in enumerate(rows) if x[:1] == ["Step"] and x[1] == "Identify the affected Cinder pools")
        header = rows[pools + 1]
        self.assertIn("Pool", header[0])
        self.assertTrue(any("DCAOPNSTACK_CINDER_15_vol" in " ".join(x) for x in rows[pools + 2:pools + 8]))
        self.assertIn(["How to fix it"], rows)
        self.assertFalse(any(cell.startswith(("=", "+", "@")) for x in rows for cell in x))   # no spreadsheet formulas
        self.assertNotIn("'-", text)                                                       # "-" stays a dash
        from modules.wi import runs as runs_mod
        self.assertEqual([runs_mod._cell(x) for x in ("=SUM(A1)", "-2+3", "-", "-5", "+1.5%", "@x")],
                         ["'=SUM(A1)", "'-2+3", "-", "-5", "+1.5%", "'@x"])
        page = c.get(f"/wi/runs/{run_id}/report?print=1")
        self.assertEqual(page.status_code, 200)
        html = page.data.decode()
        self.assertIn("Print / Save as PDF", html)
        self.assertIn("DCAOPNSTACK_CINDER_15_vol", html)
        self.assertIn("window.print()", html)
        self.assertIn('content="light"', html)
        anonymous = self.app.test_client()
        self.assertEqual(anonymous.get(f"/wi/export/runs/{run_id}.csv").status_code, 401)
        self.assertEqual(anonymous.get(f"/wi/runs/{run_id}/report").status_code, 401)
        self.assertEqual(c.get("/wi/export/runs/999999.csv").status_code, 404)

    def test_capacity_checks(self):
        """CPU / memory / disk of a Linux server and of the overcloud nodes, compute capacity, ONTAP capacity."""
        c = self.client()
        item = self.run_check(c, "linux-resources", {"host": "app-vm-01"})
        self.assertEqual(item["status"], "fail", item.get("error"))
        st = self.steps(item)
        self.assertEqual((st["cpu"], st["mem"], st["disk"], st["units"]), ("ok", "warn", "fail", "warn"))
        steps = {s["key"]: s for s in item["result"]["steps"]}
        self.assertIn("91.0% used", steps["mem"]["detail"])
        self.assertIn("40.0% busy (iowait 10.0%)", steps["cpu"]["detail"])   # /proc/stat over 2 s
        self.assertEqual(steps["disk"]["table"]["rows"][0][:2], ["/", "/dev/vda1"])
        texts = [r["text"] for r in item["result"]["recommendations"]]
        self.assertTrue(any(t.startswith("Filesystems of app-vm-01 are filling up") for t in texts))
        self.assertIn("sudo systemctl status nginx.service --no-pager -l", self.commands(item))

        item = self.run_check(c, "overcloud-node-health", {})
        self.assertEqual(item["status"], "fail", item.get("error"))
        steps = {s["key"]: s for s in item["result"]["steps"]}
        summary = {r[0]: r for r in steps["summary"]["table"]["rows"]}
        self.assertEqual(summary["overcloud-controller-0"][4], "FAIL")              # / at 95%
        self.assertEqual(summary["overcloud-controller-1"][6], "FAIL")              # neutron_api unhealthy
        cont = steps["1_containers"]["table"]["rows"]
        self.assertEqual(sorted(x[0] for x in cont), ["heat_engine", "neutron_api"])   # one-shot glance_api_init is not flagged
        self.assertIn("sudo systemctl restart tripleo_neutron_api", self.commands(item))

        item = self.run_check(c, "compute-capacity", {"cpu_ratio": "4", "ram_ratio": "1"})
        self.assertEqual(item["status"], "fail", item.get("error"))
        steps = {s["key"]: s for s in item["result"]["steps"]}
        rows = {r[0]: r for r in steps["computes"]["table"]["rows"]}
        self.assertEqual(rows["compute-07.localdomain"][7], "FAIL")                 # 230 of 256 vCPU (89.8%), RAM 93.2%
        self.assertEqual(rows["compute-03.localdomain"][1], "DOWN")
        aggs = {r[0]: r for r in steps["aggregates"]["table"]["rows"]}
        self.assertEqual(aggs["agg-gold"][2], 1)                                  # compute-08 is disabled: no room counted
        self.assertNotIn("agg-gpu", aggs)                                          # its only compute is down

        test = c.post("/api/admin/credentials/ontap:DCA", json={"username": ONTAP_RO[0], "password": ONTAP_RO[1]}).get_json()["test"]
        self.addCleanup(c.delete, "/api/admin/credentials/ontap:DCA")
        self.assertTrue(test["ok"], test)
        item = self.run_check(c, "ontap-capacity", {})
        self.assertEqual(item["status"], "fail", item.get("error"))
        st = self.steps(item)
        self.assertEqual((st["aggregates"], st["disks"]), ("fail", "fail"))
        self.assertIn("91.0%", json.dumps(item["result"]["steps"][0]["table"]))
        # every capacity result exports as CSV
        r = c.get(f"/wi/export/runs/{item['id']}.csv")
        self.assertIn("Aggregates", r.data.decode("utf-8-sig"))

    def test_cert_expiry(self):
        c = self.client()
        item = self.run_check(c, "cert-expiry", {})   # the test certificates live 2 days: within the 7-day problem window
        self.assertEqual(item["status"], "fail", item.get("error"))
        steps = {s["key"]: s for s in item["result"]["steps"]}
        rows = {r[0]: r for r in steps["certs"]["table"]["rows"]}
        for system in ("vCenter", "NSX-T Manager", "vCloud Director", "ONTAP"):
            self.assertIn(rows[system][3], (0, 1, 2), rows[system])
            self.assertEqual(rows[system][6], "FAIL")
            self.assertIn("(self-signed)", rows[system][5])
        self.assertTrue(any(r["text"].startswith("The certificate of vCenter") for r in item["result"]["recommendations"]))
        item = self.run_check(c, "cert-expiry", {"warn_days": "7", "fail_days": "0"})
        self.assertEqual(self.steps(item)["certs"], "warn")
        from wi_analysis import certs
        self.assertEqual(certs.target("https://vc.example:8443/ui"), "vc.example:8443")
        self.assertEqual(certs.target("10.252.1.5"), "10.252.1.5:443")
        self.assertEqual(certs.target("x;rm -rf /"), "")
        reads = wi_analysis.reads("cert-expiry", 1, {}, {}, {"vcenter_host": "vc.example", "bmc_targets": [["b", "a b;rm", 443]]})
        self.assertEqual(reads["tls"], {"t0": "vc.example:443"})   # an address that is not host:port is never read

    def test_host_checks(self):
        c = self.client()
        item = self.run_check(c, "cdn-disk-run", {"host": "172.31.10.67:9100"})
        self.assertEqual((item["status"], item["host"]), ("fail", "dca-cdn-lb-01"))
        node = item["topology"]["lanes"][0][0]
        self.assertEqual((node["label"], node["sub"], node["status"]), ("dca-cdn-lb-01", "172.31.10.67", "fail"))
        item = self.run_check(c, "cdn-datasource", {"host": "dca-cdn-lb-02"})
        self.assertEqual(self.steps(item)["container"], "fail")
        item = self.run_check(c, "vyos-nat-firewall", {"host": "dca-natgw-01"})
        st = self.steps(item)
        self.assertEqual((st["route"], st["state_WAN-IN"], st["dnat_WAN-IN"]), ("ok", "fail", "fail"))
        self.assertIn("set firewall ipv4 name WAN-IN rule 5 state 'established'", self.commands(item))
        self.assertIn("set firewall ipv4 name WAN-IN rule 71 protocol 'udp'", self.commands(item))
        item = self.run_check(c, "linux-service-port", {"host": "app-vm-01", "port": "80", "service": "nginx"})
        self.assertEqual(self.steps(item)["conflict"], "fail")
        self.assertIn("sudo systemctl stop apache2", self.commands(item))
        # the fix names the host it is for and the nftables rule handle that rejects the port
        item = self.run_check(c, "linux-firewall", {"host": "app-vm-01", "port": "27017", "source": "10.249.2.15"})
        self.assertEqual(self.steps(item)["nft"], "fail")
        self.assertIn("sudo nft insert rule inet filter input position 6 ip saddr 10.249.2.15 tcp dport 27017 accept", self.commands(item))
        self.assertEqual(item["result"]["recommendations"][0]["where"], "app-vm-01 (10.249.1.20)")
        item = self.run_check(c, "cdn-root-disk", {"host": "dca-cdn-lb-01"})
        self.assertIn("sudo truncate -s 0 /var/log/haproxy.log", self.commands(item))
        r = c.post("/wi/api/runs", json={"site": "DCA", "check": "cdn-disk-run", "params": {"host": "8.8.8.8"}})
        self.assertEqual(r.status_code, 400)

    def test_system_address_on_credentials_page(self):
        """vCenter, NSX-T and vCloud Director of every site are on the Credentials page, also without a host in
        sites.yml; the administrator sets the address there. A stored password only goes to the address it was
        entered for. ONTAP has no account of its own (the ONTAP Restore account is used)."""
        c = self.client()
        items = {t["name"]: t for t in c.get("/api/admin/credentials").get_json()["credentials"]}
        self.assertNotIn("ro-ontap:DCA", items)
        self.assertEqual((items["ro-vcenter:DCC"]["host"], items["ro-vcenter:DCC"]["address"]), ("", True))
        self.assertEqual(items["ro-vcenter:DCA"]["host_default"], f"127.0.0.1:{VMWARE.port}")
        dcc = {x["id"]: x for x in c.get("/wi/api/catalog?site=DCC").get_json()["checks"]}
        self.assertIn("no vcenter address for DCC (Administration → Credentials, ro-vcenter:DCC)", dcc["vcenter-datastore"]["access"]["missing"])
        account = {"username": mock_vmware.READONLY_USER, "password": mock_vmware.READONLY_PASSWORD}
        r = c.post("/api/admin/credentials/ro-vcenter:DCC", json=account)
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.get_json()["test"]["ok"])   # saved, but no address yet
        r = c.post("/api/admin/credentials/ro-vcenter:DCC", json={**account, "address": ""})
        self.assertIn("Enter the address", r.get_json()["error"])
        for bad in ("a b", "10.253.0.1:99999x", "https://"):
            r = c.post("/api/admin/credentials/ro-vcenter:DCC", json={**account, "address": bad})
            self.assertEqual(r.status_code, 400, bad)
        # a pasted console URL is accepted: only its host (and port) is kept
        r = c.post("/api/admin/credentials/ro-vcenter:DCC", json={**account, "address": "https://10.253.0.1/ui/app/login?x=1#top"})
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertEqual({t["name"]: t for t in c.get("/api/admin/credentials").get_json()["credentials"]}["ro-vcenter:DCC"]["host"], "10.253.0.1")
        # vCloud Director: a provider account without @System gets it; the pasted provider login URL gives the host
        r = c.post("/api/admin/credentials/ro-vcd", json={"username": mock_vmware.READONLY_USER, "password": mock_vmware.READONLY_PASSWORD,
                                                           "address": f"https://127.0.0.1:{VMWARE.port}/login/?service=provider&redirectTo=%2Fprovider"})
        self.assertTrue(r.get_json()["test"]["ok"], r.get_json())
        vcd = {t["name"]: t for t in c.get("/api/admin/credentials").get_json()["credentials"]}["ro-vcd"]
        self.assertEqual((vcd["username"], vcd["host"]), (f"{mock_vmware.READONLY_USER}@System", f"127.0.0.1:{VMWARE.port}"))
        c.delete("/api/admin/credentials/ro-vcd")
        r = c.post("/api/admin/credentials/ro-vcenter:DCC", json={**account, "address": f"https://127.0.0.1:{VMWARE.port}/"})
        self.assertTrue(r.get_json()["test"]["ok"], r.get_json())
        item = {t["name"]: t for t in c.get("/api/admin/credentials").get_json()["credentials"]}["ro-vcenter:DCC"]
        self.assertEqual((item["host"], item["address_set"]), (f"127.0.0.1:{VMWARE.port}", True))   # scheme and slash dropped
        self.assertTrue({x["id"]: x for x in c.get("/wi/api/catalog?site=DCC").get_json()["checks"]}["vcenter-datastore"]["access"]["runnable"])
        # same address, password left empty: the stored one is kept
        r = c.post("/api/admin/credentials/ro-vcenter:DCC", json={"username": mock_vmware.READONLY_USER, "password": "",
                                                                  "address": f"https://127.0.0.1:{VMWARE.port}"})
        self.assertTrue(r.get_json()["test"]["ok"], r.get_json())
        # a new address needs the password again (the stored one is never sent to another address)
        r = c.post("/api/admin/credentials/ro-vcenter:DCC", json={"username": mock_vmware.READONLY_USER, "password": "",
                                                                  "address": "10.251.9.9"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("Enter the password again", r.get_json()["error"])
        events = c.get("/api/admin/events").get_json()["events"]
        self.assertTrue(any(e["action"] == "credential.set" and "address=127.0.0.1" in e["detail"] for e in events))
        # back to sites.yml (DCA): empty address, password again
        c.post("/api/admin/credentials/ro-vcenter:DCA", json={**account, "address": "10.251.9.9"})
        self.assertEqual({t["name"]: t for t in c.get("/api/admin/credentials").get_json()["credentials"]}["ro-vcenter:DCA"]["host"], "10.251.9.9")
        r = c.post("/api/admin/credentials/ro-vcenter:DCA", json={**account, "address": ""})
        self.assertTrue(r.get_json()["test"]["ok"], r.get_json())
        item = {t["name"]: t for t in c.get("/api/admin/credentials").get_json()["credentials"]}["ro-vcenter:DCA"]
        self.assertEqual((item["host"], item["address_set"]), (f"127.0.0.1:{VMWARE.port}", False))
        for name in ("ro-vcenter:DCC", "ro-vcenter:DCA"):
            c.delete(f"/api/admin/credentials/{name}")

    def test_rest_checks_need_read_only_account(self):
        c = self.client()
        r = c.post("/wi/api/runs", json={"site": "DCA", "check": "vcenter-datastore", "params": {}})
        self.assertEqual(r.status_code, 400)
        self.assertIn("ro-vcenter:DCA", r.get_json()["error"])
        test = c.post("/api/admin/credentials/ro-vcenter:DCA", json={"username": "wi-readonly", "password": "wrong"}).get_json()["test"]
        self.assertFalse(test["ok"])
        for name in ("ro-vcenter:DCA", "ro-nsxt:DCA"):
            test = c.post(f"/api/admin/credentials/{name}", json={"username": mock_vmware.READONLY_USER,
                                                                 "password": mock_vmware.READONLY_PASSWORD}).get_json()["test"]
            self.assertTrue(test["ok"], test)
        item = self.run_check(c, "vcenter-datastore", {"min_free": "20"})
        self.assertEqual(self.steps(item)["datastores"], "fail")
        cmds = self.commands(item)
        self.assertTrue(any("Move-VM -VM $vm -Datastore 'DCA-DS-ARCHIVE'" in x and "-WhatIf" in x for x in cmds), cmds)
        self.assertTrue(any("Get-VM -Name 'erp-db-01', 'erp-app-01' | Get-Snapshot" in x for x in cmds), cmds)
        item = self.run_check(c, "nsxt-snat-priority", {"tier1": mock_vmware.TIER1})
        self.assertEqual(self.steps(item)["order"], "fail")
        cmds = self.commands(item)
        self.assertTrue(any(x.endswith("""/nat-rules/SNAT-Colo -H 'Content-Type: application/json' -d '{"sequence_number": 100}'""") for x in cmds), cmds)
        self.assertTrue(any(x.endswith("""/nat-rules/196613 -H 'Content-Type: application/json' -d '{"sequence_number": 200}'""") for x in cmds), cmds)
        self.assertNotIn(mock_vmware.READONLY_PASSWORD, item["log"])

    def test_vmware_checks(self):
        c = self.client()
        for name, user in (("ro-vcenter:DCA", mock_vmware.READONLY_USER), ("ro-vcd", f"{mock_vmware.READONLY_USER}@System")):
            test = c.post(f"/api/admin/credentials/{name}", json={"username": user, "password": mock_vmware.READONLY_PASSWORD}).get_json()["test"]
            self.assertTrue(test["ok"], test)
        # host load and resource pools (vCenter inventory)
        item = self.run_check(c, "vmware-host-usage", {"host": "esxi-dca-02"})
        st = self.steps(item)
        self.assertEqual((st["hosts"], st["pools"]), ("fail", "fail"), item)
        cmds = self.commands(item)
        self.assertIn("Move-VM -VM 'render-farm-01' -Destination (Get-VMHost 'esxi-dca-03') -WhatIf", cmds)
        self.assertIn("Get-DrsRecommendation -Cluster 'DCA-CL-PRIME-01' | Invoke-DrsRecommendation", cmds)
        self.assertTrue(any("Move-VM -VM 'app-04 (e1000000-0000-4000-8000-000000000004)' -Destination (Get-ResourcePool -Name 'CUST-A-VDC (" in x
                            for x in cmds), cmds)
        # vCloud Director: one VM per WI case
        item = self.run_check(c, "vcd-vm-power", {"vm": "erp-app-01"})
        self.assertEqual(self.steps(item)["quota"], "fail", item)
        self.assertFalse(any("cell-management-tool" in x for x in self.commands(item)))   # report-05's stuck task is not this VM's
        self.assertIn("at least 73728 MB", " ".join(r["text"] for r in item["result"]["recommendations"]))
        item = self.run_check(c, "vcd-vm-power", {"vm": "web-02"})
        st = self.steps(item)
        self.assertEqual((st["conflict"], st["quota"], st["stuck"]), ("fail", "ok", "info"), item)
        self.assertIn("with IP 11.15.66.100", " ".join(r["text"] for r in item["result"]["recommendations"]))
        item = self.run_check(c, "vcd-vm-power", {"vm": "db-03"})
        self.assertEqual(self.steps(item)["state"], "fail", item)
        self.assertIn("Shutdown-VMGuest -VM 'db-03 (e1000000-0000-4000-8000-000000000003)' -Confirm:$false", self.commands(item))
        item = self.run_check(c, "vcd-vm-power", {"vm": "app-04"})
        self.assertEqual(self.steps(item)["pool"], "fail", item)
        item = self.run_check(c, "vcd-vm-power", {"vm": "report-05"})
        self.assertEqual(self.steps(item)["stuck"], "fail", item)
        self.assertIn("sudo /opt/vmware/vcloud-director/bin/cell-management-tool -u administrator cell --quiesce true", self.commands(item))
        # edge gateway: IPsec down, DNAT present, firewall drops 8443
        item = self.run_check(c, "vcd-edge", {"edge": "CUST-A-EDGE", "vm_ip": "10.249.10.16", "port": "8443", "public_ip": "11.4.20.31"})
        st = self.steps(item)
        self.assertEqual((st["ipsec"], st["nat"], st["firewall"]), ("fail", "ok", "fail"), item)
        self.assertIn("TCP-8443", " ".join(r["text"] for r in item["result"]["recommendations"]))
        fw = next(x for x in item["result"]["screens"] if x["key"] == "vcd-edge-fw")
        self.assertIn("allow-tcp-8443-10.249.10.16", json.dumps(fw["after"]))   # "after the fix": the new rule above the default rule
        item = self.run_check(c, "vcd-edge", {"edge": "CUST-A-EDGE", "vm_ip": "10.249.10.15", "port": "443"})
        self.assertEqual(self.steps(item)["firewall"], "ok", item)   # allow-https: IP set web-servers + profile HTTPS
        self.assertNotIn(mock_vmware.READONLY_PASSWORD, item["log"])

    def wait_fix(self, client, action_id):
        deadline = time.time() + 120
        while time.time() < deadline:
            item = client.get(f"/wi/api/fixes/{action_id}").get_json()["item"]
            if item["status"] != "running" and (item["verify_run_id"] or item["status"] != "ok"):
                return item
            time.sleep(0.3)
        self.fail("fix did not finish")

    def wait_run(self, client, run_id):
        deadline = time.time() + 120
        while time.time() < deadline:
            item = client.get(f"/wi/api/runs/{run_id}").get_json()["item"]
            if item["status"] != "running":
                return item
            time.sleep(0.3)
        self.fail("run did not finish")

    def test_ssh_key_fingerprint_and_hints(self):
        """A stored key is shown by its fingerprint (as ssh-keygen -l), an unreadable key is refused, and an SSH failure
        says what to do."""
        import base64, hashlib, subprocess
        from modules.wi import hosts as wi_hosts
        import wi_analysis
        admin = self.client()
        key = new_key()
        r = admin.post("/wi/api/credentials", json={"name": "fp-test", "username": "root", "auth": "key", "privilege": "root",
                                                    "secret": key})
        cid = r.get_json()["id"]
        listed = next(c for c in admin.get("/wi/api/hosts").get_json()["credentials"] if c["id"] == cid)
        pub = subprocess.run(["ssh-keygen", "-y", "-f", "/dev/stdin"], input=key, capture_output=True, text=True).stdout.split()
        if pub:   # same fingerprint as OpenSSH computes
            digest = base64.b64encode(hashlib.sha256(base64.b64decode(pub[1])).digest()).decode().rstrip("=")
            self.assertEqual(listed["fingerprint"], f"ED25519 SHA256:{digest}")
        self.assertTrue(listed["fingerprint"].startswith("ED25519 SHA256:"))
        bad = "-----BEGIN OPENSSH PRIVATE KEY-----\nnot-a-key\n-----END OPENSSH PRIVATE KEY-----"
        r = admin.put(f"/wi/api/credentials/{cid}", json={"name": "fp-test", "username": "root", "auth": "key", "privilege": "root",
                                                         "secret": bad})
        self.assertIn("cannot be read", r.get_json()["error"])
        admin.delete(f"/wi/api/credentials/{cid}")
        target = {"name": "repo-dca", "address": "11.11.214.48", "port": 22, "user": "root"}
        hint = wi_analysis.ssh_hint("ssh: connect to host 11.11.214.48 port 22: Connection timed out", target)
        self.assertIn("no answer from 11.11.214.48:22", hint)
        self.assertIn("WI_SSH_PROXY", hint)
        self.assertIn("refused the sign-in of root", wi_analysis.ssh_hint("root@x: Permission denied (publickey).", target))
        behind = dict(target, address="10.248.0.11", jump={"name": "repo-dca", "address": "11.11.214.48", "port": 22, "user": "root"})
        self.assertIn("could not open the connection onwards to 10.248.0.11:22",
                      wi_analysis.ssh_hint("channel 0: open failed: connect failed: No route to host", behind))
        self.assertIn("repo-dca (11.11.214.48:22, the jump host)",
                      wi_analysis.ssh_hint("Connection timed out during banner exchange", behind))
        result = wi_analysis.action_result({"unreachable": True, "msg": "ssh: connect to host 11.11.214.48 port 22: Connection timed out"},
                                           ["hostname"], target)
        self.assertEqual(result["step"], "connect")
        self.assertIn("firewall", result["hint"])
        self.assertEqual(wi_hosts.KEY_TYPES["ssh-ed25519"], "ED25519")

    def test_ssh_through_web_proxy(self):
        """With WI_SSH_PROXY (the Squid of pfSense), SSH to a public address goes through it (HTTP CONNECT, netcat);
        private addresses and hosts behind a jump host stay direct; a public jump host is itself reached through it."""
        from modules.wi import hosts as wi_hosts
        import wi_analysis
        old = os.environ.pop("WI_SSH_PROXY", None)
        try:
            self.assertEqual(wi_hosts.ssh_proxy("11.11.214.48"), "")
            os.environ["WI_SSH_PROXY"] = "172.26.0.242:3128"
            self.assertEqual(wi_hosts.ssh_proxy("11.11.214.48"), "172.26.0.242:3128")
            for private in ("10.248.0.11", "172.31.10.67", "192.168.254.5", "172.26.0.100"):
                self.assertEqual(wi_hosts.ssh_proxy(private), "", private)
            self.assertEqual(wi_hosts.ssh_proxy("repo.example", resolve=False), "")
            self.assertEqual(wi_analysis.ssh_route_args({"address": "11.11.214.48", "proxy": "172.26.0.242:3128"}),
                             "-o 'ProxyCommand=nc -X connect -x 172.26.0.242:3128 %h %p'")
            self.assertEqual(wi_analysis.ssh_route_args({"address": "10.248.0.11"}), "")
            jump = {"name": "repo-dca", "address": "11.11.214.48", "port": 22, "user": "root", "auth": "key",
                    "proxy": "172.26.0.242:3128"}
            args = wi_analysis.ssh_route_args({"address": "10.248.0.11", "jump": jump}, "/tmp/k.key")
            self.assertIn("nc -X connect -x 172.26.0.242:3128 %%h %%p", args)   # the jump's own ssh expands them
            self.assertTrue(args.endswith("-W %h:%p root@11.11.214.48'"), args)
            with self.assertRaises(ValueError):
                wi_analysis.ssh_route_args({"address": "1.2.3.4", "proxy": "proxy;id:3128"})
            hint = wi_analysis.ssh_hint('nc: Proxy error: "HTTP/1.1 403 Forbidden"', {"address": "11.11.214.48", "proxy": "172.26.0.242:3128"})
            self.assertIn("ACL SafePorts and ACL SSLPorts", hint)
            # a portal host on a public address gets the proxy; the hosts list shows it
            admin = self.client()
            cid = admin.post("/wi/api/credentials", json={"name": "px", "username": "root", "auth": "key", "privilege": "sudo",
                                                          "secret": new_key()}).get_json()["id"]
            hid = admin.post("/wi/api/hosts", json={"site": "DCC", "group": "repo", "name": "dcc-repo-pub", "address": "11.11.214.48",
                                                    "credential_id": cid}).get_json()["id"]
            self.assertEqual(wi_hosts.target("DCC", ["repo"], "dcc-repo-pub")["proxy"], "172.26.0.242:3128")
            self.assertTrue(next(h for h in admin.get("/wi/api/hosts").get_json()["hosts"] if h["id"] == hid)["proxy"])
            admin.delete(f"/wi/api/hosts/{hid}")
            admin.delete(f"/wi/api/credentials/{cid}")
        finally:
            os.environ.pop("WI_SSH_PROXY", None)
            if old is not None:
                os.environ["WI_SSH_PROXY"] = old

    def test_openstack_fixes(self):
        try:
            self._openstack_fixes()
        finally:   # the fake cloud forgets the fixes: other tests expect its problems
            if os.path.exists(os.path.join(TMP, "cloud-state.json")):
                os.remove(os.path.join(TMP, "cloud-state.json"))

    def _openstack_fixes(self):
        """OpenStack fixes: only with the permission "run OpenStack fixes"; the state is checked again right before the
        change (nothing changes when it is no longer as found); deleting needs the name typed; the check runs again."""
        import wi_analysis
        fixer, osfix = self.client("fixer", "demo-operator-3"), self.client("osfixer", "demo-operator-5")
        app02, build03 = "5e5e5e5e-0000-4000-8000-000000000002", "5e5e5e5e-0000-4000-8000-000000000003"
        fix_of = lambda item, label: next(i for i, r in enumerate(item["result"]["recommendations"])
                                          if (r.get("action") or {}).get("label") == label)
        # wi-fix alone (SSH hosts, ONTAP) does not allow OpenStack fixes
        item = self.run_check(fixer, "instance-network", {"instance": app02})
        idx = fix_of(item, "Start it")
        f = item["fixes"][idx]
        self.assertEqual((f["kind"], f["risk"], f["available"]), ("openstack", "normal", False))
        self.assertIn("run OpenStack fixes", f["reason"])
        self.assertEqual(fixer.post(f"/wi/api/runs/{item['id']}/fixes/{idx}", json={}).status_code, 400)
        # start the stopped instance; the check runs again and finds it ACTIVE
        item = self.run_check(osfix, "instance-network", {"instance": app02})
        idx = fix_of(item, "Start it")
        f = item["fixes"][idx]
        self.assertTrue(f["available"], f)
        self.assertEqual(f["commands"][:2], [f"require server {app02} status SHUTOFF", f"openstack server start {app02}"])
        r = osfix.post(f"/wi/api/runs/{item['id']}/fixes/{idx}", json={})
        self.assertEqual(r.status_code, 200, r.get_json())
        fix = self.wait_fix(osfix, r.get_json()["action_id"])
        self.assertEqual(fix["status"], "ok", fix)
        self.assertEqual(self.steps(self.wait_run(osfix, fix["verify_run_id"]))["instance"], "ok")
        # the same fix from the old result: the instance is ACTIVE now, the check before the change stops it
        r = osfix.post(f"/wi/api/runs/{item['id']}/fixes/{idx}", json={})
        fix = self.wait_fix(osfix, r.get_json()["action_id"])
        self.assertEqual(fix["status"], "failed", fix)
        self.assertIn("nothing was changed", fix["error"])
        # an instance stuck in BUILD: deleting needs its name typed
        item = self.run_check(osfix, "stuck-resources", {})
        idx = next(i for i, x in enumerate(item["fixes"]) if x and x["label"] == "Delete this instance" and x["target"] == "build-03")
        self.assertEqual(item["fixes"][idx]["risk"], "high")
        r = osfix.post(f"/wi/api/runs/{item['id']}/fixes/{idx}", json={"confirm": "wrong"})
        self.assertIn("type the ID or name build-03", r.get_json()["error"])
        r = osfix.post(f"/wi/api/runs/{item['id']}/fixes/{idx}", json={"confirm": "build-03"})
        fix = self.wait_fix(osfix, r.get_json()["action_id"])
        self.assertEqual(fix["status"], "ok", fix)
        again = self.wait_run(osfix, fix["verify_run_id"])
        self.assertEqual(self.steps(again)["build"], "ok", again)
        self.assertNotIn(build03, json.dumps(again["result"]["steps"]))
        # every action of every recommendation is an allowed OpenStack change or read
        for check in ("stuck-resources", "cinder-pool-usage", "volume-type-legacy"):
            item = self.run_check(osfix, check, {})
            for rec in item["result"]["recommendations"]:
                for c in (rec.get("action") or {}).get("commands") or []:
                    wi_analysis.openstack_fix_command(c)
        # Cinder pool: volumes are ticked; those with snapshots are not ticked by default and delete their snapshots first
        recs = self.run_check(osfix, "cinder-pool-usage", {})["result"]["recommendations"]
        moves = [r for r in recs if (r.get("action") or {}).get("label") == "Migrate selected"]
        self.assertTrue(moves)
        for rec in moves:
            for it in rec["action"]["select"]["items"]:
                vid = it["commands"][0].split()[1]
                with_snaps = vid in ("11111111-0000-4000-8000-000000000001", "11111111-0000-4000-8000-000000000004")
                self.assertEqual(it["commands"][0].endswith("snapshots -"), not with_snaps, it)
                if with_snaps:
                    self.assertFalse(it["default"])
        snaps = [r for r in recs if (r.get("action") or {}).get("label") == "Delete these snapshots"]
        self.assertEqual(sorted(r["action"]["confirm"] for r in snaps), ["db-prod-data", "logs-old"])
        self.assertTrue(all(fixes_risk == "high" for fixes_risk in
                            [__import__("modules.wi.fixes", fromlist=["risk_of"]).risk_of(r["action"]) for r in snaps]))
        # old volume type: one item per volume; a volume with snapshots is not ticked and deletes them right before its retype
        item = self.run_check(osfix, "volume-type-legacy", {})
        st = {s["key"]: s for s in item["result"]["steps"]}
        self.assertEqual(st["snapshots"]["status"], "warn", st["snapshots"])
        self.assertIn("1 volume(s) have snapshots (4 in total)", st["snapshots"]["detail"])
        recs = item["result"]["recommendations"]
        idx = next(i for i, x in enumerate(recs) if (x.get("action") or {}).get("label") == "Change the type of the ticked volumes"
                   and any("db-prod-data" in it["label"] for it in x["action"]["select"]["items"]))
        sel = recs[idx]["action"]["select"]["items"]
        db = next(j for j, it in enumerate(sel) if it["label"].startswith("db-prod-data"))
        self.assertFalse(sel[db]["default"])
        self.assertIn("+ delete 4 snapshot(s)", sel[db]["label"])
        self.assertRegex(sel[db]["commands"][0], r"^retype-volume 11111111-0000-4000-8000-000000000001 to fas500f-standard "
                                                  r"timeout \d+ snapshots 55555555-0000-4000-8000-0000000000\d\d(,[0-9a-f-]{36}){3}$")
        self.assertTrue(all(it["default"] for j, it in enumerate(sel) if j != db))
        self.assertIn("openstack volume snapshot delete", " ".join(recs[idx]["commands"]))
        r = osfix.post(f"/wi/api/runs/{item['id']}/fixes/{idx}", json={"selected": [db], "confirm": "x"})
        self.assertEqual(r.status_code, 400, r.get_json())   # deletes snapshots: the number of volumes is typed
        r = osfix.post(f"/wi/api/runs/{item['id']}/fixes/{idx}", json={"selected": [db], "confirm": "1 volumes"})
        self.assertEqual(r.status_code, 200, r.get_json())
        fix = self.wait_fix(osfix, r.get_json()["action_id"])
        out = json.dumps(fix["output"])
        self.assertEqual(fix["status"], "ok", out)
        self.assertIn("has 4 approved snapshot(s): delete them first", out)
        self.assertIn("db-prod-data has the type fas500f-standard", out)
        # the operation alone: a snapshot that was not approved stops it before anything changes
        import sys as _sys
        _sys.path.insert(0, os.path.join(os.path.dirname(HERE), "modules", "wi", "wi_analysis"))
        import wi_ops
        lines, ran = [], []
        vol = {"id": "11111111-0000-4000-8000-000000000003", "name": "archive-2024", "status": "available", "volume_type": "basic"}

        def runner(argv, timeout):
            ran.append(" ".join(argv))
            if argv[:3] == ["openstack", "volume", "show"]:
                return 0, json.dumps(vol)
            if argv[:4] == ["openstack", "volume", "snapshot", "list"]:
                return 0, json.dumps([{"ID": "99999999-0000-4000-8000-000000000001", "Name": "new", "Status": "available"}])
            return 0, ""
        rc = wi_ops.main(["retype-volume", vol["id"], "to", "fas500f-basic", "timeout", "60", "snapshots", "-"],
                         wi_ops.Director(runner=runner, write=lines.append))
        self.assertEqual(rc, wi_ops.FAILED, lines)
        self.assertIn("not approved in the check (new)", lines[-1])
        self.assertFalse([c for c in ran if c.startswith(("cinder retype", "openstack volume snapshot delete"))], ran)

    def test_ovn_fdb_learning(self):
        try:
            self._ovn_fdb_learning()
        finally:   # the fake cloud forgets the cleared FDB entries
            if os.path.exists(os.path.join(TMP, "cloud-state.json")):
                os.remove(os.path.join(TMP, "cloud-state.json"))

    def _ovn_fdb_learning(self):
        """WI "FDB Learning Issue" (Acme Flex, OVN): instances mdt01-04 on DataGrid-Network with port security disabled;
        the MAC of the outside host 10.249.11.27 is recorded on the port of mdt01 and the MAC of mdt04 on the port of mdt02.
        Several instance IDs (rows or pasted together), the poisoned entries found, cleared with a typed confirmation."""
        import re
        osfix = self.client("osfixer", "demo-operator-5")
        mdt = [f"3d3d3d3d-0000-4000-8000-00000000000{n}" for n in (1, 2, 3, 4)]
        # ---- the list of IDs: a wrong ID is refused, duplicates count once, at most 16
        r = osfix.post("/wi/api/runs", json={"site": "DCA", "check": "ovn-fdb-learning", "params": {"instances": f"{mdt[0]},not-an-id"}})
        self.assertEqual(r.status_code, 400, r.get_json())
        self.assertIn("not-an-id is not an OpenStack UUID", r.get_json()["error"])
        r = osfix.post("/wi/api/runs", json={"site": "DCA", "check": "ovn-fdb-learning",
                                              "params": {"instances": ",".join(f"{i:08x}-0000-4000-8000-000000000000" for i in range(17))}})
        self.assertIn("at most 16 IDs per run", r.get_json()["error"])
        item = self.run_check(osfix, "ovn-fdb-learning", {"instances": f"{mdt[0]}\n{mdt[1]} {mdt[2]};{mdt[3]},{mdt[0]}",
                                                          "dest_ip": "10.249.11.27", "capture_seconds": "5"})
        self.assertEqual(item["status"], "fail", item.get("error") or item["result"])
        self.assertEqual(item["params"]["instances"], ",".join(mdt))
        st = {s["key"]: s for s in item["result"]["steps"]}
        self.assertIn("compute-07: mdt02, mdt04; compute-09: mdt01, mdt03", st["instances"]["detail"])
        self.assertEqual((st["ports"]["status"], st["backend"]["status"], st["bindings"]["status"]), ("warn", "ok", "warn"))
        self.assertIn("4 of 4 port(s) have port security DISABLED", st["ports"]["detail"])
        self.assertIn("ovn-controller 23.09.4", st["backend"]["detail"])
        self.assertIn(["DataGrid-Network", "00000000-0000-4000-8000-000000000002", "vlan", "1670", "225", "6", "4"],
                      st["networks"]["table"]["rows"])
        fdb = {row[1]: row for row in st["fdb"]["table"]["rows"]}
        self.assertIn("2 poisoned entries", st["fdb"]["detail"])
        self.assertTrue(fdb["10:70:fd:29:c7:fe"][4].startswith("POISONED: MAC of a host outside OpenStack, recorded on mdt01 port 7a7a7a7a"),
                        fdb["10:70:fd:29:c7:fe"])
        self.assertTrue(fdb["fa:16:3e:38:ae:44"][4].startswith("POISONED: MAC of mdt04 port 7a7a7a7a, recorded on mdt02"), fdb["fa:16:3e:38:ae:44"])
        self.assertTrue(fdb["10:70:fd:29:c7:01"][4].startswith("ok (outside host"))
        self.assertEqual(fdb["fa:16:3e:0b:cc:31"][4], "ok (its own MAC)")
        self.assertIn(["mdt01", "tap7a7a7a7a-00", "2", "10:70:fd:29:c7:fe"], st["capture"]["table"]["rows"])
        self.assertIn("81 FDB entr(ies) in 1 other network(s); 6 port(s)", st["audit"]["detail"])
        recs = item["result"]["recommendations"]
        idx = next(i for i, x in enumerate(recs) if (x.get("action") or {}).get("label") == "Clear the ticked FDB entries")
        fx = item["fixes"][idx]
        self.assertEqual((fx["risk"], len(fx["items"]), all(i["default"] for i in fx["items"])), ("high", 2, True))
        self.assertTrue(fx["items"][0]["commands"][0].startswith("clear-fdb fdbfdbfd-0000-4000-8000-000000000001 dp 225 mac 1070fd29c7fe port 3 "
                                                                 "node overcloud-novacompute-9=192.168.253.29 user "), fx["items"][0])
        perm = next(x for x in recs if x["text"].startswith("Turn port security on"))
        self.assertIn("openstack port set --enable-port-security --security-group port-security-allow-all 7a7a7a7a-0000-4000-8000-000000000001",
                      " ".join(perm["commands"]))
        # the reserved port without a device (the VIP of the HA pair) is a candidate, not given in the check
        self.assertEqual(st["vips"]["status"], "warn", st["vips"])
        self.assertIn(["DataGrid-Network", "mdt-vip", "10.249.11.50", "DOWN", "no"], st["vips"]["table"]["rows"])
        self.assertIn("not in the check: 10.249.11.50", st["vips"]["detail"])
        self.assertIn("VIP candidates not in the check: 10.249.11.50", perm["warning"])
        trace = next(x for x in recs if x["text"].startswith("Confirm with a trace"))
        self.assertIn("in_port=tap7a7a7a7a-00,dl_src=fa:16:3e:0b:cc:31,dl_dst=10:70:fd:29:c7:fe,icmp,nw_src=10.249.11.39,nw_dst=10.249.11.27",
                      " ".join(trace["commands"]))
        # ---- the fix: a typed confirmation, each entry read again on the node, destroyed, read once more
        r = osfix.post(f"/wi/api/runs/{item['id']}/fixes/{idx}", json={"selected": [0, 1], "confirm": "wrong"})
        self.assertEqual(r.status_code, 400, r.get_json())
        expected = re.search(r"type (.+?) to confirm", r.get_json()["error"]).group(1)
        r = osfix.post(f"/wi/api/runs/{item['id']}/fixes/{idx}", json={"selected": [0, 1], "confirm": expected})
        fix = self.wait_fix(osfix, r.get_json()["action_id"])
        self.assertEqual(fix["status"], "ok", fix)
        self.assertIn("FDB entry 10:70:fd:29:c7:fe (port key 3) removed from datapath 225", json.dumps(fix["output"]))
        again = self.wait_run(osfix, fix["verify_run_id"])
        st2 = {s["key"]: s for s in again["result"]["steps"]}
        self.assertEqual(st2["fdb"]["status"], "ok", st2["fdb"])
        self.assertEqual(again["status"], "warn")   # the ports still have port security disabled
        # ---- the permanent fix: port security on, port by port, with the allow-all group and the VIP of the check
        r = osfix.post("/wi/api/runs", json={"site": "DCA", "check": "ovn-fdb-learning",
                                              "params": {"instances": ",".join(mdt), "vips": "10.249.11.50, 999.1.1.1"}})
        self.assertIn("999.1.1.1 is not an IP address or network", r.get_json()["error"])
        item = self.run_check(osfix, "ovn-fdb-learning", {"instances": ",".join(mdt), "vips": "10.249.11.50 10.249.11.50/32"})
        self.assertEqual(item["params"]["vips"], "10.249.11.50")   # once: /32 is the same address
        st = {s["key"]: s for s in item["result"]["steps"]}
        self.assertEqual(st["vips"]["status"], "ok", st["vips"])
        recs = item["result"]["recommendations"]
        idx = next(i for i, x in enumerate(recs) if (x.get("action") or {}).get("label") == "Turn port security on for the ticked ports")
        fx = item["fixes"][idx]
        self.assertEqual((fx["risk"], len(fx["items"]), fx["available"]), ("high", 4, True), fx)
        self.assertEqual(fx["items"][0]["commands"][0],
                         "port-security 7a7a7a7a-0000-4000-8000-000000000001 project c0ffee00000000000000000000000001 sg "
                         "port-security-allow-all allow 10.249.11.50 dp 225 pkey 3 node "
                         "overcloud-novacompute-9=192.168.253.29 user " + fx["items"][0]["commands"][0].rsplit(" ", 1)[1])
        self.assertIn("--allowed-address ip-address=10.249.11.50 ", " ".join(recs[idx]["commands"]))
        r = osfix.post(f"/wi/api/runs/{item['id']}/fixes/{idx}", json={"selected": [0, 1], "confirm": "2"})
        self.assertEqual(r.status_code, 400, r.get_json())
        expected = re.search(r"type (.+?) to confirm", r.get_json()["error"]).group(1)
        self.assertEqual(expected, "2 ports")
        r = osfix.post(f"/wi/api/runs/{item['id']}/fixes/{idx}", json={"selected": [0, 1], "confirm": expected})
        self.assertEqual(r.status_code, 200, r.get_json())
        fix = self.wait_fix(osfix, r.get_json()["action_id"])
        out = json.dumps(fix["output"])
        self.assertEqual(fix["status"], "ok", out)
        self.assertIn("port security on (security group port-security-allow-all, allowed addresses 10.249.11.50)", out)
        self.assertIn("Security group port-security-allow-all exists already", out)   # the second port reuses the group
        self.assertIn("--remote-ip ::/0 5e5e5e5e-0000-4000-8000-000000000001   (exists already)", out)
        self.assertNotIn("(exit 1)", out)
        self.assertIn("1 FDB entry cleared", out)   # mdt01: its own MAC, learned while its port accepted any MAC
        again = self.wait_run(osfix, fix["verify_run_id"])
        st2 = {s["key"]: s for s in again["result"]["steps"]}
        self.assertIn("2 of 4 port(s) have port security DISABLED", st2["ports"]["detail"])
        self.assertIn(["mdt01", "7a7a7a7a-0000-4000-8000-000000000001", "fa:16:3e:0b:cc:31", "10.249.11.39", "enabled", "1",
                       "10.249.11.50", "overcloud-novacompute-9.localdomain"], st2["ports"]["table"]["rows"])
        # the compute of the first instance does not answer over SSH: the Southbound DB is read from the next node
        state_file = os.path.join(TMP, "cloud-state.json")
        with open(state_file) as f:
            cloud = json.load(f)
        with open(state_file, "w") as f:
            json.dump(dict(cloud, ssh_down=["overcloud-novacompute-9"]), f)
        item = self.run_check(osfix, "ovn-fdb-learning", {"instances": ",".join(mdt)})
        st = {s["key"]: s for s in item["result"]["steps"]}
        self.assertEqual(st["ovn"]["status"], "warn", st["ovn"])
        self.assertIn("Read from overcloud-novacompute-7 (192.168.253.27). Did not answer: overcloud-novacompute-9 (192.168.253.29): ",
                      st["ovn"]["detail"])
        self.assertIn("Connection timed out", st["ovn"]["detail"])
        self.assertEqual(st["fdb"]["status"], "ok", st["fdb"])
        fx = next(f for f in item["fixes"] if f and f.get("label") == "Turn port security on for the ticked ports")
        self.assertIn("node overcloud-novacompute-7=192.168.253.27 ", fx["items"][0]["commands"][0])
        # no node answers: the check says so, and offers no port security fix
        with open(state_file, "w") as f:
            json.dump(dict(cloud, ssh_down=[n for n, _ip in __import__("tests.fake_cloud", fromlist=["UC_NODES"]).UC_NODES]), f)
        item = self.run_check(osfix, "ovn-fdb-learning", {"instances": ",".join(mdt)})
        st = {s["key"]: s for s in item["result"]["steps"]}
        self.assertEqual(st["ovn"]["status"], "fail", st["ovn"])
        self.assertIn("No overcloud node answered over SSH from the director", st["ovn"]["detail"])
        self.assertFalse([f for f in item["fixes"] if f and f.get("label") == "Turn port security on for the ticked ports"])
        with open(state_file, "w") as f:
            json.dump(cloud, f)
        # ---- the operation itself: an entry that changed is left alone, one already gone is done
        sys.path.insert(0, os.path.join(os.path.dirname(HERE), "modules", "wi", "wi_analysis"))
        import wi_ops
        answers = {"list": (0, json.dumps({"headings": ["mac", "dp_key", "port_key"], "data": [["fa:16:3e:99:99:99", 225, 3]]}))}
        ran = []

        def runner(argv, timeout):
            ran.append(argv[-1])
            return answers["list"] if " list fdb " in argv[-1] else (0, "")
        lines = []
        args = ["clear-fdb", "fdbfdbfd-0000-4000-8000-000000000001", "dp", "225", "mac", "1070fd29c7fe", "port", "3",
                "node", "overcloud-novacompute-9=192.168.253.29", "user", "tripleo-admin"]
        rc = wi_ops.main(args, wi_ops.Director(runner=runner, write=lines.append))
        self.assertEqual(rc, wi_ops.FAILED, lines)
        self.assertFalse(any("destroy" in c for c in ran), ran)
        answers["list"] = (1, 'ovn-sbctl: no row "fdbfdbfd-0000-4000-8000-000000000001" in table FDB')
        self.assertEqual(wi_ops.main(args, wi_ops.Director(runner=runner, write=lines.append)), wi_ops.OK)
        self.assertIn("already gone", lines[-1])
        # port security: a port of another project now is left alone; a wrong address is refused before anything runs
        ran.clear()
        port = {"id": "7a7a7a7a-0000-4000-8000-000000000001", "project_id": "c0ffee00000000000000000000000002",
                "port_security_enabled": False, "allowed_address_pairs": []}
        ps = ["port-security", port["id"], "project", "c0ffee00000000000000000000000001", "sg", "port-security-allow-all",
              "allow", "10.249.11.50", "dp", "225", "pkey", "3", "node", "overcloud-novacompute-9=192.168.253.29", "user", "tripleo-admin"]
        rc = wi_ops.main(ps, wi_ops.Director(runner=lambda argv, t: (ran.append(" ".join(argv)), (0, json.dumps(port)))[1],
                                             write=lines.append))
        self.assertEqual(rc, wi_ops.FAILED, lines[-1])
        self.assertIn("belongs to project c0ffee00000000000000000000000002 now", lines[-1])
        self.assertEqual(ran, [f"openstack port show {port['id']} -f json"])
        bad = ps[:7] + ["10.10.11.500"] + ps[8:]
        self.assertEqual(wi_ops.main(bad, wi_ops.Director(runner=runner, write=lines.append)), wi_ops.ATTENTION)
        self.assertIn("refused: invalid address", lines[-1])
        # port security on already: straight to OVN; what OVN answers is told apart (not readable / still "unknown")
        on = dict(port, project_id="c0ffee00000000000000000000000001", port_security_enabled=True,
                  security_group_ids=["5e5e5e5e-0000-4000-8000-000000000001"],
                  allowed_address_pairs=[{"ip_address": "10.249.11.50", "mac_address": "fa:16:3e:0b:cc:31"}])
        binding = {"answer": (1, "sudo: a password is required")}

        def ovn_runner(argv, timeout):
            cmd = " ".join(argv)
            if cmd.startswith("openstack port show"):
                return 0, json.dumps(on)
            if cmd.startswith("openstack security group list"):
                return 0, json.dumps([{"ID": "5e5e5e5e-0000-4000-8000-000000000001", "Name": "port-security-allow-all"}])
            if "find port_binding" in cmd:
                self.assertIn("sudo -n podman exec ovn_controller ovn-sbctl", cmd)
                return binding["answer"]
            return 0, ""
        lines, ran = [], []

        def logged(argv, t):
            ran.append(" ".join(argv))
            return ovn_runner(argv, t)
        # OVN not readable before the change (e.g. the director cannot reach the node over SSH): nothing is changed
        self.assertEqual(wi_ops.main(ps, wi_ops.Director(runner=logged, sleep=lambda s: None, write=lines.append)), wi_ops.ATTENTION)
        self.assertIn("cannot be read on overcloud-novacompute-9 (sudo: a password is required): nothing was changed", lines[-1])
        self.assertFalse([c for c in ran if c.startswith(("openstack port set", "openstack security group"))], ran)
        binding["answer"] = (0, json.dumps({"headings": ["mac"], "data": [[["set", ["fa:16:3e:0b:cc:31 10.249.11.39", "unknown"]]]]}))
        self.assertEqual(wi_ops.main(ps, wi_ops.Director(runner=ovn_runner, sleep=lambda s: None, write=lines.append)), wi_ops.ATTENTION)
        self.assertIn('still has the address "unknown" after 30 s (mac: fa:16:3e:0b:cc:31 10.249.11.39, unknown)', lines[-1])
        binding["answer"] = (0, json.dumps({"headings": ["mac"], "data": [["fa:16:3e:0b:cc:31 10.249.11.39"]]}))
        self.assertEqual(wi_ops.main(ps, wi_ops.Director(runner=ovn_runner, sleep=lambda s: None, write=lines.append)), wi_ops.OK)
        self.assertIn("  mac: fa:16:3e:0b:cc:31 10.249.11.39", lines)
        # reads of the check: fixed commands, validated arguments
        from wi_analysis import overcloud as oc
        for bad in ("ovn_fdb:22a", "ovn_capture:tapx:10:fa163e0bcc31", "ovn_dp:abc", "ovn_capture:tap7a7a7a7a-00:99:fa163e0bcc31"):
            with self.assertRaises(ValueError):
                oc.parse(f"n|192.168.253.29|tripleo-admin|{bad}")

    def test_operations(self):
        try:
            self._operations()
        finally:   # the fake cloud forgets the changes: other tests expect its original state
            if os.path.exists(os.path.join(TMP, "cloud-state.json")):
                os.remove(os.path.join(TMP, "cloud-state.json"))

    def _operations(self):
        """Fixes with ticked items: emptying a compute (disable, live and cold migration one at a time with their automatic
        fixes), image housekeeping (typed number of images), Cinder volumes migrated after their approved snapshots."""
        osfix = self.client("osfixer", "demo-operator-5")
        fix_of = lambda item, label: next(i for i, r in enumerate(item["result"]["recommendations"])
                                          if (r.get("action") or {}).get("label") == label)
        web, db, batch, gpu, legacy = (f"5e5e5e5e-0000-4000-8000-00000000000{n}" for n in (1, 5, 6, 7, 8))

        # ---- the instances of compute-07: one list (server list, no server show), nothing ticked, no capacity estimate
        item = self.run_check(osfix, "compute-drain", {"compute": "compute-07"})
        self.assertEqual(item["status"], "warn", item.get("error") or item["result"])
        steps = {s["key"]: s for s in item["result"]["steps"]}
        self.assertIn("3 can be live-migrated, 1 shut off (cold migration), 1 cannot move now", steps["compute"]["detail"])
        self.assertIn("the least used of 1 other compute(s) enabled and up whose CPU and RAM stay under 70%", steps["compute"]["detail"])
        self.assertEqual(steps["destinations"]["table"]["rows"], [["compute-09", "nova", "30%", "40%", "yes"]])   # real use
        listed = {r[0]: r for r in steps["instances"]["table"]["rows"]}
        self.assertEqual(sorted(listed), ["batch-05", "db-01", "gpu-06", "legacy-08", "web-01"])
        self.assertEqual(listed["web-01"][6], "live migration")
        self.assertIn("PCI passthrough", listed["gpu-06"][6])
        self.assertNotIn("targets", steps)
        reads = [c for src in (wi_analysis.commands_run("compute-drain", {}, {"compute": "compute-07"}, {}) or {}).values() for c in src.values()]
        self.assertFalse(any("server show" in c or "hypervisor" in c for c in reads), reads)
        live, cold = fix_of(item, "Live-migrate selected"), fix_of(item, "Cold-migrate selected")
        self.assertLess(live, fix_of(item, "Disable the compute"))    # the list to tick comes first; disabling is optional
        fx = item["fixes"][live]
        self.assertTrue(fx["selectable"] and fx["available"], fx)
        self.assertEqual([i["label"] for i in fx["items"]], ["web-01 -> least used under 70%", "db-01 -> least used under 70%",
                                                              "legacy-08 -> least used under 70%"])
        self.assertFalse(any(i["default"] for i in fx["items"]))      # the operator ticks them
        self.assertEqual(fx["risk"], "normal")
        self.assertRegex(fx["items"][0]["commands"][0], r"nodes compute-07=192\.168\.253\.27,compute-09=192\.168\.253\.29 user heat-admin "
                                                        r"under 70 ram \d+$")
        stays = item["result"]["recommendations"][fix_of(item, "Disable the compute") + 1]
        self.assertIn("PCI passthrough", json.dumps(stays["items"]))
        # nothing ticked / an unknown item: refused
        for bad in ([], [7], ["0"], None):
            r = osfix.post(f"/wi/api/runs/{item['id']}/fixes/{live}", json={"selected": bad})
            self.assertEqual(r.status_code, 400, (bad, r.get_json()))
        # disable the compute first
        r = osfix.post(f"/wi/api/runs/{item['id']}/fixes/{fix_of(item, 'Disable the compute')}", json={})
        fix = self.wait_fix(osfix, r.get_json()["action_id"])
        self.assertEqual(fix["status"], "ok", fix)
        self.wait_run(osfix, fix["verify_run_id"])
        # live migration of the three, one after the other, each to the least used compute under 70 % (read right before):
        # compute-09; legacy-08 ends in ERROR, is reset to ACTIVE after virsh, and stays (not done: the run fails there)
        r = osfix.post(f"/wi/api/runs/{item['id']}/fixes/{live}", json={"selected": [0, 1, 2]})
        self.assertEqual(r.status_code, 200, r.get_json())
        fix = self.wait_fix(osfix, r.get_json()["action_id"])
        self.assertEqual(fix["status"], "failed", fix)
        lbl = "least used under 70%"
        self.assertIn(f"3. legacy-08 -> {lbl}: legacy-08 reset to ACTIVE on compute-07", fix["error"])
        out = {o["command"]: o for o in fix["output"]}
        self.assertEqual(out[f"1. web-01 -> {lbl}"]["rc"], 0)
        self.assertIn("compute-09: CPU 30%, RAM", out[f"2. db-01 -> {lbl}"]["out"])
        self.assertIn("Attempt 1: live migration of db-01 to compute-09", out[f"2. db-01 -> {lbl}"]["out"])
        self.assertIn("RESULT ok: db-01 is on compute-09", out[f"2. db-01 -> {lbl}"]["out"])
        self.assertIn("Automatic fix: virsh shows instance-00000008 running on compute-07 only", out[f"3. legacy-08 -> {lbl}"]["out"])
        self.assertEqual(out[f"3. legacy-08 -> {lbl}"]["rc"], 5)
        for _ in range(100):   # a failed fix also runs the check again
            fix = osfix.get(f"/wi/api/fixes/{fix['id']}").get_json()["item"]
            if fix["verify_run_id"]:
                break
            time.sleep(0.2)
        again = self.wait_run(osfix, fix["verify_run_id"])
        steps = {s["key"]: s for s in again["result"]["steps"]}
        self.assertIn("1 can be live-migrated, 1 shut off (cold migration)", steps["compute"]["detail"])   # legacy-08 is left
        self.assertIn("The service is disabled", steps["compute"]["detail"])
        # a lower limit: compute-09 (RAM 40 %) is over it, so the ticked instance is not moved (skipped, nothing changed)
        low = self.run_check(osfix, "compute-drain", {"compute": "compute-07", "max_usage": "40"})
        self.assertEqual({s["key"]: s for s in low["result"]["steps"]}["destinations"]["status"], "warn")
        r = osfix.post(f"/wi/api/runs/{low['id']}/fixes/{fix_of(low, 'Cold-migrate selected')}", json={"selected": [0]})
        fix = self.wait_fix(osfix, r.get_json()["action_id"])
        self.assertEqual(fix["status"], "failed", fix)
        self.assertTrue(fix["error"].startswith("No instance was moved. 1. batch-05"), fix["error"])
        self.assertIn("RESULT skipped: not moved: no compute stays under 40% CPU and RAM with batch-05", fix["output"][0]["out"])
        # the shut-off instance: cold migration, confirmed, still shut off on compute-09
        cold = fix_of(again, "Cold-migrate selected")
        r = osfix.post(f"/wi/api/runs/{again['id']}/fixes/{cold}", json={"selected": [0]})
        fix = self.wait_fix(osfix, r.get_json()["action_id"])
        self.assertEqual(fix["status"], "ok", fix)
        self.assertIn("RESULT ok: batch-05 is on compute-09", fix["output"][0]["out"])
        # one migration per site at a time: the lock of the second job is the same as the first
        # (checked through the job key; nothing else runs here)

        # ---- image housekeeping: size 0 and deleted projects; protected and used images are kept
        item = self.run_check(osfix, "image-housekeeping", {})
        self.assertEqual(item["status"], "warn", item.get("error"))
        idx = fix_of(item, "Delete selected images")
        fx = item["fixes"][idx]
        names = [i["label"] for i in fx["items"]]
        self.assertEqual(sorted(names), sorted(["upload-win2022", "snap-db-prod-2026-09", "centos7-import", "old-orphan-image"]))
        self.assertEqual(sorted(i["label"] for i in fx["items"] if i["default"]), ["centos7-import", "upload-win2022"])
        kept = {s["key"]: s for s in item["result"]["steps"]}["kept"]
        self.assertEqual(sorted(r[0] for r in kept["table"]["rows"]), ["golden-template", "rhel9-empty"])
        snap = names.index("snap-db-prod-2026-09")
        self.assertIn("snapshots 55555555-0000-4000-8000-000000000014", fx["items"][snap]["commands"][0])
        chosen = [names.index("upload-win2022"), snap]
        r = osfix.post(f"/wi/api/runs/{item['id']}/fixes/{idx}", json={"selected": chosen, "confirm": "upload-win2022"})
        self.assertIn("type 2 images to confirm", r.get_json()["error"])
        r = osfix.post(f"/wi/api/runs/{item['id']}/fixes/{idx}", json={"selected": chosen, "confirm": "2 images"})
        fix = self.wait_fix(osfix, r.get_json()["action_id"])
        self.assertEqual(fix["status"], "ok", fix)
        self.assertIn("image snap-db-prod-2026-09 and 1 volume snapshot(s) deleted", json.dumps(fix["output"]))
        again = self.wait_run(osfix, fix["verify_run_id"])
        offered = again["result"]["recommendations"][fix_of(again, "Delete selected images")]
        self.assertEqual(sorted(r[0] for r in offered["items"]["rows"]), ["centos7-import", "old-orphan-image"])
        if os.path.exists(os.path.join(TMP, "cloud-state.json")):
            os.remove(os.path.join(TMP, "cloud-state.json"))

        # ---- Cinder: archive-2024 fails once (its temporary copy is removed, the next pool takes it); logs-old migrates
        # after its 3 approved snapshots are deleted
        item = self.run_check(osfix, "cinder-pool-usage", {})
        idx = next(i for i, r in enumerate(item["result"]["recommendations"])
                   if (r.get("action") or {}).get("label") == "Migrate selected" and "CINDER_14" in r["text"].split(" to ")[0])
        fx = item["fixes"][idx]
        labels = [i["label"] for i in fx["items"]]
        archive = next(i for i, x in enumerate(labels) if x.startswith("archive-2024"))
        logs = next(i for i, x in enumerate(labels) if x.startswith("logs-old"))
        web_root = next(i for i, x in enumerate(labels) if x.startswith("web-01-root"))
        # ticked by default: the biggest without snapshots that fit below the early level of the target (archive-2024,
        # 3000 GiB, does not); never one with snapshots
        self.assertEqual([fx["items"][i]["default"] for i in (web_root, archive, logs)], [True, False, False])
        self.assertTrue(fx["items"][logs]["delete"] and labels[logs].endswith("+ delete 3 snapshot(s)"))
        r = osfix.post(f"/wi/api/runs/{item['id']}/fixes/{idx}", json={"selected": [archive, logs], "confirm": "2 volumes"})
        fix = self.wait_fix(osfix, r.get_json()["action_id"])
        self.assertEqual(fix["status"], "ok", fix)
        out = json.dumps(fix["output"])
        self.assertIn("Automatic fix: remove the temporary copy 11111111-0000-4000-8000-000000000063", out)
        self.assertRegex(out, r"Automatic fix: the temporary copy was cleaned up; (the same pool is tried once more|\S+ is tried next)")
        self.assertIn("3 snapshot(s) of logs-old deleted", out)

    def test_jump_hosts(self):
        """A host without a reachable address goes through a jump host of the same site (one hop), each with its own
        SSH credential; the job gets the jump host's key or password in the environment only."""
        admin = self.client()
        key = new_key()
        lb_cred = admin.post("/wi/api/credentials", json={"name": "dcc-lb", "username": "cdnadmin", "auth": "key",
                                                          "privilege": "sudo", "secret": key}).get_json()["id"]
        node_cred = admin.post("/wi/api/credentials", json={"name": "dcc-node", "username": "ops", "auth": "password",
                                                            "privilege": "sudo_password", "secret": "node-pw"}).get_json()["id"]
        add = lambda **kw: admin.post("/wi/api/hosts", json={"site": "DCC", "group": "cdn", **kw})
        lb = add(name="dcc-cdn-lb-01", address="11.4.0.5", credential_id=lb_cred).get_json()["id"]
        bare = add(name="dcc-cdn-lb-02", address="11.4.0.6").get_json()["id"]
        r = admin.post("/wi/api/hosts/bulk", json={"site": "DCC", "group": "cdn", "credential_id": node_cred, "jump_id": lb,
                                                   "lines": "dcc-cdn-node-01 10.248.0.11\ndcc-cdn-node-02 10.248.0.12"})
        self.assertEqual(r.get_json()["added"], 2, r.get_json())
        view = {h["name"]: h for h in admin.get("/wi/api/hosts").get_json()["hosts"]}
        node = view["dcc-cdn-node-01"]["id"]
        self.assertEqual((view["dcc-cdn-node-01"]["jump"], view["dcc-cdn-lb-01"]["jumped"]), ("dcc-cdn-lb-01", 2))
        for body, reason in (({"name": "dcc-x", "address": "10.248.0.20", "jump_id": bare}, "no SSH credential"),
                             ({"name": "dcc-x", "address": "10.248.0.20", "jump_id": node}, "itself goes through a jump host"),
                             ({"name": "dcc-x", "address": "10.248.0.20", "jump_id": 999999}, "Choose a jump host of site DCC")):
            r = add(**body)
            self.assertEqual(r.status_code, 400, body)
            self.assertIn(reason, r.get_json()["error"])
        r = admin.post("/wi/api/hosts", json={"site": "DCA", "group": "cdn", "name": "dca-x", "address": "10.252.1.1", "jump_id": lb})
        self.assertIn("Choose a jump host of site DCA", r.get_json()["error"])
        r = admin.put(f"/wi/api/hosts/{lb}", json={"site": "DCC", "group": "cdn", "name": "dcc-cdn-lb-01", "address": "11.4.0.5",
                                                   "credential_id": lb_cred, "jump_id": bare})
        self.assertIn("Other hosts connect through this host", r.get_json()["error"])
        r = admin.put(f"/wi/api/hosts/{node}", json={"site": "DCC", "group": "cdn", "name": "dcc-cdn-node-01", "address": "10.248.0.11",
                                                     "credential_id": node_cred, "jump_id": node})
        self.assertIn("its own jump host", r.get_json()["error"])
        r = admin.delete(f"/wi/api/hosts/{lb}")
        self.assertIn("2 host(s) connect through dcc-cdn-lb-01", r.get_json()["error"])
        # what a job gets: the jump host in the target, its key in the environment, the ProxyCommand option
        from core import PORTAL
        from modules.wi import hosts as wi_hosts
        import wi_analysis
        target = wi_hosts.target("DCC", ["cdn"], "10.248.0.11")
        self.assertEqual(target["jump"], {"name": "dcc-cdn-lb-01", "address": "11.4.0.5", "port": 22, "credential_id": lb_cred,
                                          "user": "cdnadmin", "auth": "key"})
        self.assertEqual(wi_hosts.jump_secrets(PORTAL.vault, target), {"WI_SSH_JUMP_SECRET": key.strip() + "\n"})
        self.assertEqual(wi_analysis.ssh_proxy_args(target["jump"], "/tmp/ansible.abc.key"),
                         "-o 'ProxyCommand=ssh -F /dev/null -p 22 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 "
                         "-o ServerAliveInterval=30 -i /tmp/ansible.abc.key -o IdentitiesOnly=yes -o BatchMode=yes -W %h:%p "
                         "cdnadmin@11.4.0.5'")
        password_jump = dict(target["jump"], auth="password", port=2222)
        self.assertIn("ProxyCommand=sshpass -e ssh -F /dev/null -p 2222", wi_analysis.ssh_proxy_args(password_jump))
        for bad in (dict(target["jump"], address="1.2.3.4;id"), dict(target["jump"], user="a b")):
            with self.assertRaises(ValueError):
                wi_analysis.ssh_proxy_args(bad, "/tmp/k")
        with self.assertRaises(ValueError):
            wi_analysis.ssh_proxy_args(target["jump"], "")   # key sign-in needs the key file
        # clean up: the nodes first, then the jump host
        for name in ("dcc-cdn-node-01", "dcc-cdn-node-02", "dcc-cdn-lb-01", "dcc-cdn-lb-02"):
            hid = {h["name"]: h["id"] for h in admin.get("/wi/api/hosts").get_json()["hosts"]}[name]
            self.assertEqual(admin.delete(f"/wi/api/hosts/{hid}").status_code, 200, name)
        for cid in (lb_cred, node_cred):
            admin.delete(f"/wi/api/credentials/{cid}")

    def test_control_plane(self):
        """OVN RAFT databases, RabbitMQ queues and Galera on the controllers (RISET-KNOWN-ISSUES 2.1 / 2.2)."""
        c = self.client()
        item = self.run_check(c, "ovn-db-cluster", {})
        st = {s["key"]: s for s in item["result"]["steps"]}
        self.assertEqual(st["model"]["status"], "ok", st["model"])
        self.assertIn("Clustered (RAFT)", st["model"]["detail"])
        self.assertEqual(st["nbraft"]["status"], "ok", st["nbraft"])
        self.assertIn("Leader: overcloud-controller-0; term 3; members per node: 3", st["nbraft"]["detail"])
        self.assertEqual(st["sbraft"]["status"], "warn", st["sbraft"])   # a removed controller is still a member
        self.assertIn("More members than controllers", st["sbraft"]["detail"])
        self.assertEqual(st["northd"]["status"], "ok")
        self.assertIn("Active on overcloud-controller-0", st["northd"]["detail"])
        self.assertEqual(st["size"]["status"], "warn")
        self.assertIn("MAC_Binding: 152,340 row(s); the biggest database file: 700 MB", st["size"]["detail"])
        self.assertTrue(any(r.get("references") for r in item["result"]["recommendations"]))
        item = self.run_check(c, "rabbitmq-queues", {})
        st = {s["key"]: s for s in item["result"]["steps"]}
        self.assertEqual((st["fd"]["status"], st["queues"]["status"]), ("warn", "warn"), st)
        self.assertIn("overcloud-controller-0 fd 93%", st["fd"]["detail"])
        self.assertIn("6 queue(s); 3 with 1000 messages or more", st["queues"]["detail"])
        purge = next(r for r in item["result"]["recommendations"] if r["text"].startswith("Notification queues"))
        self.assertEqual(len(purge["commands"]), 2)   # notifications.* only, never the fanout queue
        self.assertNotIn("fanout", " ".join(purge["commands"]))
        item = self.run_check(c, "galera-wsrep", {})
        st = {s["key"]: s for s in item["result"]["steps"]}
        self.assertEqual(st["wsrep"]["status"], "warn", st["wsrep"])
        self.assertIn("overcloud-controller-2", st["wsrep"]["detail"])
        self.assertIn(["overcloud-controller-2", "3", "Primary", "Synced", "ON", "0.25", "4.5", "3100 now, 3900 peak of 4096 (95%)"],
                      st["wsrep"]["table"]["rows"])

    def test_ontap_health(self):
        """ONTAP volumes / LUNs and HA / redundancy (RISET-KNOWN-ISSUES 2.5), with the read-only ONTAP account."""
        c = self.client()
        test = c.post("/api/admin/credentials/ontap:DCA", json={"username": ONTAP_RO[0], "password": ONTAP_RO[1]}).get_json()["test"]
        self.assertTrue(test["ok"], test)
        self.addCleanup(c.delete, "/api/admin/credentials/ontap:DCA")
        item = self.run_check(c, "ontap-volume-lun-state", {})
        st = {s["key"]: s for s in item["result"]["steps"]}
        self.assertEqual(st["volumes"]["status"], "ok", st["volumes"])
        self.assertEqual(st["luns"]["status"], "fail", st["luns"])
        self.assertIn("1 in space_error", st["luns"]["detail"])
        self.assertEqual(st["autosize"]["status"], "warn", st["autosize"])
        self.assertTrue(any(r[0].endswith("_CINDER_15_vol") for r in st["autosize"]["table"]["rows"]))
        self.assertEqual(st["inodes"]["status"], "fail", st["inodes"])   # CINDER_16 at 92%
        self.assertEqual(st["svms"]["status"], "ok", st["svms"])        # the stopped DR destination is not counted
        recs = item["result"]["recommendations"]
        self.assertIn("lun online -vserver", " ".join(c2 for r in recs for c2 in r["commands"]))
        self.assertTrue(all(ref["vendor"] == "NetApp" for r in recs for ref in r.get("references") or []))
        item = self.run_check(c, "ontap-ha-redundancy", {})
        st = {s["key"]: s for s in item["result"]["steps"]}
        self.assertEqual(st["ha"]["status"], "fail", st["ha"])
        self.assertIn("DCASTNCL-04", st["ha"]["detail"])
        self.assertEqual((st["spares"]["status"], st["ports"]["status"], st["ntp"]["status"]), ("warn", "warn", "warn"), st)
        self.assertIn("No spare disk on: DCASTNCL-04", st["spares"]["detail"])
        self.assertIn(["DCASTNCL-03", "0", "2"], st["spares"]["table"]["rows"])   # spare partitions only (ADP): not "no spare"
        self.assertEqual(st["ports"]["table"]["rows"],   # the interface group lost a member; unused e0f down is not rated
                         [["DCASTNCL-02", "a0a", "interface group", "-", "1 of 2 member port(s) active; not active: e0c"]])
        self.assertIn("8 unused port(s) are down", st["ports"]["detail"])   # e0d and e0f of each node
        self.assertIn("1 NTP server(s)", st["ntp"]["detail"])
        self.assertIn("DCASTNCL-03 +12", st["ntp"]["detail"])   # 120 s ahead (a few seconds of the run itself)

    def test_prime_platform(self):
        """NSX-T gateways and BGP, the vCloud Director platform, the vCenter appliance (RISET-KNOWN-ISSUES 2.6-2.8)."""
        c = self.client()
        account = {"username": mock_vmware.READONLY_USER, "password": mock_vmware.READONLY_PASSWORD}
        for name in ("ro-nsxt:DCA", "ro-vcenter:DCA"):
            self.assertTrue(c.post(f"/api/admin/credentials/{name}", json=account).get_json()["test"]["ok"], name)
            self.addCleanup(c.delete, f"/api/admin/credentials/{name}")
        r = c.post("/api/admin/credentials/ro-vcd", json={**account, "address": f"https://127.0.0.1:{VMWARE.port}/"})
        self.assertTrue(r.get_json()["test"]["ok"], r.get_json())
        self.addCleanup(c.delete, "/api/admin/credentials/ro-vcd")
        item = self.run_check(c, "nsxt-gateway-routing", {"tier1": "t1-cust-a"})
        st = {s["key"]: s for s in item["result"]["steps"]}
        self.assertEqual(st["gateways"]["status"], "fail", st["gateways"])   # the Tier-1 has two ACTIVE: split brain
        self.assertIn("Tier-1 t1-cust-a", st["gateways"]["detail"])
        self.assertNotIn("T0-DCA", st["gateways"]["detail"])
        self.assertEqual(st["bgp"]["status"], "fail", st["bgp"])
        self.assertIn("Not ESTABLISHED: T0-DCA → 10.240.0.2", st["bgp"]["detail"])
        self.assertIn("T0-DCA → 10.240.0.1", st["bgp"]["detail"])            # up for 20 minutes: flapped
        self.assertEqual(st["clusters"]["status"], "ok")
        self.assertTrue(any("425005" in ref["url"] for rec in item["result"]["recommendations"] for ref in rec.get("references") or []))
        item = self.run_check(c, "vcd-platform", {})
        st = {s["key"]: s for s in item["result"]["steps"]}
        self.assertEqual(st["cells"]["status"], "fail", st["cells"])
        self.assertIn("Inactive: vcd-cell-03-old", st["cells"]["detail"])
        self.assertIn("10.248.0.12", st["cells"]["detail"])
        self.assertEqual((st["vcenters"]["status"], st["edges"]["status"], st["nets"]["status"]), ("ok", "fail", "ok"), st)
        self.assertEqual(st["edges"]["table"]["rows"], [["CUST-B-EDGE", "cust-b", "REALIZATION_FAILED"]])
        item = self.run_check(c, "vcenter-appliance", {})
        st = {s["key"]: s for s in item["result"]["steps"]}
        self.assertEqual((st["health"]["status"], st["services"]["status"], st["backup"]["status"]), ("warn", "fail", "fail"), st)
        self.assertIn("system yellow, storage yellow", st["health"]["detail"])
        self.assertIn("Not running: vmware-sps", st["services"]["detail"])
        self.assertIn("Last job failed", st["backup"]["detail"])

    def test_cert_inventory(self):
        """Internal certificates of vCenter, the ESXi hosts, NSX-T, vCloud Director and ONTAP (RISET-KNOWN-ISSUES 2.5-2.8)."""
        c = self.client()
        item = self.run_check(c, "cert-inventory", {})   # no account yet: every store is skipped, nothing fails
        self.assertEqual(item["result"]["status"], "skip", item["result"]["summary"])
        overview = {s["key"]: s for s in item["result"]["steps"]}["overview"]
        self.assertTrue(all(r[4] == "NOT READ" for r in overview["table"]["rows"]), overview)
        account = {"username": mock_vmware.READONLY_USER, "password": mock_vmware.READONLY_PASSWORD}
        for name in ("ro-nsxt:DCA", "ro-vcenter:DCA"):
            self.assertTrue(c.post(f"/api/admin/credentials/{name}", json=account).get_json()["test"]["ok"], name)
            self.addCleanup(c.delete, f"/api/admin/credentials/{name}")
        r = c.post("/api/admin/credentials/ro-vcd", json={**account, "address": f"https://127.0.0.1:{VMWARE.port}/"})
        self.assertTrue(r.get_json()["test"]["ok"], r.get_json())
        self.addCleanup(c.delete, "/api/admin/credentials/ro-vcd")
        test = c.post("/api/admin/credentials/ontap:DCA", json={"username": ONTAP_RO[0], "password": ONTAP_RO[1]}).get_json()["test"]
        self.assertTrue(test["ok"], test)
        self.addCleanup(c.delete, "/api/admin/credentials/ontap:DCA")
        item = self.run_check(c, "cert-inventory", {})
        st = {s["key"]: s for s in item["result"]["steps"]}
        self.assertEqual([r[4] for r in st["overview"]["table"]["rows"]],
                         ["WARN", "WARN", "FAIL", "FAIL", "WARN", "WARN", "FAIL"], st["overview"])
        self.assertEqual(st["overview"]["table"]["columns"][-1], "Status")   # every system read: no column Note
        self.assertEqual(st["sts"]["status"], "warn", st["sts"])   # 120 days: under the 180 days of KB 318968
        self.assertIn("120 day(s) left", st["sts"]["detail"])
        self.assertIn("EXPIRED", [r[5] for r in st["sts"]["table"]["rows"]])   # an old chain, validation only
        self.assertEqual(st["vctrust"]["status"], "warn", st["vctrust"])   # the CA that issued Machine SSL: 20 days
        roots = {r[0]: r for r in st["vctrust"]["table"]["rows"]}
        self.assertEqual(roots["Trusted root (issued Machine SSL)"][4:], [20, "WARN"])
        self.assertEqual(roots["Machine SSL (vCenter on port 443)"][4:], [400, "OK"])
        self.assertIn("1 expired and not in use", st["vctrust"]["detail"])
        self.assertIn("Machine SSL: 400 day(s) left; the CA that issued it: 20 day(s)", st["vctrust"]["detail"])
        self.assertEqual(st["esxi"]["status"], "fail", st["esxi"])   # esxi-dca-03: 5 days, expirationImminent
        hosts = {r[0]: r for r in st["esxi"]["table"]["rows"]}
        self.assertEqual(hosts["esxi-dca-03"][5:], [5, "expirationImminent", "FAIL"])
        self.assertEqual(hosts["esxi-dca-02"][5:], [20, "expiringShortly", "WARN"])
        self.assertTrue(hosts["esxi-dca-05"][7].startswith("NOT READ"))
        self.assertEqual(st["nsx"]["status"], "fail", st["nsx"])   # the APH certificate in use: 5 days
        nsx = {r[0]: r for r in st["nsx"]["table"]["rows"]}
        self.assertEqual(nsx["APH-AR-nsx-mgr-dca-01"][4:], [5, "APH on 2 node(s)", "FAIL"])
        self.assertEqual(nsx["LM-dca"][4:], [25, "LOCAL_MANAGER on 1 node(s)", "WARN"])   # from its PEM (no details)
        self.assertEqual(nsx["imported-2023"][6], "EXPIRED (not in use)")
        self.assertEqual(st["vcdlib"]["status"], "warn", st["vcdlib"])   # the console proxy certificate in use: 15 days
        lib = {r[0]: r for r in st["vcdlib"]["table"]["rows"]}
        self.assertEqual(lib["console-proxy-dca"][4:], [15, "1: vcd-cell-01 console proxy", "WARN"])
        self.assertEqual(lib["old-lb-cert"][5:], ["none", "expires soon (not in use)"])
        self.assertEqual(st["vcdtrust"]["status"], "warn", st["vcdtrust"])   # an older certificate of the same name trusted
        self.assertIn("still trusts an older certificate of: vCenter, NSX-T Manager", st["vcdtrust"]["detail"])
        self.assertEqual(st["ontap"]["status"], "fail", st["ontap"])   # svm-cinder expired 3 days ago
        ontap = {r[1]: r for r in st["ontap"]["table"]["rows"] if r[2] == "server"}
        self.assertEqual(ontap["svm-cinder"][5:], [-3, "EXPIRED"])
        self.assertEqual(ontap["DCA-ONTAP"][5:], [12, "WARN"])   # the cluster certificate: the admin SVM, named as the cluster
        self.assertIn("1 of them expire soon or have expired", st["ontap"]["detail"])
        recs = item["result"]["recommendations"]
        text = " ".join(x for rec in recs for x in rec["commands"])
        self.assertIn("./fixsts.sh", text)
        self.assertIn("CertMgrRefreshCertificates_Task(@((Get-VMHost esxi-dca-03).ExtensionData.MoRef))", text)
        self.assertIn("security certificate create -vserver svm-cinder -common-name svm-cinder -type server", text)
        self.assertIn("security ssl modify -vserver DCA-ONTAP -server-enabled true", text)
        self.assertTrue(st["overview"].get("open"))
        self.assertNotIn("Get-VMHost esxi-dca-01)", text)
        urls = " ".join(ref["url"] for rec in recs for ref in rec.get("references") or [])
        for kb in ("318968", "374032", "424553", "certificate-library", "How_to_renew_an_ONTAP"):
            self.assertIn(kb, urls)
        self.assertFalse(any(rec.get("action") for rec in recs))   # Acme Prime and ONTAP certificates: no fix from the portal

    def test_certmonger(self):
        try:
            self._certmonger()
        finally:   # the fake cloud forgets the resubmits: the certificates expire again for the other runs
            if os.path.exists(os.path.join(TMP, "cloud-state.json")):
                os.remove(os.path.join(TMP, "cloud-state.json"))

    def _certmonger(self):
        """certmonger on the director and the overcloud nodes (TLS everywhere, RISET-KNOWN-ISSUES 2.2), and the fix that
        resubmits the ticked requests."""
        c = self.client()
        item = self.run_check(c, "certmonger-status", {})
        st = {s["key"]: s for s in item["result"]["steps"]}
        self.assertEqual(st["undercloud"]["status"], "warn", st["undercloud"])   # 12 days left on the director
        self.assertEqual(st["undercloud"]["table"]["rows"][0][6:], [12, "yes", "WARN"])
        self.assertEqual(st["nodes"]["status"], "ok", st["nodes"])
        self.assertEqual(st["requests"]["status"], "fail", st["requests"])
        self.assertIn("1 that certmonger cannot renew (CA problem or stuck), 1 expiring", st["requests"]["detail"])
        first = st["requests"]["table"]["rows"][0]
        self.assertEqual((first[0], first[1], first[7], first[9]), ("overcloud-controller-0", "20240101000010", 5, "FAIL"))
        self.assertIn("CA_UNREACHABLE: Server at https://idm-01.prime.local", first[5])
        recs = item["result"]["recommendations"]
        ca = next(r for r in recs if r["text"].startswith("certmonger on overcloud-controller-0 cannot renew"))
        self.assertIn("sudo getcert resubmit -i 20240101000010", ca["commands"])
        self.assertIn("ssh heat-admin@192.168.253.10", ca["where"])
        director = next(r for r in recs if r["where"] == "OpenStack director, as stack")
        self.assertTrue(any("5508191" in ref["url"] for ref in director["references"]))
        item = self.run_check(c, "certmonger-status", {"role": "compute"})
        st = {s["key"]: s for s in item["result"]["steps"]}
        self.assertEqual(st["nodes"]["status"], "warn", st["nodes"])   # overcloud-novacompute-3 does not answer
        self.assertEqual(st["requests"]["status"], "ok", st["requests"])
        # ---- the fix: the requests of the nodes, soonest first; a CA problem is not ticked (IdM first)
        osfix = self.client("osfixer", "demo-operator-5")
        item = self.run_check(osfix, "certmonger-status", {})
        recs = item["result"]["recommendations"]
        idx = next(i for i, x in enumerate(recs) if (x.get("action") or {}).get("label") == "Resubmit the ticked certificates")
        fx = item["fixes"][idx]
        self.assertEqual((fx["risk"], fx["available"], len(fx["items"])), ("normal", True, 2), fx)
        self.assertEqual([i["default"] for i in fx["items"]], [False, True])
        self.assertEqual(fx["items"][1]["commands"],
                         ["getcert-resubmit 20240101000020 node overcloud-controller-1=192.168.253.11 user heat-admin"])
        self.assertEqual(recs[idx]["items"]["rows"][0][:2], ["overcloud-controller-0", "20240101000010"])
        r = osfix.post(f"/wi/api/runs/{item['id']}/fixes/{idx}", json={"selected": [1]})
        self.assertEqual(r.status_code, 200, r.get_json())
        fix = self.wait_fix(osfix, r.get_json()["action_id"])
        out = json.dumps(fix["output"])
        self.assertEqual(fix["status"], "ok", out)
        self.assertIn("sudo getcert resubmit -i 20240101000020", out)
        self.assertIn("request 20240101000020 on overcloud-controller-1 renewed", out)
        again = self.wait_run(osfix, fix["verify_run_id"])   # the check again: controller-1 renewed, controller-0 not
        st = {s["key"]: s for s in again["result"]["steps"]}
        self.assertIn("1 that certmonger cannot renew (CA problem or stuck), 0 expiring", st["requests"]["detail"])
        rows = {(x[0], x[1]): x for x in st["requests"]["table"]["rows"]}
        self.assertEqual(rows[("overcloud-controller-1", "20240101000020")][7:], [730, "yes", "OK"])
        recs = again["result"]["recommendations"]
        idx = next(i for i, x in enumerate(recs) if (x.get("action") or {}).get("label") == "Resubmit the ticked certificates")
        r = osfix.post(f"/wi/api/runs/{again['id']}/fixes/{idx}", json={"selected": [0]})   # IdM unreachable: not renewed
        fix = self.wait_fix(osfix, r.get_json()["action_id"])
        out = json.dumps(fix["output"])
        self.assertNotEqual(fix["status"], "ok", out)
        self.assertIn("certmonger could not renew request 20240101000010 on overcloud-controller-0: CA_UNREACHABLE", out)

    def test_templates(self):
        try:
            self._templates()
        finally:   # the fake hosts forget the fixes: other tests expect their problems
            if os.path.exists(os.path.join(TMP, "hosts-state.json")):
                os.remove(os.path.join(TMP, "hosts-state.json"))

    def _templates(self):
        admin = self.client()
        ops = admin.post("/wi/api/credentials", json={"name": "tpl-ops", "username": "root", "auth": "key", "privilege": "root",
                                                      "fixes": True, "secret": new_key()}).get_json()["id"]
        r = admin.post("/wi/api/hosts", json={"site": "DCA", "group": "cdn", "name": "dca-cdn-lb-09", "address": "172.31.10.79",
                                              "credential_id": ops})
        self.assertEqual(r.status_code, 200, r.get_json())
        body = {"name": "AIDE files on /run", "summary": "", "activity": "troubleshoot", "category": "cdn", "group": "cdn",
                "steps": [{"title": "Usage of /run", "command": "df -Pk /run", "problem_if": "9[0-9]%", "warning_if": "8[0-9]%"},
                          {"title": "Delete the AIDE files", "command": "sudo rm -rf /run/aide/*", "wait": 2}]}
        # only administrators make templates; the portal (not the form) says what a step does
        l1 = self.client("l1", "demo-operator-1")
        self.assertEqual(l1.post("/wi/api/templates", json=body).status_code, 403)
        self.assertEqual(l1.post("/wi/api/templates/classify", json={"group": "cdn", "commands": ["df -h"]}).status_code, 403)
        modes = admin.post("/wi/api/templates/classify", json={"group": "cdn", "commands": ["df -Pk /run", "sudo rm -rf /run/aide/*",
                                                                                           "cat /etc/hosts > /tmp/x"]}).get_json()["items"]
        self.assertEqual([m["mode"] for m in modes], ["read", "change", "change"])
        self.assertIn("writes the output to a file", modes[2]["why"])
        bad = dict(body, group="huawei", steps=[{"title": "x", "command": "system-view"}])
        self.assertIn("read-only", admin.post("/wi/api/templates", json=bad).get_json()["error"])
        self.assertEqual(admin.post("/wi/api/templates", json=dict(body, steps=[])).status_code, 400)
        self.assertEqual(admin.post("/wi/api/templates", json=dict(body, steps=[{"title": "x", "command": "grep -E '(' f",
                                                                                  "problem_if": "("}])).status_code, 400)
        r = admin.post("/wi/api/templates", json=body)
        self.assertEqual(r.status_code, 200, r.get_json())
        tid = r.get_json()["id"]
        self.assertEqual(tid, "tpl-aide-files-on-run")
        self.assertEqual(admin.post("/wi/api/templates", json=body).status_code, 400)   # the same name twice
        # listed with the checks, runnable by every user of the module
        cat = {c["id"]: c for c in l1.get("/wi/api/catalog?site=DCA").get_json()["checks"]}
        self.assertEqual((cat[tid]["basis"], cat[tid]["activity"], cat[tid]["category"]), ("template", "troubleshoot", "cdn"))
        self.assertTrue(cat[tid]["access"]["runnable"], cat[tid]["access"])
        self.assertEqual([s["mode"] for s in cat[tid]["template"]["steps"]], ["read", "change"])
        item = self.run_check(l1, tid, {"host": "dca-cdn-lb-09"})
        self.assertEqual(self.steps(item), {"conn": "ok", "s1": "fail"}, item)
        self.assertIn("97%", next(s for s in item["result"]["steps"] if s["key"] == "s1")["detail"])
        idx = next(i for i, f in enumerate(item["fixes"]) if f)
        self.assertEqual(item["result"]["recommendations"][idx]["action"]["commands"], ["sudo rm -rf /run/aide/*", "sleep 2"])
        self.assertFalse(item["fixes"][idx]["available"])   # l1 may not run fixes
        # the change steps: a fix of risk high, after the host name is typed
        fixer = self.client("fixer", "demo-operator-3")
        item = self.run_check(fixer, tid, {"host": "dca-cdn-lb-09"})
        idx = next(i for i, f in enumerate(item["fixes"]) if f)
        self.assertEqual((item["fixes"][idx]["available"], item["fixes"][idx]["risk"]), (True, "high"), item["fixes"])
        self.assertEqual(fixer.post(f"/wi/api/runs/{item['id']}/fixes/{idx}", json={"confirm": "x"}).status_code, 400)
        r = fixer.post(f"/wi/api/runs/{item['id']}/fixes/{idx}", json={"confirm": "dca-cdn-lb-09"})
        self.assertEqual(r.status_code, 200, r.get_json())
        fix = self.wait_fix(fixer, r.get_json()["action_id"])
        self.assertEqual(fix["status"], "ok", fix)
        again = self.wait_run(fixer, fix["verify_run_id"])
        self.assertEqual(self.steps(again)["s1"], "ok", again)
        # an administrator changes and deletes it; the changes are in the portal events
        self.assertEqual(admin.put(f"/wi/api/templates/{tid}", json=dict(body, name="AIDE on /run")).status_code, 200)
        self.assertEqual(admin.get(f"/wi/api/templates/{tid}").get_json()["template"]["name"], "AIDE on /run")
        self.assertEqual(l1.delete(f"/wi/api/templates/{tid}").status_code, 403)
        self.assertEqual(admin.delete(f"/wi/api/templates/{tid}").status_code, 200)
        self.assertNotIn(tid, {c["id"] for c in admin.get("/wi/api/catalog?site=DCA").get_json()["checks"]})
        self.assertEqual(admin.post("/wi/api/runs", json={"site": "DCA", "check": tid, "params": {"host": "dca-cdn-lb-09"}}).status_code, 400)
        events = [e for e in admin.get("/api/admin/events?kinds=wi").get_json()["events"] if e["action"] == "wi.template"]
        self.assertEqual(len(events), 3, events)

    def test_fixes(self):
        try:
            self._fixes()
        finally:   # the fake hosts forget the fixes: other tests expect their problems
            if os.path.exists(os.path.join(TMP, "hosts-state.json")):
                os.remove(os.path.join(TMP, "hosts-state.json"))

    def _fixes(self):
        admin = self.client()
        key = new_key()
        r = admin.post("/wi/api/credentials", json={"name": "ops", "username": "root", "auth": "key", "privilege": "root",
                                                    "fixes": True, "secret": key})
        self.assertEqual(r.status_code, 200, r.get_json())
        ops = r.get_json()["id"]
        ro = admin.post("/wi/api/credentials", json={"name": "ro", "username": "wi-ro", "auth": "password",
                                                     "privilege": "sudo_password", "secret": "pw-ro"}).get_json()["id"]
        self.assertEqual(admin.post("/wi/api/credentials", json={"name": "bad", "username": "x", "auth": "key",
                                                                 "privilege": "root", "secret": "not a key"}).status_code, 400)
        r = admin.post("/wi/api/hosts/bulk", json={"site": "DCA", "group": "cdn", "credential_id": ops,
                                                   "lines": "dca-cdn-lb-02 172.31.10.68\ndca-cdn-lb-01 172.31.10.67"})
        self.assertEqual(r.get_json()["added"], 2, r.get_json())
        self.assertEqual(admin.post("/wi/api/hosts", json={"site": "DCA", "group": "linux", "name": "app-vm-01",
                                                           "address": "10.249.1.20", "credential_id": ro}).status_code, 200)
        view = admin.get("/wi/api/hosts").get_json()
        self.assertNotIn(key.splitlines()[1], str(view))
        self.assertNotIn("pw-ro", str(view))
        self.assertTrue(all("secret" not in c for c in view["credentials"]))
        # permissions: "all modules" does not include running fixes; operators cannot manage hosts
        l1 = self.client("l1", "demo-operator-1")
        self.assertEqual(l1.get("/wi/api/hosts").status_code, 403)
        self.assertFalse(self.client("allmods", "demo-operator-4").get("/wi/api/session").get_json()["can_fix"])
        fixer = self.client("fixer", "demo-operator-3")
        self.assertTrue(fixer.get("/wi/api/session").get_json()["can_fix"])
        # a standard fix: start the stopped lb container; the check runs again and is OK
        item = self.run_check(fixer, "cdn-datasource", {"host": "dca-cdn-lb-02"})
        self.assertEqual(self.steps(item)["container"], "fail", item)
        idx = next(i for i, f in enumerate(item["fixes"]) if f)
        self.assertEqual((item["fixes"][idx]["available"], item["fixes"][idx]["risk"]), (True, "normal"), item["fixes"])
        l1_item = l1.get(f"/wi/api/runs/{item['id']}").get_json()["item"]
        self.assertFalse(l1_item["fixes"][idx]["available"])
        self.assertEqual(l1.post(f"/wi/api/runs/{item['id']}/fixes/{idx}", json={}).status_code, 403)
        r = fixer.post(f"/wi/api/runs/{item['id']}/fixes/{idx}", json={})
        self.assertEqual(r.status_code, 200, r.get_json())
        fix = self.wait_fix(fixer, r.get_json()["action_id"])
        self.assertEqual(fix["status"], "ok", fix)
        self.assertIn("sudo docker start lb", fix["commands"])
        # its full output is in the raw output of the run (permission collect logs; the fixer has not got it)
        self.assertEqual(fixer.get(f"/wi/export/runs/{item['id']}/raw.zip").status_code, 403)
        import zipfile as zipmod
        z = zipmod.ZipFile(io.BytesIO(admin.get(f"/wi/export/runs/{item['id']}/raw.zip").data))
        text = z.read(f"fixes/fix-{fix['id']}.txt").decode()
        self.assertIn("$ sudo docker start lb", text)
        self.assertIn("(exit 0)", text)
        again = self.wait_run(fixer, fix["verify_run_id"])
        self.assertEqual((again["status"], self.steps(again)["container"]), ("ok", "ok"), again)
        # a high-risk fix (kill -9) needs the host name typed
        item = self.run_check(admin, "cdn-memory", {"host": "dca-cdn-lb-01"})
        idx = next(i for i, f in enumerate(item["fixes"]) if f and f["risk"] == "high")
        r = admin.post(f"/wi/api/runs/{item['id']}/fixes/{idx}", json={"confirm": "wrong"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("type the host name dca-cdn-lb-01", r.get_json()["error"])
        r = admin.post(f"/wi/api/runs/{item['id']}/fixes/{idx}", json={"confirm": "dca-cdn-lb-01"})
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertEqual(self.wait_fix(admin, r.get_json()["action_id"])["status"], "ok")
        # read-only credential, and a read-only host of sites.yml: the fix is shown but cannot run
        item = self.run_check(admin, "linux-firewall", {"host": "app-vm-01", "port": "27017"})
        f = next(x for x in item["fixes"] if x)
        self.assertFalse(f["available"])
        self.assertIn("may only read", f["reason"])
        item = self.run_check(admin, "vyos-nat-firewall", {"host": "dca-natgw-01"})
        f = next(x for x in item["fixes"] if x)
        self.assertIn("read-only host of sites.yml", f["reason"])
        self.assertEqual(f["risk"], "high")
        # ONTAP: read and the cluster management LIF away from home reverted with the ONTAP Restore account
        self.assertTrue(admin.post("/api/admin/credentials/ontap:DCA", json={"username": "admin", "password": mock_ontap.PASSWORD}).get_json()["test"]["ok"])
        item = self.run_check(admin, "ontap-cluster-health", {})
        self.assertEqual(self.steps(item)["cluster_mgmt"], "fail", item)
        idx = next(i for i, f in enumerate(item["fixes"]) if f)
        self.assertTrue(item["fixes"][idx]["available"], item["fixes"][idx])
        r = admin.post(f"/wi/api/runs/{item['id']}/fixes/{idx}", json={})
        fix = self.wait_fix(admin, r.get_json()["action_id"])
        self.assertEqual(fix["status"], "ok", fix)
        again = self.wait_run(admin, fix["verify_run_id"])
        self.assertEqual(self.steps(again)["cluster_mgmt"], "ok", again)
        events = admin.get("/api/admin/events?kinds=wi").get_json()["events"]
        self.assertTrue(any(e["action"] == "wi.fix_ok" for e in events))

    def start_and_wait(self, client, check, params, site="DCA"):
        r = client.post("/wi/api/runs", json={"site": site, "check": check, "params": params})
        self.assertEqual(r.status_code, 200, r.get_json())
        item = self.wait_run(client, r.get_json()["run_id"])
        self.check_screens(item)
        return item

    def bundle_of(self, client, item):
        import tarfile as tarmod
        self.assertTrue(item["files"]["bundle"], item["files"])
        r = client.get(f"/wi/export/runs/{item['id']}/bundle")
        self.assertEqual(r.status_code, 200, r.data[:300])
        self.assertIn(item["files"]["bundle"]["name"], r.headers["Content-Disposition"])
        data = r.data
        r.close()
        return tarmod.open(fileobj=io.BytesIO(data))

    def test_collect_logs_and_sos_report(self):
        """Log collection: the permission, every log line of the window from each node (secrets masked on the node), one
        bundle to download; sos report one node after the other; the raw output of a run; 7 days, then deleted."""
        import tarfile as tarmod
        import zipfile as zipmod
        from modules.wi import files as files_mod
        l1, admin, collector = self.client("l1", "demo-operator-1"), self.client(), self.client("collector", "demo-operator-6")
        self.assertFalse(l1.get("/wi/api/session").get_json()["can_logs"])
        self.assertTrue(collector.get("/wi/api/session").get_json()["can_logs"])
        cat = {c["id"]: c for c in l1.get("/wi/api/catalog?site=DCA").get_json()["checks"]}
        self.assertFalse(cat["collect-logs"]["access"]["runnable"])
        self.assertIn("collect logs", " ".join(cat["collect-logs"]["access"]["missing"]))
        self.assertEqual(l1.post("/wi/api/runs", json={"site": "DCA", "check": "collect-logs", "params": {}}).status_code, 403)
        self.assertTrue({c["id"]: c for c in collector.get("/wi/api/catalog?site=DCA").get_json()["checks"]}["sos-report"]["access"]["runnable"])

        # every node; overcloud-novacompute-3 does not answer SSH: the others are still collected
        item = self.start_and_wait(collector, "collect-logs", {"scope": "all", "hours": "1"})
        self.assertEqual(item["status"], "warn", item.get("error"))
        st = self.steps(item)
        self.assertEqual((st["nodes"], st["room"], st["collected"], st["files"]), ("warn", "ok", "ok", "info"), st)
        steps = {s["key"]: s for s in item["result"]["steps"]}
        self.assertEqual(sorted(r[0] for r in steps["collected"]["table"]["rows"]),
                         ["overcloud-controller-0", "overcloud-controller-1", "overcloud-controller-2", "overcloud-novacompute-7",
                          "overcloud-novacompute-9"])
        self.assertIn("Log bundle: 5 of 6 node(s)", item["result"]["summary"])
        tar = self.bundle_of(collector, item)
        names = tar.getnames()
        self.assertIn("MANIFEST.json", names)
        self.assertIn("overcloud-controller-0/overcloud-controller-0.logs.tar.gz", names)
        manifest = json.loads(tar.extractfile("MANIFEST.json").read())
        self.assertEqual(manifest["run"], item["id"])
        self.assertEqual(len([n for n in manifest["nodes"] if n["complete"]]), 5)
        inner = tarmod.open(fileobj=tar.extractfile("overcloud-controller-0/overcloud-controller-0.logs.tar.gz"), mode="r:gz")
        api = inner.extractfile("logs/containers/nova/nova-api.log").read().decode()
        self.assertIn("failed 30 minutes ago", api)                   # inside the window of 1 hour
        self.assertNotIn("failed 180 minutes ago", api)               # before it
        self.assertIn("Traceback (most recent call last)", api)       # lines without a timestamp stay with their line
        everything = b"".join(inner.extractfile(m).read() for m in inner.getmembers() if m.isfile()).decode()
        for secret in ("FakeRabbitPass", "FakeSecret1", "gAAAAABfake"):
            self.assertNotIn(secret, everything)
        self.assertIn("MANIFEST.txt", inner.getnames())
        self.assertIn("haproxy/haproxy.log", " ".join(inner.getnames()))   # syslog time format
        compute = tarmod.open(fileobj=tar.extractfile("overcloud-novacompute-7/overcloud-novacompute-7.logs.tar.gz"), mode="r:gz")
        self.assertFalse(any("haproxy" in n for n in compute.getnames()))  # controller-only logs are not read on a compute
        # the end of the window, in site time: 2 hours ending 1 hour ago -> the line of 3 hours ago, not the last one
        until = (datetime.datetime.now() - datetime.timedelta(hours=1)).strftime("%Y-%m-%d %H:%M")
        item = self.start_and_wait(collector, "collect-logs", {"scope": "named", "nodes": "overcloud-controller-1",
                                                               "preset": "controlplane", "hours": "3", "until": until})
        self.assertEqual(item["status"], "ok", item.get("error"))
        inner = tarmod.open(fileobj=self.bundle_of(collector, item).extractfile(
            "overcloud-controller-1/overcloud-controller-1.logs.tar.gz"), mode="r:gz")
        api = inner.extractfile("logs/containers/nova/nova-api.log").read().decode()
        self.assertIn("failed 180 minutes ago", api)
        self.assertNotIn("failed 30 minutes ago", api)
        # too many nodes, an unknown node: refused before anything is read on the nodes
        bad = self.start_and_wait(collector, "sos-report", {"scope": "controllers", "nodes": "overcloud-novacompute-7,overcloud-novacompute-9"})
        self.assertIn("at most 4", bad["result"]["steps"][0]["detail"])
        bad = self.start_and_wait(collector, "collect-logs", {"scope": "named", "nodes": "overcloud-novacompute-99"})
        self.assertEqual(bad["status"], "fail")
        self.assertIsNone(bad["files"]["bundle"])
        self.assertEqual(collector.post("/wi/api/runs", json={"site": "DCA", "check": "collect-logs",
                                                               "params": {"until": "now; rm -rf /"}}).status_code, 400)

        # sos report: one node after the other; overcloud-novacompute-9 has no sos package
        item = self.start_and_wait(collector, "sos-report", {"nodes": "overcloud-controller-0,overcloud-novacompute-9",
                                                             "case_id": "04123456"})
        self.assertEqual(item["status"], "warn", item.get("error"))
        steps = {s["key"]: s for s in item["result"]["steps"]}
        room = {r[0]: r[3] for r in steps["room"]["table"]["rows"]}
        self.assertIn("sos is not installed", room["overcloud-novacompute-9"])
        made = steps["sos"]["table"]["rows"][0]
        self.assertEqual((made[0], made[1]), ("overcloud-controller-0", "made"))
        self.assertRegex(made[2], rf"^sosreport-overcloud-controller-0-run{item['id']}-04123456-.*\.tar\.xz$")
        tar = self.bundle_of(collector, item)
        self.assertTrue(item["files"]["bundle"]["name"].startswith("sos-DCA-run"))
        self.assertIn(f"overcloud-controller-0/{made[2]}", tar.getnames())
        rec = item["result"]["recommendations"][0]
        self.assertTrue(any("generating-an-sos-report" in x["url"] for x in rec["references"]))

        # raw output of a run: each read with its command and full output, the result, the Ansible log
        self.assertEqual(l1.get(f"/wi/export/runs/{item['id']}/raw.zip").status_code, 403)
        self.assertEqual(l1.get(f"/wi/export/runs/{item['id']}/bundle").status_code, 403)
        r = collector.get(f"/wi/export/runs/{item['id']}/raw.zip")
        self.assertEqual(r.status_code, 200)
        z = zipmod.ZipFile(io.BytesIO(r.data))
        self.assertTrue({"README.txt", "result.json", "ansible.log"} <= set(z.namelist()))
        release = z.read("reads/undercloud/uc_release.txt").decode()
        self.assertTrue(release.startswith("$ cat /etc/rhosp-release"), release)
        self.assertIn("reads/collect/sos_0.txt", z.namelist())
        cinder = self.run_check(admin, "cinder-pool-usage", {"threshold": "80"})
        z = zipmod.ZipFile(io.BytesIO(admin.get(f"/wi/export/runs/{cinder['id']}/raw.zip").data))
        pools = [n for n in z.namelist() if n.startswith("reads/openstack/")]
        self.assertTrue(pools, z.namelist())
        self.assertTrue(all(z.read(n).decode().startswith("$ ") for n in pools))
        events = admin.get("/api/admin/events?kinds=wi").get_json()["events"]
        self.assertTrue(any(e["action"] == "wi.download" and "Log bundle" in e["detail"] for e in events))

        # no room on the portal server: refused before anything runs
        saved = files_mod.MIN_FREE_GB
        try:
            files_mod.MIN_FREE_GB = 10 ** 9
            r = collector.post("/wi/api/runs", json={"site": "DCA", "check": "collect-logs", "params": {}})
            self.assertEqual(r.status_code, 400)
            self.assertIn("free", r.get_json()["error"])
        finally:
            files_mod.MIN_FREE_GB = saved
        # kept KEEP_DAYS days, then deleted
        self.assertGreater(files_mod.cleanup(now=time.time() + (files_mod.KEEP_DAYS + 1) * 86400), 0)
        self.assertIsNone(collector.get(f"/wi/api/runs/{item['id']}").get_json()["item"]["files"]["bundle"])
        self.assertEqual(collector.get(f"/wi/export/runs/{item['id']}/bundle").status_code, 404)

    def test_event_log_exports(self):
        """Every entry of the BMC event logs (all pages), the ONTAP EMS events and every vCenter event: a summary on the run
        page, every entry as CSV in the raw output; only with the permission collect logs."""
        import csv as csvmod
        import zipfile as zipmod
        admin, collector, l1 = self.client(), self.client("collector", "demo-operator-6"), self.client("l1", "demo-operator-1")

        def export(item, name):
            z = zipmod.ZipFile(io.BytesIO(collector.get(f"/wi/export/runs/{item['id']}/raw.zip").data))
            return list(csvmod.reader(io.StringIO(z.read(f"export/{name}").decode("utf-8-sig")))), z
        cred = admin.post("/wi/api/bmc/credentials", json={"name": "bmc-export", "username": mock_redfish.USER,
                                                             "secret": mock_redfish.PASSWORD}).get_json()["id"]
        admin.post("/wi/api/bmc/bulk", json={"site": "DCA", "vendor": "inspur", "credential_id": cred,
                                             "lines": f"dca-export-02 127.0.0.1:{INSPUR.port}"})
        self.assertEqual(l1.post("/wi/api/runs", json={"site": "DCA", "check": "bmc-log-export",
                                                        "params": {"bmc": "dca-export-02"}}).status_code, 403)
        # Inspur: the SEL has 250 entries, 100 per page, oldest first: every page is read
        item = self.start_and_wait(collector, "bmc-log-export", {"bmc": "dca-export-02", "days": "3650"})
        self.assertEqual(item["status"], "ok", item.get("error"))
        logs = {s["key"]: s for s in item["result"]["steps"]}["logs"]["table"]["rows"]
        self.assertIn(["System Log", 250, 250], [list(r) for r in logs])   # Systems/1 Log = the Managers SEL, read once
        rows, z = export(item, "bmc-events.csv")
        self.assertEqual(rows[0][:4], ["Created", "Log", "Id", "Severity"])
        self.assertEqual(len([r for r in rows[1:] if r[1] == "System Log"]), 250)
        self.assertEqual(len({r[2] for r in rows[1:] if r[1] == "System Log"}), 250)   # every page once
        self.assertTrue(any(n.startswith("reads/redfish/page_") and n.endswith(".json") for n in z.namelist()))
        self.assertNotIn(mock_redfish.PASSWORD, z.read("ansible.log").decode())

        # ONTAP EMS: the time window in the query, every page through _links.next
        admin.post("/api/admin/credentials/ontap:DCA", json={"username": "admin", "password": mock_ontap.PASSWORD})
        path = wi_analysis.exports.OntapEms.first({"hours": 6, "severity": "error"}, {"now": 1792411200})
        self.assertIn("time=%3E2026-10-19T06%3A00%3A00%2B00%3A00", path)
        self.assertIn("message.severity=emergency|alert|error", path)
        self.assertEqual(wi_analysis.exports.next_path({"_links": {"next": {"href": "/api/support/ems/events?start.index=5&x=a b"}}}),
                         "/api/support/ems/events?start.index=5&x=a%20b")
        item = self.start_and_wait(collector, "ontap-ems-export", {"hours": "24"})
        self.assertEqual(item["status"], "ok", item.get("error"))
        rows, _z = export(item, "ontap-ems.csv")
        self.assertEqual(sorted(r[3] for r in rows[1:]), ["vifmgr.lifs.noredundancy", "vifmgr.portdown"])

        # vCenter: every event (info, user, warning) with the event history collector
        admin.post("/api/admin/credentials/ro-vcenter:DCA", json={"username": mock_vmware.READONLY_USER,
                                                                   "password": mock_vmware.READONLY_PASSWORD})
        self.addCleanup(admin.delete, "/api/admin/credentials/ro-vcenter:DCA")
        item = self.start_and_wait(collector, "vcenter-events-export", {"hours": "48"})
        self.assertEqual(item["status"], "ok", item.get("error"))
        steps = {s["key"]: s for s in item["result"]["steps"]}
        self.assertIn("1201 event(s)", steps["events"]["detail"])
        self.assertEqual(len(steps["newest"]["table"]["rows"]), 200)   # the newest; every event in the CSV
        rows, _z = export(item, "vcenter-events.csv")
        self.assertEqual(len(rows), 1202)
        self.assertEqual({r[1] for r in rows[1:]}, {"info", "user", "warning"})

    def test_vyos_upgrade(self):
        """WI VyOS Upgrade + CVE Mitigation from the portal: the VyOS behind its jump host, the image copied from the jump
        host with scp and its sha256 compared, installed, the dropbear key renewed, rebooted, SSH again, post-check; then
        roll back to the previous image. Only with the host name typed; an image that is not there changes nothing."""
        admin = self.client()
        key = new_key()
        cred = admin.post("/wi/api/credentials", json={"name": "vyos-key", "username": "vyos", "auth": "key", "privilege": "none",
                                                       "fixes": True, "secret": key}).get_json()["id"]
        jump = admin.post("/wi/api/hosts", json={"site": "DCA", "group": "vyos", "name": "dca-vyos-jump", "address": "11.6.215.125",
                                                 "credential_id": cred}).get_json()["id"]
        r = admin.post("/wi/api/hosts", json={"site": "DCA", "group": "vyos", "name": "jkt-vyos-edge-01", "address": "10.246.0.11",
                                              "credential_id": cred, "jump_id": jump})
        self.assertEqual(r.status_code, 200, r.get_json())
        item = self.run_check(admin, "vyos-upgrade", {"host": "jkt-vyos-edge-01"})
        self.assertNotEqual(item["status"], "error", item.get("error"))
        st = self.steps(item)
        self.assertEqual((st["jump"], st["version"], st["hwid"], st["room"]), ("ok", "info", "warn", "ok"))
        steps = {s["key"]: s for s in item["result"]["steps"]}
        self.assertIn("reached through dca-vyos-jump (11.6.215.125)", steps["jump"]["detail"])
        self.assertIn("eth1 52:54:00:bb:00:02", steps["hwid"]["detail"])
        # eth3 is configured but its network card is gone (Tenant-A): its hw-id is skipped, the upgrade is still offered,
        # and removing it is only advised (the whole interface: deleting its address alone fails on VyOS)
        self.assertIn("without a network card (no MAC): eth3: skipped", steps["hwid"]["detail"])
        self.assertIn(["eth3", "-", "-", "11.7.102.60/23 (configured only)", "skipped: no network card"], steps["hwid"]["table"]["rows"])
        # a network card that is not in the configuration (admin down): left as it is, no hw-id added (it would come up)
        self.assertIn(["eth4", "-", "52:54:00:bb:00:05", "-", "not configured: left as it is, its name checked after the reboot"],
                      steps["hwid"]["table"]["rows"])
        clean = next(rc for rc in item["result"]["recommendations"] if rc["text"].startswith("Optional: remove eth3"))
        self.assertIn("delete interfaces ethernet eth3", clean["commands"])
        self.assertIn("1 other line(s) name eth3", clean["warning"])
        self.assertIn("11.7.102.60/23", clean["warning"])
        idx = next(i for i, f in enumerate(item["fixes"]) if f and f["label"] == "Upgrade VyOS")
        fx = item["fixes"][idx]
        self.assertEqual((fx["available"], fx["risk"], fx["kind"]), (True, "high", "vyos_upgrade"))
        self.assertTrue(any("scp /home/vyos/vyos-2026.03-generic-amd64.iso" in c for c in fx["commands"]))
        r = admin.post(f"/wi/api/runs/{item['id']}/fixes/{idx}", json={"confirm": "wrong"})
        self.assertIn("type the host name jkt-vyos-edge-01", r.get_json()["error"])
        r = admin.post(f"/wi/api/runs/{item['id']}/fixes/{idx}", json={"confirm": "jkt-vyos-edge-01"})
        self.assertEqual(r.status_code, 200, r.get_json())
        fix = self.wait_fix(admin, r.get_json()["action_id"])
        out = {o["command"].split(" ")[0]: o for o in fix["output"]}
        self.assertEqual(fix["status"], "ok", (fix.get("error"), [(o["command"], o["rc"], o["out"][-300:]) for o in fix["output"]]))
        for n in ("1.", "2.", "3.", "4.", "5.", "6.", "7.", "8.", "9.", "10.", "11.", "12."):
            self.assertIn(n, out, list(out))
        self.assertIn("hw-id: eth1 52:54:00:bb:00:02", " ".join(o["command"] for o in fix["output"]))
        # the configuration backup is on the jump host only (sha256 compared), none on the VyOS
        backup = "/home/vyos/config-backup/jkt-vyos-edge-01/config.boot.20261021-233000.before-2026.03"
        self.assertIn(f"2. Backup: /config/config.boot → dca-vyos-jump:{backup}", [o["command"] for o in fix["output"]])
        self.assertFalse(any("config.boot.before" in c and "jump host" not in c for c in fx["commands"]), fx["commands"])
        self.assertIn("OK   Version: 2026.03", next(o["out"] for o in fix["output"] if o["command"].startswith("12. Post-check")))
        post = next(o["out"] for o in fix["output"] if o["command"].startswith("12. Post-check"))
        self.assertIn("OK   Interface eth1", post)
        self.assertIn("OK   Interface eth3: no network card, as before", post)
        # both addresses of eth1 are compared; the card outside the configuration keeps its name
        self.assertIn("OK   Interface eth1: MAC 52:54:00:bb:00:02; addresses 11.6.215.130/26, 11.6.215.131/26", post)
        self.assertIn("OK   Interface eth4 (not configured): MAC 52:54:00:bb:00:05", post)
        self.assertNotIn("eth4", next(o["command"] for o in fix["output"] if o["command"].startswith("3.")))
        # pinged: the default gateway and the next-hops of the static routes, no internet address; one that did not answer
        # before the upgrade is not a failure
        self.assertIn("OK   Ping 11.6.215.129: answers", post)
        self.assertIn("OK   Ping 10.246.0.1: no answer, as before the upgrade", post)
        self.assertNotIn("8.8.8.8", " ".join(o["command"] + o["out"] for o in fix["output"]))
        self.assertIn("1. ping 11.6.215.129 10.246.0.1 (before, for the post-check)", [o["command"] for o in fix["output"]])
        self.assertNotIn("eth3 ", next(o["command"] for o in fix["output"] if o["command"].startswith("3.")))
        self.assertIn("skip the hw-id of eth3", " ".join(fx["commands"]))
        # a card that shows up after the upgrade under the name of the skipped interface is reported
        from wi_analysis import vyos_upgrade as vu0
        rows = vu0.post_check({"ifaces": ["eth3"], "macs": {}}, {"ifaces": ["eth3"], "macs": {"eth3": "52:54:00:bb:00:09"}}, {}, "2026.03")
        self.assertFalse(next(x for x in rows if x["check"] == "Interface eth3")["ok"])
        # a next-hop that answered before the upgrade and not after is a failure
        rows = vu0.post_check({}, {}, {"10.249.1.1": False}, "2026.03", "", {"10.249.1.1": True})
        self.assertFalse(next(x for x in rows if x["check"] == "Ping 10.249.1.1")["ok"])
        # the reboot is seen by the boot ID (/proc/uptime changes on every read: a VyOS not rebooted yet looked rebooted)
        self.assertIn("/proc/sys/kernel/random/boot_id", vu0.step_script("alive"))
        again = self.wait_run(admin, fix["verify_run_id"])
        self.assertIn("Already on 2026.03", again["result"]["summary"])
        rb = next(i for i, f in enumerate(again["fixes"]) if f and f["label"] == "Roll back to 1.3.8")
        self.assertTrue(again["fixes"][rb]["available"], again["fixes"][rb])
        r = admin.post(f"/wi/api/runs/{again['id']}/fixes/{rb}", json={"confirm": "jkt-vyos-edge-01"})
        fix = self.wait_fix(admin, r.get_json()["action_id"])
        self.assertEqual(fix["status"], "ok", (fix.get("error"), [(o["command"], o["rc"], o["out"][-300:]) for o in fix["output"]]))
        self.assertIn("OK   Version: 1.3.8", next(o["out"] for o in fix["output"] if o["command"].startswith("12. Post-check")))
        # an image that is not on the jump host: the fix stops at step 4, nothing on the VyOS changed
        item = self.run_check(admin, "vyos-upgrade", {"host": "jkt-vyos-edge-01", "image": "/home/vyos/vyos-2026.09-generic-amd64.iso"})
        idx = next(i for i, f in enumerate(item["fixes"]) if f and f["label"] == "Upgrade VyOS")
        r = admin.post(f"/wi/api/runs/{item['id']}/fixes/{idx}", json={"confirm": "jkt-vyos-edge-01"})
        fix = self.wait_fix(admin, r.get_json()["action_id"])
        self.assertEqual(fix["status"], "failed")
        self.assertIn("Nothing was changed: the image /home/vyos/vyos-2026.09-generic-amd64.iso on dca-vyos-jump cannot be read", fix["error"])
        self.assertFalse(any(o["command"].startswith("8.") for o in fix["output"]))
        # a backup on the jump host that differs from the VyOS (sha256): stopped before the hw-id, nothing changed
        item = self.run_check(admin, "vyos-upgrade", {"host": "jkt-vyos-edge-01", "backup_dir": "/home/vyos/bad-backup"})
        self.assertIn("backed up there, in /home/vyos/bad-backup/jkt-vyos-edge-01/", {x["key"]: x for x in item["result"]["steps"]}["jump"]["detail"])
        idx = next(i for i, f in enumerate(item["fixes"]) if f and f["label"] == "Upgrade VyOS")
        r = admin.post(f"/wi/api/runs/{item['id']}/fixes/{idx}", json={"confirm": "jkt-vyos-edge-01"})
        fix = self.wait_fix(admin, r.get_json()["action_id"])
        self.assertEqual(fix["status"], "failed")
        self.assertIn("Nothing was changed: the configuration of jkt-vyos-edge-01 was not backed up on dca-vyos-jump (sha256 differs", fix["error"])
        self.assertFalse(any(o["command"].startswith(("3.", "4.")) for o in fix["output"]), [o["command"] for o in fix["output"]])
        # stopped after the image was copied (sha256 differs): the copy is removed from /tmp (a RAM disk on VyOS)
        item = self.run_check(admin, "vyos-upgrade", {"host": "jkt-vyos-edge-01", "backup_dir": "/home/vyos/corrupt-copy"})
        idx = next(i for i, f in enumerate(item["fixes"]) if f and f["label"] == "Upgrade VyOS")
        r = admin.post(f"/wi/api/runs/{item['id']}/fixes/{idx}", json={"confirm": "jkt-vyos-edge-01"})
        fix = self.wait_fix(admin, r.get_json()["action_id"])
        self.assertEqual(fix["status"], "failed")
        self.assertIn("differs from the image on the jump host", fix["error"])
        clean = next(o for o in fix["output"] if o["command"].startswith("Stopped: rm /tmp/vyos-2026.03-generic-amd64.iso"))
        self.assertEqual(clean["rc"], 0)
        self.assertFalse(any(o["command"].startswith("8.") for o in fix["output"]))
        # an earlier copy of the same image in /tmp counts as room (the scp replaces it); /tmp is short without it
        st = vu0.parse_state("@@VU@@tmp\nFilesystem 1024-blocks Used Available Capacity Mounted on\ntmpfs 1021200 548868 472332 54% /tmp\n"
                            "@@VU@@isos\n-rw-r--r-- 1 1002 100 561741824 Oct 22 00:11 /tmp/vyos-2026.03-generic-amd64.iso")
        self.assertEqual(st["tmp_isos"], {"vyos-2026.03-generic-amd64.iso": 548576})
        sys.path.insert(0, os.path.join(os.path.dirname(HERE), "modules", "wi", "playbooks", "filter_plugins"))
        from wi_filters import wi_vu_place
        room = ("@@VU@@tmp\nFilesystem 1024-blocks Used Available Capacity Mounted on\ntmpfs 1021200 548868 472332 54% /tmp\n"
                "@@VU@@store\nFilesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 4094636 993056 2896548 26% /p\n"
                "@@VU@@home\n/home/vyos\nFilesystem 1024-blocks Used Available Capacity Mounted on\noverlay 4094636 993056 2896548 26% /\n"
                "@@VU@@isos\n-rw-r--r-- 1 1002 100 561741824 Oct 22 00:11 /tmp/vyos-2026.03-generic-amd64.iso")
        place = wi_vu_place(room, "/home/vyos/vyos-2026.03-generic-amd64.iso", 561741824)
        self.assertEqual((place["dir"], place["store"]), ("/tmp", 2896548))   # 472332 free + 548576 of the earlier copy
        # /tmp of a VM with 1 GB of memory (half of it): the ISO goes to the disk, the home folder
        small = room.replace("tmpfs 1021200 548868 472332 54% /tmp", "tmpfs 505972 4 505968 1% /tmp").split("@@VU@@isos")[0]
        place = wi_vu_place(small, "/home/vyos/vyos-2026.03-generic-amd64.iso", 561741824)
        self.assertEqual(place["dir"], "/home/vyos", place)
        self.assertIn("No resize of the VM needed", place["text"])
        tiny = small.replace("overlay 4094636 993056 2896548 26% /", "overlay 4094636 3000000 1094636 74% /")
        self.assertEqual(wi_vu_place(tiny, "/home/vyos/vyos-2026.03-generic-amd64.iso", 561741824)["dir"], "")
        with self.assertRaises(ValueError):
            vu0.step_script("install", iso="/home/vyos/x.iso", dir="/etc")
        # the home folder of the login user, not "~": with a sudo credential the commands run as root (~ is /root,
        # where the scp of the login user cannot write: VyOS-TenantC)
        self.assertIn("getent passwd vyos", vu0.state_script("vyos"))
        self.assertIn("getent passwd vyos", vu0.step_script("room", iso="/home/vyos/x.iso", user="vyos"))
        self.assertEqual(vu0.home_dir("/root\nFilesystem 1024-blocks Used Available Capacity Mounted on\noverlay 1 1 1 1% /"), "")
        self.assertEqual(vu0.home_dir("/home/vyos\nFilesystem 1024-blocks Used Available Capacity Mounted on"), "/home/vyos")
        # a VyOS with 1 GB of memory: /tmp (RAM, half of it) is too small for the ISO; it goes to the disk (home folder),
        # no resize of the VM needed, and is removed after the install
        r = admin.post("/wi/api/hosts", json={"site": "DCA", "group": "vyos", "name": "jkt-vyos-edge-small", "address": "10.246.0.12",
                                              "credential_id": cred, "jump_id": jump})
        self.assertEqual(r.status_code, 200, r.get_json())
        item = self.run_check(admin, "vyos-upgrade", {"host": "jkt-vyos-edge-small"})
        room = {x["key"]: x for x in item["result"]["steps"]}["room"]
        self.assertEqual(room["status"], "warn", room)
        self.assertIn("the ISO goes to the disk instead, /home/vyos", room["detail"])
        idx = next(i for i, f in enumerate(item["fixes"]) if f and f["label"] == "Upgrade VyOS")
        self.assertTrue(any("scp /home/vyos/vyos-2026.03-generic-amd64.iso → jkt-vyos-edge-small:/home/vyos/" in c for c in item["fixes"][idx]["commands"]))
        r = admin.post(f"/wi/api/runs/{item['id']}/fixes/{idx}", json={"confirm": "jkt-vyos-edge-small"})
        fix = self.wait_fix(admin, r.get_json()["action_id"])
        cmds = [o["command"] for o in fix["output"]]
        self.assertEqual(fix["status"], "ok", (fix.get("error"), [(o["command"], o["rc"], o["out"][-300:]) for o in fix["output"]]))
        self.assertIn("5. The image goes to /home/vyos", cmds)
        self.assertIn("6. scp /home/vyos/vyos-2026.03-generic-amd64.iso → jkt-vyos-edge-small:/home/vyos/vyos-2026.03-generic-amd64.iso", cmds)
        self.assertTrue(any(c.startswith("8. add system image /home/vyos/vyos-2026.03-generic-amd64.iso") for c in cmds), cmds)
        self.assertIn("10. rm /home/vyos/vyos-2026.03-generic-amd64.iso", cmds)
        # a 2 GB disk (image store 936 MB free): the check says to enlarge the disk of the VM (OpenStack / vCenter) first; no
        # "Upgrade VyOS", only "Disk enlarged: ..." once it is: that fix reboots the VyOS to read the new size, grows vda1 and
        # its filesystem inside VyOS, online, then upgrades (VyOS-Tenant-B-POC)
        r = admin.post("/wi/api/hosts", json={"site": "DCA", "group": "vyos", "name": "jkt-vyos-edge-disk", "address": "10.246.0.13",
                                              "credential_id": cred, "jump_id": jump})
        self.assertEqual(r.status_code, 200, r.get_json())
        item = self.run_check(admin, "vyos-upgrade", {"host": "jkt-vyos-edge-disk"})
        room = {x["key"]: x for x in item["result"]["steps"]}["room"]
        self.assertEqual(room["status"], "fail", room)
        self.assertIn("Image store: 936 MB free, 1536 MB needed", room["detail"])
        self.assertIn("enlarge the disk of the VM to at least 3 GB first, on the VM side", room["detail"])
        labels = [f["label"] for f in item["fixes"] if f]
        self.assertNotIn("Upgrade VyOS", labels)
        idx = next(i for i, f in enumerate(item["fixes"]) if f and f["label"] == "Disk enlarged: reboot, grow, upgrade")
        self.assertTrue(item["fixes"][idx]["available"], item["fixes"][idx])
        self.assertTrue(any(c.startswith("reboot, SSH again") for c in item["fixes"][idx]["commands"]), item["fixes"][idx]["commands"])
        r = admin.post(f"/wi/api/runs/{item['id']}/fixes/{idx}", json={"confirm": "jkt-vyos-edge-disk"})
        fix = self.wait_fix(admin, r.get_json()["action_id"])
        cmds = [o["command"] for o in fix["output"]]
        self.assertEqual(fix["status"], "ok", (fix.get("error"), [(o["command"], o["rc"], o["out"][-300:]) for o in fix["output"]]))
        self.assertTrue(any(c.startswith("5. Reboot jkt-vyos-edge-disk (to read the disk enlarged") for c in cmds), cmds)
        self.assertIn("5. SSH again after the reboot (at most 15 minutes)", cmds)
        grow = next(o for o in fix["output"] if o["command"].startswith("5. Grow /dev/vda1 to the whole disk vda (+8192 MB)"))
        self.assertIn("/dev/vda1 : start=2048, size=4192256", grow["out"])   # the table before, kept in the output
        self.assertIn("5. The image goes to /tmp", cmds)
        self.assertTrue(any(c.startswith("11. Reboot jkt-vyos-edge-disk (into 2026.03") for c in cmds), cmds)
        # the disk of the VM already enlarged and seen by the VyOS: "Upgrade VyOS", vda1 grows first, no extra reboot
        r = admin.post("/wi/api/hosts", json={"site": "DCA", "group": "vyos", "name": "jkt-vyos-edge-disk-seen", "address": "10.246.0.14",
                                              "credential_id": cred, "jump_id": jump})
        self.assertEqual(r.status_code, 200, r.get_json())
        item = self.run_check(admin, "vyos-upgrade", {"host": "jkt-vyos-edge-disk-seen"})
        room = {x["key"]: x for x in item["result"]["steps"]}["room"]
        self.assertEqual(room["status"], "warn", room)
        self.assertIn("the upgrade grows vda1 and its filesystem to the whole disk first, online (no reboot for this)", room["detail"])
        idx = next(i for i, f in enumerate(item["fixes"]) if f and f["label"] == "Upgrade VyOS")
        r = admin.post(f"/wi/api/runs/{item['id']}/fixes/{idx}", json={"confirm": "jkt-vyos-edge-disk-seen"})
        fix = self.wait_fix(admin, r.get_json()["action_id"])
        cmds = [o["command"] for o in fix["output"]]
        self.assertEqual(fix["status"], "ok", (fix.get("error"), [(o["command"], o["rc"], o["out"][-300:]) for o in fix["output"]]))
        self.assertFalse(any(c.startswith("5. Reboot") for c in cmds), cmds)
        self.assertTrue(any(c.startswith("5. Grow /dev/vda1") for c in cmds), cmds)
        # show system image of VyOS 2026.x is a table (the default boot read "?": the post-check failed on a good upgrade)
        table = ("Name                       Default boot    Running\n-------------------------  --------------  ---------\n"
                 "2026.03                    Yes             Yes\n1.3-rolling-202202050134")
        self.assertEqual(vu0.parse_images(table), (["2026.03", "1.3-rolling-202202050134"], "2026.03"))
        self.assertEqual(vu0.parse_images("The system currently has the following image(s) installed:\n\n"
                                          "   1: 2026.03 (default boot)\n   2: 1.3-rolling-202202050134"),
                         (["2026.03", "1.3-rolling-202202050134"], "2026.03"))
        # a partition that is not the last one, or not ext4: not grown by the portal
        plan = vu0.grow_plan(vu0.parse_disk("dev /dev/vda1 ext4\ndisk vda 20971520\npart vda1 2048 4192256\npart vda2 4194304 1024\n"
                                            "tool sfdisk\ntool partx\ntool resize2fs"))
        self.assertFalse(plan["can"])
        self.assertIn("vda1 is not the last partition of vda", plan["why"])
        plan = vu0.grow_plan(vu0.parse_disk("dev /dev/vda1 xfs\ndisk vda 20971520\npart vda1 2048 4192256\ntool sfdisk\ntool partx\ntool resize2fs"))
        self.assertIn("not ext4", plan["why"])
        with self.assertRaises(ValueError):
            vu0.step_script("grow", dev="/dev/vda1; reboot", disk="vda", num=1)
        # the commands of the upgrade are built from validated values only
        from wi_analysis import vyos_upgrade as vu
        for bad in ({"hwid": [["eth0; reboot", "52:54:00:aa:00:01"]]}, {"hwid": [["eth0", "x'; reboot"]]}):
            with self.assertRaises(ValueError):
                vu.step_script("hwid", **bad)
        with self.assertRaises(ValueError):
            vu.jump_script("iso", {}, iso="/home/vyos/x.iso; rm -rf /")
        self.assertEqual(vu.target_version("/home/vyos/vyos-2026.03-generic-amd64.iso"), "2026.03")
        # op-mode commands go to the program behind `run`: "source script-template; run ..." on one line is refused by
        # VyOS ("Invalid command: [run]", run is an alias used only from the next line on)
        import wi_analysis as wa
        reads = [c for chk in ("vyos-upgrade", "vyos-upgrade-precheck", "vyos-nat-firewall", "vyos-static-route")
                 for src in wa.reads(chk, 1, {}, {"host": "x", "port": 514, "gateway": "10.253.0.1"}, {}).values() for c in src.values()]
        self.assertTrue(reads and not any("; run " in c for c in reads), reads)
        self.assertTrue(any("/opt/vyatta/bin/vyatta-op-cmd-wrapper show version" in c for c in reads))

    def test_running_fixes_are_listed(self):
        """A fix keeps running on the portal server when its page is closed: every page lists it with its progress and
        the run it was started from, and the Runs list shows the fixes of each run (filter Fix running)."""
        import json as jsonmod
        from modules.wi import files as files_mod, hosts as hosts_mod
        c = self.client()
        item = self.run_check(c, "cdn-memory", {"host": "dca-cdn-lb-01"})
        aid = hosts_mod.action_begin(item["id"], 0, "Live-migrate selected: 3 instances", "normal", "compute-07", ["x"], "portaladmin", "")
        try:
            with open(files_mod.progress_path(aid), "w") as f:
                jsonmod.dump({"of": 3, "current": {"n": 2, "label": "db-01 -> compute-09"},
                              "done": [{"n": 1, "status": "ok", "label": "web-01 -> compute-09", "summary": "on compute-09"}]}, f)
            running = c.get("/wi/api/fixes/running").get_json()["items"]
            mine = next(a for a in running if a["id"] == aid)
            self.assertEqual((mine["run_id"], mine["site"], mine["target"], mine["check_id"]), (item["id"], "DCA", "compute-07", "cdn-memory"))
            self.assertEqual((len(mine["progress"]["done"]), mine["progress"]["current"]["n"]), (1, 2))
            rows = {r["id"]: r for r in c.get("/wi/api/runs?status=fix-running").get_json()["items"]}
            self.assertEqual(list(rows), [item["id"]])
            self.assertEqual(rows[item["id"]]["fixes"], [{"id": aid, "status": "running", "title": "Live-migrate selected: 3 instances"}])
            self.assertEqual(self.client("l1", "demo-operator-1").get("/wi/api/fixes/running").status_code, 200)
        finally:
            hosts_mod.action_finish(aid, "ok", [], "")
            if os.path.exists(files_mod.progress_path(aid)):
                os.remove(files_mod.progress_path(aid))
        self.assertFalse(any(a["id"] == aid for a in c.get("/wi/api/fixes/running").get_json()["items"]))
        self.assertEqual(c.get("/wi/api/runs?status=fix-running").get_json()["items"], [])

    def test_runs_list_and_export(self):
        c = self.client()
        self.run_check(c, "cdn-memory", {"host": "dca-cdn-lb-01"})
        data = c.get("/wi/api/runs?site=DCA").get_json()
        self.assertGreaterEqual(data["total"], 1)
        csv = c.get("/wi/export/runs.csv").data.decode()
        self.assertIn("Alert: memory", csv)


if __name__ == "__main__":
    unittest.main()

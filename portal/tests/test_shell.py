"""Shell module tests: who may open a shell, the host list (without secrets), a session end to end on a pseudo-terminal
(with tests/fake_shell.py instead of ssh), sudo -i answered by the portal, failures, other users' sessions, limits,
idle sessions, history and recordings, snippets, and the ssh command lines the portal builds for every kind of host.

Run from the portal folder:
    .venv/bin/python -m unittest tests.test_shell -v
"""
import base64
import os
import shutil
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

TMP = tempfile.mkdtemp()
PY = sys.executable
FAKE = f'{PY} {os.path.join(HERE, "fake_shell.py")} "{{name}}" --user {{user}} --kind {{kind}} --sudo-password s3cret-sudo'
with open(os.path.join(TMP, "sites.yml"), "w") as f:
    f.write(f"""sites:
  DCB:
    mgmt: {{host: 10.253.198.11, user: admin, private_key: /etc/ops-portal/keys/openstack_mgmt}}
    director: {{host: 10.253.198.101, user: stack}}
    ontap: {{host: "127.0.0.1:9451"}}
    apic: {{host: "10.253.130.250"}}
    shell: {{test_command: '{FAKE}'}}
    hosts:
      cdn: {{user: runbook-ro, private_key: /etc/ops-portal/keys/wi_ro, members: {{dcb-cdn-01: 172.31.138.67, edge-unreachable: 172.31.138.99}}}}
      esxi: {{user: runbook-ro, private_key: /etc/ops-portal/keys/wi_ro, members: {{esxi-dcb-07: 172.25.74.7}}}}
  DCA:
    mgmt: {{host: 10.253.179.11, user: admin, port: 2222, private_key: /etc/ops-portal/keys/openstack_mgmt}}
    director: {{host: 10.253.179.101, user: stack}}
    ontap: {{host: 10.253.155.30}}
    apic: {{host: "10.253.155.251:443"}}
    hosts:
      dns: {{user: runbook-ro, private_key: /etc/ops-portal/keys/wi_ro, members: {{dns-01: 10.253.137.53}}}}
""")
with open(os.path.join(TMP, "auth.yml"), "w") as f:
    f.write("admins: []\n")
os.environ.update(OPS_SITES=os.path.join(TMP, "sites.yml"), OPS_DATA=os.path.join(TMP, "data"),
                  OPS_DB=os.path.join(TMP, "data", "portal.db"), OPS_AUTH=os.path.join(TMP, "auth.yml"),
                  OPS_CREDENTIALS_KEY=os.path.join(TMP, "credentials.key"), OPS_MODULES="wi,shell")
KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA-test-key-not-real\n-----END OPENSSH PRIVATE KEY-----\n"


def new_key():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    return ed25519.Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                                              serialization.NoEncryption()).decode()


class ShellTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import portal_auth
        store = portal_auth.Store(os.environ["OPS_DB"])
        store.add_local_user("portaladmin", portal_auth.hash_password("demo-portal-admin"), "admin", "Admin", "", "test")
        store.add_local_user("sheller", portal_auth.hash_password("demo-shell-1"), "operator", "Sheller", "", "test", "shell")
        store.add_local_user("sheller2", portal_auth.hash_password("demo-shell-2"), "operator", "Sheller 2", "", "test", "wi,shell")
        store.add_local_user("allmods", portal_auth.hash_password("demo-all-1"), "operator", "All", "", "test", "*")
        store.add_local_user("limited", portal_auth.hash_password("demo-limited-1"), "operator", "Limited", "", "test", "shell")
        import app as webapp
        from core import PORTAL
        from modules import shell
        from modules.shell import sessions, targets
        from modules.wi import hosts
        cls.app, cls.PORTAL, cls.shell, cls.sessions, cls.targets, cls.hosts = webapp.app, PORTAL, shell, sessions, targets, hosts
        shell.access.set_rules("sheller", ["*"], "test")    # operators open only the hosts given on Access
        shell.access.set_rules("sheller2", ["*"], "test")
        vault = PORTAL.vault
        PORTAL.store.set_credential("ontap:DCB", "admin", vault.encrypt("ontap-secret-pw"), "test")
        PORTAL.store.set_credential("ontap:DCA", "admin", vault.encrypt("ontap-secret-pw2"), "test")
        PORTAL.store.set_credential("apic:DCA", "apic:TACACS\\ops", vault.encrypt("apic-secret-pw"), "test")
        cls.cred_sudo = hosts.save_credential(vault, "test", {"name": "linux-sudo", "username": "ops", "auth": "password",
                                                              "privilege": "sudo_password", "secret": "s3cret-sudo", "fixes": True})
        cls.cred_ro = hosts.save_credential(vault, "test", {"name": "linux-ro", "username": "viewer", "auth": "password",
                                                            "privilege": "sudo_password", "secret": "viewer-pw", "fixes": False})
        cls.cred_key = hosts.save_credential(vault, "test", {"name": "vyos-key", "username": "vyos", "auth": "key",
                                                             "privilege": "root", "secret": new_key(), "fixes": True})
        cls.cred_jump = hosts.save_credential(vault, "test", {"name": "jump-pw", "username": "jumper", "auth": "password",
                                                              "privilege": "none", "secret": "jump-secret-pw"})
        cls.h_sudo = hosts.save_host("test", {"site": "DCB", "group": "linux", "name": "app-vm-01", "address": "10.249.129.20",
                                              "credential_id": cls.cred_sudo})
        cls.h_ro = hosts.save_host("test", {"site": "DCB", "group": "linux", "name": "app-vm-02", "address": "10.249.129.21",
                                            "credential_id": cls.cred_ro})
        cls.h_none = hosts.save_host("test", {"site": "DCB", "group": "dns", "name": "dns-nocred", "address": "10.249.129.53"})
        cls.h_esxi = hosts.save_host("test", {"site": "DCB", "group": "esxi", "name": "esxi-dcb-08", "address": "172.25.74.8",
                                              "credential_id": cls.cred_sudo})
        cls.h_jump = hosts.save_host("test", {"site": "DCA", "group": "linux", "name": "jump-01", "address": "10.248.0.5",
                                              "credential_id": cls.cred_jump})
        cls.h_vyos = hosts.save_host("test", {"site": "DCA", "group": "vyos", "name": "natgw-01", "address": "192.168.251.1",
                                              "port": 2022, "credential_id": cls.cred_key, "jump_id": cls.h_jump})

    @classmethod
    def tearDownClass(cls):
        cls.shell.MANAGER.stop_all()
        time.sleep(0.5)
        shutil.rmtree(TMP, ignore_errors=True)

    def tearDown(self):
        self.shell.MANAGER.stop_all("test ended")
        deadline = time.time() + 10
        while self.shell.MANAGER.live() and time.time() < deadline:
            time.sleep(0.05)

    # ---- helpers ----
    def client(self, user="portaladmin", password="demo-portal-admin"):
        c = self.app.test_client()
        r = c.post("/api/login", json={"username": user, "password": password})
        self.assertEqual(r.status_code, 200, r.get_json())
        return c

    def open(self, c, target, cols=100, rows=40):
        r = c.post("/terminal/api/sessions", json={"target": target, "cols": cols, "rows": rows})
        data = r.get_json()
        self.assertEqual(r.status_code, 200, data)
        return data["session"]

    def read_until(self, c, sid, text, state=None, timeout=10):
        """Output of a session until it contains text (and the session reached state); returns (output, last chunk)."""
        out, offset, chunk = b"", 0, {}
        if not hasattr(self, "_offsets"):
            self._offsets = {}
        offset, out = self._offsets.get(sid, (0, b""))
        deadline = time.time() + timeout
        while time.time() < deadline:
            data = c.get(f"/terminal/api/poll?c={sid}:{offset}&wait=1").get_json()
            chunk = data["sessions"].get(sid) or {}
            if chunk.get("data"):
                out += base64.b64decode(chunk["data"])
            offset = chunk.get("offset", offset)
            self._offsets[sid] = (offset, out)
            if text.encode() in out and (state is None or chunk.get("state") == state):
                return out.decode("utf-8", "replace"), chunk
        self.fail(f"{text!r} (state {state}) not seen in {out[-800:]!r} / {chunk}")

    def type(self, c, sid, text):
        r = c.post(f"/terminal/api/sessions/{sid}/input", json={"data": text})
        self.assertEqual(r.status_code, 200, r.get_json())

    # ---- access ----
    def test_shell_must_be_ticked_and_is_never_part_of_all_modules(self):
        for user, pw in (("allmods", "demo-all-1"),):
            c = self.client(user, pw)
            self.assertEqual(c.get("/terminal/api/targets").status_code, 403)
            self.assertFalse(c.get("/terminal/api/session").get_json()["allowed"])
            self.assertEqual(c.post("/terminal/api/sessions", json={"target": "DCB:mgmt"}).status_code, 403)
            home = c.get("/api/session").get_json()
            self.assertIn("wi", home["user"]["modules"])
            self.assertNotIn("shell", home["user"]["modules"])
            tile = next(m for m in home["modules"] if m["id"] == "shell")
            self.assertFalse(tile["allowed"])
        self.assertTrue(self.client("sheller", "demo-shell-1").get("/terminal/api/session").get_json()["allowed"])
        self.assertTrue(self.client().get("/terminal/api/session").get_json()["allowed"])
        self.assertEqual(self.app.test_client().get("/terminal/api/targets").status_code, 401)
        users = self.client().get("/api/admin/users").get_json()
        self.assertTrue(next(m for m in users["modules"] if m["id"] == "shell").get("explicit"))

    def test_host_list_has_every_kind_and_no_secret(self):
        c = self.client("sheller", "demo-shell-1")
        r = c.get("/terminal/api/targets")
        text = r.get_data(as_text=True)
        items = {t["id"]: t for t in r.get_json()["targets"]}
        for tid in ("DCB:mgmt", "DCB:director", "DCB:ontap", "DCB:group:cdn:dcb-cdn-01", f"DCB:host:{self.h_sudo}",
                    "DCA:mgmt", "DCA:director", "DCA:ontap", "DCA:apic", "DCA:group:dns:dns-01", f"DCA:host:{self.h_vyos}"):
            self.assertIn(tid, items)
        self.assertEqual(items["DCB:director"]["via"], "Management host 10.253.198.11")
        self.assertEqual(items["DCA:apic"]["user"], "apic#TACACS\\ops")
        self.assertEqual(items["DCA:apic"]["address"], "10.253.155.251")
        self.assertIn("not set", items["DCB:apic"]["problem"])               # no apic:DCB account
        self.assertIn("No SSH credential", items[f"DCB:host:{self.h_none}"]["problem"])
        self.assertEqual(items[f"DCA:host:{self.h_vyos}"]["via"], "Jump host jump-01")
        self.assertTrue(items[f"DCB:host:{self.h_sudo}"]["become"])
        self.assertFalse(items[f"DCB:host:{self.h_ro}"]["become"])           # sudo password, but no fixes with it
        for secret in ("ontap-secret-pw", "apic-secret-pw", "s3cret-sudo", "viewer-pw", "jump-secret-pw", "PRIVATE KEY", "/etc/acme-cloud"):
            self.assertNotIn(secret, text)
        bad = c.post("/terminal/api/sessions", json={"target": "DCB:host:999"})
        self.assertEqual(bad.status_code, 400)
        self.assertEqual(c.post("/terminal/api/sessions", json={"target": "DCB; rm -rf /"}).status_code, 400)
        self.assertEqual(c.post("/terminal/api/sessions", json={"target": f"DCB:host:{self.h_none}"}).status_code, 400)
        # ESXi (VMware Cloud) stays read-only from the portal: neither listed nor opened
        self.assertFalse([t for t in items.values() if t["category"] == "esxi"])
        for tid in (f"DCB:host:{self.h_esxi}", "DCB:group:esxi:esxi-dcb-07"):
            r = c.post("/terminal/api/sessions", json={"target": tid})
            self.assertEqual(r.status_code, 400)
            self.assertIn("Unknown host", r.get_json()["error"])

    # ---- a session end to end ----
    def test_session_types_resizes_records_and_ends(self):
        c = self.client("sheller", "demo-shell-1")
        s = self.open(c, "DCB:mgmt", cols=100, rows=40)
        self.assertEqual(s["state"], "open")
        self.read_until(c, s["id"], "[admin@Management host ~]$")
        self.type(c, s["id"], "hostname\r")
        self.read_until(c, s["id"], "\r\nManagement host\r\n")
        self.type(c, s["id"], "size\r")
        self.read_until(c, s["id"], "rows=40 cols=100")
        self.assertEqual(c.post(f"/terminal/api/sessions/{s['id']}/resize", json={"cols": 132, "rows": 50}).status_code, 200)
        self.type(c, s["id"], "size\r")
        self.read_until(c, s["id"], "rows=50 cols=132")
        listed = c.get("/terminal/api/sessions").get_json()["sessions"]
        self.assertEqual([x["id"] for x in listed], [s["id"]])
        self.type(c, s["id"], "lines 3000\r")
        self.read_until(c, s["id"], "line 3000\r\n")
        # a reloaded page asks from -1: what is still buffered
        again = c.get(f"/terminal/api/poll?c={s['id']}:-1&wait=0").get_json()["sessions"][s["id"]]
        self.assertIn(b"line 3000", base64.b64decode(again["data"]))
        self.type(c, s["id"], "exit\r")
        out, chunk = self.read_until(c, s["id"], "logout", state="closed")
        self.assertEqual(chunk["exit_code"], 0)
        row = self.sessions.history_row(s["id"])
        self.assertEqual((row["status"], row["username"], row["account"]), ("closed", "sheller", "admin"))
        self.assertIn("Management host", row["label"])
        with open(self.sessions.recording_path(row), "rb") as f:
            recorded = f.read()
        self.assertIn(b"rows=50 cols=132", recorded)
        self.assertEqual([x["id"] for x in c.get("/terminal/api/history").get_json()["items"]][:1], [s["id"]])   # own ones
        text = c.get(f"/terminal/export/history/{s['id']}.txt")
        self.assertEqual(text.status_code, 200)
        body = text.get_data(as_text=True)
        self.assertIn("[admin@Management host ~]$ hostname\nManagement host", body)
        self.assertNotIn("\x1b", body)
        actions = [e["action"] for e in self._events()]
        self.assertIn("shell.open", actions)
        self.assertIn("shell.close", actions)
        self.assertEqual(c.post(f"/terminal/api/sessions/{s['id']}/input", json={"data": "x"}).status_code, 400)

    def _events(self):
        with self.PORTAL.store.db() as db:
            return [dict(r) for r in db.execute("SELECT * FROM portal_events ORDER BY id")]

    def test_duo_step_up_before_a_terminal_a_join_and_root(self):
        import portal_auth
        c = self.client("sheller", "demo-shell-1")
        needed = portal_auth.StepUpRequired("Opening a terminal needs a new Duo confirmation (Duo SSO sign-in), valid 4 hours.",
                                            "/auth/sso/step-up")
        with mock.patch.object(self.PORTAL, "step_up", side_effect=needed):
            r = c.post("/terminal/api/sessions", json={"target": f"DCB:host:{self.h_sudo}", "cols": 80, "rows": 24})
            self.assertEqual((r.status_code, r.get_json()["step_up"]), (403, "/auth/sso/step-up"))
            self.assertEqual(self.shell.MANAGER.live("sheller"), [])   # nothing was opened
        with mock.patch.object(self.PORTAL, "step_up", return_value="Duo step-up 10:00") as step_up:
            s = self.open(c, f"DCB:host:{self.h_sudo}")
            self.read_until(c, s["id"], "[ops@app-vm-01 ~]$")
            self.assertEqual(c.post(f"/terminal/api/sessions/{s['id']}/root", json={}).status_code, 200)
            admin = self.client()
            self.assertEqual(admin.post(f"/terminal/api/sessions/{s['id']}/watch", json={"mode": "watch"}).status_code, 200)
            self.assertEqual(admin.post(f"/terminal/api/sessions/{s['id']}/watch", json={"mode": "join"}).status_code, 200)
            self.assertEqual([call.args[1] for call in step_up.call_args_list], ["Opening a terminal", "Become root", "Joining a session"])
        details = {e["action"]: e["detail"] for e in self._events() if e["detail"] and f"Session {s['id']}" in e["detail"]}
        for action in ("shell.open", "shell.root", "shell.join"):
            self.assertIn("· Duo step-up 10:00", details[action])
        # Local accounts (these test accounts) are exempt; the activity log says so.
        with mock.patch.object(self.PORTAL, "step_up_minutes", return_value=240):
            s2 = self.open(c, f"DCB:host:{self.h_ro}")
        detail = [e["detail"] for e in self._events() if e["action"] == "shell.open" and f"Session {s2['id']}" in e["detail"]][0]
        self.assertIn("no Duo step-up (local account)", detail)

    def test_become_root_answers_the_sudo_prompt_without_showing_the_password(self):
        c = self.client("sheller", "demo-shell-1")
        s = self.open(c, f"DCB:host:{self.h_sudo}")
        self.assertTrue(s["become"])
        self.read_until(c, s["id"], "[ops@app-vm-01 ~]$")
        self.assertEqual(c.post(f"/terminal/api/sessions/{s['id']}/root", json={}).status_code, 200)
        out, _ = self.read_until(c, s["id"], "[root@app-vm-01 ~]#")
        self.assertIn("[sudo] password for ops:", out)
        self.assertNotIn("s3cret-sudo", out)
        self.type(c, s["id"], "whoami\r")
        self.read_until(c, s["id"], "\r\nroot\r\n")
        c.delete(f"/terminal/api/sessions/{s['id']}")
        self.read_until(c, s["id"], "", state="closed")
        row = self.sessions.history_row(s["id"])
        self.assertEqual(row["root"], 1)
        with open(self.sessions.recording_path(row), "rb") as f:
            self.assertNotIn(b"s3cret-sudo", f.read())
        self.assertIn("shell.root", [e["action"] for e in self._events()])
        # a credential that may not run fixes: no sudo password from the portal
        ro = self.open(c, f"DCB:host:{self.h_ro}")
        self.assertFalse(ro["become"])
        self.assertEqual(c.post(f"/terminal/api/sessions/{ro['id']}/root", json={}).status_code, 400)

    def test_a_failed_connection_is_reported(self):
        c = self.client("sheller", "demo-shell-1")
        s = self.open(c, "DCB:group:cdn:edge-unreachable")
        _, chunk = self.read_until(c, s["id"], "Connection refused", state="closed")
        self.assertEqual(chunk["exit_code"], 255)
        self.assertIn("SSH failed: ssh: connect to host edge-unreachable port 22: Connection refused", chunk["reason"])
        self.assertEqual(self.sessions.history_row(s["id"])["status"], "failed")
        self.assertIn("shell.failed", [e["action"] for e in self._events()])

    def test_sessions_of_someone_else(self):
        mine = self.client("sheller", "demo-shell-1")
        other = self.client("sheller2", "demo-shell-2")
        admin = self.client()
        s = self.open(mine, "DCB:group:cdn:dcb-cdn-01")
        self.read_until(mine, s["id"], "$ ")
        self.assertEqual(other.post(f"/terminal/api/sessions/{s['id']}/input", json={"data": "id\r"}).status_code, 400)
        self.assertEqual(other.delete(f"/terminal/api/sessions/{s['id']}").status_code, 400)
        self.assertEqual(other.get(f"/terminal/api/poll?c={s['id']}:0&wait=0").get_json()["sessions"], {})
        self.assertEqual(other.get(f"/terminal/api/history/{s['id']}/recording").status_code, 400)   # not someone else's
        self.assertEqual(other.get(f"/terminal/export/history/{s['id']}.txt").status_code, 404)
        self.assertNotIn(s["id"], [x["id"] for x in other.get("/terminal/api/history").get_json()["items"]])
        self.assertTrue({x["username"] for x in other.get("/terminal/api/history").get_json()["items"]} <= {"sheller2"})
        self.assertIn(s["id"], [x["id"] for x in admin.get("/terminal/api/history").get_json()["items"]])
        self.assertIn(s["id"], [x["id"] for x in admin.get("/terminal/api/sessions?all=1").get_json()["sessions"]])
        self.assertEqual(admin.delete(f"/terminal/api/sessions/{s['id']}").status_code, 200)
        _, chunk = self.read_until(mine, s["id"], "", state="closed")
        self.assertIn("Ended by the administrator portaladmin", chunk["reason"])
        self.assertIn("shell.terminate", [e["action"] for e in self._events()])
        rec = admin.get(f"/terminal/api/history/{s['id']}/recording").get_json()
        self.assertIn(b"dcb-cdn-01", base64.b64decode(rec["data"]))
        self.assertIn("shell.recording", [e["action"] for e in self._events()])

    def test_limits_and_idle_sessions(self):
        c = self.client("sheller", "demo-shell-1")
        old = self.sessions.MAX_PER_USER
        self.sessions.MAX_PER_USER = 2
        try:
            a = self.open(c, "DCB:mgmt")
            self.open(c, "DCB:director")
            r = c.post("/terminal/api/sessions", json={"target": "DCB:mgmt"})
            self.assertEqual(r.status_code, 400)
            self.assertIn("2 sessions open", r.get_json()["error"])
        finally:
            self.sessions.MAX_PER_USER = old
        session = self.shell.MANAGER.get(a["id"])
        session.last_io = time.time() - self.sessions.IDLE - 5
        self.shell.MANAGER.reap()
        _, chunk = self.read_until(c, a["id"], "", state="closed")
        self.assertIn("Nothing was typed or shown", chunk["reason"])

    def test_snippets(self):
        op = self.client("sheller", "demo-shell-1")
        op2 = self.client("sheller2", "demo-shell-2")
        admin = self.client()
        self.assertEqual(op.post("/terminal/api/snippets", json={"name": "pcs", "command": "sudo pcs status", "shared": True}).status_code, 400)
        mine = op.post("/terminal/api/snippets", json={"name": "pcs", "command": "sudo pcs status"}).get_json()["id"]
        shared = admin.post("/terminal/api/snippets", json={"name": "Galera", "command": "clustercheck", "shared": True}).get_json()["id"]
        names = {s["name"] for s in op2.get("/terminal/api/snippets").get_json()["snippets"]}
        self.assertEqual(names, {"Galera"})
        self.assertEqual(op2.delete(f"/terminal/api/snippets/{mine}").status_code, 400)
        self.assertEqual(op.put(f"/terminal/api/snippets/{shared}", json={"name": "x", "command": "y"}).status_code, 400)
        self.assertEqual(op.put(f"/terminal/api/snippets/{mine}", json={"name": "pcs status", "command": "pcs status --full"}).status_code, 200)
        self.assertEqual({s["name"] for s in op.get("/terminal/api/snippets").get_json()["snippets"]}, {"pcs status", "Galera"})
        self.assertEqual(op.delete(f"/terminal/api/snippets/{mine}").status_code, 200)

    # ---- how the portal reaches each kind of host ----
    def test_ssh_command_lines(self):
        t = self.targets
        work = tempfile.mkdtemp(dir=TMP)
        mgmt = t.connection(t.find("DCA:mgmt"), work)
        self.assertEqual(mgmt["argv"][:4], ["ssh", "-tt", "-p", "2222"])
        self.assertIn("/etc/ops-portal/keys/openstack_mgmt", mgmt["argv"])
        self.assertEqual(mgmt["argv"][-1], "admin@10.253.179.11")
        director = t.connection(t.find("DCA:director"), work)["argv"]
        self.assertEqual(director[director.index("--"):], ["--", "ssh", "-t", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
                                                           "-o", "ServerAliveInterval=30", "-p", "22", "stack@10.253.179.101"])
        ontap = t.connection(t.find("DCA:ontap"), work)
        self.assertEqual(ontap["argv"][:3], ["sshpass", "-d", t.PASS_FD])
        self.assertEqual(ontap["password"], "ontap-secret-pw2")
        self.assertNotIn("ontap-secret-pw2", " ".join(ontap["argv"]))
        self.assertEqual(ontap["argv"][-1], "admin@10.253.155.30")
        apic = t.connection(t.find("DCA:apic"), work)
        self.assertEqual(apic["argv"][-1], "apic#TACACS\\ops@10.253.155.251")
        self.assertIn("HostKeyAlgorithms=+ssh-rsa", apic["argv"])        # APIC offers only an ssh-rsa host key
        self.assertNotIn("HostKeyAlgorithms=+ssh-rsa", ontap["argv"])
        dns = t.connection(t.find("DCA:group:dns:dns-01"), work)["argv"]
        self.assertIn("/etc/ops-portal/keys/wi_ro", dns)
        self.assertEqual(dns[-1], "runbook-ro@10.253.137.53")
        vyos = t.connection(t.find(f"DCA:host:{self.h_vyos}"), work)
        argv = vyos["argv"]
        key = argv[argv.index("-i") + 1]
        self.assertTrue(key.startswith(work))
        self.assertEqual(stat.S_IMODE(os.stat(key).st_mode), 0o600)
        self.assertEqual(argv[:4], ["ssh", "-tt", "-p", "2022"])
        proxy = next(a for a in argv if a.startswith("ProxyCommand="))
        self.assertIn("sshpass -e ssh", proxy)
        self.assertIn("-W %h:%p jumper@10.248.0.5", proxy)
        self.assertEqual(vyos["env"], {"SSHPASS": "jump-secret-pw"})
        self.assertNotIn("jump-secret-pw", " ".join(argv))
        self.assertEqual(argv[-1], "vyos@192.168.251.1")
        self.assertIsNone(vyos["password"])
        with self.assertRaises(ValueError):
            t.connection(t.find("DCA:host:999"), work)

    def test_password_reaches_sshpass_through_a_pipe(self):
        """The real spawn path: {pass_fd} becomes the read end of a pipe holding the password (sshpass -d reads it)."""
        fake = os.path.join(TMP, "fake_sshpass.py")
        with open(fake, "w") as f:
            f.write("import os, sys\nfd = int(sys.argv[1])\nos.write(1, b'got:' + os.read(fd, 100).strip() + b'\\r\\n')\n")
        m = self.sessions.Manager()
        work = tempfile.mkdtemp(dir=TMP)
        target = self.targets.find("DCB:mgmt")
        s = m.open("tester", target, {"argv": [PY, fake, self.targets.PASS_FD], "env": {}, "password": "pipe-pw", "folder": work},
                   "127.0.0.1")
        deadline = time.time() + 10
        while s.state != "closed" and time.time() < deadline:
            time.sleep(0.05)
        self.assertIn(b"got:pipe-pw", bytes(s.buf))
        self.assertFalse(os.path.exists(work))   # the session folder (key files) is removed at the end

    def test_a_real_shell_echoes_and_edits_lines(self):
        """The terminal of a session starts in its normal mode, as ssh expects: ssh passes its modes to the host. When it
        started raw, the host's bash showed nothing typed and Ctrl+R (reverse-i-search), arrows and Tab did not work.
        Checked with a real bash on the session terminal, directly and under sshpass (password sessions)."""
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("bash is needed")
        runs = [("ssh", [bash, "--noprofile", "--norc", "-i"], None)]
        if shutil.which("sshpass"):
            runs.append(("sshpass", ["sshpass", "-d", self.targets.PASS_FD, bash, "--noprofile", "--norc", "-i"], "unused-pw"))
        for label, argv, password in runs:
            with self.subTest(label):
                m = self.sessions.Manager()
                s = m.open("tester", self.targets.find("DCB:mgmt"), {"argv": argv, "password": password,
                           "env": {"HISTFILE": "/dev/null", "BASH_SILENCE_DEPRECATION_WARNING": "1"},
                           "folder": tempfile.mkdtemp(dir=TMP)}, "127.0.0.1")

                def seen(text, timeout=8):
                    deadline = time.time() + timeout
                    while time.time() < deadline:
                        if text.encode() in bytes(s.buf):
                            return True
                        time.sleep(0.05)
                    self.fail(f"{label}: {text!r} not in {bytes(s.buf)[-400:]!r}")

                seen("$ ")
                m.write(s, "echo history-word-42\r")
                seen("echo history-word-42\r\n")          # the command line is shown as it is typed (echo)
                seen("history-word-42\r\n", 2)
                m.write(s, "\x12history-wo")
                seen("reverse-i-search")                    # Ctrl+R reaches bash's line editor
                # Ctrl+C on its own: Linux bash drops what came in with it, so exit is typed at the next prompt (under
                # sshpass on macOS, Ctrl+C itself ends the session)
                prompts = bytes(s.buf).count(b"$ ")
                m.write(s, "\x03")
                deadline = time.time() + 8
                while bytes(s.buf).count(b"$ ") <= prompts and s.state != "closed" and time.time() < deadline:
                    time.sleep(0.05)
                try:
                    m.write(s, "exit\r")
                except ValueError:   # the session has ended already
                    pass
                deadline = time.time() + 8
                while s.state != "closed" and time.time() < deadline:
                    time.sleep(0.05)
                self.assertEqual(s.state, "closed")

    def test_streaming_output_is_batched_but_keys_answer_at_once(self):
        """A page asks a few times a second while output streams by itself (tail -f), not once per line; the echo of a
        key comes back at once."""
        stream = os.path.join(TMP, "stream.py")
        with open(stream, "w") as f:
            f.write("import sys, time, tty\nimport os\ntty.setraw(0)\ntime.sleep(1.3)\n"
                    "for i in range(60):\n    os.write(1, b'tick %d\\r\\n' % i); time.sleep(0.02)\n"
                    "os.write(1, b'$ '); c = os.read(0, 1); os.write(1, c); time.sleep(5)\n")
        m = self.sessions.Manager()
        s = m.open("tester", self.targets.find("DCB:mgmt"), {"argv": [PY, stream], "password": None,
                   "folder": tempfile.mkdtemp(dir=TMP)}, "127.0.0.1")
        s.last_input = time.time() - 5   # nothing typed: the ticks stream by themselves
        offset, polls, out = 0, 0, b""
        while b"$ " not in out:
            chunk = m.poll({s.id: offset}, wait=5)[s.id]
            polls += 1
            out += base64.b64decode(chunk["data"])
            offset = chunk["offset"]
        self.assertIn(b"tick 59", out)
        self.assertLessEqual(polls, 8, "60 lines in about 1.2 s should come in a few batches")
        m.write(s, "x")                   # a key: its echo is sent without waiting for more output
        started = time.time()
        chunk = m.poll({s.id: offset}, wait=5)[s.id]
        self.assertEqual(base64.b64decode(chunk["data"]), b"x")
        self.assertLess(time.time() - started, self.sessions.LINGER)
        m.close(s)

    def test_a_refused_session_leaves_no_key_file(self):
        c = self.client("sheller", "demo-shell-1")
        run = self.sessions.folder("run")
        before = set(os.listdir(run))
        old = self.sessions.MAX_PER_USER
        self.sessions.MAX_PER_USER = 0
        try:
            r = c.post("/terminal/api/sessions", json={"target": f"DCB:host:{self.h_sudo}"})
            self.assertEqual(r.status_code, 400)
        finally:
            self.sessions.MAX_PER_USER = old
        self.assertEqual(set(os.listdir(run)), before)

    def test_administrators_watch_and_join_a_session(self):
        owner = self.client("sheller", "demo-shell-1")
        other = self.client("sheller2", "demo-shell-2")
        admin = self.client()
        s = self.open(owner, "DCB:mgmt", cols=100, rows=40)
        sid = s["id"]
        self.read_until(owner, sid, "$ ")
        session = self.shell.MANAGER.get(sid)
        self.assertEqual(other.post(f"/terminal/api/sessions/{sid}/watch", json={"mode": "watch"}).status_code, 403)
        r = admin.post(f"/terminal/api/sessions/{sid}/watch", json={"mode": "watch"})
        self.assertEqual(r.status_code, 200, r.get_json())
        last_poll = session.last_poll = time.time() - 100
        watched = admin.get(f"/terminal/api/poll?c={sid}:-1&wait=1").get_json()["sessions"][sid]
        self.assertIn(b"Management host", base64.b64decode(watched["data"]))   # the screen so far, live afterwards
        self.assertEqual(session.last_poll, last_poll)                           # watching does not keep it alive
        self.assertEqual(owner.get("/terminal/api/sessions").get_json()["sessions"][0]["watchers"],
                         [{"user": "portaladmin", "mode": "watch"}])              # its user sees who watches
        self.assertEqual(admin.post(f"/terminal/api/sessions/{sid}/input", json={"data": "id\r"}).status_code, 400)
        admin.post(f"/terminal/api/sessions/{sid}/resize", json={"cols": 50, "rows": 10})   # not the watcher's to change
        self.type(owner, sid, "size\r")
        self.read_until(owner, sid, "rows=40 cols=100")
        self.assertEqual(admin.post(f"/terminal/api/sessions/{sid}/watch", json={"mode": "join"}).status_code, 200)
        self.assertEqual(admin.post(f"/terminal/api/sessions/{sid}/input", json={"data": "echo typed-by-admin\r"}).status_code, 200)
        self.read_until(owner, sid, "\r\ntyped-by-admin\r\n")
        self.assertEqual(admin.post(f"/terminal/api/sessions/{sid}/root", json={}).status_code, 400)   # not for a guest
        import threading
        waiting = threading.Thread(target=lambda: admin.get(f"/terminal/api/poll?c={sid}:999999&wait=2"))
        waiting.start()                    # a request of the watcher still waiting when it leaves
        time.sleep(0.3)
        self.assertEqual(admin.post(f"/terminal/api/sessions/{sid}/watch", json={"mode": "leave"}).status_code, 200)
        waiting.join()
        self.assertEqual(admin.post(f"/terminal/api/sessions/{sid}/input", json={"data": "x"}).status_code, 400)
        self.assertEqual(self.shell.MANAGER.get(sid).present(), [])
        actions = [e["action"] for e in self._events()]
        self.assertIn("shell.watch", actions)
        self.assertIn("shell.join", actions)
        owner.delete(f"/terminal/api/sessions/{sid}")
        self.read_until(owner, sid, "", state="closed")
        with open(self.sessions.recording_path(self.sessions.history_row(sid)), "rb") as f:
            recorded = f.read()
        for note in (b"portaladmin watches this session", b"portaladmin joined this session and can type",
                     b"portaladmin left this session"):
            self.assertIn(note, recorded)
        self.assertEqual(admin.post(f"/terminal/api/sessions/{sid}/watch", json={"mode": "watch"}).status_code, 400)

    def test_a_session_ended_from_the_portal_is_not_failed(self):
        """ssh ends with 255 when the portal hangs it up: that is "closed", not a failed connection."""
        m = self.sessions.Manager()
        s = m.open("tester", self.targets.find("DCB:mgmt"), {"argv": ["/bin/sh", "-c", "trap 'exit 255' HUP; echo up; sleep 30 & wait"],
                   "password": None, "folder": tempfile.mkdtemp(dir=TMP)}, "127.0.0.1")
        deadline = time.time() + 5
        while b"up" not in bytes(s.buf) and time.time() < deadline:
            time.sleep(0.05)
        m.close(s, "Ended by the user")
        while s.state != "closed" and time.time() < deadline + 5:
            time.sleep(0.05)
        self.assertEqual(s.exit_code, 255)
        self.assertEqual(self.sessions.history_row(s.id)["status"], "closed")

    def test_operators_open_only_the_hosts_given_to_them(self):
        op = self.client("limited", "demo-limited-1")
        admin = self.client()
        data = op.get("/terminal/api/targets").get_json()
        self.assertEqual((data["targets"], data["restricted"]), ([], True))          # nothing by default
        r = op.post("/terminal/api/sessions", json={"target": "DCB:mgmt"})
        self.assertEqual(r.status_code, 403)
        self.assertIn("not one of your hosts", r.get_json()["error"])
        self.assertEqual(op.get("/terminal/api/access").status_code, 403)
        self.assertEqual(op.put("/terminal/api/access/limited", json={"rules": ["*"]}).status_code, 403)
        accounts = {a["username"]: a for a in admin.get("/terminal/api/access").get_json()["accounts"]}
        self.assertIn("limited", accounts)
        self.assertNotIn("allmods", accounts)                                         # no Shell module
        self.assertEqual(accounts["portaladmin"]["role"], "admin")
        self.assertEqual(admin.put("/terminal/api/access/limited", json={"rules": ["rm -rf /"]}).status_code, 400)
        r = admin.put("/terminal/api/access/limited", json={"rules": ["cat:DCB:cdn", f"host:DCA:host:{self.h_vyos}"]})
        self.assertEqual(r.status_code, 200, r.get_json())
        ids = {t["id"] for t in op.get("/terminal/api/targets").get_json()["targets"]}
        self.assertEqual(ids, {"DCB:group:cdn:dcb-cdn-01", "DCB:group:cdn:edge-unreachable", f"DCA:host:{self.h_vyos}"})
        self.assertEqual(op.post("/terminal/api/sessions", json={"target": "DCB:mgmt"}).status_code, 403)
        self.assertEqual(op.post("/terminal/api/sessions", json={"target": "DCA:mgmt"}).status_code, 403)
        s = self.open(op, "DCB:group:cdn:dcb-cdn-01")
        self.read_until(op, s["id"], "$ ")
        self.assertIn("shell.access", [e["action"] for e in self._events()])
        self.assertEqual(admin.put("/terminal/api/access/limited", json={"rules": ["site:DCA", "*"]}).get_json()["rules"], ["*"])
        self.assertEqual(admin.put("/terminal/api/access/limited", json={"rules": []}).get_json()["rules"], [])
        self.assertEqual(op.get("/terminal/api/targets").get_json()["targets"], [])
        self.assertEqual(self.open(admin, "DCB:mgmt")["state"], "open")               # administrators: every host

    def test_temporary_access_ends_by_itself(self):
        import datetime
        op = self.client("limited", "demo-limited-1")
        admin = self.client()
        later = (datetime.datetime.now().astimezone() + datetime.timedelta(hours=4)).isoformat()
        past = (datetime.datetime.now().astimezone() - datetime.timedelta(minutes=1)).isoformat()
        too_far = (datetime.datetime.now().astimezone() + datetime.timedelta(days=400)).isoformat()
        self.assertEqual(admin.put("/terminal/api/access/limited", json={"grants": [{"rule": "site:DCA", "expires": too_far}]}).status_code, 400)
        r = admin.put("/terminal/api/access/limited", json={"grants": [
            {"rule": "cat:DCB:cdn", "expires": later, "ticket": "INC-4711 restore check"},
            {"rule": "site:DCA", "expires": past},                 # already over: dropped
            {"rule": "host:DCB:mgmt"}]})                          # permanent
        self.assertEqual(r.status_code, 200, r.get_json())
        saved = {g["rule"]: g for g in r.get_json()["grants"]}
        self.assertEqual(set(saved), {"cat:DCB:cdn", "host:DCB:mgmt"})
        self.assertEqual((saved["cat:DCB:cdn"]["ticket"], saved["host:DCB:mgmt"]["expires"]), ("INC-4711 restore check", ""))
        detail = [e["detail"] for e in self._events() if e["action"] == "shell.access"][-1]
        self.assertIn("[INC-4711 restore check]", detail)
        self.assertIn("until ", detail)
        s = self.open(op, "DCB:group:cdn:dcb-cdn-01")
        self.read_until(op, s["id"], "$ ")
        # the time passes: the grant gives nothing any more, the open session ends at the next look
        with self.shell.access._db() as db:
            db.execute("UPDATE shell_access SET expires = ? WHERE username = 'limited' AND rule = 'cat:DCB:cdn'", (past,))
        ids = {t["id"] for t in op.get("/terminal/api/targets").get_json()["targets"]}
        self.assertEqual(ids, {"DCB:mgmt"})
        self.assertEqual(op.post("/terminal/api/sessions", json={"target": "DCB:group:cdn:dcb-cdn-01"}).status_code, 403)
        self.shell.MANAGER.reap()
        _, chunk = self.read_until(op, s["id"], "", state="closed")
        self.assertIn("Access to this host ended", chunk["reason"])
        listed = next(a for a in admin.get("/terminal/api/access").get_json()["accounts"] if a["username"] == "limited")
        self.assertEqual({g["rule"]: g["active"] for g in listed["grants"]}, {"cat:DCB:cdn": False, "host:DCB:mgmt": True})
        self.assertEqual(listed["rules"], ["host:DCB:mgmt"])
        admin.put("/terminal/api/access/limited", json={"grants": []})

    def test_plain_text_and_restart(self):
        self.assertEqual(self.sessions.plain_text(b"\x1b[01;32mok\x1b[0m done\r\nprogress 10%\rprogress 100%\r\nab\bc"),
                         "ok done\nprogress 100%\nac")
        with self.sessions._db() as db:
            db.execute("INSERT INTO shell_sessions (id, username, started, status, label) VALUES ('00000000deadbeef', 'x', '2026-11-06T10:00:00+07:00', 'open', 'DCB · OpenStack · Director')")
        stale = self.sessions.init()
        self.assertEqual([r["id"] for r in stale], ["00000000deadbeef"])
        self.assertEqual(self.sessions.history_row("00000000deadbeef")["status"], "closed")


if __name__ == "__main__":
    unittest.main()

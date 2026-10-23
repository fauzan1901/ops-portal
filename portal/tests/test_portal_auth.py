"""Tests for portal_auth (shared by ACI Web UI and ONTAP Restore Web UI): AD bind against a fake LDAPS server,
the Duo Universal Prompt flow against a fake Duo, the admin-only user list, and encrypted service credentials.

Run from the application folder:
    .venv/bin/python -m unittest tests.test_portal_auth -v
"""
import contextlib
import io
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import time
import unittest
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from flask import Flask  # noqa: E402

import fake_duo  # noqa: E402
import fake_ldap  # noqa: E402
import fake_sso  # noqa: E402
import portal_auth  # noqa: E402

SSO_BASE = "https://portal.example.local"   # host of sso.redirect_uri in these tests
USERS = {"alice": {"password": "alice-pw", "display_name": "Alice Admin", "mail": "alice@example.local"},
         "bob": {"password": "bob-pw", "display_name": "Bob Operator"},
         "carol": {"password": "carol-pw", "display_name": "Carol Stranger"},
         "dave": {"password": "dave-pw", "locked": True}}


class PortalAuthTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.cert, key = fake_ldap.make_cert(cls.tmp)
        cls.ldap = fake_ldap.FakeLdap(cls.cert, key, USERS).start()
        cls.duo = fake_duo.FakeDuo(cls.cert, key).start()
        cls.sso = fake_sso.FakeSso(cls.cert, key, people={"bob": "Bob Operator"}).start()

    @classmethod
    def tearDownClass(cls):
        cls.ldap.stop()
        cls.duo.stop()
        cls.sso.stop()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        self.dir = tempfile.mkdtemp(dir=self.tmp)
        self.config_path = os.path.join(self.dir, "auth.yml")
        self.db_path = os.path.join(self.dir, "app.db")
        self.key_path = os.path.join(self.dir, "credentials.key")
        self.write_config()
        self.tested = []
        app = Flask(__name__)
        self.portal = portal_auth.Portal(
            "Test App", self.config_path, self.db_path, self.key_path, "test_sid",
            targets=lambda: [{"name": "ontap:DCB", "label": "ONTAP DCB", "host": "10.253.0.1", "kind": "ontap", "site": "DCB"}],
            tester=self.fake_tester)
        self.portal.install(app)

        @app.get("/api/whoami")
        def whoami():
            try:
                return {"user": self.portal.user()["username"]}
            except portal_auth.NotSignedIn as e:
                return {"error": str(e)}, 401

        self.app = app
        self.duo.down = self.duo.deny = self.duo.tamper = self.duo.wrong_user = False
        self.ldap.delay, self.ldap.push_deny = 0.0, False
        self.sso.deny = self.sso.tamper = self.sso.wrong_nonce = self.sso.other_audience = self.sso.drop_username = False
        self.sso.approve_as = "bob"

    def fake_tester(self, target, username, password):
        self.tested.append((target["name"], username, password))
        if password != "svc-good":
            raise RuntimeError("ONTAP rejected the account")
        return "Connected to cluster DCBSTNCL"

    def write_config(self, mfa=False, admins=("alice",), **extra):
        cfg = {"ldap": {"url": [self.ldap.url], "user_format": "{username}@example.local", "ca_file": self.cert,
                        "base_dn": "DC=example,DC=local", "timeout_seconds": 5},
               "duo": {"enabled": mfa, "client_id": fake_duo.CLIENT_ID, "client_secret": fake_duo.CLIENT_SECRET,
                       "api_host": self.duo.api_host, "ca_file": self.cert,
                       "redirect_uri": "https://portal.example.local/auth/duo/callback"},
               "admins": list(admins)}
        for key, value in extra.items():
            cfg[key] = dict(cfg.get(key) or {}, **value) if isinstance(value, dict) else value
        with open(self.config_path, "w") as f:
            json.dump(cfg, f)   # JSON is valid YAML
        os.utime(self.config_path, (time.time() + 1, time.time() + 1))   # new mtime even within the same second

    def login(self, client, username, password):
        return client.post("/api/login", json={"username": username, "password": password})

    def follow_duo(self, url):
        """The browser part: open Duo's authorize URL, return the redirect back to the portal."""
        ctx = __import__("ssl").create_default_context(cafile=self.cert)

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None

        opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx), urllib.request.ProxyHandler({}))
        try:
            opener.open(url, timeout=10)
        except urllib.error.HTTPError as e:
            if e.code == 302:
                return e.headers["Location"]
            raise
        self.fail("Duo did not redirect back")

    # ---------------- Active Directory ----------------
    def test_ad_sign_in_and_user_list(self):
        client = self.app.test_client()
        r = self.login(client, "EXAMPLE\\Alice", "alice-pw")   # domain prefix and case are normalized
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertEqual(client.get("/api/whoami").get_json(), {"user": "alice"})
        self.assertEqual(self.ldap.binds[-1], "alice@example.local")   # always bound as ldap.user_format
        users = client.get("/api/admin/users").get_json()["users"]
        self.assertEqual([(u["username"], u["role"], u["builtin"], u["display_name"]) for u in users],
                         [("alice", "admin", True, "Alice Admin")])

        # Wrong password, empty password, locked account, and an AD account that is not on the list.
        other = self.app.test_client()
        r = self.login(other, "bob", "wrong")
        self.assertEqual((r.status_code, r.get_json()["error"]), (401, "Invalid username or password."))
        binds = len(self.ldap.binds)
        self.assertEqual(self.login(other, "bob", "").status_code, 400)
        self.assertEqual(len(self.ldap.binds), binds)   # an empty password never reaches AD (anonymous bind)
        r = self.login(other, "dave", "dave-pw")
        self.assertIn("locked", r.get_json()["error"])
        r = self.login(other, "carol", "carol-pw")
        self.assertEqual(r.status_code, 403)
        self.assertIn("not allowed to use Test App", r.get_json()["error"])
        self.assertEqual(other.get("/api/whoami").status_code, 401)

        # Only admins manage the list; the added operator can sign in; removing ends the session at once.
        self.assertEqual(client.post("/api/admin/users", json={"username": "bob", "role": "operator"}).status_code, 200)
        self.assertEqual(self.login(other, "bob@example.local", "bob-pw").status_code, 200)
        self.assertEqual(other.get("/api/admin/users").status_code, 403)
        self.assertEqual(other.post("/api/admin/users", json={"username": "carol", "role": "admin"}).status_code, 403)
        self.assertEqual(client.post("/api/admin/users/bob", json={"enabled": False}).status_code, 200)
        self.assertEqual(other.get("/api/whoami").status_code, 401)
        self.assertEqual(self.login(other, "bob", "bob-pw").status_code, 403)
        self.assertEqual(client.post("/api/admin/users/bob", json={"enabled": True, "role": "admin"}).status_code, 200)
        self.assertEqual(self.login(other, "bob", "bob-pw").status_code, 200)
        self.assertEqual(other.get("/api/admin/users").status_code, 200)
        # Self-protection and auth.yml administrators.
        self.assertIn("own account", other.delete("/api/admin/users/bob").get_json()["error"])
        self.assertIn("auth.yml", other.post("/api/admin/users/alice", json={"role": "operator"}).get_json()["error"])
        self.assertEqual(client.delete("/api/admin/users/bob").status_code, 200)
        self.assertEqual(other.get("/api/whoami").status_code, 401)
        actions = [e["action"] for e in client.get("/api/admin/events").get_json()["events"]]
        for action in ("login.success", "login.failed", "login.denied", "user.add", "user.update", "user.remove"):
            self.assertIn(action, actions)

    def test_failed_attempts_lock_the_account_for_a_while(self):
        client = self.app.test_client()
        for _ in range(5):
            self.assertEqual(self.login(client, "alice", "nope").status_code, 401)
        r = self.login(client, "alice", "alice-pw")
        self.assertEqual(r.status_code, 429)
        self.assertIn("Too many failed sign-in attempts", r.get_json()["error"])

    def test_unreachable_directory_and_missing_config(self):
        self.write_config(ldap={"url": ["ldaps://localhost:1"]})
        r = self.login(self.app.test_client(), "alice", "alice-pw")
        self.assertEqual(r.status_code, 503)
        self.assertIn("Active Directory is not reachable", r.get_json()["error"])
        self.write_config(ldap={"url": ["ldap://localhost:389"]})
        r = self.login(self.app.test_client(), "alice", "alice-pw")
        self.assertIn("unencrypted", r.get_json()["error"])
        os.remove(self.config_path)
        r = self.login(self.app.test_client(), "alice", "alice-pw")
        self.assertEqual(r.status_code, 503)
        self.assertIn("does not exist", r.get_json()["error"])

    def test_tls_certificate_is_verified(self):
        other_cert, _ = fake_ldap.make_cert(self.dir, "other-ca")
        self.write_config(ldap={"ca_file": other_cert})
        r = self.login(self.app.test_client(), "alice", "alice-pw")
        self.assertEqual(r.status_code, 503)
        self.assertIn("certificate", r.get_json()["error"].lower())

    # ---------------- Duo ----------------
    def test_duo_universal_prompt_flow(self):
        self.write_config(mfa=True)
        client = self.app.test_client()
        r = self.login(client, "alice", "alice-pw")
        self.assertEqual(r.status_code, 200, r.get_json())
        url = r.get_json()["redirect"]
        self.assertTrue(url.startswith(f"https://{self.duo.api_host}/oauth/v1/authorize?"))
        self.assertEqual(client.get("/api/whoami").status_code, 401)   # not signed in before Duo approves
        back = urllib.parse.urlsplit(self.follow_duo(url))
        self.assertEqual(back.path, "/auth/duo/callback")
        r = client.get(f"/auth/duo/callback?{back.query}")
        location = urllib.parse.urlsplit(r.headers["Location"])
        self.assertEqual((r.status_code, location.path, location.query), (302, "/", ""))
        self.assertEqual(client.get("/api/whoami").get_json(), {"user": "alice"})
        # The same Duo response cannot be used twice.
        replay = client.get(f"/auth/duo/callback?{back.query}")
        self.assertIn("auth_error", replay.headers["Location"])
        calls = [c[1] for c in self.duo.calls]
        self.assertEqual(calls[-3:], ["/oauth/v1/health_check", "/oauth/v1/authorize", "/oauth/v1/token"])

    def test_duo_refusals(self):
        self.write_config(mfa=True)
        for switch, message in (("deny", "did not approve"), ("tamper", "signature"), ("wrong_user", "another user")):
            with self.subTest(switch=switch):
                setattr(self.duo, switch, True)
                try:
                    client = self.app.test_client()
                    url = self.login(client, "alice", "alice-pw").get_json()["redirect"]
                    back = urllib.parse.urlsplit(self.follow_duo(url))
                    r = client.get(f"/auth/duo/callback?{back.query}")
                    error = urllib.parse.parse_qs(urllib.parse.urlsplit(r.headers["Location"]).query)["auth_error"][0]
                    self.assertIn(message, error)
                    self.assertEqual(client.get("/api/whoami").status_code, 401)
                finally:
                    setattr(self.duo, switch, False)
        # A callback from another browser (no pending cookie) or with a wrong state is refused.
        client = self.app.test_client()
        url = self.login(client, "alice", "alice-pw").get_json()["redirect"]
        back = urllib.parse.urlsplit(self.follow_duo(url))
        stranger = self.app.test_client()
        self.assertIn("auth_error", stranger.get(f"/auth/duo/callback?{back.query}").headers["Location"])
        query = dict(urllib.parse.parse_qsl(back.query), state="x" * 36)
        self.assertIn("auth_error", client.get("/auth/duo/callback?" + urllib.parse.urlencode(query)).headers["Location"])

    def test_duo_unreachable_blocks_or_bypasses(self):
        self.write_config(mfa=True)
        self.duo.down = True
        r = self.login(self.app.test_client(), "alice", "alice-pw")
        self.assertEqual(r.status_code, 503)
        self.assertIn("Duo is not reachable", r.get_json()["error"])
        self.write_config(mfa=True, duo={"fail_mode": "open"})
        client = self.app.test_client()
        self.assertEqual(self.login(client, "alice", "alice-pw").status_code, 200)
        self.assertEqual(client.get("/api/whoami").get_json(), {"user": "alice"})
        actions = [e["action"] for e in self.portal.store.events()]
        self.assertIn("login.duo_bypassed", actions)

    def test_duo_config_problems(self):
        self.write_config(mfa=True, duo={"client_id": "short", "api_host": ""})
        r = self.login(self.app.test_client(), "alice", "alice-pw")
        self.assertEqual(r.status_code, 503)
        self.assertIn("duo.client_id", r.get_json()["error"])
        self.assertIn("duo.api_host", r.get_json()["error"])

    # ---------------- Duo Authentication Proxy (LDAP proxy) ----------------
    def test_duo_auth_proxy_sends_the_push_during_the_bind(self):
        # The fake directory plays the proxy: a correct password is answered only after the (simulated) Duo Push,
        # which takes longer than timeout_seconds. duo.enabled stays on for local accounts but is not used here.
        self.write_config(mfa=True, ldap={"duo_auth_proxy": True, "timeout_seconds": 1, "push_timeout_seconds": 30})
        self.ldap.delay = 1.5
        client = self.app.test_client()
        r = self.login(client, "alice", "alice-pw")
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertNotIn("redirect", r.get_json())   # no Universal Prompt on top of the proxy's push
        self.assertEqual(client.get("/api/whoami").get_json(), {"user": "alice"})
        event = self.portal.store.events()[0]
        self.assertEqual((event["action"], event["detail"]), ("login.success", "AD via Duo Authentication Proxy, mfa=duo"))
        with self.app.test_request_context():
            self.assertTrue(self.portal.payload()["auth"]["ad_push"])
        # A denied push is refused like a wrong password (and counts for the lockout).
        self.ldap.delay, self.ldap.push_deny = 0.0, True
        r = self.login(self.app.test_client(), "bob", "bob-pw")
        self.assertEqual(r.status_code, 401)
        self.assertIn("Duo Push was denied", r.get_json()["error"])
        # AD reasons (here a locked account) still come through the proxy.
        self.assertIn("locked", self.login(self.app.test_client(), "dave", "dave-pw").get_json()["error"])

    def test_duo_auth_proxy_push_not_answered_in_time(self):
        self.ldap.delay = 2.5
        binds = len(self.ldap.binds)
        ldap_cfg = {"url": [self.ldap.url, self.ldap.url], "user_format": "{username}@example.local", "ca_file": self.cert,
                    "timeout_seconds": 1, "duo_auth_proxy": True, "push_timeout_seconds": 1}
        with self.assertRaises(portal_auth.AuthFailed) as ctx:
            portal_auth.ldap_check(ldap_cfg, "alice", "alice-pw")
        self.assertEqual(ctx.exception.status, 401)
        self.assertIn("not approved in time", str(ctx.exception))
        self.assertEqual(len(self.ldap.binds), binds + 1)   # the second proxy is not tried (it would push again)

    def test_tls_name_checks_the_certificate_of_an_address(self):
        # The proxy is reached by an address that is not in its certificate (WSL -> the Windows host's IP); tls_name is
        # the name that must be in the certificate instead.
        cert, key = fake_ldap.make_cert(self.dir, "proxy-only-name", san="DNS:proxy.example.local")
        proxy = fake_ldap.FakeLdap(cert, key, USERS).start()
        try:
            url = f"ldaps://127.0.0.1:{proxy.port}"
            for tls_name, ok in (("proxy.example.local", True), ("", False), ("other.example.local", False)):
                with self.subTest(tls_name=tls_name):
                    self.write_config(ldap={"url": [url], "ca_file": cert, "tls_name": tls_name})
                    r = self.login(self.app.test_client(), "alice", "alice-pw")
                    if ok:
                        self.assertEqual(r.status_code, 200, r.get_json())
                    else:
                        self.assertEqual(r.status_code, 503)
                        self.assertIn("certificate", r.get_json()["error"].lower())
            # The check command verifies the same name.
            self.write_config(ldap={"url": [url], "ca_file": cert, "tls_name": "proxy.example.local"})
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                portal_auth._check(self.config_path)
            self.assertIn(f"[OK] {url}: TLS", out.getvalue())
            self.assertIn("verified for proxy.example.local", out.getvalue())
        finally:
            proxy.stop()

    def test_duo_auth_proxy_config_problems(self):
        self.write_config(ldap={"duo_auth_proxy": True, "push_timeout_seconds": 500})
        r = self.login(self.app.test_client(), "alice", "alice-pw")
        self.assertEqual(r.status_code, 503)
        self.assertIn("ldap.push_timeout_seconds", r.get_json()["error"])
        self.write_config(ldap={"duo_auth_proxy": True, "url": ["ldap://localhost:10389"]})
        self.assertIn("unencrypted", self.login(self.app.test_client(), "alice", "alice-pw").get_json()["error"])

    # ---------------- Service credentials ----------------
    def test_credentials_are_encrypted_write_only_and_tested(self):
        client = self.app.test_client()
        self.login(client, "alice", "alice-pw")
        listing = client.get("/api/admin/credentials").get_json()["credentials"]
        self.assertEqual([(c["name"], c["configured"]) for c in listing], [("ontap:DCB", False)])
        with self.assertRaises(portal_auth.CredentialError):
            self.portal.credential("ontap:DCB")
        r = client.post("/api/admin/credentials/ontap:DCB", json={"username": "svc_restore", "password": "svc-good"})
        self.assertEqual(r.get_json()["test"], {"ok": True, "message": "Connected to cluster DCBSTNCL"})
        listing = client.get("/api/admin/credentials").get_json()
        self.assertNotIn("svc-good", json.dumps(listing))   # never shown again
        self.assertEqual(listing["credentials"][0]["username"], "svc_restore")
        self.assertEqual(self.portal.credential("ontap:DCB"), {"username": "svc_restore", "password": "svc-good"})
        with sqlite3.connect(self.db_path) as db:
            raw = db.execute("SELECT secret FROM service_credentials").fetchone()[0]
        self.assertNotIn("svc-good", raw)
        self.assertEqual(client.post("/api/admin/credentials/ontap:DCB/test", json={}).get_json()["test"]["ok"], True)
        r = client.post("/api/admin/credentials/ontap:DCB", json={"username": "svc_restore", "password": "svc-bad"})
        self.assertEqual(r.get_json()["test"], {"ok": False, "message": "ONTAP rejected the account"})
        self.assertEqual(client.post("/api/admin/credentials/apic:XYZ", json={"username": "a", "password": "b"}).status_code, 400)
        # Another key cannot decrypt it.
        os.remove(self.key_path)
        self.portal.vault._fernet = None
        with self.assertRaises(portal_auth.CredentialError):
            self.portal.credential("ontap:DCB")
        self.assertEqual(client.delete("/api/admin/credentials/ontap:DCB").status_code, 200)
        self.assertFalse(self.portal.credential_configured("ontap:DCB"))

    def test_operators_cannot_touch_credentials(self):
        admin = self.app.test_client()
        self.login(admin, "alice", "alice-pw")
        admin.post("/api/admin/users", json={"username": "bob", "role": "operator"})
        operator = self.app.test_client()
        self.login(operator, "bob", "bob-pw")
        self.assertEqual(operator.get("/api/admin/credentials").status_code, 403)
        self.assertEqual(operator.post("/api/admin/credentials/ontap:DCB", json={"username": "x", "password": "y"}).status_code, 403)
        self.assertEqual(self.app.test_client().get("/api/admin/credentials").status_code, 401)

    # ---------------- Local accounts ----------------
    LOCAL_PASSWORD = "Local-Admin-Pass-2026"

    def add_local(self, name="portaladmin", duo_user="", role="admin"):
        self.portal.store.add_local_user(name, portal_auth.hash_password(self.LOCAL_PASSWORD), role, "Portal Admin", duo_user, "test")

    def test_local_admin_works_without_ad_and_manages_users(self):
        os.remove(self.config_path)   # neither AD nor Duo is configured yet
        self.add_local()
        client = self.app.test_client()
        self.assertEqual(self.login(client, "portaladmin", "Wrong-Password-123").status_code, 401)
        binds = len(self.ldap.binds)
        r = self.login(client, "PortalAdmin", self.LOCAL_PASSWORD)
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertEqual(len(self.ldap.binds), binds)   # a local account is never sent to AD
        self.assertEqual(client.get("/api/whoami").get_json(), {"user": "portaladmin"})
        users = client.get("/api/admin/users").get_json()
        self.assertEqual([(u["username"], u["source"], u["mfa"]) for u in users["users"]], [("portaladmin", "local", "none")])
        self.assertEqual(users["me_source"], "local")
        self.assertEqual(client.post("/api/admin/users", json={"username": "bob", "role": "operator"}).status_code, 200)
        self.assertIn("local account", client.post("/api/admin/users", json={"username": "portaladmin"}).get_json()["error"])
        r = self.login(self.app.test_client(), "bob", "bob-pw")   # AD users need auth.yml
        self.assertEqual(r.status_code, 503)
        self.assertIn("Active Directory sign-in is not configured yet", r.get_json()["error"])
        self.write_config()
        self.assertEqual(self.login(self.app.test_client(), "bob", "bob-pw").status_code, 200)

    def test_local_password_change_and_disable_end_sessions(self):
        self.add_local()
        client = self.app.test_client()
        self.assertEqual(self.login(client, "portaladmin", self.LOCAL_PASSWORD).status_code, 200)
        self.portal.store.update_local_user("portaladmin", password_hash=portal_auth.hash_password("New-Local-Pass-2026"),
                                            password_changed=portal_auth._now(precise=True))
        self.assertEqual(client.get("/api/whoami").status_code, 401)
        self.assertEqual(self.login(client, "portaladmin", self.LOCAL_PASSWORD).status_code, 401)
        self.assertEqual(self.login(client, "portaladmin", "New-Local-Pass-2026").status_code, 200)
        self.portal.store.update_local_user("portaladmin", enabled=0)
        self.assertEqual(client.get("/api/whoami").status_code, 401)
        r = self.login(client, "portaladmin", "New-Local-Pass-2026")
        self.assertEqual((r.status_code, r.get_json()["error"]), (403, "This local account is disabled."))

    def test_local_account_with_duo_user_goes_through_duo(self):
        self.write_config(mfa=True)
        self.add_local(duo_user="alice")
        client = self.app.test_client()
        url = self.login(client, "portaladmin", self.LOCAL_PASSWORD).get_json()["redirect"]
        back = urllib.parse.urlsplit(self.follow_duo(url))
        client.get(f"/auth/duo/callback?{back.query}")
        self.assertEqual(client.get("/api/whoami").get_json(), {"user": "portaladmin"})
        self.add_local("breakglass")   # no Duo username: password only, even with Duo enabled
        other = self.app.test_client()
        r = self.login(other, "breakglass", self.LOCAL_PASSWORD)
        self.assertNotIn("redirect", r.get_json())
        self.assertEqual(other.get("/api/whoami").get_json(), {"user": "breakglass"})

    def test_local_user_command(self):
        import subprocess
        script = os.path.join(os.path.dirname(HERE), "portal_auth.py")

        def run(action, *extra, stdin=""):
            return subprocess.run([sys.executable, script, "local-user", action, *extra, "--db", self.db_path],
                                  input=stdin, capture_output=True, text=True, timeout=60)

        r = run("add", "ops.admin", "--password-stdin", stdin="too-short\n")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("at least 12", r.stderr)
        r = run("add", "ops.admin", "--password-stdin", stdin="Very-Long-Pass-2026\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ops.admin", run("list").stdout)
        client = self.app.test_client()
        self.assertEqual(self.login(client, "ops.admin", "Very-Long-Pass-2026").status_code, 200)
        self.assertEqual(run("passwd", "ops.admin", "--password-stdin", stdin="Another-Long-Pass-2026\n").returncode, 0)
        self.assertEqual(client.get("/api/whoami").status_code, 401)
        self.assertEqual(self.login(client, "ops.admin", "Another-Long-Pass-2026").status_code, 200)
        self.assertEqual(run("disable", "ops.admin").returncode, 0)
        self.assertEqual(self.login(client, "ops.admin", "Another-Long-Pass-2026").status_code, 403)
        self.assertEqual(run("remove", "ops.admin").returncode, 0)
        self.assertNotEqual(run("remove", "ops.admin").returncode, 0)
        actions = [e["action"] for e in self.portal.store.events()]
        for action in ("local.add", "local.passwd", "local.disable", "local.remove"):
            self.assertIn(action, actions)

    # ---------------- Duo Single Sign-On (OIDC) ----------------
    def sso_config(self, **sso):
        settings = {"enabled": True, "issuer": self.sso.issuer, "client_id": fake_sso.CLIENT_ID,
                    "client_secret": fake_sso.CLIENT_SECRET, "redirect_uri": "https://portal.example.local/auth/sso/callback",
                    "ca_file": self.cert, "username_claim": "preferred_username"}
        settings.update(sso)
        self.write_config(ldap={"url": []}, sso=settings)   # AD accounts only through Duo SSO

    def sso_sign_in(self, client):
        # Opened as http://localhost: the button first moves the browser to the host of redirect_uri.
        r = client.get("/auth/sso/login")
        self.assertEqual((r.status_code, r.headers["Location"]), (302, f"{SSO_BASE}/auth/sso/login"))
        r = client.get("/auth/sso/login", base_url=SSO_BASE)
        self.assertEqual(r.status_code, 302, r.data[:300])
        back = urllib.parse.urlsplit(self.follow_duo(r.headers["Location"]))
        self.assertEqual(back.path, "/auth/sso/callback")
        return client.get(f"/auth/sso/callback?{back.query}", base_url=SSO_BASE), back.query

    def sso_error(self, response):
        return urllib.parse.parse_qs(urllib.parse.urlsplit(response.headers["Location"]).query).get("auth_error", [""])[0]

    def test_sso_sign_in(self):
        self.sso_config()
        self.portal.store.add_user("bob", "operator", "test")
        client = self.app.test_client()
        r = self.login(client, "bob", "bob-pw")   # the password form is only for local accounts now
        self.assertEqual(r.status_code, 400)
        self.assertIn("Duo SSO", r.get_json()["error"])
        r, query = self.sso_sign_in(client)
        self.assertEqual((r.status_code, urllib.parse.urlsplit(r.headers["Location"]).path, self.sso_error(r)), (302, "/", ""))
        self.assertEqual(client.get("/api/whoami", base_url=SSO_BASE).get_json(), {"user": "bob"})   # cookies are per host
        self.assertEqual(self.portal.store.user("bob")["display_name"], "Bob Operator")
        authorize = next(c for c in reversed(self.sso.calls) if c[1].endswith("/authorize"))[2]
        self.assertEqual((authorize["code_challenge_method"], len(authorize["nonce"]), len(authorize["state"])), ("S256", 36, 36))
        self.assertIn("expired or was already used", self.sso_error(client.get(f"/auth/sso/callback?{query}", base_url=SSO_BASE)))
        events = [(e["action"], e["detail"]) for e in self.portal.store.events()]
        self.assertIn(("login.success", "AD, mfa=sso"), events)

    def test_sso_refusals(self):
        self.sso_config()
        self.portal.store.add_user("bob", "operator", "test")
        for switch, message in (("deny", "did not complete"), ("tamper", "signature is invalid"),
                                ("wrong_nonce", "does not belong to this sign-in"), ("other_audience", "another application"),
                                ("drop_username", "did not send the claim 'preferred_username'")):
            with self.subTest(switch=switch):
                setattr(self.sso, switch, True)
                try:
                    client = self.app.test_client()
                    r, _ = self.sso_sign_in(client)
                    self.assertIn(message, self.sso_error(r))
                    self.assertEqual(client.get("/api/whoami", base_url=SSO_BASE).status_code, 401)
                finally:
                    setattr(self.sso, switch, False)
        # Not on the user list, another browser, and a wrong client secret.
        self.sso.approve_as = "carol"
        client = self.app.test_client()
        r, _ = self.sso_sign_in(client)
        self.assertIn("carol is not allowed", self.sso_error(r))
        self.sso.approve_as = "bob"
        r = self.app.test_client().get("/auth/sso/login", base_url=SSO_BASE)
        back = urllib.parse.urlsplit(self.follow_duo(r.headers["Location"]))
        stranger = self.app.test_client()   # another browser: no cookie of this sign-in
        self.assertIn("expired or was already used", self.sso_error(stranger.get(f"/auth/sso/callback?{back.query}", base_url=SSO_BASE)))
        self.sso_config(client_secret="wrong-secret")
        r, _ = self.sso_sign_in(self.app.test_client())
        self.assertIn("invalid_client", self.sso_error(r))
        actions = [e["action"] for e in self.portal.store.events()]
        self.assertIn("login.sso_failed", actions)
        self.assertIn("login.denied", actions)

    def test_sso_keeps_local_admins_and_check_command(self):
        self.sso_config()
        self.add_local()
        client = self.app.test_client()
        self.assertEqual(self.login(client, "portaladmin", self.LOCAL_PASSWORD).status_code, 200)
        self.assertEqual(client.get("/api/whoami").get_json(), {"user": "portaladmin"})
        self.assertTrue(portal_auth._check(self.config_path))
        self.sso_config(client_secret="wrong-secret")
        self.assertFalse(portal_auth._check(self.config_path))
        self.sso_config(redirect_uri="http://portal.example.local/auth/sso/callback")
        self.assertIn("sso.redirect_uri must start with https://",
                      self.login(self.app.test_client(), "portaladmin-x", "whatever-password").get_json().get("error", "")
                      + " ".join(portal_auth.config_problems(self.portal.config)))

    def test_jwt_and_check_command(self):
        token = portal_auth.jwt_encode({"a": 1}, "secret")
        self.assertEqual(portal_auth.jwt_decode(token, "secret"), {"a": 1})
        with self.assertRaises(portal_auth.DuoError):
            portal_auth.jwt_decode(token, "other")
        with self.assertRaises(portal_auth.DuoError):
            portal_auth.jwt_decode("not.a.jwt", "secret")
        self.write_config(mfa=True)
        self.assertTrue(portal_auth._check(self.config_path))


if __name__ == "__main__":
    unittest.main()

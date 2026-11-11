"""The engineer's review of every fix operators run (modules/wi/reviews.py): Run this fix records a request and runs
its pre-check (the check again, read-only); the same fix with the same commands and the ticked items, still allowed,
waits for review; an engineer (wi-fix-review, or an administrator) approves or rejects it, never their own; the requester
then has Run now for the minutes set (default 15, 5 to 30), the typed confirmation of a high-risk fix still applies; later
the request expires. Templates with change steps go through it; the automatic actions of alert rules do not. Every step
is in the activity log, and the requests waiting are a metric for the SRE Grafana.

Run from the portal folder (each suite in its own process):
    .venv/bin/python -m unittest tests.test_wi_fix_review -v
"""
import contextlib
import datetime
import os
import shutil
import sqlite3
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

TMP = tempfile.mkdtemp()
PY = sys.executable
FAKE_HOSTS = f"FAKE_HOSTS_STATE={TMP}/hosts-state.json {PY} {os.path.join(HERE, 'fake_hosts.py')} {{name}}"
with open(os.path.join(TMP, "sites.yml"), "w") as f:
    f.write(f"""sites:
  DCA:
    wi: {{tcp_probe: false, test_ssh_command: "{FAKE_HOSTS}"}}
    hosts:
      cdn: {{user: runbook-ro, connection: local, command: "{FAKE_HOSTS}", members: {{dca-cdn-lb-01: 172.31.138.67, dca-cdn-lb-02: 172.31.138.68}}}}
  DCC:
    hosts: {{}}
""")
with open(os.path.join(TMP, "auth.yml"), "w") as f:
    f.write("admins: []\n")
os.environ.update(OPS_SITES=os.path.join(TMP, "sites.yml"), OPS_DATA=os.path.join(TMP, "data"),
                  OPS_DB=os.path.join(TMP, "data", "portal.db"), OPS_AUTH=os.path.join(TMP, "auth.yml"),
                  OPS_CREDENTIALS_KEY=os.path.join(TMP, "credentials.key"), OPS_MODULES="wi")


def new_key():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    return ed25519.Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                                              serialization.NoEncryption()).decode()


class CompareTest(unittest.TestCase):
    """reviews.compare: what makes the fix of the pre-check the one asked for."""

    @classmethod
    def setUpClass(cls):
        from modules.wi import reviews
        cls.r = reviews

    def state(self, commands, kind="host", target="h1", label="Run this fix", available=True, reason="", items=None, noun="instances"):
        st = {"kind": kind, "target": target, "label": label, "commands": commands, "available": available, "reason": reason,
              "risk": "normal"}
        if items is not None:
            st.update(selectable=True, noun=noun, items=items)
        return st

    def test_same_commands_comments_aside(self):
        asked = self.state(["sudo docker start lb   # stopped 3 min ago"])
        fp = self.r.fingerprint({}, asked)
        now = self.state(["sudo docker start lb   # stopped 9 min ago", "   # then look at Grafana"])
        index, st, sel, notes, problems = self.r.compare(fp, None, [(0, {}, self.state(["other"], label="Other")), (2, {}, now)])
        self.assertEqual((index, sel, problems), (2, [], []))
        self.assertIn("same commands", notes[0])

    def test_other_commands_or_gone_or_not_available(self):
        fp = self.r.fingerprint({}, self.state(["kill -9 4242"]))
        *_, problems = self.r.compare(fp, None, [(0, {}, self.state(["kill -9 5151"]))])
        self.assertIn("with other commands: kill -9 5151", problems[0])
        *_, problems = self.r.compare(fp, None, [])
        self.assertIn("no longer offers this fix", problems[0])
        *_, problems = self.r.compare(fp, None, [(0, {}, self.state(["kill -9 4242"], available=False,
                                                                        reason="The fix only runs from a result with a problem."))])
        self.assertIn("cannot run from the pre-check's result: The fix only runs from a result with a problem.", problems[0])
        # another host or another kind is another fix
        *_, problems = self.r.compare(fp, None, [(0, {}, self.state(["kill -9 4242"], target="h2"))])
        self.assertIn("no longer offers", problems[0])

    def test_ticked_items_by_their_commands(self):
        items = [{"label": "vm-a (3 days)", "commands": ["live-migrate A"]}, {"label": "vm-b", "commands": ["live-migrate B"]},
                 {"label": "vm-c", "commands": ["live-migrate C"]}]
        asked = self.state([], items=items)
        fp = self.r.fingerprint({}, asked)
        action = {"select": {"items": items, "noun": "instances", "max": 40}}
        wanted = [{"label": "vm-a (2 days)", "commands": ["live-migrate A"]}, {"label": "vm-c", "commands": ["live-migrate C"]}]
        moved = [items[2], items[1], dict(items[0], label="vm-a (3 days)")]   # another order, another label: by the commands
        index, st, sel, notes, problems = self.r.compare(fp, wanted, [(1, dict(action, select=dict(action["select"], items=moved)),
                                                                        self.state([], items=moved))])
        self.assertEqual((index, sel, problems), (1, [0, 2], []))
        self.assertIn("the 2 ticked instances are still there", notes[0])
        now = [{"label": "vm-a (2 days)", "commands": [], "disabled": "SHUTOFF since 2 min"}, {"label": "vm-c", "commands": ["live-migrate C2"]}]
        *_, problems = self.r.compare(fp, wanted + [{"label": "vm-z", "commands": ["live-migrate Z"]}],
                                      [(0, {"select": {"items": now}}, self.state([], items=now))])
        self.assertIn("vm-a (2 days) cannot run now: SHUTOFF since 2 min", problems[0])
        self.assertIn("vm-c: its commands changed", problems[0])
        self.assertIn("vm-z is no longer in the result", problems[0])

    def test_settings_range(self):
        for bad in (60, 4, 31, "x", None):
            with self.assertRaises(ValueError, msg=bad):
                self.r.save_settings({"minutes": bad}, "portaladmin")
        self.assertEqual(self.r.get_settings()["minutes"], 15)


class ReviewFlowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import portal_auth
        store = portal_auth.Store(os.environ["OPS_DB"])
        store.add_local_user("portaladmin", portal_auth.hash_password("demo-portal-admin"), "admin", "Admin", "", "test")
        store.add_local_user("l1", portal_auth.hash_password("demo-operator-1"), "operator", "L1", "", "test", "wi")
        store.add_local_user("fixer", portal_auth.hash_password("demo-operator-3"), "operator", "Fixer", "", "test", "wi,wi-fix")
        store.add_local_user("allmods", portal_auth.hash_password("demo-operator-4"), "operator", "All", "", "test", "*")
        store.add_local_user("engineer", portal_auth.hash_password("demo-engineer-1"), "operator", "Engineer", "", "test",
                             "wi,wi-fix-review")
        store.add_local_user("fixrev", portal_auth.hash_password("demo-engineer-2"), "operator", "Fixer and engineer", "", "test",
                             "wi,wi-fix,wi-fix-review")
        import app as webapp
        from modules import wi
        cls.app, cls.wi = webapp.app, wi
        admin = cls._login(cls, "portaladmin", "demo-portal-admin")
        cred = admin.post("/runbook/api/credentials", json={"name": "ops", "username": "root", "auth": "key", "privilege": "root",
                                                       "fixes": True, "secret": new_key()}).get_json()["id"]
        r = admin.post("/runbook/api/hosts/bulk", json={"site": "DCA", "group": "cdn", "credential_id": cred,
                                                   "lines": "dca-cdn-lb-02 172.31.138.68\ndca-cdn-lb-01 172.31.138.67"})
        assert r.get_json()["added"] == 2, r.get_json()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(TMP, ignore_errors=True)

    def setUp(self):
        with contextlib.closing(sqlite3.connect(os.environ["OPS_DB"])) as db, db:
            db.execute("DELETE FROM wi_fix_requests")
            db.execute("DELETE FROM wi_fix_review_settings")
        if os.path.exists(os.path.join(TMP, "hosts-state.json")):   # the fake hosts have their problems again
            os.remove(os.path.join(TMP, "hosts-state.json"))

    def tearDown(self):
        """Wait for what a test left running (the check after a fix starts once the fix has ended)."""
        deadline = time.time() + 300
        while time.time() < deadline:
            with contextlib.closing(sqlite3.connect(os.environ["OPS_DB"])) as db:
                busy = db.execute("SELECT COUNT(*) FROM wi_runs WHERE status = 'running'").fetchone()[0] + db.execute(
                    "SELECT COUNT(*) FROM wi_actions WHERE status = 'running' OR (status = 'ok' AND verify_run_id IS NULL)").fetchone()[0]
            if not busy and not self.wi.JOBS.running():
                return
            time.sleep(0.3)

    def _login(self, user, password):
        c = self.app.test_client()
        r = c.post("/api/login", json={"username": user, "password": password})
        assert r.status_code == 200, r.get_json()
        return c

    def client(self, user="portaladmin", password="demo-portal-admin"):
        return self._login(user, password)

    def wait(self, client, url, done, what):
        deadline = time.time() + 300
        while time.time() < deadline:
            item = client.get(url).get_json()["item"]
            if done(item):
                return item
            time.sleep(0.3)
        self.fail(f"{what} did not finish")

    def run_check(self, client, check, params):
        r = client.post("/runbook/api/runs", json={"site": "DCA", "check": check, "params": params})
        self.assertEqual(r.status_code, 200, r.get_json())
        return self.wait(client, f"/runbook/api/runs/{r.get_json()['run_id']}", lambda x: x["status"] != "running", "run")

    def request(self, client, run, index, body=None):
        r = client.post(f"/runbook/api/runs/{run['id']}/fixes/{index}", json=body or {})
        self.assertEqual(r.status_code, 200, r.get_json())
        data = r.get_json()
        self.assertNotIn("action_id", data)                                   # nothing runs yet
        return self.wait(client, f"/runbook/api/fix-requests/{data['request_id']}", lambda x: x["status"] != "prechecking", "pre-check")

    def wait_fix(self, client, action_id):
        return self.wait(client, f"/runbook/api/fixes/{action_id}",
                         lambda x: x["status"] != "running" and (x["verify_run_id"] or x["status"] != "ok"), "fix")

    def events(self, action):
        return [e for e in self.client().get("/api/admin/events?kinds=wi").get_json()["events"] if e["action"] == action]

    def waiting_metric(self):
        from modules.wi import alerts
        line = next(x for x in alerts.metrics().splitlines() if x.startswith('ops_fix_reviews_waiting{site="DCA"}'))
        return int(line.split()[-1])

    # ------------------------------------------------------------------------------------------------------------------
    def test_permission_on_the_users_page(self):
        import core
        perm = next(m for m in core.module_list() if m["id"] == "wi-fix-review")
        self.assertEqual((perm["permission_of"], perm["explicit"]), ("wi", True))
        self.assertIn("review fixes", perm["title"])
        allmods = self.client("allmods", "demo-operator-4").get("/runbook/api/session").get_json()
        self.assertFalse(allmods["can_review"])                               # "all modules" never gives it
        self.assertTrue(self.client("engineer", "demo-engineer-1").get("/runbook/api/session").get_json()["can_review"])
        self.assertTrue(self.client().get("/runbook/api/session").get_json()["can_review"])   # administrators
        self.assertEqual(allmods["review_minutes"], 15)

    def test_request_precheck_review_run(self):
        fixer, engineer, admin = self.client("fixer", "demo-operator-3"), self.client("engineer", "demo-engineer-1"), self.client()
        item = self.run_check(fixer, "cdn-datasource", {"host": "dca-cdn-lb-02"})
        idx = next(i for i, f in enumerate(item["fixes"]) if f)
        self.assertEqual(self.client("l1", "demo-operator-1").post(f"/runbook/api/runs/{item['id']}/fixes/{idx}", json={}).status_code, 403)
        self.assertEqual(engineer.post(f"/runbook/api/runs/{item['id']}/fixes/{idx}", json={}).status_code, 403)   # reviews, cannot run
        x = self.request(fixer, item, idx)
        self.assertEqual(x["status"], "waiting", x)
        self.assertEqual(x["state"], "Waiting for review")
        self.assertIn("same commands", " ".join(x["precheck_notes"]))
        self.assertIn("sudo docker start lb", x["precheck_commands"])
        pre = fixer.get(f"/runbook/api/runs/{x['precheck_run_id']}").get_json()["item"]
        self.assertEqual((pre["check_id"], pre["params"], pre["username"], pre["status"]), ("cdn-datasource", item["params"], "fixer", "fail"))
        self.assertEqual(pre["precheck_of"][0]["id"], x["id"])
        run = fixer.get(f"/runbook/api/runs/{item['id']}").get_json()["item"]
        self.assertEqual(run["actions"], [])                                   # nothing ran
        self.assertEqual(run["requests"][0]["id"], x["id"])
        self.assertTrue(run["requests"][0]["can_withdraw"] and not run["requests"][0]["can_run"])
        self.assertEqual(self.waiting_metric(), 1)
        self.assertEqual(fixer.get("/runbook/api/session").get_json()["reviews_waiting"], 1)
        # one open request per fix
        r = fixer.post(f"/runbook/api/runs/{item['id']}/fixes/{idx}", json={})
        self.assertEqual(r.status_code, 400)
        self.assertIn(f"Fix request #{x['id']} of this fix is already waiting for review", r.get_json()["error"])
        # who reviews: not the requester (no permission), nobody their own, a note to reject
        self.assertEqual(fixer.post(f"/runbook/api/fix-requests/{x['id']}/approve", json={}).status_code, 403)
        listed = engineer.get("/runbook/api/fix-requests?status=waiting").get_json()
        self.assertEqual([i["id"] for i in listed["items"]], [x["id"]])
        self.assertTrue(listed["items"][0]["can_review"] and listed["can_review"])
        r = engineer.post(f"/runbook/api/fix-requests/{x['id']}/reject", json={"note": " "})
        self.assertEqual(r.status_code, 400)
        self.assertIn("write why", r.get_json()["error"])
        r = engineer.post(f"/runbook/api/fix-requests/{x['id']}/approve", json={"note": "Checked Grafana: datasource down since 10:02"})
        self.assertEqual(r.status_code, 200, r.get_json())
        a = r.get_json()["item"]
        left = (datetime.datetime.fromisoformat(a["approved_until"]) - datetime.datetime.now().astimezone()).total_seconds()
        self.assertTrue(14 * 60 < left <= 15 * 60, left)
        self.assertEqual((a["status"], a["reviewed_by"]), ("approved", "engineer"))
        self.assertEqual(self.waiting_metric(), 0)
        self.assertEqual(engineer.post(f"/runbook/api/fix-requests/{x['id']}/approve", json={}).status_code, 400)   # once
        # Run now: only the requester
        self.assertEqual(engineer.post(f"/runbook/api/fix-requests/{x['id']}/run", json={}).status_code, 403)
        self.assertEqual(admin.post(f"/runbook/api/fix-requests/{x['id']}/run", json={}).status_code, 403)
        mine = fixer.get(f"/runbook/api/fix-requests/{x['id']}").get_json()["item"]
        self.assertTrue(mine["can_run"] and 0 < mine["seconds_left"] <= 900)
        r = fixer.post(f"/runbook/api/fix-requests/{x['id']}/run", json={})
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertEqual(r.get_json()["run_id"], item["id"])
        self.assertEqual(fixer.post(f"/runbook/api/fix-requests/{x['id']}/run", json={}).status_code, 400)   # never twice
        fix = self.wait_fix(fixer, r.get_json()["action_id"])
        self.assertEqual(fix["status"], "ok", fix)
        self.assertIn("sudo docker start lb", fix["commands"])
        self.assertEqual((fix["run_id"], fix["rec_index"]), (item["id"], idx))   # shown with the run it was asked from
        run = fixer.get(f"/runbook/api/runs/{item['id']}").get_json()["item"]
        self.assertEqual(run["actions"][0]["review"]["reviewed_by"], "engineer")
        self.assertEqual(run["requests"][0]["status"], "ran")
        again = self.wait(fixer, f"/runbook/api/runs/{fix['verify_run_id']}", lambda v: v["status"] != "running", "check after the fix")
        self.assertEqual(again["status"], "ok", again)
        # every step in the activity log
        for action, text in (("wi.fix_request", f"Fix request #{x['id']} of troubleshooting run #{item['id']}"),
                             ("wi.fix_precheck", f"pre-check run #{x['precheck_run_id']} passed"),
                             ("wi.fix_approve", "approved by engineer"), ("wi.fix", f"fix request #{x['id']}")):
            self.assertTrue(any(text in e["detail"] for e in self.events(action)), (action, self.events(action)))
        self.assertTrue(any("pre-check of fix request" in e["detail"] for e in self.events("wi.run")))
        # the problem is gone: asked again from the same (still recent) result, the pre-check fails
        x2 = self.request(fixer, item, idx)
        self.assertEqual(x2["status"], "precheck_failed", x2)
        self.assertIn("no longer offers this fix", x2["reason"])
        self.assertTrue(self.events("wi.fix_precheck")[0]["detail"].count("failed"))

    def test_nobody_reviews_their_own(self):
        fixrev, admin, engineer = self.client("fixrev", "demo-engineer-2"), self.client(), self.client("engineer", "demo-engineer-1")
        item = self.run_check(fixrev, "cdn-datasource", {"host": "dca-cdn-lb-02"})
        idx = next(i for i, f in enumerate(item["fixes"]) if f)
        x = self.request(fixrev, item, idx)
        listed = fixrev.get("/runbook/api/fix-requests?status=waiting").get_json()["items"][0]
        self.assertFalse(listed["can_review"])
        self.assertIn("another engineer", listed["why_not"])
        r = fixrev.post(f"/runbook/api/fix-requests/{x['id']}/approve", json={})
        self.assertEqual(r.status_code, 403)
        self.assertIn("nobody approves their own request", r.get_json()["error"])
        self.assertEqual(fixrev.post(f"/runbook/api/fix-requests/{x['id']}/reject", json={"note": "not mine"}).status_code, 403)
        # an administrator neither
        item2 = self.run_check(admin, "cdn-memory", {"host": "dca-cdn-lb-01"})
        idx2 = next(i for i, f in enumerate(item2["fixes"]) if f and f["risk"] == "high")
        y = self.request(admin, item2, idx2)
        self.assertEqual(y["status"], "waiting", y)
        self.assertEqual(admin.post(f"/runbook/api/fix-requests/{y['id']}/approve", json={}).status_code, 403)
        # someone else may: the administrator approves the engineer's, the engineer rejects the administrator's
        self.assertEqual(admin.post(f"/runbook/api/fix-requests/{x['id']}/approve", json={}).status_code, 200)
        r = engineer.post(f"/runbook/api/fix-requests/{y['id']}/reject", json={"note": "Customer has not approved the kill yet"})
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertEqual(r.get_json()["item"]["reason"], "Rejected by engineer: Customer has not approved the kill yet")
        r = admin.post(f"/runbook/api/fix-requests/{y['id']}/run", json={"confirm": "dca-cdn-lb-01"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("is rejected", r.get_json()["error"])
        self.assertTrue(any("Customer has not approved" in e["detail"] for e in self.events("wi.fix_reject")))
        # withdraw: only the requester
        self.assertEqual(engineer.post(f"/runbook/api/fix-requests/{x['id']}/withdraw", json={}).status_code, 403)
        self.assertEqual(fixrev.post(f"/runbook/api/fix-requests/{x['id']}/withdraw", json={}).get_json()["item"]["status"], "withdrawn")
        self.assertTrue(self.events("wi.fix_withdraw"))

    def test_high_risk_confirmation_at_run_now(self):
        fixer, engineer = self.client("fixer", "demo-operator-3"), self.client("engineer", "demo-engineer-1")
        item = self.run_check(fixer, "cdn-memory", {"host": "dca-cdn-lb-01"})
        idx = next(i for i, f in enumerate(item["fixes"]) if f and f["risk"] == "high")
        x = self.request(fixer, item, idx)                                    # asked without typing anything
        self.assertEqual((x["status"], x["risk"]), ("waiting", "high"), x)
        self.assertEqual(engineer.post(f"/runbook/api/fix-requests/{x['id']}/approve", json={}).status_code, 200)
        r = fixer.post(f"/runbook/api/fix-requests/{x['id']}/run", json={"confirm": "wrong"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("type the host name dca-cdn-lb-01", r.get_json()["error"])
        self.assertEqual(fixer.get(f"/runbook/api/fix-requests/{x['id']}").get_json()["item"]["status"], "approved")   # still
        r = fixer.post(f"/runbook/api/fix-requests/{x['id']}/run", json={"confirm": "dca-cdn-lb-01"})
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertEqual(self.wait_fix(fixer, r.get_json()["action_id"])["status"], "ok")

    def test_expiry_and_the_time_set(self):
        fixer, engineer, admin = self.client("fixer", "demo-operator-3"), self.client("engineer", "demo-engineer-1"), self.client()
        self.assertEqual(fixer.put("/runbook/api/fix-requests/settings", json={"minutes": 10}).status_code, 403)
        r = admin.put("/runbook/api/fix-requests/settings", json={"minutes": 60})
        self.assertEqual(r.status_code, 400)
        self.assertIn("5 to 30 minutes", r.get_json()["error"])
        self.assertEqual(admin.put("/runbook/api/fix-requests/settings", json={"minutes": 10}).get_json()["settings"]["minutes"], 10)
        self.assertTrue(any("15 → 10 minutes" in e["detail"] for e in self.events("wi.fix_review_settings")))
        item = self.run_check(fixer, "cdn-datasource", {"host": "dca-cdn-lb-02"})
        idx = next(i for i, f in enumerate(item["fixes"]) if f)
        x = self.request(fixer, item, idx)
        a = engineer.post(f"/runbook/api/fix-requests/{x['id']}/approve", json={}).get_json()["item"]
        left = (datetime.datetime.fromisoformat(a["approved_until"]) - datetime.datetime.now().astimezone()).total_seconds()
        self.assertTrue(9 * 60 < left <= 10 * 60, left)
        past = (datetime.datetime.now().astimezone() - datetime.timedelta(seconds=5)).isoformat(timespec="seconds")
        with contextlib.closing(sqlite3.connect(os.environ["OPS_DB"])) as db, db:
            db.execute("UPDATE wi_fix_requests SET approved_until = ? WHERE id = ?", (past, x["id"]))
        r = fixer.post(f"/runbook/api/fix-requests/{x['id']}/run", json={})
        self.assertEqual(r.status_code, 400)
        self.assertIn("is expired: The approval by engineer ended", r.get_json()["error"])
        self.assertIn("new pre-check and review", r.get_json()["error"])
        self.assertEqual(len(self.events("wi.fix_expired")), 1)
        # waiting with a pre-check no longer recent: expires too, and is not counted
        y = self.request(fixer, item, idx)
        old = (datetime.datetime.now().astimezone() - datetime.timedelta(minutes=121)).isoformat(timespec="seconds")
        with contextlib.closing(sqlite3.connect(os.environ["OPS_DB"])) as db, db:
            db.execute("UPDATE wi_fix_requests SET precheck_finished = ? WHERE id = ?", (old, y["id"]))
        self.assertEqual(self.waiting_metric(), 0)
        r = engineer.post(f"/runbook/api/fix-requests/{y['id']}/approve", json={})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(engineer.get(f"/runbook/api/fix-requests/{y['id']}").get_json()["item"]["status"], "expired")
        self.assertEqual(len(self.events("wi.fix_expired")), 2)

    def test_busy_check_refuses_the_precheck(self):
        fixer = self.client("fixer", "demo-operator-3")
        item = self.run_check(fixer, "cdn-datasource", {"host": "dca-cdn-lb-02"})
        idx = next(i for i, f in enumerate(item["fixes"]) if f)
        r = fixer.post("/runbook/api/runs", json={"site": "DCA", "check": "cdn-datasource", "params": item["params"]})
        r2 = fixer.post(f"/runbook/api/runs/{item['id']}/fixes/{idx}", json={})
        self.assertEqual(r2.status_code, 400)
        self.assertIn("The pre-check cannot start now", r2.get_json()["error"])
        self.assertEqual(fixer.get("/runbook/api/fix-requests").get_json()["total"], 0)   # nothing recorded
        self.wait(fixer, f"/runbook/api/runs/{r.get_json()['run_id']}", lambda v: v["status"] != "running", "run")

    def test_template_change_steps_need_review(self):
        admin, fixer, engineer = self.client(), self.client("fixer", "demo-operator-3"), self.client("engineer", "demo-engineer-1")
        r = admin.post("/runbook/api/templates", json={
            "name": "AIDE files on /run", "activity": "troubleshoot", "category": "cdn", "group": "cdn",
            "steps": [{"title": "Usage of /run", "command": "df -Pk /run", "problem_if": "9[0-9]%"},
                      {"title": "Delete the AIDE files", "command": "sudo rm -rf /run/aide/*"}]})
        self.assertEqual(r.status_code, 200, r.get_json())
        item = self.run_check(fixer, r.get_json()["id"], {"host": "dca-cdn-lb-01"})
        idx = next(i for i, f in enumerate(item["fixes"]) if f)
        self.assertEqual(item["fixes"][idx]["risk"], "high")
        x = self.request(fixer, item, idx)
        self.assertEqual(x["status"], "waiting", x)
        self.assertEqual(fixer.get(f"/runbook/api/runs/{item['id']}").get_json()["item"]["actions"], [])
        engineer.post(f"/runbook/api/fix-requests/{x['id']}/approve", json={})
        r = fixer.post(f"/runbook/api/fix-requests/{x['id']}/run", json={"confirm": "dca-cdn-lb-01"})
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertEqual(self.wait_fix(fixer, r.get_json()["action_id"])["status"], "ok")

    def test_alert_actions_do_not_wait_for_review(self):
        """An automatic action of an alert rule (HOOKS start_fix, as the robot grafana): the owner approved it on the rule."""
        from modules.wi import alerts, hosts, runs
        fixer = self.client("fixer", "demo-operator-3")
        item = self.run_check(fixer, "cdn-datasource", {"host": "dca-cdn-lb-02"})
        idx = next(i for i, f in enumerate(item["fixes"]) if f)
        action_id = alerts.HOOKS["start_fix"](runs.get(item["id"]), idx, alerts.robot(fix=True), "127.0.0.1", "rule Test, alert #1")
        self.assertTrue(action_id)
        self.assertEqual(hosts.action(action_id)["username"], alerts.ROBOT)
        self.assertEqual(fixer.get("/runbook/api/fix-requests").get_json()["total"], 0)
        self.assertEqual(self.wait_fix(fixer, action_id)["status"], "ok")


if __name__ == "__main__":
    unittest.main()

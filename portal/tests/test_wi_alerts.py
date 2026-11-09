"""Grafana alerts (modules/wi/alerts.py): the receiver and its tokens, rules (labels, templates, site, several checks,
cooldown), resolved alerts, fixes that run by themselves (what may, the confirmation, the limits), the check after them,
and who may see and change what.

Run from the portal folder:
    .venv/bin/python -m unittest tests.test_wi_alerts -v
"""
import base64
import contextlib
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

TMP = tempfile.mkdtemp()
with open(os.path.join(TMP, "sites.yml"), "w") as f:
    f.write("""sites:
  DCB:
    mgmt: {host: 10.253.70.11, user: admin, private_key: /etc/ops-portal/keys/openstack_mgmt}
    director: {host: 10.253.70.101, user: stack}
    hosts:
      cdn: {user: wi-ro, private_key: /etc/ops-portal/keys/wi_ro, members: {dcb-cdn-01: 172.31.10.67}}
  DCA:
    mgmt: {host: 10.253.51.11, user: admin, private_key: /etc/ops-portal/keys/openstack_mgmt}
    director: {host: 10.253.51.101, user: stack}
""")
with open(os.path.join(TMP, "auth.yml"), "w") as f:
    f.write("admins: []\n")
os.environ.update(PORTAL_SITES=os.path.join(TMP, "sites.yml"), PORTAL_DATA=os.path.join(TMP, "data"),
                  PORTAL_DB=os.path.join(TMP, "data", "portal.db"), PORTAL_AUTH=os.path.join(TMP, "auth.yml"),
                  PORTAL_CREDENTIALS_KEY=os.path.join(TMP, "credentials.key"), PORTAL_MODULES="wi")


def alert(name="CDN root disk full", status="firing", fingerprint="fp-1", **labels):
    labels = {"alertname": name, "site": "dcb", "instance": "172.31.10.67:9100", "severity": "critical", **labels}
    return {"status": status, "labels": labels, "annotations": {"summary": "Root disk above 90%"},
            "startsAt": "2026-11-06T21:00:00+07:00", "endsAt": "0001-01-01T00:00:00Z", "fingerprint": fingerprint,
            "generatorURL": "https://grafana.example/alerting/x/edit", "values": {"B": 93.5}}


def notification(*items, status="firing"):
    return {"receiver": "portal", "status": status, "orgId": 1, "alerts": list(items), "groupLabels": {}, "commonLabels": {},
            "commonAnnotations": {}, "externalURL": "https://grafana.example/", "version": "1", "groupKey": "{}:{}",
            "truncatedAlerts": 0}


RECORD_RECS = [
    {"text": "Create the HAProxy logrotate rule so the log cannot grow without limit again, test it.",
     "action": {"commands": ["sudo tee /etc/logrotate.d/haproxy", "sudo logrotate -f /etc/logrotate.d/haproxy"]}},
    {"text": "Empty /var/log/haproxy.log (12.4 GB) with truncate — the file stays.",
     "action": {"commands": ["sudo truncate -s 0 /var/log/haproxy.log"]}},
    {"text": "The largest consumer is not a known log: look at it before deleting anything.", "commands": ["sudo du -xh /"]},
]


class AlertsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import portal_auth
        store = portal_auth.Store(os.environ["PORTAL_DB"])
        store.add_local_user("portaladmin", portal_auth.hash_password("demo-portal-admin"), "admin", "Admin", "", "test")
        store.add_local_user("operator1", portal_auth.hash_password("demo-operator-1"), "operator", "Op", "", "test", "wi")
        import app as webapp
        from core import PORTAL
        from modules import wi
        from modules.wi import alerts
        cls.app, cls.PORTAL, cls.wi, cls.alerts = webapp.app, PORTAL, wi, alerts

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(TMP, ignore_errors=True)

    def setUp(self):
        with contextlib.closing(sqlite3.connect(os.environ["PORTAL_DB"])) as db, db:
            for table in ("wi_alert_sources", "wi_alert_rules", "wi_alert_events", "wi_alert_fixes_seen", "wi_alert_settings"):
                db.execute(f"DELETE FROM {table}")
        self.alerts._rate.clear()
        self.started, self.fixed = [], []
        self.runs = {}
        self.next_run = 100
        hooks = dict(self.alerts.HOOKS)
        self.addCleanup(self.alerts.HOOKS.update, hooks)
        self.alerts.HOOKS.update(start_check=self.fake_start, get_run=lambda rid: self.runs.get(rid),
                                 fix_state=self.fake_state, start_fix=self.fake_fix)
        self.admin = self.client()

    # ---- fakes of the Operation Automation module (a real check runs Ansible: tests/test_wi.py)
    def fake_start(self, site, check, raw, client):
        self.next_run += 1
        self.started.append((site, check["id"], raw))
        return self.next_run

    def fake_state(self, record, index, rec, user):
        commands = rec["action"]["commands"]
        risk = "high" if any("truncate" in c for c in commands) else "normal"
        return {"available": True, "reason": "", "risk": risk, "target": "dcb-cdn-01", "kind": "host", "commands": commands}

    def fake_fix(self, record, index, user, client, note):
        self.fixed.append((record["id"], index, user["username"], fixed_modules(user), note))
        return 500 + len(self.fixed)

    def client(self, user="portaladmin", password="demo-portal-admin"):
        c = self.app.test_client()
        r = c.post("/api/login", json={"username": user, "password": password})
        self.assertEqual(r.status_code, 200, r.get_json())
        return c

    def source(self, networks=""):
        r = self.admin.post("/wi/api/alerts/sources", json={"name": "Grafana SRE", "networks": networks})
        self.assertEqual(r.status_code, 200, r.get_json())
        return r.get_json()["id"], r.get_json()["token"]

    def send(self, token, body, auth=None):
        headers = {"Authorization": auth if auth is not None else f"Bearer {token}"}
        return self.app.test_client().post("/wi/api/alerts/grafana", data=json.dumps(body), headers=headers,
                                           content_type="application/json")

    def rule(self, **kw):
        data = {"name": "CDN root disk", "alertname": "CDN root disk*", "matchers": "severity=critical", "site": "{{labels.site}}",
                "checks": [{"check_id": "cdn-root-disk", "params": {"host": "{{labels.instance|host}}"}}], "cooldown": 30, **kw}
        r = self.admin.post("/wi/api/alerts/rules", json=data)
        self.assertEqual(r.status_code, 200, r.get_json())
        return r.get_json()["id"], data

    def events(self):
        return self.admin.get("/wi/api/alerts?limit=200").get_json()["items"]

    def finish(self, run_id=None, status="fail", recs=None):
        """The check of the newest alert (or run_id) ends with this status and the recommendations of RECORD_RECS."""
        run_id = run_id or self.events()[0]["run_id"]
        self.runs[run_id] = {"id": run_id, "site": "DCB", "check_id": "cdn-root-disk", "status": status, "params": {"host": "dcb-cdn-01"},
                             "summary": "Root disk 93% used", "result": {"recommendations": RECORD_RECS if recs is None else recs}}
        self.alerts.run_finished(run_id, status)

    # ---- the receiver
    def test_the_receiver_needs_the_token_of_a_source_and_keeps_only_its_hash(self):
        source_id, token = self.source()
        self.assertTrue(token.startswith("gfa_"))
        body = notification(alert(name="Something else"))
        self.assertEqual(self.send(token, body, auth="").status_code, 401)
        self.assertEqual(self.send("gfa_wrong", body).status_code, 401)
        r = self.send(token, body)
        self.assertEqual((r.status_code, r.get_json()["alerts"]), (200, 1))
        basic = "Basic " + base64.b64encode(f"grafana:{token}".encode()).decode()   # Basic auth: the token is the password
        self.assertEqual(self.send(token, body, auth=basic).status_code, 200)
        self.assertEqual(self.send(token, {"no": "alerts"}).status_code, 400)
        with contextlib.closing(sqlite3.connect(os.environ["PORTAL_DB"])) as db:
            dump = "\n".join(str(row) for row in db.execute("SELECT * FROM wi_alert_sources"))
        self.assertNotIn(token, dump)
        # Allowed addresses: the test client comes from 127.0.0.1.
        self.admin.put(f"/wi/api/alerts/sources/{source_id}", json={"name": "Grafana SRE", "networks": "10.253.0.0/8", "enabled": True})
        self.assertEqual(self.send(token, body).status_code, 403)
        self.admin.put(f"/wi/api/alerts/sources/{source_id}", json={"name": "Grafana SRE", "networks": "127.0.0.1", "enabled": True})
        self.assertEqual(self.send(token, body).status_code, 200)
        # A new token: the old one stops working at once; a disabled source is refused.
        new = self.admin.post(f"/wi/api/alerts/sources/{source_id}/token").get_json()["token"]
        self.assertEqual(self.send(token, body).status_code, 401)
        self.assertEqual(self.send(new, body).status_code, 200)
        self.admin.put(f"/wi/api/alerts/sources/{source_id}", json={"name": "Grafana SRE", "networks": "", "enabled": False})
        self.assertEqual(self.send(new, body).status_code, 401)
        listed = self.admin.get("/wi/api/alerts/config").get_json()["sources"][0]
        self.assertEqual((listed["token_tail"], listed["last_ip"]), (new[-4:], "127.0.0.1"))
        self.assertNotIn("token_hash", listed)
        actions = [e["action"] for e in self.PORTAL.store.events()]
        self.assertIn("wi.alert_source", actions)

    def test_too_many_alerts_in_a_minute_are_refused(self):
        _sid, token = self.source()
        with mock.patch.object(self.alerts, "RATE_PER_MINUTE", 3):
            self.assertEqual(self.send(token, notification(alert(), alert(fingerprint="fp-2"))).status_code, 200)
            self.assertEqual(self.send(token, notification(alert(), alert(fingerprint="fp-2"))).status_code, 429)

    # ---- rules
    def test_a_rule_runs_its_check_with_parameters_from_the_labels_once_per_cooldown(self):
        _sid, token = self.source()
        self.rule()
        r = self.send(token, notification(alert()))
        self.assertEqual(r.get_json(), {"ok": True, "alerts": 1, "checks": 1})
        self.assertEqual(self.started, [("DCB", "cdn-root-disk", {"host": "172.31.10.67"})])
        ev = self.events()[0]
        self.assertEqual((ev["state"], ev["run_id"], ev["site"], ev["params"], ev["rule_name"], ev["check_id"], ev["check_title"]),
                         ("checking", 101, "DCB", {"host": "dcb-cdn-01"}, "CDN root disk", "cdn-root-disk",
                          self.wi.catalog.get("cdn-root-disk")["title"]))
        self.assertEqual(ev["value_text"], "B=93.5")
        # Grafana sends the group again (group interval, repeat interval): the same check of the rule waits its cooldown.
        self.send(token, notification(alert()))
        self.assertEqual(len(self.started), 1)
        self.assertEqual(self.events()[0]["state"], "duplicate")
        self.assertIn("run #101", self.events()[0]["outcome"])
        # Another host is another check.
        self.send(token, notification(alert(fingerprint="fp-9", instance="dcb-cdn-01")))
        self.assertEqual(len(self.started), 1)   # the same host by name: still the cooldown
        # No rule, a site the portal does not know, a label the rule needs, a busy check.
        self.send(token, notification(alert(name="Disk almost full"), alert(site="mars", fingerprint="fp-3"),
                                      alert(fingerprint="fp-4", instance=""), alert(severity="warning", fingerprint="fp-5")))
        outcomes = {(e["fingerprint"], e["state"]): e["outcome"] for e in self.events()}
        self.assertEqual(outcomes[("fp-1", "no-rule")], "No rule matches this alert.")
        self.assertIn("No site for 'mars'", outcomes[("fp-3", "refused")])
        self.assertIn("The alert has no label instance", outcomes[("fp-4", "refused")])
        self.assertEqual(outcomes[("fp-5", "no-rule")], "No rule matches this alert.")   # severity=critical only
        with mock.patch.dict(self.alerts.HOOKS, start_check=mock.Mock(side_effect=ValueError("The same check ... is already running."))):
            self.admin.put(f"/wi/api/alerts/rules/{self.alerts.rules()[0]['id']}", json=dict(self.rule_data(), cooldown=0))
            self.send(token, notification(alert(fingerprint="fp-6")))
        self.assertEqual(self.events()[0]["state"], "duplicate")

    def rule_data(self):
        r = self.alerts.rules()[0]
        return {"name": r["name"], "alertname": r["alertname"], "matchers": [f"{m['label']}{m['op']}{m['value']}" for m in r["matchers"]],
                "site": r["site"], "checks": r["checks"], "cooldown": r["cooldown"],
                "auto_fixes": r["auto_fixes"], "auto_per_hour": r["auto_per_hour"], "enabled": r["enabled"]}

    def test_one_alert_runs_every_check_of_its_rule(self):
        _sid, token = self.source()
        host = {"host": "{{labels.instance|host}}"}
        self.rule(checks=[{"check_id": "cdn-root-disk", "params": host}, {"check_id": "cdn-memory", "params": host},
                          {"check_id": "linux-resources", "params": {"host": "{{labels.instance|host}}", "disk_warn": "70"}}])
        r = self.send(token, notification(alert()))
        self.assertEqual(r.get_json()["checks"], 3)
        self.assertEqual([(c[1], c[2]) for c in self.started], [("cdn-root-disk", {"host": "172.31.10.67"}), ("cdn-memory", {"host": "172.31.10.67"}),
                                                                ("linux-resources", {"host": "172.31.10.67", "disk_warn": "70"})])
        rows = {e["check_id"]: e for e in self.events()}
        self.assertEqual({k: (v["state"], v["run_id"]) for k, v in rows.items()},
                         {"cdn-root-disk": ("checking", 101), "cdn-memory": ("checking", 102), "linux-resources": ("checking", 103)})
        params = rows["linux-resources"]["params"]   # cleaned: the host by name, numbers, defaults of the check
        self.assertEqual((params["host"], params["disk_warn"], params["disk_fail"]), ("dcb-cdn-01", 70, 90))
        # The cooldown is per check: again, nothing runs; a check that cannot run does not stop the others.
        self.send(token, notification(alert()))
        self.assertEqual(len(self.started), 3)
        self.assertEqual([e["state"] for e in self.events()[:3]], ["duplicate"] * 3)
        rid = self.alerts.rules()[0]["id"]
        self.admin.put(f"/wi/api/alerts/rules/{rid}", json=dict(self.rule_data(), cooldown=0, checks=[
            {"check_id": "cdn-root-disk", "params": host}, {"check_id": "cdn-memory", "params": {"host": "nowhere-01"}}]))
        self.send(token, notification(alert()))
        self.assertEqual([(e["check_id"], e["state"]) for e in self.events()[:2]], [("cdn-memory", "refused"), ("cdn-root-disk", "checking")])
        # Each run ends on its own: its fixes are noted per check.
        self.finish(101)
        self.assertEqual({f["check_id"] for f in self.alerts.fixes_seen(rid)}, {"cdn-root-disk"})

    def test_a_flood_of_alerts_runs_at_most_max_checking_checks_at_once(self):
        _sid, token = self.source()
        self.rule(cooldown=0)
        with mock.patch.object(self.alerts, "MAX_CHECKING", 2):
            self.send(token, notification(*[alert(fingerprint=f"f{i}") for i in range(3)]))
            self.assertEqual(len(self.started), 2)
            self.assertIn("2 checks of alerts are running", self.events()[0]["outcome"])
            self.finish(self.events()[1]["run_id"], status="ok")   # one ends: the next alert runs again
            self.send(token, notification(alert(fingerprint="f9")))
            self.assertEqual(len(self.started), 3)

    def test_rule_form_is_checked_and_previewed_with_a_received_alert(self):
        _sid, token = self.source()
        disk = lambda **params: [{"check_id": "cdn-root-disk", "params": params}]   # noqa: E731
        bad = [({"checks": [{"check_id": "collect-logs"}]}, "Choose checks"), ({"site": "MARS"}, "Unknown site"), ({"checks": []}, "1-10 checks"),
               ({"checks": disk(host="{{labels.instance|ip}}")}, "Unknown filter |ip"), ({"checks": disk(nope="x")}, "has no parameter nope"),
               ({"matchers": "severity~critical"}, "Label matcher"), ({"matchers": "x=~("}, "Label matcher x"),
               ({"checks": disk(host="{{label.instance}}")}, "Unknown placeholder"), ({"checks": disk() + disk()}, "twice in the rule")]
        for change, message in bad:
            with self.subTest(change=change):
                data = {"name": "R", "alertname": "*", "site": "DCB", "checks": disk(), **change}
                r = self.admin.post("/wi/api/alerts/rules", json=data)
                self.assertEqual(r.status_code, 400)
                self.assertIn(message, r.get_json()["error"])
        self.send(token, notification(alert(site="dcb-openstack")))   # no rule yet: recorded with its labels
        eid = self.events()[0]["id"]
        data = {"name": "R", "alertname": "CDN*", "site": "{{labels.site}}",
                "checks": [{"check_id": "cdn-root-disk", "params": {"host": "{{labels.instance|host}}"}},
                           {"check_id": "cdn-memory", "params": {"host": "{{labels.instance}}x"}}]}
        p = self.admin.post("/wi/api/alerts/rules/preview", json={"rule": data, "event_id": eid}).get_json()["preview"]
        self.assertEqual((p["matches"], p["site"], p["error"]), (True, "DCB", ""))   # "dcb-openstack" → DCB
        self.assertEqual([(c["check_id"], c["params"]) for c in p["checks"]], [("cdn-root-disk", {"host": "dcb-cdn-01"}), ("cdn-memory", {})])
        self.assertIn("not a cdn host of DCB", p["checks"][1]["error"])

    def test_templates_matchers_and_sites(self):
        a = self.alerts
        ctx = {"labels": {"alertname": "X", "instance": "https://Edge-01.dcb.example:9100/metrics", "ip6": "[fe80::1]:9100"},
               "annotations": {"summary": "s"}}
        self.assertEqual(a.render("{{labels.instance|host}}", ctx), "Edge-01.dcb.example")
        self.assertEqual(a.render("{{ labels.instance | short | lower }}", ctx), "edge-01")
        self.assertEqual(a.render("{{labels.ip6|host}}", ctx), "fe80::1")
        self.assertEqual(a.render("{{alertname}}: {{annotations.summary}}", ctx), "X: s")
        rule = {"alertname": "cinder*", "matchers": a.parse_matchers("severity=~crit.*\nteam!=dns, env!~dev|test")}
        self.assertTrue(a.matches(rule, {"alertname": "Cinder volume over 80%", "severity": "critical", "team": "ops", "env": "prod"}))
        self.assertFalse(a.matches(rule, {"alertname": "Cinder volume over 80%", "severity": "critical", "team": "dns", "env": "prod"}))
        self.assertFalse(a.matches(rule, {"alertname": "Cinder volume over 80%", "severity": "critical", "env": "dev"}))
        self.assertFalse(a.matches(rule, {"alertname": "Datastore low", "severity": "critical"}))
        site = lambda value: a.site_of({"site": value}, {"labels": {}, "annotations": {}})   # noqa: E731
        self.assertEqual((site("dca"), site("DCA-OPENSTACK")), ("DCA", "DCA"))
        with self.assertRaises(ValueError):
            site("dcb-dca")   # two sites: refused rather than guessed

    def test_a_resolved_alert_closes_the_alerts_it_resolves(self):
        _sid, token = self.source()
        self.rule()
        self.send(token, notification(alert()))
        self.send(token, notification(alert(status="resolved"), status="resolved"))
        items = self.events()
        self.assertEqual(len(items), 1)
        self.assertTrue(items[0]["resolved"])
        self.send(token, notification(alert(status="resolved", fingerprint="never-seen"), status="resolved"))
        self.assertEqual(self.events()[0]["state"], "resolved")

    # ---- fixes by themselves
    def test_only_safe_fixes_can_run_by_themselves(self):
        a = self.alerts
        host = {"available": True, "risk": "normal", "kind": "host", "commands": ["sudo logrotate -f /etc/logrotate.d/haproxy"]}
        self.assertEqual(a.auto_reason(host, {}), "")
        self.assertIn("OpenStack", a.auto_reason(dict(host, kind="openstack"), {}))
        self.assertIn("ONTAP", a.auto_reason(dict(host, kind="ontap"), {}))
        self.assertIn("VyOS", a.auto_reason(dict(host, kind="vyos_upgrade"), {}))
        self.assertIn("ticked items", a.auto_reason(dict(host, selectable=True), {}))
        self.assertIn("template", a.auto_reason(host, {"operation": True}))
        self.assertIn("High risk", a.auto_reason(dict(host, risk="high"), {}))
        for command in ("sudo iptables -I INPUT 1 -p tcp --dport 443 -j ACCEPT", "sudo nft insert rule inet filter input tcp dport 22 accept",
                        "sudo ip link set eth0 up", "sudo apt-get install -y x", "sudo usermod -aG wheel bob", "sudo mount -a"):
            with self.subTest(command=command):
                self.assertIn("firewall, network", a.auto_reason(dict(host, commands=[command]), {}))
        # The same fix in every result: numbers do not change its key.
        self.assertEqual(a.fix_key("c", {"text": "Empty /var/log/x (12.4 GB) now."}), a.fix_key("c", {"text": "Empty /var/log/x (3 GB) now."}))
        self.assertNotEqual(a.fix_key("c", {"text": "Empty /var/log/x."}), a.fix_key("d", {"text": "Empty /var/log/x."}))

    def test_an_allowed_fix_runs_by_itself_with_limits_and_the_check_after_it(self):
        _sid, token = self.source()
        rule_id, data = self.rule(cooldown=0)
        self.send(token, notification(alert()))
        self.finish()
        self.assertEqual(self.fixed, [])   # nothing allowed yet: the fixes are only noted
        seen = {f["title"]: f for f in self.admin.get("/wi/api/alerts/config").get_json()["rules"][0]["fixes_seen"]}
        logrotate = seen["Create the HAProxy logrotate rule so the log cannot grow without limit again, test it."]
        truncate = seen["Empty /var/log/haproxy.log (12.4 GB) with truncate — the file stays."]
        self.assertEqual(len(seen), 2)   # the recommendation without a fix is not listed
        self.assertTrue(logrotate["eligible"])
        self.assertFalse(truncate["eligible"])
        self.assertIn("High risk", truncate["reason"])
        # Allowing: only a fix that may, with the rule name typed.
        r = self.admin.put(f"/wi/api/alerts/rules/{rule_id}", json=dict(data, auto_fixes=[truncate["key"]], confirm="CDN root disk"))
        self.assertEqual(r.status_code, 400)
        r = self.admin.put(f"/wi/api/alerts/rules/{rule_id}", json=dict(data, auto_fixes=[logrotate["key"]]))
        self.assertIn("type the rule name", r.get_json()["error"])
        r = self.admin.put(f"/wi/api/alerts/rules/{rule_id}", json=dict(data, auto_fixes=[logrotate["key"]], confirm="CDN root disk"))
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertIn("may now run by itself: Create the HAProxy logrotate rule",
                      next(e["detail"] for e in self.PORTAL.store.events() if e["action"] == "wi.alert_rule"))
        # The next alert: the check, then the allowed fix by itself, as "grafana" with the right to run fixes.
        self.send(token, notification(alert()))
        self.finish()
        self.assertEqual(self.fixed, [(self.events()[0]["run_id"], 0, "grafana", ["wi", "wi-fix"], f"alert rule CDN root disk (alert #{self.events()[0]['id']})")])
        ev = self.events()[0]
        self.assertEqual((ev["fix_id"], ev["fix_status"]), (501, "running"))
        self.assertIn("Fix #501 started by itself", ev["outcome"])
        # It ends, the check runs again (run 900) and says OK.
        self.alerts.fix_finished(501, "ok", "", 900)
        self.alerts.run_finished(900, "ok")
        ev = self.events()[0]
        self.assertEqual((ev["fix_status"], ev["verify_run_id"], ev["verify_status"]), ("ok", 900, "ok"))
        self.assertEqual(ev["outcome"], "Checked: Problem found. Fix #501 ran by itself; the check after it: OK.")
        # The alert comes back: no second automatic fix of the same fix on the same host within AUTO_AGAIN_HOURS.
        self.send(token, notification(alert()))
        self.finish()
        self.assertEqual(len(self.fixed), 1)
        self.assertIn("came back after the automatic fix #501", self.events()[0]["outcome"])
        # A result without a problem never fixes anything; paused automatic fixes wait for an operator.
        with mock.patch.object(self.alerts, "AUTO_AGAIN_HOURS", 0):
            self.send(token, notification(alert()))
            self.finish(status="ok")
            self.assertEqual(len(self.fixed), 1)
            self.admin.put("/wi/api/alerts/settings", json={"auto_fix": False})
            self.send(token, notification(alert()))
            self.finish()
            self.assertEqual(len(self.fixed), 1)
            self.assertIn("paused", self.events()[0]["outcome"])
            self.admin.put("/wi/api/alerts/settings", json={"auto_fix": True})
            # At most auto_per_hour automatic fixes of a rule an hour.
            self.admin.put(f"/wi/api/alerts/rules/{rule_id}", json=dict(self.rule_data(), auto_per_hour=2))
            for _ in range(2):
                self.send(token, notification(alert()))
                self.finish()
            self.assertEqual(len(self.fixed), 2)
            self.assertIn("2 automatic fixes of this rule in the last hour", self.events()[0]["outcome"])
        # A check taken out of the rule takes its allowed and seen fixes with it.
        r = self.admin.put(f"/wi/api/alerts/rules/{rule_id}", json=dict(self.rule_data(), checks=[{"check_id": "cdn-memory", "params": {}}]))
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertEqual((self.alerts.rule(rule_id)["auto_fixes"], self.alerts.fixes_seen(rule_id)), ([], []))

    def test_the_real_hooks_run_the_check_and_the_fix_as_grafana(self):
        real = _real_hooks()
        self.alerts.HOOKS.update(start_check=real["start_check"], start_fix=real["start_fix"])
        with mock.patch.object(self.wi, "start_run", return_value=(77, "job")) as start_run:
            from modules.wi import catalog
            self.assertEqual(self.alerts.HOOKS["start_check"]("DCB", catalog.get("cdn-root-disk"), {"host": "x"}, "10.253.0.9"), 77)
        user = start_run.call_args.args[0]
        self.assertEqual((user["username"], user["role"], user["modules"]), ("grafana", "operator", ["wi"]))
        with mock.patch.object(self.wi, "launch_fix", return_value={"action_id": 9, "job_id": "j"}) as launch:
            self.assertEqual(self.alerts.HOOKS["start_fix"]({"id": 77}, 0, self.alerts.robot(True), "10.253.0.9", "alert rule X"), 9)
        self.assertEqual(launch.call_args.args[3], {})   # no confirmation: only normal-risk fixes run by themselves
        self.assertEqual(launch.call_args.kwargs["note"], "alert rule X")

    # ---- who sees and changes what
    def test_operators_see_alerts_and_administrators_manage_them(self):
        op = self.client("operator1", "demo-operator-1")
        self.assertEqual(op.get("/wi/api/alerts").status_code, 200)
        self.assertFalse(op.get("/wi/api/alerts").get_json()["connected"])
        for method, url in (("get", "/wi/api/alerts/config"), ("post", "/wi/api/alerts/rules"), ("post", "/wi/api/alerts/sources"),
                            ("put", "/wi/api/alerts/settings"), ("post", "/wi/api/alerts/rules/preview")):
            with self.subTest(url=url):
                self.assertEqual(getattr(op, method)(url, json={}).status_code, 403)
        self.assertEqual(self.app.test_client().get("/wi/api/alerts").status_code, 401)


def fixed_modules(user):
    return list(user.get("modules") or [])


def _real_hooks():
    """The hooks modules/wi sets (setUp replaces them with fakes)."""
    from modules import wi
    saved = dict(wi.alerts.HOOKS)
    wi._alert_hooks()
    real = dict(wi.alerts.HOOKS)
    wi.alerts.HOOKS.update(saved)
    return real


if __name__ == "__main__":
    unittest.main()

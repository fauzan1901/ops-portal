"""Grafana alerts (modules/wi/alerts.py): the receiver and its tokens, rules (labels, templates, site, several checks,
cooldown), resolved alerts, automatic actions (the loop: one item, measure, stop when the problem is gone / at the
maximum / at the first failure; the order of the items; the owner's approval of customer-impacting fixes; frozen sites;
one action per target; the switch; the limits; never on VMware Cloud / ESXi / a database), and who may see and change
what; senders accepted without a token from exact addresses of a source, and the samples of notifications the portal
could not read.

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
    mgmt: {host: 10.253.198.11, user: admin, private_key: /etc/ops-portal/keys/openstack_mgmt}
    director: {host: 10.253.198.101, user: stack}
    hosts:
      cdn: {user: runbook-ro, private_key: /etc/ops-portal/keys/wi_ro, members: {dcb-cdn-01: 172.31.138.67}}
  DCA:
    mgmt: {host: 10.253.179.11, user: admin, private_key: /etc/ops-portal/keys/openstack_mgmt}
    director: {host: 10.253.179.101, user: stack}
  LAB: {}
""")
with open(os.path.join(TMP, "auth.yml"), "w") as f:
    f.write("admins: []\n")
os.environ.update(OPS_SITES=os.path.join(TMP, "sites.yml"), OPS_DATA=os.path.join(TMP, "data"),
                  OPS_DB=os.path.join(TMP, "data", "portal.db"), OPS_AUTH=os.path.join(TMP, "auth.yml"),
                  OPS_CREDENTIALS_KEY=os.path.join(TMP, "credentials.key"), OPS_MODULES="wi")


def alert(name="CDN root disk full", status="firing", fingerprint="fp-1", **labels):
    labels = {"alertname": name, "site": "dcb", "instance": "172.31.138.67:9100", "severity": "critical", **labels}
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


LOGROTATE = "Create the HAProxy logrotate rule so the log cannot grow without limit again, test it."
TRUNCATE = "Empty /var/log/haproxy.log (12.4 GB) with truncate — the file stays."
RESTART_TITLE = "Restart nginx so it releases the deleted log files it still holds open."
RESTART = [{"text": RESTART_TITLE + " The disk space comes back at once.", "action": {"commands": ["sudo systemctl restart nginx"]}}]
NODE = "overcloud-novacomputeha-2"
HOST = NODE + ".localdomain"
LIVE = f"Live-migrate the instances you tick off {HOST}, one at a time."
VMS = (("vm-big", "11111111-1111-4111-8111-000000000001", 8192), ("vm-small", "11111111-1111-4111-8111-000000000002", 2048),
       ("vm-mid", "11111111-1111-4111-8111-000000000003", 4096))


def drain_record(run_id, params, vms=VMS):
    """A result of compute-drain (live migration of the instances ticked, one item each) as the analysis makes it."""
    import datetime
    from modules.wi.wi_analysis.openstack import os_select
    nodes = f"{NODE}=10.253.128.12,overcloud-novacomputeha-3=10.253.128.13"
    items = [{"label": f"{name} -> least used under 70%", "default": False, "size": ram, "size_text": f"{ram / 1024:g} GiB",
              "commands": [f"live-migrate {uid} from {HOST} to auto try - timeout 5400 stall abort nodes {nodes} user heat-admin under 70 ram {ram}"]}
             for name, uid, ram in vms]
    action = os_select(items, HOST, "Live-migrate selected", "instances", lock="migration", stop_on_failure=False, item_timeout=5400,
                       max_items=40, skip_attention=True)
    rec = {"text": f"{LIVE} Nothing is ticked: tick the instances to move, then start.", "commands": [], "action": action}
    return {"id": run_id, "site": "DCB", "check_id": "compute-drain", "status": "ok", "params": params, "host": "",
            "finished": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
            "result": {"status": "ok", "steps": [{"key": "compute", "title": f"Compute {HOST}", "status": "ok", "detail": "3 instance(s)"}],
                       "recommendations": [rec]}}


POOL = "POOL_18"
SNAP_TITLE = "Delete the snapshots older than 14 days of one volume, that its PIC no longer needs."
VOLS = {"vol-a": "22222222-2222-4222-8222-00000000000a", "vol-b": "22222222-2222-4222-8222-00000000000b"}
SNAPS = {"vol-a": "33333333-3333-4333-8333-00000000000a", "vol-b": "33333333-3333-4333-8333-00000000000b"}
MOVE = (("big", "44444444-4444-4444-8444-000000000001", 500, ""), ("small", "44444444-4444-4444-8444-000000000002", 50, ""),
        ("mid", "44444444-4444-4444-8444-000000000003", 100, "33333333-3333-4333-8333-0000000000ff"))


def cinder_record(run_id, pct, snapped=("vol-a", "vol-b"), moved=()):
    """A result of cinder-pool-usage for POOL with pool_warn 70: its usage, the old snapshots of each volume (one fix per
    volume, the same title) and the migration of its volumes (mid still has a recent snapshot: an operator ticks it)."""
    import datetime
    from modules.wi.wi_analysis.openstack import os_fix, os_select
    recs = [{"text": f"{SNAP_TITLE} Volume {name} (project p, pool {POOL}): 1 snapshot(s) (10 GiB).",
             "commands": [], "action": os_fix([f"delete-snapshots {VOLS[name]} snapshots {SNAPS[name]}"], f"snapshots of {name}",
                                              confirm=name, label="Delete these snapshots", scope=POOL)} for name in snapped]
    items = [{"label": f"{name} ({gib} GiB)", "size": gib, "size_text": f"{gib} GiB", "default": False,
              "manual": "its 1 snapshot(s) are deleted before it moves: an operator ticks it" if snap else "",
              "commands": [f"migrate-volume {uid} to hostgroup@be#POOL_10 try - timeout 7200 snapshots {snap or '-'}"]}
             for name, uid, gib, snap in MOVE if name not in moved]
    recs.append({"text": f"Migrate volumes from {POOL} ({pct}%) to POOL_10 (40%, same SVM), one at a time, until {POOL} is under 70%.",
                 "commands": [], "action": os_select(items, f"{POOL} → POOL_10", "Migrate selected", "volumes", lock="volume-migration",
                                                     scope=POOL)})
    level = "fail" if pct >= 80 else "warn" if pct >= 70 else "ok"
    steps = [{"key": "pools", "title": "Identify the affected Cinder pools", "status": level, "detail": f"{POOL} {pct}%",
              "table": {"rows": [[POOL, f"{pct}%"]]}},
             {"key": "snapshots", "title": "Evaluate snapshots", "status": "warn" if snapped else "ok", "detail": ""}]
    status = "fail" if level == "fail" else "warn" if level == "warn" or snapped else "ok"
    return {"id": run_id, "site": "DCB", "check_id": "cinder-pool-usage", "status": status, "host": "",
            "params": {"pool": POOL, "pool_warn": "70", "snapshot_days": "14"},
            "finished": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
            "result": {"status": status, "steps": steps, "recommendations": recs}}


def health_record(run_id, mem, disk="ok"):
    """A result of overcloud-node-health for NODE with mem_warn 75: its memory at mem %."""
    steps = [{"key": "cpu", "title": "CPU", "status": "ok", "detail": "12% busy. Threshold 85% / 95%."},
             {"key": "mem", "title": "Memory", "status": "warn" if mem >= 75 else "ok",
              "detail": f"{mem}% used (45 GiB of 62 GiB). Threshold 75% / 95%."},
             {"key": "disk", "title": "Filesystems", "status": disk, "detail": "3 filesystem(s); threshold 80% / 90%."}]
    status = "warn" if any(s["status"] == "warn" for s in steps) else "ok"
    return {"id": run_id, "site": "DCB", "check_id": "overcloud-node-health", "status": status, "params": {"role": "compute", "node": NODE},
            "result": {"status": status, "steps": steps, "recommendations": []}}


class AlertsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import portal_auth
        store = portal_auth.Store(os.environ["OPS_DB"])
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
        with contextlib.closing(sqlite3.connect(os.environ["OPS_DB"])) as db, db:
            for table in ("wi_alert_sources", "wi_alert_rules", "wi_alert_events", "wi_alert_fixes_seen", "wi_alert_settings",
                          "wi_alert_samples", "wi_alert_actions"):
                db.execute(f"DELETE FROM {table}")
        self.alerts._rate.clear()
        self.started, self.fixed, self.measured, self.bodies = [], [], [], []
        self.runs = {}
        self.next_run = 100
        hooks = dict(self.alerts.HOOKS)
        self.addCleanup(self.alerts.HOOKS.update, hooks)
        self.alerts.HOOKS.update(start_check=self.fake_start, get_run=lambda rid: self.runs.get(rid),
                                 fix_state=self.fake_state, start_fix=self.fake_fix, measure=self.fake_measure,
                                 runs_with_fixes=lambda ids, after, limit: [])
        self.admin = self.client()

    # ---- fakes of the Runbook Automation module (a real check runs Ansible: tests/test_wi.py)
    def fake_start(self, site, check, raw, client):
        self.next_run += 1
        self.started.append((site, check["id"], raw))
        return self.next_run

    def fake_state(self, record, index, rec, user):
        """A fix on the SSH host dcb-cdn-01 (high risk: truncate, restart); an OpenStack fix: the real fixes.state."""
        if rec["action"].get("kind") == "openstack":
            from modules.wi import catalog, fixes
            state = fixes.state(record, index, rec, catalog.get(record["check_id"]), self.wi.site_cfg(record["site"]), user, lambda _n: False)
            return dict(state, group="", category="flex")
        commands = rec["action"]["commands"]
        risk = "high" if any("truncate" in c or "restart" in c for c in commands) else "normal"
        return {"available": True, "reason": "", "risk": risk, "target": "dcb-cdn-01", "kind": "host", "commands": commands,
                "group": rec["action"].get("group", "cdn"), "category": "cdn"}

    def fake_fix(self, record, index, user, client, note, body=None):
        self.fixed.append((record["id"], index, user["username"], fixed_modules(user), note))
        self.bodies.append(body)
        return 500 + len(self.fixed)

    def fake_measure(self, site, check, raw, client, since):
        """A run of the measuring check (it ends when the test says so: self.measure_ends)."""
        self.next_run += 1
        self.measured.append((self.next_run, check["id"], dict(raw)))
        return self.next_run

    def client(self, user="portaladmin", password="demo-portal-admin"):
        c = self.app.test_client()
        r = c.post("/api/login", json={"username": user, "password": password})
        self.assertEqual(r.status_code, 200, r.get_json())
        return c

    def source(self, networks=""):
        r = self.admin.post("/runbook/api/alerts/sources", json={"name": "Grafana SRE", "networks": networks})
        self.assertEqual(r.status_code, 200, r.get_json())
        return r.get_json()["id"], r.get_json()["token"]

    def send(self, token, body, auth=None):
        headers = {"Authorization": auth if auth is not None else f"Bearer {token}"}
        return self.app.test_client().post("/runbook/api/alerts/grafana", data=json.dumps(body), headers=headers,
                                           content_type="application/json")

    def send_from(self, ip, body, auth=None, raw=None, headers=None):
        """A notification from address ip; auth None: no Authorization header at all."""
        h = dict(headers or {})
        if auth is not None:
            h["Authorization"] = auth
        data = raw if raw is not None else json.dumps(body)
        return self.app.test_client().post("/runbook/api/alerts/grafana", data=data, headers=h, environ_base={"REMOTE_ADDR": ip},
                                           content_type=h.pop("Content-Type", "application/json"))

    def tokenless(self, source_id, addresses, networks="172.26.112.0/23", confirm="Grafana SRE", enabled=True, name="Grafana SRE"):
        return self.admin.put(f"/runbook/api/alerts/sources/{source_id}", json={"name": name, "networks": networks, "enabled": enabled,
                                                                           "tokenless": addresses, "confirm": confirm})

    def samples(self):
        with contextlib.closing(sqlite3.connect(os.environ["OPS_DB"])) as db:
            db.row_factory = sqlite3.Row
            return [dict(r) for r in db.execute("SELECT * FROM wi_alert_samples ORDER BY id")]

    def rule(self, **kw):
        data = {"name": "CDN root disk", "alertname": "CDN root disk*", "matchers": "severity=critical", "site": "{{labels.site}}",
                "checks": [{"check_id": "cdn-root-disk", "params": {"host": "{{labels.instance|host}}"}}], "cooldown": 30, **kw}
        r = self.admin.post("/runbook/api/alerts/rules", json=data)
        self.assertEqual(r.status_code, 200, r.get_json())
        return r.get_json()["id"], data

    def events(self, state="all"):
        """The alerts received (state "all": also the resolved ones; "": the default view, still firing)."""
        return self.admin.get(f"/runbook/api/alerts?limit=200&state={state}").get_json()["items"]

    def finish(self, run_id=None, status="fail", recs=None, check_id="cdn-root-disk"):
        """The check of the newest alert (or run_id) ends with this status and the recommendations of RECORD_RECS."""
        run_id = run_id or self.events()[0]["run_id"]
        self.runs[run_id] = {"id": run_id, "site": "DCB", "check_id": check_id, "status": status, "params": {"host": "dcb-cdn-01"},
                             "summary": "Root disk 93% used", "result": {"recommendations": RECORD_RECS if recs is None else recs}}
        self.alerts.run_finished(run_id, status)

    def end(self, record):
        """A run (measuring, the check after a fix, a check of a rule) ends with this stored record."""
        self.runs[record["id"]] = record
        self.alerts.run_finished(record["id"], record["status"])

    def seen(self, rule_id):
        return {f["title"]: f for f in self.alerts.fixes_seen(rule_id)}

    def act(self, rule_id, n, fix, confirm="", ticket="", **action):
        """Make `fix` (a title seen) the automatic action of check n of the rule (the form's Save)."""
        data = self.rule_data(rule_id)
        data["checks"][n]["action"] = {"fix": self.seen(rule_id)[fix]["key"], **action} if fix else None
        return self.admin.put(f"/runbook/api/alerts/rules/{rule_id}", json=dict(data, confirm=confirm, ticket=ticket))

    def actions(self):
        with contextlib.closing(sqlite3.connect(os.environ["OPS_DB"])) as db:
            db.row_factory = sqlite3.Row
            return [self.alerts._action_row(r) for r in db.execute("SELECT * FROM wi_alert_actions ORDER BY id")]

    def activity(self, action):
        return [e["detail"] for e in self.PORTAL.store.events() if e["action"] == action]

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
        with contextlib.closing(sqlite3.connect(os.environ["OPS_DB"])) as db:
            dump = "\n".join(str(row) for row in db.execute("SELECT * FROM wi_alert_sources"))
        self.assertNotIn(token, dump)
        # Allowed addresses: the test client comes from 127.0.0.1.
        self.admin.put(f"/runbook/api/alerts/sources/{source_id}", json={"name": "Grafana SRE", "networks": "10.0.0.0/8", "enabled": True})
        self.assertEqual(self.send(token, body).status_code, 403)
        self.admin.put(f"/runbook/api/alerts/sources/{source_id}", json={"name": "Grafana SRE", "networks": "127.0.0.1", "enabled": True})
        self.assertEqual(self.send(token, body).status_code, 200)
        # A new token: the old one stops working at once; a disabled source is refused.
        new = self.admin.post(f"/runbook/api/alerts/sources/{source_id}/token").get_json()["token"]
        self.assertEqual(self.send(token, body).status_code, 401)
        self.assertEqual(self.send(new, body).status_code, 200)
        self.admin.put(f"/runbook/api/alerts/sources/{source_id}", json={"name": "Grafana SRE", "networks": "", "enabled": False})
        self.assertEqual(self.send(new, body).status_code, 401)
        listed = self.admin.get("/runbook/api/alerts/config").get_json()["sources"][0]
        self.assertEqual((listed["token_tail"], listed["last_ip"]), (new[-4:], "127.0.0.1"))
        self.assertNotIn("token_hash", listed)
        actions = [e["action"] for e in self.PORTAL.store.events()]
        self.assertIn("wi.alert_source", actions)

    def test_too_many_alerts_in_a_minute_are_refused(self):
        _sid, token = self.source()
        with mock.patch.object(self.alerts, "RATE_PER_MINUTE", 3):
            self.assertEqual(self.send(token, notification(alert(), alert(fingerprint="fp-2"))).status_code, 200)
            self.assertEqual(self.send(token, notification(alert(), alert(fingerprint="fp-2"))).status_code, 429)

    # ---- metrics for the SRE Grafana (the way back to an operator)
    def scrape(self, auth=None, ip="127.0.0.1"):
        headers = {} if auth is None else {"Authorization": auth}
        return self.app.test_client().get("/runbook/api/alerts/metrics", headers=headers, environ_base={"REMOTE_ADDR": ip})

    @staticmethod
    def samples_of(text):
        """{'name{labels}': value} of the metric lines."""
        return {line.rsplit(" ", 1)[0]: float(line.rsplit(" ", 1)[1]) for line in text.splitlines() if line and not line.startswith("#")}

    def test_metrics_need_the_token_of_a_source_or_its_listed_address(self):
        source_id, token = self.source("172.26.112.0/23")
        self.assertEqual(self.scrape().status_code, 401)
        self.assertEqual(self.scrape("Bearer gfa_wrong", ip="172.26.113.20").status_code, 401)
        self.assertEqual(self.scrape(f"Bearer {token}", ip="10.251.137.9").status_code, 403)   # outside the source's addresses
        r = self.scrape(f"Bearer {token}", ip="172.26.113.20")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.content_type.startswith("text/plain; version=0.0.4"))
        self.assertIn("# TYPE ops_alert_actions_need_operator gauge", r.get_data(as_text=True))
        self.assertEqual(self.tokenless(source_id, "172.26.113.15").status_code, 200)
        self.assertEqual(self.scrape(ip="172.26.113.15").status_code, 200)   # AlertHub's address, without a header
        self.assertEqual(self.scrape(ip="172.26.113.16").status_code, 401)

    def test_metrics_count_run_actions_an_operator_takes_over_and_leave_out_the_pilot(self):
        _sid, token = self.source()
        now, hours_ago = self.alerts._now(), self.alerts._ago(3 * 60)
        rows = [   # site, rule, mode, step, stop, ended
            ("DCB", "CDN root disk", "run", "done", "failed", now),
            ("DCB", "CDN root disk", "run", "done", "gone", now),
            ("DCB", "CDN root disk", "observe", "done", "observed", now),
            ("DCB", "CDN root disk", "observe", "done", "measure", now),   # the pilot never needs an operator
            ("DCB", "Node memory", "run", "done", "max", hours_ago),
            ("DCA", "Node memory", "run", "measuring", "", None),
        ]
        with contextlib.closing(sqlite3.connect(os.environ["OPS_DB"])) as db, db:
            for site, rule, mode, step, stop, ended in rows:
                db.execute("INSERT INTO wi_alert_actions (rule_name, site, target, mode, step, stop, outcome, started, ended) "
                           "VALUES (?,?,?,?,?,?,?,?,?)", (rule, site, "dcb-cdn-01", mode, step, stop, "Fix #9 failed: secret detail", now, ended))
            db.execute("INSERT INTO wi_alert_events (ts, source, alertname, site, state) VALUES (?,?,?,?,?)",
                       (now, "Grafana SRE", "Unknown alert", "DCB", "no-rule"))
        text = self.scrape(f"Bearer {token}").get_data(as_text=True)
        m = self.samples_of(text)
        self.assertEqual(m['ops_alert_actions_need_operator{window="1h",site="DCB"}'], 1)
        self.assertEqual(m['ops_alert_actions_need_operator{window="24h",site="DCB"}'], 2)
        self.assertEqual(m['ops_alert_actions_need_operator{window="1h",site="DCA"}'], 0)   # every site is listed
        self.assertEqual(m['ops_alert_actions_need_operator{window="1h",site="LAB"}'], 0)
        self.assertEqual(m['ops_alert_actions_running{site="DCA"}'], 1)
        self.assertEqual(m['ops_alert_actions_ended{window="1h",site="DCB",rule="CDN root disk",mode="observe",stop="observed"}'], 1)
        self.assertEqual(m['ops_alert_actions_ended{window="24h",site="DCB",rule="Node memory",mode="run",stop="max"}'], 1)
        self.assertNotIn('ops_alert_actions_ended{window="1h",site="DCB",rule="Node memory",mode="run",stop="max"}', m)
        self.assertEqual(m['ops_alerts_received{window="1h",site="DCB",state="no-rule"}'], 1)
        self.assertEqual(m["ops_alert_automatic_actions_paused"], 0)
        self.assertNotIn("dcb-cdn-01", text)   # counts only: no target, no outcome text
        self.assertNotIn("secret detail", text)
        self.admin.put("/runbook/api/alerts/settings", json={"auto_fix": False, "frozen_sites": ["DCA"]})
        m = self.samples_of(self.scrape(f"Bearer {token}").get_data(as_text=True))
        self.assertEqual((m["ops_alert_automatic_actions_paused"], m['ops_alert_site_frozen{site="DCA"}'],
                          m['ops_alert_site_frozen{site="DCB"}']), (1, 1, 0))

    def test_metric_label_values_are_escaped(self):
        self.assertEqual(self.alerts._label('a"b\\c\nd'), 'a\\"b\\\\c\\nd')

    # ---- rules
    def test_a_rule_runs_its_check_with_parameters_from_the_labels_once_per_cooldown(self):
        _sid, token = self.source()
        self.rule()
        r = self.send(token, notification(alert()))
        self.assertEqual(r.get_json(), {"ok": True, "alerts": 1, "checks": 1, "ignored": 0})
        self.assertEqual(self.started, [("DCB", "cdn-root-disk", {"host": "172.31.138.67"})])
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
            self.admin.put(f"/runbook/api/alerts/rules/{self.alerts.rules()[0]['id']}", json=dict(self.rule_data(), cooldown=0))
            self.send(token, notification(alert(fingerprint="fp-6")))
        self.assertEqual(self.events()[0]["state"], "duplicate")

    def rule_data(self, rule_id=None):
        r = self.alerts.rule(rule_id) if rule_id else self.alerts.rules()[0]
        return {"name": r["name"], "alertname": r["alertname"], "matchers": [f"{m['label']}{m['op']}{m['value']}" for m in r["matchers"]],
                "site": r["site"], "checks": json.loads(json.dumps(r["checks"])), "cooldown": r["cooldown"],
                "auto_per_hour": r["auto_per_hour"], "enabled": r["enabled"]}

    def test_one_alert_runs_every_check_of_its_rule(self):
        _sid, token = self.source()
        host = {"host": "{{labels.instance|host}}"}
        self.rule(checks=[{"check_id": "cdn-root-disk", "params": host}, {"check_id": "cdn-memory", "params": host},
                          {"check_id": "linux-resources", "params": {"host": "{{labels.instance|host}}", "disk_warn": "70"}}])
        r = self.send(token, notification(alert()))
        self.assertEqual(r.get_json()["checks"], 3)
        self.assertEqual([(c[1], c[2]) for c in self.started], [("cdn-root-disk", {"host": "172.31.138.67"}), ("cdn-memory", {"host": "172.31.138.67"}),
                                                                ("linux-resources", {"host": "172.31.138.67", "disk_warn": "70"})])
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
        self.admin.put(f"/runbook/api/alerts/rules/{rid}", json=dict(self.rule_data(), cooldown=0, checks=[
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
                r = self.admin.post("/runbook/api/alerts/rules", json=data)
                self.assertEqual(r.status_code, 400)
                self.assertIn(message, r.get_json()["error"])
        self.send(token, notification(alert(site="dcb-openstack")))   # no rule yet: recorded with its labels
        eid = self.events()[0]["id"]
        data = {"name": "R", "alertname": "CDN*", "site": "{{labels.site}}",
                "checks": [{"check_id": "cdn-root-disk", "params": {"host": "{{labels.instance|host}}"}},
                           {"check_id": "cdn-memory", "params": {"host": "{{labels.instance}}x"}}]}
        p = self.admin.post("/runbook/api/alerts/rules/preview", json={"rule": data, "event_id": eid}).get_json()["preview"]
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

    def test_the_list_shows_the_firing_alerts_and_hides_resolved_and_ignored_ones(self):
        _sid, token = self.source()
        self.send(token, notification(alert(fingerprint="fp-open")))
        self.send(token, notification(alert(fingerprint="fp-closed")))
        self.send(token, notification(alert(status="resolved", fingerprint="fp-closed"), status="resolved"))
        self.send(token, notification(alert(status="resolved", fingerprint="never-seen"), status="resolved"))
        with contextlib.closing(sqlite3.connect(os.environ["OPS_DB"])) as db, db:   # one hidden by its source's pattern
            db.execute("INSERT INTO wi_alert_events (ts, source, alertname, status, state, ignored) VALUES (?,?,?,?,?,?)",
                       (self.alerts._now(), "Grafana SRE", "Speedtest Bandwidth Low", "firing", "no-rule", 1))
        prints = lambda items: sorted(e["fingerprint"] or e["alertname"] for e in items)
        self.assertEqual(prints(self.events("")), ["fp-open"])   # the default view: still firing only
        self.assertEqual(prints(self.events("resolved")), ["fp-closed", "never-seen"])
        self.assertEqual(prints(self.events("all")), ["fp-closed", "fp-open", "never-seen"])
        self.assertEqual(prints(self.events("ignored")), ["Speedtest Bandwidth Low"])
        self.assertEqual(self.admin.get("/runbook/api/alerts?state=bogus").status_code, 400)
        self.assertEqual(self.alerts.KEEP_DAYS, 30)

    # ---- automatic actions
    def test_what_is_customer_impacting_and_what_never_runs_by_itself(self):
        a = self.alerts
        host = {"available": True, "risk": "normal", "kind": "host", "commands": ["sudo logrotate -f /etc/logrotate.d/haproxy"]}
        self.assertEqual((a.impact_of(host, {}), a.never_reason(host)), ("", ""))   # runs by itself without an approval
        self.assertIn("OpenStack change", a.impact_of(dict(host, kind="openstack"), {}))
        self.assertIn("ONTAP change", a.impact_of(dict(host, kind="ontap"), {}))
        self.assertIn("VyOS change", a.impact_of(dict(host, kind="vyos_upgrade"), {}))
        self.assertIn("ticked items", a.impact_of(dict(host, selectable=True), {}))
        self.assertIn("template", a.impact_of(host, {"operation": True}))
        self.assertIn("high risk", a.impact_of(dict(host, risk="high"), {}))
        self.assertIn("high risk", a.impact_of(dict(host, selectable=True, items=[{"commands": ["delete-image x"], "delete": True}]), {}))
        for command in ("sudo iptables -I INPUT 1 -p tcp --dport 443 -j ACCEPT", "sudo nft insert rule inet filter input tcp dport 22 accept",
                        "sudo ip link set eth0 up", "sudo apt-get install -y x", "sudo usermod -aG wheel bob", "sudo mount -a"):
            with self.subTest(command=command):
                self.assertIn("firewall, network", a.impact_of(dict(host, commands=[command]), {}))
        # Never, approved or not: VMware Cloud and ESXi stay read-only; a database is changed by an operator.
        self.assertIn("VMware Cloud", a.never_reason(dict(host, category="prime")))
        self.assertIn("ESXi", a.never_reason(dict(host, group="esxi")))
        for command in ("sudo podman exec galera mysql -e \"UPDATE nova.block_device_mapping SET deleted=1\"", "cinder-manage volume update_host",
                        "cinder reset-state --state available 11111111-1111-4111-8111-111111111111"):
            with self.subTest(command=command):
                self.assertIn("database", a.never_reason(dict(host, commands=[command])))
        self.assertIn("database", a.never_reason(dict(host, commands=[], items=[{"commands": ["nova-manage db sync"]}])))
        self.assertEqual(a.never_reason(dict(host, commands=["sudo podman exec galera mysql -e \"SHOW STATUS\""])), "")
        self.assertEqual(a.never_reason(None), "No fix the portal can run")
        # The same fix in every result: numbers do not change its key.
        self.assertEqual(a.fix_key("c", {"text": "Empty /var/log/x (12.4 GB) now."}), a.fix_key("c", {"text": "Empty /var/log/x (3 GB) now."}))
        self.assertNotEqual(a.fix_key("c", {"text": "Empty /var/log/x."}), a.fix_key("d", {"text": "Empty /var/log/x."}))
        # Items: smallest / largest first by their size (the flavor RAM, also read from a migration of before), ties as listed.
        items = [{"label": "a", "commands": ["x"], "size": 8192}, {"label": "b", "commands": ["x"], "size": 2048},
                 {"label": "c", "commands": ["live-migrate 1 from h to auto try - timeout 60 stall abort nodes - user - under 70 ram 4096"]},
                 {"label": "d", "commands": [], "disabled": "cannot run", "size": 1}, {"label": "e", "commands": ["x"], "size": 2048},
                 {"label": "f", "commands": ["x"]}]
        self.assertEqual([x[1]["label"] for x in a.ordered(items, "smallest")], ["b", "e", "c", "a", "f"])
        self.assertEqual([x[1]["label"] for x in a.ordered(items, "largest")], ["a", "c", "b", "e", "f"])
        self.assertEqual([x[0] for x in a.ordered(items, "listed")], [0, 1, 2, 4, 5])

    def test_a_normal_risk_fix_runs_by_itself_with_limits_and_the_check_after_it(self):
        _sid, token = self.source()
        rule_id, data = self.rule(cooldown=0)
        self.send(token, notification(alert()))
        self.finish()
        self.assertEqual(self.fixed, [])   # no automatic action yet: the fixes are only noted
        seen = {f["title"]: f for f in self.admin.get("/runbook/api/alerts/config").get_json()["rules"][0]["fixes_seen"]}
        self.assertEqual(len(seen), 2)   # the recommendation without a fix is not listed
        self.assertEqual((seen[LOGROTATE]["eligible"], seen[LOGROTATE]["impact"]), (True, ""))
        self.assertEqual((seen[TRUNCATE]["eligible"], seen[TRUNCATE]["impact"]), (True, "high risk (deletes, restarts, kills, reboots)"))
        # Choosing it: with the rule name typed; only a fix seen in the results of that check.
        self.assertIn("type the rule name", self.act(rule_id, 0, LOGROTATE).get_json()["error"])
        bad = self.act(rule_id, 0, LOGROTATE, confirm="CDN root disk", measure=3)
        self.assertIn("measured by a check of this rule", bad.get_json()["error"])
        bad = self.act(rule_id, 0, LOGROTATE, confirm="CDN root disk", order="smallest")
        self.assertIn("as listed (they have no size)", bad.get_json()["error"])
        r = self.act(rule_id, 0, LOGROTATE, confirm="CDN root disk")
        self.assertEqual((r.status_code, r.get_json()["locked"]), (200, []), r.get_json())
        self.assertIn(f"automatic actions: check 1: {LOGROTATE} (as listed, at most 1, stops: cdn-root-disk)", self.activity("wi.alert_rule")[0])
        self.assertEqual(self.alerts.rule(rule_id)["checks"][0]["action"]["measure"], 0)
        # The next alert: the check, then the fix by itself as "grafana" (no OpenStack permission), measured by the check itself.
        self.send(token, notification(alert()))
        ev = self.events()[0]
        self.finish()
        self.assertEqual(self.fixed, [(ev["run_id"], 0, "grafana", ["wi", "wi-fix"],
                                       f"alert rule CDN root disk (alert #{ev['id']}), automatic action #{self.actions()[0]['id']}")])
        self.assertEqual(self.bodies, [{}])   # normal risk: nothing to confirm
        ev = self.events()[0]
        self.assertEqual((ev["fix_id"], ev["fix_status"], ev["action"]["step"]), (501, "running", "fixing"))
        self.assertIn("Fix #501 running", ev["outcome"])
        # It ends, the check runs again after it (run 900, the same check and parameters: the measurement) and says OK.
        self.runs[900] = dict(self.runs[ev["run_id"]], id=900, status="running")
        self.alerts.fix_finished(501, "ok", "", 900)
        self.assertEqual(self.measured, [])   # the check after the fix is the measurement
        self.end(dict(self.runs[900], status="ok", result={"steps": [{"key": "root", "title": "Root filesystem", "status": "ok",
                                                                       "detail": "41% used on dcb-cdn-01"}], "recommendations": []}))
        ev = self.events()[0]
        self.assertEqual((ev["fix_status"], ev["verify_run_id"], ev["verify_status"], ev["action"]["stop"]), ("ok", 900, "ok", "gone"))
        self.assertIn("(fix #501 ran): ", ev["outcome"])
        self.assertIn("Root filesystem: 41% used on dcb-cdn-01. The problem of dcb-cdn-01 is gone: stopped.", ev["outcome"])
        # The alert comes back: no second automatic action of the same fix on the same host within AUTO_AGAIN_HOURS.
        self.send(token, notification(alert()))
        self.finish()
        self.assertEqual(len(self.fixed), 1)
        self.assertIn("came back after automatic action", self.events()[0]["outcome"])
        with mock.patch.object(self.alerts, "AUTO_AGAIN_HOURS", 0):
            # A result without a problem (its own measurement) does nothing; paused automatic actions wait for an operator.
            self.send(token, notification(alert()))
            self.finish(status="ok")
            self.assertIn("nothing to do", self.events()[0]["outcome"])
            self.admin.put("/runbook/api/alerts/settings", json={"auto_fix": False})
            self.send(token, notification(alert()))
            self.finish()
            self.assertIn("Automatic actions are paused", self.events()[0]["outcome"])
            self.admin.put("/runbook/api/alerts/settings", json={"auto_fix": True})
            self.assertEqual(len(self.fixed), 1)
            # At most auto_per_hour automatic actions of a rule an hour (one ran above).
            self.admin.put(f"/runbook/api/alerts/rules/{rule_id}", json=dict(self.rule_data(), auto_per_hour=2))
            self.send(token, notification(alert()))
            self.finish()
            self.alerts.fix_finished(502, "ok", "", None)   # no check after it: the measuring check runs (fake_measure)
            self.end(dict(self.runs[self.events()[0]["run_id"]], id=self.measured[-1][0], status="ok", result={"steps": []}))
            self.send(token, notification(alert()))
            self.finish()
            self.assertEqual(len(self.fixed), 2)
            self.assertIn("2 automatic actions of this rule in the last hour", self.events()[0]["outcome"])
        # A check taken out of the rule takes its action and seen fixes with it.
        r = self.admin.put(f"/runbook/api/alerts/rules/{rule_id}", json=dict(self.rule_data(), checks=[{"check_id": "cdn-memory", "params": {}}]))
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertEqual((self.alerts.rule(rule_id)["checks"], self.alerts.fixes_seen(rule_id)), ([{"check_id": "cdn-memory", "params": {}}], []))
        self.assertTrue(self.activity("wi.alert_action"))

    def drain_rule(self, token=None, approve=True, **action):
        """A rule for a compute memory alert: check 1 drains the compute (live migration of ticked instances), check 2
        measures its memory; the automatic action of check 1 with the owner's approval (approve)."""
        token = token or self.source()[1]
        rule_id, _data = self.rule(name="Compute memory", alertname="Compute memory*", matchers="", cooldown=0, checks=[
            {"check_id": "compute-drain", "params": {"compute": "{{labels.nodename}}"}},
            {"check_id": "overcloud-node-health", "params": {"role": "compute", "node": "{{labels.nodename}}"}}])
        drain, _health = self.memory_alert(token)
        self.end(drain_record(drain["run_id"], drain["params"]))
        r = self.act(rule_id, 0, LIVE, confirm="Compute memory", ticket="CHG-2026-1110" if approve else "",
                     **{"order": "smallest", "max_items": 5, "measure": 1, **action})
        self.assertEqual(r.status_code, 200, r.get_json())
        return token, rule_id

    def memory_alert(self, token, fingerprint="fp-mem"):
        """Grafana: memory of overcloud-novacomputeha-2 high. Returns the rows of its two checks (drain, node health)."""
        self.send(token, notification(alert(name="Compute memory high", fingerprint=fingerprint, nodename=NODE)))
        rows = {e["check_id"]: e for e in self.events()[:2]}
        return rows["compute-drain"], rows["overcloud-node-health"]

    def test_a_live_migration_moves_the_smallest_first_until_the_memory_is_under_the_threshold(self):
        token, rule_id = self.drain_rule(approve=False)
        seen = self.seen(rule_id)[LIVE]
        self.assertEqual((seen["eligible"], seen["impact"], seen["items"], seen["sized"], seen["noun"], seen["kind"]),
                         (True, "OpenStack change; ticked items", True, True, "instances", "openstack"))
        action = self.alerts.rule(rule_id)["checks"][0]["action"]
        self.assertEqual((action["order"], action["max_items"], action["measure"], action["thresholds"]), ("smallest", 5, 1, {"mem_warn": "75"}))
        # Customer-impacting without the owner's approval: saved, shown locked, does not run.
        cfg = self.admin.get("/runbook/api/alerts/config").get_json()["rules"][0]["approval"]
        self.assertEqual((cfg["needed"], cfg["valid"], cfg["impact"]), (True, False, [LIVE]))
        drain, _health = self.memory_alert(token)
        self.end(drain_record(drain["run_id"], drain["params"]))
        self.assertIn("Locked: customer-impacting (OpenStack change; ticked items)", self.events()[1]["outcome"])
        self.assertEqual((self.fixed, self.actions()), ([], []))
        # The approval: a ticket and the rule name typed; the administrator saving is the approver.
        r = self.act(rule_id, 0, LIVE, ticket="CHG-2026-1110", order="smallest", measure=1)
        self.assertIn("type the rule name", r.get_json()["error"])
        r = self.act(rule_id, 0, LIVE, confirm="Compute memory", ticket="CHG-2026-1110", order="smallest", measure=1)
        self.assertEqual((r.status_code, r.get_json()["locked"]), (200, []))
        cfg = self.admin.get("/runbook/api/alerts/config").get_json()["rules"][0]["approval"]
        self.assertEqual((cfg["valid"], cfg["by"], cfg["name"], cfg["ticket"]), (True, "portaladmin", "Admin", "CHG-2026-1110"))
        self.assertIn("customer-impacting actions approved by Admin (portaladmin), ticket CHG-2026-1110", self.activity("wi.alert_rule")[0])
        # The alert: the drain check lists 3 instances; the stop condition is measured first (node health, mem_warn 75).
        drain, _health = self.memory_alert(token)
        self.end(drain_record(drain["run_id"], drain["params"]))
        self.assertEqual(self.measured[-1][1:], ("overcloud-node-health", {"role": "compute", "node": NODE, "mem_warn": "75"}))
        self.end(health_record(self.measured[-1][0], 82))
        # 82% >= 75%: the smallest instance moves first (2 GiB), as grafana with the OpenStack permission, approval in its note.
        self.assertEqual([(f[1], f[2], f[3]) for f in self.fixed], [(0, "grafana", ["wi", "wi-fix", "wi-fix-openstack"])])
        self.assertEqual(self.bodies, [{"selected": [1]}])
        self.assertIn("instances 1 of at most 5; approved by Admin, ticket CHG-2026-1110", self.fixed[0][4])
        self.assertIn("Fix #501 running: instances 1 of at most 5, vm-small", self.events()[1]["outcome"])
        self.alerts.fix_finished(501, "ok", "", 900)
        self.end(health_record(self.measured[-1][0], 78))
        self.assertEqual(self.bodies[-1], {"selected": [2]})   # then 4 GiB
        self.alerts.fix_finished(502, "ok", "", 901)
        self.end(health_record(self.measured[-1][0], 72, disk="warn"))   # memory under 75% (a disk warning is not this problem)
        self.assertEqual(len(self.fixed), 2)
        a = self.actions()[-1]
        self.assertEqual((a["step"], a["stop"], [i["label"].split(" ")[0] for i in a["items"]]), ("done", "gone", ["vm-small", "vm-mid"]))
        ev = next(e for e in self.events() if e["action_id"] == a["id"])
        self.assertIn(f"Automatic action #{a['id']} (2 instances moved, smallest first: vm-small (2 GiB), vm-mid (4 GiB))", ev["outcome"])
        self.assertIn("Memory: 72% used (45 GiB of 62 GiB). Threshold 75% / 95%. The problem of overcloud-novacomputeha-2.localdomain "
                      "is gone: stopped.", ev["outcome"])
        self.assertEqual((ev["action"]["done"], ev["action"]["max"], ev["action"]["noun"]), (2, 5, "instances"))
        log = self.activity("wi.alert_action")
        self.assertIn("started. Live-migrate the instances", log[1])
        self.assertIn("(smallest first, at most 5 instances per alert); stops when Overcloud node health", log[1])
        self.assertIn("approved by Admin, ticket CHG-2026-1110", log[1])
        self.assertIn("is gone: stopped", log[0])
        # The owner's approval covers the rule as it is: what it matches changed, it is locked again.
        data = self.rule_data(rule_id)
        self.assertEqual(self.admin.put(f"/runbook/api/alerts/rules/{rule_id}", json=dict(data, alertname="Compute*")).get_json()["locked"], [LIVE])
        cfg = self.admin.get("/runbook/api/alerts/config").get_json()["rules"][0]["approval"]
        self.assertEqual((cfg["valid"], cfg["stale"]), (False, True))

    def test_an_automatic_action_stops_at_its_maximum_and_at_the_first_failure(self):
        token, _rule_id = self.drain_rule(max_items=2)
        drain, _health = self.memory_alert(token)
        self.end(drain_record(drain["run_id"], drain["params"]))
        for fix_id in (None, 501, 502):
            if fix_id:
                self.alerts.fix_finished(fix_id, "ok", "", None)
            self.end(health_record(self.measured[-1][0], 90))   # memory stays high
        self.assertEqual((len(self.fixed), self.actions()[-1]["stop"]), (2, "max"))
        self.assertIn("Still a problem, and the maximum of 2 instances per alert is used up: an operator continues.", self.events()[1]["outcome"])
        with mock.patch.object(self.alerts, "AUTO_AGAIN_HOURS", 0):
            drain, _health = self.memory_alert(token)
            self.end(drain_record(drain["run_id"], drain["params"]))
            self.end(health_record(self.measured[-1][0], 90))
            measured = len(self.measured)
            self.alerts.fix_finished(503, "failed", "No valid host was found.", 902)
        self.assertEqual((len(self.fixed), len(self.measured), self.actions()[-1]["stop"]), (3, measured, "failed"))
        self.assertIn("Fix #503 (vm-small -> least used under 70%) failed: No valid host was found. Stopped at the first failure",
                      self.events()[1]["outcome"])
        self.assertTrue(self.alerts.fix_finished(503, "ok") is None and len(self.fixed) == 3)   # once only

    def test_an_automatic_action_stops_when_it_cannot_tell_has_no_item_left_or_the_portal_restarts(self):
        token, _rule_id = self.drain_rule()
        drain, _health = self.memory_alert(token)
        self.end(drain_record(drain["run_id"], drain["params"]))
        self.end(dict(health_record(self.measured[-1][0], 90), status="error", result=None))   # the measuring check could not run
        self.assertEqual((self.fixed, self.actions()[-1]["stop"]), ([], "measure"))
        self.assertIn("The measuring check could not tell (Could not run): an operator decides.", self.events()[1]["outcome"])
        with mock.patch.object(self.alerts, "AUTO_AGAIN_HOURS", 0):
            drain, _health = self.memory_alert(token)   # one instance only: moved, the memory stays high, nothing else to move
            self.end(drain_record(drain["run_id"], drain["params"], vms=VMS[:1]))
            self.end(health_record(self.measured[-1][0], 90))
            self.alerts.fix_finished(501, "ok", "", None)
            self.end(health_record(self.measured[-1][0], 91))
            self.assertEqual((len(self.fixed), self.actions()[-1]["stop"]), (1, "no-items"))
            self.assertIn("Still a problem, but no further instances can run: an operator continues.", self.events()[1]["outcome"])
            drain, _health = self.memory_alert(token)   # the portal restarts while an action measures: it stops, its target is free
            self.end(drain_record(drain["run_id"], drain["params"]))
            self.assertEqual(self.actions()[-1]["step"], "measuring")
            self.alerts.init()
        a = self.actions()[-1]
        self.assertEqual((a["step"], a["stop"]), ("done", "restart"))
        self.assertIn(f"Automatic action #{a['id']} stopped: the portal restarted during it", self.events()[1]["outcome"])
        self.end(health_record(a["measure_run"], 90))   # its measurement ends after the restart: nothing more runs
        self.assertEqual(len(self.fixed), 1)

    def test_the_switch_turned_off_meanwhile_and_a_frozen_site_stop_automatic_changes(self):
        token, _rule_id = self.drain_rule()
        drain, _health = self.memory_alert(token)
        self.end(drain_record(drain["run_id"], drain["params"]))
        self.end(health_record(self.measured[-1][0], 90))
        self.admin.put("/runbook/api/alerts/settings", json={"auto_fix": False})   # during the first migration
        self.alerts.fix_finished(501, "ok", "", None)
        self.end(health_record(self.measured[-1][0], 88))
        self.assertEqual((len(self.fixed), self.actions()[-1]["stop"]), (1, "refused"))
        self.assertIn("Automatic actions are paused", self.events()[1]["outcome"])
        # A frozen site: its checks still run, nothing changes there.
        r = self.admin.put("/runbook/api/alerts/settings", json={"auto_fix": True, "frozen_sites": ["dcb"]})
        self.assertEqual(r.get_json()["settings"]["frozen_sites"], ["DCB"])
        self.assertIn("sites where automatic changes never run: (none) → DCB", self.activity("wi.alert_settings")[0])
        with mock.patch.object(self.alerts, "AUTO_AGAIN_HOURS", 0):
            started = len(self.started)
            drain, _health = self.memory_alert(token)
            self.assertEqual(len(self.started), started + 2)   # both checks ran
            self.end(drain_record(drain["run_id"], drain["params"]))
        self.assertIn("DCB is a site where automatic changes never run (Alerts → Automatic fixes): the check ran, nothing was changed.",
                      self.events()[1]["outcome"])
        self.assertEqual((len(self.fixed), len(self.actions())), (1, 1))

    def test_one_automatic_action_per_target_at_a_time(self):
        token, _rule_id = self.drain_rule()
        drain, _health = self.memory_alert(token)
        self.end(drain_record(drain["run_id"], drain["params"]))   # action #1: measuring (its run has not ended)
        first = self.actions()[-1]
        self.assertEqual(first["step"], "measuring")
        drain2, _health = self.memory_alert(token, fingerprint="fp-other")   # a second alert for the same compute
        self.end(drain_record(drain2["run_id"], drain2["params"]))
        self.assertIn(f"overcloud-novacomputeha-2.localdomain is already being handled by run #{drain['run_id']} (automatic action "
                      f"#{first['id']} of rule Compute memory): this alert starts nothing more.", self.events()[1]["outcome"])
        self.assertEqual((len(self.actions()), self.fixed), (1, []))

    def test_observe_only_records_what_it_would_run_and_changes_nothing(self):
        token, rule_id = self.drain_rule(approve=False, mode="observe", max_items=2)
        action = self.alerts.rule(rule_id)["checks"][0]["action"]
        self.assertEqual((action["mode"], self.alerts.mode_of(action)), ("observe", "observe"))
        cfg = self.admin.get("/runbook/api/alerts/config").get_json()["rules"][0]["approval"]
        self.assertEqual((cfg["needed"], cfg["impact"]), (False, []))   # nothing changes: nothing to approve
        self.assertIn(f"check 1: {LIVE} (observe only, smallest first, at most 2, stops: overcloud-node-health mem_warn=75)",
                      self.activity("wi.alert_rule")[0])
        r = self.act(rule_id, 0, LIVE, confirm="Compute memory", ticket="CHG-1", mode="observe", order="smallest", max_items=2, measure=1)
        self.assertIn("observe only changes nothing", r.get_json()["error"])
        self.assertIn("observe (it changes nothing) or run", self.act(rule_id, 0, LIVE, confirm="Compute memory", mode="dry", measure=1).get_json()["error"])
        # Paused, and the site frozen: an action that only observes still measures and decides (the checks run there anyway).
        self.admin.put("/runbook/api/alerts/settings", json={"auto_fix": False, "frozen_sites": ["DCB"]})
        drain, _health = self.memory_alert(token)
        record = drain_record(drain["run_id"], drain["params"])
        record["result"]["steps"].append({
            "key": "destinations", "title": "Destinations: CPU and RAM under 70%", "status": "ok",
            "detail": "1 of 2 compute(s) are under 70% CPU and RAM now (real use, read on each compute). Right before each migration they are read again.",
            "table": {"columns": ["Compute", "Zone", "CPU now", "RAM now", "Under 70%"],
                      "rows": [["overcloud-novacomputeha-3.localdomain", "-", "21%", "48%", "yes"], ["overcloud-novacomputeha-4.localdomain", "-", "35%", "81%", "no"]]}})
        self.end(record)
        self.assertEqual(self.measured[-1][1], "overcloud-node-health")
        self.end(health_record(self.measured[-1][0], 82))
        self.assertEqual((self.fixed, self.bodies), ([], []))
        a = self.actions()[-1]
        self.assertEqual((a["mode"], a["step"], a["stop"], a["fix_id"]), ("observe", "done", "observed", None))
        self.assertEqual([(i["label"].split(" ")[0], i["size_text"], i["status"], i["fix_id"]) for i in a["items"]],
                         [("vm-small", "2 GiB", "observed", None), ("vm-mid", "4 GiB", "observed", None)])
        ev = next(e for e in self.events() if e["action_id"] == a["id"])
        self.assertEqual((ev["action"]["mode"], ev["action"]["observed"], ev["action"]["done"], ev["fix_id"]), ("observe", 2, 0, None))
        self.assertIn(f"Automatic action #{a['id']} (observe only, would run 2 instances, nothing changed): ", ev["outcome"])
        self.assertIn("Memory: 82% used (45 GiB of 62 GiB). Threshold 75% / 95%. Observe only, it would run 2 instances of 3 that can run, "
                      "smallest first: 1. vm-small (2 GiB), 2. vm-mid (4 GiB). In Run mode they run one at a time", ev["outcome"])
        self.assertIn("Destinations: CPU and RAM under 70%: 1 of 2 compute(s) are under 70% CPU and RAM now (real use, read on each compute). "
                      "Under the limit now: overcloud-novacomputeha-3.localdomain. The destination of each is chosen when it runs", ev["outcome"])
        self.assertIn("In Run mode now: Automatic actions are paused", ev["outcome"])
        self.assertTrue(ev["outcome"].endswith("Nothing was changed."), ev["outcome"])
        log = self.activity("wi.alert_action")
        self.assertIn("Observe only (changes nothing): Live-migrate", log[1])
        self.assertIn("customer-impacting in Run mode (OpenStack change; ticked items)", log[1])
        # Not limited by the limits of changes: the same target again at once; a measurement without the problem: nothing.
        drain, _health = self.memory_alert(token)
        self.end(drain_record(drain["run_id"], drain["params"]))
        self.end(health_record(self.measured[-1][0], 70))
        a2 = self.actions()[-1]
        self.assertEqual((a2["id"] != a["id"], a2["stop"], a2["items"]), (True, "gone", []))
        self.assertIn("(observe only, nothing changed): ", next(e for e in self.events() if e["action_id"] == a2["id"])["outcome"])
        # It can never start a fix (a guard behind the decision).
        self.assertFalse(self.alerts._launch(self.alerts.action(a2["id"]), None, {}, {"index": 0, "key": "", "title": ""}, "fix", {}, None,
                                             "Measured"))
        self.assertEqual((self.fixed, self.alerts.action(a2["id"])["stop"]), ([], "error"))
        # Run: observe rows count neither for the actions per hour (1) nor for the same target again within 6 hours.
        self.admin.put("/runbook/api/alerts/settings", json={"auto_fix": True, "frozen_sites": []})
        data = self.rule_data(rule_id)
        data["auto_per_hour"] = 1
        data["checks"][0]["action"] = dict(data["checks"][0]["action"], mode="run")
        r = self.admin.put(f"/runbook/api/alerts/rules/{rule_id}", json=dict(data, confirm="Compute memory", ticket="CHG-2026-1110"))
        self.assertEqual((r.status_code, r.get_json()["locked"]), (200, []), r.get_json())
        self.assertNotIn("mode", self.alerts.rule(rule_id)["checks"][0]["action"])   # run is stored as the actions of before
        drain, _health = self.memory_alert(token)
        self.end(drain_record(drain["run_id"], drain["params"]))
        self.end(health_record(self.measured[-1][0], 82))
        self.assertEqual((len(self.fixed), self.bodies, self.actions()[-1]["mode"]), (1, [{"selected": [1]}], "run"))

    def test_observe_to_run_needs_the_owners_approval_again(self):
        _token, rule_id = self.drain_rule()   # run (no mode), approved
        self.assertEqual(self.admin.get("/runbook/api/alerts/config").get_json()["rules"][0]["approval"]["valid"], True)
        r = self.act(rule_id, 0, LIVE, confirm="Compute memory", mode="observe", order="smallest", measure=1)
        self.assertEqual((r.status_code, r.get_json()["locked"]), (200, []))
        self.assertEqual(self.alerts.rule(rule_id)["approval"], {})   # nothing runs: the approval of before ends
        r = self.act(rule_id, 0, LIVE, mode="run", order="smallest", measure=1)
        self.assertIn("type the rule name", r.get_json()["error"])   # a changed action
        r = self.act(rule_id, 0, LIVE, confirm="Compute memory", mode="run", order="smallest", measure=1)
        self.assertEqual(r.get_json()["locked"], [LIVE])
        cfg = self.admin.get("/runbook/api/alerts/config").get_json()["rules"][0]["approval"]
        self.assertEqual((cfg["needed"], cfg["valid"]), (True, False))

    def test_a_high_risk_fix_on_an_ssh_host_restarts_a_service_through_the_same_path(self):
        _sid, token = self.source()
        rule_id, _data = self.rule(cooldown=0)
        self.send(token, notification(alert()))
        self.finish(recs=RESTART)
        self.assertEqual(self.seen(rule_id)[RESTART_TITLE]["impact"], "high risk (deletes, restarts, kills, reboots)")
        self.assertEqual(self.act(rule_id, 0, RESTART_TITLE, confirm="CDN root disk").get_json()["locked"], [RESTART_TITLE])
        self.send(token, notification(alert()))
        self.finish(recs=RESTART)
        self.assertIn("Locked: customer-impacting (high risk", self.events()[0]["outcome"])
        self.assertEqual(self.fixed, [])
        self.assertEqual(self.act(rule_id, 0, RESTART_TITLE, confirm="CDN root disk", ticket="INC-778").get_json()["locked"], [])
        self.send(token, notification(alert()))
        self.finish(recs=RESTART)
        self.assertEqual((self.fixed[0][3], self.bodies), (["wi", "wi-fix"], [{"confirm": "dcb-cdn-01"}]))   # the host name, as typed
        self.runs[900] = dict(self.runs[self.events()[0]["run_id"]], id=900, status="running")
        self.alerts.fix_finished(501, "ok", "", 900)
        self.end(dict(self.runs[900], status="ok", result={"steps": [], "recommendations": []}))
        self.assertIn("(fix #501 ran)", self.events()[0]["outcome"])
        self.assertIn("is gone: stopped.", self.events()[0]["outcome"])
        # ESXi stays read-only: such a fix is noted, never an automatic action.
        self.send(token, notification(alert()))
        self.finish(recs=[{"text": "Restart hostd on the ESXi host.", "action": {"commands": ["/etc/init.d/hostd restart"], "group": "esxi"}}])
        esxi = self.seen(rule_id)["Restart hostd on the ESXi host."]
        self.assertEqual((esxi["eligible"], esxi["reason"]), (False, "ESXi hosts (VMware Cloud) are read-only from the portal"))
        r = self.act(rule_id, 0, "Restart hostd on the ESXi host.", confirm="CDN root disk", ticket="INC-778")
        self.assertIn("never runs by itself: ESXi hosts", r.get_json()["error"])

    def test_alert_settings_are_for_administrators_and_frozen_sites_are_known_sites(self):
        op = self.client("operator1", "demo-operator-1")
        self.assertEqual(op.put("/runbook/api/alerts/settings", json={"frozen_sites": ["LAB"]}).status_code, 403)
        self.assertEqual(self.alerts.get_settings()["frozen_sites"], [])   # optional: no site is frozen unless an administrator ticks it
        r = self.admin.put("/runbook/api/alerts/settings", json={"frozen_sites": ["LAB", "MARS"]})
        self.assertEqual((r.status_code, r.get_json()["error"]), (400, "Unknown site MARS"))
        r = self.admin.put("/runbook/api/alerts/settings", json={"frozen_sites": "lab"})
        self.assertEqual(r.get_json()["settings"], {"auto_fix": True, "frozen_sites": ["LAB"]})
        self.assertTrue(self.alerts.frozen("lab") and not self.alerts.frozen("DCB"))
        self.assertEqual(self.admin.get("/runbook/api/alerts/config").get_json()["settings"]["frozen_sites"], ["LAB"])
        self.assertIn("sites where automatic changes never run: (none) → LAB", self.activity("wi.alert_settings")[0])
        self.admin.put("/runbook/api/alerts/settings", json={"auto_fix": False})   # the other setting keeps the sites
        self.assertEqual(self.alerts.get_settings(), {"auto_fix": False, "frozen_sites": ["LAB"]})
        self.assertIn("paused; automatic changes never run on LAB", self.activity("wi.alert_settings")[0])

    def test_the_allowed_fixes_of_before_become_automatic_actions(self):
        rule_id, _data = self.rule()
        with contextlib.closing(sqlite3.connect(os.environ["OPS_DB"])) as db, db:
            for key, title in (("k1", LOGROTATE), ("k2", "Another fix of the same check.")):
                db.execute("INSERT INTO wi_alert_fixes_seen (rule_id, key, check_id, title, eligible, reason, run_id, seen) VALUES "
                           "(?,?,?,?,1,'',1,'x')", (rule_id, key, "cdn-root-disk", title))
            db.execute("UPDATE wi_alert_rules SET auto_fixes = ? WHERE id = ?", (json.dumps(["k1", "k2"]), rule_id))
        notes = self.alerts._migrate_auto_fixes()
        r = self.alerts.rule(rule_id)
        self.assertEqual(r["checks"][0]["action"], {"fix": "k1", "title": LOGROTATE, "order": "listed", "max_items": 5, "measure": 0,
                                                    "thresholds": {}})
        self.assertEqual(notes, [("CDN root disk", f"Alert rule CDN root disk: the fixes it allowed to run by themselves are now the "
                                                   f"automatic actions of their checks ({LOGROTATE}); not kept, one automatic action per "
                                                   "check: Another fix of the same check.")])
        self.assertEqual(self.alerts._migrate_auto_fixes(), [])   # once

    def test_the_real_hooks_run_the_check_and_the_fix_as_grafana(self):
        real = _real_hooks()
        self.alerts.HOOKS.update(start_check=real["start_check"], start_fix=real["start_fix"], measure=real["measure"])
        from modules.wi import catalog
        with mock.patch.object(self.wi, "start_run", return_value=(77, "job")) as start_run:
            self.assertEqual(self.alerts.HOOKS["start_check"]("DCB", catalog.get("cdn-root-disk"), {"host": "x"}, "10.253.128.9"), 77)
        user = start_run.call_args.args[0]
        self.assertEqual((user["username"], user["role"], user["modules"]), ("grafana", "operator", ["wi"]))
        with mock.patch.object(self.wi, "launch_fix", return_value={"action_id": 9, "job_id": "j"}) as launch:
            self.assertEqual(self.alerts.HOOKS["start_fix"]({"id": 77}, 0, self.alerts.robot(True), "10.253.128.9", "alert rule X",
                                                            {"selected": [2]}), 9)
        self.assertEqual((launch.call_args.args[3], launch.call_args.kwargs["note"]), ({"selected": [2]}, "alert rule X"))
        # The measuring check: a run of it started since then is used (the rule's own, one running), else one starts.
        check = catalog.get("cdn-root-disk")
        with mock.patch.object(self.wi.runs, "since", return_value=55), mock.patch.object(self.wi, "start_run") as start_run:
            self.assertEqual(self.alerts.HOOKS["measure"]("DCB", check, {"host": "dcb-cdn-01"}, "", "2026-11-10T10:00:00+07:00"), 55)
        start_run.assert_not_called()
        with mock.patch.object(self.wi.runs, "since", return_value=None), mock.patch.object(self.wi, "start_run", return_value=(56, "j")) as start_run:
            self.assertEqual(self.alerts.HOOKS["measure"]("DCB", check, {"host": "dcb-cdn-01"}, "", "2026-11-10T10:00:00+07:00"), 56)
        self.assertEqual(start_run.call_args.args[0]["modules"], ["wi"])   # measuring only reads

    # ---- who sees and changes what
    # ---- senders without a token (exact addresses of a source)
    def test_a_listed_address_is_accepted_without_a_token(self):
        source_id, token = self.source("172.26.112.0/23")
        self.assertEqual(self.tokenless(source_id, "172.26.113.15, 172.26.113.16,172.26.113.18").status_code, 200)
        self.rule()
        body = notification(alert())
        r = self.send_from("172.26.113.15", body)   # no Authorization header at all
        self.assertEqual((r.status_code, r.get_json()["checks"]), (200, 1), r.get_json())
        ev = self.events()[0]
        self.assertEqual((ev["source"], ev["auth"], ev["client_ip"]), ("Grafana SRE", "none", "172.26.113.15"))
        self.assertEqual(len(self.started), 1)   # its rules run as for any alert
        self.assertEqual(self.send_from("172.26.113.17", body).status_code, 401)   # inside Allowed from, but not listed
        self.assertEqual(self.send_from("10.251.137.9", body).status_code, 401)
        self.assertEqual(self.send_from("172.26.113.16", body, auth="Bearer gfa_wrong").status_code, 401)   # a wrong token: refused
        self.assertEqual(self.send_from("172.26.113.16", body, auth="Basic " + base64.b64encode(b"x:gfa_wrong").decode()).status_code, 401)
        r = self.send_from("172.26.113.16", notification(alert(fingerprint="fp-2")), auth=f"Bearer {token}")   # the token still works
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.events()[0]["auth"], "token")
        self.assertEqual(self.send_from("::ffff:172.26.113.18", notification(alert(fingerprint="fp-3"))).status_code, 200)
        listed = self.admin.get("/runbook/api/alerts/config").get_json()["sources"][0]
        self.assertEqual(listed["tokenless"], "172.26.113.15,172.26.113.16,172.26.113.18")
        self.assertEqual(self.tokenless(source_id, "172.26.113.15, 172.26.113.16,172.26.113.18", enabled=False, confirm="").status_code, 200)
        self.assertEqual(self.send_from("172.26.113.15", body).status_code, 401)   # a disabled source: refused
        detail = [e["detail"] for e in self.PORTAL.store.events() if e["action"] == "wi.alert_source"]   # newest first
        self.assertIn("accept without a token from: none → 172.26.113.15, 172.26.113.16, 172.26.113.18", detail[1])
        self.assertIn("off, from 172.26.112.0/23; without a token from 172.26.113.15, 172.26.113.16, 172.26.113.18", detail[0])

    def test_addresses_without_a_token_are_checked(self):
        source_id, _token = self.source("172.26.112.0/23")
        for value, text in (("172.26.113.0/24", "no networks or ranges"), ("172.26.113.15-172.26.113.18", "no networks or ranges"),
                            ("grafana.example", "not an IPv4 address"), ("fe80::1", "not an IPv4 address"),
                            ("10.253.128.5", "not inside Allowed from"),
                            (", ".join(f"172.26.113.{n}" for n in range(1, 12)), "At most 10")):
            r = self.tokenless(source_id, value)
            self.assertEqual(r.status_code, 400, value)
            self.assertIn(text, r.get_json()["error"], value)
        self.assertIn("type the source name Grafana SRE", self.tokenless(source_id, "172.26.113.15", confirm="").get_json()["error"])
        self.assertEqual(self.tokenless(source_id, "172.26.113.15", confirm="grafana sre").status_code, 400)
        self.assertEqual(self.tokenless(source_id, "172.26.113.15").status_code, 200)
        # the same address on two enabled sources: refused; on a disabled one it waits until the other lets it go
        r = self.admin.post("/runbook/api/alerts/sources", json={"name": "Grafana NOC", "networks": "", "tokenless": "172.26.113.15",
                                                            "confirm": "Grafana NOC"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("already accepted without a token for the source Grafana SRE", r.get_json()["error"])
        self.assertEqual(self.tokenless(source_id, "172.26.113.15", enabled=False, confirm="").status_code, 200)
        r = self.admin.post("/runbook/api/alerts/sources", json={"name": "Grafana NOC", "networks": "", "tokenless": "172.26.113.15",
                                                            "confirm": "Grafana NOC"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.tokenless(source_id, "172.26.113.15", enabled=True, confirm="").status_code, 400)   # enabled again: taken
        # allowed addresses that no longer hold a listed address: refused
        noc = r.get_json()["id"]
        r = self.tokenless(noc, "172.26.113.15", networks="10.0.0.0/8", confirm="", name="Grafana NOC")
        self.assertIn("not inside Allowed from", r.get_json()["error"])
        added = [e["detail"] for e in self.PORTAL.store.events() if e["action"] == "wi.alert_source" and "NOC" in e["target"]]
        self.assertIn("added (from anywhere; without a token from 172.26.113.15)", added[0])

    # ---- notifications the portal cannot read
    def test_unreadable_notifications_are_kept_as_samples_for_the_administrator(self):
        source_id, token = self.source("172.26.112.0/23")
        self.tokenless(source_id, "172.26.113.15")
        r = self.send_from("172.26.113.15", None, raw="event=cpu_high&host=10.253.128.1",
                           headers={"User-Agent": "AlertHub-Webhook/1.0", "Content-Type": "text/plain"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("recorded for the portal administrator", r.get_json()["error"])
        r = self.send_from("172.26.113.16", {"event": "cpu_high"}, auth=f"Bearer {token}", headers={"User-Agent": "AlertHub-Webhook/1.0"})
        self.assertEqual(r.status_code, 400)
        self.send_from("172.26.113.16", {"alerts": ["cpu_high"]}, auth="Basic " + base64.b64encode(f"x:{token}".encode()).decode())
        rows = self.samples()
        self.assertEqual([x["reason"][:30] for x in rows], ["The body is not JSON", "No alerts list (not a Grafana ",
                                                             "The alerts have no labels (not"])
        self.assertEqual((rows[0]["source_name"], rows[0]["client_ip"], rows[0]["user_agent"], rows[0]["content_type"], rows[0]["body"]),
                         ("Grafana SRE", "172.26.113.15", "AlertHub-Webhook/1.0", "text/plain", "event=cpu_high&host=10.253.128.1"))
        dump = repr(rows)
        self.assertNotIn(token, dump)   # never the Authorization header nor the token
        self.assertNotIn("Authorization", dump)
        big = json.dumps({"event": "x" * 20000})
        self.send_from("172.26.113.15", None, raw=big)
        last = self.samples()[-1]
        self.assertEqual((last["size"], len(last["body"].encode())), (len(big), 8 * 1024))
        for n in range(25):
            self.send_from("172.26.113.15", {"n": n})
        rows = self.samples()
        self.assertEqual(len(rows), 20)
        self.assertEqual(json.loads(rows[-1]["body"]), {"n": 24})
        # an unknown sender is refused before anything is kept
        self.assertEqual(self.send_from("172.26.113.17", {"event": "x"}).status_code, 401)
        self.assertEqual(self.send_from("172.26.113.17", None, raw="junk", auth="Bearer gfa_wrong").status_code, 401)
        self.assertEqual(len(self.samples()), 20)
        # administrators see them (with the body); operators do not
        listed = self.admin.get("/runbook/api/alerts/samples").get_json()
        self.assertEqual((len(listed["items"]), listed["max"]), (20, 20))
        self.assertEqual(len(self.admin.get("/runbook/api/alerts/config").get_json()["samples"]), 20)
        op = self.client("operator1", "demo-operator-1")
        self.assertEqual(op.get("/runbook/api/alerts/samples").status_code, 403)
        self.assertEqual(op.delete("/runbook/api/alerts/samples").status_code, 403)
        self.assertNotIn("samples", op.get("/runbook/api/alerts").get_json())
        self.assertEqual(self.admin.delete("/runbook/api/alerts/samples").get_json()["deleted"], 20)
        self.assertEqual(self.samples(), [])
        self.assertIn("20 samples of unreadable notifications deleted",
                      [e["detail"] for e in self.PORTAL.store.events() if e["action"] == "wi.alert_samples"])

    def test_alerthub_notifications_are_read_as_grafana_alerts(self):
        """The SRE team's webhook (AlertHub-Webhook/1.0, event alertify.*): the Grafana notification it carries ("grafana",
        or "raw"), else its markdown message (alert name, node, cluster, site, role, instance, status)."""
        source_id, _token = self.source("172.26.112.0/23")
        self.tokenless(source_id, "172.26.113.15")
        name = "OpenStack Cloud Node High Memory Usage"
        inner = {"status": "firing", "alerts": [{"status": "firing", "fingerprint": "d57991b9dea8e7af", "startsAt": "2026-11-10T01:51:00Z",
                                                  "labels": {"alertname": name, "nodename": "overcloud-novacomputeha-12",
                                                             "instance": "172.26.83.126:59100", "site": "dca", "role": "compute"},
                                                  "annotations": {"summary": "High memory usage on node overcloud-novacomputeha-12"}}]}
        full = {"event": "alertify.analysis", "timestamp": "2026-11-10T19:03:19+07:00", "status": "firing", "title": "OpenStack Cloud",
                "message": f"*Alert: {name}*  \n**Node:** overcloud-novacomputeha-12", "grafana": inner, "raw": inner}
        short = {"event": "alertify.analysis", "timestamp": "2026-11-10T19:03:29+07:00", "status": "firing", "title": "OpenStack Cloud",
                 "message": f"*ALERT: {name}*  \n**Node:** overcloud-novacomputeha-2  \n**Cluster:** acmeflex-dca  \n**Site:** dca  \n"
                            "**Role:** compute  \n**Usage:** *80.89%* (1629.15 GB / 2014.02 GB)  \n**Instance:** 172.26.83.116:59100  \n"
                            "**Status:** *Firing*  \n\nPerlu penanganan segera."}
        self.assertIs(self.alerts.normalize(full), inner)
        self.assertIs(self.alerts.normalize(dict(full, grafana=None)), inner)   # "raw" when "grafana" is missing
        alert = self.alerts.normalize(short)["alerts"][0]
        self.assertEqual(alert["labels"], {"alertname": name, "nodename": "overcloud-novacomputeha-2", "cluster": "acmeflex-dca",
                                           "site": "dca", "role": "compute", "instance": "172.26.83.116:59100"})
        self.assertEqual((alert["status"], alert["startsAt"], alert["annotations"]["usage"]),
                         ("firing", "2026-11-10T19:03:29+07:00", "80.89% (1629.15 GB / 2014.02 GB)"))
        self.assertEqual(alert["annotations"]["summary"], f"{name} on overcloud-novacomputeha-2")
        self.assertEqual(alert["fingerprint"], self.alerts.normalize(dict(short, timestamp="later"))["alerts"][0]["fingerprint"])
        resolved = self.alerts.normalize(dict(short, message=short["message"].replace("*Firing*", "*Resolved*")))
        self.assertEqual(resolved["alerts"][0]["status"], "resolved")
        for body in (full, short):
            r = self.send_from("172.26.113.15", body, headers={"User-Agent": "AlertHub-Webhook/1.0"})
            self.assertEqual((r.status_code, r.get_json()["alerts"]), (200, 1), r.get_json())
        rows = {e["fingerprint"]: e for e in self.events()}
        self.assertEqual(rows["d57991b9dea8e7af"]["alertname"], name)
        self.assertEqual(rows[alert["fingerprint"]]["alertname"], name)
        self.assertEqual({e["state"] for e in rows.values()}, {"no-rule"})
        self.assertEqual(self.samples(), [])   # read, so not kept as samples
        # another alertify event without an alert line, or another sender: still a sample
        self.assertEqual(self.send_from("172.26.113.15", {"event": "alertify.heartbeat", "message": "ok"}).status_code, 400)
        self.assertEqual(len(self.samples()), 1)

    # ---- alerts a source ignores
    def test_a_source_ignores_the_alerts_named_by_its_patterns(self):
        source_id, token = self.source()
        self.rule(alertname="*")
        r = self.admin.put(f"/runbook/api/alerts/sources/{source_id}", json={"name": "Grafana SRE", "networks": "", "enabled": True,
                                                                          "ignore": "speedtest*\nDisk test, speedtest*"})
        self.assertEqual(r.status_code, 200, r.get_json())   # no typed confirmation
        listed = self.admin.get("/runbook/api/alerts/config").get_json()["sources"][0]
        self.assertEqual(listed["ignore"], ["speedtest*", "Disk test"])
        body = notification(alert(name="Speedtest Bandwidth Low"), alert(name="SPEEDTEST upload", fingerprint="fp-2"),
                            alert(name="disk TEST", fingerprint="fp-3"), alert(fingerprint="fp-4"),
                            alert(name="Speedtest Bandwidth Low", status="resolved", fingerprint="fp-5"))
        r = self.send(token, body)
        self.assertEqual(r.get_json(), {"ok": True, "alerts": 5, "checks": 1, "ignored": 4})
        self.assertEqual([e["alertname"] for e in self.events()], ["CDN root disk full"])   # the others: not recorded, nothing ran
        self.assertEqual(len(self.started), 1)
        self.send(token, notification(alert(name="Speedtest Bandwidth Low", fingerprint="fp-6")))
        listed = self.admin.get("/runbook/api/alerts/config").get_json()["sources"][0]
        self.assertEqual((listed["ignored"], listed["ignored_days"]), (5, 7))
        detail = [e["detail"] for e in self.PORTAL.store.events() if e["action"] == "wi.alert_source"]
        self.assertIn("ignore alerts named: none → speedtest*, Disk test", detail[0])
        # validation: at most 20 patterns of 200 characters; nothing is saved when one is wrong
        r = self.admin.put(f"/runbook/api/alerts/sources/{source_id}", json={"name": "Grafana SRE", "networks": "", "enabled": True,
                                                                          "ignore": ",".join(f"a{n}*" for n in range(21))})
        self.assertIn("at most 20 patterns", r.get_json()["error"])
        r = self.admin.put(f"/runbook/api/alerts/sources/{source_id}", json={"name": "Renamed", "networks": "", "enabled": True,
                                                                          "ignore": "x" * 201})
        self.assertIn("longer than 200 characters", r.get_json()["error"])
        self.assertEqual(self.admin.get("/runbook/api/alerts/config").get_json()["sources"][0]["name"], "Grafana SRE")
        # a change that does not name ignore keeps the patterns; an empty list ignores nothing again
        self.admin.put(f"/runbook/api/alerts/sources/{source_id}", json={"name": "Grafana SRE", "networks": "", "enabled": True})
        self.assertEqual(self.admin.get("/runbook/api/alerts/config").get_json()["sources"][0]["ignore"], ["speedtest*", "Disk test"])
        self.admin.put(f"/runbook/api/alerts/sources/{source_id}", json={"name": "Grafana SRE", "networks": "", "enabled": True, "ignore": ""})
        self.assertEqual(self.send(token, notification(alert(name="Speedtest Bandwidth Low", fingerprint="fp-7"))).get_json()["ignored"], 0)
        detail = [e["detail"] for e in self.PORTAL.store.events() if e["action"] == "wi.alert_source"]
        self.assertIn("ignore alerts named: speedtest*, Disk test → none", detail[0])
        r = self.admin.post("/runbook/api/alerts/sources", json={"name": "Grafana NOC", "networks": "", "ignore": "Watchdog"})
        self.assertEqual(self.admin.get("/runbook/api/alerts/config").get_json()["sources"][0]["ignore"], ["Watchdog"])

    def test_earlier_alerts_of_an_ignored_name_are_hidden_not_deleted(self):
        sre, sre_token = self.source()
        r = self.admin.post("/runbook/api/alerts/sources", json={"name": "Grafana NOC", "networks": ""})
        noc, noc_token = r.get_json()["id"], r.get_json()["token"]
        for n in range(3):
            self.send(sre_token, notification(alert(name="Speedtest Bandwidth Low", fingerprint=f"s-{n}")))
        self.send(sre_token, notification(alert()))
        self.send(noc_token, notification(alert(name="Speedtest Bandwidth Low", fingerprint="noc-1")))
        self.assertEqual(self.admin.get("/runbook/api/alerts").get_json()["total"], 5)
        put = lambda ignore: self.admin.put(f"/runbook/api/alerts/sources/{sre}", json={"name": "Grafana SRE", "networks": "",   # noqa: E731
                                                                                     "enabled": True, "ignore": ignore})
        self.assertEqual(put("Speedtest*").status_code, 200)
        listed = self.admin.get("/runbook/api/alerts").get_json()   # hidden by default, the counts too
        self.assertEqual(listed["total"], 2)
        self.assertEqual(sorted((e["source"], e["alertname"]) for e in listed["items"]),
                         [("Grafana NOC", "Speedtest Bandwidth Low"), ("Grafana SRE", "CDN root disk full")])   # not another source's
        hidden = self.admin.get("/runbook/api/alerts?state=ignored").get_json()
        self.assertEqual((hidden["total"], {e["source"] for e in hidden["items"]}, {e["ignored"] for e in hidden["items"]}),
                         (3, {"Grafana SRE"}, {True}))
        op = self.client("operator1", "demo-operator-1")   # every module user has the filter
        self.assertEqual(op.get("/runbook/api/alerts?state=ignored").get_json()["total"], 3)
        with contextlib.closing(sqlite3.connect(os.environ["OPS_DB"])) as db:   # kept as history: nothing deleted
            self.assertEqual(db.execute("SELECT COUNT(*) FROM wi_alert_events").fetchone()[0], 5)
        detail = [e["detail"] for e in self.PORTAL.store.events() if e["action"] == "wi.alert_source"]
        self.assertIn("ignore alerts named: none → Speedtest* (3 earlier alerts hidden)", detail[0])
        # removing the pattern shows them again
        put("")
        self.assertEqual(self.admin.get("/runbook/api/alerts").get_json()["total"], 5)
        self.assertEqual(self.admin.get("/runbook/api/alerts?state=ignored").get_json()["total"], 0)
        detail = [e["detail"] for e in self.PORTAL.store.events() if e["action"] == "wi.alert_source"]
        self.assertIn("ignore alerts named: Speedtest* → none (3 earlier alerts shown again)", detail[0])
        # a pattern saved by an older portal (or in the database): hidden at start-up, without saving again
        with contextlib.closing(sqlite3.connect(os.environ["OPS_DB"])) as db, db:
            db.execute("UPDATE wi_alert_sources SET ignore_names = 'speedtest*' WHERE id = ?", (noc,))
        self.assertEqual(self.admin.get("/runbook/api/alerts").get_json()["total"], 5)
        self.alerts.init()
        listed = self.admin.get("/runbook/api/alerts").get_json()
        self.assertEqual((listed["total"], [e["source"] for e in self.admin.get("/runbook/api/alerts?state=ignored").get_json()["items"]]),
                         (4, ["Grafana NOC"]))
        self.assertEqual(self.alerts.apply_ignore(noc), (0, 0))   # again: nothing to change

    # ---- samples read again
    def alerthub(self, name="OpenStack Cloud Node High Memory Usage", node="overcloud-novacomputeha-2"):
        return {"event": "alertify.analysis", "timestamp": "2026-11-10T19:03:29+07:00", "status": "firing", "title": "OpenStack Cloud",
                "message": f"*ALERT: {name}*  \n**Node:** {node}  \n**Site:** dca  \n**Status:** *Firing*"}

    def kept(self, source_id, body, ip="172.26.113.15", raw=None, auth="none"):
        """A sample as the receiver kept it before the mapping of AlertHub existed."""
        src = dict(self.alerts.source(source_id), auth=auth)
        data = raw if raw is not None else json.dumps(body).encode()
        return self.alerts.record_sample(src, ip, "AlertHub-Webhook/1.0", "application/json", data, "No alerts list (not a Grafana ...)")

    def test_a_sample_is_read_again_with_the_mapping_of_now(self):
        source_id, _token = self.source("172.26.112.0/23")
        self.tokenless(source_id, "172.26.113.15")
        first = self.kept(source_id, self.alerthub())
        r = self.admin.post(f"/runbook/api/alerts/samples/{first}/read")
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertEqual((r.get_json()["alerts"], r.get_json()["ignored"], r.get_json()["id"]), (1, 0, first))
        ev = self.events()[0]
        self.assertEqual((ev["alertname"], ev["source"], ev["auth"], ev["client_ip"]),
                         ("OpenStack Cloud Node High Memory Usage", "Grafana SRE", "none", "172.26.113.15"))
        self.assertEqual(self.samples(), [])   # read: the sample goes
        entry = next(e for e in self.PORTAL.store.events() if e["action"] == "wi.alert_samples")
        self.assertIn(f"Sample #{first} (received ", entry["detail"])
        self.assertIn("read again: 1 alert, 0 checks started", entry["detail"])
        # still not readable: 400 with the reason, the sample stays
        other = self.kept(source_id, {"event": "alertify.heartbeat", "message": "ok"})
        r = self.admin.post(f"/runbook/api/alerts/samples/{other}/read")
        self.assertEqual(r.status_code, 400)
        self.assertIn("still not readable: No alerts list", r.get_json()["error"])
        # cut at 8 KB: cannot be read again
        big = self.kept(source_id, None, raw=json.dumps(dict(self.alerthub(), padding="x" * 9000)).encode())
        r = self.admin.post(f"/runbook/api/alerts/samples/{big}/read")
        self.assertIn("was cut to 8 KB", r.get_json()["error"])
        self.assertEqual(sorted(x["id"] for x in self.samples()), [other, big])
        # the ignore patterns of the source apply as at the receiver
        self.admin.put(f"/runbook/api/alerts/sources/{source_id}", json={"name": "Grafana SRE", "networks": "172.26.112.0/23", "enabled": True,
                                                                      "ignore": "Speedtest*"})
        speed = self.kept(source_id, self.alerthub("Speedtest Bandwidth Low"))
        r = self.admin.post(f"/runbook/api/alerts/samples/{speed}/read").get_json()
        self.assertEqual((r["alerts"], r["ignored"]), (1, 1))
        # read all again: the readable ones go, the others stay with their reason
        two = self.kept(source_id, self.alerthub(node="overcloud-novacomputeha-5"))
        r = self.admin.post("/runbook/api/alerts/samples/read").get_json()
        self.assertEqual([x["id"] for x in r["read"]], [two])
        self.assertEqual(sorted(x["id"] for x in r["left"]), [other, big])
        # a source that is off, or removed: refused, the sample stays
        off = self.kept(source_id, self.alerthub(node="overcloud-novacomputeha-6"))
        self.tokenless(source_id, "172.26.113.15", enabled=False, confirm="")
        self.assertIn("is off", self.admin.post(f"/runbook/api/alerts/samples/{off}/read").get_json()["error"])
        self.admin.delete(f"/runbook/api/alerts/sources/{source_id}")
        self.assertIn("was removed", self.admin.post(f"/runbook/api/alerts/samples/{off}/read").get_json()["error"])
        self.assertEqual(self.admin.post("/runbook/api/alerts/samples/999/read").status_code, 400)
        op = self.client("operator1", "demo-operator-1")   # administrators only
        self.assertEqual(op.post(f"/runbook/api/alerts/samples/{off}/read", json={}).status_code, 403)
        self.assertEqual(op.post("/runbook/api/alerts/samples/read", json={}).status_code, 403)

    def test_operators_see_alerts_and_administrators_manage_them(self):
        op = self.client("operator1", "demo-operator-1")
        self.assertEqual(op.get("/runbook/api/alerts").status_code, 200)
        self.assertFalse(op.get("/runbook/api/alerts").get_json()["connected"])
        for method, url in (("get", "/runbook/api/alerts/config"), ("post", "/runbook/api/alerts/rules"), ("post", "/runbook/api/alerts/sources"),
                            ("put", "/runbook/api/alerts/settings"), ("post", "/runbook/api/alerts/rules/preview")):
            with self.subTest(url=url):
                self.assertEqual(getattr(op, method)(url, json={}).status_code, 403)
        self.assertEqual(self.app.test_client().get("/runbook/api/alerts").status_code, 401)

    # ---- Ignore on an alert, the fixes of other runs, presets
    def test_ignore_on_an_alert_ignores_its_exact_name_and_stop_ignoring_takes_it_back(self):
        sid, token = self.source()
        for fp in ("fp-a", "fp-b"):
            self.send(token, notification(alert(name="Speedtest Bandwidth Low", fingerprint=fp)))
        self.send(token, notification(alert(fingerprint="fp-c")))
        ev = next(e for e in self.events("") if e["fingerprint"] == "fp-a")
        op = self.client("operator1", "demo-operator-1")
        self.assertEqual(op.post(f"/runbook/api/alerts/{ev['id']}/ignore", json={}).status_code, 403)
        r = self.admin.post(f"/runbook/api/alerts/{ev['id']}/ignore", json={})
        self.assertEqual((r.status_code, r.get_json()["pattern"], r.get_json()["hidden"]), (200, "Speedtest Bandwidth Low", 2))
        self.assertEqual(self.alerts.source(sid)["ignore"], ["Speedtest Bandwidth Low"])
        self.assertEqual([e["fingerprint"] for e in self.events("")], ["fp-c"])   # the others moved to the history
        self.assertEqual(sorted(e["fingerprint"] for e in self.events("ignored")), ["fp-a", "fp-b"])
        self.assertTrue(any("ignore alerts named Speedtest Bandwidth Low (Ignore on alert" in d for d in self.activity("wi.alert_source")))
        self.send(token, notification(alert(name="Speedtest Bandwidth Low", fingerprint="fp-d")))   # from now on: not recorded
        self.assertEqual((len(self.events("all")), self.alerts.source(sid)["ignored"]), (1, 1))
        self.assertIn("already ignored", self.admin.post(f"/runbook/api/alerts/{ev['id']}/ignore", json={}).get_json()["error"])
        r = self.admin.post(f"/runbook/api/alerts/{ev['id']}/unignore", json={})
        self.assertEqual((r.status_code, r.get_json()["shown"], self.alerts.source(sid)["ignore"]), (200, 2, []))
        self.assertEqual(len(self.events("")), 3)
        # an exact name with * in it is ignored literally; an alert ignored by a * pattern: Edit source changes it
        self.assertEqual(self.alerts.exact_pattern("Disk * full [x]"), "Disk [*] full [[]x]")
        self.assertTrue(self.alerts.ignored_by([self.alerts.exact_pattern("Disk * full")], "Disk * full"))
        self.assertFalse(self.alerts.ignored_by([self.alerts.exact_pattern("Disk * full")], "Disk root full"))
        self.admin.put(f"/runbook/api/alerts/sources/{sid}", json={"name": "Grafana SRE", "networks": "", "ignore": "Speedtest*"})
        self.assertIn("pattern Speedtest* of the source", self.admin.post(f"/runbook/api/alerts/{ev['id']}/unignore", json={}).get_json()["error"])

    def test_the_same_fix_for_another_host_has_the_same_shape(self):
        s = self.alerts.fix_shape
        self.assertEqual(s(LIVE), s(LIVE.replace(HOST, "overcloud-novacompute-7.example.net")))
        self.assertNotEqual(s(LIVE), s(LIVE.replace("Live-migrate", "Cold-migrate")))
        self.assertEqual(s("Restart nginx on 10.248.0.11."), s("Restart nginx on 10.248.0.12."))
        self.assertNotEqual(s(TRUNCATE), s(LOGROTATE))

    def test_a_new_rule_gets_its_automatic_action_from_another_run_of_the_check(self):
        token = self.source()[1]
        other_host = "overcloud-novacomputeha-7.localdomain"
        other = drain_record(41, {"compute": "overcloud-novacomputeha-7"})   # an operator's drain of another compute
        rec = other["result"]["recommendations"][0]
        rec["text"] = rec["text"].replace(HOST, other_host)
        self.alerts.HOOKS["runs_with_fixes"] = lambda ids, after, limit: [x for x in (other,) if x["id"] > after and x["check_id"] in ids]
        cfg = self.admin.get("/runbook/api/alerts/config").get_json()
        known = [f for f in cfg["known_fixes"] if f["check_id"] == "compute-drain"]
        self.assertEqual([(f["eligible"], f["sized"], f["items"], f["run_id"], f["known"]) for f in known], [(True, True, True, 41, True)])
        self.assertEqual(self.alerts.scan_runs(), 0)   # read once
        # A new rule with that action at once: Check 1 measures the CPU of the node, smallest first, observe only.
        data = {"name": "Compute CPU", "alertname": "Compute CPU*", "matchers": "", "site": "{{labels.site}}", "cooldown": 0,
                "checks": [{"check_id": "overcloud-node-health", "params": {"role": "compute", "node": "{{labels.nodename}}"}},
                           {"check_id": "compute-drain", "params": {"compute": "{{labels.nodename}}"},
                            "action": {"fix": known[0]["key"], "mode": "observe", "order": "smallest", "max_items": 3, "measure": 0,
                                       "thresholds": {"cpu_warn": "70"}}}]}
        self.assertIn("type the rule name", self.admin.post("/runbook/api/alerts/rules", json=data).get_json()["error"])
        r = self.admin.post("/runbook/api/alerts/rules", json=dict(data, confirm="Compute CPU"))
        self.assertEqual(r.status_code, 200, r.get_json())
        action = self.alerts.rule(r.get_json()["id"])["checks"][1]["action"]
        self.assertEqual((action["order"], action["max_items"], action["thresholds"], action["mode"]),
                         ("smallest", 3, {"cpu_warn": "70"}, "observe"))   # a CPU stop gets no memory default
        # Its first alert, for another compute (ha-2): the same fix by its shape; the stop is measured with cpu_warn 70.
        self.send(token, notification(alert(name="Compute CPU high", fingerprint="fp-cpu", nodename=NODE)))
        drain = next(e for e in self.events() if e["check_id"] == "compute-drain")
        self.end(drain_record(drain["run_id"], drain["params"]))
        self.assertNotIn("is not in this result", self.events()[0]["outcome"] or "")
        self.assertEqual([(c, raw.get("cpu_warn"), raw.get("node")) for _id, c, raw in self.measured], [("overcloud-node-health", "70", NODE)])

    def cinder_rule(self, mode="observe", ticket=""):
        """A Cinder pool alert: the old snapshots of each volume first, then the volumes, smallest first, until POOL is under 70%."""
        self.alerts.HOOKS["runs_with_fixes"] = lambda ids, after, limit: [x for x in (cinder_record(41, 85),) if x["id"] > after]
        known = {f["title"]: f for f in self.admin.get("/runbook/api/alerts/config").get_json()["known_fixes"]}
        move = next(f for t, f in known.items() if t.startswith("Migrate volumes from"))
        self.assertEqual((known[SNAP_TITLE]["items"], move["items"], move["sized"]), (False, True, True))
        data = {"name": "Cinder pool", "alertname": "Cinder volume*", "matchers": "", "site": "{{labels.site}}", "cooldown": 0,
                "checks": [{"check_id": "cinder-pool-usage", "params": {"pool": POOL, "pool_warn": "70", "snapshot_days": "14"},
                            "action": {"fix": known[SNAP_TITLE]["key"], "mode": mode, "max_items": 10, "measure": 0,
                                       "thresholds": {"pool_warn": "70"},
                                       "then": {"fix": move["key"], "order": "smallest", "max_items": 5}}}],
                "confirm": "Cinder pool", "ticket": ticket}
        r = self.admin.post("/runbook/api/alerts/rules", json=data)
        self.assertEqual(r.status_code, 200, r.get_json())
        token = self.source()[1]
        self.send(token, notification(alert(name="Cinder volume over 80%", fingerprint="fp-pool")))
        self.end(cinder_record(self.events()[0]["run_id"], 85))
        self.assertEqual(self.measured[-1][1:], ("cinder-pool-usage", {"pool": POOL, "pool_warn": "70", "snapshot_days": "14"}))
        return r.get_json()["id"]

    def test_cinder_pool_old_snapshots_volume_by_volume_then_the_smallest_volumes(self):
        self.cinder_rule()
        self.end(cinder_record(self.measured[-1][0], 85))
        a = self.actions()[-1]
        self.assertEqual((a["step"], a["stop"]), ("done", "observed"))
        self.assertEqual([(i["which"], i["label"]) for i in a["items"]],
                         [("fix", SNAP_TITLE[:-1] + " (vol-a)"), ("fix", SNAP_TITLE[:-1] + " (vol-b)"),
                          ("then", "small (50 GiB)"), ("then", "big (500 GiB)")])   # mid has a recent snapshot: never by itself
        self.assertIn("; then Migrate volumes from", self.events()[0]["outcome"])
        self.assertEqual(self.fixed, [])

    def test_cinder_pool_run_stops_when_the_pool_is_under_its_level(self):
        rule_id = self.cinder_rule("run", ticket="CHG-2026-1111")
        self.assertEqual(len(self.alerts.approval_state(self.alerts.rule(rule_id))["impact"]), 2)   # both fixes need the approval
        self.end(cinder_record(self.measured[-1][0], 85))
        self.assertEqual(self.bodies, [{"confirm": "vol-a"}])   # the snapshots of vol-a, with the confirmation it needs
        self.assertIn("fix 1 of at most 10", self.fixed[0][4])
        self.alerts.fix_finished(501, "ok", "", 900)
        self.end(cinder_record(self.measured[-1][0], 82, snapped=("vol-b",)))
        self.assertEqual(self.bodies[-1], {"confirm": "vol-b"})
        self.alerts.fix_finished(502, "ok", "", 901)
        self.end(cinder_record(self.measured[-1][0], 78, snapped=()))   # no old snapshot left: then the smallest volume
        self.assertEqual((self.bodies[-1], self.fixed[-1][1]), ({"selected": [1]}, 0))   # small; the migration is the only fix left
        self.assertIn(", then, volumes 1 of at most 5", self.fixed[-1][4])
        self.alerts.fix_finished(503, "ok", "", 902)
        self.end(cinder_record(self.measured[-1][0], 69, snapped=(), moved=("small",)))
        a = self.actions()[-1]
        self.assertEqual((a["step"], a["stop"], len(self.fixed)), ("done", "gone", 3))
        self.assertEqual([i["which"] for i in a["items"]], ["fix", "fix", "then"])

    def test_stop_defaults_only_when_the_rule_sets_no_threshold(self):
        self.alerts.HOOKS["runs_with_fixes"] = lambda ids, after, limit: [x for x in (drain_record(41, {"compute": NODE}),) if x["id"] > after]
        self.alerts.scan_runs()
        key = next(f["key"] for f in self.alerts.fixes_for(None) if f["check_id"] == "compute-drain")
        def stop(health_params, thresholds):
            return self.alerts.clean_rule({"name": "x", "alertname": "x", "site": "DCB", "checks": [
                {"check_id": "compute-drain", "params": {"compute": NODE},
                 "action": {"fix": key, "measure": 1, "order": "smallest", "thresholds": thresholds}},
                {"check_id": "overcloud-node-health", "params": dict({"role": "compute", "node": NODE}, **health_params)}]})["checks"][0]["action"]["thresholds"]
        self.assertEqual(stop({}, {}), {"mem_warn": "75"})
        self.assertEqual(stop({}, {"cpu_warn": "70"}), {"cpu_warn": "70"})
        self.assertEqual(stop({}, {"cpu_warn": "70", "mem_warn": "80"}), {"cpu_warn": "70", "mem_warn": "80"})
        self.assertEqual(stop({"cpu_warn": "80"}, {}), {})   # its check sets the threshold already

    def test_every_preset_is_a_valid_rule_and_its_fix_is_a_fix_of_its_check(self):
        import glob
        import re
        code = {}
        for path in glob.glob(os.path.join(os.path.dirname(self.alerts.__file__), "wi_analysis", "*.py")):
            text = open(path, encoding="utf-8").read()
            for check_id in re.findall(r'Result\("([a-z0-9-]+)"\)', text):
                code[check_id] = code.get(check_id, "") + text.lower()
        presets = self.alerts.presets()
        self.assertGreaterEqual(len(presets), 20)
        self.assertEqual(len({p["id"] for p in presets}), len(presets))
        for p in presets:
            with self.subTest(p["id"]):
                for rx in (p.get("labels") or {}).values():
                    re.compile(rx)
                    self.assertNotIn(",", rx)   # a rule's matchers are comma or line separated
                filled = self.alerts.preset_rule(p["id"])
                self.alerts.clean_rule(dict(filled, checks=[{k: v for k, v in c.items() if k != "action"} for c in filled["checks"]]))
                for c in p["rule"]["checks"]:
                    if c.get("action"):
                        self.assertIn(c["action"]["fix"].lower(), code[c["check"]], "the fix text is not in its check")
                        if c["action"].get("then"):
                            self.assertIn(c["action"]["then"]["fix"].lower(), code[c["check"]], "the Then text is not in its check")
                        self.assertLess(c["action"].get("measure", 0), len(p["rule"]["checks"]))

    def test_presets_with_a_safe_fix_get_an_automatic_action(self):
        """A2: the presets whose check already offers a safe fix get an automatic action (observe only when the form is
        filled, preset_rule); a fix that touches traffic or security (restart lb, DNS query logging, firewalld, the
        leftover instance directories, a NIC link) never comes from a preset."""
        want = {"certificates": ("certmonger-status", "renew the certificates that expire soon", 5),
                "compute-storage-paths": ("compute-disks", "give the disks without any path their paths back", 4),
                "cdn-datasource": ("cdn-datasource", "start the stopped lb container", 1),
                "dns": ("dns-recursor-syslog", "free the disk", 1),
                "siem": ("siem-collector", "rsyslog must run and listen", 1)}
        by = {p["id"]: p for p in self.alerts.presets()}
        for pid, (check, fix, most) in want.items():
            with self.subTest(pid):
                checks = by[pid]["rule"]["checks"]
                c = next(c for c in checks if c["check"] == check)
                a = c.get("action") or {}
                self.assertEqual((a.get("fix", "").lower(), a.get("max_items", 1)), (fix, most))
                self.assertEqual(checks[a.get("measure", 0)]["check"], check)   # measured again by the same check
        never = ("restart the container", "stop the query logging", "open the syslog ports", "move the leftover", "has no link")
        for p in by.values():
            for c in p["rule"]["checks"]:
                a = c.get("action") or {}
                for text in (a.get("fix", ""), (a.get("then") or {}).get("fix", "")):
                    self.assertFalse(any(n in text.lower() for n in never), (p["id"], text))

    def test_create_rule_on_an_alert_fills_the_preset_that_fits_it(self):
        fits = lambda name, **labels: (self.alerts.preset_for(name, labels) or {}).get("id")   # noqa: E731
        self.assertEqual(fits("OpenStack Cloud Node High Memory Usage", nodename="overcloud-novacomputeha-2"), "openstack-compute-memory")
        self.assertEqual(fits("OpenStack Cloud Node High CPU Usage", nodename="overcloud-novacomputeha-2"), "openstack-compute-cpu")
        self.assertEqual(fits("Memory ECC error", nodename="overcloud-novacomputeha-2"), "hardware")
        self.assertEqual(fits("OpenStack Cloud Node High Memory Usage", nodename="overcloud-controller-0"), "openstack-controller-resources")
        self.assertEqual(fits("disk_alert_cdn_run", instance="172.31.138.67:9100"), "cdn-run")
        self.assertEqual(fits("High Memory Usage", instance="10.248.0.11:9100"), "linux-host")
        self.assertEqual(fits("Galera cluster size low"), "galera")
        self.assertIsNone(fits("Speedtest Bandwidth Low"))
        self.assertIsNone(fits("Upload success rate"))
        # Create rule on the alert: the form from the preset, its exact name; the live migration once a drain ran in the portal
        token = self.source()[1]
        self.send(token, notification(alert(name="OpenStack Cloud Node High Memory Usage", fingerprint="fp-m", nodename=NODE)))
        ev = self.events()[0]
        p = self.admin.post("/runbook/api/alerts/presets/fill", json={"event_id": ev["id"]}).get_json()["rule"]
        self.assertEqual((p["preset"], p["alertname"], p["site"], p["matchers"]),
                         ("openstack-compute-memory", "OpenStack Cloud Node High Memory Usage", "{{labels.site}}", "nodename=~(?i).*compute.*"))
        self.assertEqual([(c["check_id"], c["params"].get("node") or c["params"].get("compute")) for c in p["checks"]],
                         [("overcloud-node-health", "{{labels.nodename}}"), ("compute-drain", "{{labels.nodename}}")])
        self.assertNotIn("action", p["checks"][1])
        self.assertIn("run the check once from Checks", p["notes"][0])
        self.alerts.HOOKS["runs_with_fixes"] = lambda ids, after, limit: [x for x in (drain_record(41, {"compute": NODE}),) if x["id"] > after]
        self.alerts.scan_runs()
        p = self.admin.post("/runbook/api/alerts/presets/fill", json={"event_id": ev["id"]}).get_json()["rule"]
        a = p["checks"][1]["action"]
        self.assertEqual((a["mode"], a["order"], a["max_items"], a["measure"], a["thresholds"], p["notes"]),
                         ("observe", "smallest", 5, 0, {"mem_warn": "80"}, []))
        r = self.admin.post("/runbook/api/alerts/rules", json=dict(p, enabled=True, auto_per_hour=3, confirm=p["name"]))
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertEqual(self.admin.post("/runbook/api/alerts/presets/fill", json={"preset_id": "linux-host"}).get_json()["rule"]["alertname"],
                         "*memory*")
        op = self.client("operator1", "demo-operator-1")
        self.assertEqual(op.post("/runbook/api/alerts/presets/fill", json={"preset_id": "linux-host"}).status_code, 403)


    def test_pick_skips_manual_single_fix(self):
        """A fix without items that the LUN copy guard made manual is never taken by an automatic action."""
        cfg = {"fix": "k", "title": "Detach it", "order": "listed", "max_items": 1}
        manual = [{"key": "k", "title": "Detach it", "state": {"target": "a", "manual": "NetApp not read: LUN copies unknown"}}]
        self.assertEqual(self.alerts._pick(cfg, manual, []), (None, "", None))
        plain = [{"key": "k", "title": "Detach it", "state": {"target": "a"}}]
        self.assertIs(self.alerts._pick(cfg, plain, [])[0], plain[0])

    def test_plan_skips_manual_single_fix(self):
        cfg = {"fix": "k", "title": "Detach it", "order": "listed", "max_items": 1}
        manual = [{"key": "k", "title": "Detach it", "state": {"target": "a", "manual": "LUN volume-x also in y"}}]
        self.assertEqual(self.alerts._plan(cfg, manual), [])
        self.assertEqual(len(self.alerts._plan(cfg, [{"key": "k", "title": "Detach it", "state": {"target": "a"}}])), 1)

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

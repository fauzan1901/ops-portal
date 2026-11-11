"""Status module (modules/health): the products and their checks, a round (checks one after the other as "health"),
the page of a site, Run now, the scheduler and the metrics on the alert scrape. The checks themselves are faked
(rounds.HOOKS); a real check runs Ansible (tests/test_wi.py)."""
import contextlib
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import threading
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
  DCA:
    mgmt: {host: 10.253.179.11, user: admin, private_key: /etc/ops-portal/keys/openstack_mgmt}
    director: {host: 10.253.179.101, user: stack}
  LAB: {}
""")
with open(os.path.join(TMP, "auth.yml"), "w") as f:
    f.write("admins: []\n")
os.environ.update(OPS_SITES=os.path.join(TMP, "sites.yml"), OPS_DATA=os.path.join(TMP, "data"),
                  OPS_DB=os.path.join(TMP, "data", "portal.db"), OPS_AUTH=os.path.join(TMP, "auth.yml"),
                  OPS_CREDENTIALS_KEY=os.path.join(TMP, "credentials.key"), OPS_MODULES="wi,health",
                  STATUS_INTERVAL_HOURS="0")   # no scheduler thread in the tests: tick() is called by hand

RESTORE_PRIME = ("ontap-", "vcenter-", "vcd-", "nsxt-", "cert-inventory")
BMCS = {"DCB": ["dcb-compute-01", "dcb-storage-02"]}   # the BMCs of the page BMC per site


class HealthTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import portal_auth
        store = portal_auth.Store(os.environ["OPS_DB"])
        store.add_local_user("portaladmin", portal_auth.hash_password("demo-portal-admin"), "admin", "Admin", "", "test")
        store.add_local_user("operator1", portal_auth.hash_password("demo-operator-1"), "operator", "Op", "", "test", "health")
        store.add_local_user("operator2", portal_auth.hash_password("demo-operator-2"), "operator", "Op2", "", "test", "wi")
        import app as webapp
        from modules import health
        from modules.health import products, rounds
        from modules.wi import alerts, catalog
        cls.app, cls.health, cls.products, cls.rounds, cls.alerts, cls.catalog = webapp.app, health, products, rounds, alerts, catalog

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(TMP, ignore_errors=True)

    def setUp(self):
        with contextlib.closing(sqlite3.connect(os.environ["OPS_DB"])) as db, db:
            db.execute("DELETE FROM health_items")
            db.execute("DELETE FROM health_rounds")
        self.started, self.runs, self.outcome, self.next_run = [], {}, {}, 100
        hooks = dict(self.rounds.HOOKS)
        self.addCleanup(self.rounds.HOOKS.update, hooks)
        self.rounds.HOOKS.update(start=self.fake_start, access=self.fake_access, get_run=lambda rid: self.runs.get(rid),
                                 targets=lambda site, kind: BMCS.get(site, []) if kind == "bmc" else [])
        for name, value in (("BUSY_WAIT", 0), ("CHECK_WAIT", 5)):
            patcher = mock.patch.object(self.rounds, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.admin = self.client()

    # ---- fakes of Runbook Automation
    def fake_access(self, check_id, site):
        if site == "LAB":
            return {"runnable": False, "missing": ["OpenStack of LAB is not in sites.yml (mgmt, director)"]}
        if site == "DCA" and check_id.startswith(RESTORE_PRIME):
            return {"runnable": False, "missing": [f"No account for {check_id} on DCA"]}
        if check_id == "bmc-health" and not BMCS.get(site):
            return {"runnable": False, "missing": [f"No BMC of {site} on the page BMC"]}
        return {"runnable": True, "missing": []}

    def fake_start(self, user, site, check_id, raw, after, note):
        """A check that ends at once with self.outcome[check_id] (default ok); "busy": the same check already runs."""
        status = self.outcome.get(check_id, "ok")
        if status == "busy":
            raise ValueError("The same check with the same parameters is already running.")
        self.next_run += 1
        rid = self.next_run
        self.started.append((user["username"], site, check_id, dict(raw), note))
        bad = status in ("warn", "fail")
        self.runs[rid] = {"id": rid, "status": status, "summary": f"{check_id}: {status}", "finished": "2026-11-11T14:00:00+07:00",
                          "result": {"steps": [{"title": "Memory", "status": status, "detail": "92% used. Threshold 85%."}] if bad else
                                     [{"title": "Memory", "status": "ok"}],
                                     "recommendations": [{"text": "Live-migrate the instances you tick off compute-2, one at a time. Nothing is ticked.",
                                                          "action": {"kind": "openstack"}},
                                                         {"text": "Look at the logs of the node. Then decide."}] if bad else []}}
        after(rid, status)   # the run ended at once
        return rid

    def client(self, user="portaladmin", password="demo-portal-admin"):
        c = self.app.test_client()
        r = c.post("/api/login", json={"username": user, "password": password})
        self.assertEqual(r.status_code, 200, r.get_json())
        return c

    def round(self, site="DCB", client=None):
        r = (client or self.admin).post("/status/api/rounds", json={"site": site})
        self.assertEqual(r.status_code, 200, r.get_json())
        self.rounds._threads[site].join(10)
        return r.get_json()["round_id"]

    def view(self, site="DCB"):
        r = self.admin.get(f"/status/api/overview?site={site}")
        self.assertEqual(r.status_code, 200, r.get_json())
        return {p["id"]: p for p in r.get_json()["products"]}

    # ---- the products
    def test_every_product_runs_read_only_checks_that_need_no_parameter(self):
        ids = self.products.check_ids()
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual([p["id"] for p in self.products.PRODUCTS], ["openstack", "ontap", "prime", "hardware"])
        for p in self.products.PRODUCTS:
            for entry in p["checks"]:
                with self.subTest(entry["check"]):
                    check = self.catalog.get(entry["check"])
                    self.assertEqual(check["status"], "ready")
                    self.assertFalse(check.get("bundle") or check.get("permission"), "a round runs no log collection")
                    given = entry.get("params") or {}
                    names = {x["name"] for x in check["params"]}
                    self.assertLessEqual(set(given), names)
                    for x in check["params"]:
                        if x.get("required"):   # a "per" product gives its target in entry["param"]
                            self.assertTrue(x["name"] in given or x.get("default") is not None or x["name"] == entry.get("param"),
                                            f"{x['name']} is needed")
                    if p.get("per"):
                        self.assertIn(entry.get("param"), names)
                    for nxt in entry.get("next") or []:
                        self.assertEqual(self.catalog.get(nxt)["status"], "ready", nxt)

    # ---- a round and the page
    def test_a_round_runs_every_check_as_health_and_the_page_shows_each_product(self):
        self.outcome = {"galera-wsrep": "fail", "ontap-capacity": "warn"}
        rid = self.round("DCB")
        self.assertEqual({u for u, *_ in self.started}, {"health"})
        expected = [c for c in self.products.check_ids() if c != "bmc-health"] + ["bmc-health", "bmc-health"]   # one per BMC
        self.assertEqual([c for _u, _s, c, _r, _n in self.started], expected)   # one after the other, in order
        self.assertEqual([r for _u, _s, c, r, _n in self.started if c == "bmc-health"], [{"bmc": "dcb-compute-01"}, {"bmc": "dcb-storage-02"}])
        self.assertIn(("health", "DCB", "overcloud-node-health", {"role": "all"}, f"health round #{rid}"), self.started)
        v = self.view("DCB")
        self.assertEqual({k: p["status"] for k, p in v.items()}, {"openstack": "problem", "ontap": "warn", "prime": "ok", "hardware": "ok"})
        self.assertEqual([(c["title"], c["key"]) for c in v["hardware"]["checks"]],
                         [("Server hardware (BMC): dcb-compute-01", "bmc-health:dcb-compute-01"),
                          ("Server hardware (BMC): dcb-storage-02", "bmc-health:dcb-storage-02")])
        galera = next(c for c in v["openstack"]["checks"] if c["check_id"] == "galera-wsrep")
        self.assertEqual((galera["status"], galera["summary"], galera["findings"][0]["title"]), ("fail", "galera-wsrep: fail", "Memory"))
        self.assertEqual(galera["recommendations"], [{"title": "Live-migrate the instances you tick off compute-2, one at a time.", "fix": True},
                                                     {"title": "Look at the logs of the node.", "fix": False}])
        self.assertEqual([x["id"] for x in galera["next"]], ["pacemaker-health", "overcloud-logs"])
        ok = next(c for c in v["openstack"]["checks"] if c["check_id"] == "pacemaker-health")
        self.assertEqual((ok["status"], ok["next"], ok["run_id"] is not None), ("ok", [], True))
        self.assertEqual(v["openstack"]["counts"], {"fail": 1, "ok": 13})   # with the OVN and Nova checks of deploy/ovn-nova-checks
        self.assertTrue(any("Status round #" in e["detail"] and "DCB" in e["detail"] for e in self.app_events("health.round")))

    def app_events(self, action):
        from core import PORTAL
        return [e for e in PORTAL.store.events() if e["action"] == action]

    def test_not_configured_products_and_a_check_already_running(self):
        self.outcome = {"rabbitmq-queues": "busy"}
        self.round("DCA")
        v = self.view("DCA")
        self.assertEqual((v["ontap"]["status"], v["prime"]["status"], v["hardware"]["status"]), ("not-configured",) * 3)
        self.assertEqual(v["hardware"]["checks"][0]["note"], "No BMC of DCA on the page BMC")
        self.assertEqual(v["ontap"]["checks"][0]["note"], "No account for ontap-cluster-health on DCA")
        rabbit = next(c for c in v["openstack"]["checks"] if c["check_id"] == "rabbitmq-queues")
        self.assertEqual(rabbit["status"], "error")
        self.assertIn("already running", rabbit["note"])
        self.assertEqual(v["openstack"]["status"], "unknown")   # could not check one of them; the others are OK
        self.assertEqual(self.view("LAB")["openstack"]["status"], "never")   # no round of LAB yet
        r = self.admin.post("/status/api/rounds", json={"site": "LAB"})
        self.assertIn("No product is configured on LAB", r.get_json()["error"])

    def test_one_round_of_a_site_at_a_time_and_who_may_start_it(self):
        gate = threading.Event()
        slow = self.fake_start

        def held(*a):
            gate.wait(5)
            return slow(*a)
        self.rounds.HOOKS["start"] = held
        r = self.admin.post("/status/api/rounds", json={"site": "DCB"})
        self.assertEqual(r.status_code, 200)
        again = self.admin.post("/status/api/rounds", json={"site": "DCB"})
        self.assertIn("is running", again.get_json()["error"])
        self.assertTrue(self.admin.get("/status/api/overview?site=DCB").get_json()["running"])
        gate.set()
        self.rounds._threads["DCB"].join(10)
        op = self.client("operator1", "demo-operator-1")   # a user of the module may run it
        self.round("DCB", op)
        other = self.client("operator2", "demo-operator-2")   # Runbook Automation only
        self.assertEqual(other.get("/status/api/overview?site=DCB").status_code, 403)
        self.assertEqual(other.post("/status/api/rounds", json={"site": "DCB"}).status_code, 403)
        self.assertEqual(self.app.test_client().get("/status/api/overview?site=DCB").status_code, 401)
        self.assertIn("Unknown site", self.admin.post("/status/api/rounds", json={"site": "XYZ"}).get_json()["error"])
        s = op.get("/status/api/session").get_json()
        self.assertEqual({x["name"]: x["products"] for x in s["sites"]},
                         {"DCB": ["openstack", "ontap", "prime", "hardware"], "DCA": ["openstack"], "LAB": []})

    # ---- the scheduler
    def test_the_scheduler_starts_the_rounds_that_are_due_on_configured_sites(self):
        with mock.patch.object(self.rounds, "INTERVAL_HOURS", 4):
            self.assertEqual(self.rounds.tick(), ["DCB", "DCA"])   # LAB: nothing configured
            for s in ("DCB", "DCA"):
                self.rounds._threads[s].join(10)
            self.assertEqual(self.rounds.tick(), [])   # not due again before 4 hours
            with contextlib.closing(sqlite3.connect(os.environ["OPS_DB"])) as db, db:
                db.execute("UPDATE health_rounds SET started = '2026-01-01T00:00:00+07:00' WHERE site = 'DCA'")
            self.assertEqual(self.rounds.tick(), ["DCA"])
            self.rounds._threads["DCA"].join(10)
            self.assertEqual(self.rounds.last_round("DCA")["trigger"], "auto")
            self.assertEqual(self.rounds.last_round("DCA")["username"], "health")
        with mock.patch.object(self.rounds, "INTERVAL_HOURS", 0):
            self.assertEqual(self.rounds.tick(), [])   # Run now only
            self.assertEqual(self.rounds.next_round("DCB"), "")

    def test_a_bmc_with_a_problem_makes_the_hardware_not_safe_and_names_the_server(self):
        self.outcome = {"bmc-health": "fail"}
        self.round("DCB")
        hw = self.view("DCB")["hardware"]
        self.assertEqual((hw["status"], hw["counts"]), ("problem", {"fail": 2}))
        self.assertEqual([c["next"][0]["id"] for c in hw["checks"]], ["ironic-nodes", "ironic-nodes"])
        self.assertRegex(self.alerts.metrics(), r'ops_platform_status\{(product="hardware",site="DCB"|site="DCB",product="hardware")\} 2\n')
        # before any round: the BMCs of the site are listed, not checked yet
        with contextlib.closing(sqlite3.connect(os.environ["OPS_DB"])) as db, db:
            db.execute("DELETE FROM health_items")
            db.execute("DELETE FROM health_rounds")
        self.assertEqual([c["status"] for c in self.view("DCB")["hardware"]["checks"]], ["never", "never"])

    def test_a_round_the_portal_stopped_is_marked_stopped(self):
        with contextlib.closing(sqlite3.connect(os.environ["OPS_DB"])) as db, db:
            rid = db.execute("INSERT INTO health_rounds (site, trigger, username, started) VALUES ('DCB', 'auto', 'health', "
                             "'2026-11-11T10:00:00+07:00')").lastrowid
            db.execute("INSERT INTO health_items (round_id, product, check_id, status) VALUES (?, 'openstack', 'galera-wsrep', 'running')", (rid,))
        self.rounds.init()
        self.assertTrue(self.rounds.last_round("DCB")["finished"])
        self.assertEqual(self.rounds.items(rid)[0]["status"], "stopped")
        self.assertEqual(self.view("DCB")["openstack"]["status"], "unknown")

    # ---- Runs of Runbook Automation
    def test_runs_leave_the_health_rounds_out_unless_that_user_is_chosen(self):
        from modules.wi import runs
        check = self.catalog.get("galera-wsrep")
        mine = runs.begin("portaladmin", "DCB", check, {}, "", "127.0.0.1")
        robot = runs.begin("health", "DCB", check, {}, "", "health")
        ids = lambda url: [r["id"] for r in self.admin.get(url).get_json()["items"]]   # noqa: E731
        self.assertIn(mine, ids("/runbook/api/runs?limit=200"))
        self.assertNotIn(robot, ids("/runbook/api/runs?limit=200"))
        self.assertEqual(ids("/runbook/api/runs?limit=200&user=health"), [robot])
        self.assertIn("health", self.admin.get("/runbook/api/runs").get_json()["users"])   # the filter offers it
        self.assertEqual(self.admin.get(f"/runbook/api/runs/{robot}").status_code, 200)   # Status links it by id
        csv = lambda url: "," + self.admin.get(url).get_data(as_text=True).replace("\n", ",").replace(";", ",")   # noqa: E731
        self.assertIn(",health,", csv("/runbook/export/runs.csv?user=health"))
        self.assertNotIn(",health,", csv("/runbook/export/runs.csv"))

    # ---- metrics on the alert scrape
    def test_the_status_of_every_product_joins_the_alert_metrics(self):
        self.outcome = {"galera-wsrep": "fail"}
        self.round("DCB")
        text = self.alerts.metrics()
        self.assertRegex(text, r'ops_platform_status\{(product="openstack",site="DCB"|site="DCB",product="openstack")\} 2\n')
        self.assertRegex(text, r'ops_platform_status\{(product="prime",site="DCB"|site="DCB",product="prime")\} 0\n')
        self.assertRegex(text, r'ops_platform_round_age_seconds\{site="DCB"\} \d+\n')
        self.assertRegex(text, r'ops_platform_round_running\{site="DCA"\} 0\n')
        self.assertNotRegex(text, r'ops_platform_status\{[^}]*site="DCA"')   # no round of DCA yet
        self.assertEqual(len(re.findall(r"^# TYPE ops_platform_status gauge$", text, re.M)), 1)


if __name__ == "__main__":
    unittest.main()

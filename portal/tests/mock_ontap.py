"""Mock ONTAP REST API (HTTPS + basic auth) for automated tests and the Web UI demo mode.

Emulated endpoints (the ones used by the Web UI and playbooks):
  GET  /api/cluster
  GET  /api/storage/luns?name=<full path or *suffix>
  GET  /api/storage/volumes?name=<a|b|...>   (FlexVols of the Cinder pools, for the pool choice and lun move)
  GET  /api/storage/volumes/<uuid>
  GET  /api/storage/volumes/<uuid>/snapshots
  POST /api/private/cli/volume/snapshot/restore-file
  PATCH /api/storage/luns/<uuid> {"name": "<path in another FlexVol>"}   (lun move; progress in the movement field)
  GET/PATCH /api/network/ip/interfaces/<uuid> {"location": {"is_home": true}} / {"enabled": true}   (revert a LIF)
Test helper endpoints (no auth): GET /__state, POST /__rename {"from", "to"}, POST /__delete {"name"}
"""
import base64
import copy
import datetime
import json
import os
import re
import ssl
import subprocess
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

USER, PASSWORD = "admin", "secret"
GIB = 1024 ** 3
VOLUME_ID = "a80a1a07-06b8-489b-a984-b046981f68b9"        # sample volume from the WI
FULL_VOLUME_ID = "22222222-2222-4222-8222-222222222222"   # LUN in an almost full FlexVol
# A migrated/retyped volume: OpenStack ID 3333…, but its LUN is named volume-<name_id> (4444…).
NAMEID_VOLUME_ID = "33333333-3333-4333-8333-333333333333"
NAMEID_BACKEND_ID = "44444444-4444-4444-8444-444444444444"
BOOT_VOLUME_ID = "55555555-5555-4555-8555-555555555555"   # boot disk (vda) of instance vm-01 in the fake director
SVM = "SVM_ISCSI_OPENSTACK"
OTHER_SVM = "SVM_ARCHIVE"   # the archive tier FlexVol is in another SVM: lun move cannot target it
SNAPSHOTS = [  # (name, create_time) like ONTAP hourly/daily/weekly schedules
    ("weekly.2025-12-14_0015", "2025-12-14T00:15:00+07:00"),
    ("daily.2025-12-17_0010", "2025-12-17T00:10:00+07:00"),
    ("hourly.2025-12-17_1705", "2025-12-17T17:05:00+07:00"),
    ("hourly.2025-12-17_1805", "2025-12-17T18:05:00+07:00"),
    ("hourly.2025-12-17_1905", "2025-12-17T19:05:00+07:00"),
    ("hourly.2025-12-17_2005", "2025-12-17T20:05:00+07:00"),
]


def make_cert(workdir):
    cert, key = os.path.join(workdir, "ontap.crt"), os.path.join(workdir, "ontap.key")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=mock-ontap",
                    "-keyout", key, "-out", cert], check=True, capture_output=True)
    return cert, key


def error(message, code="1"):
    return {"error": {"message": message, "code": code}}


class MockOntap:
    def __init__(self, cluster_name, cert, key, port=0, prefix="DCAOPNSTACK", reject=False, password=PASSWORD, user=None,
                 readonly=None, mgmt_not_home=False):
        # Each ONTAP site has its own account. user=None: any username is accepted (for automated tests).
        # readonly=(user, password): an extra account with the ONTAP role readonly (Operation Automation): GET only, 403 otherwise.
        # mgmt_not_home: the cluster_mgmt LIF runs on node 03 instead of its home node 01 (after a cable move).
        self.user, self.password, self.readonly = user, password, readonly
        self.mgmt_not_home = mgmt_not_home
        self.cluster = {"name": cluster_name, "version": {"full": "NetApp Release 9.14.1P3", "generation": 9, "major": 14, "minor": 1}}
        self.cert, self.key, self.port, self.reject = cert, key, port, reject
        self.lock = threading.Lock()
        self.volumes, self.luns, self.snapshots, self.cli_calls = {}, {}, {}, []
        self.fail_restore = None
        # lun move (native REST): the LUN moves to the destination path at once, movement.progress rises on every read
        # until complete. fail_move = failure message (state failed). stop_moves = number of attempts ONTAP stops without
        # creating the destination LUN (as on DCB when a lun move starts too soon after restore-file).
        self.move_calls, self.fail_move, self.stop_moves = [], None, 0
        self.patch_delay = 0   # seconds before the PATCH returns (large LUN: ONTAP is slow to answer a lun move request)
        # Restored LUN: used starts at 0 and grows on every read, up to used_ratio x the source LUN used space.
        # used_ratio < 1 emulates data that changed after the snapshot (used stops below the existing LUN).
        self.used_ratio = 1.0
        self.growing = {}
        self._seed(prefix)

    def _seed(self, prefix):
        for number, available, lun_id in ((14, 2048 * GIB, VOLUME_ID), (15, 10 * GIB, FULL_VOLUME_ID)):
            vol_uuid = str(uuid.uuid4())
            name = f"{prefix}_CINDER_{number}_vol"
            self.volumes[vol_uuid] = {"uuid": vol_uuid, "name": name, "state": "online", "svm": {"name": SVM},
                                      "space": {"size": 10240 * GIB, "available": available}}
            self.snapshots[vol_uuid] = [{"uuid": str(uuid.uuid4()), "name": n, "create_time": t} for n, t in SNAPSHOTS]
            self._add_lun(f"/vol/{name}/volume-{lun_id}", vol_uuid, mapped=True)
            if number == 14:
                self._add_lun(f"/vol/{name}/volume-{NAMEID_BACKEND_ID}", vol_uuid, mapped=True)
                self._add_lun(f"/vol/{name}/volume-{BOOT_VOLUME_ID}", vol_uuid, mapped=True)
        # More pools of the same backend (see the Cinder pools in fake_director): 16 has room, 17 is in another SVM,
        # TEST50 is a test pool (most room, but never a restore target).
        for name, svm, available in ((f"{prefix}_CINDER_16_vol", SVM, 6000), (f"{prefix}_CINDER_17_vol", OTHER_SVM, 5000),
                                     (f"{prefix}_CINDER_TEST50_vol", SVM, 9000)):
            vol_uuid = str(uuid.uuid4())
            self.volumes[vol_uuid] = {"uuid": vol_uuid, "name": name, "state": "online", "svm": {"name": svm},
                                      "space": {"size": 10240 * GIB, "available": available * GIB}}
            self.snapshots[vol_uuid] = []
        # FlexVols of other tier pools (see the pools in fake_director): NVMe in the same SVM, an unnumbered NVMe test pool
        # and an NVMe clone (most free space, but must never be chosen), and archive in another SVM.
        for name, svm, available in ((f"{prefix}_NVME_01_vol", SVM, 4096), (f"{prefix}_NVME_TEST99_vol", SVM, 9000),
                                     (f"{prefix}_NVME_01_vol_clone_7", SVM, 9999), (f"{prefix}_ARCHIVE_01_vol", OTHER_SVM, 4096)):
            vol_uuid = str(uuid.uuid4())
            self.volumes[vol_uuid] = {"uuid": vol_uuid, "name": name, "state": "online", "svm": {"name": svm},
                                      "space": {"size": 20480 * GIB, "available": available * GIB}}
            self.snapshots[vol_uuid] = []
        # Cloned/reclaimed FlexVols (not Cinder pools) hold LUN copies with the same name: they must be ignored.
        for name, lun_id in ((f"{prefix}_CINDER_14_vol_clone_1", VOLUME_ID), (f"{prefix}_CINDER_15_vol_reclaimed", FULL_VOLUME_ID)):
            vol_uuid = str(uuid.uuid4())
            self.volumes[vol_uuid] = {"uuid": vol_uuid, "name": name, "state": "online", "svm": {"name": SVM},
                                      "space": {"size": 10240 * GIB, "available": 5000 * GIB}}
            self.snapshots[vol_uuid] = []
            self._add_lun(f"/vol/{name}/volume-{lun_id}", vol_uuid)

    def _add_lun(self, path, vol_uuid, mapped=False):
        vol = self.volumes[vol_uuid]
        self.luns[path] = {"uuid": str(uuid.uuid4()), "name": path, "svm": {"name": SVM},
                           "location": {"volume": {"name": vol["name"], "uuid": vol_uuid}},
                           "space": {"size": 100 * GIB, "used": 30 * GIB}, "status": {"state": "online", "mapped": mapped}}

    def _advance_movement(self, lun):
        progress = (lun.get("movement") or {}).get("progress")
        if not progress:
            return
        if progress.get("stop_after") is not None:   # stopped by ONTAP: no movement, the LUN stays at the source path
            progress["stop_after"] -= 1
            if progress["stop_after"] < 0:
                del lun["movement"]
            return
        if self.fail_move:
            progress.update(state="failed", failure={"message": self.fail_move})
        elif progress["state"] == "preparing":
            progress.update(state="replicating", percent_complete=0)
        elif progress["state"] == "replicating":
            progress["percent_complete"] = min(100, progress["percent_complete"] + 50)
            if progress["percent_complete"] >= 100:
                progress["state"] = "complete"
        elif progress["state"] == "complete":
            del lun["movement"]

    def find_luns(self, pattern):
        with self.lock:
            if pattern.startswith("*"):
                found = [l for p, l in self.luns.items() if p.endswith(pattern[1:])]
                result = [copy.deepcopy(l) for l in found]
                for lun in found:
                    self._advance_movement(lun)
                return result
            if pattern in self.growing:
                final, step = self.growing[pattern]
                space = self.luns[pattern]["space"]
                space["used"] = min(final, space["used"] + step)
                if space["used"] >= final:
                    del self.growing[pattern]
            return [copy.deepcopy(self.luns[pattern])] if pattern in self.luns else []

    def restore_file(self, body):
        missing = [k for k in ("vserver", "volume", "snapshot", "path", "restore-path") if not body.get(k)]
        if missing:
            return 400, error(f"Missing value for {', '.join(missing)}", "2")
        with self.lock:
            self.cli_calls.append(dict(body))
            if self.fail_restore:
                return 400, error(self.fail_restore)
            vol = next((v for v in self.volumes.values() if v["name"] == body["volume"] and v["svm"]["name"] == body["vserver"]), None)
            if not vol:
                return 400, error(f'Volume "{body["volume"]}" in Vserver "{body["vserver"]}" does not exist.', "917927")
            if body["snapshot"] not in [s["name"] for s in self.snapshots[vol["uuid"]]]:
                return 400, error(f'Snapshot copy "{body["snapshot"]}" does not exist.', "15661")
            if body["path"] not in self.luns:
                return 400, error(f'File "{body["path"]}" does not exist in Snapshot copy.', "13042")
            if body["restore-path"] in self.luns:
                return 400, error(f'File "{body["restore-path"]}" already exists.', "13043")
            if not body["restore-path"].startswith(f"/vol/{vol['name']}/"):
                return 400, error("Restore path must be in the same volume.", "13001")
            self._add_lun(body["restore-path"], vol["uuid"])
            source_used = self.luns[body["path"]]["space"]["used"]
            self.luns[body["restore-path"]]["space"]["used"] = 0
            self.growing[body["restore-path"]] = (int(source_used * self.used_ratio), max(1, int(source_used * 0.4)))
        return 200, {"num_records": 1, "records": [{"cli_output": ""}]}

    def find_volumes(self, names):
        """FlexVols by name ({""} = all), with space.used (size - available) like ONTAP."""
        with self.lock:
            found = [copy.deepcopy(v) for v in self.volumes.values() if names == {""} or v["name"] in names]
        for v in found:
            space = v.get("space") or {}
            space["used"] = space.get("size", 0) - space.get("available", 0)
            space.setdefault("snapshot", {"used": 0, "reserve_percent": 5})
        return found

    # ---- read-only data of the cluster (Operation Automation "ONTAP cluster health") ----
    def nodes(self):
        prefix = self.cluster["name"].replace("-ONTAP", "STNCL")
        return [f"{prefix}-0{i}" for i in range(1, 5)]

    def node_records(self):
        return [{"name": n, "state": "up", "membership": "member", "service_processor": {
            "state": "online", "ipv4_interface": {"address": f"10.238.0.{20 + i}"}}} for i, n in enumerate(self.nodes())]

    @staticmethod
    def lif_uuid(name):
        return str(uuid.uuid5(uuid.NAMESPACE_URL, f"lif/{name}"))

    def lifs(self):
        return [dict(l, uuid=self.lif_uuid(f"{self.cluster['name']}/{l['name']}")) for l in self._lifs()]

    def lif_patch(self, lif_uuid, body):
        """Revert (location.is_home true) or enable the cluster management LIF, like ONTAP."""
        lif = next((l for l in self.lifs() if l["uuid"] == lif_uuid), None)
        if not lif:
            return 404, error("entry doesn't exist", "4")
        if (body.get("location") or {}).get("is_home") is True and lif["name"] == "cluster_mgmt":
            self.mgmt_not_home = False
        return 200, {}

    def _lifs(self):
        nodes, svm = self.nodes(), self.cluster["name"].replace("-ONTAP", "STNCL")
        current = nodes[2] if self.mgmt_not_home else nodes[0]
        lifs = [{"name": "cluster_mgmt", "svm": {"name": svm}, "scope": "cluster", "ip": {"address": "10.238.0.44"}, "state": "up",
                 "enabled": True, "location": {"home_node": {"name": nodes[0]}, "home_port": {"name": "e0M"},
                                               "node": {"name": current}, "port": {"name": "e0M"}, "is_home": not self.mgmt_not_home}}]
        for i, n in enumerate(nodes):
            lifs.append({"name": f"{n}_mgmt1", "svm": {"name": svm}, "scope": "cluster", "ip": {"address": f"10.238.0.{48 + i}"},
                         "state": "up", "enabled": True, "location": {"home_node": {"name": n}, "home_port": {"name": "e0M"},
                                                                      "node": {"name": n}, "port": {"name": "e0M"}, "is_home": True}})
            lifs.append({"name": f"{n}_iscsi_lif_1", "svm": {"name": SVM}, "scope": "svm", "ip": {"address": f"10.239.0.{10 + i}"},
                         "state": "up", "enabled": True, "location": {"home_node": {"name": n}, "home_port": {"name": "a0a-100"},
                                                                      "node": {"name": n}, "port": {"name": "a0a-100"}, "is_home": True}})
        return lifs

    def events(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        if not self.mgmt_not_home:
            return []
        return [{"time": (now - datetime.timedelta(minutes=m)).isoformat(timespec="seconds"), "node": {"name": self.nodes()[0]},
                 "message": {"severity": "error", "name": name}, "log_message": text}
                for m, name, text in ((42, "vifmgr.lifs.noredundancy", "No redundancy in the failover configuration for 1 LIF assigned to node."),
                                      (44, "vifmgr.portdown", "A link down event was received on node port e0M."))]

    def lun_patch(self, lun_uuid, body):
        with self.lock:
            self.move_calls.append({"uuid": lun_uuid, **body})
            src, lun = next(((p, l) for p, l in self.luns.items() if l["uuid"] == lun_uuid), (None, None))
            if not lun:
                return 404, error(f'LUN "{lun_uuid}" not found.', "5374852")
            dst = body.get("name", src)
            if dst == src:
                return 200, {}
            if dst in self.luns:
                return 400, error(f'LUN "{dst}" already exists.', "5374920")
            dest_vol = next((v for v in self.volumes.values() if dst.startswith(f"/vol/{v['name']}/")), None)
            if not dest_vol or dest_vol["svm"]["name"] != lun["svm"]["name"]:
                return 400, error("Moving a LUN to a volume in a different SVM is not supported.", "5374934")
            if self.stop_moves > 0:   # stopped by ONTAP before the destination LUN exists
                self.stop_moves -= 1
                lun["movement"] = {"progress": {"state": "preparing", "percent_complete": 0, "stop_after": 1}}
                return 200, {}
            # Like ONTAP (promote early): the LUN is at the destination path at once, data is copied in the background.
            self.growing.pop(src, None)
            del self.luns[src]
            lun.update(name=dst, location={"volume": {"name": dest_vol["name"], "uuid": dest_vol["uuid"]}},
                       movement={"progress": {"state": "preparing", "percent_complete": 50}})
            self.luns[dst] = lun
        return 200, {}

    def rename(self, old, new):
        with self.lock:
            if old in self.luns and new not in self.luns:
                self.growing.pop(old, None)
                lun = self.luns.pop(old)
                lun["name"] = new
                self.luns[new] = lun
                return True
        return False

    def delete_lun(self, path):
        with self.lock:
            self.growing.pop(path, None)
            return self.luns.pop(path, None) is not None

    def state(self):
        with self.lock:
            return {"luns": sorted(self.luns), "cli_calls": list(self.cli_calls), "move_calls": list(self.move_calls)}

    # ---------------- server ----------------
    def start(self):
        handler = type("Handler", (Handler,), {"ontap": self})
        self.httpd = ThreadingHTTPServer(("127.0.0.1", self.port), handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert, self.key)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    @property
    def host(self):
        return f"127.0.0.1:{self.port}"


class Handler(BaseHTTPRequestHandler):
    ontap = None

    def log_message(self, *args):
        pass

    def reply(self, code, body):
        data = json.dumps(body).encode()
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/hal+json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass   # the client stopped waiting (timeout)

    def authorized(self, write=False):
        """The restore account may do everything; the read-only account (Operation Automation) only GET."""
        header = self.headers.get("Authorization", "")
        if self.ontap.reject or not header.startswith("Basic "):
            return False
        # Like the APIC mock: any user with the test password is accepted (to test several operators).
        user, _, password = base64.b64decode(header[6:]).decode().partition(":")
        if self.ontap.readonly and (user, password) == tuple(self.ontap.readonly):
            self.read_only = True
            return True
        self.read_only = False
        return bool(user) and self.ontap.user in (None, user) and password == self.ontap.password

    def refuse_read_only(self):
        if getattr(self, "read_only", False):
            self.reply(403, error("not authorized for that command (role readonly)", "6"))
            return True
        return False

    def body(self):
        length = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(length) or b"{}")

    def do_GET(self):
        url = urlparse(self.path)
        path, query = unquote(url.path), parse_qs(url.query)
        if path == "/__state":
            return self.reply(200, self.ontap.state())
        if not self.authorized():
            return self.reply(401, error("User is not authorized.", "6"))
        if path == "/api/cluster":
            return self.reply(200, self.ontap.cluster)
        if path == "/api/storage/luns":
            records = self.ontap.find_luns((query.get("name") or [""])[0])
            return self.reply(200, {"records": records, "num_records": len(records)})
        if path == "/api/storage/volumes":
            records = self.ontap.find_volumes(set((query.get("name") or [""])[0].split("|")))
            return self.reply(200, {"records": records, "num_records": len(records)})
        if path == "/api/cluster/nodes":
            records = self.ontap.node_records()
            return self.reply(200, {"records": records, "num_records": len(records)})
        if path == "/api/private/cli/system/node":
            records = [{"node": n, "health": True, "eligibility": True} for n in self.ontap.nodes()]
            return self.reply(200, {"records": records, "num_records": len(records)})
        if path == "/api/network/ip/interfaces":
            records = self.ontap.lifs()
            return self.reply(200, {"records": records, "num_records": len(records)})
        match = re.match(r"^/api/network/ip/interfaces/([0-9a-f-]{36})$", path)
        if match:
            lif = next((l for l in self.ontap.lifs() if l["uuid"] == match.group(1)), None)
            return self.reply(200, lif) if lif else self.reply(404, error("entry doesn't exist", "4"))
        if path == "/api/network/ethernet/ports":
            records = [{"node": {"name": n}, "name": "e0M", "state": "up", "enabled": True} for n in self.ontap.nodes()]
            return self.reply(200, {"records": records, "num_records": len(records)})
        if path == "/api/storage/aggregates":   # capacity check: aggr1 of node 02 at 91%
            records = [{"name": f"aggr1_{n.lower().replace('-', '_')}", "node": {"name": n}, "state": "online",
                        "space": {"block_storage": {"size": 100 * 1024 * GIB, "used": (91 if i == 1 else 60) * 1024 * GIB,
                                                    "available": (9 if i == 1 else 40) * 1024 * GIB}}}
                       for i, n in enumerate(self.ontap.nodes()[:2])]
            return self.reply(200, {"records": records, "num_records": len(records)})
        if path == "/api/storage/disks":
            records = [{"name": "1.0.11", "state": "broken", "node": {"name": self.ontap.nodes()[0]}, "bay": 11,
                        "shelf": {"uid": "5000CCA0123"}, "model": "X357_S163A3T8ATE"}]
            return self.reply(200, {"records": records, "num_records": len(records)})
        if path == "/api/support/ems/events":
            records = self.ontap.events()
            return self.reply(200, {"records": records, "num_records": len(records)})
        match = re.match(r"^/api/storage/volumes/([0-9a-f-]+)(/snapshots)?$", path)
        if match and match.group(1) in self.ontap.volumes:
            if match.group(2):
                records = self.ontap.snapshots[match.group(1)]
                return self.reply(200, {"records": records, "num_records": len(records)})
            return self.reply(200, self.ontap.volumes[match.group(1)])
        return self.reply(404, error("API not found", "3"))

    def do_PATCH(self):
        path = urlparse(self.path).path
        if not self.authorized():
            return self.reply(401, error("User is not authorized.", "6"))
        if self.refuse_read_only():
            return
        match = re.match(r"^/api/storage/luns/([0-9a-f-]+)$", path)
        if match:
            body = self.body()
            time.sleep(self.ontap.patch_delay)
            return self.reply(*self.ontap.lun_patch(match.group(1), body))
        match = re.match(r"^/api/network/ip/interfaces/([0-9a-f-]{36})$", path)
        if match:
            return self.reply(*self.ontap.lif_patch(match.group(1), self.body()))
        return self.reply(404, error("API not found", "3"))

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/__rename":
            body = self.body()
            return self.reply(200 if self.ontap.rename(body.get("from"), body.get("to")) else 404, {})
        if path == "/__delete":   # the NetApp driver deletes the LUN of a deleted Cinder volume
            return self.reply(200 if self.ontap.delete_lun(self.body().get("name")) else 404, {})
        if not self.authorized():
            return self.reply(401, error("User is not authorized.", "6"))
        if self.refuse_read_only():
            return
        if path == "/api/private/cli/volume/snapshot/restore-file":
            return self.reply(*self.ontap.restore_file(self.body()))
        return self.reply(404, error("API not found", "3"))


# Demo mode accounts: a different password per site, like production ONTAP.
DEMO_ACCOUNTS = {"DCB": ("admin", "demo-dcb"), "DCA": ("admin", "demo-dca"), "DCC": ("admin", "demo-dcc")}
DEMO_PORTS = {"DCB": 9451, "DCA": 9452, "DCC": 9453}
# Read-only accounts of Operation Automation (ONTAP role readonly): GET only. DCC shows the cluster_mgmt LIF away from home.
READONLY_ACCOUNTS = {"DCB": ("wi-readonly", "demo-ro-dcb"), "DCA": ("wi-readonly", "demo-ro-dca"), "DCC": ("wi-readonly", "demo-ro-dcc")}

if __name__ == "__main__":
    workdir = tempfile.mkdtemp()
    cert, key = make_cert(workdir)
    reject = {s.strip().upper() for s in os.environ.get("MOCK_REJECT", "").split(",") if s.strip()}
    mocks = [MockOntap(f"{site}-ONTAP", cert, key, port=DEMO_PORTS[site], prefix=f"{site}OPNSTACK", reject=site in reject,
                       user=user, password=password, readonly=READONLY_ACCOUNTS[site], mgmt_not_home=site == "DCC").start()
             for site, (user, password) in DEMO_ACCOUNTS.items()]
    print("Mock ONTAP running:", ", ".join(m.host for m in mocks), "Ctrl+C to stop.", flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass

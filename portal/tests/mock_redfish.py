"""Mock BMCs for Operation Automation tests: Redfish over HTTPS with Basic auth, GET only, like a Lenovo XClarity
Controller and an Inspur BMC (the differences the check must handle):

  lenovo  Systems/1, Chassis/1 (+ an extra backplane chassis), Managers/1; logs under Systems/1/LogServices: ActiveLog (an
          active critical DIMM alert), PlatformLog (one page, oldest first, Lenovo event IDs FQXSP...), AuditLog (skipped);
          PSU 2 failed and power redundancy lost; RAID with one degraded drive
  inspur  Systems/1 links Storage as .../Storages (404) — the real path is .../Storage; logs under Managers/1/LogServices
          (SEL: 250 entries, 100 per page, oldest first, only $skip / $top reach the newest; AuditLog skipped); the
          Systems SEL ("Log") links the same entries; collection members as plain strings; health "NA" on absent parts
"""
import base64
import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

USER, PASSWORD = "bmc-readonly", "demo-bmc-ro-1"
R = "/redfish/v1"


def ref(path):
    return {"@odata.id": path}


def coll(paths, plain=False):
    return {"Members": [p if plain else ref(p) for p in paths], "Members@odata.count": len(paths)}


def lenovo_tree():
    t = {
        R: {"RedfishVersion": "1.15.0", "Vendor": "Lenovo", "Systems": ref(f"{R}/Systems"), "Chassis": ref(f"{R}/Chassis"),
            "Managers": ref(f"{R}/Managers")},
        f"{R}/Systems": coll([f"{R}/Systems/1"]),
        f"{R}/Chassis": coll([f"{R}/Chassis/1", f"{R}/Chassis/Drive_Backplane_SB27A1"]),
        f"{R}/Managers": coll([f"{R}/Managers/1"]),
        f"{R}/Systems/1": {"Id": "1", "Manufacturer": "Lenovo", "Model": "ThinkSystem SR650 V2", "SerialNumber": "J30ABCDE",
                           "PowerState": "On", "Status": {"State": "Enabled", "Health": "Critical", "HealthRollup": "Critical"},
                           "MemorySummary": {"Status": {"HealthRollup": "Critical"}}, "ProcessorSummary": {"Status": {"HealthRollup": "OK"}},
                           "LogServices": ref(f"{R}/Systems/1/LogServices"), "Storage": ref(f"{R}/Systems/1/Storage")},
        f"{R}/Chassis/1": {"Id": "1", "Status": {"Health": "Critical"}, "Power": ref(f"{R}/Chassis/1/Power"),
                           "Thermal": ref(f"{R}/Chassis/1/Thermal")},
        f"{R}/Managers/1": {"Id": "1", "FirmwareVersion": "AFBT30K 4.10", "DateTime": "2026-10-11T08:00:00+00:00",
                            "LogServices": ref(f"{R}/Managers/1/LogServices")},
        f"{R}/Managers/1/LogServices": coll([]),
        f"{R}/Chassis/1/Power": {"PowerSupplies": [
            {"MemberId": "0", "Name": "PSU1", "Model": "SP57A02", "PowerCapacityWatts": 1100, "LineInputVoltage": 230,
             "Status": {"State": "Enabled", "Health": "OK"}},
            {"MemberId": "1", "Name": "PSU2", "Model": "SP57A02", "PowerCapacityWatts": 1100, "LineInputVoltage": 0,
             "Status": {"State": "Enabled", "Health": "Critical"}}],
            "Redundancy": [{"Mode": "N+m", "MinNumNeeded": 1, "MaxNumSupported": 2, "Status": {"State": "Enabled", "Health": "Critical"}}]},
        f"{R}/Chassis/1/Thermal": {"Fans": [{"MemberId": str(i), "Name": f"Fan {i + 1} Tach", "Reading": 6400, "ReadingUnits": "RPM",
                                             "Status": {"State": "Enabled", "Health": "OK"}} for i in range(6)],
                                   "Temperatures": [{"MemberId": "0", "Name": "Ambient Temp", "ReadingCelsius": 24,
                                                     "UpperThresholdCritical": 47, "Status": {"State": "Enabled", "Health": "OK"}}]},
        f"{R}/Systems/1/LogServices": coll([f"{R}/Systems/1/LogServices/{n}" for n in ("ActiveLog", "PlatformLog", "AuditLog", "SEL")]),
        f"{R}/Systems/1/LogServices/SEL": {"Id": "SEL"},   # no Entries on Lenovo (ClearLog only)
        f"{R}/Systems/1/Storage": coll([f"{R}/Systems/1/Storage/RAID_Slot1"]),
        f"{R}/Systems/1/Storage/RAID_Slot1": {"Id": "RAID_Slot1", "Name": "RAID 930-8i", "StorageControllers": [
            {"Name": "RAID 930-8i", "Model": "RAID 930-8i-2GB", "Status": {"State": "Enabled", "Health": "Warning"}}],
            "Drives": [ref(f"{R}/Systems/1/Storage/RAID_Slot1/Drives/Disk.{i}") for i in range(3)]},
    }
    for i in range(3):
        t[f"{R}/Systems/1/Storage/RAID_Slot1/Drives/Disk.{i}"] = {
            "Id": f"Disk.{i}", "Name": f"Drive {i}", "MediaType": "SSD", "CapacityBytes": 960197124096,
            "Status": {"State": "Enabled", "Health": "Critical" if i == 2 else "OK"}}
    for name in ("ActiveLog", "PlatformLog", "AuditLog"):
        t[f"{R}/Systems/1/LogServices/{name}"] = {"Id": name, "Entries": ref(f"{R}/Systems/1/LogServices/{name}/Entries")}
    t[f"{R}/Systems/1/LogServices/ActiveLog/Entries"] = {"Members": [
        {"Id": "1", "Created": "2026-10-10T21:14:00+00:00", "Severity": "Critical", "MessageSeverity": "Critical",
         "Message": "An Uncorrectable Error has been detected on DIMM 12 on Subsystem System Memory.", "EntryType": "Oem",
         "Oem": {"Lenovo": {"CommonEventID": "FQXSPMA2010N"}}}], "Members@odata.count": 1}
    t[f"{R}/Systems/1/LogServices/PlatformLog/Entries"] = {"Members": [
        {"Id": "1", "Created": "2026-09-01T10:00:00+00:00", "Severity": "Warning", "Message": "Old warning outside the window.",
         "Oem": {"Lenovo": {"CommonEventID": "FQXSPUN0018I"}}},
        {"Id": "40", "Created": "2026-10-10T21:13:00+00:00", "Severity": "Warning",
         "Message": "Memory DIMM 12 has exceeded the correctable error threshold.", "Oem": {"Lenovo": {"CommonEventID": "FQXSPMA0010M"}}},
        {"Id": "41", "Created": "2026-10-11T02:00:00+00:00", "Severity": "Critical",
         "Message": "Power supply PSU2 has lost input.", "Oem": {"Lenovo": {"CommonEventID": "FQXSPPW0007L"}}},
        {"Id": "42", "Created": "2026-10-11T02:01:00+00:00", "Severity": "OK", "Message": "Informational: sensor reset.",
         "Oem": {"Lenovo": {"CommonEventID": "FQXSPUN0019I"}}}], "Members@odata.count": 4}
    t[f"{R}/Systems/1/LogServices/AuditLog/Entries"] = {"Members": [
        {"Id": "1", "Created": "2026-10-11T03:00:00+00:00", "Severity": "Critical", "Message": "Audit entry must be skipped."}]}
    return t


def inspur_tree():
    sel = [{"Id": str(i), "Created": f"2026-10-{1 + i // 25:02d}T{i % 24:02d}:00:00+08:00", "Severity": "OK",
            "Message": "System event", "EntryType": "SEL", "EntryCode": "Assert", "SensorType": "System Event"} for i in range(250)]
    sel[245].update(Severity="Critical", Message="Fan_FAN3_F Speed Lower Critical going low", SensorType="Fan",
                    Created="2026-10-11T05:00:00+08:00")
    sel[246].update(Severity="Critical", Message="Fan_FAN3_F Speed Lower Critical going low", SensorType="Fan", EntryCode="Deassert",
                    Created="2026-10-11T05:10:00+08:00")
    # as real Inspur firmware writes them: local time "YY-MM-DD hh:mm:ss", "-Asserted" / "-Deasserted" in the message,
    # the DIMM named only in the OEM fields
    sel[247].update(Severity="Warning", Message="Correctable ECC Logging Limit Reached-Asserted", SensorType="Memory",
                    SensorNumber=82, Created="26-10-11 06:00:00", Oem={"Public": {"Description": "CPU1_CH1_DIMM0 ECC"}})
    sel[248].update(Severity="Critical", Message="Power Supply Input Lost (AC/DC)-Asserted", SensorType="Power Supply",
                    SensorNumber=101, Created="26-10-11 07:00:00", Oem={"Public": {"SensorName": "PSU1_Status"}})
    sel[249].update(Severity="Critical", Message="Power Supply Input Lost (AC/DC)-Deasserted", SensorType="Power Supply",
                    SensorNumber=101, Created="26-10-11 07:05:00", Oem={"Public": {"SensorName": "PSU1_Status"}})
    sel[20].update(Severity="Critical", Message="Redundancy Lost-Asserted", SensorType="Power Supply", Created="24-06-12 00:33:32")
    sel[30].update(Severity="Critical", Message="Event with a time in an unknown form", SensorType="Power Supply", Created="??")
    sel[10].update(Severity="Critical", Message="Old critical event on PSU0 (outside the window)", SensorType="Power Supply")
    t = {
        R: {"RedfishVersion": "1.8.0", "Vendor": "Inspur", "Systems": ref(f"{R}/Systems"), "Chassis": ref(f"{R}/Chassis"),
            "Managers": ref(f"{R}/Managers")},
        f"{R}/Systems": coll([f"{R}/Systems/1"], plain=True),
        f"{R}/Chassis": coll([f"{R}/Chassis/1"], plain=True),
        f"{R}/Managers": coll([f"{R}/Managers/1"], plain=True),
        f"{R}/Systems/1": {"Id": "1", "Manufacturer": "Inspur", "Model": "NF5280M6", "SerialNumber": "220712345",
                           "PowerState": "On", "Status": {"State": "Enabled", "Health": "Warning"},
                           "MemorySummary": {"Status": {"Health": "Warning"}}, "ProcessorSummary": {"Status": {"Health": "OK"}},
                           "LogServices": ref(f"{R}/Systems/1/LogServices"), "Storage": ref(f"{R}/Systems/1/Storages"),
                           "Memory": ref(f"{R}/Systems/1/Memory"), "Processors": ref(f"{R}/Systems/1/Processors")},
        f"{R}/Systems/1/Memory": coll([f"{R}/Systems/1/Memory/CPU{c}_CH{ch}_DIMM{d}" for c in (0, 1) for ch in (0, 1) for d in (0, 1)],
                                      plain=True),
        f"{R}/Systems/1/Processors": coll([f"{R}/Systems/1/Processors/{n}" for n in ("CPU0", "CPU1")], plain=True),
        f"{R}/Systems/1/Processors/CPU0": {"Id": "CPU0", "Socket": "CPU0", "Model": "Intel(R) Xeon(R) Gold 6338", "TotalCores": 32,
                                           "TotalThreads": 64, "Status": {"State": "Enabled", "Health": "OK"}},
        f"{R}/Systems/1/Processors/CPU1": {"Id": "CPU1", "Socket": "CPU1", "Model": "Intel(R) Xeon(R) Gold 6338", "TotalCores": 32,
                                           "TotalThreads": 64, "Status": {"State": "Enabled", "Health": "OK"}},
        f"{R}/Chassis/1": {"Id": "1", "Status": {"Health": "Warning"}, "Power": ref(f"{R}/Chassis/1/Power"),
                           "Thermal": ref(f"{R}/Chassis/1/Thermal")},
        f"{R}/Managers/1": {"Id": "1", "FirmwareVersion": "4.21.0", "DateTime": "2026-10-11T08:00:00+08:00",
                            "LogServices": ref(f"{R}/Managers/1/LogServices")},
        f"{R}/Chassis/1/Power": {"PowerSupplies": [
            {"MemberId": "0", "Name": "PSU0", "PowerCapacityWatts": 1300, "Status": {"State": "Enabled", "Health": "OK"}},
            {"MemberId": "1", "Name": "PSU1", "PowerCapacityWatts": 1300, "LineInputVoltage": 0, "SerialNumber": "PSU1SN",
             "Status": {"State": "Enabled", "Health": "OK"}},
            {"MemberId": "2", "Name": "PSU2", "Status": {"State": "Absent", "Health": "NA"}}],
            "Redundancy": [{"Mode": "Sharing", "Status": {"State": "Enabled", "Health": "OK"}}]},
        f"{R}/Chassis/1/Thermal": {"Fans": [{"MemberId": "3", "Name": "FAN3_F", "Reading": 3600, "ReadingUnits": "RPM",
                                             "Status": {"State": "Enabled", "Health": "OK"}},
                                            {"MemberId": "7", "Name": "FAN7_R", "Status": {"State": "Absent", "Health": "NA"}}],
                                   "Temperatures": [{"MemberId": "0", "Name": "Inlet_Temp", "ReadingCelsius": 23, "UpperThresholdCritical": None,
                                                     "Status": {"State": "Enabled", "Health": "OK"}},
                                                    # distance to Tjmax: 47 is cool, though this firmware calls it Critical
                                                    {"MemberId": "1", "Name": "CPU0_Margin_Temp", "ReadingCelsius": 47,
                                                     "Status": {"State": "Enabled", "Health": "Critical"}},
                                                    {"MemberId": "2", "Name": "GPU0_Temp", "ReadingCelsius": 0, "UpperThresholdCritical": 90,
                                                     "Status": {"State": "Enabled", "Health": None}}]},
        f"{R}/Systems/1/LogServices": coll([f"{R}/Systems/1/LogServices/Log"], plain=True),
        f"{R}/Systems/1/LogServices/Log": {"Id": "Log", "Entries": ref(f"{R}/Managers/1/LogServices/SEL/Entries")},
        f"{R}/Managers/1/LogServices": coll([f"{R}/Managers/1/LogServices/{n}" for n in ("SEL", "AuditLog", "IDL")]),
        f"{R}/Managers/1/LogServices/SEL": {"Id": "SEL", "Entries": ref(f"{R}/Managers/1/LogServices/SEL/Entries")},
        f"{R}/Systems/1/Storage": coll([f"{R}/Systems/1/Storage/PCIE0_RAID"], plain=True),
        f"{R}/Systems/1/Storage/PCIE0_RAID": {"Id": "PCIE0_RAID", "Name": "PCIE0_RAID", "Status": {"Health": "OK"},
                                             "Drives": [ref(f"{R}/Chassis/1/Drives/0")]},
        f"{R}/Chassis/1/Drives/0": {"Id": "0", "Name": "Front0", "MediaType": "HDD", "CapacityBytes": 1200243695616,
                                    "Status": {"State": "Enabled", "Health": "OK"}},
    }
    for c in (0, 1):
        for ch in (0, 1):
            for d in (0, 1):
                name = f"CPU{c}_CH{ch}_DIMM{d}"
                fitted = d == 0
                t[f"{R}/Systems/1/Memory/{name}"] = (
                    {"Id": name, "DeviceLocator": name, "CapacityMiB": 65536, "MemoryDeviceType": "DDR4", "OperatingSpeedMhz": 2933,
                     "Manufacturer": "Samsung", "PartNumber": "M393A8G40AB2-CWE", "SerialNumber": f"S{c}{ch}{d}0000",
                     "Status": {"State": "Enabled", "Health": "Warning" if name == "CPU1_CH1_DIMM0" else "OK"}}
                    if fitted else {"Id": name, "DeviceLocator": name, "CapacityMiB": 0, "Status": {"State": "Absent", "Health": "NA"}})
    return t, sel


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json;charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        auth = self.headers.get("Authorization") or ""
        expected = "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
        url = urlparse(self.path)
        path, query = url.path.rstrip("/") or "/", parse_qs(url.query)
        if path != R and auth != expected:   # the service root answers without sign-in (Redfish)
            self.server.failed.append(self.path)
            return self.send(401, {"error": {"code": "Base.1.8.GeneralError", "message": "Invalid Authentication"}})
        self.server.calls.append(self.path)
        if self.server.kind == "inspur" and path == f"{R}/Managers/1/LogServices/SEL/Entries":
            skip, top = int((query.get("$skip") or ["0"])[0]), int((query.get("$top") or ["100"])[0])
            page = self.server.sel[skip:skip + min(top, 100)]
            body = {"Members": page, "Members@odata.count": len(self.server.sel)}
            if skip + len(page) < len(self.server.sel):
                body["Members@odata.nextLink"] = f"{path}?$skip={skip + len(page)}&$top=100"
            return self.send(200, body)
        if self.server.kind == "inspur" and path == f"{R}/Systems/1/Storage/PCIE1_RAID":
            return self.send(500, {"error": "There are no RAID Controller Available", "code": 17034})
        body = self.server.tree.get(path)
        return self.send(200, body) if body is not None else self.send(404, {"error": {"message": "not found"}})

    def do_POST(self):
        self.send(405, {"error": "read-only mock"})

    do_PATCH = do_PUT = do_DELETE = do_POST


class MockBmc:
    def __init__(self, kind, cert, key, port=0):
        self.server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.server.kind, self.server.calls, self.server.failed = kind, [], []
        if kind == "lenovo":
            self.server.tree, self.server.sel = lenovo_tree(), []
        else:
            self.server.tree, self.server.sel = inspur_tree()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self.calls, self.failed = self.server.calls, self.server.failed

    def start(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self.server.shutdown()


if __name__ == "__main__":   # test_mode.sh: mock_redfish.py <lenovo|inspur> <port> <work dir>
    import sys
    import time
    sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.abspath(__file__)))
    import fake_ldap
    kind, port, work = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    cert, key = fake_ldap.make_cert(work, f"demo-bmc-{kind}")
    bmc = MockBmc(kind, cert, key, port)
    bmc.start()
    print(f"Mock {kind} BMC on https://127.0.0.1:{port} (account {USER} / {PASSWORD})", flush=True)
    while True:
        time.sleep(3600)

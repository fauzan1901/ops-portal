#!/usr/bin/env python3
"""Mock vCenter (vSphere Automation REST), NSX-T Manager (Policy API) and vCloud Director (query service + CloudAPI) for
Operation Automation tests and the demo, over HTTPS.

Only the read-only account is accepted (basic auth): READONLY_USER / READONLY_PASSWORD (vCloud Director: the provider
account READONLY_USER@System). Anything that is not a GET (except opening and closing a session) is refused with 403,
like a read-only role.
  vCenter: POST/DELETE /api/session, GET /api/vcenter/datastore, /api/vcenter/vm?datastores=|resource_pools=&names=,
           /api/vcenter/vm/<vm>/power, /api/vcenter/resource-pool?names=
  NSX-T:   GET /policy/api/v1/infra/tier-1s, GET /policy/api/v1/infra/tier-1s/<id>/nat/USER/nat-rules (and the platform checks below)
  Internal certificates (check cert-inventory): vCenter certificate-management (STS signing, tls, trusted roots), NSX-T
           trust-management/certificates, vCloud Director ssl/certificateLibrary (+ consumers) and ssl/trustedCertificates;
           every certificate expires a fixed number of days after now (made when asked, see pem()).
  vCD:     POST /cloudapi/1.0.0/sessions/provider, DELETE /cloudapi/1.0.0/sessions/current,
           GET /api/query?type=adminVM|adminTask|cell, /api/admin/vdc/<id>, /cloudapi/1.0.0/orgVdcNetworks[/<id>/allocatedIpAddresses],
           /cloudapi/1.0.0/edgeGateways[/<id>/ipsec/tunnels[/<t>/status]|/nat/rules|/firewall/rules],
           /cloudapi/1.0.0/firewallGroups/<id>, /cloudapi/1.0.0/applicationPortProfiles/<id>

    python tests/mock_vmware.py [port]     (default 9461)
"""
import base64
import datetime
import json
import os
import re
import secrets
import ssl
import sys
import tempfile
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fake_ldap  # noqa: E402

READONLY_USER, READONLY_PASSWORD = "wi-readonly", "demo-readonly"
GIB = 1024 ** 3
DATASTORES = [  # id, name, capacity GiB, free GiB
    ("datastore-1001", "DCA-DS-SSD-01", 20480, 1520),
    ("datastore-1002", "DCA-DS-SSD-02", 20480, 4900),
    ("datastore-1003", "DCA-DS-NVME-01", 10240, 6100),
    ("datastore-1004", "DCA-DS-ARCHIVE", 40960, 30500),
]
VMS = {"datastore-1001": [f"cust-a-vm-{i:02d}" for i in range(1, 15)], "datastore-1002": ["erp-db-01", "erp-app-01"],
       "datastore-1003": ["k8s-node-01", "k8s-node-02", "k8s-node-03"], "datastore-1004": ["backup-repo-01"]}
TIER1 = "t1-cust-a"
NAT_RULES = [
    {"id": "196613", "display_name": "196613", "action": "SNAT", "source_network": "172.31.50.2", "destination_network": "",
     "translated_network": "11.2.120.122", "sequence_number": 100, "enabled": True},
    {"id": "SNAT-Colo", "display_name": "SNAT-Colo", "action": "SNAT", "source_network": "172.31.50.2",
     "destination_network": "10.253.0.0/8", "translated_network": "192.168.252.21", "sequence_number": 200, "enabled": True},
    {"id": "DNAT-web", "display_name": "DNAT-web", "action": "DNAT", "destination_network": "11.2.120.122",
     "translated_network": "172.31.50.2", "sequence_number": 300, "enabled": True},
]


# ---------------- vCloud Director (DCA demo): the cases of the Acme Prime WIs ----------------
def _ago(minutes):
    return (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


VCD_ORG, VCD_VDC = "0a0a0a0a-0000-4000-8000-00000000000a", "da0a0a0a-0000-4000-8000-0000000000a1"
VCD_NET, VCD_EDGE = "ae000000-0000-4000-8000-0000000000e1", "ed000000-0000-4000-8000-0000000000e1"
VCD_VMS = [  # name, uuid tail, status, memory MB, vCPU, moref, network, ip, vCenter power, in the Org VDC pool
    ("erp-app-01", 1, "POWERED_OFF", 16384, 4, "vm-3001", "CUST-A-NET", "11.15.66.110", "POWERED_OFF", True),
    ("web-02", 2, "POWERED_OFF", 4096, 2, "vm-3002", "CUST-A-NET", "11.15.66.102", "POWERED_OFF", True),
    ("db-03", 3, "POWERED_OFF", 16384, 8, "vm-3003", "CUST-A-NET", "11.15.66.103", "POWERED_ON", True),
    ("app-04", 4, "POWERED_OFF", 4096, 2, "vm-3004", "CUST-A-NET", "11.15.66.104", "POWERED_OFF", False),
    ("report-05", 5, "POWERED_ON", 8192, 4, "vm-3005", "CUST-A-NET", "11.15.66.105", "POWERED_ON", True),
]
VCD_ERRORS = {
    "erp-app-01": "Quota Exceeded: memory allocation limit reached for the organization VDC CUST-A-VDC (requested 16384 MB, available 8192 MB).",
    "web-02": "The following IP/MAC addresses have already been used by running virtual machines: MAC addresses: IP addresses: "
              "11.15.66.102 Use the Fence vApp option to use same MAC/IP. Fencing allows identical virtual machines in different "
              "vApps to be powered on without conflict, by isolating the MAC and IP address",
    "app-04": "Resource Pool not available or invalid for VM.",
}


def vcd_uuid(n):
    return f"e1000000-0000-4000-8000-{n:012d}"


def vcd_vm_record(name, n, status, mem, cpu, moref, net, ip, *_):
    return {"name": name, "href": f"https://vcd.demo/api/vApp/vm-{vcd_uuid(n)}", "status": status, "memoryMB": mem,
            "numberOfCpus": cpu, "moref": moref, "networkName": net, "ipAddress": ip, "containerName": f"vapp-{name}",
            "vdc": f"https://vcd.demo/api/vdc/{VCD_VDC}", "vdcName": "CUST-A-VDC", "orgName": "cust-a", "hostName": "esxi-dca-02",
            "isVAppTemplate": False, "isBusy": name == "report-05"}


def vcd_tasks():
    out = []
    for name, *_ in VCD_VMS:
        if name in VCD_ERRORS:
            out.append({"name": "vappDeploy", "operationFull": f"Starting Virtual Machine {name}", "status": "error",
                        "objectName": name, "ownerName": "cust-a-admin", "startDate": _ago(20), "endDate": _ago(19),
                        "details": VCD_ERRORS[name]})
        out.append({"name": "vappUpdateVm", "operationFull": f"Updating Virtual Machine {name}", "status": "success",
                    "objectName": name, "ownerName": "cust-a-admin", "startDate": _ago(600), "endDate": _ago(598), "details": ""})
    out.append({"name": "vappUpdateVm", "operationFull": "Updating Virtual Machine report-05", "status": "running",
                "objectName": "report-05", "ownerName": "cust-a-admin", "startDate": _ago(95), "details": ""})
    out.append({"name": "vdcComposeVapp", "operationFull": "Creating vApp vapp-new", "status": "running",
                "objectName": "vapp-new", "ownerName": "cust-b-admin", "startDate": _ago(4), "details": ""})
    return sorted(out, key=lambda t: t["startDate"], reverse=True)


VCD_IPS = [("11.15.66.101", "web-01", "VM_ALLOCATED", True), ("11.15.66.102", "web-03", "VM_ALLOCATED", True),
           ("11.15.66.102", "web-02", "VM_ALLOCATED", False), ("11.15.66.103", "db-03", "VM_ALLOCATED", True),
           ("11.15.66.104", "app-04", "VM_ALLOCATED", False), ("11.15.66.105", "report-05", "VM_ALLOCATED", True),
           ("11.15.66.110", "erp-app-01", "VM_ALLOCATED", False)]
FW_GROUP, PROFILE_HTTPS = "f9000000-0000-4000-8000-000000000001", "a9000000-0000-4000-8000-000000000443"
TUNNELS = [("1d000000-0000-4000-8000-000000000001", "to-HQ", "11.3.10.5", "DOWN", "Peer not responding"),
           ("1d000000-0000-4000-8000-000000000002", "to-DRC", "11.17.1.9", "UP", "")]


def vcd_get(path, query):
    """vCloud Director answers of the demo (None = 404)."""
    flt = (query.get("filter") or [""])[0]
    cond = dict(c.split("==", 1) for c in flt.split(";") if "==" in c)
    if path == "/api/query":
        kind = (query.get("type") or [""])[0]
        if kind == "adminVM":
            recs = [vcd_vm_record(*v) for v in VCD_VMS if "name" not in cond or v[0] == cond["name"]]
        elif kind == "adminTask":
            recs = [t for t in vcd_tasks() if ("objectName" not in cond or t["objectName"] == cond["objectName"])
                    and ("status" not in cond or t["status"] == cond["status"])]
        elif kind == "cell":
            recs = [{"name": "cell-01", "primaryIp": "10.248.0.11", "isActive": True, "productBuildNumber": "10.5.1"},
                    {"name": "cell-02", "primaryIp": "10.248.0.12", "isActive": True, "productBuildNumber": "10.5.1"}]
        else:
            return None
        return {"name": kind, "total": len(recs), "page": 1, "pageSize": 25, "record": recs}
    for name, n, _, _, _, _, net, ip, *_ in VCD_VMS:
        if path == f"/api/vApp/vm-{vcd_uuid(n)}/networkConnectionSection/":
            return {"primaryNetworkConnectionIndex": 0, "networkConnection": [
                {"network": net, "networkConnectionIndex": 0, "ipAddress": ip, "isConnected": True,
                 "macAddress": f"00:50:56:01:00:{n:02x}", "ipAddressAllocationMode": "MANUAL", "networkAdapterType": "VMXNET3"},
                {"network": "CUST-A-BACKUP", "networkConnectionIndex": 1, "ipAddress": f"10.242.0.{10 + n}", "isConnected": True,
                 "macAddress": f"00:50:56:01:01:{n:02x}", "ipAddressAllocationMode": "POOL", "networkAdapterType": "VMXNET3"}]}
    if path == f"/api/admin/vdc/{VCD_VDC}":
        return {"name": "CUST-A-VDC", "id": f"urn:vcloud:vdc:{VCD_VDC}", "allocationModel": "Flex",
                "computeCapacity": {"cpu": {"units": "MHz", "allocated": 40000, "limit": 40000, "used": 30000},
                                    "memory": {"units": "MB", "allocated": 65536, "limit": 65536, "used": 57344}}}
    if path == "/cloudapi/1.0.0/orgVdcNetworks":
        nets = [{"id": f"urn:vcloud:network:{VCD_NET}", "name": "CUST-A-NET", "status": "REALIZED", "orgRef": {"name": "cust-a"},
                 "subnets": {"values": [{"gateway": "11.15.66.1", "prefixLength": 24,
                                         "ipRanges": {"values": [{"startAddress": "11.15.66.100", "endAddress": "11.15.66.120"}]}}]}}]
        return {"values": [n for n in nets if "name" not in cond or n["name"] == cond["name"]]}
    if path == f"/cloudapi/1.0.0/orgVdcNetworks/urn:vcloud:network:{VCD_NET}/allocatedIpAddresses":
        return {"values": [{"ipAddress": ip, "entityName": who, "allocationType": kind, "deployed": up} for ip, who, kind, up in VCD_IPS]}
    edge = f"/cloudapi/1.0.0/edgeGateways/urn:vcloud:gateway:{VCD_EDGE}"
    if path == "/cloudapi/1.0.0/cells":   # vCloud platform check: cell 3 is a stale registration of an old cell (same IP)
        return {"values": [{"name": "vcd-cell-01", "primaryIP": "10.248.0.11", "isActive": True, "status": "ACTIVE", "productVersion": "10.5.1.24183505"},
                           {"name": "vcd-cell-02", "primaryIP": "10.248.0.12", "isActive": True, "status": "ACTIVE", "productVersion": "10.5.1.24183505"},
                           {"name": "vcd-cell-03-old", "primaryIP": "10.248.0.12", "isActive": False, "status": "INACTIVE", "productVersion": "10.4.2.21954589"}]}
    if path.startswith("/cloudapi/1.0.0/ssl/"):
        return vcd_cert_get(path)
    if path == "/cloudapi/1.0.0/virtualCenters":
        return {"values": [{"name": "vcenter-dca", "isConnected": True, "listenerState": "CONNECTED", "clusterHealthStatus": "GREEN", "vcVersion": "8.0.3"}]}
    if path == "/cloudapi/1.0.0/edgeGateways":
        edges = [{"id": f"urn:vcloud:gateway:{VCD_EDGE}", "name": "CUST-A-EDGE", "gatewayBacking": {"gatewayType": "NSXT_BACKED"},
                  "orgVdc": {"name": "CUST-A-VDC"}, "orgRef": {"name": "cust-a"}, "status": "REALIZED",
                  "edgeGatewayUplinks": [{"subnets": {"values": [{"primaryIp": "11.4.20.30"}]}}]},
                 # vCloud platform check: an edge whose last change did not realize in NSX
                 {"id": "urn:vcloud:gateway:ed000000-0000-4000-8000-0000000000e2", "name": "CUST-B-EDGE", "status": "REALIZATION_FAILED",
                  "gatewayBacking": {"gatewayType": "NSXT_BACKED"}, "orgVdc": {"name": "CUST-B-VDC"}, "orgRef": {"name": "cust-b"},
                  "edgeGatewayUplinks": []}]
        found = [e for e in edges if "name" not in cond or e["name"] == cond["name"]]
        if "name" in cond:
            return {"values": found}
        page = int((query.get("page") or ["1"])[0])   # every edge gateway: one per page (CUST-B-EDGE on page 2)
        return {"values": found[page - 1:page], "page": page, "pageSize": 1, "pageCount": len(found), "resultTotal": len(found)}
    if path == f"{edge}/ipsec/tunnels":
        return {"values": [{"id": t, "name": n, "active": True, "localEndpoint": {"localAddress": "11.4.20.30"},
                            "remoteEndpoint": {"remoteAddress": r}} for t, n, r, _, _ in TUNNELS]}
    for t, n, r, st, reason in TUNNELS:
        if path == f"{edge}/ipsec/tunnels/{t}/status":
            return {"tunnelStatus": st, "ikeStatus": {"ikeServiceStatus": st, "failReason": reason}}
    if path == f"{edge}/nat/rules":
        return {"values": [
            {"name": "snat-all", "ruleType": "SNAT", "externalAddresses": "11.4.20.30", "internalAddresses": "10.249.10.0/24", "enabled": True},
            {"name": "dnat-web", "ruleType": "DNAT", "externalAddresses": "11.4.20.31", "dnatExternalPort": "443",
             "internalAddresses": "10.249.10.15", "enabled": True, "firewallMatch": "MATCH_INTERNAL_ADDRESS"},
            {"name": "dnat-app", "ruleType": "DNAT", "externalAddresses": "11.4.20.31", "dnatExternalPort": "8443",
             "internalAddresses": "10.249.10.16", "internalPort": "8443", "enabled": True, "firewallMatch": "MATCH_INTERNAL_ADDRESS"}]}
    if path == f"{edge}/firewall/rules":
        return {"userDefinedRules": [
            {"name": "allow-https", "enabled": True, "actionValue": "ALLOW",
             "destinationFirewallGroups": [{"name": "web-servers", "id": f"urn:vcloud:firewallGroup:{FW_GROUP}"}],
             "applicationPortProfiles": [{"name": "HTTPS", "id": f"urn:vcloud:applicationPortProfile:{PROFILE_HTTPS}"}]}],
            "defaultRules": [{"name": "default_rule", "enabled": True, "actionValue": "DROP"}]}
    if path == f"/cloudapi/1.0.0/firewallGroups/urn:vcloud:firewallGroup:{FW_GROUP}":
        return {"name": "web-servers", "ipAddresses": ["10.249.10.15"]}
    if path == f"/cloudapi/1.0.0/applicationPortProfiles/urn:vcloud:applicationPortProfile:{PROFILE_HTTPS}":
        return {"name": "HTTPS", "scope": "SYSTEM", "applicationPorts": [{"protocol": "TCP", "destinationPorts": ["443"]}]}
    return None


class Handler(BaseHTTPRequestHandler):
    sessions = set()
    vcd_tokens = set()

    def log_message(self, *args):
        pass

    def send(self, status, body=None):
        data = b"" if body is None else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def basic_ok(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            return False
        user, _, password = base64.b64decode(auth[6:]).decode().partition(":")
        return user == READONLY_USER and password == READONLY_PASSWORD

    def session_ok(self):
        return self.headers.get("vmware-api-session-id", "") in self.sessions

    def vcd_ok(self):
        auth = self.headers.get("Authorization", "")
        return auth.startswith("Bearer ") and auth[7:] in self.vcd_tokens and "version=" in self.headers.get("Accept", "")

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/api/session":
            if not self.basic_ok():
                return self.send(401, {"error_type": "UNAUTHENTICATED"})
            token = secrets.token_hex(16)
            self.sessions.add(token)
            return self.send(201, token)
        if path == "/cloudapi/1.0.0/sessions/provider":
            auth = self.headers.get("Authorization", "")
            user, _, password = base64.b64decode(auth[6:]).decode().partition(":") if auth.startswith("Basic ") else ("", "", "")
            if user != f"{READONLY_USER}@System" or password != READONLY_PASSWORD:
                return self.send(401, {"message": "Invalid credentials"})
            token = secrets.token_hex(16)
            self.vcd_tokens.add(token)
            body = json.dumps({"user": {"name": READONLY_USER}, "org": {"name": "System"}, "roles": ["Read-only provider"]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-VMWARE-VCLOUD-ACCESS-TOKEN", token)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send(403, {"error_message": "read-only account"})

    def do_DELETE(self):
        if urllib.parse.urlsplit(self.path).path == "/cloudapi/1.0.0/sessions/current":
            self.vcd_tokens.discard(self.headers.get("Authorization", "")[7:])
            return self.send(204)
        if urllib.parse.urlsplit(self.path).path == "/api/session":
            self.sessions.discard(self.headers.get("vmware-api-session-id", ""))
            return self.send(204)
        self.send(403, {"error_message": "read-only account"})

    do_PUT = do_PATCH = lambda self: self.send(403, {"error_message": "read-only account"})

    def do_GET(self):
        parts = urllib.parse.urlsplit(self.path)
        path, query = parts.path, urllib.parse.parse_qs(parts.query)
        if path.startswith("/api/appliance/") or path == "/api/vcenter/services":
            if not self.session_ok():
                return self.send(401, {"error_type": "UNAUTHENTICATED"})
            body = appliance_get(path)
            return self.send(404, {"error_type": "NOT_FOUND"}) if body is None else self.send(200, body)
        if path.startswith("/api/vcenter/"):
            if not self.session_ok():
                return self.send(401, {"error_type": "UNAUTHENTICATED"})
            if path == "/api/vcenter/datacenter":
                return self.send(200, [{"datacenter": "datacenter-3", "name": "DCA-VDC03"}])
            if path == "/api/vcenter/datastore":
                return self.send(200, [{"datastore": d, "name": n, "type": "VMFS", "capacity": c * GIB, "free_space": f * GIB}
                                       for d, n, c, f in DATASTORES])
            if path == "/api/vcenter/vm" and "resource_pools" in query:
                names = (query.get("names") or [""])[0].split(",")
                inside = [{"vm": moref, "name": f"{name} ({vcd_uuid(n)})", "power_state": vc}
                          for name, n, _, _, _, moref, _, _, vc, in_pool in VCD_VMS
                          if in_pool and (query.get("resource_pools") or [""])[0] == "resgroup-501"]
                return self.send(200, [v for v in inside if not names[0] or v["name"] in names])
            if path == "/api/vcenter/vm" and "names" in query:   # a vCloud VM by its vCenter name "<name> (<uuid>)"
                names = (query.get("names") or [""])[0].split(",")
                return self.send(200, [{"vm": moref, "name": f"{name} ({vcd_uuid(n)})", "power_state": vc, "cpu_count": cpu,
                                        "memory_size_MiB": mem}
                                       for name, n, _, mem, cpu, moref, _, _, vc, _ in VCD_VMS if f"{name} ({vcd_uuid(n)})" in names])
            if path == "/api/vcenter/vm":
                wanted = (query.get("datastores") or [""])[0].split(",")
                vms = [name for d in wanted for name in VMS.get(d, [])]
                return self.send(200, [{"vm": f"vm-{2000 + i}", "name": n, "power_state": "POWERED_ON", "cpu_count": 2 + i % 3 * 2,
                                        "memory_size_MiB": 4096 * (1 + i % 4)} for i, n in enumerate(vms)])
            for name, n, _, _, _, moref, _, _, vc, _ in VCD_VMS:
                if path == f"/api/vcenter/vm/{moref}/power":
                    return self.send(200, {"state": vc})
            if path == "/api/vcenter/resource-pool":
                pools = [{"resource_pool": "resgroup-501", "name": f"CUST-A-VDC ({VCD_VDC})"}]
                names = (query.get("names") or [""])[0]
                return self.send(200, [p for p in pools if not names or p["name"] == names])
            body = vcenter_cert_get(path)
            if body is not None:
                return self.send(200, body)
            return self.send(404, {"error_type": "NOT_FOUND"})
        if path.startswith(("/api/query", "/api/admin/", "/api/vApp/", "/cloudapi/")):
            if not self.vcd_ok():
                return self.send(401, {"message": "Not authenticated (Bearer token and a versioned Accept header are required)"})
            body = vcd_get(path, query)
            return self.send(404, {"message": "not found"}) if body is None else self.send(200, body)
        if path.startswith("/api/v1/"):   # NSX-T Manager API (platform health)
            if not self.basic_ok():
                return self.send(403, {"error_message": "The credentials were incorrect or the account specified has been locked."})
            body = nsx_manager_get(path, query)
            return self.send(404, {"error_message": "not found"}) if body is None else self.send(200, body)
        if path.startswith("/policy/api/v1/"):
            if not self.basic_ok():
                return self.send(403, {"error_message": "The credentials were incorrect or the account specified has been locked."})
            if path == "/policy/api/v1/infra/tier-1s":
                return self.send(200, {"results": [{"id": TIER1, "display_name": "T1 customer A"}], "result_count": 1})
            if path == f"/policy/api/v1/infra/tier-1s/{TIER1}/nat/USER/nat-rules":
                return self.send(200, {"results": NAT_RULES, "result_count": len(NAT_RULES)})
            body = nsx_policy_get(path, query)
            return self.send(404, {"error_message": "not found"}) if body is None else self.send(200, body)
        self.send(404, {})


NOW_MS = 1791700000000   # 2026-10-11 (epoch milliseconds, as NSX writes times)
NSX_ALARMS = [
    {"id": "a1", "feature_name": "routing", "feature_display_name": "Routing", "event_type": "bgp_down", "event_type_display_name": "BGP Down",
     "severity": "CRITICAL", "status": "OPEN", "node_id": "edge-dca-01-id", "node_display_name": "edge-dca-01",
     "summary": "BGP neighbor down.", "description": "In Router edge-dca-01, BGP neighbor 10.240.0.1 is down. Reason: Edge is not ready.",
     "recommended_action": "1. Invoke the NSX CLI command get logical-routers. 2. Switch to service router. 3. Check the BGP neighbor status.",
     "_create_time": NOW_MS - 3600000},
    {"id": "a2", "feature_name": "certificates", "feature_display_name": "Certificates", "event_type": "certificate_expiration_approaching",
     "event_type_display_name": "Certificate Expiration Approaching", "severity": "MEDIUM", "status": "OPEN", "node_id": "mgr-1",
     "node_display_name": "nsx-mgr-dca-01", "summary": "A certificate is approaching expiration.",
     "description": "Certificate 9a1b expires on 2026-11-02.", "recommended_action": "Replace the certificate before it expires.",
     "_create_time": NOW_MS - 86400000},
    {"id": "a3", "feature_name": "edge_health", "feature_display_name": "Edge Health", "event_type": "edge_disk_usage_high",
     "event_type_display_name": "Edge Disk Usage High", "severity": "LOW", "status": "OPEN", "node_id": "edge-dca-02-id",
     "node_display_name": "edge-dca-02", "summary": "Edge disk usage is high.", "description": "", "recommended_action": "",
     "_create_time": NOW_MS - 7200000},
]


def appliance_get(path):
    """vCenter appliance check: /storage/log is yellow, vmware-sps (automatic) is stopped, the last backup failed."""
    health = {"system": "yellow", "load": "green", "mem": "green", "swap": "green", "storage": "yellow", "database-storage": "green",
              "software-packages": "green", "applmgmt": "green"}
    m = re.match(r"^/api/appliance/health/([a-z-]+)$", path)
    if m and m.group(1) in health:
        return health[m.group(1)]
    if path == "/api/vcenter/services":
        return {"vpxd": {"startup_type": "AUTOMATIC", "state": "STARTED", "health": "HEALTHY"},
                "vmware-sps": {"startup_type": "AUTOMATIC", "state": "STOPPED", "health": "HEALTHY"},
                "vmcam": {"startup_type": "MANUAL", "state": "STOPPED", "health": "HEALTHY"}}
    if path == "/api/appliance/recovery/backup/job/details":
        return {"20261024-020000-24205021": {"type": "BACKUP", "status": "SUCCEEDED", "start_time": "2026-10-24T02:00:00.000Z",
                                             "end_time": "2026-10-24T02:21:00.000Z"},
                "20261025-020000-24205021": {"type": "BACKUP", "status": "FAILED", "start_time": "2026-10-25T02:00:00.000Z",
                                             "end_time": "2026-10-25T02:01:00.000Z"}}
    if path == "/api/appliance/recovery/backup/schedules":
        return {"default": {"enable": True, "recurrence_info": {"hour": 2, "minute": 0}}}
    return None


def nsx_manager_get(path, query):
    if path == "/api/v1/alarms":
        status = (query.get("status") or [""])[0]
        items = [a for a in NSX_ALARMS if not status or a["status"] == status]
        return {"results": items, "result_count": len(items)}
    if path == "/api/v1/cluster/status":
        return {"detailed_cluster_status": {"overall_status": "STABLE", "groups": [{"group_id": "g1", "group_type": "MANAGER", "group_status": "STABLE"}]},
                "mgmt_cluster_status": {"status": "STABLE"}, "control_cluster_status": {"status": "STABLE"}}
    if path == "/api/v1/transport-nodes/state":
        return {"results": [{"transport_node_id": "tn-esxi-01", "state": "success"},
                            {"transport_node_id": "tn-edge-01", "state": "failed", "failure_message": "Host switch nvds-overlay is not realized.",
                             "node_deployment_state": {"state": "NODE_READY"}}], "result_count": 2}
    if path == "/api/v1/transport-nodes":
        return {"results": [{"id": "tn-esxi-01", "display_name": "esxi-dca-01"}, {"id": "tn-edge-01", "display_name": "edge-dca-01"}]}
    if path == "/api/v1/edge-clusters":
        return {"results": [{"id": "ec-dca-01", "display_name": "edge-cluster-dca"}], "result_count": 1}
    if path == "/api/v1/edge-clusters/ec-dca-01/state":
        return {"edge_cluster_id": "ec-dca-01", "state": "success"}
    if path == "/api/v1/trust-management/certificates":   # two per page, as NSX with a cursor
        every = nsx_certificates()["results"]
        start = int((query.get("cursor") or ["0"])[0] or 0)
        page = {"results": every[start:start + 2], "result_count": len(every)}
        if start + 2 < len(every):
            page["cursor"] = str(start + 2)
        return page
    return None


T0 = "t0-dca"


def nsx_policy_get(path, query):
    """Tier-0 gateway of the NSX gateways check: active / standby, one BGP neighbour down, one that flapped 20 minutes ago."""
    if path == "/policy/api/v1/infra/tier-0s":
        return {"results": [{"id": T0, "display_name": "T0-DCA", "ha_mode": "ACTIVE_STANDBY"}], "result_count": 1}
    if path == f"/policy/api/v1/infra/tier-0s/{T0}/state":
        return {"tier0_state": {"per_node_status": [{"transport_node_id": "edge-dca-01-id", "high_availability_status": "ACTIVE"},
                                                    {"transport_node_id": "edge-dca-02-id", "high_availability_status": "STANDBY"}]}}
    if path == f"/policy/api/v1/infra/tier-0s/{T0}/locale-services":
        return {"results": [{"id": "default"}], "result_count": 1}
    if path == f"/policy/api/v1/infra/tier-0s/{T0}/locale-services/default/bgp/neighbors/status":
        return {"results": [{"neighbor_address": "10.240.0.1", "remote_as_number": "65001", "connection_state": "ESTABLISHED",
                             "time_since_established": 20 * 60 * 1000, "connection_drop_count": 4},
                            {"neighbor_address": "10.240.0.2", "remote_as_number": "65001", "connection_state": "ACTIVE",
                             "time_since_established": 0, "connection_drop_count": 9},
                            {"neighbor_address": "10.240.0.3", "remote_as_number": "65002", "connection_state": "ESTABLISHED",
                             "time_since_established": 9 * 86400 * 1000, "connection_drop_count": 0}]}
    if path == f"/policy/api/v1/infra/tier-1s/{TIER1}/state":
        return {"tier1_state": {"per_node_status": [{"transport_node_id": "edge-dca-01-id", "high_availability_status": "ACTIVE"},
                                                    {"transport_node_id": "edge-dca-02-id", "high_availability_status": "ACTIVE"}]}}
    return None


# ---------------- internal certificates (check cert-inventory)
LIVE_CN = "mock-vmware"   # the name of the certificate this server presents (set by MockVmware)
_PEMS = {}
CHAINS = {"6b1c5a0e3f7d4c2a9e8b1d0f2a3c4e5f6a7b8c9d": ("CA-DCA", 20), "0f9e8d7c6b5a49382716a5b4c3d2e1f0a9b8c7d6": ("CA-DCA-OLD", -100)}
LIB = [  # id, alias, days left, consumers (None: no consumers read)
    ("11111111-1111-4111-8111-111111111111", "console-proxy-dca", 15, ["vcd-cell-01 console proxy"]),
    ("22222222-2222-4222-8222-222222222222", "old-lb-cert", 10, []),
    ("33333333-3333-4333-8333-333333333333", "tenant-ipsec-cust-a", 500, None)]


def cert_cn(path):
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    with open(path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    found = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(found[0].value) if found else "mock-vmware"


def pem(cn, days, issuer=None, ca=False):
    """A certificate (PEM) named cn that expires `days` days from now: the analysis, run within the hour, finds exactly
    that many days left (made again every hour)."""
    bucket = int(time.time() // 3600)
    key = (cn, days, issuer, ca, bucket)
    if key not in _PEMS:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        k = ec.generate_private_key(ec.SECP256R1())
        after = datetime.datetime.fromtimestamp(bucket * 3600, datetime.timezone.utc) + datetime.timedelta(days=days, hours=2)
        name = lambda n: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, n)])
        cert = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(name(issuer or cn)).public_key(k.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(after - datetime.timedelta(days=730))
                .not_valid_after(after).add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
                .sign(k, hashes.SHA256()))
        _PEMS[key] = cert.public_bytes(serialization.Encoding.PEM).decode()
    return _PEMS[key]


def vcenter_cert_get(path):
    """STS signing certificate with 120 days left (under the 180 days of KB 318968), Machine SSL issued by CA-DCA whose
    root expires in 20 days, and an old expired root nobody uses."""
    base = "/api/vcenter/certificate-management/vcenter"
    if path == f"{base}/signing-certificate":
        return {"active_cert_chain": {"cert_chain": [pem("ssoserverSign", 120, "CA-DCA"), pem("CA-DCA", 20, ca=True)]},
                "signing_cert_chains": [{"cert_chain": [pem("ssoserverSign", 120, "CA-DCA")]},
                                        {"cert_chain": [pem("ssoserverSign-2019", -400, "CA-DCA-OLD")]}]}
    if path == f"{base}/tls":
        return {"subject_dn": "CN=vcsa-dca.prime.local, C=US", "issuer_dn": "CN=CA-DCA, DC=vsphere, DC=local", "valid_to":
                "2027-12-01T00:00:00.000Z", "cert": pem("vcsa-dca.prime.local", 400, "CA-DCA")}
    if path == f"{base}/trusted-root-chains":
        return [{"chain": c} for c in CHAINS]
    m = re.match(rf"^{base}/trusted-root-chains/([0-9a-f]+)$", path)
    if m and m.group(1) in CHAINS:
        cn, days = CHAINS[m.group(1)]
        return {"cert_chain": {"cert_chain": [pem(cn, days, ca=True)]}}
    return None


def nsx_certificates():
    """The NSX trust store: the APH certificate of the manager expires in 5 days (in use), a local manager certificate in
    25 days (only its PEM, no details), an expired import nobody uses."""
    ms = lambda days: int((time.time() + days * 86400 + 7200) * 1000)
    return {"results": [
        {"id": "c0a1b2c3-0000-4000-8000-000000000001", "display_name": "mgr-cluster-dca", "used_by": [
            {"node_id": "mgr-1", "service_types": ["MGMT_CLUSTER", "API"]}],
         "details": [{"not_after": ms(300), "subject_cn": "nsx-mgr-dca.prime.local", "issuer_cn": "nsx-mgr-dca.prime.local"}]},
        {"id": "c0a1b2c3-0000-4000-8000-000000000002", "display_name": "APH-AR-nsx-mgr-dca-01", "used_by": [
            {"node_id": "mgr-1", "service_types": ["APH"]}, {"node_id": "mgr-2", "service_types": ["APH"]}],
         "details": [{"not_after": ms(5), "subject_cn": "APH-AR-nsx-mgr-dca-01", "issuer_cn": "NSX-CA"}]},
        {"id": "c0a1b2c3-0000-4000-8000-000000000003", "display_name": "LM-dca", "used_by": [
            {"node_id": "mgr-1", "service_types": ["LOCAL_MANAGER"]}], "pem_encoded": pem("lm-dca.prime.local", 25)},
        {"id": "c0a1b2c3-0000-4000-8000-000000000004", "display_name": "imported-2023", "used_by": [],
         "details": [{"not_after": ms(-10), "subject_cn": "old.prime.local", "issuer_cn": "old.prime.local"}]}],
        "result_count": 4}


def vcd_cert_get(path):
    """Certificate library (console proxy in 15 days, in use; an unused one in 10 days) and the trusted certificates:
    an older certificate with the name of the one vCenter / NSX-T present now (still trusted after the renewal)."""
    lib = "/cloudapi/1.0.0/ssl/certificateLibrary"
    if path == lib:
        return {"values": [{"id": f"urn:vcloud:certificateLibraryItem:{i}", "alias": a, "certificate": pem(f"{a}.prime.local", d),
                            "description": ""} for i, a, d, _c in LIB], "resultTotal": len(LIB)}
    for i, _a, _d, consumers in LIB:
        if path == f"{lib}/urn:vcloud:certificateLibraryItem:{i}/consumers" and consumers is not None:
            return {"values": [{"name": c} for c in consumers], "resultTotal": len(consumers)}
    if path == "/cloudapi/1.0.0/ssl/trustedCertificates":
        return {"values": [{"id": "urn:vcloud:trustedCertificate:a1", "alias": "vcenter-dca (before the renewal)",
                            "certificate": pem(LIVE_CN, -20)},
                           {"id": "urn:vcloud:trustedCertificate:a2", "alias": "prime-root", "certificate": pem("DCA Prime Root CA", 900, ca=True)}],
                "resultTotal": 2}
    return None


class MockVmware:
    def __init__(self, cert, key, port=0):
        global LIVE_CN
        LIVE_CN = cert_cn(cert)
        self.server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]

    def start(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self.server.shutdown()


if __name__ == "__main__":
    work = tempfile.mkdtemp()
    cert, key = fake_ldap.make_cert(work, "mock-vmware")
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9461
    MockVmware(cert, key, port).start()
    print(f"Mock vCenter + NSX-T + vCloud Director on https://127.0.0.1:{port} (account {READONLY_USER} / {READONLY_PASSWORD}, "
          f"vCD {READONLY_USER}@System, Tier-1 {TIER1})", flush=True)
    threading.Event().wait()

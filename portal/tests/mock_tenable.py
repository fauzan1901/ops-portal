#!/usr/bin/env python3
"""Mock Tenable Vulnerability Management (cloud.tenable.com) for the Nessus module tests and the demo, over HTTP on
127.0.0.1. With VULNS_PROXY pointing at it, it is also the proxy: a request line with an absolute URL is counted in
`proxied` (the tests check that the portal goes through VULNS_PROXY).

Only the API keys ACCESS_KEY / SECRET_KEY are accepted (header X-ApiKeys: accessKey=...; secretKey=...), else 401.
  GET  /session, /scanners, /scans (folders + scans), /scans/<id> (info, hosts with counts, history), /scans/<id>/latest-status
  POST /scans/<id>/launch {"alt_targets": [...]}: running for run_seconds, then completed; /scans/<id>/stop: canceled
  POST /vulns/export {"num_assets", "filters": {"severity", "state", "since"}} -> {"export_uuid"}
  GET  /vulns/export/<uuid>/status: QUEUED, then PROCESSING (chunk 1), then FINISHED (chunks 1 and 2)
  GET  /vulns/export/<uuid>/chunks/<n>
Every finding carries what "How to fix it" reads: the asset's operating system and fqdn, the plugin's description,
see_also, has_patch, patch_publication_date, exploit_available and type, and a plugin output as Tenable prints it (local
package checks of Ubuntu and RHEL, a Cisco IOS XE advisory, a Windows rollup KB, SSH algorithms, TLS, Telnet, versions).
Remediation in the demo data: export 1 has every finding (one already FIXED, one fixed long ago); export 2 has what
changed since: the SWEET32 finding of dca-xcc-02 FIXED, a new Terrapin finding on dcb-director, TLS 1.0 on dcc-mgmt-01
REOPENED; later exports: every host a Verify fix scanned (alt_targets) has its worst open finding FIXED.
fail_next = [429, ...]: the next requests get these codes (with Retry-After: 1).

    python tests/mock_tenable.py [port]     (default 9481)
"""
import copy
import datetime
import ipaddress
import json
import re
import sys
import threading
import time
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ACCESS_KEY = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
SECRET_KEY = "5ec2e7b3d4c5b6a79881726354a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3"
API_USER = "svc-portal-api@example.com"
SCANNERS = [  # name, status, type
    ("nessus-dcb-01", "on", "managed"), ("nessus-dca-01", "on", "managed"), ("nessus-dcc-01", "off", "managed"),
    ("lab-scanner-01", "on", "managed"), ("US Cloud Scanner", "on", "pool")]
SCANS = [  # id, name, scanner, targets, rrules, starttime, enabled, folder (2 = trash)
    (11, "DCB management weekly", "nessus-dcb-01", "10.248.0.0/24, 10.248.1.10-10.248.1.40", "FREQ=WEEKLY;INTERVAL=1;BYDAY=SU",
     "20261101T020000", True, 1),
    (12, "DCA management daily", "nessus-dca-01", "10.245.0.0/24,10.245.1.40,10.245.1.41", "FREQ=DAILY;INTERVAL=1", "20261101T013000", True, 1),
    (13, "DCA customer edge (DMZ)", "nessus-dca-01", "10.245.0.0/24, 11.6.148.0/24", "", "", False, 1),
    (14, "DCC management discovery", "nessus-dcc-01", "10.243.128.0/22", "FREQ=MONTHLY;INTERVAL=1;BYMONTHDAY=1", "20261101T030000", True, 1),
    (15, "DCC directors by name", "nessus-dcc-01", "dcc-director.example.local, 10.243.128.11", "", "", False, 1),
    (16, "DCB out-of-band range", "nessus-dcb-01", "10.248.1.250-10.248.2.5", "", "", False, 1),
    (17, "Lab switches", "lab-scanner-01", "192.168.252.0/24", "FREQ=WEEKLY;INTERVAL=2;BYDAY=MO,TH", "20261103T220000", True, 1),
    (18, "Internet perimeter", "US Cloud Scanner", "203.0.113.0/24", "FREQ=WEEKLY;INTERVAL=1;BYDAY=WE", "20261101T040000", True, 1),
    (19, "DCB storage management", "nessus-dcb-01", "10.247.136.0/24", "", "", False, 1),
    (99, "Old DCB scan", "nessus-dcb-01", "10.248.0.0/16", "", "", False, 2),
]
PLUGINS = {  # id: name, family, severity, CVSS v3, VPR, CVEs, synopsis, solution
    187315: ("SSH Terrapin Prefix Truncation Weakness (CVE-2023-48795)", "Misc.", "medium", 5.9, 6.1, ["CVE-2023-48795"],
             "The remote SSH server is vulnerable to a man-in-the-middle prefix truncation weakness.",
             "Contact the vendor for an update with the strict key exchange countermeasures, or disable the affected algorithms."),
    201194: ("OpenSSH < 9.8 RCE", "Misc.", "high", 8.1, 7.4, ["CVE-2024-6387"],
             "The SSH server running on the remote host is affected by a remote code execution vulnerability.",
             "Upgrade to OpenSSH version 9.8 / 9.8p1 or later."),
    70658: ("SSH Server CBC Mode Ciphers Enabled", "Misc.", "low", 3.7, 1.4, ["CVE-2008-5161"],
            "The SSH server is configured to use Cipher Block Chaining.",
            "Contact the vendor or consult product documentation to disable CBC mode cipher encryption, and enable CTR or GCM."),
    153953: ("SSH Weak Key Exchange Algorithms Enabled", "Misc.", "low", 3.7, None, [],
             "The remote SSH server is configured to allow weak key exchange algorithms.",
             "Contact the vendor or consult product documentation to disable the weak algorithms."),
    104743: ("TLS Version 1.0 Protocol Detection", "Service detection", "medium", 6.5, None, [],
             "The remote service encrypts traffic using an older version of TLS.",
             "Enable support for TLS 1.2 and 1.3, and disable support for TLS 1.0."),
    51192: ("SSL Certificate Cannot Be Trusted", "General", "medium", 6.5, None, [],
            "The SSL certificate for this service cannot be trusted.",
            "Purchase or generate a proper SSL certificate for this service."),
    57582: ("SSL Self-Signed Certificate", "General", "medium", 6.5, None, [],
            "The SSL certificate chain for this service ends in an unrecognized self-signed certificate.",
            "Purchase or generate a proper SSL certificate for this service."),
    42873: ("SSL Medium Strength Cipher Suites Supported (SWEET32)", "General", "high", 7.5, 5.1, ["CVE-2016-2183"],
            "The remote service supports the use of medium strength SSL ciphers.",
            "Reconfigure the affected application if possible to avoid use of medium strength ciphers."),
    41028: ("SNMP Agent Default Community Name (public)", "SNMP", "high", 7.5, 5.2, ["CVE-1999-0517"],
            "The community name of the remote SNMP server can be guessed.",
            "Disable the SNMP service if it is not used, filter UDP packets to this port, or change the default community string."),
    33850: ("Unix Operating System Unsupported Version Detection", "General", "critical", 10.0, None, [],
            "The operating system running on the remote host is no longer supported.",
            "Upgrade to a version of the operating system that is currently supported."),
    11213: ("HTTP TRACE / TRACK Methods Allowed", "Web Servers", "medium", 5.3, 4.0, ["CVE-2003-1567", "CVE-2004-2320"],
            "Debugging functions are enabled on the remote web server.", "Disable these HTTP methods. Refer to the plugin output for more information."),
    10114: ("ICMP Timestamp Request Remote Date Disclosure", "General", "low", None, None, ["CVE-1999-0524"],
            "It is possible to determine the exact time set on the remote host.",
            "Filter out the ICMP timestamp requests (13), and the outgoing ICMP timestamp replies (14)."),
    19506: ("Nessus Scan Information", "Settings", "info", None, None, [], "This plugin displays information about the Nessus scan.", "n/a"),
    190596: ("Ubuntu 22.04 LTS : Linux kernel vulnerabilities (USN-6608-1)", "Ubuntu Local Security Checks", "high", 7.8, 6.7,
             ["CVE-2023-6176", "CVE-2023-6622", "CVE-2023-6932"],
             "The remote Ubuntu host is missing one or more security updates.",
             "Update the affected kernel package."),
    189585: ("RHEL 8 : kernel (RHSA-2024:0897)", "Red Hat Local Security Checks", "high", 7.8, 6.0, ["CVE-2023-4623", "CVE-2023-42753"],
             "The remote Red Hat host is missing one or more security updates for kernel.",
             "Update the affected packages."),
    182896: ("Cisco IOS XE Software Web UI Privilege Escalation (cisco-sa-iosxe-webui-privesc-j22SaA4z)", "CISCO", "critical", 10.0, 9.9,
             ["CVE-2023-20198", "CVE-2023-20273"],
             "The remote device is missing a vendor-supplied security patch.",
             "Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwh87343"),
    42263: ("Unencrypted Telnet Server", "Misc.", "medium", 6.5, None, [],
            "The remote Telnet server transmits traffic in cleartext.",
            "Disable the Telnet service and use SSH instead."),
    187833: ("KB5034127: Windows 10 version 1809 / Windows Server 2019 Security Update (January 2024)", "Windows : Microsoft Bulletins",
             "high", 8.8, 7.4, ["CVE-2024-20674", "CVE-2024-20700"],
             "The remote Windows host is affected by multiple vulnerabilities.",
             "Apply Security Update 5034127"),
}
# What else the export says about a plugin: patch available (days ago), exploit, local or remote check, links, description
PLUGIN_META = {
    187315: (True, 330, True, "remote", ["https://terrapin-attack.com/", "https://www.openssh.com/txt/release-9.6"],
             "The remote SSH server is vulnerable to a man-in-the-middle prefix truncation weakness known as Terrapin."),
    70658: (False, None, False, "remote", [], "The SSH server is configured to support Cipher Block Chaining (CBC) encryption."),
    201194: (True, 120, True, "remote", ["https://www.openssh.com/txt/release-9.8", "https://www.qualys.com/2024/07/01/cve-2024-6387/regresshion.txt"],
             "The version of OpenSSH installed on the remote host is prior to 9.8. It is affected by a signal handler race condition."),
    153953: (False, None, False, "remote", ["https://datatracker.ietf.org/doc/html/rfc9142"],
             "The remote SSH server is configured to allow key exchange algorithms which are considered weak."),
    104743: (False, None, False, "remote", ["https://datatracker.ietf.org/doc/html/rfc8996"],
             "The remote service accepts connections encrypted using TLS 1.0."),
    51192: (False, None, False, "remote", [], "The X.509 certificate chain for this service is not signed by a recognized certificate authority."),
    57582: (False, None, False, "remote", [], "The X.509 certificate chain for this service ends in a self-signed certificate."),
    42873: (False, None, False, "remote", ["https://sweet32.info", "https://www.openssl.org/blog/blog/2016/08/24/sweet32/"],
            "The remote host supports the use of SSL ciphers that offer medium strength encryption (3DES)."),
    41028: (False, None, True, "remote", [], "It is possible to obtain the default community name of the remote SNMP server."),
    11213: (False, None, False, "remote", [], "The remote web server supports the TRACE and/or TRACK methods."),
    10114: (False, None, False, "remote", [], "The remote host answers to an ICMP timestamp request."),
    190596: (True, 280, False, "local", ["https://ubuntu.com/security/notices/USN-6608-1"],
             "The remote Ubuntu 22.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced "
             "in the USN-6608-1 advisory."),
    189585: (True, 270, False, "local", ["https://access.redhat.com/errata/RHSA-2024:0897"],
             "The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as "
             "referenced in the RHSA-2024:0897 advisory."),
    182896: (True, 380, True, "combined", ["https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z",
                                          "https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh87343"],
             "Cisco is aware of active exploitation of a vulnerability in the web UI feature of Cisco IOS XE Software."),
    42263: (False, None, False, "remote", [], "The remote host is running a Telnet server over an unencrypted channel."),
    187833: (True, 300, False, "local", ["https://support.microsoft.com/help/5034127"],
             "The remote Windows host is missing security update 5034127."),
}
HOSTS = {"10.248.0.11": "dcb-mgmt-01", "10.248.0.21": "dcb-director", "10.248.0.30": "dcb-ontap-mgmt", "10.248.1.15": "dcb-xcc-07",
         "10.245.0.11": "dca-mgmt-01", "10.245.0.25": "dca-apic-1", "10.245.1.40": "dca-xcc-02", "10.245.1.41": "dca-oob-sw-02",
         "10.243.128.11": "dcc-mgmt-01", "10.243.128.26": "dcc-dns-05", "10.243.128.44": "dcc-ontap-mgmt", "192.168.252.10": "lab-sw-01",
         "10.247.136.21": "dcb-ontap-n1", "10.247.136.22": "dcb-ontap-n2", "203.0.113.10": "edge-vip-01"}
OS = {"10.248.0.11": "Linux Kernel 5.15.0-91-generic on Ubuntu 22.04", "10.248.0.21": "Red Hat Enterprise Linux 8.8",
      "10.248.0.30": "NetApp ONTAP 9.12", "10.248.1.15": "Lenovo XClarity Controller", "10.245.0.11": "Linux Kernel 6.8.0-45-generic on Ubuntu 24.04",
      "10.245.0.25": "Cisco Application Policy Infrastructure Controller (APIC) 5.2(7f)", "10.245.1.40": "Lenovo XClarity Controller",
      "10.245.1.41": "Cisco IOS XE 17.3.4a", "10.243.128.11": "Linux Kernel 5.15.0-91-generic on Ubuntu 22.04",
      "10.243.128.26": "Microsoft Windows Server 2019 Standard", "10.243.128.44": "NetApp ONTAP 9.12", "192.168.252.10": "Cisco IOS 15.2(7)E8",
      "10.247.136.21": "NetApp ONTAP 9.12", "10.247.136.22": "NetApp ONTAP 9.12", "203.0.113.10": "F5 Networks BIG-IP"}
# The scan that found each host (vuln export "scan"): by its schedule uuid, or (RUN_ONLY) by the uuid of its last run only.
# 10.247.136.x: outside every network of the tests' sites.yml, found by the DCB scanner; 203.0.113.10: a Tenable cloud scanner.
SCAN_OF = (("10.248.", 11), ("10.247.136.", 19), ("10.245.", 12), ("10.243.", 14), ("192.168.252.", 17), ("203.0.113.", 18))
RUN_ONLY = ("10.245.", "10.247.136.22")
FINDINGS = [  # ip, plugin, port, protocol, service, state, first found (days ago), last fixed (days ago or None)
    ("10.248.0.11", 187315, 22, "TCP", "ssh", "OPEN", 41, None), ("10.248.0.11", 70658, 22, "TCP", "ssh", "OPEN", 41, None),
    ("10.248.0.11", 201194, 22, "TCP", "ssh", "OPEN", 20, None), ("10.248.0.11", 19506, 0, "TCP", "general", "OPEN", 41, None),
    ("10.248.0.11", 190596, 0, "TCP", "general", "OPEN", 25, None), ("10.248.0.21", 189585, 0, "TCP", "general", "OPEN", 25, None),
    ("10.248.0.21", 153953, 22, "TCP", "ssh", "OPEN", 41, None), ("10.248.0.21", 104743, 443, "TCP", "www", "OPEN", 41, None),
    ("10.248.0.30", 51192, 443, "TCP", "www", "OPEN", 62, None), ("10.248.0.30", 42873, 443, "TCP", "www", "OPEN", 62, None),
    ("10.248.0.30", 10114, 0, "ICMP", "general", "OPEN", 62, None),
    ("10.248.1.15", 57582, 443, "TCP", "www", "OPEN", 33, None), ("10.248.1.15", 104743, 443, "TCP", "www", "OPEN", 33, None),
    ("10.248.1.15", 41028, 161, "UDP", "snmp", "OPEN", 33, None),
    ("10.245.0.11", 187315, 22, "TCP", "ssh", "OPEN", 48, None), ("10.245.0.11", 201194, 22, "TCP", "ssh", "OPEN", 20, None),
    ("10.245.0.25", 51192, 443, "TCP", "www", "OPEN", 70, None), ("10.245.0.25", 11213, 80, "TCP", "www", "OPEN", 70, None),
    ("10.245.1.40", 42873, 443, "TCP", "www", "OPEN", 55, None), ("10.245.1.40", 57582, 443, "TCP", "www", "OPEN", 55, None),
    ("10.245.1.41", 182896, 443, "TCP", "www", "OPEN", 80, None), ("10.245.1.41", 41028, 161, "UDP", "snmp", "OPEN", 80, None),
    ("10.245.1.41", 10114, 0, "ICMP", "general", "OPEN", 80, None), ("10.245.1.41", 42263, 23, "TCP", "telnet", "OPEN", 80, None),
    ("10.243.128.26", 187833, 445, "TCP", "cifs", "OPEN", 40, None), ("10.243.128.26", 42873, 3389, "TCP", "msrdp", "OPEN", 40, None),
    ("10.243.128.11", 104743, 443, "TCP", "www", "FIXED", 85, 12), ("10.243.128.11", 187315, 22, "TCP", "ssh", "OPEN", 30, None),
    ("10.243.128.44", 51192, 443, "TCP", "www", "OPEN", 64, None), ("10.243.128.44", 70658, 22, "TCP", "ssh", "FIXED", 88, 60),
    ("192.168.252.10", 41028, 161, "UDP", "snmp", "OPEN", 25, None),
    ("10.247.136.21", 70658, 22, "TCP", "ssh", "OPEN", 30, None), ("10.247.136.22", 51192, 443, "TCP", "www", "OPEN", 30, None),
    ("203.0.113.10", 104743, 443, "TCP", "www", "OPEN", 15, None),
]
ROUND_2 = {("10.245.1.40", 42873): "FIXED", ("10.243.128.11", 104743): "REOPENED"}
NEW_IN_ROUND_2 = [("10.248.0.21", 187315, 22, "TCP", "ssh", "OPEN", 0, None)]
RUNNING = {"running", "pending"}


def iso(days=0, seconds=0):
    when = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days, seconds=seconds)
    return when.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def asset_uuid(ip):
    return f"a55e7000-0000-4000-8000-{int(ipaddress.ip_address(ip)):012x}"


OUTPUTS = {  # what Tenable prints for each plugin (as its plugin output looks), {host} / {ip} / {port} filled in
    187315: ("\nSupports following ChaCha20-Poly1305 Algorithms :\n\n  Client to Server: chacha20-poly1305@openssh.com\n"
             "  Server to Client: chacha20-poly1305@openssh.com\n\nSupports Strict Key Exchange : False\n"),
    70658: ("\nThe following client-to-server Cipher Block Chaining (CBC) algorithms\nare supported : \n\n  3des-cbc\n  aes128-cbc\n"
            "  aes256-cbc\n\nThe following server-to-client Cipher Block Chaining (CBC) algorithms\nare supported : \n\n  3des-cbc\n"
            "  aes128-cbc\n  aes256-cbc\n"),
    153953: "\nThe following weak key exchange algorithms are enabled : \n\n  diffie-hellman-group-exchange-sha1\n  diffie-hellman-group1-sha1\n",
    201194: "\n  Version source    : SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\n  Installed version : 8.9p1\n  Fixed version     : 9.8p1 / 9.8\n",
    104743: "\nTLSv1 is enabled and the server supports at least one cipher.\n",
    51192: ("\nThe following certificate was at the top of the certificate\nchain sent by the remote host, but it is signed by an unknown\n"
            "certificate authority :\n\n|-Subject : CN={host}\n|-Issuer  : CN={host}\n"),
    57582: ("\nThe following certificate was found at the top of the certificate\nchain sent by the remote host, but is self-signed and was not\n"
            "found in the list of known certificate authorities :\n\n|-Subject : CN={host}\n|-RSA Key Length : 1024 bits\n"),
    42873: ("\n  Medium Strength Ciphers (> 64-bit and < 112-bit key, or 3DES)\n\n    Name                          Code             KEX"
            "           Auth     Encryption             MAC\n    ----------------------        ----------       ---           ----"
            "     ---------------------  ---\n    DES-CBC3-SHA                  0x00, 0x0A       RSA           RSA      3DES-CBC(168)"
            "          SHA1\n    ECDHE-RSA-DES-CBC3-SHA        0xC0, 0x12       ECDH          RSA      3DES-CBC(168)          SHA1\n\n"
            "The fields above are :\n\n  {{Tenable ciphername}}\n  {{Cipher ID code}}\n  Kex={{key exchange}}\n  Auth={{authentication}}\n"
            "  Encrypt={{symmetric encryption method}}\n  MAC={{message authentication code}}\n  {{export flag}}\n"),
    41028: "\nThe remote SNMP server replies to the following default community\nstring :\n\npublic\n",
    10114: "\nThe remote clock is synchronized with the local clock.\n",
    190596: ("\n  - Installed package : linux-image-5.15.0-91-generic_5.15.0-91.101\n  - Fixed package     : linux-image-5.15.0-94-generic_5.15.0-94.104\n"
             "\n  - Installed package : linux-modules-5.15.0-91-generic_5.15.0-91.101\n  - Fixed package     : linux-modules-5.15.0-94-generic_5.15.0-94.104\n"
             "\n  - Installed package : linux-libc-dev_5.15.0-91.101\n  - Fixed package     : linux-libc-dev_5.15.0-94.104\n"),
    189585: ("\nRemote package installed : kernel-4.18.0-477.10.1.el8_8\nShould be                : kernel-4.18.0-513.18.1.el8_9\n"
             "\nRemote package installed : kernel-core-4.18.0-477.10.1.el8_8\nShould be                : kernel-core-4.18.0-513.18.1.el8_9\n"
             "\nRemote package installed : kernel-modules-4.18.0-477.10.1.el8_8\nShould be                : kernel-modules-4.18.0-513.18.1.el8_9\n"
             "\nRemote package installed : bpftool-4.18.0-477.10.1.el8_8\nShould be                : bpftool-4.18.0-513.18.1.el8_9\n"),
    182896: "\n  Cisco bug ID      : CSCwh87343\n  Installed release : 17.3.4a\n  Fixed release     : 17.3.8a\n",
    42263: ("Nessus collected the following banner from the remote Telnet server :\n\n------------------------------ snip"
            " ------------------------------\n\nUser Access Verification\n\nUsername: \n------------------------------ snip"
            " ------------------------------\n"),
    187833: ("\nThe remote host is missing one of the following rollup KBs :\n  - 5034127\n\n\n"
             "  - C:\\Windows\\system32\\ntoskrnl.exe has not been patched.\n    Remote version : 10.0.17763.5206\n"
             "    Should be      : 10.0.17763.5329\n"),
}


def output_of(ip, plugin, port):
    if plugin == 11213:   # longer than the 8 KB the portal keeps
        return "To use TRACE, the request was :\n\n" + "".join(f"TRACE /Nessus{n:05d}.html HTTP/1.1\nConnection: Close\nHost: {ip}\n\n"
                                                              for n in range(260))
    if plugin in OUTPUTS:
        return OUTPUTS[plugin].format(host=HOSTS.get(ip, ip), ip=ip, port=port)
    return f"\nDetected on {ip} port {port}.\n"


def scan_of(ip):
    """The scan of a finding as the export names it: the uuid of the scan run (the last of the three of the history) and the
    schedule uuid of the scan (empty for RUN_ONLY: the portal then finds the scan by its run)."""
    sid = next((n for prefix, n in SCAN_OF if ip.startswith(prefix)), 0)
    run_only = any(ip.startswith(x) or ip == x for x in RUN_ONLY)
    return {"uuid": f"run-{sid}-2", "schedule_uuid": "" if run_only else f"template-{sid}", "started_at": iso(1),
            "completed_at": iso(0, 80000)}


def make_finding(ip, plugin, port, protocol, service, state, first_days, fixed_days):
    name, family, severity, cvss3, vpr, cves, synopsis, solution = PLUGINS[plugin]
    has_patch, patch_days, exploit, kind, see_also, description = PLUGIN_META.get(plugin, (False, None, False, "remote", [], ""))
    item = {"asset": {"uuid": asset_uuid(ip), "ipv4": ip, "hostname": HOSTS.get(ip, ""), "fqdn": f"{HOSTS.get(ip, ip)}.mgmt.example.local",
                      "operating_system": [OS.get(ip, "Linux Kernel 5.14")]},
            "plugin": {"id": plugin, "name": name, "family": family, "synopsis": synopsis, "solution": solution, "cve": list(cves),
                       "description": description, "see_also": list(see_also), "has_patch": has_patch, "exploit_available": exploit,
                       "type": kind, **({"patch_publication_date": iso(patch_days)} if patch_days is not None else {}),
                       **({"cvss3_base_score": cvss3} if cvss3 is not None else {}), **({"vpr": {"score": vpr}} if vpr is not None else {})},
            "port": {"port": port, "protocol": protocol, "service": service}, "severity": severity, "state": state,
            "first_found": iso(first_days), "last_found": iso(0, 3600), "output": output_of(ip, plugin, port),
            "scan": scan_of(ip)}
    if state == "FIXED":
        item["last_fixed"] = iso(fixed_days or 0)
    return item


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self._fill()

    def reset(self):
        """Tests: the data of a fresh mock."""
        with self.lock:
            self._fill()

    def _fill(self):
        self.findings = {(ip, plugin, port, proto): make_finding(ip, plugin, port, proto, svc, st, first, fixed)
                         for ip, plugin, port, proto, svc, st, first, fixed in FINDINGS}
        self.exports = {}
        self.export_count = 0
        self.export_filters = []
        self.requests = []
        self.proxied = 0
        self.fail_next = []
        self.run_seconds = 20.0
        self.verified = []      # addresses a Verify fix scanned, FIXED at the next export
        self.history_id = 1000
        now = int(time.time())
        self.scans = {}
        for sid, name, scanner, targets, rrules, start, enabled, folder in SCANS:
            runs = [{"history_id": self._hid(), "uuid": f"run-{sid}-{k}", "status": "completed", "type": "remote",
                     "creation_date": now - (21 - 7 * k) * 86400, "last_modification_date": now - (21 - 7 * k) * 86400 + 5400,
                     "scheduler": 1 if enabled else 0} for k in range(3)] if folder == 1 and sid != 15 else []
            self.scans[sid] = {"id": sid, "name": name, "scanner": scanner, "targets": targets, "rrules": rrules,
                               "starttime": start, "enabled": enabled, "folder": folder, "status": "completed" if runs else "empty",
                               "launched": 0.0, "alt_targets": None, "history": runs, "modified": now - 3 * 86400,
                               "launches": []}

    def _hid(self):
        self.history_id += 1
        return self.history_id

    # a launched scan completes run_seconds later (a Verify fix: its address is fixed at the next export)
    def settle(self, scan):
        if scan["status"] in RUNNING and time.time() - scan["launched"] >= self.run_seconds:
            scan["status"] = "completed"
            scan["history"][-1].update(status="completed", last_modification_date=int(time.time()))
            scan["modified"] = int(time.time())
            if scan["alt_targets"]:
                self.verified += list(scan["alt_targets"])
            scan["alt_targets"] = None

    def complete_all(self):
        """Tests: every running scan ends now."""
        with self.lock:
            for scan in self.scans.values():
                if scan["status"] in RUNNING:
                    scan["launched"] = 0
                    self.settle(scan)


def _hosts_of(targets):
    """Addresses of the mock findings that a scan's targets cover (names are skipped)."""
    nets = []
    for t in re.split(r"[\s,;]+", targets or ""):
        try:
            if "-" in t:
                a, b = t.split("-", 1)
                b = b if "." in b else ".".join(a.split(".")[:3] + [b])
                nets += list(ipaddress.summarize_address_range(ipaddress.ip_address(a), ipaddress.ip_address(b)))
            elif t:
                nets.append(ipaddress.ip_network(t, strict=False))
        except ValueError:
            continue
    return sorted({ip for ip in HOSTS if any(ipaddress.ip_address(ip) in n for n in nets)}, key=ipaddress.ip_address)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    @property
    def state(self):
        return self.server.state

    def send(self, status, body=None, headers=None):
        data = b"" if body is None else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def route(self, method):
        target = self.path
        if target.startswith("http://") or target.startswith("https://"):   # sent to a proxy: absolute URL
            self.state.proxied += 1
            parts = urllib.parse.urlsplit(target)
            target = parts.path + (f"?{parts.query}" if parts.query else "")
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw.decode() or "null")
        except ValueError:
            return self.send(400, {"statusCode": 400, "error": "Bad Request", "message": "invalid JSON"})
        path = urllib.parse.urlsplit(target).path
        with self.state.lock:
            self.state.requests.append({"method": method, "path": path, "body": body})
            if self.state.fail_next:
                code = self.state.fail_next.pop(0)
                return self.send(code, {"statusCode": code, "error": "Too Many Requests" if code == 429 else "Service Unavailable"},
                                 {"Retry-After": "1"})
        keys = dict(p.strip().split("=", 1) for p in self.headers.get("X-ApiKeys", "").split(";") if "=" in p)
        if keys.get("accessKey") != ACCESS_KEY or keys.get("secretKey") != SECRET_KEY:
            return self.send(401, {"statusCode": 401, "error": "Unauthorized", "message": "Invalid Credentials"})
        with self.state.lock:
            return self.handle_api(method, path, body or {})

    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    do_PUT = do_DELETE = lambda self: self.send(405, {"statusCode": 405, "error": "Method Not Allowed"})

    def handle_api(self, method, path, body):
        s = self.state
        now = int(time.time())
        if method == "GET" and path == "/session":
            return self.send(200, {"id": 7, "username": API_USER, "email": API_USER, "name": "Portal API", "type": "local",
                                   "permissions": 40, "lastlogin": now - 600, "container_uuid": "c0ffee00-0000-4000-8000-000000000001"})
        if method == "GET" and path == "/scanners":
            return self.send(200, {"scanners": [{"id": i + 1, "uuid": f"5ca00000-0000-4000-8000-00000000000{i + 1}", "name": n, "status": st,
                                                 "type": typ, "engine_version": "10.8.3", "platform": "LINUX",
                                                 "loaded_plugin_set": "202611100512", "linked": 1, "last_connect": now - 120 - i * 30,
                                                 "pool": typ == "pool"} for i, (n, st, typ) in enumerate(SCANNERS)]})
        if method == "GET" and path == "/scans":
            for scan in s.scans.values():
                s.settle(scan)
            return self.send(200, {"folders": [{"id": 1, "name": "My Scans", "type": "main"}, {"id": 2, "name": "Trash", "type": "trash"}],
                                   "scans": [{"id": x["id"], "uuid": f"scan-{x['id']}", "schedule_uuid": f"template-{x['id']}",
                                              "name": x["name"], "type": "remote",
                                              "owner": API_USER, "enabled": x["enabled"], "folder_id": x["folder"], "read": True,
                                              "status": x["status"], "shared": False, "user_permissions": 128,
                                              "creation_date": now - 90 * 86400, "last_modification_date": x["modified"],
                                              "control": True, "starttime": x["starttime"], "timezone": "Asia/Jakarta" if x["rrules"] else None,
                                              "rrules": x["rrules"] or None} for x in s.scans.values()],
                                   "timestamp": now})
        m = re.fullmatch(r"/scans/(\d+)(/latest-status|/launch|/stop)?", path)
        if m:
            scan = s.scans.get(int(m.group(1)))
            if not scan:
                return self.send(404, {"statusCode": 404, "error": "Not Found", "message": "Scan not found"})
            s.settle(scan)
            what = m.group(2) or ""
            if method == "GET" and what == "":
                return self.send(200, self.detail(scan))
            if method == "GET" and what == "/latest-status":
                return self.send(200, {"status": scan["status"], "tag": "latest"})
            if method == "POST" and what == "/launch":
                if scan["status"] in RUNNING:
                    return self.send(409, {"statusCode": 409, "error": "Conflict", "message": "The scan is already running"})
                alt = body.get("alt_targets") if isinstance(body, dict) else None
                run_uuid = str(uuid.uuid4())
                scan.update(status="running", launched=time.time(), alt_targets=list(alt) if alt else None, modified=now)
                scan["launches"].append({"alt_targets": list(alt) if alt else None, "at": now})
                scan["history"].append({"history_id": s._hid(), "uuid": run_uuid, "status": "running", "type": "remote",
                                        "creation_date": now, "last_modification_date": now, "scheduler": 0})
                return self.send(200, {"scan_uuid": run_uuid})
            if method == "POST" and what == "/stop":
                if scan["status"] not in RUNNING:
                    return self.send(409, {"statusCode": 409, "error": "Conflict", "message": "The scan is not running"})
                scan.update(status="canceled", alt_targets=None, modified=now)
                scan["history"][-1].update(status="canceled", last_modification_date=now)
                return self.send(200, {})
        if method == "POST" and path == "/vulns/export":
            return self.send(200, {"export_uuid": self.new_export(body)})
        m = re.fullmatch(r"/vulns/export/([0-9a-f-]{36})/(status|chunks/(\d+))", path)
        if m and method == "GET":
            export = s.exports.get(m.group(1))
            if not export:
                return self.send(404, {"statusCode": 404, "error": "Not Found", "message": "Export not found"})
            if m.group(2) == "status":
                export["polls"] += 1
                ids = list(range(1, len(export["chunks"]) + 1))
                status = "QUEUED" if export["polls"] == 1 else "PROCESSING" if export["polls"] == 2 else "FINISHED"
                return self.send(200, {"uuid": m.group(1), "status": status,
                                       "chunks_available": [] if status == "QUEUED" else ids[:1] if status == "PROCESSING" else ids,
                                       "chunks_failed": [], "chunks_cancelled": [], "total_chunks": len(ids),
                                       "num_assets_per_chunk": 500, "created": now * 1000})
            n = int(m.group(3))
            if not 1 <= n <= len(export["chunks"]):
                return self.send(404, {"statusCode": 404, "error": "Not Found", "message": "Chunk not found"})
            return self.send(200, export["chunks"][n - 1])
        return self.send(404, {"statusCode": 404, "error": "Not Found", "message": f"No mock for {method} {path}"})

    def detail(self, scan):
        hosts = []
        for k, ip in enumerate(_hosts_of(scan["targets"]), start=2):
            counts = {sev: 0 for sev in ("critical", "high", "medium", "low", "info")}
            for (fip, plugin, _port, _proto), f in self.state.findings.items():
                if fip == ip and f["state"] != "FIXED":
                    counts[f["severity"]] += 1
            hosts.append({"host_id": k, "hostname": ip, **counts, "severity": sum(counts.values()), "score": counts["critical"] * 10000})
        last = scan["history"][-1] if scan["history"] else {}
        return {"info": {"object_id": scan["id"], "uuid": f"template-{scan['id']}", "name": scan["name"], "status": scan["status"],
                         "targets": scan["targets"], "scanner_name": scan["scanner"], "policy": "Advanced Network Scan",
                         "scan_type": "remote", "hostcount": len(hosts), "scan_start": last.get("creation_date"),
                         "scan_end": last.get("last_modification_date") if scan["status"] not in RUNNING else None,
                         "edit_allowed": True, "user_permissions": 128, **scan.get("extra_info", {})},
                "hosts": hosts, "history": scan["history"], "vulnerabilities": [], "comphosts": [], "compliance": []}

    def new_export(self, body):
        """Export 1: every finding; export 2: what changed since (round 2); later: the hosts a Verify fix scanned."""
        s = self.state
        s.export_count += 1
        filters = (body or {}).get("filters") or {}
        s.export_filters.append(copy.deepcopy(filters))
        changed = []
        if s.export_count == 1:
            changed = list(s.findings)
        elif s.export_count == 2:
            for (ip, plugin), state in ROUND_2.items():
                key = next(k for k in s.findings if k[:2] == (ip, plugin))
                f = s.findings[key]
                f["state"], f["last_found"] = state, iso(0, 600)
                if state == "FIXED":
                    f["last_fixed"] = iso(0, 600)
                changed.append(key)
            for ip, plugin, port, proto, svc, st, first, fixed in NEW_IN_ROUND_2:
                s.findings[(ip, plugin, port, proto)] = make_finding(ip, plugin, port, proto, svc, st, first, fixed)
                changed.append((ip, plugin, port, proto))
        for ip in s.verified:   # the worst open finding of a host a Verify fix scanned is gone
            mine = sorted((k for k, f in s.findings.items() if k[0] == ip and f["state"] != "FIXED" and f["severity"] != "info"),
                          key=lambda k: ["low", "medium", "high", "critical"].index(s.findings[k]["severity"]), reverse=True)
            if mine:
                s.findings[mine[0]].update(state="FIXED", last_fixed=iso(0, 60), last_found=iso(0, 60))
                changed.append(mine[0])
        s.verified = []
        severities = [str(x).lower() for x in filters.get("severity") or []]
        states = [str(x).upper() for x in filters.get("state") or []]
        items = [copy.deepcopy(s.findings[k]) for k in dict.fromkeys(changed)
                 if (not severities or s.findings[k]["severity"] in severities) and (not states or s.findings[k]["state"] in states)]
        half = (len(items) + 1) // 2
        chunks = [c for c in (items[:half], items[half:]) if c]
        export_id = str(uuid.uuid4())
        s.exports[export_id] = {"polls": 0, "chunks": chunks}
        return export_id


class MockTenable:
    def __init__(self, port=0):
        self.state = State()
        self.server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.server.state = self.state
        self.port = self.server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"

    def start(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9481
    mock = MockTenable(port).start()
    mock.state.run_seconds = 25.0
    print(f"Mock Tenable Vulnerability Management on {mock.url} (scanners {', '.join(n for n, _s, _t in SCANNERS)})", flush=True)
    threading.Event().wait()

#!/usr/bin/env python3
"""Fake hosts for Operation Automation in test mode: called instead of ssh with the host name and the script (or one command):

    fake_hosts.py <host name> '<script>'

Each host shows the problem of its work instruction, so the demo has something to find:
  *-cdn-lb-01     /run full of AIDE files, haproxy.log 141 GB without logrotate, memory 92% (logparser stuck)
  *-cdn-lb-02     Docker HAProxy 'lb' exited -> Grafana DatasourceError
  *-cdn-vcp-2     Varnish MSE store 940G preallocated (df 99%, cache empty), AIDE running
  *-repo-01       nginx failed, certificate expired
  *-dns-recursive  PowerDNS Recursor quiet=no, syslog 44 GB
  *-natgw-01      VyOS: WAN-IN without established/related, UDP 514 not allowed, hw-id missing, static route missing
  *RCGW*          Huawei: the prefix is not added yet (pre-check)
  app-vm-01       Ubuntu: apache2 holds port 80 (nginx failed), nftables rejects 27017
  rhel-vm-01      RHEL: rsyslog to 172.26.0.40:541 blocked by SELinux
  siem-collector  collector: no new veeam logs, files in unknown
  esxi-*          ESXi: no remote syslog host, ruleset off
  gb200-*         one ConnectX port without link
"""
import json
import os
import re
import shlex
import sys
import time

NOW = int(time.time())
# Fixes run from the portal (test mode) are remembered per host in FAKE_HOSTS_STATE (JSON), so the check that runs again
# after a fix sees the problem gone, like on a real host.
STATE_FILE = os.environ.get("FAKE_HOSTS_STATE", "")
STATE = {}


def load_state():
    global STATE
    try:
        with open(STATE_FILE) as f:
            STATE = json.load(f)
    except (OSError, ValueError):
        STATE = {}


def remember(name, commands):
    if not STATE_FILE:
        return
    STATE.setdefault(name, []).extend(commands)
    with open(STATE_FILE, "w") as f:
        json.dump(STATE, f)


def applied(name, needle):
    return any(needle in c for c in STATE.get(name, []))


def cdn_lb(name, cmd):
    broken = "lb-02" in name and not (applied(name, "docker start lb") or applied(name, "docker restart lb"))
    fixed = [
        ("df -Pk /run", "Filesystem 1024-blocks Used Available Capacity Mounted on\ntmpfs 1638400 98304 1540096 6% /run"
         if applied(name, "rm -rf /run/aide") else None),
        ("du -sk /run/aide", "0\t/run/aide" if applied(name, "rm -rf /run/aide") else None),
        ("find /run/aide", "0" if applied(name, "rm -rf /run/aide") else None),
        ("df -Pk /", "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 203056560 50907000 152149560 26% /"
         if applied(name, "truncate -s 0 /var/log/haproxy.log") else None),
        ("du -xsk", "2202009\t/var/log/journal\n1048576\t/var/lib/docker\n524288\t/var/log/syslog\n31112\t/root\n0\t/var/log/haproxy.log"
         if applied(name, "truncate -s 0 /var/log/haproxy.log") else None),
        ("stat -c '%s' /var/log/haproxy.log", "0" if applied(name, "truncate -s 0 /var/log/haproxy.log") else None),
        ("/etc/logrotate.d/haproxy", "/var/log/haproxy.log {\n    daily\n    rotate 7\n    size 500M\n}"
         if applied(name, "tee /etc/logrotate.d/haproxy") else None),
        ("journalctl --disk-usage", "Archived and active journals take up 696.0M in the file system."
         if applied(name, "--vacuum-size") else None),
        ("lsof -nP +L1", "" if applied(name, "systemctl restart") else None),
        ("/proc/meminfo", "MemTotal:       32780000 kB\nMemAvailable:   17800000 kB" if applied(name, "kill -9") else None),
        ("pgrep -a logparser", "" if applied(name, "kill -9") else None),
        ("ps -eo", "  PID USER     COMMAND           RSS %CPU\n 1880 varnish  cache-main    9800000 22.1\n 3101 root     haproxy       2900000  6.4\n"
                   "  901 root     dockerd        310000  1.1" if applied(name, "kill -9") else None),
    ]
    hit = next((out for needle, out in fixed if out is not None and needle in cmd), None)
    if hit is not None:
        return hit
    table = [
        ("df -Pk /run", "Filesystem 1024-blocks Used Available Capacity Mounted on\ntmpfs 1638400 1589248 49152 97% /run"),
        ("du -sk /run/aide", "1531904\t/run/aide"),
        ("find /run/aide", "18342"),
        ("df -Pk /", "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 203056560 198907000 4149560 98% /"),
        ("du -xsk", "147849216\t/var/log/haproxy.log\n2202009\t/var/log/journal\n1048576\t/var/lib/docker\n524288\t/var/log/syslog\n31112\t/root"),
        ("stat -c '%s' /var/log/haproxy.log", "151397597184"),
        ("/etc/logrotate.d/haproxy", "MISSING"),
        ("journalctl --disk-usage", "Archived and active journals take up 2.1G in the file system."),
        ("lsof -nP +L1", "rsyslogd 1011 536870912\nhaproxy 3101 104857600"),
        ("pgrep -a aide", ""),
        ("systemctl is-active haproxy rsyslog", "active\nactive"),
        ("/proc/meminfo", "MemTotal:       32780000 kB\nMemAvailable:    2400000 kB"),
        ("ps -eo", "  PID USER     COMMAND           RSS %CPU\n 1880 varnish  cache-main    9800000 22.1\n 2211 root     logparser     3900000 31.0\n"
                   " 2212 root     logparser     3800000 30.2\n 2213 root     logparser     3700000 29.8\n 2214 root     logparser     3600000 28.9\n"
                   " 3101 root     haproxy       2900000  6.4\n 2290 root     logparser     1200000 12.0\n  901 root     dockerd        310000  1.1"),
        ("systemctl is-active varnish", "active"),
        ("docker ps -a", "CONTAINER ID   IMAGE           COMMAND                  CREATED        STATUS                     PORTS     NAMES\n"
                         + ("3f2a1b9c8d7e   haproxy:2.8     \"docker-entrypoint.s…\"   8 months ago   Exited (137) 2 hours ago             lb"
                            if broken else "3f2a1b9c8d7e   haproxy:2.8     \"docker-entrypoint.s…\"   8 months ago   Up 3 days                            lb")),
        ("docker stats", "CONTAINER ID   NAME   CPU %   MEM USAGE / LIMIT    MEM %   NET I/O   BLOCK I/O   PIDS\n"
                         + ("" if broken else "3f2a1b9c8d7e   lb     6.40%   2.9GiB / 31.26GiB   9.28%   1.2TB / 1.4TB   0B / 0B   41")),
        ("pgrep -a logparser", "2211 /usr/bin/logparser\n2212 /usr/bin/logparser\n2213 /usr/bin/logparser\n2214 /usr/bin/logparser\n2290 /usr/bin/logparser"),
        ("docker exec lb", "Error response from daemon: Container 3f2a1b9c8d7e is not running" if broken
         else "backend prometheus_backend\n    server prom1 10.249.10.5:9090 check"),
        ("/-/ready", "000" if broken else "200"),
    ]
    return lookup(table, cmd)


def cdn_vcp(name, cmd):
    table = [
        ("varnishd -V", "varnishd (varnish-plus-6.0.16r1 revision 2a3b4c5d)"),
        ("mse.conf", '5:        database_size = "2G";\n9:                    filename = "/cache/mse/store.dat";\n10:                    size = "940G";'),
        ("df -Pk /cache", "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/mapper/vg_varnish-vcp_cache 1055762372 1029680000 26082372 99% /cache"),
        ("varnishstat", "MSE_STORE.store.g_objects 0\nMSE_STORE.store.g_alloc_bytes 0\nMSE_STORE.store.g_free_bytes 1009317310464\n"
                        "MSE.mse.c_fail 0\nMSE.mse.n_lru_nuked 0\nMAIN.backend_fail 0"),
        ("systemctl is-active varnish", "active"),
        ("varnishadm ping", "PONG 1760000000 1.0"),
        ("pgrep -a aide", "4242 /usr/bin/aide --config /var/lib/aide/aide.conf.autogenerated --check"),
        ("store.dat", "1009317310464 varnish:varnish 644"),
        ("/proc/meminfo", "MemTotal:       65536000 kB\nMemAvailable:   20000000 kB"),
    ]
    return lookup(table, cmd) or cdn_lb(name, cmd)


def repo(name, cmd):
    started = applied(name, "systemctl start nginx")
    table = [
        ("systemctl is-active nginx", "active" if started else "failed"),
        ("nginx -t", "nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\nnginx: configuration file /etc/nginx/nginx.conf test is successful"),
        ("openssl s_client", "notAfter=Sep 30 23:59:59 2026 GMT\nsubject=CN = ubuntu-mirror.example.com"),
        ("curl -sk", "200" if started else "502"),
        ("date -u +%s", str(NOW)),
    ]
    return lookup(table, cmd)


def dns(name, cmd):
    quiet, emptied = applied(name, "quiet=yes"), applied(name, "truncate -s 0 /var/log/syslog")
    table = [
        ("df -Pk /", "Filesystem 1024-blocks Used Available Capacity Mounted on\n" + ("/dev/sda2 61611820 12127788 49484032 20% /"
                     if emptied else "/dev/sda2 61611820 59127788 2484032 96% /")),
        ("/var/log/syslog*", "2048\t/var/log/syslog" if emptied else
                             "46137344\t/var/log/syslog\n984064\t/var/log/syslog.2.gz\n235520\t/var/log/syslog.3.gz\n203776\t/var/log/syslog.4.gz"),
        ("systemctl is-active pdns-recursor", "active"),
        ("recursor", "/etc/powerdns/recursor.conf:loglevel=5\n/etc/powerdns/recursor.d/recursor-local.conf:quiet=" + ("yes" if quiet else "no") + "\n"
                     "/etc/powerdns/recursor.d/recursor-local.conf:structured-logging=yes"),
        ("Question answered", "0" if quiet else "1873"),
        ("journalctl --disk-usage", "Archived and active journals take up 900.0M in the file system."),
    ]
    return lookup(table, cmd)


VYOS_CONFIG = """set firewall ipv4 forward filter default-action 'accept'
set firewall ipv4 forward filter rule 10 action 'jump'
set firewall ipv4 forward filter rule 10 inbound-interface name 'eth2'
set firewall ipv4 forward filter rule 10 jump-target 'WAN-IN'
set firewall ipv4 name OUTSIDE-IN default-action 'drop'
set firewall ipv4 name OUTSIDE-IN rule 5 action 'accept'
set firewall ipv4 name OUTSIDE-IN rule 5 state 'established'
set firewall ipv4 name OUTSIDE-IN rule 5 state 'related'
set firewall ipv4 name WAN-IN default-action 'drop'
set firewall ipv4 name WAN-IN rule 70 action 'return'
set firewall ipv4 name WAN-IN rule 70 destination port '514'
set firewall ipv4 name WAN-IN rule 70 protocol 'tcp'
set firewall ipv4 name WAN-IN rule 70 state 'new'
set interfaces ethernet eth0 address '10.248.0.5/24'
set interfaces ethernet eth0 hw-id '52:54:00:aa:00:01'
set interfaces ethernet eth1 address '11.14.100.147/24'
set interfaces ethernet eth2 address '11.7.101.238/24'
set nat destination rule 434 destination address '11.7.101.238'
set nat destination rule 434 destination port '514'
set nat destination rule 434 inbound-interface name 'eth2'
set nat destination rule 434 protocol 'tcp'
set nat destination rule 434 translation address '11.14.100.11'
set nat destination rule 434 translation port '514'
set nat destination rule 435 destination address '11.7.101.238'
set nat destination rule 435 destination port '514'
set nat destination rule 435 inbound-interface name 'eth2'
set nat destination rule 435 protocol 'udp'
set nat destination rule 435 translation address '11.14.100.11'
set nat destination rule 435 translation port '514'
set nat source rule 593 outbound-interface name 'eth2'
set nat source rule 593 source address '11.14.100.0/24'
set nat source rule 593 translation address 'masquerade'
set protocols static route 0.0.0.0/0 next-hop '11.7.101.1'
set protocols static route 172.0.0.0/8 next-hop '172.26.220.1'
set system host-name 'natgw-01'"""


def vyos(name, cmd):
    added = [c.strip() for c in STATE.get(name, []) if c.strip().startswith("set ")]
    table = [
        ("show configuration commands", VYOS_CONFIG + ("\n" + "\n".join(added) if added else "")),
        ("show ip route 0.0.0.0/0", "Routing entry for 0.0.0.0/0\n  Known via \"static\", distance 1, metric 0, best\n  * 11.7.101.1, via eth2, weight 1"),
        ("show ip route static", "S>* 0.0.0.0/0 [1/0] via 11.7.101.1, eth2, weight 1, 5d02h11m"),
        ("show interfaces", "Interface    IP Address           MAC                VRF        MTU  S/L    Description\n"
                                "eth0         10.248.0.5/24         52:54:00:aa:00:01  default   1500  u/u\n"
                                "eth1         11.14.100.147/24   52:54:00:aa:00:02  default   1500  u/u\n"
                                "eth2         11.7.101.238/24   52:54:00:aa:00:03  default   1500  u/u"),
        ("show version", "Version:          VyOS 1.3.8\nRelease train:    equuleus\nBuilt on:         Tue 02 Jul 2024 12:00 UTC"),
        ("show system image", "The system currently has the following image(s) installed:\n\n   1: 1.3.8 (default boot)"),
        ("ip -o link show", "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode DEFAULT group default qlen 1000\\    link/ether 52:54:00:aa:00:01 brd ff:ff:ff:ff:ff:ff\n"
                            "3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode DEFAULT group default qlen 1000\\    link/ether 52:54:00:aa:00:02 brd ff:ff:ff:ff:ff:ff\n"
                            "4: eth2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode DEFAULT group default qlen 1000\\    link/ether 52:54:00:aa:00:03 brd ff:ff:ff:ff:ff:ff"),
        ("ls /etc/dropbear", "/etc/dropbear/:\ndropbear_rsa_host_key\ndropbear_ecdsa_host_key"),
        ("/config/config.boot", "-rw-rw---- 1 root vyattacfg 5120 Oct  1 10:00 /config/config.boot"),
        ("ping -c 3", "FAIL"),
    ]
    return lookup(table, cmd)


def huawei(name, cmd):
    table = [
        ("display bgp peer", " BGP local router ID : 172.26.15.15\n Local AS number : 38513\n Total number of peers : 2\n\n"
                             "  Peer            V          AS  MsgRcvd  MsgSent  OutQ  Up/Down       State  PrefRcv\n\n"
                             "  11.18.9.157   4        4800   912345   456789     0 0201h12m Established        1\n"
                             "  172.26.15.17    4       38513   120000   118000     0 0201h10m Established       42"),
        ("longer-match", "Route Flags: R - relay, D - download to fib\n------------------------------------------------------------------------------\n"
                         "Routing Table : _public_\nSummary Count : 1\nDestination/Mask    Proto   Pre  Cost  Flags NextHop         Interface\n"
                         "  11.5.244.0/24  IBGP    255  0     RD    172.26.15.17    Eth-Trunk10"),
        ("display ip routing-table", "Route Flags: R - relay, D - download to fib\n------------------------------------------------------------------------------\nRouting Table : _public_\nSummary Count : 0"),
        ("display bgp routing-table", " Info: The network does not exist."),
        ("section ALLOWED_BGP_OUT", "xpl ip-prefix-list ALLOWED_BGP_OUT\n 11.13.129.0 24,\n 11.15.72.0 24,\n 11.13.128.0 24,\n 11.15.70.0 24,\n"
                                    " 11.15.67.0 24,\n 11.15.64.0 24,\n 11.15.65.0 24,\n 11.8.158.0 24,\n 11.13.130.0 24,\n"
                                    " 11.7.100.0 23,\n 11.7.90.0 24,\n 11.6.214.0 23\n end-list"),
        ("display current-configuration", ""),
    ]
    return lookup(table, cmd)


def app_vm(name, cmd):
    nginx = applied(name, "systemctl start nginx")
    accept = next((c for c in STATE.get(name, []) if "nft insert rule" in c and "dport 27017 accept" in c), "")
    accept_rule = re.sub(r"^.*position \d+ ", "", accept).strip()
    table = [
        ("ss -H -lntup", ('tcp LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=2302,fd=6))\n' if nginx else
                          'tcp LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("apache2",pid=1234,fd=4))\n')
                         + 'tcp LISTEN 0 4096 0.0.0.0:27017 0.0.0.0:* users:(("mongod",pid=900,fd=11))\n'
                         'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=700,fd=3))'),
        ("systemctl is-active nginx", "active\n● nginx.service - A high performance web server\n   Active: active (running)" if nginx else
                                      "failed\n× nginx.service - A high performance web server and a reverse proxy server\n"
                                      "   Active: failed (Result: exit-code)\n"
                                      "nginx[2301]: nginx: [emerg] bind() to 0.0.0.0:80 failed (98: Address already in use)\n"
                                      "nginx[2301]: nginx: [emerg] still could not bind()"),
        ("for u in nginx apache2 httpd", "nginx active\napache2 inactive\nhttpd inactive" if nginx else None),
        ("list ruleset", "table inet filter { # handle 1\n\tchain input { # handle 1\n\t\ttype filter hook input priority filter; policy accept;\n"
                         "\t\tct state established,related accept # handle 4\n\t\ttcp dport 22 accept # handle 5\n"
                         f"\t\t{accept_rule} # handle 7\n\t\ttcp dport 27017 reject with icmpx admin-prohibited # handle 6\n\t}}\n}}"
         if accept_rule else None),
        ("/dev/tcp/127.0.0.1/80'", "TCP_OPEN"), ("/dev/tcp/127.0.0.1/27017", "TCP_OPEN"), ("/dev/tcp/127.0.0.1/", "TCP_CLOSED"),
        ("ping -c 2", "OK"),
        ("for u in nginx apache2 httpd", "nginx failed\napache2 active\nhttpd inactive"),
        ("list ruleset", "table inet filter { # handle 1\n\tchain input { # handle 1\n\t\ttype filter hook input priority filter; policy accept;\n"
                         "\t\tct state established,related accept # handle 4\n\t\ttcp dport 22 accept # handle 5\n"
                         "\t\ttcp dport 27017 reject with icmpx admin-prohibited # handle 6\n\t}\n}"),
        ("iptables-save", "# Generated by iptables-nft-save v1.8.7\n*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT"),
        ("iptables -V", "iptables v1.8.7 (nf_tables)"),
        ("ufw status", "Status: inactive"),
        ("for u in nftables", "nftables active\nfirewalld inactive\nufw inactive\nnetfilter-persistent inactive"),
        ("ip route show table all", ""),
        ("ip route show default", "default via 10.249.1.1 dev ens192 proto static"),
        ("ip -br a", "lo UNKNOWN 127.0.0.1/8\nens192 UP 10.249.1.20/24"),
    ]
    return lookup(table, cmd)


def rhel_vm(name, cmd):
    if applied(name, "semanage port -a -t syslogd_port_t -p tcp 541"):
        fixed = lookup([("semanage port -l", "syslogd_port_t                 tcp      541, 6514, 601\nsyslogd_port_t                 udp      514, 6514, 601"),
                        ("journalctl -u rsyslog", "")], cmd)
        if fixed is not None:
            return fixed
    table = [
        ("rpm -q rsyslog", "rsyslog-8.2102.0-117.el9.x86_64"),
        ("systemctl is-active rsyslog", "active"),
        ("omfwd", 'action(\n    type="omfwd"\n    target="172.26.0.40"\n    port="541"\n    protocol="tcp"'),
        ("getenforce", "Enforcing"),
        ("semanage port -l", "syslogd_port_t                 tcp      6514, 601\nsyslogd_port_t                 udp      514, 6514, 601"),
        ("/dev/tcp/", "OPEN"),
        ("journalctl -u rsyslog", "rsyslogd[1088]: omfwd: cannot connect to 172.26.0.40:541: Permission denied [v8.2102.0]\n"
                                  "rsyslogd[1088]: action 'action-0-builtin:omfwd' suspended (module 'builtin:omfwd')"),
        ("rsyslogd -N1", "rsyslogd: version 8.2102.0, config validation run (level 1), master config /etc/rsyslog.conf\nrsyslogd: End of config validation run. Bye."),
    ]
    return lookup(table, cmd) or app_vm(name, cmd)


def siem(name, cmd):
    table = [
        ("systemctl is-active rsyslog", "active"),
        ("ss -H -lntup", 'tcp LISTEN 0 25 0.0.0.0:514 0.0.0.0:* users:(("rsyslogd",pid=1011,fd=6))\n'
                         'tcp LISTEN 0 25 0.0.0.0:541 0.0.0.0:* users:(("rsyslogd",pid=1011,fd=7))'),
        ("firewall-cmd", "514/tcp 514/udp 541/tcp"),
        ("for d in /data/collectorlogs", "unknown 4\nveeam 0\nvmware 12\nwindows-server 7"),
        ("ls -1t /data/collectorlogs/unknown", "10.246.5.21\n10.246.5.22"),
        ("df -Pk /data", "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/mapper/data 2113928192 1500889600 613038592 71% /data"),
    ]
    return lookup(table, cmd)


def esxi(name, cmd):
    host = next((re.search(r'--loghost="([^"]*)"', c).group(1) for c in STATE.get(name, []) if "--loghost=" in c), "")
    table = [
        ("syslog config get", "   Check Certificate Revocation: false\n   Default Network Retry Timeout: 180\n   Local Log Output: /scratch/log\n"
                              f"   Remote Host: {host or '<none>'}"),
        ("ruleset list", "syslog                       " + ("true" if applied(name, "--ruleset-id=syslog --enabled=true") else "false")),
        ("nc -z", "OPEN"),
        (".vmsyslogd.err", ""),
    ]
    return lookup(table, cmd)


def gb200(name, cmd):
    table = [
        ("lspci", "03:00.0 Ethernet controller: Mellanox Technologies MT2910 Family [ConnectX-7]\n03:00.1 Ethernet controller: Mellanox Technologies MT2910 Family [ConnectX-7]\n"
                  "c1:00.0 Ethernet controller: Mellanox Technologies MT43244 BlueField-3 integrated ConnectX-7 network controller\n"
                  "c1:00.1 DMA controller: Mellanox Technologies MT43244 BlueField-3 SoC Management Interface"),
        ("ip -br link", "lo UNKNOWN 00:00:00:00:00:00\nens1f0np0 UP b8:3f:d2:00:00:01\nens1f1np1 DOWN b8:3f:d2:00:00:02\nenp193s0f0np0 UP b8:3f:d2:00:10:01"),
        ("ethtool", "ens1f0np0 \tLink detected: yes\nens1f1np1 \tLink detected: no\nenp193s0f0np0 \tLink detected: yes"),
        ("dmesg", "[86400.123456] mlx5_core 0000:03:00.1 ens1f1np1: Link down\n[86410.654321] mlx5_core 0000:03:00.1: mlx5_cmd_check:810: query_vport_state failed"),
    ]
    return lookup(table, cmd)


# ---------------- VyOS upgrade (wi_analysis/vyos_upgrade.py): a VyOS 1.3 behind its jump host, the image on the jump host
ISO_SIZE, ISO_SHA = 612368384, "ab" * 32
CONFIG_SHA = "ef" * 32   # sha256 of /config/config.boot of the edge (the backup on the jump host has the same)


def vu_state(name):
    st = STATE.get(f"vu:{name}")
    if not isinstance(st, dict):
        st = {"version": "1.3.8", "images": ["1.3.8"], "default": "1.3.8", "hwid": {"eth0": "52:54:00:bb:00:01"},
              "tmp": "", "boot": 1, "down_until": 0, "next_version": ""}
    return st


def vu_save(name, st):
    STATE[f"vu:{name}"] = st
    if STATE_FILE:
        with open(STATE_FILE, "w") as f:
            json.dump(STATE, f)


EDGE_BY_ADDRESS = {"10.246.0.11": "jkt-vyos-edge-01", "10.246.0.12": "jkt-vyos-edge-small", "10.246.0.13": "jkt-vyos-edge-disk",
                   "10.246.0.14": "jkt-vyos-edge-disk-seen"}


def vu_images_text(st):
    """show system image as the running version prints it: VyOS 1.3 a numbered list, 2026.x a table."""
    if st["version"].startswith("1."):
        rows = "\n".join(f"   {i + 1}: {n}{' (default boot)' if n == st['default'] else ''}" for i, n in enumerate(st["images"]))
        return f"The system currently has the following image(s) installed:\n\n{rows}"
    w = max(len(n) for n in st["images"] + ["Name"])
    rows = "\n".join(f"{n.ljust(w)}  {('Yes' if n == st['default'] else '').ljust(12)}  {'Yes' if n == st['version'] else ''}".rstrip()
                     for n in st["images"])
    return f"{'Name'.ljust(w)}  Default boot  Running\n{'-' * w}  ------------  -------\n{rows}"


def vu_state_text(st, name=""):
    # eth4: a network card not in the configuration (admin down, no address); eth1: two addresses (vyos-VPC-E-New)
    macs = {"eth0": "52:54:00:bb:00:01", "eth1": "52:54:00:bb:00:02", "eth4": "52:54:00:bb:00:05"}
    # eth3: configured, its network card removed from the VM (no link, no MAC: hw-id skipped by the upgrade)
    cfg = ["set interfaces ethernet eth0 address '10.246.0.11/24'", "set interfaces ethernet eth1 address '11.6.215.130/26'",
           "set interfaces ethernet eth1 address '11.6.215.131/26'",
           "set interfaces ethernet eth3 address '11.7.102.60/23'", "set nat source rule 200 outbound-interface name 'eth3'"]
    cfg += [f"set interfaces ethernet {e} hw-id '{m}'" for e, m in st["hwid"].items()]
    cfg += ["set nat source rule 100 outbound-interface name 'eth1'", "set nat source rule 100 translation address 'masquerade'",
            "set nat destination rule 10 destination port '443'", "set protocols static route 0.0.0.0/0 next-hop '11.6.215.129'",
            "set protocols static route 10.248.0.0/16 next-hop '10.246.0.1'"]   # 10.246.0.1 never answers ping (before and after)
    images = vu_images_text(st)
    if "disk" in name:   # a 2 GB disk, enlarged to 10 GB in OpenStack: the VyOS sees it after a reboot (-seen: at once)
        seen = st.get("grown") or st["boot"] > 1 or "seen" in name
        store = f"/dev/vda1 2064208 1105744 {6000000 if st.get('grown') else 958464} 54% /usr/lib/live/mount/persistence"
        disk = (f"dev /dev/vda1 ext4\ndisk vda {20971520 if seen else 4194304}\npart vda1 2048 {20969472 if st.get('grown') else 4192256}\n"
                "tool sfdisk\ntool partx\ntool resize2fs")
    else:
        store = "/dev/sda3 8000000 2000000 6000000 25% /usr/lib/live/mount/persistence"
        disk = "dev /dev/sda3 ext4\ndisk sda 16777216\npart sda1 2048 2048\npart sda2 4096 409600\npart sda3 413696 16363520\ntool sfdisk\ntool partx\ntool resize2fs"
    sec = {"version": f"Version:          VyOS {st['version']}",
           "images": images,
           "config": "\n".join(sorted(cfg)),
           "links": "\n".join(f"{i + 2}: {e}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\\    link/ether {m} brd ff:ff:ff:ff:ff:ff"
                              for i, (e, m) in enumerate(macs.items())),
           "addrs": "2: eth0    inet 10.246.0.11/24 brd 10.246.0.255 scope global eth0\n3: eth1    inet 11.6.215.130/26 scope global eth1\n"
                    "3: eth1    inet 11.6.215.131/26 scope global secondary eth1",
           "routes": "default via 11.6.215.129 dev eth1 proto static metric 20\n10.246.0.0/24 dev eth0 proto kernel scope link src 10.246.0.11\n"
                     "11.6.215.128/26 dev eth1 proto kernel scope link src 11.6.215.130",
           # a VM with 1 GB of memory (-small): /tmp, half of it, is too small for the ISO; the disk has room
           "tmp": "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
                  + ("tmpfs 505972 4 505968 1% /tmp" if "small" in name else "tmpfs 2000000 10000 1990000 1% /tmp"),
           "isos": "",
           "home": "/home/vyos\nFilesystem 1024-blocks Used Available Capacity Mounted on\noverlay 8000000 2000000 6000000 25% /",
           "store": "Filesystem 1024-blocks Used Available Capacity Mounted on\n" + store,
           "disk": disk,
           "dropbear": "dropbear_rsa_host_key\ndropbear_ecdsa_host_key" if st["version"].startswith("1.3") else "",
           "python": "/usr/bin/python3"}
    return "\n".join(f"@@VU@@{k}\n{v}" for k, v in sec.items())


def vyos_edge(name, cmd):
    st = vu_state(name)
    now = time.time()
    if st["down_until"] and now < st.get("down_from", 0):   # the reboot was asked; the VyOS still answers for a moment
        pass
    elif st["down_until"] and now < st["down_until"]:   # rebooting
        return None if False else ("__rc__255", f"ssh: connect to host 10.246.0.11 port 22: Connection refused")
    if st["down_until"] and now >= st["down_until"]:   # booted into the default image
        st.update(down_until=0, boot=st["boot"] + 1, version=st["default"].replace("vyos-", "") if st["default"] else st["version"], tmp="")
        vu_save(name, st)
    if "@@VU@@version" in cmd:
        return vu_state_text(st, name)
    m = re.match(r"^: wi-vu (\S+); ", cmd)
    step = m.group(1) if m else ""
    if step == "backup":
        if "cp " in cmd or "before-" in cmd:
            return ("__rc__1", "a copy of the configuration on the VyOS itself: the backup belongs on the jump host")
        return (f"Saving configuration to '/config/config.boot'...\nDone\n{CONFIG_SHA}  /config/config.boot\n"
                "-rw-rw---- 1 root vyattacfg 5120 /config/config.boot")
    if step == "hwid":
        for e, mac in re.findall(r"set interfaces ethernet (eth\d+) hw-id \W*([0-9a-f:]{17})", cmd):
            st["hwid"][e] = mac
        vu_save(name, st)
        return "\n".join(f"set interfaces ethernet {e} hw-id '{m}'" for e, m in st["hwid"].items())
    if step == "room":
        t = vu_state_text(st, name)
        part = lambda k: t.split(f"@@VU@@{k}\n")[1].split("\n@@VU@@")[0]
        return "\n".join(f"@@VU@@{k}\n{part(k)}" for k in ("tmp", "store", "home", "disk")) + "\n@@VU@@isos\n"
    if step == "grow":
        seen = st.get("grown") or st["boot"] > 1 or "seen" in name
        if not seen or "sfdisk --no-reread -N 1 /dev/vda" not in cmd or "resize2fs /dev/vda1" not in cmd:
            return ("__rc__4", "NOCHANGE: partition 1 is size 4192256. it cannot be grown")
        st["grown"] = True
        vu_save(name, st)
        return ("# the partition table before:\nlabel: dos\ndevice: /dev/vda\n/dev/vda1 : start=2048, size=4192256, type=83, bootable\n"
                "Resizing the filesystem on /dev/vda1 to 2621184 (4k) blocks.\nThe filesystem on /dev/vda1 is now 2621184 (4k) blocks long.")
    if step == "checksum":
        path = re.search(r"sha256sum (\S+)", cmd).group(1)
        if st["tmp"] and path.startswith(st.get("iso_dir", "/tmp") + "/"):
            return f"{st['tmp']}  {path}"
        return ("__rc__1", f"sha256sum: {path}: No such file or directory")
    if step == "install":
        path = re.search(r"install (\S+)", cmd).group(1)
        if not st["tmp"] or not path.startswith(st.get("iso_dir", "/tmp") + "/"):
            return ("__rc__5", f"RESULT failed: {path} is not on the VyOS")
        if "2026.03" not in st["images"]:
            st["images"].insert(0, "2026.03")
        st["default"] = "2026.03"
        vu_save(name, st)
        images = "\n".join(f"   {i + 1}: {n}{' (default boot)' if n == st['default'] else ''}" for i, n in enumerate(st["images"]))
        return ("[portal] answered Yes to: Would you like to set the new image as the default one for boot? [Y/n]\nRESULT ok\n"
                f"The system currently has the following image(s) installed:\n\n{images}")
    if step == "default_boot":
        image = re.search(r"default-boot '?([A-Za-z0-9_.+-]+)'?", cmd).group(1)
        st["default"] = image
        vu_save(name, st)
        return f"RESULT ok\n{vu_images_text(st)}"
    if step == "cve":
        return "Public key portion is:\nssh-rsa AAAA... root@vyos\nFingerprint: SHA256:newkey"
    if step == "cleanup":
        st["tmp"] = ""
        vu_save(name, st)
        return ""
    if step == "reboot":
        st["down_from"] = now + 2   # as on a real VyOS: "sleep 3; reboot" in the background
        st["down_until"] = st["down_from"] + float(os.environ.get("FAKE_VYOS_BOOT_SECONDS", "3"))
        vu_save(name, st)
        return "reboot in 3 seconds"
    if step == "alive":
        if "/proc/sys/kernel/random/boot_id" not in cmd:   # anything else (the uptime) changes without a reboot
            return f"{now:.2f} 1234.56"
        return f"boot-{st['boot']}"
    if step == "ping":
        return "\n".join(f"@@VU@@ping {h}\n{'FAIL' if h == '10.246.0.1' else 'OK'}"
                         for h in re.findall(r"echo '@@VU@@ping ([0-9.]+)'", cmd))
    return None


def vyos_jump(name, cmd):
    m = re.match(r"^: wi-vu (\S+); ", cmd)
    step = m.group(1) if m else ""
    if step == "iso":
        if "/home/vyos/vyos-2026.03-generic-amd64.iso" not in cmd:
            return ("__rc__2", "not found: " + cmd.split("test -r ")[1].split(" ")[0])
        return f"{ISO_SIZE}\n{ISO_SHA}  /home/vyos/vyos-2026.03-generic-amd64.iso"
    if step == "backup":   # scp of /config/config.boot from the edge into the backup folder of the jump host
        src = re.search(r"([A-Za-z0-9_.-]+)@([0-9.]+):/config/config\.boot", cmd)
        folder = re.search(r"mkdir -p (\S+) ", cmd).group(1).strip("'")
        if not src or "umask 077" not in cmd or "chmod 600" not in cmd:
            return ("__rc__4", "the configuration was not copied")
        f = f"{folder}/config.boot.20261021-233000.before-2026.03"
        if "corrupt-copy" in folder:   # the next scp of the image arrives damaged (sha256 differs)
            edge = vu_state(os.environ.get("FAKE_VYOS_EDGE", "jkt-vyos-edge-01"))
            edge["corrupt"] = True
            vu_save(os.environ.get("FAKE_VYOS_EDGE", "jkt-vyos-edge-01"), edge)
        return f"@@VU@@backup {f}\n{'00' * 32 if 'bad-backup' in folder else CONFIG_SHA}  {f}\n-rw------- 1 vyos users 5120 {f}"
    if step == "copy":
        target = re.search(r"([A-Za-z0-9_.-]+)@([0-9.]+):(/[A-Za-z0-9_./-]+)/vyos-[^/ ']+\.iso", cmd)
        edge = EDGE_BY_ADDRESS.get(target.group(2)) or os.environ.get("FAKE_VYOS_EDGE", "jkt-vyos-edge-01")
        st = vu_state(edge)
        st["tmp"] = "00" * 32 if st.pop("corrupt", False) else ISO_SHA
        st["iso_dir"] = target.group(3)
        vu_save(edge, st)
        return f"(test mode) copied to {target.group(1)}@{target.group(2)}:{target.group(3)}"
    return None


PROFILES = [(r"vyos-edge", vyos_edge), (r"vyos-jump", vyos_jump), (r"cdn-vcp", cdn_vcp), (r"cdn-lb", cdn_lb), (r"repo", repo), (r"dns", dns), (r"natgw|vyos", vyos),
            (r"rcgw", huawei), (r"rhel", rhel_vm), (r"siem", siem), (r"esxi", esxi), (r"gb200", gb200), (r".*", app_vm)]


def lookup(table, cmd):
    for needle, out in table:
        if out is not None and needle in cmd:
            return out
    return None


RESOURCES = [  # the reads of the check Server resources (same on every host; app-vm-01: / at 93%, memory 91%, a failed unit)
    ("df -Pk -x tmpfs", lambda n: "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
                                  + (f"/dev/vda1 41152736 38272044 2880692 93% /\n" if n == "app-vm-01" else "/dev/vda1 41152736 12000000 29152736 30% /\n")
                                  + "/dev/vdb1 103080224 41232090 61848134 40% /data"),
    ("df -Pi -x tmpfs", lambda n: "Filesystem Inodes IUsed IFree IUse% Mounted on\n/dev/vda1 2621440 340000 2281440 13% /\n/dev/vdb1 6553600 65536 6488064 1% /data"),
    ("free -k", lambda n: "               total        used        free      shared  buff/cache   available\n"
                          + ("Mem:        16265076    14600000      300000       10000     1365076     1463856\n" if n == "app-vm-01" else
                             "Mem:        16265076     6000000     6000000       10000     4265076     9900000\n")
                          + "Swap:        2097148      512000     1585148"),
    ("nproc; cat /proc/loadavg", lambda n: "4\n" + ("3.80 3.10 2.40 3/412 98123" if n == "app-vm-01" else "0.20 0.15 0.10 1/300 1234")),
    ("head -n 1 /proc/stat", lambda n: "cpu  1000 0 1000 8000 0 0 0 0 0 0\ncpu  1100 0 1100 8250 50 0 0 0 0 0"),
    ("systemctl --failed", lambda n: "nginx.service loaded failed failed A high performance web server" if n == "app-vm-01" else ""),
    ("ps -eo pid,user,pmem,pcpu,rss,comm", lambda n: "    PID USER     %MEM %CPU   RSS COMMAND\n   2201 mongodb  61.2 12.0 9955000 mongod\n    880 root      2.1  0.3 340000 dockerd"),
    ("ps -eo pid,user,pcpu,pmem,comm", lambda n: "    PID USER     %CPU %MEM COMMAND\n   2201 mongodb  45.0 61.2 mongod\n    880 root      1.0  2.1 dockerd"),
    ("uptime", lambda n: " 10:00:00 up 12 days,  3:04,  0 users,  load average: 3.80, 3.10, 2.40"),
]


def answer(name, cmd):
    for needle, fn in RESOURCES:
        if cmd.startswith(needle):
            return 0, fn(name)
    profile = next(fn for pattern, fn in PROFILES if re.search(pattern, name, re.I))
    out = profile(name, cmd)
    if isinstance(out, tuple):   # (rc marker, output): a command that fails
        return int(out[0].replace("__rc__", "")), out[1]
    return (0, out) if out is not None else (127, f"fake_hosts: {name}: command not emulated: {cmd[:120]}")


ACTION_RE = re.compile(r"echo '@@WI@@begin (a\d+)'\n\{\n(.*?)\n\} 2>&1\nrc=\$\?\necho \"@@WI@@end \1 \$rc\"", re.S)


def run_fix(name, script):
    """A fix script of the portal (modules/wi/wi_analysis action_script): every command succeeds and is remembered."""
    if script.startswith("/bin/vbash -c "):
        script = shlex.split(script)[2]
    done = []
    for key, cmd in ACTION_RE.findall(script):
        done.append(cmd)
        out = lookup([("hostname", name), ("id -un", "root"), ("uptime", " 10:00:00 up 12 days,  3:04,  0 users,  load average: 0.10, 0.20, 0.15")], cmd)
        print(f"@@WI@@begin {key}")
        print(out if out is not None else f"(test mode) {cmd.splitlines()[0][:160]}")
        print(f"@@WI@@end {key} 0")
    remember(name, done)
    return 0


def main():
    name, script = sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else ""
    load_state()
    if "@@WI@@begin a1" in script:
        return run_fix(name, script)
    if "@@WI@@begin" not in script:   # a network device: one command
        rc, out = answer(name, script)
        print(out)
        return rc
    for line in script.splitlines():
        m = re.match(r"^echo '@@WI@@begin (\S+)'; \{ (.*) ; \} 2>&1; echo \"@@WI@@end \1 \$\?\"$", line)
        if not m:
            continue
        key, cmd = m.group(1), m.group(2)
        rc, out = answer(name, cmd)
        print(f"@@WI@@begin {key}")
        if out:
            print(out)
        print(f"@@WI@@end {key} {rc}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Operation Automation analysis: what each check reads (per phase and per source) and how it rates what was read.

Used by the Ansible filter plugin (playbooks/filter_plugins/wi_filters.py) and by the tests. Sources:
  openstack  commands on the director (management host -> director -> overcloudrc), read-only allowlist below
  ontap      REST GET on the site's ONTAP cluster with the ONTAP Restore account of the site (ontap:<site>)
  vcenter    REST GET on vCenter with the read-only account (ro-vcenter:<site>)
  nsxt       REST GET on NSX-T Manager with the read-only account (ro-nsxt:<site>)
  vcd        REST GET on vCloud Director with the read-only provider account (ro-vcd, every site)
  vsphere    vCenter inventory (pyVmomi PropertyCollector) with the read-only vCenter account; items name the sets
  host       fixed shell commands on a host of a sites.yml hosts group (SSH key, read-only account)
  device     single commands on a network device of a hosts group (one SSH exec per command)
  tcp        TCP connection tests from the portal server
  undercloud commands on the director after `source ~/stackrc` (ironic: the bare metal nodes), read-only allowlist below
  redfish    Redfish GET on one BMC of the page BMC (its management IP, HTTPS) with the BMC account given there
  tls        the certificate a configured address presents (TLS handshake from the portal server, no account)
  overcloud  fixed read commands on the overcloud nodes, from the director (ssh heat-admin / tripleo-admin to the ctlplane
             address, see overcloud.py): pcs status, stonith history, rabbitmqctl cluster_status, chrony, log lines
  collect    an archive from an overcloud node (log files of a time window, or a sos report) streamed through the director
             and the management host into the bundle folder of the run (see logs.py, wi_collect.py)
"""
import base64
import gzip
import os
import re
import shlex
import urllib.parse

from . import (capacity, cert_inventory, certs, control_plane, exports, hardware, linux, logs, network, ontap, openstack, openstack_health, openstack_ops,
               ontap_health, overcloud, overcloud_checks, ovn, prime_platform, screens, template, vcloud, vmware, vyos_upgrade)
from .common import unavailable

CHECKS = {
    "nsxt-gateway-routing": prime_platform.NsxtGatewayRouting,
    "vcd-platform": prime_platform.VcdPlatform,
    "vcenter-appliance": prime_platform.VcenterAppliance,
    "ontap-volume-lun-state": ontap_health.OntapVolumeLunState,
    "ontap-ha-redundancy": ontap_health.OntapHaRedundancy,
    "ovn-db-cluster": control_plane.OvnDbCluster,
    "rabbitmq-queues": control_plane.RabbitmqQueues,
    "galera-wsrep": control_plane.GaleraWsrep,
    "cinder-pool-usage": openstack.CinderPoolUsage,
    "volume-type-legacy": openstack.VolumeTypeLegacy,
    "project-quota": openstack.ProjectQuota,
    "stuck-resources": openstack.StuckResources,
    "volume-attach": openstack.VolumeAttach,
    "instance-network": openstack.InstanceNetwork,
    "custom-port-tcp": openstack.InstanceNetwork,
    "ovn-fdb-learning": ovn.OvnFdbLearning,
    "openstack-services": openstack_health.OpenstackServices,
    "ironic-nodes": openstack_health.IronicNodes,
    "bmc-health": hardware.BmcHealth,
    "pacemaker-health": overcloud_checks.PacemakerHealth,
    "overcloud-logs": overcloud_checks.OvercloudLogs,
    "collect-logs": logs.CollectLogs,
    "sos-report": logs.SosReport,
    "bmc-log-export": exports.BmcLogs,
    "ontap-ems-export": exports.OntapEms,
    "vcenter-events-export": exports.VcenterEvents,
    "overcloud-node-health": capacity.OvercloudNodeHealth,
    "compute-capacity": capacity.ComputeCapacity,
    "compute-drain": openstack_ops.ComputeDrain,
    "image-housekeeping": openstack_ops.ImageHousekeeping,
    "linux-resources": capacity.LinuxResources,
    "ontap-capacity": capacity.OntapCapacity,
    "cert-expiry": certs.CertExpiry,
    "cert-inventory": cert_inventory.CertInventory,
    "certmonger-status": cert_inventory.CertmongerStatus,
    "ontap-cluster-health": ontap.OntapClusterHealth,
    "cdn-disk-run": linux.CdnDiskRun,
    "cdn-root-disk": linux.CdnRootDisk,
    "cdn-memory": linux.CdnMemory,
    "cdn-datasource": linux.CdnDatasource,
    "cdn-repo": linux.CdnRepo,
    "cdn-varnish-mse": linux.CdnVarnishMse,
    "dns-recursor-syslog": linux.DnsRecursorSyslog,
    "linux-service-port": linux.LinuxServicePort,
    "linux-firewall": linux.LinuxFirewall,
    "siem-forwarder": linux.SiemForwarder,
    "siem-collector": linux.SiemCollector,
    "esxi-syslog": linux.EsxiSyslog,
    "gb200-nic-link": linux.Gb200NicLink,
    "vyos-nat-firewall": network.VyosNatFirewall,
    "vyos-upgrade-precheck": network.VyosUpgradePrecheck,
    "vyos-upgrade": vyos_upgrade.VyosUpgrade,
    "vyos-static-route": network.VyosStaticRoute,
    "huawei-bgp-prefix": network.HuaweiBgpPrefix,
    "nsxt-snat-priority": network.NsxtSnatPriority,
    "nsxt-health": network.NsxtHealth,
    "vcenter-datastore": vmware.VcenterDatastore,
    "vmware-host-usage": vmware.VmwareHostUsage,
    "vcenter-health": vmware.VcenterHealth,
    "vcd-vm-power": vcloud.VcdVmPower,
    "vcd-edge": vcloud.VcdEdge,
}
SOURCES = ("openstack", "ontap", "vcenter", "nsxt", "vcd", "vsphere", "host", "device", "tcp", "undercloud", "redfish", "overcloud", "tls",
           "collect")
VSPHERE_SETS = ("hosts", "vms", "pools", "clusters", "alarms", "events", "hosthealth", "vmhealth", "datastores", "hostcerts")


def vsphere_set_ok(name):
    """A set of the vCenter reader: one of VSPHERE_SETS, or events@<hours> / allevents@<hours> (1-720)."""
    base, at, arg = str(name).partition("@")
    if at:
        return base in ("events", "allevents") and arg.isdigit() and 1 <= int(arg) <= 720
    return base in VSPHERE_SETS

# OpenStack commands a check may run on the director: list / show / get-pools / quota / limits only.
OPENSTACK_READ = re.compile(
    r"^(openstack (server|volume|volume snapshot|volume type|port|floating ip|subnet|network|security group"
    r"|security group rule|project|router|hypervisor|compute service|volume service|network agent|ip availability|server event"
    r"|aggregate|image|flavor)"
    r" (list|show)( |$)"
    r"|openstack (quota|limits) show( |$)|openstack --version$"
    r"|cinder (get-pools|list|show|snapshot-list|type-list|service-list)( |$)"
    r"|date -u \+%Y-%m-%dT%H:%M:%SZ$)")
# The undercloud (stackrc): the bare metal nodes as ironic sees them through their BMC, and the certificates certmonger
# tracks on the director (getcert list), nothing else.
UNDERCLOUD_READ = re.compile(r"^(openstack baremetal node (list|show)( |$)|openstack server list -f json$|metalsmith -f json list$"
                             r"|cat /etc/rhosp-release$|date -u \+%Y-%m-%dT%H:%M:%SZ$|sudo -n getcert list$|"
                             + re.escape(overcloud.INVENTORY_GREP) + "$|" + re.escape(overcloud.PORTS_READ) + "$)")
SHELL_META = re.compile(r"[;&|`$<>(){}\\\n\"]|(^|\s)#")   # outside '...': no shell syntax, no "...", no comment
# options of the clients themselves: another Keystone (the admin password would go there), a log file, debug output
CLIENT_OPTION = re.compile(r"(^|\s)(--os-[A-Za-z-]+|--log-file|--debug)(=|\s|$)")


def shell_problem(text):
    """Why a command line is not safe to paste into the script of the director ("" when it is): every quote paired, and
    outside the '...' strings no shell syntax and no option that redirects the client."""
    if text.count("'") % 2:
        return "an unpaired quote"
    bare = re.sub(r"'[^']*'", "''", text)
    if SHELL_META.search(bare):
        return "shell syntax"
    if CLIENT_OPTION.search(bare):
        return "an option of the client itself (--os-*, --log-file, --debug)"
    return ""
# Changes a fix may make on OpenStack (Run this fix, permission wi-fix-openstack), each with strict arguments: only the
# commands the analysis generated from what it read, never text from the browser.
_U = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"   # UUID
_P = r"[0-9a-f]{32}"                                                     # project ID
_N = r"'?[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}'?"                            # volume type / plain name
_H = r"'?[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+#[A-Za-z0-9_.-]+'?"              # cinder host: host@backend#pool
_C = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}"                    # CIDR
_HN = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}"                                # compute host
_HL = rf"(-|{_HN}(,{_HN}){{0,7}})"                                      # computes to try next
_IP4 = r"\d{1,3}(\.\d{1,3}){3}"
_NM = rf"(-|{_HN}={_IP4}(,{_HN}={_IP4}){{0,63}})"                         # ctlplane address of the computes
_PH = r"[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+#[A-Za-z0-9_.-]+"                 # cinder pool, unquoted
_UL = rf"(-|{_U}(,{_U}){{0,49}})"                                       # IDs (snapshots)
_AD = r"[0-9a-fA-F.:]{2,39}(/\d{1,3})?"                                 # IPv4 / IPv6 address or network
OPENSTACK_FIX = [re.compile("^" + x + "$") for x in (
    rf"cinder migrate {_U} {_H}",   # as the Red Hat OpenStack Platform storage guide: cinder migrate <volume> <host@backend#pool>
    # cinder retype: the same syntax on every client version (openstack volume set renamed --retype-policy in 2024)
    rf"cinder retype --migration-policy (on-demand|never) {_U} {_N}",
    rf"cinder reset-state --state (available|in-use|error)( --attach-status (attached|detached))?( --reset-migration-status)? {_U}",
    rf"openstack volume snapshot delete {_U}",
    rf"cinder delete {_U}",
    rf"openstack quota set( --(instances|cores|ram|volumes|gigabytes|snapshots|ports|floating-ips|secgroups|secgroup-rules"
    rf"|networks|subnets|routers) \d{{1,9}})+ {_P}",
    rf"openstack server (start|stop|reboot) {_U}",
    rf"openstack server remove volume {_U} {_U}",
    rf"openstack server delete {_U}",
    rf"openstack server migrate --live-migration {_U}",
    rf"openstack security group rule create --ingress( --ethertype IPv4)? --protocol (tcp|udp) --dst-port \d{{1,5}}(:\d{{1,5}})? "
    rf"--remote-ip {_C}( --description '[A-Za-z0-9 _.:-]{{1,64}}')? {_U}",
    rf"openstack security group rule create --ingress( --ethertype IPv4)? --protocol icmp --remote-ip {_C} {_U}",
    r"sleep \d{1,3}",
    # Operations of wi_ops.py (one item each, followed until it ends, with its automatic fixes; see wi_ops.py).
    # under <percent> ram <MB>: the destination is the least used compute under that real CPU and RAM use (wi_ops.py)
    rf"live-migrate {_U} from {_HN} to ({_HN}|auto) try {_HL} timeout \d{{2,5}} stall (abort|force) nodes {_NM} "
    rf"user (heat-admin|tripleo-admin|-)( under \d{{2}} ram \d{{1,8}})?",
    rf"cold-migrate {_U} from {_HN} to ({_HN}|auto) try {_HL} timeout \d{{2,5}}"
    rf"( nodes {_NM} user (heat-admin|tripleo-admin|-) under \d{{2}} ram \d{{1,8}})?",
    rf"migrate-volume {_U} to {_PH} try (-|{_PH}(,{_PH}){{0,3}}) timeout \d{{2,5}} snapshots {_UL}",
    # the volume type of one volume (on-demand migration), its approved snapshots deleted first
    rf"retype-volume {_U} to [A-Za-z0-9][A-Za-z0-9_.:-]{{0,127}} timeout \d{{2,5}} snapshots {_UL}",
    rf"delete-image {_U} expect (size0|any) snapshots {_UL}",
    # one OVN FDB entry (its UUID), checked again on the node before and after the destroy (WI "FDB Learning Issue")
    rf"clear-fdb {_U} dp \d{{1,9}} mac [0-9a-f]{{12}} port \d{{1,9}} node {_HN}={_IP4} user (heat-admin|tripleo-admin)",
    # port security on for one port, with the allow-all security group of its project and the VIPs of the check (stage 9)
    rf"port-security {_U} project {_P} sg port-security-allow-all allow (-|{_AD}(,{_AD}){{0,15}}) dp \d{{1,9}} pkey \d{{1,9}} "
    rf"node {_HN}={_IP4} user (heat-admin|tripleo-admin)",
    # one certmonger request of an overcloud node resubmitted to its CA, followed until it monitors a new certificate
    rf"getcert-resubmit [A-Za-z0-9_.-]{{1,64}} node {_HN}={_IP4} user (heat-admin|tripleo-admin)",
    # The scheduler stops / starts placing instances on a compute (before and after it is emptied).
    rf"openstack compute service set --disable --disable-reason '[A-Za-z0-9 _.:,-]{{1,80}}' {_HN} nova-compute",
    rf"openstack compute service set --enable {_HN} nova-compute",
    # Checked right before the changes (the state may have changed since the check ran): a mismatch stops the fix.
    rf"require (volume|server) {_U} (status|migration_status|attachments|snapshots) [A-Za-z0-9_:,-]{{1,80}}",
    rf"wait (volume|server) {_U} (status|migration_status) [A-Za-z0-9_:,-]{{1,80}} \d{{1,5}}",
)]
# Shell functions of an OpenStack fix (trusted code of the portal): require = stop unless the value is one of the expected
# ones; wait = poll every 5 s until it is, up to <seconds>.
OS_FUNCTIONS = r"""wi_value() {
  case "$3" in
    snapshots) openstack volume snapshot list --all-projects --volume "$2" -f value -c ID | wc -l | tr -d ' ';;
    attachments) case "$(openstack volume show "$2" -f value -c attachments)" in *server_id*) echo attached;; *) echo none;; esac;;
    *) openstack "$1" show "$2" -f value -c "$3";;
  esac
}
wi_require() {
  have=$(wi_value "$1" "$2" "$3")
  case ",$4," in *",$have,"*) echo "$1 $2 $3: $have (as expected)";;
    *) echo "$1 $2 $3 is now '$have', not $4: nothing was changed"; return 3;; esac
}
wi_wait() {
  end=$(( $(date +%s) + $5 ))
  pause=5; [ "$5" -gt 600 ] && pause=15
  while :; do
    have=$(wi_value "$1" "$2" "$3")
    case ",$4," in *",$have,"*) echo "$1 $2 $3: $have"; return 0;; esac
    [ "$(date +%s)" -ge "$end" ] && { echo "$1 $2 $3 is still '$have' after $5 s (expected $4)"; return 4; }
    sleep $pause
  done
}"""
# What deletes on OpenStack (the operator types the ID, the name or the number of items): also an image clean-up and a
# volume migration that deletes the volume's snapshots first.
OPENSTACK_DELETE = re.compile(r"^(openstack (volume snapshot|server|image) delete|cinder delete|delete-image|clear-fdb|port-security) "
                              r"|^(migrate|retype)-volume .* snapshots [0-9a-f]")
OPS = ("live-migrate", "cold-migrate", "migrate-volume", "retype-volume", "delete-image", "clear-fdb", "port-security",
       "getcert-resubmit")
OPS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wi_ops.py")
REST_PATH = re.compile(r"^/[A-Za-z0-9_\-./:]*(\?[A-Za-z0-9_\-.,=&|%:;]*)?$")
MARK = "@@WI@@"


def check(check_id):
    if str(check_id).startswith("tpl-"):   # a template made on the portal: its steps come with the run (ctx["template"])
        return template.Template
    try:
        return CHECKS[check_id]
    except KeyError:
        raise ValueError(f"Unknown troubleshooting check {check_id!r}")


def plan(check_id):
    c = check(check_id)
    return {"sources": list(c.sources), "phases": int(c.phases)}


def reads(check_id, phase, data, params, ctx):
    """Everything a check reads in one phase: {source: {key: command, path or probe}}, every source present."""
    wanted = check(check_id).reads(int(phase), data or {}, params or {}, ctx or {}) or {}
    unknown = set(wanted) - set(SOURCES)
    if unknown:
        raise ValueError(f"{check_id}: unknown source {sorted(unknown)}")
    out = {s: dict(wanted.get(s) or {}) for s in SOURCES}
    for key in [k for s in SOURCES for k in out[s]]:
        if not re.match(r"^[A-Za-z0-9_.:-]{1,80}$", key):
            raise ValueError(f"{check_id}: invalid key {key!r}")
    for key, cmd in out["openstack"].items():
        assert_openstack_read(cmd)
    for key, cmd in out["undercloud"].items():
        assert_undercloud_read(cmd)
    for key, value in out["tls"].items():
        if not certs.TARGET.match(str(value)):
            raise ValueError(f"{check_id}: invalid TLS address {value!r}")
    for key, value in out["overcloud"].items():
        overcloud.parse(value)
    for key, value in out["collect"].items():
        if not logs.KEY_RE.match(key):
            raise ValueError(f"{check_id}: invalid collection key {key!r}")
        logs.parse(value)
    for key, path in out["redfish"].items():
        if not REST_PATH.match(str(path)) or not str(path).startswith("/redfish/v1") or ".." in str(path):
            raise ValueError(f"{check_id}: invalid Redfish path {path!r}")
    for source in ("ontap", "vcenter", "nsxt", "vcd"):
        for key, path in out[source].items():
            if not REST_PATH.match(str(path)):
                raise ValueError(f"{check_id}: invalid REST path {path!r}")
    for key, sets in out["vsphere"].items():
        if not sets or not all(vsphere_set_ok(x) for x in str(sets).split(",")):
            raise ValueError(f"{check_id}: invalid vCenter inventory sets {sets!r}")
    return out


def assert_openstack_read(command):
    """ValueError unless the command is an allowed read-only OpenStack command without shell syntax."""
    text = str(command or "")
    if not OPENSTACK_READ.match(text):
        raise ValueError(f"Refused: not a read-only OpenStack command: {text[:120]}")
    if shell_problem(text) and not text.startswith("date -u "):
        raise ValueError(f"Refused: {shell_problem(text)} in an OpenStack command: {text[:120]}")
    return text


def assert_undercloud_read(command):
    """ValueError unless the command is an allowed read of the undercloud (ironic) without shell syntax."""
    text = str(command or "")
    if not UNDERCLOUD_READ.match(text):
        raise ValueError(f"Refused: not a read-only undercloud command: {text[:120]}")
    if shell_problem(text) and not text.startswith("date -u ") and text not in (overcloud.INVENTORY_GREP, overcloud.PORTS_READ):
        raise ValueError(f"Refused: {shell_problem(text)} in an undercloud command: {text[:120]}")
    return text


def openstack_fix_command(command):
    """The command of an OpenStack fix without its trailing comment ("   # ..."); ValueError unless it is an allowed
    change (OPENSTACK_FIX) or an allowed read (to show the result), without shell syntax."""
    text = re.sub(r"\s{2,}#\s.*$", "", str(command or "")).strip()
    if shell_problem(text):
        raise ValueError(f"Refused: {shell_problem(text)} in an OpenStack fix: {text[:120]}")
    if not any(p.match(text) for p in OPENSTACK_FIX):
        assert_openstack_read(text)
    return text


# ---------------- live output of a long fix (an item of an OpenStack fix): the script runs in the background on the
# director, its output goes to a private temporary folder there, read every few seconds and shown on the run page; the
# last read gives its full output and exit code exactly as one raw run would (then the folder is removed).
LIVE_DIR = re.compile(r"^/tmp/wi-live\.[A-Za-z0-9]{8,16}$")


def live_start(script):
    """Shell for the director: start the script in the background (it survives the SSH session); prints its folder."""
    # compressed: the whole start line is one argument of ssh / bash -c (Linux: 128 KB at most), wi_ops.py included
    payload = base64.b64encode(gzip.compress(str(script).encode())).decode()
    return ("# wi-live start\n"
            "d=$(mktemp -d /tmp/wi-live.XXXXXXXX) || exit 97\n"
            f"printf %s '{payload}' | base64 -d | gunzip > \"$d/script\" || exit 97\n"
            # the exit code written whole (rc.tmp, then renamed): a reader never sees the file before the code is in it
            "nohup setsid bash -c 'bash \"$1/script\" > \"$1/out\" 2>&1 < /dev/null; echo $? > \"$1/rc.tmp\"; "
            "mv \"$1/rc.tmp\" \"$1/rc\"' _ \"$d\" > /dev/null 2>&1 < /dev/null &\n"
            f"echo \"{MARK}live $d\"")


def live_dir(stdout):
    m = re.search(rf"^{re.escape(MARK)}live (\S+)$", str(stdout or ""), re.M)
    return m.group(1) if m and LIVE_DIR.match(m.group(1)) else ""


def live_poll(folder, seen, wait=5):
    """Shell: wait, then the complete lines after the first `seen` ones, and the exit code once the script ended."""
    if not LIVE_DIR.match(str(folder)):
        raise ValueError("invalid live folder")
    return (f"# wi-live poll\nsleep {max(0, min(int(wait), 60))}\nd={folder}; n={max(0, int(seen))}\n"
            "t=$( (cat \"$d/out\" 2>/dev/null || true) | wc -l | tr -d ' ')\n"
            "[ \"$t\" -gt \"$n\" ] && sed -n \"$((n+1)),${t}p\" \"$d/out\"\n"
            f"echo \"{MARK}live-at $t $(cat \"$d/rc\" 2>/dev/null)\"")


def live_lines(stdout):
    """{"lines": new complete lines, "at": lines read so far, "rc": exit code or None while it runs} of a poll."""
    text = str(stdout or "")
    found = list(re.finditer(rf"^{re.escape(MARK)}live-at (\d+) ?(\d*)\s*$", text, re.M))
    m = found[-1] if found else None   # the poll prints its marker last; a line of the output can look like one
    if not m:
        return {"lines": [], "at": None, "rc": None}
    lines = [l for l in text[:m.start()].splitlines()]
    return {"lines": lines, "at": int(m.group(1)), "rc": int(m.group(2)) if m.group(2) else None}


def live_wait(folder, seconds):
    """Shell: wait until the script ended (no more live output: the run page shows it at the end), up to `seconds`."""
    if not LIVE_DIR.match(str(folder)):
        raise ValueError("invalid live folder")
    return (f"# wi-live wait\nd={folder}; end=$(( $(date +%s) + {max(60, int(seconds))} ))\n"
            "while [ ! -f \"$d/rc\" ] && [ \"$(date +%s)\" -lt \"$end\" ]; do sleep 10; done\n"
            f"echo \"{MARK}live-at 0 $(cat \"$d/rc\" 2>/dev/null)\"")


def live_interval(polls):
    """Seconds before poll number `polls` (0-based): often at first, less often for long items."""
    polls = int(polls)
    return 5 if polls < 12 else 15 if polls < 48 else 30 if polls < 84 else 60


LIVE_MAX_POLLS = 120   # include depth of tasks/live_poll.yml (Ansible stops near 200 nested includes): then live_wait


def live_end(folder):
    """Shell: the full output and the exit code of the script (as if it had run directly), then the folder removed."""
    if not LIVE_DIR.match(str(folder)):
        raise ValueError("invalid live folder")
    return (f"# wi-live end\nd={folder}\ncat \"$d/out\" 2>/dev/null\nrc=$(cat \"$d/rc\" 2>/dev/null)\n"
            "rm -rf \"$d\"\nexit ${rc:-98}")


def os_action_script(commands, overcloudrc="~/overcloudrc", until=0):
    """One script for an OpenStack fix on the director: source overcloudrc, then each command between markers (keys a1,
    a2, ... as action_result expects), stopping at the first that fails. until: the end of the time of the item (epoch
    seconds): wi_ops.py starts no change and waits no longer after it."""
    if not re.match(r"^[~A-Za-z0-9_./-]+$", str(overcloudrc)):
        raise ValueError("invalid overcloudrc path")
    parts = [f"source {overcloudrc} >/dev/null 2>&1 || {{ echo 'source {overcloudrc} failed'; exit 97; }}", OS_FUNCTIONS]
    if int(until or 0) > 0:
        parts.insert(0, f"export WI_ITEM_UNTIL={int(until)}")
    texts = [openstack_fix_command(cmd) for cmd in commands]
    if any(t.split(" ", 1)[0] in OPS for t in texts):
        parts.append(ops_preamble())
    for i, text in enumerate(texts, 1):
        text = re.sub(r"^(require|wait) ", r"wi_\1 ", text)
        if text.split(" ", 1)[0] in OPS:
            text = "wi_ops " + text
        parts.append(f"echo '{MARK}begin a{i}'; {text} 2>&1; rc=$?; echo \"{MARK}end a{i} $rc\"; [ \"$rc\" = 0 ] || exit \"$rc\"")
    return "\n".join(parts)


def ops_preamble():
    """Shell lines that write wi_ops.py (trusted code of the portal) to a temporary file on the director and define
    wi_ops(): the operations of an OpenStack fix that follow an item until it ends."""
    with open(OPS_FILE, encoding="utf-8") as f:
        source = f.read()
    if "\nWI_OPS_EOF" in source:
        raise ValueError("wi_ops.py must not contain the here-document terminator")
    return ("WI_OPS_FILE=$(mktemp /tmp/wi_ops.XXXXXX) || exit 98\n"
            "trap 'rm -f \"$WI_OPS_FILE\"' EXIT\n"
            f"cat > \"$WI_OPS_FILE\" <<'WI_OPS_EOF'\n{source.rstrip()}\nWI_OPS_EOF\n"
            "wi_ops() { python3 \"$WI_OPS_FILE\" \"$@\"; }")


def os_script(commands, overcloudrc="~/overcloudrc", undercloud=False):
    """One shell script for the director: source overcloudrc (undercloud: stackrc), then every (allowed) command between
    markers."""
    if not re.match(r"^[~A-Za-z0-9_./-]+$", str(overcloudrc)):
        raise ValueError("invalid overcloudrc path")
    parts = [f"source {overcloudrc} >/dev/null 2>&1 || {{ echo 'source {overcloudrc} failed'; exit 97; }}"]
    for key, cmd in commands.items():
        (assert_undercloud_read if undercloud else assert_openstack_read)(cmd)
        parts.append(f"echo '{MARK}begin {key}'; {cmd} 2>&1; echo \"{MARK}end {key} $?\"")
    return "\n".join(parts)


def oc_script(reads):
    """One script for the director: each overcloud read is one ssh to its node (overcloud.py), between markers."""
    return overcloud.oc_script(reads, MARK)


def host_script(commands, sudo=False):
    """One shell script for a host: every fixed command between markers; "SUDO " -> "sudo -n " when the group uses sudo."""
    parts = []
    for key, cmd in commands.items():
        cmd = str(cmd).replace("SUDO ", "sudo -n " if sudo else "")
        parts.append(f"echo '{MARK}begin {key}'; {{ {cmd} ; }} 2>&1; echo \"{MARK}end {key} $?\"")
    return "\n".join(parts)


JUMP_ADDRESS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}$")
JUMP_USER = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}$")


PROXY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}:\d{1,5}$")


def _via_proxy(proxy, escape=False):
    """ProxyCommand through an HTTP proxy (Squid of pfSense) with CONNECT: OpenBSD netcat. escape: inside the
    ProxyCommand of another ssh, whose own %h %p expansion must leave these to the inner ssh (%%h -> %h)."""
    if not PROXY_RE.match(str(proxy)):
        raise ValueError(f"Web proxy {proxy!r} is not host:port")
    pct = "%%" if escape else "%"
    return f"nc -X connect -x {proxy} {pct}h {pct}p"


def ssh_proxy_args(jump, keyfile=""):
    """ssh option that reaches a host through its jump host (Hosts & SSH): the jump host opens the TCP connection
    onwards (ssh -W, like ProxyJump) with its own account: a private key file, or a password through sshpass -e
    (SSHPASS in the environment). A jump host on a public address is itself reached through the web proxy
    (jump["proxy"]). The values were validated when the hosts were saved; checked again here."""
    address, user, port = str(jump.get("address") or ""), str(jump.get("user") or ""), int(jump.get("port") or 22)
    if not JUMP_ADDRESS.match(address) or not JUMP_USER.match(user) or not 0 < port < 65536:
        raise ValueError(f"Jump host {jump.get('name')!r} is not valid")
    common = f"-F /dev/null -p {port} -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 -o ServerAliveInterval=30"
    if jump.get("proxy"):
        common += " -o " + shlex.quote("ProxyCommand=" + _via_proxy(jump["proxy"], escape=True))
    if jump.get("auth") == "password":
        cmd = f"sshpass -e ssh {common} -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive"
    else:
        if not re.match(r"^/[A-Za-z0-9_./-]+$", str(keyfile)):
            raise ValueError("No key file for the jump host")
        cmd = f"ssh {common} -i {keyfile} -o IdentitiesOnly=yes -o BatchMode=yes"
    return "-o " + shlex.quote(f"ProxyCommand={cmd} -W %h:%p {user}@{address}")


def ssh_route_args(target, keyfile=""):
    """Extra ssh options for how the portal server reaches a host: through its jump host, through the web proxy (a
    public address while the portal server has no direct route to the internet), or directly ("")."""
    target = target or {}
    if target.get("jump"):
        return ssh_proxy_args(target["jump"], keyfile)
    if target.get("proxy"):
        return "-o " + shlex.quote("ProxyCommand=" + _via_proxy(target["proxy"]))
    return ""


SUDO_RE = re.compile(r"(?<![\w-])sudo\s+(-n\s+)?(?=\S)")


def action_script(commands, shell="sh", strip_sudo=False):
    """One script for a fix: every command between markers, stopping at the first that fails. Each command stays on
    its own lines, so here-documents keep their terminator. strip_sudo: the script already runs as root (sudo dropped).
    shell "vyos": a vbash script with the VyOS script template (configure / set / commit / save work non-interactively)."""
    parts = []
    for i, cmd in enumerate(commands, 1):
        text = str(cmd).rstrip()
        if strip_sudo:
            text = SUDO_RE.sub("", text)
        parts.append(f"echo '{MARK}begin a{i}'\n{{\n{text}\n}} 2>&1\nrc=$?\necho \"{MARK}end a{i} $rc\"\n"
                     f"[ \"$rc\" = 0 ] || exit \"$rc\"")
    script = "\n".join(parts)
    if shell == "vyos":
        return "/bin/vbash -c " + shlex.quote("source /opt/vyatta/etc/functions/script-template\n" + script)
    return script


def ssh_hint(message, target=None):
    """What an SSH failure means and what to do, from the ssh error text; "" when it is not recognised."""
    m, t = str(message or "").lower(), target or {}
    jump = t.get("jump") or {}
    port = t.get("port") or 22
    hop_port = (jump.get("port") or 22) if jump else port   # the first connection the portal server opens
    first = f"{jump.get('name')} ({jump.get('address')}:{hop_port}, the jump host)" if jump else \
        f"{t.get('address') or 'the host'}:{port}"
    proxy = (jump.get("proxy") if jump else t.get("proxy")) or ""
    if "proxy error" in m or ("nc:" in m and "connect" in m and "http/1" in m):
        code = re.search(r"http/1\.[01] (\d{3})", m)
        if code and code.group(1) == "403":
            return (f"The web proxy {proxy or ''} refused the SSH connection (HTTP 403): allow the SSH port in Squid on "
                    "pfSense (Services → Squid Proxy Server → ACLs → ACL SafePorts and ACL SSLPorts: add 22).").replace("  ", " ")
        return (f"The web proxy {proxy} could not open the connection to {first} "
                f"({'HTTP ' + code.group(1) if code else 'proxy error'}): check that the address answers on that port from pfSense.")
    if jump and ("open failed" in m or "administratively prohibited" in m):
        return (f"The jump host {jump.get('name')} answered but could not open the connection onwards to "
                f"{t.get('address')}:{port}: check from {jump.get('name')} that it reaches this address and port, and that "
                "its sshd allows forwarding (AllowTcpForwarding yes).")
    if any(x in m for x in ("timed out", "no route to host", "network is unreachable")):
        return (f"The portal server gets no answer from {first}: the network does not let it through. Allow TCP "
                f"{hop_port} from the portal server to that address in the firewall on the way and in the host's own "
                "firewall / security group. The bastion reaches public addresses only through routes to pfSense "
                "(172.26.0.242) for the allowed networks: add a route for this network on the bastion, or set WI_SSH_PROXY "
                "(the web proxy) when Squid allows SSH.")
    if "connection refused" in m:
        return f"{first} answered, but no SSH server listens on that port: check the SSH port of the host."
    if "permission denied" in m or "authentication failed" in m or "too many authentication failures" in m:
        user = (jump.get("user") if jump and "proxy" in m else t.get("user")) or "the account"
        return (f"The host refused the sign-in of {user}: check the username and that the public key of the credential "
                "(fingerprint on Hosts & SSH) is in ~/.ssh/authorized_keys of that user, or the password.")
    if "host key verification failed" in m or "remote host identification has changed" in m:
        return ("The host key differs from the one the portal saw before: confirm it is the right host, then remove its old "
                "line from /var/lib/ops-portal/.ssh/known_hosts on the portal server.")
    if "could not resolve hostname" in m or "name or service not known" in m:
        return "The name does not resolve on the portal server: use the IP address, or fix its DNS."
    if "sshpass" in m and ("not found" in m or "no such file" in m):
        return "Password sign-in needs the program sshpass on the portal server (apt install sshpass), or use a key."
    return ""


def action_result(out, commands, target=None):
    """raw result of a fix -> {"ok", "status", "summary", "steps": [{"command", "rc", "out"}], "error", "step"}."""
    out = out or {}
    if out.get("unreachable"):
        msg = str(out.get("msg") or "").strip()[:500]
        hint = ssh_hint(msg, target)
        return {"ok": False, "status": "failed", "summary": "", "steps": [], "step": "connect", "hint": hint,
                "error": f"The host cannot be reached: {msg}" + (f" — {hint}" if hint else "")}
    found = batch(out.get("stdout") or "", [f"a{i}" for i in range(1, len(commands) + 1)])
    steps = []
    for i, cmd in enumerate(commands, 1):
        item = found.get(f"a{i}") or {}
        if "rc" not in item:
            break
        steps.append({"command": str(cmd), "rc": item["rc"], "out": str(item.get("out") or "")[-4000:]})
    failed = next((s for s in steps if s["rc"] != 0), None)
    ok = not failed and len(steps) == len(commands)
    if ok:
        return {"ok": True, "status": "ok", "summary": f"{len(steps)} command(s) done", "steps": steps, "error": ""}
    if failed:
        first = next((l for l in failed["out"].splitlines() if l.strip()), "")
        error = f"Command {steps.index(failed) + 1} failed (exit {failed['rc']})" + (f": {first[:300]}" if first else "")
    else:
        error = ("The fix stopped before every command ran: "
                 + (str(out.get("stderr") or out.get("msg") or "").strip()[:300] or "no output"))
    return {"ok": False, "status": "failed", "summary": "", "steps": steps, "step": "fix", "error": error}


ITEM_STATUS = {0: "ok", 5: "failed", 3: "failed", 4: "failed",   # 3 / 4: require / wait found another state, nothing changed
               7: "skipped"}                                       # 7: not moved on purpose (no compute under the usage limit)


def item_result(out, item, index, stop_rcs=(6,)):
    """Raw result of one item of an OpenStack fix with selected items (playbooks/tasks/openstack_item.yml) ->
    {"index", "label", "status": ok|failed|skipped|attention, "rc", "summary", "steps", "stop", "progress"}. failed: not
    done, but healthy where it was (wi_ops exit 5, or a require / wait that found another state); skipped: left where it
    is on purpose (wi_ops exit 7: no destination under the usage limit), the next item always runs; attention: a person
    must look (exit 6, the connection, anything else). stop: the next item must not start (attention, or failed when the
    operator asked to stop at the first failure: 5 in stop_rcs)."""
    out = out or {}
    res = action_result(out, item.get("commands") or [])
    steps = res["steps"]
    rc = steps[-1]["rc"] if steps else -1
    result_line = ""
    for st in steps:
        for line in str(st.get("out") or "").splitlines():
            if line.startswith("RESULT "):
                result_line = line[7:].strip()
    if out.get("unreachable") or not steps:
        status = "attention"
    elif res["ok"]:
        status = "ok"
    else:
        status = ITEM_STATUS.get(rc, "attention")
    summary = (result_line.split(": ", 1)[-1] if result_line else res.get("summary") if res["ok"] else res.get("error")) or ""
    label = str(item.get("label") or f"item {index + 1}")
    stop = status == "attention" or (status == "failed" and 5 in [int(x) for x in stop_rcs or []])
    return {"index": int(index), "label": label, "status": status, "rc": rc, "summary": summary[:600], "steps": steps,
            "stop": stop, "progress": f"{MARK}item {int(index) + 1} {status} {label} :: {summary[:300]}"}


def items_result(results, items):
    """Result of an OpenStack fix with selected items: one step per item (its label, last exit code and its output). The
    fix is ok when every item ran and none failed; items skipped on purpose (usage limit) are counted apart."""
    results, items = list(results or []), list(items or [])
    done = [r for r in results if r["status"] == "ok"]
    skipped = [r for r in results if r["status"] == "skipped"]
    bad = [r for r in results if r["status"] not in ("ok", "skipped")]
    not_run = len(items) - len(results)
    steps = [{"command": f"{r['index'] + 1}. {r['label']}", "rc": r["rc"] if r["status"] != "ok" else 0,
              "out": "\n".join(str(s.get("out") or "") for s in r["steps"])[-6000:]} for r in results]
    summary = f"{len(done)} of {len(items)} done" + (f", {len(skipped)} skipped (no destination under the usage limit)"
                                                     if skipped else "") \
        + (f", {len(bad)} not done" if bad else "") + (f", {not_run} not started" if not_run else "")
    ok = items and not bad and not not_run and done
    first = bad[0] if bad else skipped[0] if skipped else None
    error = "" if ok else ((("No instance was moved. " if not bad and skipped and not done else "")
                            + f"{first['index'] + 1}. {first['label']}: {first['summary']}" if first else "Nothing ran")
                           + (f" ({summary})" if len(items) > 1 else "")
                           + ("; the run stopped there" if not_run else ""))
    return {"ok": bool(ok), "status": "ok" if ok else "failed", "summary": summary, "steps": steps, "error": error[:1000],
            "items": [{"label": r["label"], "status": r["status"], "summary": r["summary"]} for r in results]}


def batch(stdout, keys):
    """Split the output of os_script / host_script: {key: {"rc", "out"}}; a key without output is skipped."""
    found, current, buf, ended, end_line = {}, None, [], None, ""
    for line in str(stdout or "").splitlines():
        if line.startswith(f"{MARK}begin "):
            current, buf, ended = line[len(MARK) + 6:].strip(), [], None
            continue
        m = re.match(rf"^{re.escape(MARK)}end (\S+) (\d+)$", line)
        if m and m.group(1) in (current, ended):   # the last end of a command wins: an output line can look like one
            found[m.group(1)] = {"rc": int(m.group(2)), "out": "\n".join(buf)}
            current, ended, end_line = None, m.group(1), line
            continue
        if current is None and ended is not None:   # more output of the same command: that "end" was a line of it
            current = ended
            buf.append(end_line)
        if current is not None:
            buf.append(line)
    for key in keys:
        found.setdefault(key, {"skipped": "no output (the connection or the script stopped before this command)"})
    return found


# ---------------- pages of the REST lists: a list that is longer than one answer (ONTAP _links.next, NSX cursor, vCloud
# Director page / pageCount, query service total) is read to its end, page after page, between the phases of a check
# (playbooks/tasks/read_pages.yml), and its pages are merged into the first answer: a check rates every item without
# knowing pages exist. "The latest N" (sorted: order_by, sortDesc / sortAsc) is never followed.
PAGE_SOURCES = ("ontap", "nsxt", "vcd")
PAGE_ROUNDS = 8       # ONTAP / NSX: pages one after the other (each answer gives the next), after the first
VCD_MAX_PAGES = 40    # vCloud Director: the pages its first answer announces, read together
TOP_N = re.compile(r"[?&](order_by|sortDesc|sortAsc)=")
PAGE_KEY = re.compile(r"^(.+):p(\d+)$")


def _with_param(path, name, value):
    base, _, query = str(path).partition("?")
    parts = [p for p in query.split("&") if p and p.split("=", 1)[0] != name]
    return base + "?" + "&".join(parts + [f"{name}={value}"])


def _safe_query(path):
    """A path with its query values percent-encoded where REST_PATH would refuse them ("/" in a start name)."""
    base, _, query = str(path).partition("?")
    parts = []
    for p in query.split("&"):
        k, eq, v = p.partition("=")
        parts.append(k + eq + urllib.parse.quote(urllib.parse.unquote(v), safe=",.:-_|*") if eq else p)
    return base + ("?" + "&".join(parts) if query else "")


def list_field(doc):
    """(field, items) of a REST list answer: ONTAP records, NSX results, CloudAPI values, query service record."""
    for field in ("records", "results", "values", "record"):
        if isinstance(doc, dict) and isinstance(doc.get(field), list):
            return field, doc[field]
    return None, None


def _vcd_pages(doc):
    """(page, page count) of a vCloud answer, or (None, None)."""
    page, count = doc.get("page"), doc.get("pageCount")
    if count is None and isinstance(doc.get("total"), int) and doc.get("pageSize"):   # the query service
        count = -(-doc["total"] // max(1, int(doc["pageSize"])))
    return (page, count) if isinstance(page, int) and isinstance(count, int) else (None, None)


def next_page_path(source, path, doc):
    """The path of the page after this answer of `path` ("" when it was the last one, or the list must not be followed)."""
    if not isinstance(doc, dict) or TOP_N.search(str(path)) or list_field(doc)[0] is None:
        return ""
    if source == "ontap":
        href = str(((doc.get("_links") or {}).get("next") or {}).get("href") or "")
        href = _safe_query(href) if href.startswith("/api/") and ".." not in href else ""
        return href if href and REST_PATH.match(href) else ""
    if source == "nsxt" and doc.get("cursor"):
        nxt = _with_param(path, "cursor", urllib.parse.quote(str(doc["cursor"]), safe=""))
        return nxt if REST_PATH.match(nxt) else ""
    if source == "vcd":
        page, count = _vcd_pages(doc)
        if page is not None and page < count:
            return _with_param(path, "page", page + 1)
    return ""


def next_pages(data, reads):
    """{source: {"<key>:p<n>": path}}: the next pages to read of the lists of this phase (vCloud: every announced page at
    once; ONTAP / NSX: the next one)."""
    out = {s: {} for s in PAGE_SOURCES}
    for source in PAGE_SOURCES:
        for key, path in ((reads or {}).get(source) or {}).items():
            item = (data or {}).get(key)
            if not isinstance(item, dict) or item.get("status") not in (200, "200") or not isinstance(item.get("json"), dict):
                continue
            if "pages" not in item:   # only the first answer so far
                if source == "vcd":
                    page, count = _vcd_pages(item["json"])
                    if page is not None and not TOP_N.search(str(path)) and list_field(item["json"])[0]:
                        for n in range(page + 1, min(count, VCD_MAX_PAGES) + 1):
                            out[source][f"{key}:p{n}"] = _with_param(path, "page", n)
                    continue
                nxt = next_page_path(source, path, item["json"])
                if nxt:
                    out[source][f"{key}:p2"] = nxt
            elif source != "vcd" and item.get("next") and int(item["pages"]) <= PAGE_ROUNDS:
                out[source][f"{key}:p{int(item['pages']) + 1}"] = item["next"]
    return out


def merge_pages(data, reads):
    """The pages read so far merged into their list (and removed): the list item gets "pages" (read), "next" (the page
    still to read, "" when complete) and "more" (pages that will not be read)."""
    out = dict(data or {})
    for source in PAGE_SOURCES:
        for key, path in ((reads or {}).get(source) or {}).items():
            base = out.get(key)
            if not isinstance(base, dict) or base.get("status") not in (200, "200") or not isinstance(base.get("json"), dict):
                continue
            field, first = list_field(base["json"])
            if field is None:
                continue
            pages = sorted((int(m.group(2)), k) for k in list(out) for m in [PAGE_KEY.match(k)] if m and m.group(1) == key)
            if "pages" not in base:
                base = dict(base, json=dict(base["json"]), pages=1, next="" if source == "vcd" else next_page_path(source, path, base["json"]))
                if source == "vcd":
                    page, count = _vcd_pages(base["json"])
                    if page is not None and not TOP_N.search(str(path)) and count > VCD_MAX_PAGES:
                        base["more"] = f"{VCD_MAX_PAGES} of {count} pages"
            items, last = list(base["json"][field]), None
            for n, k in pages:
                page = out.pop(k)
                f2, more = list_field(page.get("json")) if page.get("status") in (200, "200") else (None, None)
                if f2 is None:   # a page that failed: the rest of the list is not read
                    base["next"], base["more"] = "", base.get("more") or f"page {n} not read ({unavailable(page) or 'no list'})"
                    break
                items += more
                base["pages"], last = max(int(base["pages"]), n), page.get("json")
            if pages:
                base["json"][field] = items
                if source != "vcd" and last is not None and not base.get("more"):
                    base["next"] = next_page_path(source, path, last)
            out[key] = base
    return out


def analyze(check_id, data, params, ctx):
    try:
        result = check(check_id).analyze(data or {}, params or {}, ctx or {})
    except Exception as e:   # a bug in an analysis must still give a readable result with the collected data
        return {"ok": False, "check": check_id, "status": "error", "error": f"Analysis of the collected data failed: {e!r}",
                "steps": [], "recommendations": []}
    cut = [f"{k} ({v.get('pages')} page(s) read; " + (v.get("more") or "more pages were not read") + ")"
           for k, v in (data or {}).items() if isinstance(v, dict) and (v.get("more") or v.get("next"))]
    if cut and isinstance(result.get("steps"), list):   # never silent: a list read only in part may hide a finding
        result["steps"].append({"key": "pages", "title": "Lists read only in part", "status": "info",
                                "detail": "These lists are longer than the portal reads in one run: " + "; ".join(cut[:10])
                                          + ". Items on the pages not read were not checked."})
    try:   # "Where to look": never in the way of the result itself
        result["screens"] = screens.build(check_id, data or {}, params or {}, ctx or {}, result,
                                          commands_run(check_id, data or {}, params or {}, ctx or {}))
    except Exception as e:
        result["screens"], result["screens_error"] = [], f"{e!r}"[:300]
    return result


def export_files(check_id, data, params):
    """{file name: text} a check adds to the raw output of a run (every entry of an event log as CSV), made from the reads."""
    fn = getattr(check(check_id), "export", None)
    return fn(data or {}, params or {}) if fn else {}


def commands_run(check_id, data, params, ctx):
    """{source: {key: command}} of the commands, probes and paths a run read (the phases replayed on its data)."""
    out = {}
    for phase in range(1, plan(check_id)["phases"] + 1):
        try:
            wanted = reads(check_id, phase, data, params, ctx)
        except (ValueError, KeyError, TypeError):
            continue
        for src, items in wanted.items():
            for key, cmd in items.items():
                if key in data:
                    out.setdefault(src, {}).setdefault(key, cmd)
    return out


def quote(value):
    return shlex.quote(str(value))

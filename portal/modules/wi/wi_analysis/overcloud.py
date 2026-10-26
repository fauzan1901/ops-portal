"""Read-only access to the overcloud nodes (controllers, computes) of RHOSP 16.2 / 17.1, from the director as TripleO
does it: ssh to the ctlplane address of the node as heat-admin (16.2) or tripleo-admin (17.1), sudo without a password.

The node list comes from the undercloud (stackrc): `openstack server list` on 16.2 (nova on the undercloud),
`metalsmith -f json list` on 17.1; the release from /etc/rhosp-release. A check only names fixed commands of
COMMANDS (with validated arguments: hours, a UUID or a request ID); no text from the browser reaches a shell.

Source "overcloud" in wi_analysis: {key: "<node>|<ctlplane IP>|<user>|<command>[:<args>]"}; oc_script() turns it into one
script for the director (one ssh per command, BatchMode, the director's own key; known_hosts of the director is not
written, like TripleO's own ansible).
"""
import ipaddress
import re
import shlex

NODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
USERS = ("heat-admin", "tripleo-admin")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
REQ_RE = re.compile(r"^req-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
SSH = "ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
MAX_LINES = 400

# Log files of each component on a node (containers of RHOSP 16.2 / 17.1); a file that does not exist is skipped.
LOG_FILES = {
    "nova": ["/var/log/containers/nova/nova-api.log", "/var/log/containers/nova/nova-conductor.log",
             "/var/log/containers/nova/nova-scheduler.log", "/var/log/containers/nova/nova-compute.log"],
    "neutron": ["/var/log/containers/neutron/server.log", "/var/log/containers/neutron/ovn-metadata-agent.log",
                "/var/log/containers/openvswitch/ovn-controller.log", "/var/log/containers/neutron/openvswitch-agent.log",
                "/var/log/containers/neutron/l3-agent.log", "/var/log/containers/neutron/dhcp-agent.log"],
    "cinder": ["/var/log/containers/cinder/cinder-api.log", "/var/log/containers/cinder/cinder-scheduler.log",
               "/var/log/containers/cinder/cinder-volume.log"],
    "keystone": ["/var/log/containers/keystone/keystone.log"],
    "glance": ["/var/log/containers/glance/api.log"],
}
COMPONENTS = ("nova", "neutron", "cinder", "keystone", "glance", "rabbitmq", "galera", "haproxy", "pacemaker", "kernel")
CONTROLLER_ONLY = {"keystone", "glance", "rabbitmq", "galera", "haproxy", "pacemaker"}


def _since(hours):
    """Shell expression: the local time <hours> ago as the logs write it ('YYYY-MM-DD HH:MM:SS')."""
    return f"$(date -d '-{int(hours)} hours' '+%Y-%m-%d %H:%M:%S')"


def _grep(args):
    """Extra filter: a UUID or request ID (validated), as fixed strings."""
    ids = [a for a in args if UUID_RE.match(a) or REQ_RE.match(a)]
    return (" | grep -F " + " ".join(f"-e {i}" for i in ids)) if ids else ""


def log_command(component, hours, ids=()):
    """The read of one component's log on a node: the lines of the last <hours> at warning level or above (or every line
    naming one of ids), at most MAX_LINES. Each line keeps its file name ("<file>:<line>")."""
    h = int(hours)
    if not 1 <= h <= 72:
        raise ValueError("hours must be 1-72")
    ids = [i for i in ids if UUID_RE.match(i) or REQ_RE.match(i)]
    level = "" if ids else " | grep -E ' (ERROR|CRITICAL|WARNING) '"
    if component in LOG_FILES:
        files = " ".join(LOG_FILES[component])
        return (f"for f in {files}; do [ -r \"$f\" ] || sudo -n test -r \"$f\" || continue; "
                f"sudo -n awk -v s=\"{_since(h)}\" 'substr($0,1,19) >= s {{print FILENAME\": \"$0}}' \"$f\"; done"
                f"{level}{_grep(ids)} | tail -n {MAX_LINES}")
    if component == "rabbitmq":   # rabbit@<host>.log: "2026-10-11 08:00:00.123 [error] <0.1.0> ..."
        return (f"for f in /var/log/containers/rabbitmq/rabbit@*.log; do [ -e \"$f\" ] || continue; "
                f"sudo -n awk -v s=\"{_since(h)}\" 'substr($0,1,19) >= s {{print FILENAME\": \"$0}}' \"$f\"; done"
                f" | grep -Ei '\\[(error|warning|critical)\\]|partition|alarm'{_grep(ids)} | tail -n {MAX_LINES}")
    if component == "galera":     # mysqld.log has its own time format: the last lines with [ERROR] / [Warning] / WSREP problems
        return (f"sudo -n tail -n 20000 /var/log/containers/mysql/mysqld.log 2>/dev/null | grep -E '\\[(ERROR|Warning)\\]|WSREP.*(fail|error|non-primary)'"
                f" | tail -n {MAX_LINES}")
    if component == "haproxy":    # backends going DOWN / no server available
        return (f"sudo -n tail -n 50000 /var/log/containers/haproxy/haproxy.log 2>/dev/null"
                f" | grep -E 'is DOWN|is UP|has no server available|NOSRV' | tail -n {MAX_LINES}")
    if component == "pacemaker":
        return (f"sudo -n journalctl -u pacemaker -u corosync -u pcsd --since '-{h}h' -p warning -o short-iso --no-pager"
                f" | tail -n {MAX_LINES}")
    if component == "kernel":
        return f"sudo -n journalctl -k --since '-{h}h' -p warning -o short-iso --no-pager | tail -n {MAX_LINES}"
    raise ValueError(f"unknown log component {component!r}")


# Fixed commands on a node. Arguments come after ":" and are validated by command().
COMMANDS = {
    "reach": lambda a: "hostname -s",
    "pcs_status": lambda a: "sudo -n pcs status --full",
    "pcs_history": lambda a: "sudo -n pcs stonith history",
    "pcs_property": lambda a: "sudo -n pcs property",
    "quorum": lambda a: "sudo -n corosync-quorumtool -s",
    "rabbit": lambda a: ("sudo -n podman exec $(sudo -n podman ps -q --filter name=rabbitmq-bundle | head -n 1) "
                         "rabbitmqctl cluster_status"),
    "chrony": lambda a: "chronyc tracking",
    "log": lambda a: log_command(a[0], a[1] if len(a) > 1 else 6, a[2:]),
    # resources of the node (check Overcloud node health)
    "df": lambda a: "df -Pk -x tmpfs -x devtmpfs -x squashfs -x overlay -x iso9660 2>/dev/null",
    "dfi": lambda a: "df -Pi -x tmpfs -x devtmpfs -x squashfs -x overlay -x iso9660 2>/dev/null",
    "mem": lambda a: "free -k",
    "load": lambda a: "nproc; cat /proc/loadavg",
    "cpu": lambda a: "head -n 1 /proc/stat; sleep 2; head -n 1 /proc/stat",
    "failed": lambda a: "systemctl --failed --no-legend --plain 2>/dev/null; true",
    "topmem": lambda a: "ps -eo pid,user,pmem,pcpu,rss,comm --sort=-rss | head -n 9",
    "topcpu": lambda a: "ps -eo pid,user,pcpu,pmem,comm --sort=-pcpu | head -n 9",
    "containers": lambda a: "sudo -n podman ps -a --format '{{.Names}}|{{.Status}}'",
    # before a log collection / sos report (wi_collect.py writes its temporary files in /var/tmp)
    "tmpfree": lambda a: "df -Pk /var/tmp | tail -n 1",
    "sosver": lambda a: "rpm -q sos 2>/dev/null || echo 'sos is not installed'",
    # real CPU (over 2 seconds) and memory use of a compute (Live migrate: destinations under a usage limit); the same
    # command as wi_ops.USAGE_COMMAND, read just before each migration
    "usage": lambda a: USAGE_COMMAND,
    # OVN Southbound DB, read through the ovn_controller container of a compute (as the WI "FDB Learning Issue"):
    # --no-leader-only reads from any member of the cluster; JSON for the analysis
    "ovn_dp": lambda a: f"{OVN_SB} --format=json --columns=_uuid,tunnel_key,external_ids find datapath_binding external_ids:name=neutron-{a[0]}",
    "ovn_pb": lambda a: (f"{OVN_SB} --format=json --columns=_uuid,logical_port,mac,port_security,tunnel_key,type,chassis,up "
                         f"find port_binding datapath={a[0]}"),
    "ovn_fdb": lambda a: f"{OVN_SB} --format=json --columns=_uuid,mac,dp_key,port_key find fdb dp_key={a[0]}",
    # every FDB entry per datapath, and the ports that accept any MAC ("unknown": port security disabled)
    "ovn_fdb_count": lambda a: f"{OVN_SB} --bare --columns=dp_key list fdb | grep . | sort | uniq -c | sort -rn | head -n 50",
    "ovn_unknown": lambda a: (f"{OVN_SB} --bare --columns=logical_port,mac,type list port_binding"
                              " | awk 'BEGIN{RS=\"\";FS=\"\\n\"} $2 ~ /(^| )unknown( |$)/ {print $1\"|\"$3}' | head -n 1000"),
    "ovn_version": lambda a: "sudo -n podman exec ovn_controller ovn-controller --version 2>&1 | head -n 2",
    # whether this node can read the OVN Southbound DB (the FDB check tries several nodes, uses the first that answers)
    "ovn_sb": lambda a: f"{OVN_SB} --bare --columns=_uuid list SB_Global",
    # OVN NB / SB databases of the controllers (check OVN database cluster): the model from the file itself (CLUSTER =
    # RAFT, RHOSP 17.x; JSON = active / backup in the Pacemaker bundle ovn-dbs-bundle, 16.2), the RAFT state of each
    # member, northd, the replication of 16.2, the size of the DBs and of MAC_Binding
    # the header of the NB database file: "OVSDB CLUSTER ..." (RAFT, 17.x) or "OVSDB JSON ..." (standalone, 16.2)
    "ovn_model": lambda a: "sudo -n head -c 13 /var/lib/openvswitch/ovn/ovnnb_db.db 2>/dev/null; echo",
    "ovn_nb_raft": lambda a: ("sudo -n podman exec ovn_cluster_north_db_server ovs-appctl -t /var/run/ovn/ovnnb_db.ctl "
                              "cluster/status OVN_Northbound"),
    "ovn_sb_raft": lambda a: ("sudo -n podman exec ovn_cluster_south_db_server ovs-appctl -t /var/run/ovn/ovnsb_db.ctl "
                              "cluster/status OVN_Southbound"),
    "ovn_northd": lambda a: ("c=$(sudo -n podman ps --format '{{.Names}}' | grep -E '^ovn_cluster_northd$|^ovn-dbs-bundle' | head -n 1); "
                             "[ -n \"$c\" ] && sudo -n podman exec \"$c\" ovn-appctl -t ovn-northd status"),
    "ovn_sync": lambda a: ("c=$(sudo -n podman ps -q --filter name=ovn-dbs-bundle | head -n 1); [ -n \"$c\" ] || exit 3; "
                           "for d in nb sb; do for s in /var/run/ovn/ovn${d}_db.ctl /var/run/openvswitch/ovn${d}_db.ctl; do "
                           "if sudo -n podman exec \"$c\" test -S \"$s\"; then echo \"== $d\"; "
                           "sudo -n podman exec \"$c\" ovs-appctl -t \"$s\" ovsdb-server/sync-status; break; fi; done; done"),
    "ovn_dbsize": lambda a: "sudo -n ls -l /var/lib/openvswitch/ovn/ 2>/dev/null | grep -E 'ovn(nb|sb)_db.db$'",
    "ovn_macb": lambda a: f"{OVN_SB} --bare --columns=_uuid list MAC_Binding | grep -c .",
    # RabbitMQ (check RabbitMQ queues): the queues of the cluster with their messages and consumers, and the file
    # descriptors / sockets of the node
    "rabbit_queues": lambda a: ("sudo -n podman exec $(sudo -n podman ps -q --filter name=rabbitmq-bundle | head -n 1) "
                                "rabbitmqctl -q list_queues name messages consumers"),
    "rabbit_status": lambda a: ("sudo -n podman exec $(sudo -n podman ps -q --filter name=rabbitmq-bundle | head -n 1) "
                                "rabbitmqctl -q status"),
    # Galera (check Galera replication): wsrep state and connections of the node, with the root option file of the
    # galera container (no password passes through the portal)
    "galera_status": lambda a: ("sudo -n podman exec $(sudo -n podman ps -q --filter name=galera-bundle | head -n 1) mysql -B -N -e "
                                "\"SHOW GLOBAL STATUS WHERE Variable_name IN ('wsrep_cluster_size','wsrep_cluster_status',"
                                "'wsrep_local_state_comment','wsrep_ready','wsrep_flow_control_paused','wsrep_local_recv_queue_avg',"
                                "'Threads_connected','Max_used_connections'); SHOW GLOBAL VARIABLES LIKE 'max_connections';\""),
    # certmonger (check certmonger certificates): every certificate it tracks (TLS everywhere), only the lines the check
    # rates (a controller tracks dozens: the full output is thousands of lines)
    "getcert": lambda a: (f"command -v getcert >/dev/null || {{ echo '{NO_CERTMONGER}'; exit 0; }}; sudo -n getcert list | grep -E "
                          "'^(Number of|Request ID)|^[[:space:]]+(status|stuck|ca-error|CA|subject|expires|certificate|auto-renew):'"),
    # frames the instance sends with a MAC that is not its own (what fills the FDB), a few seconds on its tap device
    "ovn_capture": lambda a: (f"command -v tcpdump >/dev/null || {{ echo 'tcpdump is not installed on this compute'; exit 0; }}; "
                              f"sudo -n timeout {int(a[1])} tcpdump -nnei {a[0]} -c 200 -Q in 'not ether src {mac_text(a[2])}' 2>&1; true"),
}
OVN_SB = "sudo -n podman exec ovn_controller ovn-sbctl --no-leader-only"
NO_CERTMONGER = "certmonger is not installed on this node"
TAP_RE = re.compile(r"^tap[0-9a-f]{8}-[0-9a-f]{2}$")
MAC_ARG = re.compile(r"^[0-9a-f]{12}$")   # a MAC without its colons (":" separates the arguments of a read)


def mac_text(value):
    """fa163e0bcc31 -> fa:16:3e:0b:cc:31"""
    value = str(value).lower()
    if not MAC_ARG.match(value):
        raise ValueError("invalid MAC")
    return ":".join(value[i:i + 2] for i in range(0, 12, 2))


def mac_arg(mac):
    """fa:16:3e:0b:cc:31 -> fa163e0bcc31 (the form of a read argument)"""
    value = str(mac or "").lower().replace(":", "")
    if not MAC_ARG.match(value):
        raise ValueError("invalid MAC")
    return value


# the arguments of the reads that take some, each validated: a UUID, a number, a tap device, a MAC
ARGS = {"ovn_dp": ("uuid",), "ovn_pb": ("uuid",), "ovn_fdb": ("int",), "ovn_capture": ("tap", "seconds", "mac")}
USAGE_COMMAND = "head -n 1 /proc/stat; grep -E '^(MemTotal|MemAvailable):' /proc/meminfo; sleep 2; head -n 1 /proc/stat"
PARALLEL = ("use_",)   # reads whose keys start so run on all their nodes at once (each node once, short reads)
READ_RE = re.compile(r"^(?P<node>[A-Za-z0-9][A-Za-z0-9_.-]{0,62})\|(?P<ip>[0-9.]{7,15})\|(?P<user>[a-z-]{5,20})\|"
                     r"(?P<cmd>[a-z_]{2,20})(?::(?P<args>[A-Za-z0-9_.:-]{0,200}))?$")


def read(node, ip, user, cmd, *args):
    """The value of one overcloud read (validated when the check plans it)."""
    value = f"{node}|{ip}|{user}|{cmd}" + (":" + ":".join(str(a) for a in args) if args else "")
    parse(value)
    return value


def parse(value):
    """(node, ip, user, shell command) of one read; ValueError unless every part is valid."""
    m = READ_RE.match(str(value or ""))
    if not m:
        raise ValueError(f"invalid overcloud read {str(value)[:120]!r}")
    node, ip, user, cmd = m.group("node"), m.group("ip"), m.group("user"), m.group("cmd")
    try:
        if not ipaddress.IPv4Address(ip).is_private:
            raise ValueError
    except ValueError:
        raise ValueError(f"{node}: {ip} is not a private ctlplane address")
    if user not in USERS:
        raise ValueError(f"invalid overcloud user {user!r}")
    if cmd not in COMMANDS:
        raise ValueError(f"unknown overcloud command {cmd!r}")
    args = [a for a in (m.group("args") or "").split(":") if a] if m.group("args") is not None else []
    if cmd == "log":
        if not args or args[0] not in COMPONENTS or (len(args) > 1 and not args[1].isdigit()):
            raise ValueError(f"invalid log read {value!r}")
        if any(not (UUID_RE.match(a) or REQ_RE.match(a)) for a in args[2:]):
            raise ValueError(f"invalid log filter in {value!r}")
    elif cmd in ARGS:
        kinds = ARGS[cmd]
        ok = len(args) == len(kinds) and all(
            UUID_RE.match(v) if k == "uuid" else v.isdigit() and int(v) < 10 ** 9 if k == "int" else TAP_RE.match(v) if k == "tap"
            else v.isdigit() and 1 <= int(v) <= 30 if k == "seconds" else MAC_ARG.match(v) if k == "mac" else False
            for k, v in zip(kinds, args))
        if not ok:
            raise ValueError(f"invalid arguments of {cmd}: {value!r}")
    elif args:
        raise ValueError(f"{cmd} takes no argument")
    return node, ip, user, COMMANDS[cmd](args)


def oc_script(reads, mark="@@WI@@"):
    """One script for the director: each read is one ssh to its node, between markers. Reads of PARALLEL keys run on
    all their nodes at once (output in temporary files of the director, printed in order, then removed)."""
    parts, together = [], [(k, v) for k, v in reads.items() if k.startswith(PARALLEL)]
    if together:
        parts.append("WI_OC_TMP=$(mktemp -d /tmp/wi_oc.XXXXXX) || exit 98")
        for key, value in together:
            node, ip, user, command = parse(value)
            parts.append(f"( {SSH} {user}@{ip} {shlex.quote(command)} > \"$WI_OC_TMP/{key}\" 2>&1; "
                         f"echo $? > \"$WI_OC_TMP/{key}.rc\" ) &")
        parts.append("wait")
        for key, _value in together:
            parts.append(f"echo '{mark}begin {key}'; cat \"$WI_OC_TMP/{key}\"; echo \"{mark}end {key} $(cat \"$WI_OC_TMP/{key}.rc\")\"")
        parts.append('rm -rf "$WI_OC_TMP"')
    for key, value in reads.items():
        if key.startswith(PARALLEL):
            continue
        node, ip, user, command = parse(value)
        parts.append(f"echo '{mark}begin {key}'; {SSH} {user}@{ip} {shlex.quote(command)} 2>&1; echo \"{mark}end {key} $?\"")
    return "\n".join(parts)


def parse_usage(text):
    """The output of the usage read -> {"cpu": % busy over the 2 seconds, "ram": % in use, "total_kb"}, or None (the
    same arithmetic as wi_ops.parse_usage, which decides at migration time)."""
    cpu = [list(map(int, l.split()[1:])) for l in str(text or "").splitlines() if re.match(r"^cpu\s+\d", l)]
    mem = dict(re.findall(r"^(MemTotal|MemAvailable):\s+(\d+)", str(text or ""), re.M))
    if len(cpu) < 2 or "MemTotal" not in mem or "MemAvailable" not in mem or int(mem["MemTotal"]) <= 0:
        return None
    a, b = cpu[0], cpu[-1]
    idle = lambda v: v[3] + (v[4] if len(v) > 4 else 0)   # noqa: E731  idle + iowait
    total = sum(b) - sum(a)
    busy = total - (idle(b) - idle(a))
    total_kb, avail_kb = int(mem["MemTotal"]), int(mem["MemAvailable"])
    return {"cpu": round(100.0 * busy / total, 1) if total > 0 else 0.0,
            "ram": round(100.0 * (total_kb - avail_kb) / total_kb, 1), "used_kb": total_kb - avail_kb, "total_kb": total_kb}


# ---------------------------------------------------------------- the node list from the undercloud
def _ctlplane(value):
    """The ctlplane address in a networks value: "ctlplane=192.168.253.15", {"ctlplane": ["..."]} or [{"ip_address": ...}]."""
    if isinstance(value, dict):
        v = value.get("ctlplane")
        return str(v[0] if isinstance(v, list) and v else v or "")
    m = re.search(r"ctlplane=([0-9.]+)", str(value or ""))
    return m.group(1) if m else ""


def parse_inventory(text):
    """{host: {"ip", "groups", "user"}} from the grep of the TripleO Ansible inventory (YAML, 2-space indent)."""
    hosts, group, host, group_user = {}, "", "", {}
    for line in str(text or "").splitlines():
        m = re.match(r"^([A-Za-z0-9_]+):$", line)
        if m:
            group, host = m.group(1), ""
            continue
        if line == "  hosts:":
            continue
        m = re.match(r"^    ([A-Za-z0-9_.-]+):$", line)
        if m:
            host = m.group(1)
            hosts.setdefault(host, {"ip": "", "groups": set(), "user": ""})["groups"].add(group)
            continue
        m = re.match(r"^      (ansible_host|ctlplane_ip): +['\"]?([0-9.]+)['\"]?\s*$", line)
        if m and host:
            if m.group(1) == "ctlplane_ip" or not hosts[host]["ip"]:
                hosts[host]["ip"] = m.group(2)
            continue
        m = re.match(r"^ +ansible_ssh_user: +['\"]?([a-z-]+)['\"]?\s*$", line)
        if m:
            if host and line.startswith("      "):
                hosts[host]["user"] = m.group(1)
            elif group:
                group_user[group] = m.group(1)
    for h in hosts.values():
        h["user"] = h["user"] or next((group_user[g] for g in h["groups"] if g in group_user), "")
    return hosts


def nodes(data, json_of, source, unavailable):
    """[{"name", "ip", "role", "user"}] of the overcloud, from the first source that lists them (INVENTORY_READS), and
    {source: why it gave nothing} for the others."""
    tried = {}

    def from_servers():
        item = source(data, "uc_servers")
        if unavailable(item):
            tried["openstack server list"] = unavailable(item)
            return {}
        out = {str(s["Name"]): {"ip": _ctlplane(s.get("Networks") or s.get("networks"))}
               for s in json_of(item) or [] if isinstance(s, dict) and s.get("Name")}
        if not out:
            tried["openstack server list"] = "no server on the undercloud"
        return out

    def from_metalsmith():
        item = source(data, "uc_metalsmith")
        if unavailable(item):
            tried["metalsmith list"] = unavailable(item)
            return {}
        value = json_of(item)
        rows = value.items() if isinstance(value, dict) else [(x.get("hostname") or x.get("Hostname"), x) for x in value or [] if isinstance(x, dict)]
        out = {}
        for name, x in rows:
            x = x if isinstance(x, dict) else {}
            name = x.get("hostname") or name
            ip = _ctlplane(x.get("ip_addresses") or x.get("IP Addresses") or {})
            if name:
                out[str(name)] = {"ip": ip}
        if not out:
            tried["metalsmith list"] = "no instance"
        return out

    def from_inventory():
        text = str(source(data, "uc_inventory").get("out") or "")   # grep exits 2 when one of the files is missing
        hosts = parse_inventory(text)
        out = {}
        for name, h in hosts.items():
            groups = " ".join(h["groups"]).lower()
            if name in ("undercloud", "localhost") or "undercloud" in groups or not h["ip"]:
                continue
            role = "controller" if "controller" in groups else "compute" if "compute" in groups else ""
            out[name] = {"ip": h["ip"], "role": role, "user": h["user"]}
        if not out:
            tried["TripleO inventory"] = "no inventory file with overcloud hosts (~/overcloud-deploy/*/, ~/config-download/*/)"
        return out

    def from_ports():
        item = source(data, "uc_ports")
        if unavailable(item):
            tried["ctlplane ports"] = unavailable(item)
            return {}
        out = {}
        for p in json_of(item) or []:
            if not isinstance(p, dict):
                continue
            name = str(p.get("Name") or "")
            ips = p.get("Fixed IP Addresses") or []
            ip = ips[0].get("ip_address") if isinstance(ips, list) and ips and isinstance(ips[0], dict) else ""
            m = re.search(r"ip_address='([0-9.]+)'", str(ips)) if not ip else None
            ip = ip or (m.group(1) if m else "")
            if name.endswith("-ctlplane") and ip:
                out[name[:-len("-ctlplane")]] = {"ip": ip}
        if not out:
            tried["ctlplane ports"] = "no port named <host>-ctlplane"
        return out

    found = {}
    for reader in (from_servers, from_metalsmith, from_inventory, from_ports):
        found = reader()
        if any(v.get("ip") for v in found.values()):
            break
    result = []
    for name, x in sorted(found.items()):
        ip = x.get("ip") or ""
        try:
            if not ipaddress.IPv4Address(ip).is_private or not NODE_RE.match(name):
                continue
        except ValueError:
            continue
        low = name.lower()
        role = x.get("role") or ("controller" if re.search(r"controller|ctrl", low) else "compute" if "compute" in low else "other")
        result.append({"name": name, "ip": ip, "role": role, "user": x.get("user") or ""})
    return result, tried


def release(data, source):
    """('16.2.4', 'heat-admin') from /etc/rhosp-release; 17.x and later use tripleo-admin."""
    text = str(source(data, "uc_release").get("out") or "")
    m = re.search(r"release (\d+)\.(\d+)(?:\.(\d+))?", text)
    if not m:
        return "", "heat-admin"
    version = ".".join(x for x in m.groups() if x)
    return version, ("tripleo-admin" if int(m.group(1)) >= 17 else "heat-admin")


def short(name):
    return str(name or "").split(".")[0].lower()


# Where the node list comes from, tried in this order (every one is read; the first that gives nodes is used):
#   uc_servers    nova on the undercloud (classic RHOSP 16 deployments)
#   uc_metalsmith metalsmith (nodes provisioned with openstack overcloud node provision: 16.2 and 17.1)
#   uc_inventory  the TripleO Ansible inventory written by the deployment, only the lines of the groups, hosts and their
#                 ctlplane address / SSH user (the file also holds passwords: those lines are never read)
#   uc_ports      the ctlplane ports of the undercloud neutron ("<hostname>-ctlplane", metalsmith)
INVENTORY_FILES = ("~/overcloud-deploy/*/tripleo-ansible-inventory.yaml ~/config-download/*/tripleo-ansible-inventory.yaml "
                   "~/tripleo-ansible-inventory.yaml")
INVENTORY_GREP = ("grep -shE '^[A-Za-z0-9_]+:$|^  hosts:$|^    [A-Za-z0-9_.-]+:$|^      (ansible_host|ctlplane_ip): "
                  "|^ +ansible_ssh_user: ' " + INVENTORY_FILES)
PORTS_READ = "openstack port list --network ctlplane -f json -c Name -c 'Fixed IP Addresses'"
INVENTORY_READS = {"uc_servers": "openstack server list -f json", "uc_metalsmith": "metalsmith -f json list",
                   "uc_inventory": INVENTORY_GREP, "uc_ports": PORTS_READ, "uc_release": "cat /etc/rhosp-release"}

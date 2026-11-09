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

from . import wi_ops

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
    # Controller reboot readiness: Elastic Endpoint (package, units started at boot / running, /opt/Elastic), clustercheck
    # (container, the listener on 9200 and its HTTP answer: 200 = Galera synced), the kernel (running, newest installed,
    # needs-restarting -r: 1 = a reboot is needed)
    "elastic": lambda a: ("rpm -q elastic-agent 2>/dev/null; for u in elastic-agent ElasticEndpoint; do "
                          "echo \"unit $u $(systemctl is-enabled $u 2>/dev/null) $(systemctl is-active $u 2>/dev/null)\"; done; "
                          "if [ -d /opt/Elastic ]; then echo opt-elastic present; else echo opt-elastic absent; fi"),
    "clustercheck": lambda a: ("sudo -n podman ps -a --filter name=clustercheck --format 'container {{.Names}}|{{.Status}}'; "
                               "l=$(ss -ltnH 'sport = :9200' 2>/dev/null | awk '{print $4}' | head -n 1); "
                               "[ -n \"$l\" ] && echo \"listen $l\"; h=${l%:*}; case \"$h\" in ''|'*'|0.0.0.0|'[::]') h=127.0.0.1;; esac; "
                               "echo \"http $(curl -s -m 5 -o /dev/null -w '%{http_code}' http://$h:9200/)\""),
    "kernel": lambda a: ("uname -r; rpm -q --last kernel 2>/dev/null | head -n 1; needs-restarting -r >/dev/null 2>&1; "
                         "echo \"needs-restarting $?\"; echo \"up since $(uptime -s 2>/dev/null)\""),
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
    # Volume connections of an instance (check volume-connections), read-only: what Nova and Cinder record for its volumes
    # (a controller), its domain and the device of each LUN (its compute), and the migration / volume errors of nova-compute
    "vc_db": lambda a: vc_db_command(a[0]),
    "vc_domain": lambda a: vc_domain_command(a[0]),
    "vc_lun": lambda a: vc_lun_command(a[0]),
    "vc_log": lambda a: vc_log_command(a[0]),
    # VM disks on a compute (check compute-disks), read-only: its kernel disk events of the last <hours>, its multipath
    # maps, the disks of its running domains and the instance directories it keeps
    "cd_disks": lambda a: cd_disks_command(a[0]),
    # Guest LVs active on a compute (check host-lvm), read-only, as root: its LVM filter, every LVM LV and multipath map of
    # the host (what is under each LV, open count, holders, running paths) and the disks of its running domains
    "hl_lvm": lambda a: "sudo -n sh -c " + shlex.quote(wi_ops.HOST_LVS),
    # Memory errors of a compute (check compute-memory), read-only: the BMC event log and memory sensors in-band, the
    # kernel hardware error lines of the last <days>, the EDAC counters and the crash dumps
    "mem_ecc": lambda a: mem_ecc_command(a[0]),
    # NetApp LUN mappings against Cinder (check lun-map-audit), read-only: every live Cinder attachment and volume of the
    # site with the Nova action that made the attachment (a controller), the iSCSI initiator, SCSI devices and domain
    # disks of every node
    "lm_db": lambda a: lm_db_command(),
    "lm_node": lambda a: lm_node_command(),
}
LIBVIRT = ("c=$(sudo -n podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$'); "
           "[ -n \"$c\" ] || { echo 'no libvirt container'; exit 7; }; ")
VIRSH = 'sudo -n podman exec "$c" virsh -c qemu:///system'
VC_ERRORS = ("duplicate connectors|DestinationDiskExists|cannot acquire state change lock|Flushing .* failed"
             "|Pre live migration failed|Live migration failed")


def vc_db_command(sid):
    """The volumes of an instance as Nova (block device mapping) and Cinder (attachments) record them, and its last 3
    migrations: SELECT on the galera container, tab separated, one row per line tagged bdm / att / mig / vol. Never the
    connection_info itself (it holds the CHAP secret of the iSCSI target): only the fields named here. vol: every Cinder
    row naming a volume of Nova (by ID, name_id, display name or migration target:<ID>), deleted ones too, and the
    attachments of the live ones (vm-c3, 2026-11-02: Nova's volume deleted in Cinder, the target of a volume migration
    that never completed named after it, attached to the instance)."""
    if not UUID_RE.match(str(sid)):
        raise ValueError("invalid instance ID")
    mine = f"SELECT volume_id FROM nova.block_device_mapping WHERE instance_uuid='{sid}' AND deleted=0 AND destination_type='volume'"
    targets = ("SELECT CONCAT('target:', volume_id) FROM nova.block_device_mapping "
               f"WHERE instance_uuid='{sid}' AND deleted=0 AND destination_type='volume'")
    named = f"SELECT id FROM cinder.volumes WHERE deleted=0 AND (display_name IN ({mine}) OR migration_status IN ({targets}))"
    sql = ("SELECT 'bdm', volume_id, IFNULL(attachment_id,''), IFNULL(device_name,''), "
           "IFNULL(JSON_VALUE(connection_info,'$.driver_volume_type'),''), IFNULL(JSON_VALUE(connection_info,'$.data.target_iqn'),''), "
           "IFNULL(JSON_VALUE(connection_info,'$.data.target_lun'),''), IFNULL(JSON_EXTRACT(connection_info,'$.data.target_luns'),''), "
           "IFNULL(JSON_VALUE(connection_info,'$.data.device_path'),'') FROM nova.block_device_mapping "
           f"WHERE instance_uuid='{sid}' AND deleted=0 AND destination_type='volume'; "
           "SELECT 'att', volume_id, id, IFNULL(attach_status,''), IFNULL(attached_host,''), IFNULL(JSON_VALUE(connector,'$.host'),''), "
           "IF(connection_info IS NULL,0,1), IFNULL(instance_uuid,'') FROM cinder.volume_attachment WHERE deleted=0 AND "
           f"(volume_id IN ({mine}) OR volume_id IN ({named})); "
           "SELECT 'vol', id, deleted, IFNULL(deleted_at,''), IFNULL(_name_id,''), IFNULL(display_name,''), IFNULL(status,''), "
           "IFNULL(attach_status,''), IFNULL(migration_status,''), IFNULL(host,''), IFNULL(updated_at,'') FROM cinder.volumes "
           f"WHERE id IN ({mine}) OR _name_id IN ({mine}) OR display_name IN ({mine}) OR migration_status IN ({targets}) "
           "ORDER BY created_at, deleted; "
           "SELECT 'mig', id, IFNULL(migration_type,''), IFNULL(status,''), IFNULL(source_compute,''), IFNULL(dest_compute,''), "
           f"IFNULL(created_at,'') FROM nova.migrations WHERE instance_uuid='{sid}' AND deleted=0 ORDER BY id DESC LIMIT 3")
    return f"sudo -n podman exec $(sudo -n podman ps -q --filter name=galera-bundle | head -n 1) mysql -B -N -e \"{sql}\""


def vc_domain_command(instance):
    """The domain of an instance on its compute: state, UUID, every disk (target, source, dm device, multipath WWID, the
    LUN numbers of its paths), the iSCSI initiator of the compute (its igroup on NetApp), and whether libvirt can take a
    job on it now (domjobinfo; a reconnect of virtqemud that never ended holds the job: "cannot acquire state change
    lock" after 30 s)."""
    if not INSTANCE_RE.match(str(instance)):
        raise ValueError("invalid instance name")
    return (LIBVIRT + f"echo \"@@state $({VIRSH} domstate {instance} --reason 2>&1 | head -n 1)\"; "
            f"echo \"@@uuid $({VIRSH} domuuid {instance} 2>/dev/null)\"; "
            f"{VIRSH} domblklist --details {instance} 2>/dev/null | awk '$2 == \"disk\" && $4 ~ /^\\/dev\\// {{print $3, $4}}' | "
            "while read -r t s; do m=$(basename \"$(readlink -f \"$s\")\"); "
            "l=$(for p in $(ls /sys/block/$m/slaves 2>/dev/null); do basename \"$(readlink -f /sys/block/$p/device)\"; done "
            "| awk -F: '{print $4}' | sort -un | paste -sd, -); "
            "echo \"@@disk $t $s $m $(cat /sys/block/$m/dm/name 2>/dev/null || echo -) ${l:--}\"; done; "
            "echo \"@@initiator $(sudo -n cat /etc/iscsi/initiatorname.iscsi 2>/dev/null | sed -n 's/^InitiatorName=//p' | head -n 1)\"; "
            f"echo \"@@job $(timeout 45 {VIRSH} domjobinfo {instance} 2>&1 | tr '\\n' ' ')\"")


def vc_lun_command(lun):
    """Every device of one LUN number on a compute (each iSCSI path, its multipath device and WWID; the target is in the
    path name) and the disks of every running domain, to find who uses it."""
    n = int(lun)
    return (LIBVIRT + f"for p in $(ls /dev/disk/by-path/ 2>/dev/null | grep -E -- '-lun-{n}$'); do "
            "s=$(basename \"$(readlink -f /dev/disk/by-path/$p)\"); m=$(ls /sys/block/$s/holders 2>/dev/null | head -n 1); "
            "echo \"@@path $p $s ${m:--} $(cat /sys/block/$m/dm/name 2>/dev/null || echo -)\"; done; "
            f"for x in $({VIRSH} list --name 2>/dev/null); do u=$({VIRSH} domuuid $x 2>/dev/null); "
            f"for s in $({VIRSH} domblklist $x 2>/dev/null | awk '$2 ~ /^\\/dev\\// {{print $2}}'); do echo \"@@use $x $u $s\"; done; done")


def vc_log_command(hours):
    """The lines of nova-compute of the last <hours> about a failed migration or volume connection (no traceback lines)."""
    h = int(hours)
    if not 1 <= h <= 72:
        raise ValueError("hours must be 1-72")
    return ("f=/var/log/containers/nova/nova-compute.log; sudo -n test -r \"$f\" || exit 0; "
            f"sudo -n awk -v s=\"{_since(h)}\" 'substr($0,1,19) >= s' \"$f\" | grep -E '{VC_ERRORS}' | grep -vE '\\]  ' "
            "| tail -n 60 | cut -c1-400")
LM_LUN = "IFNULL(JSON_VALUE({t}.connection_info,'$.target_lun'),IFNULL(JSON_VALUE({t}.connection_info,'$.data.target_lun'),''))"


def lm_db_command():
    """Every live Cinder attachment and volume of the site (check lun-map-audit): SELECT on the galera container, tab
    separated, one row per line tagged att / vol / org. Of connection_info only the target IQN and LUN (it holds the CHAP
    secret). org, per attached attachment: the Nova action of its instance nearest to its creation (within 2 h: what
    made it, a live migration, an attach, an unshelve), the last migration of the instance, and the attachment of the
    same volume made before it (deleted ones too: where the volume was before, its LUN number and detach time)."""
    lun = LM_LUN.format(t="a")
    sql = ("SELECT 'att', a.id, a.volume_id, IFNULL(a.instance_uuid,''), IFNULL(a.attach_status,''), "
           "IFNULL(JSON_VALUE(a.connector,'$.host'),IFNULL(a.attached_host,'')), IFNULL(JSON_VALUE(a.connector,'$.initiator'),''), "
           "IFNULL(JSON_VALUE(a.connection_info,'$.target_iqn'),IFNULL(JSON_VALUE(a.connection_info,'$.data.target_iqn'),'')), "
           f"{lun}, IFNULL(a.created_at,''), IFNULL(a.attach_time,'') FROM cinder.volume_attachment a WHERE a.deleted=0; "
           "SELECT 'vol', id, IFNULL(_name_id,''), IFNULL(status,''), IFNULL(host,''), IFNULL(size,''), IFNULL(migration_status,''), "
           "REPLACE(IFNULL(LEFT(display_name,40),''),'\\t',' ') FROM cinder.volumes WHERE deleted=0; "
           "SELECT 'org', a.id, IFNULL((SELECT CONCAT(ia.action,'|',IFNULL(ia.request_id,''),'|',ia.start_time) FROM nova.instance_actions ia "
           "WHERE ia.instance_uuid=a.instance_uuid AND ia.start_time BETWEEN a.created_at - INTERVAL 2 HOUR AND a.created_at + INTERVAL 2 HOUR "
           "ORDER BY ABS(TIMESTAMPDIFF(SECOND, ia.start_time, a.created_at)) LIMIT 1),''), "
           "IFNULL((SELECT CONCAT(IFNULL(m.migration_type,''),'|',IFNULL(m.status,''),'|',IFNULL(m.source_compute,''),'|',"
           "IFNULL(m.dest_compute,''),'|',m.created_at) FROM nova.migrations m WHERE m.instance_uuid=a.instance_uuid AND m.deleted=0 "
           "ORDER BY m.created_at DESC LIMIT 1),''), "
           "IFNULL((SELECT CONCAT(p.id,'|',IFNULL(JSON_VALUE(p.connector,'$.host'),IFNULL(p.attached_host,'')),'|',"
           f"{LM_LUN.format(t='p')},'|',p.created_at,'|',IFNULL(p.detach_time,''),'|',IFNULL(p.deleted_at,'')) "
           "FROM cinder.volume_attachment p WHERE p.volume_id=a.volume_id AND p.id<>a.id AND p.created_at<=a.created_at "
           "ORDER BY p.created_at DESC LIMIT 1),'') FROM cinder.volume_attachment a WHERE a.deleted=0 AND a.attach_status='attached'; "
           "SELECT 'min', IFNULL((SELECT MIN(deleted_at) FROM cinder.volume_attachment WHERE deleted=1),'')")
    return f"sudo -n podman exec $(sudo -n podman ps -q --filter name=galera-bundle | head -n 1) mysql -B -N -e \"{sql}\""


def lm_node_command():
    """The iSCSI initiator of a node, every SCSI device on an iSCSI session (device, H:C:T:L, state, target, WWID, its
    multipath map) and, on a compute, the disks of the running domains (check lun-map-audit). sysfs and virsh
    domblklist only."""
    return ("echo \"@@node $(hostname -s) $(sudo -n cat /etc/iscsi/initiatorname.iscsi 2>/dev/null | sed -n 's/^InitiatorName=//p' | head -n 1)\"; "
            "for b in /sys/block/sd*; do [ -e \"$b/device\" ] || continue; p=$(readlink -f \"$b/device\"); "
            "s=$(echo \"$p\" | grep -o 'session[0-9]*' | head -n 1); [ -n \"$s\" ] || continue; h=$(ls \"$b/holders\" 2>/dev/null | head -n 1); "
            "echo \"@@dev ${b##*/} ${p##*/} $(cat \"$b/device/state\" 2>/dev/null || echo -) "
            "$(cat /sys/class/iscsi_session/$s/targetname 2>/dev/null || echo -) $(sed -E 's/^naa[.]/3/' \"$b/device/wwid\" 2>/dev/null || echo -) "
            "${h:--}\"; done; "
            "c=$(sudo -n podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$'); [ -n \"$c\" ] || exit 0; "
            "sudo -n podman exec \"$c\" sh -c 'for x in $(virsh -c qemu:///system list --name); do u=$(virsh -c qemu:///system domuuid $x); "
            "virsh -c qemu:///system domblklist $x | while read -r t s; do case \"$s\" in /dev/*) echo \"$x $u $t $s\";; esac; done; done' 2>/dev/null "
            "| while read -r x u t s; do echo \"@@use $(basename \"$(readlink -f \"$s\")\") $u $x $t\"; done")


CD_KERNEL = "alua: Detached|Synchronizing SCSI cache|I/O error, dev (dm|sd)|remaining active paths|Fail(ing)? (all )?path"
# over every kernel line of the window (not only the 400 shown, a real case: 120 I/O errors a minute): the last
# 400 lines, then @@kstat with the I/O errors of each device (count, first, last), every SCSI address removed, every map
# that lost its last path
CD_AWK = ("{ r[NR % 400] = substr($0, 1, 300) } "
          "/I.O error, dev / { if (match($0, /dev (dm|sd)[a-z0-9-]+/)) { d = substr($0, RSTART + 4, RLENGTH - 4); n[d]++; "
          "if (!(d in f)) f[d] = $1; l[d] = $1 } } "
          "/alua: Detached|Synchronizing SCSI cache/ { if (match($0, /[0-9]+:[0-9]+:[0-9]+:[0-9]+:/)) { a = substr($0, RSTART, RLENGTH - 1); "
          "if (!(a in ga)) { ga[a] = 1; ra[++na] = a } } } "
          "/remaining active paths: 0/ { if (match($0, /[^ ]+: remaining active paths: 0/)) { m = substr($0, RSTART, RLENGTH); "
          "sub(/: remaining.*/, \"\", m); lost[m] = 1 } } "
          "END { for (i = (NR > 400 ? NR - 399 : 1); i <= NR; i++) print r[i % 400]; print \"@@kstat\"; "
          "for (d in n) print \"@@io\", d, n[d], f[d], l[d]; for (i = 1; i <= na; i++) print \"@@removed\", ra[i]; "
          "for (m in lost) print \"@@lost\", m }")


def cd_disks_command(hours):
    """The disks of the running VMs of a compute and what happened to them: the kernel lines of the last <hours> about
    removed SCSI devices, I/O errors and failed paths (the last 400, then @@kstat: the totals of the whole window, the time
    now and how long each guest's QEMU runs); multipath -ll (multipathd container or host); every running
    domain (name, UUID) with its disks (target, source); the instance directories of /var/lib/nova/instances (UUID,
    whether a domain of it is defined here, age in minutes, files) with the filesystem type of that path."""
    h = int(hours)
    if not 1 <= h <= 72:
        raise ValueError("hours must be 1-72")
    return (LIBVIRT + "echo @@kernel; "
            f"sudo -n journalctl -k --since '-{h}h' --no-pager -o short-iso 2>/dev/null | grep -E '{CD_KERNEL}' | awk '{CD_AWK}'; "
            "echo \"@@now $(date +%s)\"; "
            "ps -ww -eo etimes=,args= | awk '/guest=instance-/ { if (match($0, /guest=instance-[0-9a-f]+/)) "
            "print \"@@qemu\", substr($0, RSTART + 6, RLENGTH - 6), $1 }'; "
            "echo @@maps; m=$(sudo -n podman ps --format '{{.Names}}' | grep -m1 -x multipathd); "
            "if [ -n \"$m\" ]; then sudo -n podman exec \"$m\" multipath -ll 2>/dev/null; else sudo -n multipath -ll 2>/dev/null; fi; "
            "echo @@domains; "
            f"for x in $({VIRSH} list --name 2>/dev/null); do echo \"@@dom $x $({VIRSH} domuuid $x 2>/dev/null)\"; "
            f"{VIRSH} domblklist $x 2>/dev/null | awk '$2 ~ /^\\/dev\\// {{print \"@@disk \" $1 \" \" $2}}'; done; "
            "echo @@dirs; echo \"@@fs $(findmnt -n -T /var/lib/nova/instances -o FSTYPE)\"; "
            f"all=$({VIRSH} list --all --uuid 2>/dev/null); now=$(date +%s); "
            "for d in /var/lib/nova/instances/*; do u=$(basename \"$d\"); [ -d \"$d\" ] || continue; "
            "echo \"$u\" | grep -qE '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' || continue; "
            "dom=no; echo \"$all\" | grep -qx \"$u\" && dom=yes; "
            "echo \"@@dir $u $dom $(( (now - $(stat -c %Y \"$d\")) / 60 )) $(ls \"$d\" 2>/dev/null | tr '\\n' ',' | cut -c1-80)\"; done")


MEM_KERNEL = ("ghes_notify_nmi|Hardware Error|EDAC|mce: |[Mm]achine [Cc]heck|Memory failure|CMCI storm|hard LOCKUP"
              "|Kernel panic")


def mem_ecc_command(days):
    """Memory errors of a compute (check compute-memory), read-only: its BMC event log (SEL) and memory sensors read
    in-band with ipmitool, as sosreport reads them (the same log the BMC web page shows, no BMC account needed), the BMC
    clock, the first entry of the SEL and its last clear (what time it covers), the boot time of the compute, the kernel
    lines of the last <days>, every boot (journalctl -k reads the current boot only: the NMIs before a
    crash are in the boot before), about hardware errors (APEI / GHES firmware first, EDAC, machine checks,
    lockups, panics), the EDAC counters and the crash dumps (a real case: DIMM CPU2_C3D0 reached its correctable ECC
    logging limit three times in three days, then the compute crashed with a hard lockup)."""
    d = int(days)
    if not 1 <= d <= 30:
        raise ValueError("days must be 1-30")
    return ("echo \"@@now $(date -u '+%Y-%m-%d %H:%M:%S')\"; "
            "echo \"@@boot $(uptime -s 2>/dev/null) $(date +%z)\"; "
            "echo \"@@serial $(sudo -n cat /sys/class/dmi/id/product_serial 2>/dev/null)\"; "
            "if ! command -v ipmitool >/dev/null 2>&1; then echo '@@noipmi ipmitool is not installed on this node'; "
            "elif ! { [ -e /dev/ipmi0 ] || [ -e /dev/ipmi/0 ] || [ -e /dev/ipmidev/0 ]; }; then "
            "echo '@@noipmi no IPMI device (/dev/ipmi0): the ipmi_si / ipmi_devintf modules are not loaded'; "
            "else echo \"@@bmctime $(sudo -n timeout 30 ipmitool sel time get 2>&1 | head -n 1)\"; "
            "echo \"@@bmcip $(sudo -n timeout 30 ipmitool lan print 2>/dev/null | awk -F': *' '/^IP Address  / {print $2; exit}')\"; "
            "echo @@selinfo; sudo -n timeout 30 ipmitool sel info 2>&1 "
            "| grep -E 'Entries|Percent Used|Overflow|Free Space|Last Add Time|Last Del Time'; "
            "S=$(sudo -n timeout 150 ipmitool sel elist 2>/dev/null); "
            "echo \"@@selfirst $(printf '%s\\n' \"$S\" | head -n 1 | cut -c1-200)\"; "
            "echo @@sel; printf '%s\\n' \"$S\" | grep -E '[Mm]emory|ECC|DIMM' | tail -n 300 | cut -c1-200; "
            "echo @@sdr; sudo -n timeout 90 ipmitool sdr type Memory 2>/dev/null | cut -c1-200; fi; "
            f"echo @@kernel; sudo -n journalctl _TRANSPORT=kernel --since '-{d}d' --no-pager -q 2>/dev/null | grep -E '{MEM_KERNEL}' "
            "| tail -n 200 | cut -c1-250; "
            "echo @@edac; grep -H . /sys/devices/system/edac/mc/mc*/ce_count /sys/devices/system/edac/mc/mc*/ue_count 2>/dev/null "
            "| head -n 16; "
            "echo @@crash; sudo -n ls -1 /var/crash 2>/dev/null | tail -n 8; echo @@end")


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
ARGS = {"ovn_dp": ("uuid",), "ovn_pb": ("uuid",), "ovn_fdb": ("int",), "ovn_capture": ("tap", "seconds", "mac"),
        "vc_db": ("uuid",), "vc_domain": ("inst",), "vc_lun": ("int",), "vc_log": ("hours",), "cd_disks": ("hours",),
        "mem_ecc": ("days",)}
INSTANCE_RE = re.compile(r"^instance-[0-9a-f]{8}$")
USAGE_COMMAND = ("head -n 1 /proc/stat; grep -E '^(MemTotal|MemAvailable):' /proc/meminfo; sleep 2; head -n 1 /proc/stat; "
                 "grep -m1 '^vendor_id' /proc/cpuinfo")
PARALLEL = ("use_", "lmn_")   # reads whose keys start so run on all their nodes at once (each node once, short reads)
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
            else v.isdigit() and 1 <= int(v) <= 30 if k == "seconds" else MAC_ARG.match(v) if k == "mac"
            else INSTANCE_RE.match(v) if k == "inst" else v.isdigit() and 1 <= int(v) <= 72 if k == "hours"
            else v.isdigit() and 1 <= int(v) <= 30 if k == "days" else False
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
    a, b = cpu[0][:8], cpu[-1][:8]   # guest and guest_nice are already counted in user and nice (see wi_ops.parse_usage)
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

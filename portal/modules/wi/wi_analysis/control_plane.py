"""Control plane of Acme Flex beyond `pcs status` (RISET-KNOWN-ISSUES.md 2.1 #1-2, 2.2 #1-3): the OVN NB / SB databases
(RAFT clusters on RHOSP 17.x, not managed by Pacemaker any more; the active / backup bundle ovn-dbs-bundle on 16.2), the
queues of RabbitMQ and the replication and connections of Galera. Read only, on the controllers, from the director (ssh
heat-admin / tripleo-admin with sudo, as the other overcloud checks). No fix runs from the portal: the commands to look
further and the vendor documentation are given.
"""
import re

from . import overcloud
from .common import Result, first_line, source, unavailable
from .overcloud_checks import inventory, item_out

MACB_WARN, MACB_FAIL = 100_000, 500_000   # MAC_Binding rows (Red Hat 6410121: 1.15 million rows, neutron-server OOM)
DB_WARN_MB = 500
QUEUE_WARN = 1000
FD_WARN = 80   # % of the file descriptor / socket limit of a RabbitMQ node
WSREP_FC_WARN = 0.1
CONN_WARN = 80   # % of max_connections used at the peak


def reached(item):
    """The node answered SSH: the read ran on it (whatever its own exit code). ssh itself exits 255 when it cannot connect
    or log in; any other code is the command's (a stopped container, Access denied), not the connection's."""
    return not item.get("skipped") and str(item.get("rc")) != "255"


def controllers_up(data, ctx, prefix):
    """(controllers, user, version, problem, [(index, node)] reached by the read `prefix`<i>)."""
    _found, controllers, user, version, problem = inventory(data, ctx)
    up = [(i, n) for i, n in enumerate(controllers) if reached(source(data, f"{prefix}{i}"))]
    return controllers, user, version, problem, up


def model_of(text):
    """How a controller runs the OVN databases, from the header of ovnnb_db.db: RAFT (17.x), active/backup (16.2)."""
    head = str(text or "").strip()
    return "RAFT" if head.startswith("OVSDB CLUSTER") else "active/backup" if head.startswith("OVSDB JSON") else "unknown"


def count_of(item):
    """The number printed by `<read> | grep -c .`, or None when the read before the pipe failed (its error is printed too,
    and grep prints 0)."""
    lines = [x.strip() for x in str(item.get("out") or "").splitlines() if x.strip()]
    return int(lines[0]) if "out" in item and len(lines) == 1 and lines[0].isdigit() else None


def nodes_step(r, controllers, up, data, prefix, user, version):
    rows = [[n["name"], n["ip"], "reached" if (i, n) in up else (unavailable(source(data, f"{prefix}{i}")) or "no answer")[:160]]
            for i, n in enumerate(controllers)]
    down = [n["name"] for i, n in enumerate(controllers) if (i, n) not in up]
    r.step("nodes", "Controllers reached from the director", "fail" if not up else "warn" if down else "ok",
           f"{len(up)} of {len(controllers)} controller(s) answered as {user}" + (f" (RHOSP {version})" if version else "") + ".",
           {"columns": ["Controller", "ctlplane", "SSH from the director"], "rows": rows}, marks=down)
    return down


def parse_raft(text):
    """`ovs-appctl cluster/status <db>` of one member -> {"role", "leader", "term", "status", "sid", "servers": [sid]}."""
    text = str(text or "")
    field = lambda name: (re.search(rf"^{name}:\s*(.+)$", text, re.M) or [None, ""])[1].strip()
    servers = re.findall(r"^\s+([0-9a-f]{4}) \(", text.split("Servers:", 1)[1], re.M) if "Servers:" in text else []
    return {"role": field("Role"), "leader": field("Leader"), "term": field("Term"), "status": field("Status"),
            "sid": field("Server ID").split()[0] if field("Server ID") else "", "servers": servers}


def parse_sync(text):
    """`ovsdb-server/sync-status` of the bundle (16.2), per database: {"nb"|"sb": {"state", "replicating"}}."""
    out, current = {}, None
    for line in str(text or "").splitlines():
        m = re.match(r"^== (nb|sb)$", line.strip())
        if m:
            current = m.group(1)
            out[current] = {"state": "", "replicating": ""}
            continue
        m = re.match(r"^\s*(state|replicating):\s*(.*)$", line)
        if m and current:
            out[current][m.group(1)] = m.group(2).strip()
    return out


class OvnDbCluster:
    """OVN NB / SB databases of the controllers: RAFT leader, terms and members (17.x), active / backup and replication
    (16.2), northd active on one node, the size of the databases and of MAC_Binding."""
    sources = ("undercloud", "overcloud")
    phases = 3

    @staticmethod
    def reads(phase, data, params, ctx):
        if phase == 1:
            return {"undercloud": dict(overcloud.INVENTORY_READS)}
        _found, controllers, user, _v, problem = inventory(data, ctx)
        if problem:
            return {}
        if phase == 2:   # the model of each controller, all at once (also tells which controllers answer)
            return {"overcloud": {f"use_model_{i}": overcloud.read(n["name"], n["ip"], user, "ovn_model")
                                  for i, n in enumerate(controllers)}}
        _c, _u, _v, _p, up = controllers_up(data, ctx, "use_model_")
        out = {}
        for i, n in up:
            model = model_of(item_out(data, f"use_model_{i}"))   # unknown: both ways are read
            cmds = (("ovn_nb_raft", "ovn_sb_raft") if model != "active/backup" else ()) \
                + (("ovn_sync",) if model != "RAFT" else ()) + ("ovn_northd", "ovn_dbsize")
            for cmd in cmds:
                out[f"use_{cmd}_{i}"] = overcloud.read(n["name"], n["ip"], user, cmd)
        if up:
            i, n = up[0]
            out["macb"] = overcloud.read(n["name"], n["ip"], user, "ovn_macb")
        return {"overcloud": out} if out else {}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("ovn-db-cluster")
        controllers, user, version, problem, up = controllers_up(data, ctx, "use_model_")
        if problem:
            r.step("nodes", "Controllers", "fail", problem)
            return r.done()
        nodes_step(r, controllers, up, data, "use_model_", user, version)
        if not up:
            r.recommend("No controller answers SSH from the director: check the controllers and the ctlplane network first "
                        "(Pacemaker and fencing, Bare metal nodes).", [f"ssh {user}@{controllers[0]['ip']} hostname"],
                        where="OpenStack director, as stack")
            return r.done()
        models = {n["name"]: model_of(item_out(data, f"use_model_{i}")) for i, n in up}
        kinds = sorted(set(models.values()))
        raft = "RAFT" in kinds   # one controller whose file was not read does not make a 17.x cloud a 16.2 one
        r.step("model", "How the OVN databases are run", "ok" if len(kinds) == 1 and kinds != ["unknown"] else "warn",
               ("Clustered (RAFT) on every controller: RHOSP 17.x, not managed by Pacemaker (the check \"Pacemaker and "
                "fencing\" does not see them)." if raft else
                "Active / backup in the Pacemaker bundle ovn-dbs-bundle (RHOSP 16.2): one controller is the active (Master)."
                if kinds == ["active/backup"] else
                "The controllers do not agree: " + ", ".join(f"{k}: {v}" for k, v in models.items())
                + " (unknown = /var/lib/openvswitch/ovn/ovnnb_db.db not readable)."))
        where = f"each controller, as {user} with sudo: from the director, ssh {user}@<its ctlplane address>"
        if raft:
            for db, key, title in (("nb", "ovn_nb_raft", "Northbound"), ("sb", "ovn_sb_raft", "Southbound")):
                views = {n["name"]: parse_raft(item_out(data, f"use_{key}_{i}")) for i, n in up}
                rows, unread = [], []
                for name, v in views.items():
                    if not v["role"]:
                        unread.append(name)
                    rows.append([name, v["role"] or "not read", v["leader"] or "-", v["term"] or "-", v["status"] or "-",
                                 str(len(v["servers"])) if v["servers"] else "-"])
                read = {k: v for k, v in views.items() if v["role"]}
                leaders = [k for k, v in read.items() if v["role"] == "leader"]
                named = sorted({v["leader"] for v in read.values() if v["role"] == "follower" and v["leader"] not in ("", "unknown", "self")})
                # the leader's own status was not read, but every follower names the same one: there is a leader
                silent_leader = named[0] if not leaders and len(named) == 1 and unread else ""
                not_member = [k for k, v in read.items() if v["status"] and v["status"] != "cluster member"]
                unknown = [k for k, v in read.items() if v["leader"] in ("", "unknown")]
                sizes = sorted({len(v["servers"]) for v in read.values() if v["servers"]})
                terms = sorted({v["term"] for v in read.values() if v["term"]})
                status = "skip" if not read else \
                    "fail" if (len(leaders) != 1 and not silent_leader) or not_member or len(unknown) * 2 >= len(read) else \
                    "warn" if unread or (sizes and (sizes[-1] != len(controllers) or len(sizes) > 1)) or len(terms) > 1 else "ok"
                detail = ("Not read on any controller." if not read else
                          (f"Leader: {leaders[0]}" if len(leaders) == 1 else
                           f"Leader: server {silent_leader}, as every follower reports (its own status was not read)" if silent_leader else
                           "NO LEADER" if not leaders else f"{len(leaders)} LEADERS ({', '.join(leaders)})")
                          + f"; term {', '.join(terms) or '-'}; members per node: {', '.join(map(str, sizes)) or '-'} "
                          f"(controllers: {len(controllers)}).")
                if not_member:
                    detail += f" Not a cluster member: {', '.join(not_member)}."
                if sizes and sizes[-1] > len(controllers):
                    detail += (" More members than controllers: a removed controller is still a member (BZ 2222828): "
                               "a partition risk; remove it as Red Hat 7091792 describes.")
                if unread:
                    detail += f" Not read on: {', '.join(unread)}."
                r.step(f"{db}raft", f"OVN {title} database: RAFT leader and members", status, detail,
                       {"columns": ["Controller", "Role", "Leader", "Term", "Status", "Members"], "rows": rows},
                       marks=unread + not_member, evidence="\n\n".join(f"== {k}\n{item_out(data, f'use_{key}_{i}')}"
                                                                     for i, n in up for k in [n["name"]])[:4000])
                if status == "fail":
                    r.recommend(f"The OVN {title} database cluster has no single leader or a member left it: Neutron API "
                                "calls time out and ports are not bound until it has one. Look at the members and their "
                                "logs; a member is removed and added again only as Red Hat describes (a wrong kick loses "
                                "the quorum).",
                                [f"sudo podman exec ovn_cluster_{'north' if db == 'nb' else 'south'}_db_server ovs-appctl -t "
                                 f"/var/run/ovn/ovn{db}_db.ctl cluster/status OVN_{title}",
                                 f"sudo tail -n 100 /var/log/containers/openvswitch/ovsdb-server-{db}.log",
                                 "sudo systemctl status tripleo_ovn_cluster_north_db_server tripleo_ovn_cluster_south_db_server"],
                                where=where, refs=["rhosp-ovn-raft"])
        elif "active/backup" in kinds:
            rows, actives = [], {"nb": [], "sb": []}
            for i, n in up:
                sync = parse_sync(item_out(data, f"use_ovn_sync_{i}"))
                for db in ("nb", "sb"):
                    st = (sync.get(db) or {}).get("state", "")
                    if st == "active":
                        actives[db].append(n["name"])
                rows.append([n["name"]] + [f"{(sync.get(db) or {}).get('state') or '-'}"
                                           + (f" ({sync[db]['replicating']})" if (sync.get(db) or {}).get("replicating") else "")
                                           for db in ("nb", "sb")])
            bad = [db for db in ("nb", "sb") if len(actives[db]) != 1]
            r.step("sync", "OVN databases: active and backups (ovn-dbs-bundle)", "fail" if bad else "ok",
                   "; ".join(f"{db.upper()} active on {', '.join(actives[db]) or 'NO controller'}" for db in ("nb", "sb")) + ".",
                   {"columns": ["Controller", "NB", "SB"], "rows": rows})
            if bad:
                r.recommend("No (or more than one) active OVN database: Pacemaker promotes one controller of ovn-dbs-bundle "
                            "(Master). Look at the bundle in pcs status and clean up its failed actions.",
                            ["sudo pcs status | grep -A4 ovn-dbs-bundle", "sudo pcs resource cleanup ovn-dbs-bundle"],
                            where=where, refs=["rhosp-pcs-resource"])
        # northd: exactly one active
        actives = [n["name"] for i, n in up if re.search(r"Status:\s*active", item_out(data, f"use_ovn_northd_{i}"))]
        read = [n["name"] for i, n in up if re.search(r"Status:\s*\w+", item_out(data, f"use_ovn_northd_{i}"))]
        r.step("northd", "ovn-northd: one active instance", "skip" if not read else "ok" if len(actives) == 1 else "fail",
               ("ovn-northd status was not read (container ovn_cluster_northd / ovn-dbs-bundle not found)." if not read else
                f"Active on {', '.join(actives) or 'NO controller'}; standby on "
                f"{', '.join(x for x in read if x not in actives) or '-'}."))
        # size of the databases and of MAC_Binding (Red Hat 6410121)
        sizes = []
        for i, n in up:
            for line in item_out(data, f"use_ovn_dbsize_{i}").splitlines():
                m = re.search(r"\s(\d+)\s+\w+\s+\d+\s+[\d:]+\s+(ovn(?:nb|sb)_db\.db)$", line)
                if m:
                    sizes.append((n["name"], m.group(2), int(m.group(1)) / 1048576))
        macb_item = source(data, "macb")
        macb = count_of(macb_item)
        biggest = max((s[2] for s in sizes), default=0)
        status = "fail" if macb is not None and macb >= MACB_FAIL else \
            "warn" if (macb is not None and macb >= MACB_WARN) or biggest >= DB_WARN_MB else "ok"
        r.step("size", "Size of the databases and MAC_Binding", status,
               (f"MAC_Binding: {macb:,} row(s)" if macb is not None else
                f"MAC_Binding not read ({unavailable(macb_item) or first_line(macb_item.get('out')) or 'no answer'})")
               + f"; the biggest database file: {biggest:.0f} MB.",
               {"columns": ["Controller", "File", "Size (MB)"], "rows": [[a, b, f"{c:.0f}"] for a, b, c in sizes]})
        if status != "ok":
            r.recommend("The Southbound database grows (MAC_Binding): neutron-server and ovsdb-server use more memory, and a "
                        "compaction can move the leader (Neutron 504). Turn on the aging of MAC_Binding through the director "
                        "(RHOSP 17.1.2 and later) and follow its size; never delete rows by hand without Red Hat.",
                        ["sudo podman exec ovn_controller ovn-sbctl --no-leader-only --bare --columns=datapath list MAC_Binding "
                         "| sort | uniq -c | sort -rn | head", "ps -eo rss,cmd | grep [n]eutron-server"],
                        where=where, refs=["rhosp-ovn-macbinding"])
        return r.done()


def parse_queues(text):
    """`rabbitmqctl -q list_queues name messages consumers` -> [(name, messages, consumers)]."""
    out = []
    for line in str(text or "").splitlines():
        parts = line.split("\t") if "\t" in line else line.split()
        if len(parts) >= 3 and parts[-1].isdigit() and parts[-2].isdigit():
            out.append((" ".join(parts[:-2]).strip(), int(parts[-2]), int(parts[-1])))
    return out


def parse_fd(text):
    """File descriptors and sockets of `rabbitmqctl status`: {"fd": (used, limit), "sockets": (used, limit)} (3.8+ text,
    or the Erlang terms of 3.6)."""
    text = str(text or "")
    out = {}
    m = re.search(r"File Descriptors\s*\n+\s*Total:\s*(\d+),\s*limit:\s*(\d+)", text)
    if m:
        out["fd"] = (int(m.group(1)), int(m.group(2)))
    m = re.search(r"Sockets:\s*(\d+),\s*limit:\s*(\d+)", text)
    if m:
        out["sockets"] = (int(m.group(1)), int(m.group(2)))
    m = re.search(r"\{total_limit,(\d+)\},\s*\{total_used,(\d+)\},\s*\{sockets_limit,(\d+)\},\s*\{sockets_used,(\d+)\}", text)
    if m:
        out["fd"] = (int(m.group(2)), int(m.group(1)))
        out["sockets"] = (int(m.group(4)), int(m.group(3)))
    return out


class RabbitmqQueues:
    """RabbitMQ of the controllers: queues that grow (messages >= 1000) or have messages without a consumer, and the file
    descriptors / sockets of each node."""
    sources = ("undercloud", "overcloud")
    phases = 2

    @staticmethod
    def reads(phase, data, params, ctx):
        if phase == 1:
            return {"undercloud": dict(overcloud.INVENTORY_READS)}
        _found, controllers, user, _v, problem = inventory(data, ctx)
        if problem:
            return {}
        out = {f"use_rstatus_{i}": overcloud.read(n["name"], n["ip"], user, "rabbit_status") for i, n in enumerate(controllers)}
        out.update({f"use_rqueues_{i}": overcloud.read(n["name"], n["ip"], user, "rabbit_queues") for i, n in enumerate(controllers)})
        return {"overcloud": out}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("rabbitmq-queues")
        controllers, user, version, problem, up = controllers_up(data, ctx, "use_rstatus_")
        if problem:
            r.step("nodes", "Controllers", "fail", problem)
            return r.done()
        nodes_step(r, controllers, up, data, "use_rstatus_", user, version)
        if not up:
            return r.done("No controller answered: RabbitMQ was not read.")
        where = f"a controller, as {user} with sudo: from the director, ssh {user}@<its ctlplane address>"
        rows, high, silent = [], [], []
        for i, n in up:
            item = source(data, f"use_rstatus_{i}")
            if unavailable(item):   # reached, but rabbitmqctl did not answer (container stopped, node down in the cluster)
                silent.append(n["name"])
                rows.append([n["name"], f"not read: {(first_line(item.get('out')) or unavailable(item))[:120]}", "-"])
                continue
            fd = parse_fd(item_out(data, f"use_rstatus_{i}"))
            cells = []
            for key in ("fd", "sockets"):
                used, limit = fd.get(key, (None, None))
                pct = round(used * 100 / limit) if used is not None and limit else None
                cells.append(f"{used} of {limit} ({pct}%)" if pct is not None else "-")
                if pct is not None and pct >= FD_WARN:
                    high.append(f"{n['name']} {key} {pct}%")
            rows.append([n["name"]] + cells)
        parsed = [x for x in rows if x[0] not in silent and x[1] != "-"]
        r.step("fd", "File descriptors and sockets of each RabbitMQ node",
               "fail" if silent else "warn" if high else "ok" if parsed else "skip",
               (f"rabbitmqctl does not answer on: {', '.join(silent)} (the rabbitmq-bundle of that controller is stopped or "
                "not in the cluster: see Pacemaker and fencing). " if silent else "")
               + (f"Near the limit: {', '.join(high)}: new connections are refused when it is reached." if high else
                  f"Under {FD_WARN}% of the limit on every node read." if parsed else "The limits were not in the output."),
               {"columns": ["Controller", "File descriptors", "Sockets"], "rows": rows}, marks=silent + high)
        queues = next((parse_queues(item_out(data, f"use_rqueues_{i}")) for i, n in up if parse_queues(item_out(data, f"use_rqueues_{i}"))), [])
        if not queues:
            r.step("queues", "Queues", "skip", "list_queues did not answer on any controller.")
            return r.done()
        big = sorted([q for q in queues if q[1] >= QUEUE_WARN], key=lambda q: -q[1])
        orphan = sorted([q for q in queues if q[2] == 0 and q[1] > 0 and q not in big], key=lambda q: -q[1])
        notif = [q for q in big + orphan if q[0].startswith(("notifications.", "versioned_notifications.")) and q[2] == 0]
        r.step("queues", "Queues that grow or have no consumer", "warn" if big or orphan else "ok",
               (f"{len(queues)} queue(s); {len(big)} with {QUEUE_WARN} messages or more, {len(orphan)} more with messages "
                "and no consumer." + (f" {len(notif)} are notification queues no service reads (nothing consumes them: "
                                      "Red Hat 3139721)." if notif else "")) if big or orphan else
               f"{len(queues)} queue(s): none with {QUEUE_WARN} messages or more, none with messages and no consumer.",
               {"columns": ["Queue", "Messages", "Consumers"], "rows": [[q[0], str(q[1]), str(q[2])] for q in (big + orphan)[:40]]},
               marks=[q[0] for q in (big + orphan)[:5]])
        if notif:
            r.recommend("Notification queues fill without a consumer (no telemetry reads them): they take memory from "
                        "RabbitMQ. Confirm that nothing should read them, then purge them, or stop the notifications in the "
                        "services through the director. The reply_* and *_fanout_* queues expire by themselves: never purge "
                        "them.", [f"sudo podman exec $(sudo podman ps -q -f name=rabbitmq-bundle) rabbitmqctl purge_queue {q[0]}"
                                  for q in notif[:5]], where=where, refs=["rhosp-rabbitmq-queues"],
                        warning="Purging deletes the messages of the queue; confirm first that no service reads it.")
        if [q for q in big if q not in notif]:
            r.recommend("Queues of the services fill faster than they are read: the service that consumes them is slow or "
                        "down (look at its logs and at Overcloud logs, MessagingTimeout).",
                        ["sudo podman exec $(sudo podman ps -q -f name=rabbitmq-bundle) rabbitmqctl -q list_queues name messages "
                         "consumers | sort -k2 -n -r | head -20"], where=where, refs=["rhosp-rabbitmq-queues"])
        if high:
            r.recommend("A RabbitMQ node is near its file descriptor / socket limit: raise the limit through the director "
                        "and look for services that open too many connections.",
                        ["sudo podman exec $(sudo podman ps -q -f name=rabbitmq-bundle) rabbitmqctl status | grep -A3 -i 'file descriptors'",
                         "sudo podman exec $(sudo podman ps -q -f name=rabbitmq-bundle) rabbitmqctl -q list_connections | wc -l"],
                        where=where, refs=["rhosp-rabbitmq-queues"])
        return r.done()


def parse_wsrep(text):
    """`SHOW GLOBAL STATUS ...; SHOW GLOBAL VARIABLES LIKE 'max_connections'` (-B -N): {name: value}."""
    out = {}
    for line in str(text or "").splitlines():
        parts = line.split("\t")
        if len(parts) == 2:
            out[parts[0].strip().lower()] = parts[1].strip()
    return out


class GaleraWsrep:
    """Galera of the controllers: cluster size, Primary component, Synced state, flow control, receive queue, and the
    connections against max_connections."""
    sources = ("undercloud", "overcloud")
    phases = 2

    @staticmethod
    def reads(phase, data, params, ctx):
        if phase == 1:
            return {"undercloud": dict(overcloud.INVENTORY_READS)}
        _found, controllers, user, _v, problem = inventory(data, ctx)
        if problem:
            return {}
        return {"overcloud": {f"use_galera_{i}": overcloud.read(n["name"], n["ip"], user, "galera_status")
                              for i, n in enumerate(controllers)}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("galera-wsrep")
        controllers, user, version, problem, up = controllers_up(data, ctx, "use_galera_")
        if problem:
            r.step("nodes", "Controllers", "fail", problem)
            return r.done()
        nodes_step(r, controllers, up, data, "use_galera_", user, version)
        where = f"a controller, as {user} with sudo: from the director, ssh {user}@<its ctlplane address>"
        if not up:
            return r.done("No controller answered: Galera was not read.")
        answers = {i: source(data, f"use_galera_{i}") for i, _n in up}
        if all(unavailable(x) and "Access denied" in str(x.get("out") or "") for x in answers.values()):
            r.step("wsrep", "Galera replication", "skip", "mysql in the galera container refused the root option file "
                   "(Access denied): read it as Red Hat describes (the password of hiera, never shown in the portal).")
            return r.done()
        rows, bad, warn = [], [], []
        for i, n in up:
            if unavailable(answers[i]):   # reached, but mysql did not answer: the galera container is down on that node
                bad.append(n["name"])
                rows.append([n["name"], "-", f"not read: {(first_line(answers[i].get('out')) or unavailable(answers[i]))[:120]}",
                             "-", "-", "-", "-", "-"])
                continue
            w = parse_wsrep(item_out(data, f"use_galera_{i}"))
            size, status = w.get("wsrep_cluster_size", ""), w.get("wsrep_cluster_status", "")
            state, fc = w.get("wsrep_local_state_comment", ""), float(w.get("wsrep_flow_control_paused") or 0)
            used, peak, limit = int(w.get("threads_connected") or 0), int(w.get("max_used_connections") or 0), int(w.get("max_connections") or 0)
            pct = round(peak * 100 / limit) if limit else None
            if size and int(size) < 3 or status and status != "Primary" or state and state != "Synced":
                bad.append(n["name"])
            elif fc > WSREP_FC_WARN or (pct is not None and pct >= CONN_WARN):
                warn.append(n["name"])
            rows.append([n["name"], size or "-", status or "-", state or "-", w.get("wsrep_ready") or "-", f"{fc:.2f}",
                         w.get("wsrep_local_recv_queue_avg") or "-", f"{used} now, {peak} peak of {limit or '?'}"
                         + (f" ({pct}%)" if pct is not None else "")])
        r.step("wsrep", "Galera replication and connections", "fail" if bad else "warn" if warn else "ok",
               (f"Not Synced / not Primary / cluster under 3, or mysql not answering: {', '.join(bad)}. " if bad else "")
               + (f"Flow control above {WSREP_FC_WARN} or connections at {CONN_WARN}% of max_connections: {', '.join(warn)}." if warn else "")
               or "Every node read is Synced in a Primary cluster of 3, without flow control, connections under the limit.",
               {"columns": ["Controller", "Cluster size", "Status", "State", "Ready", "Flow control paused", "Recv queue avg",
                            "Connections"], "rows": rows}, marks=bad + warn)
        if bad:
            r.recommend("A Galera node is not Synced in the Primary component: writes may stall or that node serves old data. "
                        "Look at the galera bundle in Pacemaker and at mysqld.log of the node.",
                        ["sudo pcs status | grep -A6 galera-bundle", "sudo tail -n 100 /var/log/containers/mysql/mysqld.log"],
                        where=where, refs=["rhosp-galera"])
        if warn:
            r.recommend("Flow control pauses the replication or the connections reach max_connections (\"Too many "
                        "connections\", API 500/503): find the slow node (disk I/O) and raise MysqlMaxConnections through the "
                        "director when the peak is real.",
                        ["sudo podman exec $(sudo podman ps -q -f name=galera-bundle) mysql -e \"SHOW PROCESSLIST\" | wc -l"],
                        where=where, refs=["rhosp-galera", "rhosp-galera-connections"])
        return r.done()

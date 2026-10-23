"""Platform health of the RHOSP control plane read on the overcloud nodes through the director (see overcloud.py):
Pacemaker and fencing of the controllers, and the logs of the OpenStack services, Pacemaker / corosync and the kernel.
Read-only: pcs status / stonith history / property, corosync-quorumtool, rabbitmqctl cluster_status, chronyc
tracking, and log lines. The fixes are commands for an engineer (the portal does not run them).
"""
import re
import shlex

from . import overcloud
from .common import Result, json_of, source, unavailable, worst
from .screens import redact

RESOURCE = re.compile(r"^\s*(?:\*\s+)?([A-Za-z0-9_.:@-]+)\s+\(([^)]+)\):\s+(\S+)(?:\s+(.*?))?\s*$")
OK_STATES = {"started", "master", "promoted", "slave", "unpromoted"}


# ---------------------------------------------------------------- parsers
def parse_pcs(text):
    """`pcs status --full` (pcs 0.10 / 0.11, also the older layout without bullets) -> dict."""
    out = {"quorum": None, "dc": "", "online": [], "offline": [], "unclean": [], "standby": [], "resources": [],
           "failed_actions": [], "failed_fencing": [], "pending_fencing": [], "daemons": {}}
    section, bundle = "", ""
    for raw in str(text or "").splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            if section in ("failed_actions", "failed_fencing", "pending_fencing"):
                section = ""
            continue
        low = stripped.lower()
        if "current dc:" in low:
            out["dc"] = stripped.split(":", 1)[1].strip().split(" ")[0]
            out["quorum"] = "without quorum" not in low if "quorum" in low else out["quorum"]
            continue
        if low.startswith(("failed resource actions", "failed actions")):
            section = "failed_actions"
            continue
        if low.startswith("failed fencing actions"):
            section = "failed_fencing"
            continue
        if low.startswith("pending fencing actions"):
            section = "pending_fencing"
            continue
        if low.startswith("daemon status"):
            section = "daemons"
            continue
        if low.startswith(("full list of resources", "node list", "cluster summary", "fencing history")):
            section = "resources" if low.startswith("full list") else ""
            continue
        if section in ("failed_actions", "failed_fencing", "pending_fencing"):
            out[section].append(stripped.lstrip("* ").strip())
            continue
        if section == "daemons":
            m = re.match(r"^(\S+):\s+(\S+)", stripped)
            if m:
                out["daemons"][m.group(1)] = m.group(2)
            continue
        m = re.match(r"^\*?\s*(Online|OFFLINE|Standby|RemoteOnline|RemoteOFFLINE):\s*\[(.*)\]", stripped)
        if m and m.group(1) in ("Online", "OFFLINE", "Standby"):
            names = [n for n in re.sub(r"\(\d+\)", " ", m.group(2)).split() if n]
            out[{"Online": "online", "OFFLINE": "offline", "Standby": "standby"}[m.group(1)]] += names
            continue
        m = re.match(r"^\*?\s*Node\s+(\S+)(?:\s+\(\d+\))?:\s*(.+)$", stripped)
        if m:
            state = m.group(2).lower()
            name = m.group(1)
            if "unclean" in state:
                out["unclean"].append(name)
            elif "offline" in state:
                out["offline"].append(name)
            elif "standby" in state:
                out["standby"].append(name)
            elif "online" in state:
                out["online"].append(name)
            continue
        m = re.match(r"^\*?\s*(?:Container bundle(?: set)?|Clone Set|Resource Group|Master/Slave Set):\s*(\S+)", stripped)
        if m:
            bundle = m.group(1)
            continue
        m = RESOURCE.match(line)
        if m and section in ("resources", ""):
            name, agent, state, rest = m.group(1), m.group(2), m.group(3), (m.group(4) or "")
            out["resources"].append({"name": name, "agent": agent, "state": state, "rest": rest.strip(),
                                     "bundle": bundle if raw.startswith(("    ", "\t\t")) else ""})
    for key in ("online", "offline", "unclean", "standby"):
        out[key] = list(dict.fromkeys(out[key]))
    return out


def resource_status(r):
    """ok | warn | fail of one resource line, with the reason."""
    state, agent, rest = r["state"].lower(), r["agent"].lower(), r["rest"].lower()
    galera = "galera" in agent or "galera" in r["bundle"].lower() or r["name"].startswith("galera")
    if state == "failed":
        return "fail", "FAILED"
    if state == "stopped":
        return ("warn", "stopped (disabled)") if "disabled" in rest else ("fail", "stopped")
    if galera and state in ("slave", "unpromoted"):
        return "fail", "Galera node not promoted (not in sync with the cluster)"
    if state in OK_STATES:
        return "ok", ""
    return "warn", r["state"]


def failed_resource(action):
    """The resource to clean up for a failed action: "rabbitmq_monitor_10000 on rabbitmq-bundle-1 ..." -> rabbitmq-bundle."""
    m = re.search(r"\bon\s+(\S+?-bundle)-\d+\b", action)
    if m:
        return m.group(1)
    return re.split(r"_(?:monitor|start|stop|promote|demote|notify|migrate_to|migrate_from)_", action.split(" on ")[0].strip())[0]


def parse_property(text):
    props = {}
    for line in str(text or "").splitlines():
        m = re.match(r"^\s*([a-z0-9-]+)\s*[:=]\s*(\S+)\s*$", line.strip())
        if m:
            props[m.group(1)] = m.group(2).lower()
    return props


def parse_history(text):
    events = []
    for line in str(text or "").splitlines():
        m = re.search(r"\b(reboot|off|on)\s+of\s+(\S+)\s+(successful|failed|pending)", line)
        if m:
            when = re.search(r"(?:completed|last-failed|last-successful)='([^']+)'", line)
            events.append({"action": m.group(1), "node": m.group(2), "result": m.group(3), "time": when.group(1) if when else "",
                           "line": line.strip()})
    return events


def parse_rabbit(text):
    """rabbitmqctl cluster_status (3.8+ sections, or the 3.7 Erlang terms) -> {"running", "disk", "partitions", "alarms"}."""
    text = str(text or "")
    out = {"running": [], "disk": [], "partitions": [], "alarms": []}
    if "{partitions," in text:   # 3.7
        m = re.search(r"\{partitions,\[(.*?)\]\}", text, re.S)
        out["partitions"] = [x for x in re.findall(r"'?(rabbit@[A-Za-z0-9_.-]+)'?", m.group(1))] if m else []
        m = re.search(r"\{running_nodes,\[(.*?)\]\}", text, re.S)
        out["running"] = re.findall(r"'?(rabbit@[A-Za-z0-9_.-]+)'?", m.group(1)) if m else []
        m = re.search(r"\{disc,\[(.*?)\]\}", text, re.S)
        out["disk"] = re.findall(r"'?(rabbit@[A-Za-z0-9_.-]+)'?", m.group(1)) if m else []
        m = re.search(r"\{alarms,\[(.*?)\]\}\]?\s*$", text, re.S)
        out["alarms"] = re.findall(r"(memory|disk)", m.group(1)) if m else []
        return out
    section = ""
    names = {"disk nodes": "disk", "running nodes": "running", "network partitions": "partitions", "alarms": "alarms"}
    for line in text.splitlines():
        s = line.strip()
        if s.lower() in names:
            section = names[s.lower()]
            continue
        if not s or s == "(none)" or s.startswith(("Cluster status", "Basics", "Cluster name", "Versions", "Maintenance status",
                                                    "Feature flags", "Listeners", "Disk Nodes", "Running Nodes")):
            if s and not s.startswith(("Disk Nodes", "Running Nodes")) and section in ("disk", "running") and not s.startswith("rabbit@"):
                section = ""
            continue
        if section in ("disk", "running") and s.startswith("rabbit@"):
            out[section].append(s.split()[0])
        elif section in ("partitions", "alarms"):
            if re.match(r"^[A-Z][a-z]+ (status|name)", s):
                section = ""
                continue
            out[section].append(s)
    return out


def parse_chrony(text):
    text = str(text or "")
    leap = re.search(r"Leap status\s*:\s*(.+)", text)
    offset = re.search(r"System time\s*:\s*([0-9.]+) seconds (fast|slow)", text)
    return {"leap": leap.group(1).strip() if leap else "",
            "offset": float(offset.group(1)) * (1 if offset.group(2) == "fast" else -1) if offset else None}


def item_out(data, key):
    item = source(data, key)
    return "" if unavailable(item) else str(item.get("out") or "")


# ---------------------------------------------------------------- shared: nodes of the overcloud
def inventory(data, ctx):
    """(nodes, controllers, user, version, problem) from the undercloud reads of phase 1."""
    found, tried = overcloud.nodes(data, json_of, source, unavailable)
    version, user = overcloud.release(data, source)
    user = ctx.get("overcloud_user") or next((n["user"] for n in found if n.get("user") in overcloud.USERS), "") or user
    wanted = [overcloud.short(x) for x in ctx.get("controllers") or []]
    controllers = [n for n in found if (overcloud.short(n["name"]) in wanted if wanted else n["role"] == "controller")]
    problem = ""
    if not found:
        problem = ("The overcloud nodes could not be listed from the undercloud (stackrc on the director). Tried: "
                   + "; ".join(f"{k}: {v[:160]}" for k, v in tried.items()) + ".")
    elif not controllers:
        problem = ("No controller found by name among " + ", ".join(n["name"] for n in found[:8])
                   + ": set director.controllers in sites.yml (the controller node names).")
    return found, controllers, user, version, problem


def reached(data, prefix, nodes):
    """The nodes whose reach read answered (hostname), in order."""
    return [n for i, n in enumerate(nodes) if not unavailable(source(data, f"{prefix}{i}"))
            and str(source(data, f"{prefix}{i}").get("out") or "").strip()]


def reach_step(r, data, prefix, nodes, user, version, title):
    rows, down = [], []
    for i, n in enumerate(nodes):
        item = source(data, f"{prefix}{i}")
        ok = not unavailable(item) and str(item.get("out") or "").strip()
        if not ok:
            down.append(n)
        rows.append([n["name"], n["ip"], n["role"], "reached" if ok else (unavailable(item) or "no answer")[:160]])
    r.step("nodes", title, "fail" if len(down) == len(nodes) else "warn" if down else "ok",
           f"{len(nodes) - len(down)} of {len(nodes)} reached from the director as {user}"
           + (f" (RHOSP {version})" if version else "") + ".",
           {"columns": ["Node", "ctlplane", "Role", "SSH from the director"], "rows": rows}, marks=[n["name"] for n in down])
    return down


# ---------------------------------------------------------------- Pacemaker and fencing
class PacemakerHealth:
    """Pacemaker cluster of the controllers: quorum, nodes, resources (Galera, RabbitMQ, Redis, HAProxy, OVN DBs, VIPs,
    cinder-volume), failed actions, fencing (stonith-enabled, stonith devices, failed and past fencing), the RabbitMQ
    cluster and the time sync of the controllers."""
    sources = ("undercloud", "overcloud")
    phases = 3

    @staticmethod
    def reads(phase, data, params, ctx):
        if phase == 1:
            return {"undercloud": dict(overcloud.INVENTORY_READS)}
        _found, controllers, user, _v, problem = inventory(data, ctx)
        if problem:
            return {}
        if phase == 2:
            return {"overcloud": {f"reach_{i}": overcloud.read(n["name"], n["ip"], user, "reach") for i, n in enumerate(controllers)}}
        up = reached(data, "reach_", controllers)
        out = {}
        for n in up:
            i = controllers.index(n)
            for cmd in ("pcs_status", "rabbit", "chrony"):
                out[f"{cmd}_{i}"] = overcloud.read(n["name"], n["ip"], user, cmd)
        if up:
            first = up[0]
            for cmd in ("pcs_history", "pcs_property", "quorum"):
                out[cmd] = overcloud.read(first["name"], first["ip"], user, cmd)
        return {"overcloud": out}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("pacemaker-health")
        _found, controllers, user, version, problem = inventory(data, ctx)
        if problem:
            r.step("nodes", "Controllers", "fail", problem)
            return r.done()
        down = reach_step(r, data, "reach_", controllers, user, version, "Controllers reached from the director")
        up = [n for n in controllers if n not in down]
        node_where = (f"a controller ({', '.join(n['name'] for n in up[:3])}), as {user} with sudo: from the director, ssh "
                      f"{user}@<its ctlplane address>")
        if not up:
            r.recommend("No controller answers SSH from the director: the controllers or the ctlplane network are down, or "
                        f"the director's key is not accepted for {user}. Check the nodes with Bare metal nodes (BMC power state).",
                        [f"ssh {user}@{controllers[0]['ip']} hostname"], where="OpenStack director, as stack",
                        refs=["rhosp-ironic-troubleshoot"])
            return r.done()
        views = {n["name"]: parse_pcs(item_out(data, f"pcs_status_{controllers.index(n)}")) for n in up}
        main_node = next((n for n in up if views[n["name"]]["resources"] or views[n["name"]]["online"]), up[0])
        pcs = views[main_node["name"]]
        if not (pcs["resources"] or pcs["online"]):
            reason = unavailable(source(data, f"pcs_status_{controllers.index(main_node)}")) or "no output"
            r.step("quorum", "Cluster quorum and nodes", "fail", f"pcs status did not answer on {main_node['name']}: {reason}")
            return r.done()

        # ---------------- quorum and nodes ----------------
        quorate = str(item_out(data, "quorum"))
        q = re.search(r"Quorate:\s*(Yes|No)", quorate)
        quorum_ok = pcs["quorum"] if pcs["quorum"] is not None else (q.group(1) == "Yes" if q else None)
        bad_nodes = pcs["offline"] + pcs["unclean"]
        status = "fail" if quorum_ok is False or bad_nodes else "warn" if pcs["standby"] else "ok"
        detail = (f"Quorum {'yes' if quorum_ok else 'NO' if quorum_ok is False else 'unknown'}; DC {pcs['dc'] or '?'}; "
                  f"online: {', '.join(pcs['online']) or '-'}"
                  + (f"; OFFLINE: {', '.join(pcs['offline'])}" if pcs["offline"] else "")
                  + (f"; UNCLEAN: {', '.join(pcs['unclean'])}" if pcs["unclean"] else "")
                  + (f"; standby: {', '.join(pcs['standby'])}" if pcs["standby"] else "") + ".")
        disagree = [name for name, v in views.items() if v["online"] and sorted(v["online"]) != sorted(pcs["online"])]
        r.step("quorum", "Cluster quorum and nodes", status, detail + (f" {', '.join(disagree)} see(s) other members (split view)." if disagree else ""),
               evidence=redact(item_out(data, f"pcs_status_{controllers.index(main_node)}"))[:4000],
               marks=bad_nodes or (["WITHOUT quorum"] if quorum_ok is False else []))
        if quorum_ok is False or bad_nodes:
            r.recommend(("The cluster has lost quorum: Pacemaker stops the resources it cannot run safely. " if quorum_ok is False else "")
                        + (f"{', '.join(bad_nodes)} is offline or unclean in the cluster: an unclean node is fenced (rebooted "
                           "through its BMC) before its resources move. " if bad_nodes else "")
                        + "Check the node itself (BMC power, Bare metal nodes check), then the corosync rings.",
                        ["sudo pcs status --full", "sudo corosync-cfgtool -s", "sudo corosync-quorumtool -s",
                         "sudo journalctl -u corosync -u pacemaker --since '-2h' --no-pager | tail -n 100"],
                        where=node_where, refs=["rhosp-fencing", "rhosp-fence-daemons"])

        # ---------------- resources ----------------
        rows, bad = [], []
        for res in pcs["resources"]:
            if res["agent"].lower().startswith("stonith:"):
                continue
            st, why = resource_status(res)
            if st != "ok":
                bad.append((res, st, why))
            rows.append([res["bundle"] or "", res["name"], res["agent"], res["state"], res["rest"], st.upper()])
        r.step("resources", "Cluster resources (bundles, VIPs, cinder-volume)", worst(*[b[1] for b in bad]) if bad else "ok",
               f"{len(bad)} of {len(rows)} resource(s) not running as expected." if bad else f"{len(rows)} resource(s), all running.",
               {"columns": ["Bundle / set", "Resource", "Agent", "State", "Node", "Status"],
                "rows": [x for x in rows if x[5] != "OK"] or rows[:60]}, marks=[b[0]["name"] for b in bad])
        failed = pcs["failed_actions"]
        if failed:
            r.step("failed", "Failed resource actions", "warn", f"{len(failed)} failed action(s) recorded.",
                   {"columns": ["Failed action"], "rows": [[x[:300]] for x in failed]})
        names = sorted({(b[0]["bundle"] or b[0]["name"]) for b in bad if "galera" not in (b[0]["bundle"] + b[0]["name"]).lower()}
                       | {failed_resource(x) for x in failed})
        if bad or failed:
            r.recommend("Resources are stopped or failed in Pacemaker. Find the cause first (the resource's log, the node), "
                        "then clear the failure so Pacemaker starts them again; a cleanup alone hides the problem when the "
                        "cause is still there.",
                        ["sudo pcs status --full", "sudo pcs resource failcount show"]
                        + [f"sudo pcs resource cleanup {n}" for n in names[:6] if re.match(r"^[A-Za-z0-9_.:-]+$", n)],
                        where=node_where, refs=["rhosp-pcs-resource", "rhel-pcs-cleanup", "rhosp-bundles"],
                        items={"columns": ["Resource", "State", "Why"], "rows": [[b[0]["name"], b[0]["state"], b[2]] for b in bad]}
                        if bad else None)
        galera = [b for b in bad if "galera" in (b[0]["bundle"] + b[0]["name"] + b[0]["agent"]).lower()]
        if galera:
            r.recommend("Galera is not promoted on every controller: the database cluster runs degraded (or not at all). Read "
                        "mysqld.log on that controller (check Overcloud logs, component galera) before any restart: a "
                        "wrong bootstrap loses data.",
                        ["sudo pcs status | grep -A4 galera", "sudo tail -n 100 /var/log/containers/mysql/mysqld.log"],
                        where=node_where, refs=["rhosp-galera"],
                        warning="Never bootstrap Galera from a node that is not the most advanced one; follow the Red Hat procedure.")

        # ---------------- fencing ----------------
        props = parse_property(item_out(data, "pcs_property"))
        stonith_enabled = props.get("stonith-enabled", "true") != "false"
        devices = [x for x in pcs["resources"] if x["agent"].lower().startswith("stonith:")]
        dev_bad = [d for d in devices if d["state"].lower() not in ("started",)]
        history = parse_history(item_out(data, "pcs_history"))
        failed_fence = pcs["failed_fencing"] + [h["line"] for h in history if h["result"] == "failed"]
        fenced = [h for h in history if h["result"] == "successful"]
        st = "fail" if not stonith_enabled or failed_fence or dev_bad or not devices else "warn" if fenced or props.get("maintenance-mode") == "true" else "ok"
        r.step("fencing", "Fencing (STONITH)", st,
               f"stonith-enabled {'true' if stonith_enabled else 'FALSE'}"
               + (f" ({'set' if 'stonith-enabled' in props else 'default'})" if stonith_enabled else "")
               + f"; {len(devices)} stonith device(s), {len(dev_bad)} not started; {len(failed_fence)} failed fencing action(s); "
               f"{len(fenced)} node(s) fenced in the history" + ("; maintenance-mode is ON" if props.get("maintenance-mode") == "true" else "") + ".",
               {"columns": ["Fencing", "Node / device", "Result / state", "When"],
                "rows": [["device", d["name"], d["state"] + (f" on {d['rest']}" if d["rest"] else ""), ""] for d in devices]
                + [[h["action"], h["node"], h["result"], h["time"]] for h in history[:20]]},
               marks=[d["name"] for d in dev_bad] + [h["node"] for h in history if h["result"] == "failed"])
        if not stonith_enabled:
            r.recommend("Fencing is disabled (stonith-enabled=false): Red Hat does not support an HA overcloud without "
                        "fencing — a hung controller can keep its resources and corrupt data. Enable it again once the "
                        "stonith devices are configured and tested (planned change).",
                        ["sudo pcs property", "sudo pcs stonith status"], where=node_where, refs=["rhosp-fencing"])
        if failed_fence or dev_bad or (stonith_enabled and not devices):
            r.recommend("Fencing failed or a stonith device is not running: when a controller hangs, Pacemaker cannot fence it "
                        "and the cluster stops recovering. The stonith devices use the BMC of each controller: check that the "
                        "BMC answers (Bare metal nodes check: fault 'power failure'; Server hardware (BMC) check) and that its "
                        "account still works.",
                        ["sudo pcs stonith status", "sudo pcs stonith history",
                         "sudo journalctl -u pacemaker --since '-24h' --no-pager | grep -i -E 'stonith|fence' | tail -n 50"],
                        where=node_where, refs=["rhosp-fencing", "rhosp-fence-daemons", "rhosp-ironic-power"],
                        warning="Do not disable fencing to work around it, and do not run pcs stonith fence for a test on a "
                                "controller in use.",
                        items={"columns": ["Fencing problem"], "rows": [[x[:300]] for x in failed_fence]
                               + [[f"{d['name']}: {d['state']}"] for d in dev_bad]})
        if fenced and not failed_fence:
            r.recommend(f"{', '.join(sorted({h['node'] for h in fenced}))} was fenced (rebooted through the BMC) by the cluster: "
                        "find out why (the node hung or lost the cluster network) in the logs of that time.",
                        ["sudo pcs stonith history",
                         "sudo journalctl -u corosync -u pacemaker --since '-24h' --no-pager | grep -i -E 'fence|token|lost|stonith' | tail -n 80"],
                        where=node_where, refs=["rhosp-fencing"])

        # ---------------- RabbitMQ ----------------
        rows, parts, alarms = [], set(), set()
        for n in up:
            i = controllers.index(n)
            item = source(data, f"rabbit_{i}")
            if unavailable(item):
                rows.append([n["name"], "-", "-", "-", unavailable(item)[:160]])
                continue
            rb = parse_rabbit(item.get("out"))
            parts.update(rb["partitions"])
            alarms.update(rb["alarms"])
            rows.append([n["name"], len(rb["running"]), len(rb["disk"]), ", ".join(rb["partitions"]) or "none", ", ".join(rb["alarms"]) or "none"])
        if rows:
            not_all = any(isinstance(x[1], int) and isinstance(x[2], int) and x[1] < x[2] for x in rows)
            r.step("rabbitmq", "RabbitMQ cluster", "fail" if parts else "warn" if alarms or not_all else "ok",
                   ("Network partition: " + ", ".join(sorted(parts)) + ". " if parts else "")
                   + ("Resource alarm: " + ", ".join(sorted(alarms)) + ". " if alarms else "")
                   + ("Not every node is running. " if not_all else "") or "Every node running, no partition, no alarm.",
                   {"columns": ["Seen from", "Running nodes", "Disk nodes", "Partitions", "Alarms"], "rows": rows})
            if parts or alarms or not_all:
                r.recommend("The RabbitMQ cluster is partitioned, missing nodes or blocked by a memory / disk alarm: services "
                            "log 'AMQP server ... is unreachable' / MessagingTimeout and API calls hang. Look at the bundle in "
                            "Pacemaker and the RabbitMQ logs (check Overcloud logs, component rabbitmq) before restarting it.",
                            ["sudo pcs status | grep -A4 rabbitmq",
                             "sudo podman exec $(sudo podman ps -q --filter name=rabbitmq-bundle | head -n 1) rabbitmqctl cluster_status"],
                            where=node_where, refs=["rhosp-bundles", "rhosp-pcs-resource"])

        # ---------------- time ----------------
        rows, worst_t = [], "ok"
        for n in up:
            c = parse_chrony(item_out(data, f"chrony_{controllers.index(n)}"))
            st = ("fail" if "not synchronised" in c["leap"].lower() else "warn" if c["offset"] is not None and abs(c["offset"]) >= 0.5
                  else "ok" if c["leap"] else "skip")
            worst_t = worst(worst_t, st) if st != "skip" else worst_t
            rows.append([n["name"], c["leap"] or "-", f"{c['offset']:+.3f} s" if c["offset"] is not None else "-", st.upper()])
        r.step("time", "Time sync of the controllers (chrony)", worst_t,
               "Galera, RabbitMQ, Pacemaker and Keystone tokens need the controllers in sync.",
               {"columns": ["Controller", "Leap status", "Offset", "Status"], "rows": rows})
        if worst_t != "ok":
            r.recommend("A controller is not in sync with its NTP servers: check chronyd and the NTP sources from that node.",
                        ["chronyc tracking", "chronyc sources -v", "sudo systemctl status chronyd --no-pager"], where=node_where)

        # ---------------- daemons ----------------
        daemons = pcs["daemons"]
        if daemons:
            badd = {k: v for k, v in daemons.items() if not v.startswith("active")}
            r.step("daemons", "Cluster daemons", "fail" if badd else "ok",
                   ", ".join(f"{k}: {v}" for k, v in daemons.items()) + ".", marks=list(badd))
        return r.done()


# ---------------------------------------------------------------- logs
LOG_TIME = re.compile(r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})")
PATTERNS = (  # regex, label, how serious, what it means, vendor references
    (r"VirtualInterfaceCreateException|Timeout waiting for \[\('network-vif-plugged'|vif.*plug.*time(d)? ?out",
     "Instance network not plugged in time (network-vif-plugged)", "fail",
     "Nova waited for Neutron to confirm the port of the instance and gave up: the instance fails to build or move. Look "
     "at ovn-controller / the OVN agent of that compute and at neutron-server.", ["rhosp-ovn"]),
    (r"No valid host was found", "No valid host (scheduler)", "warn",
     "The scheduler found no compute for the request: capacity, the aggregate / flavor properties, or computes down.", []),
    (r"Failed to bind port|binding_failed|PortBindingFailed", "Port binding failed", "fail",
     "Neutron could not bind the port to the compute: the OVN controller (or OVS agent) of that compute is down or "
     "misconfigured.", ["rhosp-ovn"]),
    (r"No more IP addresses available|IpAddressGenerationFailure", "Subnet out of addresses", "warn",
     "A subnet (or the floating IP pool) has no free address left.", ["rhosp-floating-ip"]),
    (r"AMQP server on .* is unreachable|MessagingTimeout|Timed out waiting for a reply|AMQP.*Connection reset",
     "RabbitMQ unreachable / message timeouts", "fail",
     "Services cannot talk through RabbitMQ: API calls hang or fail. Check the RabbitMQ cluster (Pacemaker and fencing check).",
     ["rhosp-bundles"]),
    (r"WSREP has not yet prepared node|WSREP.*non-Primary|Lost connection to MySQL|Can't connect to MySQL|DBConnectionError|"
     r"Deadlock found when trying to get lock", "Database (Galera) not available", "fail",
     "Services lost the database or Galera is not in a primary component.", ["rhosp-galera"]),
    (r"NetAppDriverException|VolumeBackendAPIException|No valid backend was found", "Block storage backend error", "fail",
     "Cinder could not do the operation on the NetApp backend (unreachable, credentials, pool full).", ["rhosp-cinder-ha"]),
    (r"Unable to obtain correct plug status|stonith.*(failed|error)|fence.*(failed|timed out)|Fencing.*failed",
     "Fencing failed", "fail", "Pacemaker could not fence a node through its BMC.", ["rhosp-fencing", "rhosp-fence-daemons"]),
    (r"A processor failed, forming new configuration|Token has not been received|Retransmit List|corosync.*(lost|failed)",
     "Corosync membership changes (cluster network)", "warn",
     "The controllers lost each other on the cluster network: a node may be fenced. Check the network of the controllers.",
     ["rhosp-fencing"]),
    (r"is DOWN|has no server available|NOSRV", "HAProxy backend down", "warn",
     "HAProxy marked an API backend down (or had none for a request): the service of that backend does not answer on a "
     "controller.", ["rhosp-pcs-resource"]),
    (r"Out of memory: Killed process|oom-kill|invoked oom-killer", "Out of memory (OOM killer)", "fail",
     "The kernel killed processes for lack of memory on the node.", []),
    (r"nf_conntrack: table full", "Connection tracking table full", "fail",
     "The node drops new connections (conntrack table full).", []),
    (r"mce: \[Hardware Error\]|EDAC .* (CE|UE)|Machine Check|Hardware Error", "Hardware error (memory / CPU)", "fail",
     "The kernel reports hardware errors: read the BMC event log of this server (check Server hardware (BMC)).", []),
    (r"I/O error, dev|blk_update_request: I/O error|Buffer I/O error|failing path|remaining active paths: 0",
     "Disk / storage path errors", "fail", "The node reports I/O errors or lost storage paths.", []),
    (r"Unauthorized|The request you have made requires authentication", "Authentication failures", "info",
     "Requests with expired or wrong credentials (often a client, not the platform).", []),
)


def classify(message):
    for pattern, label, level, meaning, refs in PATTERNS:
        if re.search(pattern, message, re.I):
            return label, level, meaning, refs
    return None


def norm(message):
    """A message without IDs, numbers and addresses: lines of the same error group together."""
    text = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|req-\S+|\b\d+(\.\d+)*\b|0x[0-9a-f]+", "#", message, flags=re.I)
    return re.sub(r"\s+", " ", text).strip()[:140]


class OvercloudLogs:
    """Logs of the overcloud nodes for the last hours: OpenStack services (nova, neutron / OVN, cinder, keystone, glance),
    RabbitMQ, Galera, HAProxy, Pacemaker / corosync and the kernel, on the controllers (and the compute of an
    instance, or a node named). Known problems are recognised and linked to Red Hat; for an instance, its request IDs
    (openstack server event list) are followed through the logs."""
    sources = ("undercloud", "openstack", "overcloud")
    phases = 3

    @staticmethod
    def _targets(data, params, ctx):
        found, controllers, user, version, problem = inventory(data, ctx)
        targets = list(controllers)
        server = json_of(source(data, "server")) or {}
        host = overcloud.short(server.get("OS-EXT-SRV-ATTR:hypervisor_hostname") or server.get("OS-EXT-SRV-ATTR:host") or "") if isinstance(server, dict) else ""
        def same(n, w):
            name = overcloud.short(n["name"])
            return bool(w) and (name == w or name.endswith(w))
        node = overcloud.short(params.get("node"))
        for w in (host, node):
            n = next((n for n in found if same(n, w)), None)
            if n and n not in targets:
                targets.append(n)
        if node and not any(same(n, node) for n in found):
            problem = problem or f"Node {params['node']} is not an overcloud node of this site."
        if node and not params.get("instance"):   # a node named: that node only
            targets = [n for n in targets if same(n, node)]
        return found, targets, user, version, problem, host

    @staticmethod
    def _ids(data, params):
        ids = [x for x in (params.get("instance"), params.get("request_id")) if x]
        for e in json_of(source(data, "events")) or []:
            if isinstance(e, dict) and overcloud.REQ_RE.match(str(e.get("Request ID") or "")):
                ids.append(e["Request ID"])
        return list(dict.fromkeys(ids))[:6]

    @staticmethod
    def reads(phase, data, params, ctx):
        if phase == 1:
            out = {"undercloud": dict(overcloud.INVENTORY_READS)}
            if params.get("instance"):
                out["openstack"] = {"server": f"openstack server show {params['instance']} -f json",
                                    "events": f"openstack server event list {params['instance']} -f json"}
            return out
        _found, targets, user, _v, problem, _h = OvercloudLogs._targets(data, params, ctx)
        if problem and not targets:
            return {}
        if phase == 2:
            return {"overcloud": {f"reach_{i}": overcloud.read(n["name"], n["ip"], user, "reach") for i, n in enumerate(targets)}}
        hours = int(params.get("hours") or 6)
        component = params.get("component") or "all"
        ids = OvercloudLogs._ids(data, params)
        out = {}
        for i, n in enumerate(targets):
            if n not in reached(data, "reach_", targets):
                continue
            comps = overcloud.COMPONENTS if component == "all" else (component,)
            if ids:
                comps = [c for c in comps if c in ("nova", "neutron", "cinder")]
            if n["role"] != "controller":
                comps = [c for c in comps if c not in overcloud.CONTROLLER_ONLY]
            for c in comps:
                out[f"log_{i}_{c}"] = overcloud.read(n["name"], n["ip"], user, "log", c, hours, *ids)
        return {"overcloud": out}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("overcloud-logs")
        found, targets, user, version, problem, host = OvercloudLogs._targets(data, params, ctx)
        if problem:
            r.step("nodes", "Overcloud nodes", "fail" if not targets else "warn", problem)
            if not targets:
                return r.done()
        hours = int(params.get("hours") or 6)
        ids = OvercloudLogs._ids(data, params)
        if params.get("instance"):
            item = source(data, "server")
            n_req = sum(1 for i in ids if i.startswith("req-"))
            r.step("instance", f"Instance {params['instance']}", "fail" if unavailable(item) else "info",
                   unavailable(item) or f"On {host or 'no compute'}; the instance ID and {n_req} request ID(s) of its actions are "
                   "followed through the logs.",
                   {"columns": ["Request ID", "Action", "Start"],
                    "rows": [[e.get("Request ID"), e.get("Action"), e.get("Start Time")] for e in json_of(source(data, "events")) or [] if isinstance(e, dict)][:20]})
        down = reach_step(r, data, "reach_", targets, user, version, "Nodes whose logs are read")
        entries = []
        for i, n in enumerate(targets):
            if n in down:
                continue
            for c in overcloud.COMPONENTS:
                item = source(data, f"log_{i}_{c}")
                if unavailable(item) and "was not collected" in unavailable(item):
                    continue
                for line in str(item.get("out") or "").splitlines():
                    line = redact(line).strip()
                    if not line or line.startswith(("-- No entries --", "-- Logs begin")):
                        continue
                    m = LOG_TIME.search(line[:120])
                    file = line.split(": ", 1)[0] if line.startswith("/var/log/") else c
                    message = line.split(": ", 1)[1] if line.startswith("/var/log/") and ": " in line else line
                    level = ("error" if re.search(r" (ERROR|CRITICAL) |\[(error|ERROR|critical)\]", message)
                             or (c in ("pacemaker", "kernel", "haproxy", "galera")) else "warning")
                    entries.append({"node": n["name"], "component": c, "file": file.rsplit("/", 1)[-1],
                                    "time": m.group(1).replace("T", " ") if m else "", "level": level, "message": message})
        known, other = {}, {}
        for e in entries:
            hit = classify(e["message"])
            if hit:
                g = known.setdefault(hit[0], {"hit": hit, "items": []})
                g["items"].append(e)
            elif e["level"] == "error":
                other.setdefault((e["component"], norm(e["message"])), []).append(e)
        rank = {"fail": 0, "warn": 1, "info": 2}
        order = sorted(known.items(), key=lambda kv: (rank[kv[1]["hit"][1]], -len(kv[1]["items"])))
        status = worst(*[g["hit"][1] for g in known.values() if g["hit"][1] != "info"]) if any(g["hit"][1] != "info" for g in known.values()) else (
            "warn" if other else "ok")
        r.step("known", f"Known problems in the logs (last {hours} h)", status,
               f"{len(entries)} line(s) read; {sum(len(g['items']) for g in known.values())} match {len(known)} known problem(s)."
               if entries else "No warning or error line.",
               {"columns": ["Problem", "Lines", "Nodes", "First", "Last"],
                "rows": [[label, len(g["items"]), ", ".join(sorted({e["node"] for e in g["items"]})),
                          min((e["time"] for e in g["items"] if e["time"]), default=""), max((e["time"] for e in g["items"] if e["time"]), default="")]
                         for label, g in order]},
               marks=[label for label, g in order if g["hit"][1] == "fail"])
        if other:
            rows = sorted(other.items(), key=lambda kv: -len(kv[1]))[:25]
            r.step("other", "Other errors (grouped)", "warn", f"{len(other)} kind(s) of error not in the known list.",
                   {"columns": ["Component", "Lines", "Nodes", "Last", "Message"],
                    "rows": [[c, len(items), ", ".join(sorted({e["node"] for e in items})),
                              max((e["time"] for e in items if e["time"]), default=""), items[-1]["message"][:220]] for (c, _), items in rows]})
        if ids:
            timeline = sorted(entries, key=lambda e: e["time"])
            r.step("timeline", "Timeline of the instance's requests", "info", f"{len(timeline)} line(s) naming the instance or its request IDs.",
                   {"columns": ["Time", "Node", "File", "Message"],
                    "rows": [[e["time"], e["node"], e["file"], e["message"][:260]] for e in timeline[:150]]})
        for label, g in order:
            _label, level, meaning, refs = g["hit"]
            if level == "info":
                continue
            items = g["items"]
            sample = "\n".join(f"{e['node']} {e['file']}: {e['message'][:300]}" for e in items[-8:])
            nodes = sorted({e["node"] for e in items})
            comps = sorted({e["component"] for e in items})
            r.recommend(f"{label}: {len(items)} line(s) on {', '.join(nodes)}. {meaning}",
                        [grep_command(c, PATTERNS_BY_LABEL[label], hours) for c in comps],
                        where=f"{', '.join(nodes[:3])}, as {user} with sudo (from the director: ssh {user}@<ctlplane address of the node>)",
                        refs=refs, items={"columns": ["Last lines"], "rows": [[x] for x in sample.splitlines()]})
        return r.done()


PATTERNS_BY_LABEL = {label: pattern for pattern, label, *_ in PATTERNS}


def grep_command(component, pattern, hours):
    """The command an engineer runs on the node to see the same lines (journal or the component's log files)."""
    pat = shlex.quote(pattern)
    if component == "pacemaker":
        return f"sudo journalctl -u pacemaker -u corosync --since '-{hours}h' --no-pager | grep -i -E {pat} | tail -n 50"
    if component == "kernel":
        return f"sudo journalctl -k --since '-{hours}h' --no-pager | grep -i -E {pat} | tail -n 50"
    files = {"rabbitmq": "/var/log/containers/rabbitmq/rabbit@*.log", "galera": "/var/log/containers/mysql/mysqld.log",
             "haproxy": "/var/log/containers/haproxy/haproxy.log"}.get(component) or " ".join(overcloud.LOG_FILES.get(component, []))
    return f"sudo grep -h -i -E {pat} {files} 2>/dev/null | tail -n 50"

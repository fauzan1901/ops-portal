"""Operation Automation checks of NetApp ONTAP, read with the site's read-only ONTAP account (REST GET only)."""
import datetime
import re

from .common import Result, json_of, source, unavailable


def records(item):
    data = json_of(item) or {}
    return data.get("records") or [] if isinstance(data, dict) else []


class OntapClusterHealth:
    """WI "NetApp Cluster Management Recovery": node health, the cluster management LIF on its home port, other LIFs
    that are down or not home, service processors, e0M ports, and recent error events."""
    sources = ("ontap",)
    phases = 1

    @staticmethod
    def reads(phase, data, params, ctx):
        return {"ontap": {
            "cluster": "/api/cluster?fields=name,version,management_interfaces",
            "nodes": "/api/cluster/nodes?fields=name,state,membership,service_processor.state,"
                     "service_processor.ipv4_interface.address&max_records=50",
            "node_cli": "/api/private/cli/system/node?fields=node,health,eligibility",
            "lifs": "/api/network/ip/interfaces?fields=uuid,name,svm.name,scope,ip,state,enabled,location.home_node.name,"
                    "location.home_port.name,location.node.name,location.port.name,location.is_home,service_policy.name"
                    "&max_records=1000",
            "ports": "/api/network/ethernet/ports?name=e0M&fields=node.name,name,state,enabled",
            "events": "/api/support/ems/events?fields=time,node.name,message.severity,message.name,log_message"
                      "&message.severity=error|alert|emergency&order_by=time%20desc&max_records=30"}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("ontap-cluster-health")
        cluster_item = source(data, "cluster")
        if unavailable(cluster_item):
            r.step("cluster", "Reach the cluster (REST API)", "fail", unavailable(cluster_item))
            return r.done()
        cluster = json_of(cluster_item) or {}
        name = cluster.get("name") or "?"
        version = (cluster.get("version") or {}).get("full", "") if isinstance(cluster.get("version"), dict) else ""
        r.step("cluster", "Reach the cluster (REST API)", "ok", f"Cluster {name}, {version or 'version unknown'}.")
        nodes = records(source(data, "nodes"))
        cli = {x.get("node"): x for x in records(source(data, "node_cli"))}
        bad, rows = [], []
        for n in nodes:
            c = cli.get(n.get("name"), {})
            health, elig = c.get("health"), c.get("eligibility")
            ok = n.get("state") == "up" and health is not False and elig is not False
            if not ok:
                bad.append(n.get("name"))
            sp = n.get("service_processor") or {}
            rows.append([n.get("name"), n.get("state"), n.get("membership") or "-", "-" if health is None else str(health).lower(),
                         "-" if elig is None else str(elig).lower(), sp.get("state") or "-",
                         (sp.get("ipv4_interface") or {}).get("address") or "-"])
        r.step("nodes", "Node health and eligibility", "fail" if bad or not nodes else "ok",
               f"Not healthy: {', '.join(bad)}. Stop here and escalate to the storage team." if bad else
               f"{len(nodes)} node(s) up, healthy and eligible." if nodes else f"Nodes not read: {unavailable(source(data, 'nodes'))}",
               {"columns": ["Node", "State", "Membership", "Health", "Eligibility", "SP/BMC", "SP address"], "rows": rows})
        sp_off = [x[0] for x in rows if x[5] not in ("online", "-")]
        r.step("sp", "Service processor / BMC online (emergency path)", "warn" if sp_off else "ok",
               f"Not online: {', '.join(sp_off)}." if sp_off else "Every SP/BMC is online.")
        lifs = records(source(data, "lifs"))
        mgmt = [l for l in lifs if l.get("name") == "cluster_mgmt"]
        if not mgmt:
            r.step("cluster_mgmt", "Cluster management LIF on its home port", "fail",
                   "LIF cluster_mgmt not found" + (f": {unavailable(source(data, 'lifs'))}" if unavailable(source(data, "lifs")) else "."))
        for l in mgmt:
            loc = l.get("location") or {}
            home = f"{(loc.get('home_node') or {}).get('name')} {(loc.get('home_port') or {}).get('name')}"
            cur = f"{(loc.get('node') or {}).get('name')} {(loc.get('port') or {}).get('name')}"
            up = l.get("state") == "up" and l.get("enabled", True)
            is_home = loc.get("is_home") is not False
            svm = (l.get("svm") or {}).get("name") or name
            r.step("cluster_mgmt", "Cluster management LIF on its home port", "ok" if up and is_home else "fail",
                   f"cluster_mgmt {(l.get('ip') or {}).get('address', '')} is {'up' if up else 'DOWN'} on {cur}; home {home}; "
                   f"is-home {str(is_home).lower()}.")
            if not up or not is_home:
                home_node = (loc.get("home_node") or {}).get("name")
                home_port = (loc.get("home_port") or {}).get("name")
                # Log in on the node management LIF of the home node: the session must not depend on cluster_mgmt.
                def node_mgmt_lif(x):
                    on_home = ((x.get("location") or {}).get("home_node") or {}).get("name") == home_node
                    mgmt = "mgmt" in str(x.get("name")) or "management" in str((x.get("service_policy") or {}).get("name"))
                    return x.get("name") != "cluster_mgmt" and on_home and mgmt
                node_mgmt = next((x for x in lifs if node_mgmt_lif(x)), None)
                node_ip = ((node_mgmt or {}).get("ip") or {}).get("address", "")
                node_ips = [((x.get("ip") or {}).get("address") or "") for x in lifs if node_mgmt_lif(x)]
                node_ips += [((x.get("ip") or {}).get("address") or "") for x in lifs if x.get("name") != "cluster_mgmt"
                             and ("mgmt" in str(x.get("name")) or "management" in str((x.get("service_policy") or {}).get("name")))]
                action = {"kind": "ontap", "op": "revert_lif", "uuid": l.get("uuid"), "lif": "cluster_mgmt", "enable": not up,
                          "hosts": list(dict.fromkeys(ip for ip in node_ips if ip)),
                          "summary": ("Bring cluster_mgmt up and revert it" if not up else "Revert cluster_mgmt")
                                     + f" to {home}, through the cluster or a node management address (ONTAP REST)"} \
                    if re.match(r"^[0-9a-f-]{36}$", str(l.get("uuid") or "")) else None
                r.recommend(("Bring cluster_mgmt up and revert it" if not up else f"Revert cluster_mgmt from {cur}") + f" to its home port "
                            f"{home}, logged in on the node management IP of "
                            f"{home_node}{' (' + node_ip + ')' if node_ip else ''}, after checking that {home_port} is up. Only this LIF.",
                            [f"network port show -node {home_node} -port {home_port} -fields link,mtu,broadcast-domain",
                             f"network interface show -vserver {svm} -lif cluster_mgmt -failover"]
                            + ([f"network interface modify -vserver {svm} -lif cluster_mgmt -status-admin up"] if not up else []) + [
                             f"network interface revert -vserver {svm} -lif cluster_mgmt",
                             f"network interface show -vserver {svm} -lif cluster_mgmt -fields curr-node,curr-port,is-home,status-oper",
                             f"network interface show -vserver {svm} -lif cluster_mgmt -fields auto-revert"],
                            where=f"ONTAP CLI: ssh admin@{node_ip}" if node_ip else f"ONTAP CLI on the node management IP of {home_node}",
                            warning="The revert can drop SSH/HTTPS sessions on the cluster management IP. Review auto-revert "
                                    "with the storage team afterwards (change approval needed).", action=action)
        others = [l for l in lifs if l.get("name") != "cluster_mgmt"]
        down = [l for l in others if l.get("state") != "up"]
        away = [l for l in others if (l.get("location") or {}).get("is_home") is False]
        r.step("lifs", "Other LIFs down or not on their home port", "warn" if down or away else "ok",
               f"{len(down)} down, {len(away)} not home (of {len(others)}). Check these separately: do not revert data LIFs "
               "in bulk." if down or away else f"All {len(others)} other LIFs are up and home.",
               {"columns": ["LIF", "SVM", "State", "Current", "Home", "Home?"],
                "rows": [[l.get("name"), (l.get("svm") or {}).get("name", ""), l.get("state"),
                          f"{((l.get('location') or {}).get('node') or {}).get('name')} {((l.get('location') or {}).get('port') or {}).get('name')}",
                          f"{((l.get('location') or {}).get('home_node') or {}).get('name')} {((l.get('location') or {}).get('home_port') or {}).get('name')}",
                          str((l.get("location") or {}).get("is_home")).lower()] for l in (down + [x for x in away if x not in down])]})
        ports = records(source(data, "ports"))
        pdown = [p for p in ports if p.get("state") != "up"]
        down_names = [f"{(p.get('node') or {}).get('name', '?')} e0M" for p in pdown]
        r.step("e0m", "Management ports (e0M) up", "fail" if pdown else "ok" if ports else "skip",
               f"Down: {', '.join(down_names)}." if pdown else f"{len(ports)} e0M port(s) up." if ports else "e0M ports were not read.")
        events = records(source(data, "events"))
        now = datetime.datetime.now(datetime.timezone.utc)
        recent = []
        for e in events:
            try:
                t = datetime.datetime.fromisoformat(str(e.get("time")).replace("Z", "+00:00"))
            except ValueError:
                continue
            if (now - t).total_seconds() <= 24 * 3600:
                recent.append([e.get("time"), (e.get("node") or {}).get("name", ""), (e.get("message") or {}).get("severity", ""),
                               (e.get("message") or {}).get("name", ""), str(e.get("log_message") or "")[:200]])
        r.step("events", "Error events of the last 24 hours", "warn" if recent else "ok",
               f"{len(recent)} event(s) of severity error or worse." if recent else "None.",
               {"columns": ["Time", "Node", "Severity", "Event", "Message"], "rows": recent})
        return r.done()

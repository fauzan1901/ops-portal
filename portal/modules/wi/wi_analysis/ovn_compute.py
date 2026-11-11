"""OVN and Nova consistency of OpenStack Cloud (RISET-KNOWN-ISSUES.md 2.1 #4, #6 and 2.3 #1-4): the metadata service of each
compute (ovnmeta namespaces and their haproxy sidecars), the chassis of the OVN Southbound that no node runs any more,
Nova against libvirt and the cell mapping, and the allocations of Placement. Read only, on the overcloud nodes through the
director (ssh heat-admin / tripleo-admin with sudo, as the other overcloud checks) and the OpenStack API (overcloudrc).
One fix runs from the portal: a stale chassis deleted from the Southbound (wi_ops.py chassis-del, read again on the node
before and after, through the review of fixes); restarts and Placement changes stay commands for the engineer.
"""
import json
import re

from . import overcloud
from .common import Result, first_line, json_of, source, unavailable
from .openstack import UUID, os_select
from .openstack_ops import node_of
from .overcloud_checks import inventory, item_out

MAX_NODES = 63
FRESH_SECONDS = 600          # a chassis whose ovn-controller answered nb_cfg in the last 10 minutes is alive
RSS_WARN_GB, RSS_FAIL_GB = 8, 32   # neutron-server memory of one controller (Red Hat 6410121: 73.5 GB before the OOM)
HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
NET_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def sections(text):
    """{"name": [lines]} of a read that prints @@name markers; "@@rc 3" lines go to {"rc:<section>": 3}."""
    out, cur = {}, ""
    for line in str(text or "").splitlines():
        m = re.match(r"^@@(\w+)(?: (.*))?$", line.strip())
        if m and m.group(1) == "rc":
            out[f"rc:{cur}"] = int(m.group(2)) if (m.group(2) or "").strip().lstrip("-").isdigit() else None
            continue
        if m:
            cur = m.group(1)
            out.setdefault(cur, [])
            if m.group(2):
                out[f"{cur}:arg"] = m.group(2).strip()
            continue
        if line.strip():
            out.setdefault(cur, []).append(line.rstrip())
    return out


def reached(item):
    """The node answered SSH (ssh itself exits 255 when it cannot connect or log in)."""
    return bool(item) and not item.get("skipped") and str(item.get("rc")) != "255"


def computes_of(found, params):
    """The compute nodes to read: the one given (node or Nova name), else every compute (at most MAX_NODES)."""
    want = str(params.get("compute") or "").strip()
    if want:
        n = node_of(want, found)
        return [n] if n else []
    return [n for n in found if n["role"] == "compute"][:MAX_NODES]


def ovsdb_rows(text):
    """Rows of `ovn-sbctl --format=json list <table>` as dicts; a ["uuid", x] cell becomes x."""
    try:
        doc = json.loads(text)
    except (ValueError, TypeError):
        return None
    heads = doc.get("headings") or []
    rows = []
    for row in doc.get("data") or []:
        cells = [c[1] if isinstance(c, list) and len(c) == 2 and c[0] in ("uuid", "named-uuid") else
                 ("" if isinstance(c, list) else c) for c in row]
        rows.append(dict(zip(heads, cells)))
    return rows


def age_text(seconds):
    if seconds is None:
        return "never"
    if seconds < 120:
        return f"{int(seconds)} s ago"
    if seconds < 7200:
        return f"{int(seconds // 60)} min ago"
    if seconds < 172800:
        return f"{int(seconds // 3600)} h ago"
    return f"{int(seconds // 86400)} days ago"


def controllers_step(r, data, prefix, controllers, user, version):
    """(index, node) of the controllers that answered the read `prefix`<i>, with the step that says so."""
    up = [(i, n) for i, n in enumerate(controllers) if reached(source(data, f"{prefix}{i}"))]
    down = [n["name"] for i, n in enumerate(controllers) if (i, n) not in up]
    r.step("nodes", "Controllers reached from the director", "ok" if up and not down else "warn" if up else "fail",
           f"{len(up)} of {len(controllers)} controller(s) answered as {user} (RHOSP {version or '?'})"
           + (f"; not reached: {', '.join(down)}." if down else "."))
    return up


# ---------------------------------------------------------------------------------------------------- OVN metadata
class OvnMetadata:
    """The metadata service of OVN on each compute: one ovnmeta-<network> namespace per network with ports there, each
    served by its haproxy sidecar (neutron-haproxy-ovnmeta-<network>) of ovn_metadata_agent. A namespace without a
    running sidecar: cloud-init and SSH keys of the instances of that network fail (169.254.169.254 refused)."""
    sources = ("undercloud", "overcloud")
    phases = 2

    @staticmethod
    def reads(phase, data, params, ctx):
        if phase == 1:
            return {"undercloud": dict(overcloud.INVENTORY_READS)}
        found, _c, user, _v, problem = inventory(data, ctx)
        if problem:
            return {}
        out = {f"meta_{i}": overcloud.read(n["name"], n["ip"], user, "ovn_meta") for i, n in enumerate(computes_of(found, params))}
        return {"overcloud": out} if out else {}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("ovn-metadata")
        found, _c, user, version, problem = inventory(data, ctx)
        if problem:
            r.step("nodes", "Computes reached from the director", "fail", problem)
            return r.done()
        nodes = computes_of(found, params)
        if not nodes:
            r.step("nodes", "Computes reached from the director", "fail",
                   f"No compute node {params.get('compute')!r} among the overcloud nodes." if params.get("compute") else
                   "No compute node among the overcloud nodes.")
            return r.done()
        up = [(i, n) for i, n in enumerate(nodes) if reached(source(data, f"meta_{i}"))]
        down = [n["name"] for i, n in enumerate(nodes) if (i, n) not in up]
        r.step("nodes", "Computes reached from the director", "ok" if not down else "warn" if up else "fail",
               f"{len(up)} of {len(nodes)} compute(s) answered as {user} (RHOSP {version or '?'})"
               + (f"; not reached: {', '.join(down)}." if down else "."))
        agent_rows, ns_rows, err_rows = [], [], []
        agent_bad, ns_bad, ns_warn, missing_cmds = [], [], [], []
        for i, n in up:
            sec = sections(item_out(data, f"meta_{i}"))
            nets = sorted({x[len("ovnmeta-"):] for x in sec.get("ns", []) if x.startswith("ovnmeta-")})
            ctrs = {}
            for line in sec.get("ctr", []):
                name, _, status = line.partition(" ")
                ctrs[name] = status
            agent = ctrs.get("ovn_metadata_agent", "")
            if not agent.startswith("Up"):
                agent_bad.append(n["name"])
            agent_rows.append([n["name"], agent or "not found"])
            side = {k[len("neutron-haproxy-ovnmeta-"):]: v for k, v in ctrs.items() if k.startswith("neutron-haproxy-ovnmeta-")}
            running = {k for k, v in side.items() if v.startswith("Up")}
            exited = sorted(k for k, v in side.items() if not v.startswith("Up"))
            missing = sorted(x for x in nets if x not in running)
            orphan = sorted(k for k in running if k not in nets)
            if missing:
                ns_bad.append(n["name"])
                missing_cmds += [f"sudo podman ps -a --filter name=neutron-haproxy-ovnmeta-{x}   # {n['name']}" for x in missing]
            elif orphan:
                ns_warn.append(n["name"])
            ns_rows.append([n["name"], len(nets), len(running), ", ".join(missing) or "-", ", ".join(exited) or "-",
                            ", ".join(orphan) or "-"])
            errs = sec.get("err", [])
            if errs:
                last = re.sub(r"^\S+ \S+ \d+ ", "", errs[-1])[:160]
                err_rows.append([n["name"], len(errs), last])
        r.step("agent", "ovn_metadata_agent on each compute", "fail" if agent_bad else "ok" if up else "skip",
               (f"Not running on {', '.join(agent_bad)}: no instance there gets its metadata." if agent_bad else
                f"Running on the {len(up)} compute(s) read." if up else "No compute read."),
               {"columns": ["Compute", "Container"], "rows": agent_rows}, marks=agent_bad)
        r.step("sidecars", "Metadata namespaces and their haproxy sidecars",
               "fail" if ns_bad else "warn" if ns_warn else "ok" if up else "skip",
               (f"A namespace without a running sidecar on {', '.join(ns_bad)}: instances of those networks there get no "
                "metadata (cloud-init, SSH key, hostname)." if ns_bad else
                f"A sidecar without its namespace on {', '.join(ns_warn)} (left over after a network left the compute)."
                if ns_warn else "Every ovnmeta namespace has its sidecar running."),
               {"columns": ["Compute", "Namespaces", "Sidecars up", "Without sidecar", "Sidecar exited", "Sidecar without namespace"],
                "rows": ns_rows}, marks=ns_bad + ns_warn)
        r.step("errors", "Errors of the metadata agent (24 h)", "warn" if err_rows else "ok" if up else "skip",
               (f"ERROR / CRITICAL lines on {', '.join(x[0] for x in err_rows)}." if err_rows else
                "No ERROR or CRITICAL line in /var/log/containers/neutron/ovn-metadata-agent.log in the last 24 hours."),
               {"columns": ["Compute", "Lines", "Last"], "rows": err_rows} if err_rows else None)
        where = f"the compute, as {user} with sudo: from the director, ssh {user}@<its ctlplane address>"
        if agent_bad or ns_bad:
            r.recommend("Restart the metadata agent of the compute: it starts the missing sidecars again. Running instances "
                        "keep their network; only metadata requests during the restart fail.",
                        ["sudo systemctl status tripleo_ovn_metadata_agent", *missing_cmds,
                         "sudo grep -E ' (ERROR|CRITICAL) ' /var/log/containers/neutron/ovn-metadata-agent.log | tail -20",
                         "sudo systemctl restart tripleo_ovn_metadata_agent",
                         "sudo ip netns | grep -c ovnmeta-; sudo podman ps --format '{{.Names}}' | grep -c haproxy-ovnmeta"],
                        where=where, refs=["rhosp-containers"],
                        warning="A restart of a service on a compute with customer instances: as any restart, with a ticket.")
        return r.done()


# ---------------------------------------------------------------------------------------------------- stale chassis
def chassis_view(data, agents, found):
    """[{name, uuid, host, alive, seen, ports, gateway, node}] from the Southbound reads and the Neutron agents."""
    sec = sections(item_out(data, "chassis"))
    rows = ovsdb_rows("\n".join(sec.get("", []))) or []
    priv = {str(x.get("name")): x.get("nb_cfg_timestamp") for x in ovsdb_rows("\n".join(sec.get("priv", []))) or []}
    now = next((int(x) for x in sec.get("now", []) if str(x).strip().isdigit()), None)
    ports = {}
    for line in sec.get("ports", []):
        m = re.match(r"^\s*(\d+)\s*(\S*)\s*$", line)
        if m and m.group(2):
            ports[m.group(2)] = int(m.group(1))
    gw = sections(item_out(data, "gw"))
    gateways = {x.strip() for k in ("gw", "ha") for x in gw.get(k, []) if x.strip()}
    alive = {str(a.get("ID")): bool(a.get("Alive")) for a in agents if "OVN Controller" in str(a.get("Agent Type") or "")}
    out = []
    for c in rows:
        name, host = str(c.get("name") or ""), str(c.get("hostname") or "")
        ts = priv.get(name)
        seen = (now - int(ts) / 1000) if now and isinstance(ts, (int, float)) and ts > 0 else None
        out.append({"name": name, "uuid": str(c.get("_uuid") or ""), "host": host, "alive": alive.get(name),
                    "seen": seen, "ports": ports.get(str(c.get("_uuid") or ""), 0), "gateway": name in gateways,
                    "node": node_of(host, found)})
    return out


class OvnChassisStale:
    """Chassis of the OVN Southbound that no ovn-controller runs any more (after a reinstall, a new system-id or a node
    removed): their agent is dead or gone in Neutron and they have not answered nb_cfg for 10 minutes. A router gateway
    scheduled on such a chassis breaks north-south traffic; duplicate agents of one host confuse the scheduling."""
    sources = ("openstack", "undercloud", "overcloud")
    phases = 3

    @staticmethod
    def reads(phase, data, params, ctx):
        if phase == 1:
            return {"openstack": {"agents": "openstack network agent list -f json"},
                    "undercloud": dict(overcloud.INVENTORY_READS)}
        _f, controllers, user, _v, problem = inventory(data, ctx)
        if problem:
            return {}
        if phase == 2:
            return {"overcloud": {f"reach_{i}": overcloud.read(n["name"], n["ip"], user, "reach")
                                  for i, n in enumerate(controllers)}}
        up = [n for i, n in enumerate(controllers) if reached(source(data, f"reach_{i}"))]
        if not up:
            return {}
        n = up[0]
        return {"overcloud": {"chassis": overcloud.read(n["name"], n["ip"], user, "ovn_chassis"),
                              "gw": overcloud.read(n["name"], n["ip"], user, "ovn_gw")}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("ovn-chassis-stale")
        found, controllers, user, version, problem = inventory(data, ctx)
        if problem:
            r.step("nodes", "Controllers reached from the director", "fail", problem)
            return r.done()
        up = controllers_step(r, data, "reach_", controllers, user, version)
        if not up:
            return r.done()
        ctl = up[0][1]
        agents_item = source(data, "agents")
        agents = json_of(agents_item)
        if not isinstance(agents, list):
            r.step("agents", "OVN agents in Neutron", "fail",
                   f"openstack network agent list could not be read ({unavailable(agents_item) or first_line(agents_item.get('out'))}).")
            return r.done()
        ovn = [a for a in agents if "OVN Controller" in str(a.get("Agent Type") or "")]
        by_host = {}
        for a in ovn:
            by_host.setdefault(overcloud.short(a.get("Host")), []).append(a)
        dup = {h: v for h, v in by_host.items() if len(v) > 1}
        dead = [a for a in ovn if not a.get("Alive")]
        r.step("agents", "OVN controller agents in Neutron", "warn" if dup or dead else "ok",
               f"{len(ovn)} agent(s), {len(dead)} not alive"
               + (f"; more than one agent for {', '.join(sorted(dup))} (an old one of a reinstalled node)." if dup else "."),
               {"columns": ["Host", "Agent ID", "Type", "Alive"],
                "rows": [[a.get("Host"), a.get("ID"), a.get("Agent Type"), "yes" if a.get("Alive") else "NO"]
                         for a in sorted(ovn, key=lambda x: (str(x.get("Host")), str(x.get("ID"))))]},
               marks=[str(a.get("ID")) for a in dead])
        sb = source(data, "chassis")
        if not reached(sb) or str(sb.get("rc")) not in ("0", "None") and not item_out(data, "chassis"):
            r.step("chassis", "Chassis of the OVN Southbound", "fail",
                   f"The Southbound could not be read on {ctl['name']} ({unavailable(sb) or first_line(sb.get('out')) or 'no answer'}).")
            return r.done()
        view = chassis_view(data, ovn, found)
        if not view:
            r.step("chassis", "Chassis of the OVN Southbound", "fail",
                   f"No chassis read on {ctl['name']} ({first_line(item_out(data, 'chassis')) or 'empty answer'}).")
            return r.done()
        for c in view:
            fresh = c["seen"] is not None and c["seen"] < FRESH_SECONDS
            c["stale"] = not c["alive"] and not fresh
        stale = [c for c in view if c["stale"]]
        gw_stale = [c for c in stale if c["gateway"]]
        gw_read = bool(sections(item_out(data, "gw")).get("gw") is not None)
        r.step("chassis", "Chassis of the OVN Southbound", "fail" if gw_stale else "warn" if stale else "ok",
               (f"{len(stale)} stale chassis (no live agent, no nb_cfg answer for 10 minutes)"
                + (f"; router gateways are scheduled on {', '.join(c['host'] or c['name'] for c in gw_stale)}: north-south "
                   "traffic of those routers can break." if gw_stale else ".") if stale else
                f"{len(view)} chassis, every one with a live agent or a recent nb_cfg answer.")
               + ("" if gw_read else " The gateways of the Northbound were not read."),
               {"columns": ["Chassis", "Host", "Agent alive", "Last nb_cfg", "Ports bound", "Gateway", "Stale"],
                "rows": [[c["name"], c["host"], "yes" if c["alive"] else "no agent" if c["alive"] is None else "NO",
                          age_text(c["seen"]), c["ports"], "yes" if c["gateway"] else "-", "STALE" if c["stale"] else "-"]
                         for c in sorted(view, key=lambda x: (not x["stale"], x["host"]))]},
               marks=[c["name"] for c in stale])
        if not stale:
            return r.done()
        node_line = f"{ctl['name']}={ctl['ip']}"
        items = []
        for c in stale:
            why = ("ports are still bound to it" if c["ports"] else "its name is not a system-id (UUID)"
                   if not UUID.match(c["name"]) else "" if HOST.match(overcloud.short(c["host"]) or "-") else "no host name")
            items.append({"label": f"{c['host'] or '?'} ({c['name']})",
                          "commands": [] if why else
                          [f"chassis-del {c['name']} host {overcloud.short(c['host'])} node {node_line} user {user}"],
                          "disabled": why, "default": not why})
        where = f"a controller, as {user} with sudo: from the director, ssh {user}@{ctl['ip']}"
        r.recommend("Delete the stale chassis from the Southbound. Neutron schedules the router gateways again on live "
                    "chassis; an ovn-controller that is still alive would register its chassis again by itself.",
                    ["sudo podman exec ovn_controller ovn-sbctl --no-leader-only list Chassis_Private",
                     *(f"sudo podman exec ovn_controller ovn-sbctl --no-leader-only find Port_Binding chassis={c['uuid']}   # {c['host']}"
                       for c in stale if c["uuid"]),
                     *(f"sudo podman exec ovn_controller ovn-sbctl chassis-del {c['name']}   # {c['host']}" for c in stale),
                     *(f"openstack network agent delete {a.get('ID')}   # dead agent of {a.get('Host')}" for a in dead)],
                    where=where,
                    items={"columns": ["Chassis", "Host", "Last nb_cfg", "Ports bound", "Gateway"],
                           "rows": [[c["name"], c["host"], age_text(c["seen"]), c["ports"], "yes" if c["gateway"] else "-"]
                                    for c in stale]},
                    warning="A write to the OVN Southbound DB. Each chassis is read again on the node right before: it is "
                            "deleted only while it binds no port, its agent is not alive and it has not answered nb_cfg "
                            "for 10 minutes.",
                    action=os_select(items, target=", ".join(sorted({c["host"] or c["name"] for c in stale})),
                                     label="Delete the ticked stale chassis", noun="chassis", lock="ovn-chassis",
                                     stop_on_failure=True, item_timeout=180, max_items=20))
        return r.done()


# ---------------------------------------------------------------------------------------------------- Nova vs libvirt
class ComputeHypervisorSync:
    """Nova against the hypervisor of each compute: the nova containers and the libvirt daemon, the domains libvirt runs
    against the instances Nova places there (a running domain of an instance Nova places elsewhere can write to the same
    volume twice), and the nova-compute hosts of the cell mapping."""
    sources = ("openstack", "undercloud", "overcloud")
    phases = 2

    @staticmethod
    def reads(phase, data, params, ctx):
        if phase == 1:
            return {"openstack": {"servers": "openstack server list --all-projects --long -f json",
                                  "services": "openstack compute service list --service nova-compute -f json"},
                    "undercloud": dict(overcloud.INVENTORY_READS)}
        found, controllers, user, _v, problem = inventory(data, ctx)
        if problem:
            return {}
        out = {f"sync_{i}": overcloud.read(n["name"], n["ip"], user, "nova_sync") for i, n in enumerate(computes_of(found, params))}
        out.update({f"cells_{i}": overcloud.read(n["name"], n["ip"], user, "nova_cells") for i, n in enumerate(controllers[:3])})
        return {"overcloud": out}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("compute-hypervisor-sync")
        found, controllers, user, version, problem = inventory(data, ctx)
        if problem:
            r.step("nodes", "Computes reached from the director", "fail", problem)
            return r.done()
        servers, services = json_of(source(data, "servers")), json_of(source(data, "services"))
        if not isinstance(servers, list) or not isinstance(services, list):
            bad = source(data, "servers") if not isinstance(servers, list) else source(data, "services")
            r.step("nova", "Instances and compute services in Nova", "fail",
                   f"Nova could not be read ({unavailable(bad) or first_line(bad.get('out'))}).")
            return r.done()
        nodes = computes_of(found, params)
        up = [(i, n) for i, n in enumerate(nodes) if reached(source(data, f"sync_{i}"))]
        down = [n["name"] for i, n in enumerate(nodes) if (i, n) not in up]
        r.step("nodes", "Computes reached from the director", "ok" if nodes and not down else "warn" if up else "fail",
               (f"{len(up)} of {len(nodes)} compute(s) answered as {user} (RHOSP {version or '?'})"
                + (f"; not reached: {', '.join(down)}." if down else ".")) if nodes else "No compute node to read.")
        where_of = {s: n for s in {str(x.get("Host") or "") for x in services} for n in [node_of(s, found)] if n}
        host_of = {}   # instance -> (nova host, status)
        for s in servers:
            host_of[str(s.get("ID"))] = (str(s.get("Host") or ""), str(s.get("Status") or "").upper(), str(s.get("Name") or ""))
        svc_rows, svc_bad, dom_rows, dom_fail, dom_warn, unread = [], [], [], [], [], []
        for i, n in up:
            sec = sections(item_out(data, f"sync_{i}"))
            ctrs = dict((ln.partition(" ")[0], ln.partition(" ")[2]) for ln in sec.get("ctr", []))
            units = dict((ln.partition(" ")[0], ln.partition(" ")[2].strip()) for ln in sec.get("unit", []))
            compute_up = ctrs.get("nova_compute", "").startswith("Up")
            daemon = sec.get("virsh:arg", "")
            libvirt_up = "active" in units.values() or bool(daemon)
            if not compute_up or not libvirt_up:
                svc_bad.append(n["name"])
            svc_rows.append([n["name"], ctrs.get("nova_compute", "not found"), daemon or "no libvirt container",
                             ", ".join(f"{k}: {v}" for k, v in units.items() if v and v != "inactive") or "-"])
            hosts = [h for h, node in where_of.items() if node["name"] == n["name"]]
            mine = {sid: v for sid, v in host_of.items() if v[0] in hosts}
            if not daemon or sec.get("rc:running") not in (0, None) or "running" not in sec:
                unread.append(n["name"])
                continue
            running = {x.strip() for x in sec.get("running", []) if NET_UUID.fullmatch(x.strip())}
            every = {x.strip() for x in sec.get("all", []) if NET_UUID.fullmatch(x.strip())}
            for sid, (h, st, name) in sorted(mine.items(), key=lambda x: x[1][2]):
                if st == "ACTIVE" and sid not in running:
                    dom_fail.append(n["name"])
                    dom_rows.append([n["name"], name, sid, "ACTIVE in Nova", "not running" if sid in every else "no domain"])
                elif st == "SHUTOFF" and sid in running:
                    dom_warn.append(n["name"])
                    dom_rows.append([n["name"], name, sid, "SHUTOFF in Nova", "running"])
            for sid in sorted(every - set(mine)):
                other = host_of.get(sid)
                state = "running" if sid in running else "defined"
                if other and sid in running:
                    dom_fail.append(n["name"])
                    dom_rows.append([n["name"], other[2], sid, f"Nova places it on {other[0] or '-'}", state])
                else:
                    dom_warn.append(n["name"])
                    dom_rows.append([n["name"], other[2] if other else "-", sid,
                                     f"Nova places it on {other[0] or '-'}" if other else "no instance in Nova", state])
        r.step("services", "nova_compute and the libvirt daemon", "fail" if svc_bad else "ok" if up else "skip",
               (f"Not running on {', '.join(svc_bad)}: Nova reports the compute down and its instances cannot be managed."
                if svc_bad else "nova_compute and libvirt run on every compute read."),
               {"columns": ["Compute", "nova_compute", "libvirt container", "Units"], "rows": svc_rows}, marks=svc_bad)
        r.step("domains", "Domains of libvirt against the instances of Nova",
               "fail" if dom_fail else "warn" if dom_warn or unread else "ok" if up else "skip",
               ((f"{len(dom_rows)} difference(s)"
                 + (f"; on {', '.join(sorted(set(dom_fail)))} an ACTIVE instance has no running domain or a domain runs "
                    "for an instance Nova places on another compute (two hosts can write to its volumes)." if dom_fail else ".")
                 if dom_rows else "Every instance Nova places on the computes read matches a domain of libvirt.")
                + (f" virsh did not answer on {', '.join(unread)} (10 s)." if unread else "")),
               {"columns": ["Compute", "Instance", "ID", "Nova", "libvirt"], "rows": dom_rows} if dom_rows else None,
               marks=[x[2] for x in dom_rows])
        # cell mapping of the nova-compute hosts
        cells_txt = next((item_out(data, f"cells_{i}") for i in range(len(controllers[:3]))
                          if reached(source(data, f"cells_{i}")) and str(source(data, f"cells_{i}").get("rc")) in ("0", "None")
                          and "|" in item_out(data, f"cells_{i}")), "")
        mapped = {overcloud.short(c.strip()) for line in cells_txt.splitlines() if line.startswith("|")
                  for c in line.strip("|").split("|")[-1:] if c.strip() and c.strip() != "Hostname"}
        live = [s for s in services if str(s.get("State") or "").lower() == "up"]
        unmapped = sorted(str(s.get("Host")) for s in live if overcloud.short(s.get("Host")) not in mapped)
        r.step("cells", "nova-compute hosts mapped to a cell", "skip" if not cells_txt else "fail" if unmapped else "ok",
               ("nova-manage cell_v2 list_hosts was not read on any controller." if not cells_txt else
                f"Not mapped: {', '.join(unmapped)} (instances there end in ERROR \"Host is not mapped to any cell\")."
                if unmapped else f"Every nova-compute host that is up ({len(live)}) is mapped to a cell."), marks=unmapped)
        where = f"the compute, as {user} with sudo: from the director, ssh {user}@<its ctlplane address>"
        if svc_bad:
            r.recommend("Bring nova_compute and the libvirt daemon back on the compute before anything else: look at why "
                        "they stopped, then start them.",
                        ["sudo podman ps -a --filter name=nova_ --format '{{.Names}} {{.Status}}'",
                         "sudo systemctl status tripleo_nova_virtqemud tripleo_nova_compute",
                         "sudo journalctl -u tripleo_nova_virtqemud -u tripleo_nova_compute --since -2h | tail -50",
                         "sudo systemctl restart tripleo_nova_virtqemud tripleo_nova_compute"],
                        where=where, refs=["rhosp-compute-down"],
                        warning="RHOSP 16.2: the units are tripleo_nova_libvirt and tripleo_nova_compute.")
        if dom_rows:
            r.recommend("Make Nova and libvirt agree, one instance at a time, after a person has looked at it: never start a "
                        "second copy of an instance whose domain still runs on another compute.",
                        [*(f"openstack server show {x[2]} -c status -c OS-EXT-SRV-ATTR:host -c OS-EXT-STS:power_state   # {x[1]}"
                           for x in dom_rows[:10]),
                         "sudo podman exec nova_virtqemud virsh list --all   # on the compute",
                         "sudo podman exec nova_virtqemud virsh dominfo <uuid>   # the domain of the row"],
                        where=where,
                        warning="Destroying or starting a domain by hand can lose or corrupt data: only after the owner of "
                                "the instance knows, with a ticket.")
        if unmapped:
            r.recommend("Map the new compute hosts to their cell.",
                        ["sudo podman exec nova_api nova-manage cell_v2 list_hosts",
                         "sudo podman exec nova_api nova-manage cell_v2 discover_hosts --by-service --verbose"],
                        where=f"a controller, as {user} with sudo", warning="A change of the Nova database: owner approval, run by "
                        "the operator.")
        return r.done()


# ---------------------------------------------------------------------------------------------------- Placement
def parse_audit(text):
    """(rc, [(consumer, resource provider)]) of nova-manage placement audit --verbose."""
    sec = sections(text)
    rc = sec.get("rc:")
    pairs = []
    for line in sec.get("", []):
        if "consumer" in line.lower():
            ids = NET_UUID.findall(line)
            if len(ids) >= 2:
                pairs.append((ids[0], ids[1]))
    return rc, pairs


def parse_heal(text):
    """(rc, [instance]) of nova-manage placement heal_allocations --dry-run --verbose."""
    sec = sections(text)
    rc = sec.get("rc:")
    found = []
    for line in sec.get("", []):
        low = line.lower()
        if ("dry" in low or "would" in low or "allocation" in low) and "instance" in low:
            found += [x for x in NET_UUID.findall(line) if x not in found]
    return rc, found


class PlacementConsistency:
    """The allocations of Placement against Nova: orphaned allocations (left by failed migrations or evacuations) make
    \"No valid host\" while the host is empty, and instances without allocations overfill a host. Both read with the
    read-only forms of nova-manage (audit without --delete, heal_allocations --dry-run) on one controller."""
    sources = ("undercloud", "overcloud")
    phases = 3

    @staticmethod
    def reads(phase, data, params, ctx):
        if phase == 1:
            return {"undercloud": dict(overcloud.INVENTORY_READS)}
        _f, controllers, user, _v, problem = inventory(data, ctx)
        if problem:
            return {}
        if phase == 2:
            return {"overcloud": {f"reach_{i}": overcloud.read(n["name"], n["ip"], user, "reach")
                                  for i, n in enumerate(controllers)}}
        up = [n for i, n in enumerate(controllers) if reached(source(data, f"reach_{i}"))]
        if not up:
            return {}
        n = up[0]
        return {"overcloud": {"audit": overcloud.read(n["name"], n["ip"], user, "placement_audit"),
                              "heal": overcloud.read(n["name"], n["ip"], user, "placement_heal")}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("placement-consistency")
        _f, controllers, user, version, problem = inventory(data, ctx)
        if problem:
            r.step("nodes", "Controllers reached from the director", "fail", problem)
            return r.done()
        up = controllers_step(r, data, "reach_", controllers, user, version)
        if not up:
            return r.done()
        ctl = up[0][1]
        rc, orphans = parse_audit(item_out(data, "audit"))
        audit_ok = rc in (0, 1, 3)
        r.step("audit", "Orphaned allocations (placement audit)",
               "warn" if rc == 3 or orphans else "warn" if rc == 1 else "ok" if rc == 0 else "fail",
               (f"{len(orphans)} allocation(s) of consumers Nova does not know any more: their resources stay used."
                if rc == 3 or orphans else "More than --max-count allocations: only part was audited." if rc == 1 else
                "No orphaned allocation." if rc == 0 else
                f"nova-manage placement audit did not run on {ctl['name']} (exit {rc}: "
                f"{first_line(item_out(data, 'audit')) or 'no answer'})."),
               {"columns": ["Consumer", "Resource provider"], "rows": [list(p) for p in orphans]} if orphans else None,
               marks=[p[0] for p in orphans])
        hrc, heal = parse_heal(item_out(data, "heal"))
        r.step("heal", "Instances without allocations (heal_allocations --dry-run)",
               "ok" if hrc == 4 and not heal else "warn" if hrc in (0, 1) or heal else "fail",
               ("Every instance has its allocations." if hrc == 4 and not heal else
                f"{len(heal) or 'Some'} instance(s) would get allocations: the hosts they run on look emptier to the scheduler "
                "than they are." if hrc in (0, 1) or heal else
                f"nova-manage placement heal_allocations --dry-run did not run (exit {hrc}: "
                f"{first_line(item_out(data, 'heal')) or 'no answer'})."),
               {"columns": ["Instance"], "rows": [[x] for x in heal]} if heal else None, marks=heal)
        where = f"a controller, as {user} with sudo: from the director, ssh {user}@{ctl['ip']}"
        if orphans or rc == 1:
            r.recommend("Delete the orphaned allocations after a person has checked each consumer: an orphan of a migration "
                        "still in progress is not one.",
                        ["sudo podman exec nova_api nova-manage placement audit --verbose",
                         *(f"openstack server show {c} -c status -c OS-EXT-SRV-ATTR:host   # consumer of an orphan" for c, _rp in orphans[:10]),
                         "sudo podman exec nova_api nova-manage placement audit --verbose --delete"],
                        where=where, refs=["rhosp-compute-down"],
                        warning="A change of the Placement database: owner approval, run by the operator (not from the portal).")
        if heal:
            r.recommend("Create the missing allocations.",
                        ["sudo podman exec nova_api nova-manage placement heal_allocations --dry-run --verbose",
                         "sudo podman exec nova_api nova-manage placement heal_allocations --verbose"],
                        where=where, warning="A change of the Placement database: owner approval, run by the operator.")
        return r.done()

"""Health of the Acme Flex platform itself (not from a Knowledge Base work instruction): the OpenStack services and
agents, the address pools of the external networks, and the bare metal nodes of the overcloud as the undercloud
(ironic) sees them through their BMC. Read-only like every check: list / show on the director, with overcloudrc for the
overcloud and stackrc for the undercloud.

The fixes are commands with the hosts found, to run on the node itself (containers of RHOSP 16.2 / 17.1, systemd unit
tripleo_<container>) or on the director; the portal does not run them.
"""
import re
import shlex

from .common import Result, director, json_of, pct, source, unavailable, worst
from .openstack import UUID, minutes_since, project_names, pname

q = shlex.quote
HOST_KEY = re.compile(r"^[A-Za-z0-9_.:-]{1,70}$")
STALE_DAYS = 7          # a service down longer than this, without instances: an old record, not an outage
CONTROL_BINARIES = {"nova-scheduler", "nova-conductor", "nova-consoleauth", "cinder-scheduler"}
# Agent type -> container of RHOSP 16.2 / 17.1 (systemd unit tripleo_<container>) and its log on the node.
AGENT_CONTAINERS = {
    "ovn controller agent": ("ovn_controller", "/var/log/containers/openvswitch/ovn-controller.log"),
    "ovn controller gateway agent": ("ovn_controller", "/var/log/containers/openvswitch/ovn-controller.log"),
    "ovn metadata agent": ("ovn_metadata_agent", "/var/log/containers/neutron/ovn-metadata-agent.log"),
    "open vswitch agent": ("neutron_ovs_agent", "/var/log/containers/neutron/openvswitch-agent.log"),
    "l3 agent": ("neutron_l3_agent", "/var/log/containers/neutron/l3-agent.log"),
    "dhcp agent": ("neutron_dhcp", "/var/log/containers/neutron/dhcp-agent.log"),
    "metadata agent": ("neutron_metadata_agent", "/var/log/containers/neutron/metadata-agent.log"),
}
NODE_WHERE = ("{host}, as heat-admin (RHOSP 16.2) or tripleo-admin (17.1): from the director, ssh to its ctlplane address "
              "(source ~/stackrc; 16.2: openstack server list; 17.1: metalsmith -f value -c Hostname -c 'IP Addresses' list)")


def rows_of(item):
    """A `-f json` list -> list of dicts with lower-case keys without spaces ('Updated At' -> 'updated_at')."""
    data = json_of(item)
    if not isinstance(data, list):
        return []
    return [{re.sub(r"[\s-]+", "_", str(k).strip().lower()): v for k, v in x.items()} for x in data if isinstance(x, dict)]


def truthy(value):
    """Alive / State of `network agent list`: JSON true/false, or the table words (':-)', 'XXX', 'UP', 'DOWN')."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", ":-)", "up", "yes", "1", "alive")


def short(host):
    return str(host or "").split(".")[0]


def node_where(host):
    return NODE_WHERE.format(host=host)


class OpenstackServices:
    """Nova and Cinder services, Neutron agents (ML2/OVN or ML2/OVS) and the address pools of the external networks:
    what is down, what it affects (instances on a compute whose nova-compute is down), and old records of removed
    nodes (down for weeks, nothing on them) kept apart from real outages."""
    sources = ("openstack",)
    phases = 2

    @staticmethod
    def reads(phase, data, params, ctx):
        if phase == 1:
            return {"openstack": {"compute": "openstack compute service list --long -f json",
                                  "volume": "openstack volume service list --long -f json",
                                  "agents": "openstack network agent list -f json",
                                  "ipavail": "openstack ip availability list --ip-version 4 -f json",
                                  "external": "openstack network list --external -f json",
                                  "now": "date -u +%Y-%m-%dT%H:%M:%SZ"}}
        reads = {}
        for host in OpenstackServices._down_computes(data)[:8]:
            if HOST_KEY.match(host):
                reads[f"servers_{host}"] = f"openstack server list --all-projects --host {q(host)} -f json"
        warn = int(params.get("ip_warn") or 85)
        for net in OpenstackServices._external_usage(data):
            if net["pct"] is not None and net["pct"] >= warn and UUID.match(net["id"]):
                reads[f"subnets_{net['id']}"] = f"openstack ip availability show {q(net['id'])} -f json"
                reads[f"fips_{net['id']}"] = f"openstack floating ip list --network {q(net['id'])} -f json"
        if any(k.startswith("fips_") for k in reads):
            reads["projects"] = "openstack project list -f json"
        return {"openstack": dict(list(reads.items())[:24])}

    @staticmethod
    def _down_computes(data):
        return sorted({str(s.get("host")) for s in rows_of(source(data, "compute"))
                       if s.get("binary") == "nova-compute" and str(s.get("state")).lower() == "down" and s.get("host")})

    @staticmethod
    def _external_usage(data):
        external = {str(n.get("id")) for n in rows_of(source(data, "external"))}
        out = []
        for n in rows_of(source(data, "ipavail")):
            nid = str(n.get("network_id") or "")
            if nid in external:
                total, used = n.get("total_ips"), n.get("used_ips")
                out.append({"id": nid, "name": n.get("network_name") or nid, "total": total, "used": used, "pct": pct(used, total)})
        return out

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("openstack-services")
        now = str(source(data, "now").get("out") or "").strip()
        where_dir = director(ctx)

        def age_days(updated):
            minutes = minutes_since(str(updated or "").replace(" ", "T"), now)
            return None if minutes is None else minutes / 1440

        def instances_on(host):
            item = (data or {}).get(f"servers_{host}")
            if not isinstance(item, dict) or unavailable(item):
                return None
            return [s for s in json_of(item) or [] if isinstance(s, dict)]

        # ---------------- Nova ----------------
        compute = source(data, "compute")
        if unavailable(compute):
            r.step("nova", "Compute services (nova)", "fail", unavailable(compute))
        else:
            OpenstackServices._services(r, "nova", "Compute services (nova)", rows_of(compute), age_days, instances_on, where_dir)
        # ---------------- Cinder ----------------
        volume = source(data, "volume")
        if unavailable(volume):
            r.step("cinder", "Block storage services (cinder)", "fail", unavailable(volume))
        else:
            OpenstackServices._services(r, "cinder", "Block storage services (cinder)", rows_of(volume), age_days, None, where_dir)
        # ---------------- Neutron agents ----------------
        agents_item = source(data, "agents")
        if unavailable(agents_item):
            r.step("neutron", "Network agents (neutron)", "fail", unavailable(agents_item))
        else:
            OpenstackServices._agents(r, rows_of(agents_item), rows_of(compute) if not unavailable(compute) else [], age_days)
        # ---------------- external address pools ----------------
        OpenstackServices._pools(r, data, params, where_dir)
        return r.done()

    @staticmethod
    def _services(r, key, title, rows, age_days, instances_on, where_dir):
        problems, stale, disabled, table = [], [], [], []
        by_binary = {}
        for s in rows:
            by_binary.setdefault(s.get("binary"), []).append(s)
        for s in sorted(rows, key=lambda x: (str(x.get("binary")), str(x.get("host")))):
            host, binary = str(s.get("host") or ""), str(s.get("binary") or "")
            up = str(s.get("state")).lower() == "up"
            enabled = str(s.get("status")).lower() == "enabled"
            days = age_days(s.get("updated_at"))
            servers = instances_on(host) if instances_on and binary == "nova-compute" else None
            note = ""
            if not up:
                if days is not None and days >= STALE_DAYS and not servers:
                    stale.append(s)
                    note = f"old record: no report for {int(days)} days" + (", no instances" if servers is not None else "")
                elif enabled:
                    problems.append(dict(s, servers=servers))
                    note = "DOWN" + (f", {len(servers)} instance(s) on it" if servers else "")
                else:
                    disabled.append(s)
                    note = "down, disabled" + (f", {len(servers)} instance(s) on it" if servers else "")
            elif not enabled:
                disabled.append(s)
                note = "disabled"
            table.append([binary, host, s.get("zone") or "", s.get("status") or "", s.get("state") or "",
                          str(s.get("updated_at") or "")[:19], note or (s.get("disabled_reason") or "")])
        # A control service (scheduler, conductor) still runs elsewhere when only one controller lost it.
        status = "ok"
        for s in problems:
            binary = s.get("binary")
            peers_up = [x for x in by_binary.get(binary, []) if str(x.get("state")).lower() == "up"]
            status = worst(status, "warn" if binary in CONTROL_BINARIES and peers_up else "fail")
        if stale and status == "ok":
            status = "warn"
        detail = (f"{len(problems)} enabled service(s) down" if problems else "Every enabled service is up") + \
                 (f"; {len(stale)} old record(s) of removed nodes" if stale else "") + \
                 (f"; {len(disabled)} disabled" if disabled else "") + "."
        r.step(key, title, status, detail, {"columns": ["Service", "Host", "Zone", "Status", "State", "Last report (UTC)", "Note"],
                                            "rows": table}, marks=[s.get("host") for s in problems + stale])
        for s in problems:
            host, binary = str(s.get("host")), str(s.get("binary"))
            servers = s.get("servers") or []
            if binary == "nova-compute":
                r.recommend(f"nova-compute on {host} is down: the {len(servers)} instance(s) there cannot be started, stopped, "
                            "migrated or resized until it is back. Look at the node and the container, then restart the container. "
                            "If the node itself is down, see the check Bare metal nodes (BMC power state).",
                            ["sudo podman ps -a --filter name=nova_compute --format '{{.Names}} {{.Status}}'",
                             "sudo tail -n 100 /var/log/containers/nova/nova-compute.log",
                             "sudo systemctl restart tripleo_nova_compute",
                             "sudo systemctl status tripleo_nova_compute --no-pager"],
                            where=node_where(host),
                            warning="Do not evacuate the instances while the node may still run them (the disks would be written "
                                    "from two hosts): only when the node is confirmed powered off.",
                            items={"columns": ["Instance", "ID", "Status"],
                                   "rows": [[x.get("Name"), x.get("ID"), x.get("Status")] for x in servers[:50]]} if servers else None,
                            refs=["rhosp-compute-down", "rhosp-containers", "rhosp-evacuate"])
            elif binary == "cinder-volume":
                r.recommend(f"cinder-volume of backend {host} is down: volumes of this backend cannot be created, attached, "
                            "extended or deleted. It runs as a Pacemaker resource on one controller: look at it there.",
                            ["sudo pcs status | grep -A3 cinder-volume",
                             "sudo tail -n 100 /var/log/containers/cinder/cinder-volume.log",
                             "sudo pcs resource cleanup openstack-cinder-volume",
                             "sudo pcs status | grep -A3 cinder-volume"],
                            where="A controller node, as heat-admin (RHOSP 16.2) or tripleo-admin (17.1)",
                            warning="An error in the log about the storage (NetApp unreachable, credentials) comes back after the "
                                    "cleanup: fix that first.", refs=["rhosp-pcs-resource", "rhosp-cinder-ha"])
            else:
                container = binary.replace("-", "_")
                r.recommend(f"{binary} on {host} is down"
                            + (" (it still runs on the other controllers)." if binary in CONTROL_BINARIES else ".")
                            + " Look at its container and log on that controller, then restart the container.",
                            [f"sudo podman ps -a --filter name={container} --format '{{{{.Names}}}} {{{{.Status}}}}'",
                             f"sudo tail -n 100 /var/log/containers/{binary.split('-')[0]}/{binary}.log",
                             f"sudo systemctl restart tripleo_{container}"],
                            where=node_where(host), refs=["rhosp-containers"])
        if stale:
            cmds = [f"openstack compute service delete {s.get('id')}" for s in stale if s.get("binary") == "nova-compute" and s.get("id")]
            cmds += [f"sudo podman exec cinder_api cinder-manage service remove {s.get('binary')} {s.get('host')}"
                     for s in stale if str(s.get("binary", "")).startswith("cinder")]
            r.recommend(f"{len(stale)} service record(s) have not reported for {STALE_DAYS} days or more and have nothing on them: "
                        "nodes that were removed or renamed. They are not an outage, but they hide real failures in this list. "
                        "Remove the records only after confirming the node is gone.",
                        cmds, where=f"{where_dir} (cinder-manage: on a controller)", refs=["rhosp-remove-compute", "rhosp-cinder-manage"],
                        items={"columns": ["Service", "Host", "Last report"],
                               "rows": [[s.get("binary"), s.get("host"), str(s.get("updated_at") or "")[:19]] for s in stale]})

    @staticmethod
    def _agents(r, rows, compute_rows, age_days):
        stale_hosts = {str(s.get("host")) for s in compute_rows if str(s.get("state")).lower() == "down"
                       and (age_days(s.get("updated_at")) or 0) >= STALE_DAYS}
        dead, stale, table = [], [], []
        types = sorted({str(a.get("agent_type")) for a in rows})
        backend = "ML2/OVN" if any("ovn" in t.lower() for t in types) else "ML2/OVS" if types else "unknown"
        for a in sorted(rows, key=lambda x: (str(x.get("agent_type")), str(x.get("host")))):
            alive, admin_up = truthy(a.get("alive")), truthy(a.get("state"))
            note = ""
            if not alive:
                if str(a.get("host")) in stale_hosts or short(a.get("host")) in {short(h) for h in stale_hosts}:
                    stale.append(a)
                    note = "dead, node removed (old record)"
                elif admin_up:
                    dead.append(a)
                    note = "DEAD"
                else:
                    note = "dead, disabled"
            elif not admin_up:
                note = "disabled"
            table.append([a.get("agent_type"), a.get("host"), a.get("availability_zone") or "", "yes" if alive else "no",
                          "UP" if admin_up else "DOWN", note])
        r.step("neutron", f"Network agents (neutron, {backend})", "fail" if dead else "warn" if stale else "ok",
               (f"{len(dead)} agent(s) dead." if dead else "Every agent is alive.") + (f" {len(stale)} on removed nodes." if stale else ""),
               {"columns": ["Agent", "Host", "Zone", "Alive", "Admin state", "Note"], "rows": table},
               marks=[a.get("host") for a in dead])
        for a in dead:
            kind = str(a.get("agent_type") or "")
            container, log = AGENT_CONTAINERS.get(kind.lower(), (str(a.get("binary") or "").replace("-", "_"), ""))
            effect = {"ovn controller agent": "ports of instances on this node are not programmed (new or migrated instances "
                                              "get no network)",
                      "ovn controller gateway agent": "routers and floating IPs scheduled on this gateway node lose traffic",
                      "ovn metadata agent": "instances on this node get no metadata (cloud-init, SSH keys, passwords)",
                      "metadata agent": "instances get no metadata (cloud-init, SSH keys, passwords)",
                      "dhcp agent": "instances on its networks get no DHCP address",
                      "l3 agent": "routers on this node lose traffic",
                      "open vswitch agent": "ports of instances on this node are not programmed"}.get(kind.lower(), "its function is not available")
            cmds = [f"sudo podman ps -a --filter name={container} --format '{{{{.Names}}}} {{{{.Status}}}}'"] if container else []
            if log:
                cmds.append(f"sudo tail -n 100 {log}")
            if container:
                cmds += [f"sudo systemctl restart tripleo_{container}", f"sudo systemctl status tripleo_{container} --no-pager"]
            r.recommend(f"{kind} on {a.get('host')} is dead: {effect}. Look at the container and its log on that node, then restart "
                        "it.", cmds, where=node_where(a.get("host")),
                        warning="When every agent of one node is dead, the node itself or its control-plane network is down: "
                                "check the node first (Bare metal nodes, BMC).",
                        refs=(["rhosp-ovn-metadata", "rhosp-ovn"] if "metadata" in kind.lower() else ["rhosp-ovn"]))

    @staticmethod
    def _pools(r, data, params, where_dir):
        warn, fail = int(params.get("ip_warn") or 85), int(params.get("ip_fail") or 95)
        item = source(data, "ipavail")
        if unavailable(item) or unavailable(source(data, "external")):
            r.step("pools", "External address pools (floating IPs)", "skip",
                   unavailable(item) or unavailable(source(data, "external")))
            return
        nets = OpenstackServices._external_usage(data)
        names = project_names(data)
        rows, status = [], "ok"
        for n in sorted(nets, key=lambda x: -(x["pct"] or 0)):
            st = "fail" if (n["pct"] or 0) >= fail else "warn" if (n["pct"] or 0) >= warn else "ok"
            status = worst(status, st)
            rows.append([n["name"], n["total"], n["used"], f"{n['pct']}%" if n["pct"] is not None else "-", st.upper()])
        r.step("pools", f"External address pools at {warn}% used or more", status,
               f"{len(nets)} external network(s) (IPv4)." if nets else "No external network found.",
               {"columns": ["Network", "Total IPs", "Used IPs", "Used", "Status"], "rows": rows})
        for n in nets:
            if n["pct"] is None or n["pct"] < warn:
                continue
            subnets = json_of(source(data, f"subnets_{n['id']}")) or {}
            subs = ((subnets.get("subnet_ip_availability") or subnets.get("Subnet IP Availability") or [])
                    if isinstance(subnets, dict) else [])
            fips = [f for f in json_of(source(data, f"fips_{n['id']}")) or [] if isinstance(f, dict)]
            free = [f for f in fips if not f.get("Port") and not f.get("Fixed IP Address")]
            per_project = {}
            for f in free:
                per_project[str(f.get("Project") or "")] = per_project.get(str(f.get("Project") or ""), 0) + 1
            if isinstance(subs, list) and subs:
                r.step(f"subnets_{n['id']}", f"Subnets of {n['name']}", "info", "",
                       {"columns": ["Subnet", "CIDR", "Total", "Used", "Used %"],
                        "rows": [[s.get("subnet_name") or s.get("subnet_id"), s.get("cidr"), s.get("total_ips"), s.get("used_ips"),
                                  pct(s.get("used_ips"), s.get("total_ips"))] for s in subs if isinstance(s, dict)]})
            r.recommend(f"{n['name']} is {n['pct']}% used: when it is full, new floating IPs and router gateways fail. "
                        f"{len(free)} floating IP(s) are allocated but not attached to anything: ask their projects to release "
                        "the ones they do not need, or ask the network team for another subnet on this network.",
                        [f"openstack floating ip list --network {n['id']} --status DOWN -f value -c 'Floating IP Address' -c Project",
                         f"openstack ip availability show {n['id']}"],
                        where=where_dir, refs=["rhosp-floating-ip"],
                        items={"columns": ["Project", "Unattached floating IPs"],
                               "rows": sorted([[pname(names, p), c] for p, c in per_project.items()], key=lambda x: -x[1])[:30]}
                        if per_project else None)


class IronicNodes:
    """The overcloud nodes as the undercloud (ironic) manages them through their BMC: power state, maintenance and the
    fault ironic set (power failure = ironic cannot read the BMC; Pacemaker fencing of a controller uses the same BMC)."""
    sources = ("undercloud",)
    phases = 1

    @staticmethod
    def reads(phase, data, params, ctx):
        return {"undercloud": {"nodes": "openstack baremetal node list --long -f json -c UUID -c Name -c 'Power State' "
                                        "-c 'Provisioning State' -c Maintenance -c 'Maintenance Reason' -c Fault -c 'Last Error' "
                                        "-c 'Instance UUID' -c Driver"}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("ironic-nodes")
        item = source(data, "nodes")
        if unavailable(item):
            r.step("nodes", "Bare metal nodes (ironic, undercloud)", "fail", unavailable(item))
            return r.done()
        nodes = rows_of(item)
        where = f"OpenStack director of {ctx.get('site') or 'the site'}, as stack after: source ~/stackrc"
        problems, rows = [], []
        for n in sorted(nodes, key=lambda x: str(x.get("name") or x.get("uuid"))):
            power = str(n.get("power_state") or "None")
            prov = str(n.get("provisioning_state") or "")
            maint = truthy(n.get("maintenance"))
            fault = str(n.get("fault") or "").strip()
            fault = "" if fault.lower() == "none" else fault
            last_error = str(n.get("last_error") or "").strip()
            last_error = "" if last_error.lower() == "none" else last_error
            status, why = "ok", ""
            if prov == "active" and power != "power on":
                status, why = "fail", f"deployed but {power}"
            if fault:
                status, why = "fail", f"fault: {fault}"
            elif maint:
                status = "fail" if prov == "active" else "warn"
                why = why or "maintenance"
            if prov.endswith("failed") or prov == "error":
                status, why = ("fail" if prov == "error" else "warn"), why or prov
            if status != "ok":
                problems.append(dict(n, status=status, why=why, fault=fault, last_error=last_error))
            rows.append([n.get("name") or "", n.get("uuid"), power, prov, "yes" if maint else "no",
                         fault or (str(n.get("maintenance_reason") or "") if maint else ""), status.upper() if status != "ok" else "OK"])
        status = "fail" if any(p["status"] == "fail" for p in problems) else "warn" if problems else "ok"
        r.step("nodes", "Bare metal nodes (ironic, through the BMC)", status,
               f"{len(nodes)} node(s); {len(problems)} with a problem." if nodes else "No bare metal node in the undercloud.",
               {"columns": ["Node", "UUID", "Power", "Provisioning", "Maintenance", "Fault / reason", "Status"], "rows": rows},
               marks=[p.get("name") or p.get("uuid") for p in problems])
        for p in problems:
            name, uuid = p.get("name") or p.get("uuid"), p.get("uuid")
            cmds = [f"openstack baremetal node show {uuid} -f yaml -c power_state -c provision_state -c maintenance_reason "
                    "-c fault -c last_error", f"openstack baremetal node validate {uuid}"]
            if p["fault"] == "power failure" or (p.get("maintenance_reason") and "power" in str(p.get("maintenance_reason")).lower()):
                text = (f"{name}: ironic cannot read the power state from its BMC (fault 'power failure'): the BMC does not "
                        "answer or its account / password changed. Pacemaker fences a controller through the same BMC, so a "
                        "controller in this state cannot be fenced. Open the BMC web page (management IP) and check it. Once "
                        "the BMC answers again, ironic clears the fault and the maintenance by itself (it retries every 5 "
                        "minutes); unset the maintenance by hand only when it stays.")
                cmds.append(f"openstack baremetal node maintenance unset {uuid}")
            elif p["why"].startswith("deployed but"):
                text = (f"{name} is deployed but {p.get('power_state')}: the node is down. Find out why on its BMC (event log, "
                        "power supply) before powering it on; a compute's instances are down meanwhile.")
            elif p["fault"]:
                text = f"{name}: ironic set the fault '{p['fault']}'. Read the last error, fix the cause, then unset maintenance."
                cmds.append(f"openstack baremetal node maintenance unset {uuid}")
            else:
                text = (f"{name}: {p['why']}" + (f" ({p.get('maintenance_reason')})" if p.get("maintenance_reason") else "")
                        + ". Confirm with the team whether this is planned work.")
            power_fault = p["fault"] == "power failure" or "power" in str(p.get("maintenance_reason") or "").lower()
            r.recommend(text, cmds, where=where,
                        refs=["rhosp-ironic-power", "rhosp-fencing"] if power_fault else ["rhosp-ironic-troubleshoot"],
                        warning=("Do not power a controller on or off from ironic while it is in the Pacemaker cluster; for a "
                                 "compute, move or stop its instances first. ") + (f"Last error: {p['last_error'][:300]}" if p["last_error"] else ""))
        return r.done()

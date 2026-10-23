"""Operation Automation checks of network devices: VyOS gateways (SSH, op-mode show commands through the VyOS script template), Huawei
RCGW routers (SSH, display commands) and NSX-T Manager (REST GET with a read-only Auditor account).

The fixes are complete configuration commands for the device that was read: free rule numbers, the real chains,
interfaces, prefixes and prefix-list entries. The portal never sends them; the engineer pastes them in a change window."""
import ipaddress
import re
import shlex

from .common import Result, json_of, lines, on_host, source, text_of, unavailable, worst

q = shlex.quote


VYOS_OP = "/opt/vyatta/bin/vyatta-op-cmd-wrapper"


def vyos(command):
    """A VyOS op-mode command run non-interactively: the program behind `run` of the script template. (`source
    script-template; run ...` on ONE line fails with "Invalid command: [run]": run is an alias, and bash uses an alias only
    from the next line on.)"""
    return f"{VYOS_OP} {command}"


def vyos_config(text):
    """`show configuration commands` -> list of "set ..." lines without quotes."""
    return [l.strip().replace("'", "") for l in str(text or "").splitlines() if l.strip().startswith("set ")]


def nat_rules(cfg, kind):
    rules = {}
    for l in cfg:
        m = re.match(rf"^set nat {kind} rule (\d+) (.+)$", l)
        if m:
            rules.setdefault(int(m.group(1)), []).append(m.group(2))
    out = []
    for num, attrs in sorted(rules.items()):
        a = " ".join(attrs)

        def val(pattern):
            m = re.search(pattern, a)
            return m.group(1) if m else ""
        out.append({"rule": num, "outbound": val(r"outbound-interface (?:name )?(\S+)"),
                    "inbound": val(r"inbound-interface (?:name )?(\S+)"), "protocol": val(r"\bprotocol (\S+)"),
                    "source": val(r"source address (\S+)"), "dest": val(r"destination address (\S+)"),
                    "dport": val(r"destination port (\S+)"), "to": val(r"translation address (\S+)"),
                    "to_port": val(r"translation port (\S+)"), "disabled": "disable" in attrs})
    return out


def firewall_hooks(cfg):
    """Interface -> chain that filters traffic coming in on it (VyOS 1.4/1.5 forward filter jump, or 1.3 'firewall in')."""
    hooks, rules = {}, {}
    for l in cfg:
        m = re.match(r"^set firewall ipv4 (forward|input) filter rule (\d+) (.+)$", l)
        if m:
            rules.setdefault((m.group(1), int(m.group(2))), []).append(m.group(3))
        m = re.match(r"^set interfaces ethernet (\S+) firewall (?:in|local) (?:name )?(\S+)$", l)
        if m:
            hooks.setdefault(m.group(1), set()).add(m.group(2))
    for (hook, _), attrs in rules.items():
        a = " ".join(attrs)
        iface = re.search(r"inbound-interface (?:name )?(\S+)", a)
        target = re.search(r"jump-target (\S+)", a)
        if iface and target and "action jump" in a:
            hooks.setdefault(iface.group(1), set()).add(target.group(1))
    return {k: sorted(v) for k, v in hooks.items()}


def chain(cfg, name):
    """Default action and rules of a named ipv4 chain."""
    default, rules = "accept", {}
    for l in cfg:
        m = re.match(rf"^set firewall (?:ipv4 )?name {re.escape(name)} default-action (\S+)$", l)
        if m:
            default = m.group(1)
        m = re.match(rf"^set firewall (?:ipv4 )?name {re.escape(name)} rule (\d+) (.+)$", l)
        if m:
            rules.setdefault(int(m.group(1)), []).append(m.group(2))
    parsed = []
    for num, attrs in sorted(rules.items()):
        a = " ".join(attrs)
        parsed.append({"rule": num, "action": (re.search(r"action (\S+)", a) or [None, ""])[1],
                       "states": set(re.findall(r"state (established|related|new|invalid)", a)),
                       "protocol": (re.search(r"protocol (\S+)", a) or [None, ""])[1],
                       "dport": (re.search(r"destination port (\S+)", a) or [None, ""])[1], "disabled": "disable" in attrs})
    return default, parsed


def chains_defined(cfg):
    return sorted({m.group(1) for l in cfg for m in [re.match(r"^set firewall (?:ipv4 )?name (\S+) ", l)] if m})


def port_in(spec, port):
    for part in str(spec or "").split(","):
        lo, _, hi = part.partition("-")
        if lo.isdigit() and int(lo) <= port <= int(hi or lo):
            return True
    return False


def modern(cfg):
    """VyOS 1.4/1.5 syntax (firewall ipv4 …, interface "name …") rather than 1.3."""
    return any(l.startswith("set firewall ipv4 ") or "-interface name " in l for l in cfg)


def fw_name(cfg, name):
    return f"set firewall ipv4 name {name}" if modern(cfg) else f"set firewall name {name}"


def free_before(numbers):
    """A free rule number in front of every rule: 5 like the WI, else the highest free number below the first rule."""
    if not numbers or 5 < min(numbers):
        return 5
    return next((n for n in range(min(numbers) - 1, 0, -1) if n not in numbers), None)


def free_after(numbers, after):
    n = after + 1
    while n in numbers:
        n += 1
    return n


def iface_addresses(cfg):
    """Interface -> [ip_interface] from "set interfaces ethernet ethX [vif N] address A/L"."""
    out = {}
    for l in cfg:
        m = re.match(r"^set interfaces ethernet (\S+)(?: vif (\d+))? address (\d+\.\d+\.\d+\.\d+/\d+)$", l)
        if m:
            name = f"{m.group(1)}.{m.group(2)}" if m.group(2) else m.group(1)
            out.setdefault(name, []).append(ipaddress.ip_interface(m.group(3)))
    return out


def iface_for(addresses, ip):
    """The interface whose subnet holds ip ('' when none)."""
    try:
        addr = ipaddress.ip_address(str(ip).split("/")[0])
    except ValueError:
        return ""
    return next((i for i, nets in addresses.items() for n in nets if addr in n.network), "")


def vyos_change(lines_):
    return ["configure"] + lines_ + ["commit", "save", "exit"]


def vyos_action(lines_, verify=()):
    """The fix as a vbash script (VyOS script template): the configuration lines, commit, save, then op-mode checks."""
    return {"shell": "vyos", "risk": "high", "commands": vyos_change(lines_) + [f"run {v}" for v in verify]}


class VyosNatFirewall:
    """WI "Troubleshooting SNAT DNAT VyOS 1.5 + Lesson Learned": default route, SNAT/DNAT rules, the firewall chain that
    really handles WAN traffic (established/related, new for DNAT ports)."""
    sources = ("host",)
    phases = 1

    @staticmethod
    def reads(phase, data, params, ctx):
        return {"host": {"config": vyos("show configuration commands"), "route": vyos("show ip route 0.0.0.0/0"),
                         "ifaces": vyos("show interfaces")}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("vyos-nat-firewall")
        where = f"{on_host(ctx)}, VyOS CLI"
        item = source(data, "config")
        if unavailable(item):
            r.step("config", "Read the VyOS configuration", "fail", unavailable(item))
            return r.done()
        cfg = vyos_config(text_of(item))
        new = modern(cfg)
        name_kw = "name " if new else ""
        addresses = iface_addresses(cfg)
        snat, dnat = nat_rules(cfg, "source"), nat_rules(cfg, "destination")
        wan = params.get("wan") or next((x["outbound"] for x in snat if x["outbound"]), "") or next((x["inbound"] for x in dnat if x["inbound"]), "")
        route = text_of(source(data, "route"))
        default = any(l.startswith("set protocols static route 0.0.0.0/0") for l in cfg) or "0.0.0.0/0" in route
        r.step("route", "Default route to the upstream", "ok" if default else "fail",
               "Present." if default else "No default route: SNAT to the internet cannot work.",
               evidence=route or None)
        if not default and addresses.get(wan):
            net = addresses[wan][0].network
            gw = next(net.hosts())
            r.recommend(f"Add the default route out of {wan} ({addresses[wan][0]}). {gw} is the first address of the WAN subnet "
                        f"{net}, the usual upstream gateway: confirm it with the upstream before the commit.",
                        vyos_change([f"set protocols static route 0.0.0.0/0 next-hop '{gw}'"]) + ["show ip route 0.0.0.0/0", "ping 8.8.8.8 count 3"],
                        where=where, action=vyos_action([f"set protocols static route 0.0.0.0/0 next-hop '{gw}'"], ["show ip route 0.0.0.0/0"]))
        on_wan = [x for x in snat if x["outbound"] == wan and not x["disabled"]]
        r.step("snat", f"SNAT on the WAN interface {wan or '?'}", "ok" if on_wan else "fail",
               ", ".join(f"rule {x['rule']}: {x['source'] or 'any'} → {x['to']}" for x in on_wan) or "No SNAT rule out of the WAN interface.",
               {"columns": ["Rule", "Outbound", "Source", "Translation"], "rows": [[x["rule"], x["outbound"], x["source"], x["to"]] for x in snat]})
        if wan and not on_wan:
            lans = [str(n.network) for i, nets in sorted(addresses.items()) if i != wan for n in nets if n.network.is_private]
            numbers = {x["rule"] for x in snat}
            cmds, n = [], max(numbers or {99})
            for lan in lans:
                n = free_after(numbers, n)
                numbers.add(n)
                cmds += [f"set nat source rule {n} description 'SNAT {lan} to WAN masquerade'",
                         f"set nat source rule {n} outbound-interface {name_kw}'{wan}'",
                         f"set nat source rule {n} source address '{lan}'",
                         f"set nat source rule {n} translation address 'masquerade'"]
            if cmds:
                r.recommend(f"Add SNAT (masquerade) out of {wan} for the LAN subnets {', '.join(lans)} — leave out a subnet that "
                            "must not reach the internet (e.g. management).",
                            vyos_change(cmds) + ["show nat source rules", "show nat source translations"], where=where,
                            action=vyos_action(cmds, ["show nat source rules"]))
        r.step("dnat", "DNAT (port forwarding) rules", "info" if dnat else "ok",
               f"{len(dnat)} rule(s)." if dnat else "No DNAT rule.",
               {"columns": ["Rule", "Inbound", "Protocol", "Public address:port", "To"],
                "rows": [[x["rule"], x["inbound"], x["protocol"], f"{x['dest']}:{x['dport']}", f"{x['to']}:{x['to_port'] or x['dport']}"] for x in dnat]})
        hooks = firewall_hooks(cfg)
        wan_chains = hooks.get(wan, [])
        unused = [c for c in chains_defined(cfg) if not any(c in v for v in hooks.values())]
        r.step("hook", f"Firewall chain that handles traffic from {wan or 'WAN'}", "ok" if wan_chains else "info",
               (f"{', '.join(wan_chains)} (hooked)." if wan_chains else "No chain is hooked to the WAN interface: forward traffic is not filtered.")
               + (f" Defined but NOT hooked (rules there have no effect): {', '.join(unused)}." if unused else ""))
        show_fw = "show firewall ipv4 name" if new else "show firewall name"
        for name in wan_chains:
            default_action, rules = chain(cfg, name)
            numbers = {x["rule"] for x in rules}
            est = any({"established", "related"} <= x["states"] and x["action"] in ("accept", "return") and not x["disabled"] for x in rules)
            needs = default_action == "drop"
            r.step(f"state_{name}", f"{name}: allows established/related (return traffic of SNAT)",
                   "ok" if est or not needs else "fail",
                   "Present." if est else f"Missing while default-action is {default_action}: replies to outbound (SNAT) "
                                          "connections are dropped — the root cause in the lesson learned.",
                   marks=[f"name {name} default-action"] if needs and not est else None)
            if needs and not est:
                n = free_before(numbers)
                if n is None:
                    r.recommend(f"{name} has no free rule number in front of rule {min(numbers)}: renumber the first rule, then add "
                                "the established/related rule in front of every other rule.", where=where)
                else:
                    state = ([f"{fw_name(cfg, name)} rule {n} state 'established'", f"{fw_name(cfg, name)} rule {n} state 'related'"] if new else
                             [f"{fw_name(cfg, name)} rule {n} state established 'enable'", f"{fw_name(cfg, name)} rule {n} state related 'enable'"])
                    r.recommend(f"Add rule {n} at the top of {name} (the chain hooked to {wan}) so replies to outbound connections "
                                "come back in. Note the commit ID first (show system commit) for a quick rollback.",
                                vyos_change([f"{fw_name(cfg, name)} rule {n} action '{'return' if new else 'accept'}'"] + state
                                            + [f"{fw_name(cfg, name)} rule {n} description 'allow established related'"])
                                + [f"{show_fw} {name}"],
                                where=where,
                                action=vyos_action([f"{fw_name(cfg, name)} rule {n} action '{'return' if new else 'accept'}'"] + state
                                                   + [f"{fw_name(cfg, name)} rule {n} description 'allow established related'"],
                                                   [f"{show_fw} {name}"]), warning="Rollback: configure → rollback-soft <commit ID> (1.5) or delete the rule, commit, save.")
            missing = []
            for d in [x for x in dnat if x["inbound"] == wan and x["dport"] and not x["disabled"]]:
                port = int(re.findall(r"\d+", d["dport"])[0])
                ok = any(port_in(x["dport"], port) and (not x["protocol"] or x["protocol"] in (d["protocol"], "tcp_udp"))
                         and x["action"] in ("accept", "return") and ("new" in x["states"] or not x["states"]) for x in rules)
                if not ok and default_action == "drop":
                    missing.append(d)
            if [x for x in dnat if x["inbound"] == wan]:
                r.step(f"dnat_{name}", f"{name}: allows the DNAT ports (state new)", "fail" if missing else "ok",
                       ("Not allowed: " + ", ".join(f"{d['protocol'] or 'tcp'}/{d['dport']}" for d in missing) + ".")
                       if missing else "Every DNAT port is allowed.",
                       marks=[f"set nat destination rule {d['rule']} destination port" for d in missing])
            if missing:
                cmds, n = [], max(numbers or {0})
                for d in missing:
                    n = free_after(numbers, n)
                    numbers.add(n)
                    proto = d["protocol"] or "tcp"
                    cmds += [f"{fw_name(cfg, name)} rule {n} action '{'return' if new else 'accept'}'",
                             f"{fw_name(cfg, name)} rule {n} protocol '{proto}'",
                             f"{fw_name(cfg, name)} rule {n} destination port '{d['dport']}'",
                             f"{fw_name(cfg, name)} rule {n} state 'new'" if new else f"{fw_name(cfg, name)} rule {n} state new 'enable'",
                             f"{fw_name(cfg, name)} rule {n} description 'allow new {proto} {d['dport']} to {d['to']} (DNAT rule {d['rule']})'"]
                r.recommend(f"Allow the DNAT ports that {name} drops: " + ", ".join(f"{d['protocol'] or 'tcp'}/{d['dport']} → {d['to']}" for d in missing) + ".",
                            vyos_change(cmds) + [f"{show_fw} {name}"], where=where, action=vyos_action(cmds, [f"{show_fw} {name}"]))
        tests = []
        for d in [x for x in dnat if x["inbound"] == wan and not x["disabled"]][:3]:
            lan = iface_for(addresses, d["to"])
            tests += [f"nc -vz{'u' if d['protocol'] == 'udp' else ''} {d['dest'] or '<public IP>'} {d['dport']}   # from an external host",
                      f"sudo tcpdump -ni {wan} '{d['protocol'] or 'tcp'} port {d['dport']}'   # on VyOS: arrives on WAN?"]
            if lan:
                tests.append(f"sudo tcpdump -ni {lan} 'host {d['to']} and port {d['to_port'] or d['dport']}'   # on VyOS: forwarded to the VM?")
        lan_src = next((x["source"] for x in on_wan if x["source"]), "")
        tests += [f"sudo tcpdump -ni {wan or 'eth0'} host 8.8.8.8   # on VyOS while a VM{(' in ' + lan_src) if lan_src else ''} pings 8.8.8.8"]
        r.recommend("Test after the change from the right places: inbound from an external host (not from VyOS to its own "
                    "public IP), outbound from a VM, with tcpdump on the WAN and LAN interfaces.", list(dict.fromkeys(tests)), where=where)
        return r.done()


class VyosUpgradePrecheck:
    """WI "VyOS Upgrade 1.3 → 1.5 + CVE-2025-30095 Mitigation": version, hw-id of every ethernet interface (must be set
    before the upgrade), installed images, dropbear host keys."""
    sources = ("host",)
    phases = 1

    @staticmethod
    def reads(phase, data, params, ctx):
        return {"host": {"version": vyos("show version"), "config": vyos("show configuration commands"),
                         "images": vyos("show system image"), "macs": "ip -o link show | grep -E ' eth[0-9]+'",
                         "ifaces": vyos("show interfaces"),
                         "keys": "ls /etc/dropbear/ /etc/dropbear-initramfs/ 2>/dev/null; true", "boot": "ls -l /config/config.boot"}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("vyos-upgrade-precheck")
        where = f"{on_host(ctx)}, VyOS CLI"
        version = text_of(source(data, "version"))
        v = (re.search(r"Version:\s*(?:VyOS\s*)?(\S+)", version) or [None, "?"])[1]
        due = v.startswith(("1.2", "1.3", "1.4"))
        r.step("version", "Current VyOS version", "info", f"VyOS {v}." + (" Upgrade to 1.5 is due." if due else ""))
        cfg = vyos_config(text_of(source(data, "config")))
        ifaces = sorted({m.group(1) for l in cfg for m in [re.match(r"^set interfaces ethernet (eth\d+) ", l)] if m})
        hwid = {m.group(1): m.group(2) for l in cfg for m in [re.match(r"^set interfaces ethernet (eth\d+) hw-id (\S+)", l)] if m}
        macs = {m.group(1): m.group(2) for l in lines(text_of(source(data, "macs")))
                for m in [re.search(r"\d+: (eth\d+)[@:].*link/ether ([0-9a-f:]{17})", l)] if m}
        for l in lines(text_of(source(data, "ifaces"))):
            m = re.match(r"^(eth\d+)\s+\S+\s+([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b", l)
            if m:
                macs.setdefault(m.group(1), m.group(2))
        missing = [i for i in ifaces if i not in hwid]
        r.step("hwid", "hw-id set on every ethernet interface", "fail" if missing else "ok",
               f"Missing on: {', '.join(missing)} — interfaces can swap after booting the new image." if missing else "All set.",
               {"columns": ["Interface", "hw-id in config", "MAC now"], "rows": [[i, hwid.get(i, "-"), macs.get(i, "-")] for i in ifaces]})
        if missing:
            unknown = [i for i in missing if i not in macs]
            r.recommend("Pin every interface to its current MAC BEFORE adding the new image, so eth0/eth1/eth2 keep their role "
                        "after the reboot.",
                        vyos_change([f"set interfaces ethernet {i} hw-id '{macs[i]}'" for i in missing if i in macs])
                        + ["show configuration commands | match hw-id"], where=where,
                        action=vyos_action([f"set interfaces ethernet {i} hw-id '{macs[i]}'" for i in missing if i in macs],
                                           ["show interfaces"]) if any(i in macs for i in missing) else None,
                        warning=f"MAC not found for {', '.join(unknown)}: read it with show interfaces ethernet {unknown[0]} first." if unknown else "")
        images = lines(text_of(source(data, "images")))
        r.step("images", "Installed images", "info", "; ".join(images[:6]) or "-")
        current = (re.search(r"\d+:\s+(\S+)\s+\(default boot\)", "\n".join(images)) or [None, v])[1]
        keys = [k for k in lines(text_of(source(data, "keys"))) if "key" in k]
        r.step("cve", "CVE-2025-30095: dropbear host keys", "warn" if keys else "ok",
               f"{len(keys)} key file(s) present: regenerate them after adding the image and before the reboot." if keys else "No dropbear key files.")
        backup = "config.boot" in text_of(source(data, "boot"))
        r.step("backup", "Config backup /config/config.boot", "ok" if backup else "warn", "Present." if backup else "Not found.")
        url = ctx.get("vyos_image_url") or ""
        nh = next((m.group(1) for l in cfg for m in [re.match(r"^set protocols static route 0\.0\.0\.0/0 next-hop (\S+)", l)] if m), "")
        if due:
            safe = re.sub(r"[^A-Za-z0-9_.-]", "_", str(ctx.get("host_name") or "vyos"))
            backup = f"/home/vyos/config-backup/{safe}/config.boot.$(date +%Y%m%d-%H%M%S).before-1.5"
            src = f"{ctx.get('host_user') or 'vyos'}@{str(ctx.get('host_address') or '<management IP>').split(':')[0]}"
            r.recommend(f"Upgrade {v} → 1.5 in this order (snapshot the VM in vCenter/OpenStack first; the commands change nothing "
                        "until the reboot):",
                        ["configure", "save", "exit",
                         f"mkdir -p -m 700 /home/vyos/config-backup/{safe}; scp -P {ctx.get('host_port') or 22} {src}:/config/config.boot "
                         f"{backup}   # on the jump host{' ' + ctx['host_jump'] if ctx.get('host_jump') else ''}: the backup stays off the VyOS",
                         f"add system image {url or '<URL of the VyOS 1.5 image: set wi.vyos_image_url in sites.yml>'}",
                         "show system image   # 1.5 listed, do NOT reboot yet"]
                        + (["sudo rm -f /etc/dropbear/*key* /etc/dropbear-initramfs/*key*",
                            "sudo dropbearkey -t rsa -s 4096 -f /etc/dropbear_rsa_host_key"] if keys else [])
                        + ["reboot now", "show version", "show interfaces", "show ip route",
                           f"ping {nh} count 3" if nh else "", "ping 8.8.8.8 count 3"],
                        where=where,
                        warning=f"Rollback: set system image default-boot '{current}' and reboot now; or configure → "
                                "scp the backup from the jump host to /tmp of the VyOS → load /tmp/<backup> → commit → save.")
        return r.done()


class VyosStaticRoute:
    """WIs "IP Route on VyOS Does Not Show the Static Route" (Flex NAT Gateway) and "Metro Link Interconnection Problems
    from the NAT Gateway (VyOS)": configured static routes in the routing table, metro gateway reachable."""
    sources = ("host",)
    phases = 1

    @staticmethod
    def reads(phase, data, params, ctx):
        reads = {"config": vyos("show configuration commands"), "rib": vyos("show ip route static"), "ifaces": vyos("show interfaces")}
        if params.get("gateway"):
            reads["ping"] = f"ping -c 3 -W 2 {q(params['gateway'])} >/dev/null 2>&1 && echo OK || echo FAIL"
        return {"host": reads}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("vyos-static-route")
        where = f"{on_host(ctx)}, VyOS CLI"
        cfg = vyos_config(text_of(source(data, "config")))
        addresses = iface_addresses(cfg)
        routes = {}
        for l in cfg:
            m = re.match(r"^set protocols static route (\S+) next-hop (\S+)", l)
            if m:
                routes.setdefault(m.group(1), []).append(m.group(2))
        rib = text_of(source(data, "rib"))
        rows, missing = [], []
        for prefix, hops in sorted(routes.items()):
            present = bool(re.search(rf"^S>?\*?\s*{re.escape(prefix)}\b", rib, re.M)) or prefix in rib
            via = [f"{h} ({iface_for(addresses, h) or 'no connected subnet'})" for h in hops]
            rows.append([prefix, ", ".join(via), "yes" if present else "NO"])
            if not present:
                missing.append(prefix)
        want = params.get("prefix") or ""
        gateway = params.get("gateway") or ""
        not_configured = want and want not in routes
        r.step("routes", "Static routes in the routing table (show ip route)", "fail" if missing or not_configured else "ok" if routes else "warn",
               ("Missing: " + ", ".join(missing + ([f"{want} (not configured)"] if not_configured else [])) + "."
                if missing or not_configured else f"{len(routes)} static route(s), all present." if routes else "No static route configured."),
               {"columns": ["Prefix", "Next hop (interface)", "In routing table"], "rows": rows}, evidence=rib or None)
        for prefix in missing:
            hops = routes[prefix]
            unreachable = [h for h in hops if not iface_for(addresses, h)]
            if unreachable:
                r.recommend(f"{prefix} via {', '.join(hops)} is configured but never installed: {', '.join(unreachable)} is on no "
                            "subnet of this VyOS. Re-adding the same route does not help: put the Metro IP on the Metro interface "
                            "(or correct the next hop in Service Portal → Network → NAT Gateway → Edit Configuration → Static Route).",
                            [f"show ip route {unreachable[0]}", "show interfaces", f"ping {unreachable[0]} count 3"], where=where)
                continue
            r.recommend(f"{prefix} via {', '.join(hops)} is configured but not in the routing table (not loaded). On a Flex NAT "
                        "Gateway re-add it in the Service Portal (Network → NAT Gateway → Edit Configuration → Static Route: delete "
                        f"{prefix} via {hops[0]}, add it again); on a VyOS without the portal use the CLI lines.",
                        [f"ping {hops[0]} count 3"]
                        + vyos_change([f"delete protocols static route {prefix}"] + [f"set protocols static route {prefix} next-hop '{h}'" for h in hops])
                        + [f"show ip route {prefix}"], where=where,
                        action=vyos_action([f"delete protocols static route {prefix}"] + [f"set protocols static route {prefix} next-hop '{h}'" for h in hops],
                                           [f"show ip route {prefix}"]))
        if not_configured:
            nh = gateway or "<next hop>"
            r.recommend(f"{want} is not configured: add it" + (f" via the Metro gateway {gateway}" if gateway else "")
                        + " (Service Portal → NAT Gateway → Edit Configuration → Static Route, or the CLI).",
                        vyos_change([f"set protocols static route {want} next-hop '{nh}'"]) + [f"show ip route {want}"], where=where,
                        action=vyos_action([f"set protocols static route {want} next-hop '{nh}'"], [f"show ip route {want}"]) if gateway else None)
        if gateway:
            ok = "OK" in text_of(source(data, "ping"))
            iface = iface_for(addresses, gateway)
            mine = next((str(n.ip) for n in addresses.get(iface, [])), "")
            r.step("gateway", f"Metro gateway {gateway} reachable", "ok" if ok else "fail",
                   "Ping OK." if ok else (f"No reply. {iface} ({mine}) is on its subnet." if iface else
                                          f"No reply, and no interface of this VyOS is on the subnet of {gateway}: the Metro IP is missing."))
            if not ok:
                r.recommend((f"The Metro IP of VyOS ({mine} on {iface}) does not reach {gateway}: check that APIC learned {mine} "
                             "(endpoint in the right EPG), then the NAT of the VM subnet to the VyOS Metro IP. Still down → ticket "
                             "to Datacom Acme Corp with these outputs.") if iface else
                            f"Add the Metro IP on the Metro interface of VyOS (same subnet as {gateway}), then test again.",
                            [f"ping {gateway} count 5", "show arp", f"show interfaces ethernet {iface}" if iface else "show interfaces",
                             f"moquery -c fvCEp -f 'fv.CEp.ip==\"{mine}\"'   # on APIC: learned?" if mine else ""],
                            where=where)
        return r.done()


def prefix_entries(text, name="ALLOWED_BGP_OUT"):
    """Entries of an XPL ip-prefix-list ("A.B.C.D LEN[ ge/le …][,]") or classic ip ip-prefix lines -> ["A.B.C.D LEN", …]."""
    entries, inside = [], False
    for l in str(text or "").splitlines():
        s = l.strip()
        if s.startswith(f"xpl ip-prefix-list {name}"):
            inside = True
            continue
        if inside and s.startswith("end-list"):
            break
        if inside:
            m = re.match(r"^(\d+\.\d+\.\d+\.\d+ \d+(?: (?:greater-equal|less-equal) \d+)*)\s*,?$", s)
            if m:
                entries.append(m.group(1))
        m = re.search(rf"ip-prefix(?:-list)? {name} index \d+ permit (\d+\.\d+\.\d+\.\d+ \d+)", s)
        if m:
            entries.append(m.group(1))
    return entries


def xpl_list(name, entries):
    return [f"xpl ip-prefix-list {name}"] + [f" {e}," for e in entries[:-1]] + [f" {entries[-1]}", " end-list"]


class HuaweiBgpPrefix:
    """WI "Adding an Internet Subnet to Huawei RCGW": pre-/post-check of one prefix (routing table, BGP, prefix list,
    advertised to the upstream), and the change for this router (display commands only are run)."""
    sources = ("host",)
    phases = 1

    @staticmethod
    def reads(phase, data, params, ctx):
        net = ipaddress.ip_network(params["prefix"], strict=False)
        peer = params.get("peer") or ctx.get("upstream_peer") or ""
        reads = {"peers": "display bgp peer", "rib": f"display ip routing-table {net.network_address}",
                 "longer": f"display ip routing-table {net.network_address} {net.prefixlen} longer-match",
                 "bgp": f"display bgp routing-table {net.network_address}",
                 "conf": f"display current-configuration | include {net.network_address}",
                 "plist": "display current-configuration | section ALLOWED_BGP_OUT"}
        if peer:
            reads["adv"] = f"display bgp routing-table peer {peer} advertised-routes {net.network_address} {net.prefixlen}"
        return {"device": reads}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("huawei-bgp-prefix")
        where = f"{on_host(ctx)}, VRP CLI (system-view)"
        net = ipaddress.ip_network(params["prefix"], strict=False)
        addr, mask, length = str(net.network_address), str(net.netmask), net.prefixlen
        peer = params.get("peer") or ctx.get("upstream_peer") or ""
        peers_text = text_of(source(data, "peers"))
        asn = (re.search(r"Local AS number\s*:\s*(\d+)", peers_text) or [None, ""])[1]
        peers = [l for l in lines(peers_text) if re.match(r"^\s*\d+\.\d+\.\d+\.\d+\s", l)]
        down = [l.split()[0] for l in peers if "Established" not in l]
        r.step("peers", "BGP peers Established", "fail" if down else "ok" if peers else "warn",
               f"Not established: {', '.join(down)}." if down else f"{len(peers)} peer(s) established (local AS {asn or '?'})." if peers else "No peer list.",
               evidence="\n".join(peers) or None)
        rib = text_of(source(data, "rib"))
        in_rib = bool(re.search(rf"\b{re.escape(addr)}/{length}\b", rib))
        r.step("rib", f"{net} in the routing table", "ok" if in_rib else "warn", "Present." if in_rib else "Not present.", evidence=rib or None)
        longer = [l for l in lines(text_of(source(data, "longer"))) if re.match(r"^\s*\d+\.\d+\.\d+\.\d+/\d+", l) and "NULL0" not in l]
        r.step("internal", f"Internal (more specific) routes inside {net}", "ok" if longer else "warn",
               f"{len(longer)} route(s) towards the workload." if longer else "Only the discard route or nothing: traffic to the subnet "
               "would be dropped once it is advertised. Check the internal route before the change.", evidence="\n".join(longer) or None)
        bgp = text_of(source(data, "bgp"))
        in_bgp = addr in bgp and "does not exist" not in bgp
        r.step("bgp", f"{net} in the BGP table", "ok" if in_bgp else "warn",
               "Present." if in_bgp else "Not present (not originated yet).", evidence=bgp or None)
        conf = text_of(source(data, "conf"))
        static_null = bool(re.search(rf"ip route-static {re.escape(addr)} .*NULL0", conf))
        has_network = bool(re.search(rf"network {re.escape(addr)} {re.escape(mask)}", conf))
        has_aggregate = bool(re.search(rf"aggregate {re.escape(addr)} {re.escape(mask)}", conf))
        r.step("config", "Static discard route (NULL0) and BGP network/aggregate",
               "ok" if static_null and has_network and has_aggregate else "warn",
               ", ".join(f"{k}: {'yes' if v else 'NO'}" for k, v in (("NULL0 route", static_null), ("network", has_network), ("aggregate", has_aggregate))) + ".",
               evidence=conf or None)
        plist = text_of(source(data, "plist"))
        entries = prefix_entries(plist)
        listed = f"{addr} {length}" in entries
        r.step("plist", "Prefix in ALLOWED_BGP_OUT", "ok" if listed else "warn",
               f"Listed ({len(entries)} entries)." if listed else f"Not in the prefix list ({len(entries)} entries): it will not be exported.",
               evidence=plist or None)
        advertised = None
        if "adv" in (data or {}):
            adv = text_of(source(data, "adv"))
            advertised = addr in adv and "does not exist" not in adv
            r.step("adv", f"Advertised to the upstream peer {peer}", "ok" if advertised else "warn",
                   "Advertised." if advertised else "Not advertised.", evidence=adv or None)
        change = []
        if not (has_aggregate and has_network):
            change += [f"bgp {asn or '<local AS>'}", " ipv4-family unicast"]
            change += [] if has_aggregate else [f"  aggregate {addr} {mask} detail-suppressed"]
            change += [] if has_network else [f"  network {addr} {mask}"]
            change += [" quit", "quit"]
        if not static_null:
            change.append(f"ip route-static {addr} {mask} NULL0 preference 180")
        if change:
            change.append("commit")
        if not listed and entries:
            change += xpl_list("ALLOWED_BGP_OUT", entries + [f"{addr} {length}"]) + ["display configuration candidate", "commit"]
        if change:
            post = [f"display ip routing-table {addr}", f"display bgp routing-table {addr}",
                    f"display current-configuration | include {addr}", "display current-configuration | section ALLOWED_BGP_OUT"]
            if peer:
                post.append(f"display bgp routing-table peer {peer} advertised-routes {addr} {length}")
            rollback = []
            if not (has_aggregate and has_network):
                rollback += [f"bgp {asn or '<local AS>'} / ipv4-family unicast / undo aggregate {addr} {mask} / undo network {addr} {mask}"]
            if not static_null:
                rollback.append(f"undo ip route-static {addr} {mask} NULL0")
            if not listed and entries:
                rollback.append(f"xpl ip-prefix-list ALLOWED_BGP_OUT with the {len(entries)} current entries (without {addr} {length}), end-list")
            r.recommend(f"Change for {net} on this router with an approved change request. The prefix list is written in full: "
                        f"the {len(entries)} current entries plus {addr} {length} (XPL replaces the whole list). After the post-check: "
                        "return, save.",
                        ["system-view"] + change + ["return"] + post + ["save"], where=where,
                        warning="Rollback: " + "; ".join(rollback) + "; commit." + ("" if longer else
                                f" No internal route inside {net} yet: advertising it now blackholes the traffic."))
        elif not entries and plist.strip():
            r.recommend("ALLOWED_BGP_OUT could not be parsed: write the list by hand from 'display current-configuration | section "
                        "ALLOWED_BGP_OUT' — every existing entry plus the new one.", where=where)
        elif advertised is False:
            r.recommend(f"{net} is configured and listed but not advertised to {peer}: check the export policy and the peer.",
                        [f"display bgp peer {peer} verbose | include policy|filter", "display current-configuration | section ITS-Net-Out",
                         f"display bgp routing-table peer {peer} advertised-routes {addr} {length}"], where=where)
        return r.done()


class NsxtSnatPriority:
    """WI "Configure Priority SNAT Internet Colo MPLS NSX-T": overlapping SNAT rules of one source on a Tier-1 gateway
    (the specific Colo/MPLS rule must have a smaller priority number than the catch-all Internet rule)."""
    sources = ("nsxt",)
    phases = 1

    @staticmethod
    def reads(phase, data, params, ctx):
        t1 = params["tier1"]
        return {"nsxt": {"rules": f"/policy/api/v1/infra/tier-1s/{t1}/nat/USER/nat-rules?page_size=1000"}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("nsxt-snat-priority")
        t1 = params["tier1"]
        item = source(data, "rules")
        if unavailable(item):
            r.step("rules", "Read the NAT rules of the Tier-1 gateway", "fail", unavailable(item))
            return r.done()
        rules = [x for x in (json_of(item) or {}).get("results") or [] if str(x.get("action")).upper() == "SNAT"]
        only = params.get("source") or ""
        if only:
            rules = [x for x in rules if only in str(x.get("source_network") or "")]
        rows = [[x.get("display_name") or x.get("id"), x.get("source_network") or "any", x.get("destination_network") or "any",
                 x.get("translated_network"), x.get("sequence_number"), "yes" if x.get("enabled", True) else "no"] for x in rules]
        r.step("rules", "SNAT rules", "info" if rules else "warn", f"{len(rules)} SNAT rule(s).",
               {"columns": ["Rule", "Source", "Destination", "Translated", "Priority", "Enabled"], "rows": rows})
        by_source = {}
        for x in rules:
            if x.get("enabled", True):
                by_source.setdefault(str(x.get("source_network") or "any"), []).append(x)
        problems, changes = [], {}
        for src, group in by_source.items():
            if len(group) < 2:
                continue
            catch = [x for x in group if not x.get("destination_network")]
            specific = [x for x in group if x.get("destination_network")]
            prios = [x.get("sequence_number") for x in group]
            if len(set(prios)) < len(prios):
                problems.append(f"{src}: two rules with the same priority {prios}")
            wrong = [s for s in specific for c in catch if (s.get("sequence_number") or 0) >= (c.get("sequence_number") or 0)]
            for c in catch:
                for s in specific:
                    if (s.get("sequence_number") or 0) >= (c.get("sequence_number") or 0):
                        problems.append(f"{src}: specific rule {s.get('display_name')} ({s.get('destination_network')}, priority "
                                        f"{s.get('sequence_number')}) is evaluated after the catch-all {c.get('display_name')} "
                                        f"(priority {c.get('sequence_number')})")
            if wrong or len(set(prios)) < len(prios):
                # Specific rules first (smallest numbers), the catch-all after them: swap/space them like the WI (100, 200).
                ordered = sorted(specific, key=lambda x: x.get("sequence_number") or 0) + sorted(catch, key=lambda x: x.get("sequence_number") or 0)
                current = sorted(x.get("sequence_number") or 0 for x in ordered)
                new = current if len(set(current)) == len(current) else [current[0] + 100 * i for i in range(len(ordered))]
                for x, n in zip(ordered, new):
                    if (x.get("sequence_number") or 0) != n:
                        changes[x.get("id")] = (x, n)
        r.step("order", "Specific rule first, catch-all last", "fail" if problems else "ok",
               "; ".join(problems) if problems else "No overlapping SNAT rule is evaluated in the wrong order.")
        if changes:
            host = ctx.get("nsxt_host") or "<NSX Manager>"
            base = f"https://{host}/policy/api/v1/infra/tier-1s/{t1}/nat/USER/nat-rules"
            cmds = ["read -p 'NSX admin user: ' NSX_USER"]
            cmds += [f"curl -sk -u \"$NSX_USER\" -X PATCH {base}/{rid} -H 'Content-Type: application/json' -d '{{\"sequence_number\": {n}}}'"
                     for rid, (x, n) in changes.items()]
            cmds.append(f"curl -sk -u \"$NSX_USER\" {base} | jq -r '.results[] | select(.action==\"SNAT\") | "
                        "[.display_name, .source_network, (.destination_network // \"any\"), .sequence_number] | @tsv'")
            r.recommend("Set the priorities so the specific (Colo/MPLS) rule comes first: "
                        + ", ".join(f"{x.get('display_name')} {x.get('sequence_number')} → {n}" for x, n in changes.values())
                        + f" (UI: Networking → NAT → gateway {t1} → edit the rule → Priority, Save; or the Policy API below). "
                        "Test with NEW sessions: existing sessions keep their NAT state.",
                        cmds, where=f"NSX Manager {host} (any shell with curl; curl asks for the password)",
                        warning="Rollback: PATCH the old values back — " + ", ".join(f"{x.get('display_name')} {x.get('sequence_number')}"
                                                                                for x, _ in changes.values()) + ". Never delete rules to roll back.")
        return r.done()


# =========================================================================================== NSX-T health (platform)
def epoch_ms(value):
    """NSX time (epoch milliseconds) -> 'YYYY-MM-DD HH:MM' UTC ('' when unknown)."""
    import datetime
    try:
        return datetime.datetime.fromtimestamp(int(value) / 1000, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M")
    except (TypeError, ValueError, OverflowError, OSError):
        return ""


TN_OK = {"success", "node_ready", "transport_node_ready"}
TN_PENDING = {"pending", "in_progress", "in_sync", "vm_deployment_queued", "vm_deployment_in_progress", "registration_pending"}
NSX_SEVERITY = {"CRITICAL": "fail", "HIGH": "fail", "MEDIUM": "warn", "LOW": "info"}


class NsxtHealth:
    """Platform health of NSX-T (not from a KB page): the open alarms of NSX Manager with NSX's own description and
    recommended action, the state of the manager cluster, and transport nodes (ESXi, edges) that are not ready.
    Read-only NSX account (GET on the Manager API)."""
    sources = ("nsxt",)
    phases = 1

    @staticmethod
    def reads(phase, data, params, ctx):
        return {"nsxt": {"alarms": "/api/v1/alarms?status=OPEN&page_size=1000",
                         "acked": "/api/v1/alarms?status=ACKNOWLEDGED&page_size=1000",
                         "cluster": "/api/v1/cluster/status",
                         "tn_state": "/api/v1/transport-nodes/state",
                         "tn": "/api/v1/transport-nodes?page_size=1000"}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("nsxt-health")
        nsx = ctx.get("nsxt_host") or "<NSX Manager>"
        where = f"NSX Manager {nsx}: System → Alarms (or the API with the same account)"
        # ---------------- manager cluster ----------------
        item = source(data, "cluster")
        if unavailable(item):
            r.step("cluster", "NSX Manager cluster", "fail", unavailable(item))
        else:
            c = json_of(item) or {}
            overall = str(((c.get("detailed_cluster_status") or {}).get("overall_status")) or "").upper()
            mgmt = str(((c.get("mgmt_cluster_status") or {}).get("status")) or "").upper()
            control = str(((c.get("control_cluster_status") or {}).get("status")) or "").upper()
            state = overall or mgmt
            st = "ok" if state == "STABLE" else "warn" if state == "DEGRADED" else "fail"
            groups = [g for g in (c.get("detailed_cluster_status") or {}).get("groups") or [] if isinstance(g, dict)]
            bad = [g for g in groups if str(g.get("group_status") or "").upper() != "STABLE"]
            r.step("cluster", "NSX Manager cluster", st,
                   f"Overall {state or 'unknown'}" + (f", management {mgmt}" if mgmt and overall else "")
                   + (f", control {control}" if control else "") + ".",
                   {"columns": ["Group", "Type", "Status"],
                    "rows": [[g.get("group_id") or "", g.get("group_type") or "", g.get("group_status") or ""] for g in bad]})
            if st != "ok":
                r.recommend(f"The NSX Manager cluster is {state or 'not stable'}: configuration changes may not be applied and the "
                            "UI may not answer. Look at the managers in System → Appliances and at the alarms below.",
                            [], where=f"NSX Manager {nsx}: System → Appliances", refs=["nsx-cluster"])
        # ---------------- alarms ----------------
        alarms = []
        for key in ("alarms", "acked"):
            it = source(data, key)
            if unavailable(it):
                if key == "alarms":
                    r.step("alarms", "Open alarms", "fail", unavailable(it))
                continue
            alarms += [a for a in (json_of(it) or {}).get("results") or [] if isinstance(a, dict)]
        if alarms or not unavailable(source(data, "alarms")):
            alarms.sort(key=lambda a: (["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(a.get("severity")) if a.get("severity") in
                                       ("CRITICAL", "HIGH", "MEDIUM", "LOW") else 4, -(a.get("_create_time") or 0)))
            open_ = [a for a in alarms if a.get("status") == "OPEN"]
            st = worst(*[NSX_SEVERITY.get(a.get("severity"), "info") for a in open_]) if open_ else "ok"
            st = "ok" if st == "info" else st
            if any(a.get("status") == "ACKNOWLEDGED" and NSX_SEVERITY.get(a.get("severity")) == "fail" for a in alarms) and st == "ok":
                st = "warn"
            r.step("alarms", "Open alarms", st,
                   f"{len(open_)} open, {len(alarms) - len(open_)} acknowledged." if alarms else "No open alarm.",
                   {"columns": ["Severity", "Feature", "Event", "Node", "Since (UTC)", "Status", "Summary"],
                    "rows": [[a.get("severity"), a.get("feature_display_name") or a.get("feature_name"),
                              a.get("event_type_display_name") or a.get("event_type"),
                              a.get("node_display_name") or a.get("node_id") or "", epoch_ms(a.get("_create_time")),
                              a.get("status"), (a.get("summary") or a.get("description") or "")[:200]] for a in alarms]},
                   marks=[a.get("event_type_display_name") or a.get("event_type") for a in open_ if NSX_SEVERITY.get(a.get("severity")) == "fail"])
            groups = {}
            for a in alarms:
                if NSX_SEVERITY.get(a.get("severity")) in ("fail", "warn"):
                    groups.setdefault((a.get("feature_name"), a.get("event_type")), []).append(a)
            for (_feature, _event), items in list(groups.items())[:12]:
                a = items[0]
                label = f"{a.get('feature_display_name') or a.get('feature_name')}: {a.get('event_type_display_name') or a.get('event_type')}"
                action = str(a.get("recommended_action") or "").strip()
                r.recommend(f"{label} ({a.get('severity')}, {len(items)} alarm(s)). {str(a.get('description') or a.get('summary') or '').strip()[:600]}",
                            [], where=where,
                            warning=f"NSX recommended action: {action[:800]}" if action else "",
                            refs=["nsx-event-catalog"],
                            items={"columns": ["Node", "Since (UTC)", "Status"],
                                   "rows": [[x.get("node_display_name") or x.get("node_id") or "", epoch_ms(x.get("_create_time")),
                                             x.get("status")] for x in items]})
        # ---------------- transport nodes ----------------
        item = source(data, "tn_state")
        if unavailable(item):
            r.step("nodes", "Transport nodes (ESXi, edges)", "skip", unavailable(item))
        else:
            names = {str(n.get("id") or n.get("node_id")): n.get("display_name") or "" for n in (json_of(source(data, "tn")) or {}).get("results") or []
                     if isinstance(n, dict)}
            states = [s for s in (json_of(item) or {}).get("results") or [] if isinstance(s, dict)]
            failed, pending = [], []
            for s in states:
                state = str(s.get("state") or "").lower()
                if state in TN_OK:
                    continue
                (pending if state in TN_PENDING else failed).append(s)
            r.step("nodes", "Transport nodes (ESXi, edges)", "fail" if failed else "warn" if pending else "ok",
                   f"{len(failed)} failed, {len(pending)} in progress, of {len(states)}." if failed or pending else f"{len(states)} node(s), all ready.",
                   {"columns": ["Node", "State", "Deployment", "Message"],
                    "rows": [[names.get(str(s.get("transport_node_id"))) or s.get("transport_node_id"), s.get("state"),
                              (s.get("node_deployment_state") or {}).get("state") or "",
                              (s.get("failure_message") or (s.get("node_deployment_state") or {}).get("failure_message") or "")[:200]]
                             for s in failed + pending]},
                   marks=[names.get(str(s.get("transport_node_id"))) or s.get("transport_node_id") for s in failed])
            if failed:
                r.recommend(f"{len(failed)} transport node(s) are not ready: their overlay tunnels or the configuration of their "
                            "switch may be missing, so VMs on them can lose network. Open each node in System → Fabric → Nodes "
                            "and read its status details before resolving it.",
                            [], where=f"NSX Manager {nsx}", refs=["nsx-transport-node"],
                            items={"columns": ["Node", "State", "Message"],
                                   "rows": [[names.get(str(s.get("transport_node_id"))) or s.get("transport_node_id"), s.get("state"),
                                             (s.get("failure_message") or "")[:200]] for s in failed]})
        return r.done()

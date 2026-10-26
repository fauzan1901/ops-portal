"""Resource and capacity checks (platform health, not from a KB page): CPU, memory, disk and inodes of a Linux server or
of an overcloud node (with its systemd units and containers), the capacity of the OpenStack computes (hypervisors and
aggregates), and the capacity of ONTAP (aggregates, FlexVols, snapshots, disks). Every value is shown with its
threshold, so a result can be exported (CSV / PDF) as a capacity report. Read-only.
"""
import re

from . import overcloud
from .common import Result, human, json_of, kib, level, parse_df, pct, source, text_of, unavailable, worst
from .overcloud_checks import inventory, reach_step, reached

DF = "df -Pk -x tmpfs -x devtmpfs -x squashfs -x overlay -x iso9660 2>/dev/null"
DFI = "df -Pi -x tmpfs -x devtmpfs -x squashfs -x overlay -x iso9660 2>/dev/null"
HOST_READS = {   # fixed read commands of a Linux server ("SUDO " -> sudo -n when the group uses sudo)
    "df": DF,
    "dfi": DFI,
    "mem": "free -k",
    "load": "nproc; cat /proc/loadavg",
    "cpu": "head -n 1 /proc/stat; sleep 2; head -n 1 /proc/stat",
    "failed": "systemctl --failed --no-legend --plain 2>/dev/null; true",
    "topmem": "ps -eo pid,user,pmem,pcpu,rss,comm --sort=-rss | head -n 9",
    "topcpu": "ps -eo pid,user,pcpu,pmem,comm --sort=-pcpu | head -n 9",
    "uptime": "uptime",
}
OC_READS = ("df", "dfi", "mem", "load", "cpu", "failed", "topmem", "topcpu", "containers")
# One-shot containers of TripleO that exit by design (their exit 0 is normal)
ONE_SHOT = re.compile(r"(_init|_bootstrap|_db_sync|_setup|puppet|_wait|_fix_perms|_cron_?init|_api_db|cellv2|_discover_hosts|_copy|"
                      r"_statedir_owner|create_|configure_)", re.I)


# ---------------------------------------------------------------- parsers
def parse_free(text):
    """`free -k` -> {"total", "available", "used_pct", "swap_total", "swap_used"} (KiB)."""
    out = {}
    for line in str(text or "").splitlines():
        parts = line.split()
        if parts[:1] == ["Mem:"] and len(parts) >= 7 and all(p.isdigit() for p in parts[1:7]):
            total, available = int(parts[1]), int(parts[6])
            out.update(total=total, available=available, used_pct=round((total - available) * 100 / total, 1) if total else None)
        elif parts[:1] == ["Swap:"] and len(parts) >= 3 and parts[1].isdigit():
            out.update(swap_total=int(parts[1]), swap_used=int(parts[2]))
    return out


def parse_load(text):
    vals = str(text or "").split()
    try:
        cpus = int(vals[0])
        return {"cpus": cpus, "load1": float(vals[1]), "load5": float(vals[2]), "load15": float(vals[3])}
    except (IndexError, ValueError):
        return {}


def parse_cpu(text):
    """Two `cpu ...` lines of /proc/stat taken 2 s apart -> CPU busy % (all cores) and iowait %."""
    rows = [[int(x) for x in l.split()[1:]] for l in str(text or "").splitlines() if l.startswith("cpu ") and len(l.split()) > 5]
    if len(rows) < 2:
        return {}
    a, b = rows[0], rows[1]
    delta = [y - x for x, y in zip(a, b)]
    total = sum(delta)
    if total <= 0:
        return {}
    idle = delta[3] + (delta[4] if len(delta) > 4 else 0)
    return {"busy": round((total - idle) * 100 / total, 1), "iowait": round((delta[4] if len(delta) > 4 else 0) * 100 / total, 1)}


def parse_failed(text):
    units = []
    for line in str(text or "").splitlines():
        parts = line.split()
        if parts and (parts[0].endswith((".service", ".mount", ".socket", ".timer", ".scope", ".slice", ".target"))):
            units.append(parts[0])
    return units


def parse_containers(text):
    """`podman ps -a --format '{{.Names}}|{{.Status}}'` -> (unhealthy, exited with an error) lists of (name, status)."""
    unhealthy, failed = [], []
    for line in str(text or "").splitlines():
        if "|" not in line:
            continue
        name, status = (x.strip() for x in line.split("|", 1))
        low = status.lower()
        if "unhealthy" in low:
            unhealthy.append((name, status))
        else:
            m = re.match(r"exited \((\d+)\)", low)
            if m and m.group(1) != "0" and not ONE_SHOT.search(name):
                failed.append((name, status))
    return unhealthy, failed


def top_rows(text, mem=True):
    rows = []
    for line in str(text or "").splitlines()[1:]:
        p = line.split(None, 5 if mem else 4)
        if mem and len(p) == 6:
            rows.append([p[5], p[0], p[1], f"{p[2]}%", f"{p[3]}%", kib(p[4]) if p[4].isdigit() else p[4]])
        elif not mem and len(p) == 5:
            rows.append([p[4], p[0], p[1], f"{p[2]}%", f"{p[3]}%"])
    return rows


# ---------------------------------------------------------------- the rating of one server
def rate_server(r, get, name, params, prefix="", where="", node=True):
    """Steps for one server from its reads (get(key) -> item): CPU, memory, disks, inodes, failed units. Returns the
    findings [(kind, text)] for the recommendations."""
    disk_w, disk_f = int(params.get("disk_warn") or 80), int(params.get("disk_fail") or 90)
    mem_w, mem_f = int(params.get("mem_warn") or 85), int(params.get("mem_fail") or 95)
    cpu_w, cpu_f = int(params.get("cpu_warn") or 85), int(params.get("cpu_fail") or 95)
    findings, label = [], (f"{name}: " if prefix else "")
    # CPU: busy % over 2 s, and load per core
    cpu, load = parse_cpu(text_of(get("cpu"))), parse_load(text_of(get("load")))
    if cpu or load:
        per_core = round(load["load5"] / load["cpus"], 2) if load.get("cpus") else None
        st = worst(level(cpu.get("busy"), cpu_w, cpu_f) if cpu else "skip", level(per_core * 100 if per_core is not None else None, 100, 200))
        st = "ok" if st == "skip" else st
        r.step(f"{prefix}cpu", f"{label}CPU", st,
               (f"{cpu['busy']}% busy (iowait {cpu['iowait']}%) over 2 s" if cpu else "busy % not read")
               + (f"; load {load['load1']} / {load['load5']} / {load['load15']} on {load['cpus']} CPU(s) "
                  f"({per_core} per CPU over 5 min)" if load else "") + f". Threshold {cpu_w}% / {cpu_f}%.",
               {"columns": ["Process", "PID", "User", "CPU", "Memory"], "rows": top_rows(text_of(get("topcpu")), mem=False)})
        if st in ("warn", "fail"):
            findings.append(("cpu", f"CPU {cpu.get('busy', '?')}% busy, load per CPU {per_core}"))
        if cpu.get("iowait", 0) >= 20:
            findings.append(("iowait", f"iowait {cpu['iowait']}%: the processes wait for the disk"))
    else:
        r.skip(f"{prefix}cpu", f"{label}CPU", unavailable(get("cpu")) or "not read")
    # memory: used = total - available (the kernel counts cache that can be freed as available)
    mem = parse_free(text_of(get("mem")))
    if mem.get("total"):
        st = level(mem["used_pct"], mem_w, mem_f)
        swap = (f"; swap {kib(mem.get('swap_used', 0))} used of {kib(mem['swap_total'])}" if mem.get("swap_total") else "; no swap")
        r.step(f"{prefix}mem", f"{label}Memory", st,
               f"{mem['used_pct']}% used ({kib(mem['total'] - mem['available'])} of {kib(mem['total'])}; {kib(mem['available'])} "
               f"available){swap}. Threshold {mem_w}% / {mem_f}%.",
               {"columns": ["Process", "PID", "User", "Memory", "CPU", "Resident"], "rows": top_rows(text_of(get("topmem")))})
        if st in ("warn", "fail"):
            top = top_rows(text_of(get("topmem")))
            findings.append(("mem", f"memory {mem['used_pct']}% used" + (f", largest: {top[0][0]} ({top[0][5]})" if top else "")))
    else:
        r.skip(f"{prefix}mem", f"{label}Memory", unavailable(get("mem")) or "not read")
    # filesystems and inodes
    disks = parse_df(text_of(get("df")))
    inodes = {d["mount"]: d["pct"] for d in parse_df(text_of(get("dfi")))}
    if disks:
        rows, statuses = [], []
        for d in sorted(disks, key=lambda x: -x["pct"]):
            st = worst(level(d["pct"], disk_w, disk_f), level(inodes.get(d["mount"]), disk_w, disk_f) if d["mount"] in inodes else "ok")
            statuses.append(st)
            rows.append([d["mount"], d["fs"], kib(d["size_kb"]), kib(d["used_kb"]), kib(d["avail_kb"]), f"{d['pct']}%",
                         f"{inodes[d['mount']]}%" if d["mount"] in inodes else "-", st.upper()])
            if st in ("warn", "fail"):
                findings.append(("disk", f"{d['mount']} {d['pct']}% used ({kib(d['avail_kb'])} free)"
                                 + (f", inodes {inodes[d['mount']]}%" if inodes.get(d["mount"], 0) >= disk_w else "")))
        r.step(f"{prefix}disk", f"{label}Filesystems", worst(*statuses),
               f"{len(disks)} filesystem(s); threshold {disk_w}% / {disk_f}% (space and inodes).",
               {"columns": ["Mount", "Device", "Size", "Used", "Free", "Used %", "Inodes used", "Status"], "rows": rows},
               marks=[x[0] for x in rows if x[7] in ("WARN", "FAIL")])
    else:
        r.skip(f"{prefix}disk", f"{label}Filesystems", unavailable(get("df")) or "df gave no output")
    # failed systemd units
    failed = parse_failed(text_of(get("failed")))
    if not unavailable(get("failed")):
        r.step(f"{prefix}units", f"{label}Failed systemd units", "warn" if failed else "ok",
               ", ".join(failed) if failed else "None.", marks=failed)
        for u in failed:
            findings.append(("unit", u))
    return findings


def advise(r, findings, where, name, node=False):
    kinds = {k for k, _ in findings}
    items = {"columns": ["Finding"], "rows": [[t] for _, t in findings]}
    if "disk" in kinds:
        r.recommend(f"Filesystems of {name} are filling up. Find what grows (logs, journal, old files, deleted files still held "
                    "open), clean or rotate it, and extend the volume when the data is legitimate.",
                    ["sudo du -xh --max-depth=2 / 2>/dev/null | sort -rh | head -20", "sudo journalctl --disk-usage",
                     "sudo find /var/log -xdev -type f -size +500M -exec ls -lh {} +",
                     "sudo lsof -nP +L1 2>/dev/null | awk 'NR>1 {print $1, $2, $7}' | sort -k3 -rn | head",
                     "sudo journalctl --vacuum-size=1G"] + (["sudo podman system df"] if node else []),
                    where=where, warning="Do not delete files of a running database or of a container's storage by hand; "
                    "/var/lib/mysql, /var/lib/rabbitmq and /var/lib/containers belong to the services." if node else "",
                    items=items)
    if "mem" in kinds:
        r.recommend(f"Memory of {name} is nearly used up: the kernel starts swapping, then kills processes (OOM). Look at the "
                    "largest processes and whether one keeps growing (leak), and at OOM kills in the kernel log.",
                    ["ps -eo pid,user,pmem,rss,comm --sort=-rss | head -15", "free -h", "sudo journalctl -k --since '-24h' | grep -i -E 'out of memory|oom' | tail"]
                    + (["sudo podman stats --no-stream --format '{{.Name}} {{.MemUsage}}' | sort -k2 -h | tail -15"] if node else []),
                    where=where, items=items)
    if "cpu" in kinds or "iowait" in kinds:
        r.recommend(f"{name} is CPU bound" + (" and waits for its disk (iowait)" if "iowait" in kinds else "")
                    + ": look at the busiest processes and what they do.",
                    ["top -b -n 1 | head -25", "ps -eo pid,user,pcpu,pmem,etime,comm --sort=-pcpu | head -15"]
                    + (["sudo iostat -x 2 3"] if "iowait" in kinds else []), where=where, items=items)
    if "unit" in kinds:
        units = [t for k, t in findings if k == "unit"]
        r.recommend(f"{len(units)} systemd unit(s) failed on {name}: read why, fix the cause, then restart the unit.",
                    [f"sudo systemctl status {u} --no-pager -l" for u in units[:6]]
                    + [f"sudo journalctl -u {u} -n 50 --no-pager" for u in units[:3]],
                    where=where, refs=["rhosp-containers"] if node and any(u.startswith("tripleo_") for u in units) else None,
                    items={"columns": ["Unit"], "rows": [[u] for u in units]})


# ---------------------------------------------------------------- Linux server (Hosts & SSH)
class LinuxResources:
    """CPU, memory, disks and inodes, failed systemd units and the largest processes of one Linux server of Hosts & SSH /
    sites.yml (any product group)."""
    sources = ("host",)
    phases = 1

    @staticmethod
    def reads(phase, data, params, ctx):
        return {"host": dict(HOST_READS)}

    @staticmethod
    def analyze(data, params, ctx):
        from .common import on_host
        r = Result("linux-resources")
        name = ctx.get("host_name") or "the server"
        if all(unavailable(source(data, k)) for k in ("df", "mem", "load")):
            r.step("reach", f"Read {name}", "fail", unavailable(source(data, "df")))
            return r.done()
        up = text_of(source(data, "uptime")).strip()
        if up:
            r.step("uptime", "Uptime", "info", up)
        findings = rate_server(r, lambda k: source(data, k), name, params)
        advise(r, findings, on_host(ctx), name)
        return r.done()


# ---------------------------------------------------------------- overcloud nodes
class OvercloudNodeHealth:
    """CPU, memory, disks and inodes, failed systemd units (tripleo_*) and unhealthy / failed containers of the overcloud
    nodes (the controllers, or one node), read through the director."""
    sources = ("undercloud", "overcloud")
    phases = 3

    @staticmethod
    def _targets(data, params, ctx):
        found, controllers, user, version, problem = inventory(data, ctx)
        node = overcloud.short(params.get("node"))
        if node:
            targets = [n for n in found if overcloud.short(n["name"]) == node or overcloud.short(n["name"]).endswith(node)]
            if found and not targets:
                problem = f"Node {params['node']} is not an overcloud node of this site."
            elif targets:
                problem = ""
        elif params.get("role") == "all":
            targets = found
        elif params.get("role") == "compute":
            targets = [n for n in found if n["role"] == "compute"]
        else:
            targets = controllers
        return found, targets[:24], user, version, problem

    @staticmethod
    def reads(phase, data, params, ctx):
        if phase == 1:
            return {"undercloud": dict(overcloud.INVENTORY_READS)}
        _f, targets, user, _v, problem = OvercloudNodeHealth._targets(data, params, ctx)
        if not targets:
            return {}
        if phase == 2:
            return {"overcloud": {f"reach_{i}": overcloud.read(n["name"], n["ip"], user, "reach") for i, n in enumerate(targets)}}
        out = {}
        for n in reached(data, "reach_", targets):
            i = targets.index(n)
            for cmd in OC_READS:
                out[f"{cmd}_{i}"] = overcloud.read(n["name"], n["ip"], user, cmd)
        return {"overcloud": out}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("overcloud-node-health")
        _f, targets, user, version, problem = OvercloudNodeHealth._targets(data, params, ctx)
        if problem or not targets:
            r.step("nodes", "Overcloud nodes", "fail", problem or "No node of this role.")
            return r.done()
        down = reach_step(r, data, "reach_", targets, user, version, "Nodes reached from the director")
        summary = []
        for i, n in enumerate(targets):
            if n in down:
                continue
            get = (lambda i: (lambda k: source(data, f"{k}_{i}")))(i)
            where = f"{n['name']}, as {user} with sudo (from the director: ssh {user}@{n['ip']})"
            findings = rate_server(r, get, n["name"], params, prefix=f"{i}_", where=where, node=True)
            unhealthy, failed = parse_containers(text_of(get("containers")))
            if not unavailable(get("containers")):
                st = "fail" if unhealthy else "warn" if failed else "ok"
                r.step(f"{i}_containers", f"{n['name']}: containers", st,
                       f"{len(unhealthy)} unhealthy, {len(failed)} exited with an error." if unhealthy or failed else "Every container healthy.",
                       {"columns": ["Container", "Status"], "rows": [[a, b] for a, b in unhealthy + failed]},
                       marks=[a for a, _ in unhealthy])
                if unhealthy or failed:
                    names = [a for a, _ in unhealthy + failed]
                    r.recommend(f"Containers of {n['name']} are unhealthy or stopped with an error: read the container log, fix the "
                                "cause, then restart its systemd unit (tripleo_<container>). Pacemaker bundles (galera, rabbitmq, "
                                "redis, haproxy, ovn-dbs, cinder-volume) are restarted through pcs, not systemd.",
                                [f"sudo podman logs --tail 50 {c}" for c in names[:4]]
                                + [f"sudo systemctl restart tripleo_{c}" for c in names[:4] if "bundle" not in c],
                                where=where, refs=["rhosp-containers", "rhosp-pcs-resource"],
                                items={"columns": ["Container", "Status"], "rows": [[a, b] for a, b in unhealthy + failed]})
            advise(r, findings, where, n["name"], node=True)
            summary.append([n["name"], n["role"]] + [next((s["status"].upper() for s in r.steps if s["key"] == f"{i}_{k}"), "-")
                                                     for k in ("cpu", "mem", "disk", "units", "containers")])
        if summary:
            r.steps.insert(1, {"key": "summary", "title": "Summary per node", "status": "info", "open": True, "detail": "",
                               "table": {"columns": ["Node", "Role", "CPU", "Memory", "Disks", "Units", "Containers"],
                                         "rows": summary, "more": 0}})
        return r.done()


# ---------------------------------------------------------------- OpenStack compute capacity
class ComputeCapacity:
    """vCPU, RAM and disk of every compute (hypervisor) against its physical size and the allocation ratios, the computes
    that are down, and the room left per aggregate: why new instances fail with "No valid host"."""
    sources = ("openstack",)
    phases = 2

    @staticmethod
    def reads(phase, data, params, ctx):
        if phase == 1:
            return {"openstack": {"hypervisors": "openstack hypervisor list --long -f json",
                                  "services": "openstack compute service list --service nova-compute -f json",
                                  "aggregates": "openstack aggregate list -f json"}}
        ids = [str(a.get("ID")) for a in json_of(source(data, "aggregates")) or [] if isinstance(a, dict) and str(a.get("ID", "")).isdigit()]
        return {"openstack": {f"agg_{i}": f"openstack aggregate show {i} -f json" for i in ids[:20]}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("compute-capacity")
        item = source(data, "hypervisors")
        if unavailable(item):
            r.step("computes", "Computes (hypervisors)", "fail", unavailable(item))
            return r.done()
        cpu_ratio, ram_ratio = float(params.get("cpu_ratio") or 4), float(params.get("ram_ratio") or 1)
        warn, fail = int(params.get("warn") or 80), int(params.get("fail") or 90)
        services = {str(s.get("Host")): s for s in json_of(source(data, "services")) or [] if isinstance(s, dict)}
        rows, hvs = [], []
        for h in json_of(item) or []:
            if not isinstance(h, dict):
                continue
            name = str(h.get("Hypervisor Hostname") or "")
            host = name.split(".")[0]
            svc = services.get(host) or services.get(name) or {}
            vcpu, vcpu_used = h.get("vCPUs") or 0, h.get("vCPUs Used") or 0
            ram, ram_used = h.get("Memory MB") or 0, h.get("Memory MB Used") or 0
            cpu_pct = pct(vcpu_used, vcpu * cpu_ratio)
            ram_pct = pct(ram_used, ram * ram_ratio)
            up = str(h.get("State") or "").lower() == "up"
            enabled = str(svc.get("Status") or "enabled").lower() == "enabled"
            st = worst(level(cpu_pct, warn, fail), level(ram_pct, warn, fail)) if up and enabled else "info"
            hvs.append({"name": name, "up": up, "enabled": enabled, "vcpu": vcpu, "vcpu_used": vcpu_used, "ram": ram,
                        "ram_used": ram_used, "status": st, "host": host})
            rows.append([name, "up" if up else "DOWN", "enabled" if enabled else "disabled", f"{vcpu_used} / {vcpu}",
                         f"{cpu_pct}%" if cpu_pct is not None else "-", f"{human(ram_used * 2 ** 20)} / {human(ram * 2 ** 20)}",
                         f"{ram_pct}%" if ram_pct is not None else "-", st.upper()])
        active = [h for h in hvs if h["up"] and h["enabled"]]
        status = worst(*[h["status"] for h in active]) if active else "fail"
        down = [h for h in hvs if not h["up"]]
        r.step("computes", "Computes (hypervisors)", worst(status, "fail" if down else "ok"),
               f"{len(hvs)} compute(s), {len(down)} down; vCPU against {cpu_ratio:g}:1, RAM against {ram_ratio:g}:1 "
               f"(the allocation ratios of nova: set them as on this site). Threshold {warn}% / {fail}%.",
               {"columns": ["Compute", "State", "Service", "vCPU used", "vCPU % of ratio", "RAM used", "RAM % of ratio", "Status"],
                "rows": sorted(rows, key=lambda x: ({"FAIL": 0, "WARN": 1}.get(x[7], 2), x[0]))},
               marks=[h["name"] for h in hvs if h["status"] == "fail" or not h["up"]])
        free_cpu = sum(max(h["vcpu"] * cpu_ratio - h["vcpu_used"], 0) for h in active)
        free_ram = sum(max(h["ram"] * ram_ratio - h["ram_used"], 0) for h in active)
        biggest = max(active, key=lambda h: h["ram"] * ram_ratio - h["ram_used"], default=None)   # most RAM left on one compute
        r.step("room", "Room left for new instances", "info",
               f"{free_cpu:g} vCPU and {human(free_ram * 2 ** 20)} RAM free in total on {len(active)} active compute(s)"
               + (f"; the most RAM left on one compute is on {biggest['name']}: {human(max(biggest['ram'] * ram_ratio - biggest['ram_used'], 0) * 2 ** 20)} "
                  f"RAM with {max(biggest['vcpu'] * cpu_ratio - biggest['vcpu_used'], 0):g} vCPU (an instance must fit on one compute)."
                  if biggest else "."))
        aggs = []
        for k, v in (data or {}).items():
            if k.startswith("agg_") and isinstance(v, dict) and not unavailable(v):
                a = json_of(v) or {}
                hosts = a.get("hosts") or []
                hosts = hosts if isinstance(hosts, list) else re.findall(r"[A-Za-z0-9_.-]+", str(hosts))
                members = [h for h in active if h["host"] in {str(x).split(".")[0] for x in hosts}]
                if members:
                    fc = sum(max(h["vcpu"] * cpu_ratio - h["vcpu_used"], 0) for h in members)
                    fr = sum(max(h["ram"] * ram_ratio - h["ram_used"], 0) for h in members)
                    used = pct(sum(h["ram_used"] for h in members), sum(h["ram"] * ram_ratio for h in members))
                    aggs.append([a.get("name"), a.get("availability_zone") or "", len(members), f"{fc:g}", human(fr * 2 ** 20),
                                 f"{used}%" if used is not None else "-", level(used, warn, fail).upper()])
        if aggs:
            r.step("aggregates", "Room per aggregate (flavors pinned to an aggregate only land there)",
                   worst(*[x[6].lower() for x in aggs if x[6] != "SKIP"]) if any(x[6] != "SKIP" for x in aggs) else "info", "",
                   {"columns": ["Aggregate", "Zone", "Computes", "Free vCPU", "Free RAM", "RAM used", "Status"], "rows": aggs})
        hot = [h for h in active if h["status"] in ("warn", "fail")]
        where = f"OpenStack director of {ctx.get('site') or 'the site'}, as stack after: source ~/overcloudrc"
        if hot:
            r.recommend(f"{len(hot)} compute(s) are at or above {warn}% of their vCPU or RAM allocation: new instances (and "
                        "resizes, migrations to them) fail with No valid host once the room is gone. Spread the load with live "
                        "migration, or ask for capacity (another compute) for this aggregate.",
                        [f"openstack server list --all-projects --host {h['host']} --long -c Name -c Status -c Flavor" for h in hot[:5]]
                        + ["openstack hypervisor list --long"], where=where, refs=["rhosp-compute-down"],
                        items={"columns": ["Compute", "vCPU used", "RAM used"],
                               "rows": [[h["name"], f"{h['vcpu_used']} / {h['vcpu']}", f"{human(h['ram_used'] * 2 ** 20)} / {human(h['ram'] * 2 ** 20)}"] for h in hot]})
        if down:
            r.recommend(f"{len(down)} compute(s) are down: their instances cannot be managed and their room is lost. See the check "
                        "OpenStack services and agents, and Bare metal nodes (BMC power state).",
                        ["openstack compute service list --service nova-compute"], where=where, refs=["rhosp-compute-down"],
                        items={"columns": ["Compute"], "rows": [[h["name"]] for h in down]})
        return r.done()


# ---------------------------------------------------------------- ONTAP capacity
class OntapCapacity:
    """Aggregates and FlexVols of the site's ONTAP cluster against the thresholds, snapshot space above its reserve, and
    disks that are broken or not in use. ONTAP Restore account of the site, REST GET only."""
    sources = ("ontap",)
    phases = 1

    @staticmethod
    def reads(phase, data, params, ctx):
        return {"ontap": {
            "aggregates": "/api/storage/aggregates?fields=name,node.name,state,space.block_storage.size,space.block_storage.used,"
                          "space.block_storage.available&max_records=500",
            "volumes": "/api/storage/volumes?fields=name,svm.name,state,type,space.size,space.used,space.available&max_records=5000",
            "snapshots": "/api/storage/volumes?fields=name,svm.name,space.snapshot.used,space.snapshot.reserve_percent,space.size"
                         "&max_records=5000",
            "disks": "/api/storage/disks?fields=name,state,node.name,bay,shelf.uid,model&state=broken|maintenance|removed|unfail"
                     "&max_records=500"}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("ontap-capacity")
        warn, fail = int(params.get("warn") or 80), int(params.get("fail") or 90)
        item = source(data, "aggregates")
        if unavailable(item):
            r.step("aggregates", "Aggregates", "fail", unavailable(item))
            return r.done()
        rows, sts = [], []
        for a in (json_of(item) or {}).get("records") or []:
            bs = ((a.get("space") or {}).get("block_storage") or {})
            used_pct = pct(bs.get("used"), bs.get("size"))
            st = level(used_pct, warn, fail) if a.get("state", "online") == "online" else "fail"
            sts.append(st)
            rows.append([a.get("name"), (a.get("node") or {}).get("name") or "", a.get("state") or "", human(bs.get("size") or 0),
                         human(bs.get("used") or 0), human(bs.get("available") or 0), f"{used_pct}%" if used_pct is not None else "-", st.upper()])
        r.step("aggregates", "Aggregates", worst(*sts) if sts else "skip",
               f"{len(rows)} aggregate(s); threshold {warn}% / {fail}%.",
               {"columns": ["Aggregate", "Node", "State", "Size", "Used", "Free", "Used %", "Status"],
                "rows": sorted(rows, key=lambda x: -float(str(x[6]).rstrip("%") or 0) if x[6] != "-" else 0)},
               marks=[x[0] for x in rows if x[7] in ("WARN", "FAIL")])
        vols = source(data, "volumes")
        hot = []
        if unavailable(vols):
            r.skip("volumes", "FlexVols", unavailable(vols))
        else:
            rows, sts = [], []
            for v in (json_of(vols) or {}).get("records") or []:
                sp = v.get("space") or {}
                used_pct = pct(sp.get("used"), sp.get("size"))
                if used_pct is None or v.get("type") == "dp":
                    continue
                st = level(used_pct, warn, fail)
                if st != "ok":
                    sts.append(st)
                    hot.append(v)
                    rows.append([v.get("name"), (v.get("svm") or {}).get("name") or "", human(sp.get("size") or 0), human(sp.get("used") or 0),
                                 human(sp.get("available") or 0), f"{used_pct}%", st.upper()])
            r.step("volumes", f"FlexVols at {warn}% used or more", worst(*sts) if sts else "ok",
                   f"{len(rows)} volume(s) at or above {warn}% (data protection copies excluded).",
                   {"columns": ["Volume", "SVM", "Size", "Used", "Free", "Used %", "Status"],
                    "rows": sorted(rows, key=lambda x: float(x[5].rstrip("%")), reverse=True)},
                   marks=[x[0] for x in rows if x[6] == "FAIL"])
        snaps = source(data, "snapshots")
        over = []
        if not unavailable(snaps):
            for v in (json_of(snaps) or {}).get("records") or []:
                sp = (v.get("space") or {})
                snap = sp.get("snapshot") or {}
                reserve = (snap.get("reserve_percent") or 0) * (sp.get("size") or 0) / 100
                if snap.get("used") and snap["used"] > reserve and snap["used"] > 10 * 2 ** 30:
                    over.append([v.get("name"), (v.get("svm") or {}).get("name") or "", human(snap["used"]), f"{snap.get('reserve_percent', 0)}%",
                                 human(snap["used"] - reserve)])
            if over:
                r.step("snapshots", "Snapshots using more than their reserve", "warn",
                       f"{len(over)} volume(s): their snapshots take space from the data.",
                       {"columns": ["Volume", "SVM", "Snapshot used", "Reserve", "Above the reserve"], "rows": sorted(over, key=lambda x: x[0])[:200]})
        disks = source(data, "disks")
        if not unavailable(disks):
            bad = (json_of(disks) or {}).get("records") or []
            r.step("disks", "Disks broken or out of service", "fail" if bad else "ok", f"{len(bad)} disk(s)." if bad else "None.",
                   {"columns": ["Disk", "State", "Node", "Shelf", "Bay", "Model"],
                    "rows": [[d.get("name"), d.get("state"), (d.get("node") or {}).get("name") or "", (d.get("shelf") or {}).get("uid") or "",
                              d.get("bay") or "", d.get("model") or ""] for d in bad]})
        where = f"ONTAP CLI of {ctx.get('ontap_host') or 'the cluster'} (ssh admin)"
        if hot:
            r.recommend(f"{len(hot)} FlexVol(s) are at or above {warn}% used: a full volume takes its LUNs / Cinder volumes offline. "
                        "Grow the volume when the aggregate has room, or move data (Cinder: migrate volumes to another pool, "
                        "see the check Cinder volume over 80%).",
                        [f"volume show -vserver {(v.get('svm') or {}).get('name')} -volume {v.get('name')} -fields size,used,available,percent-used,"
                         "autosize-mode" for v in hot[:6]], where=where,
                        items={"columns": ["Volume", "SVM"], "rows": [[v.get("name"), (v.get("svm") or {}).get("name")] for v in hot]})
        return r.done()

"""Log collection from the overcloud nodes (permission "collect logs"): the checks Collect logs and sos report.

Source "collect" in wi_analysis: {key: "<node>|<ctlplane IP>|<user>|logs:<components>:<since>:<until>:<max MB>"} or
{key: "<node>|<ctlplane IP>|<user>|sos:<label>:<case ID or ->:<all logs 0|1>:<min free GB>"}. The playbook
(tasks/collect_files.yml) runs transfer_command() on the portal server: the archive comes as a stream
  node (wi_collect.py with sudo, output on stdout) -> director (ssh) -> management host (ssh) -> portal server
into the bundle folder of the run, so nothing is left on the node, the director or the management host. Logs: every
node at once; sos report: one node after the other (it loads the node for minutes).
"""
import base64
import datetime
import functools
import json
import os
import re
import shlex

from . import overcloud
from .common import Result, human, json_of, source, unavailable
from .overcloud_checks import inventory, reach_step, reached

MARK = "@@WI@@"
HERE = os.path.dirname(os.path.abspath(__file__))
COLLECTOR = os.path.join(HERE, "wi_collect.py")
MAX_NODES = 12
MAX_SOS_NODES = 4
COMPONENTS = ("nova", "placement", "libvirt", "neutron", "ovn", "cinder", "glance", "keystone", "heat", "horizon", "rabbitmq",
              "galera", "haproxy", "pacemaker", "system", "kernel", "iscsi")
PRESETS = {
    "all": COMPONENTS,
    "compute": ("nova", "libvirt", "neutron", "ovn", "iscsi", "kernel", "system"),
    "network": ("neutron", "ovn", "haproxy", "kernel", "system"),
    "storage": ("cinder", "glance", "nova", "iscsi", "kernel", "system"),
    "controlplane": ("keystone", "nova", "placement", "neutron", "cinder", "glance", "heat", "horizon", "rabbitmq", "galera",
                     "haproxy", "pacemaker", "system"),
}
SPEC_RE = re.compile(r"^(?P<node>[A-Za-z0-9][A-Za-z0-9_.-]{0,62})\|(?P<ip>[0-9.]{7,15})\|(?P<user>heat-admin|tripleo-admin)\|"
                     r"(?:logs:(?P<comps>[a-z]{2,12}(?:,[a-z]{2,12}){0,20}):(?P<since>\d{9,11}):(?P<until>\d{9,11}):(?P<mb>\d{2,4})"
                     r"|sos:(?P<label>[A-Za-z0-9]{1,30}):(?P<case>\d{1,12}|-):(?P<all>[01]):(?P<free>\d{1,3}))$")
KEY_RE = re.compile(r"^(logs|sos)_\d{1,2}$")
HOST_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")
SUFFIX = {"logs": ".logs.tar.gz", "sos": ".sos.archive"}


def logs_spec(node, ip, user, components, since, until, max_mb):
    value = f"{node}|{ip}|{user}|logs:{','.join(components)}:{int(since)}:{int(until)}:{int(max_mb)}"
    parse(value)
    return value


def sos_spec(node, ip, user, label, case_id, all_logs, min_free_gb):
    value = f"{node}|{ip}|{user}|sos:{label}:{case_id or '-'}:{1 if all_logs else 0}:{int(min_free_gb)}"
    parse(value)
    return value


def parse(value):
    """(node, ip, user, kind, collector arguments); ValueError unless every part is valid."""
    m = SPEC_RE.match(str(value or ""))
    if not m:
        raise ValueError(f"invalid log collection {str(value)[:160]!r}")
    node, ip, user = m.group("node"), m.group("ip"), m.group("user")
    overcloud.parse(f"{node}|{ip}|{user}|reach")   # a private ctlplane address, a known user
    if m.group("comps"):
        comps = m.group("comps").split(",")
        if any(c not in COMPONENTS for c in comps):
            raise ValueError(f"unknown log component in {value!r}")
        since, until, mb = int(m.group("since")), int(m.group("until")), int(m.group("mb"))
        if not 0 < until - since <= 72 * 3600 + 60 or not 50 <= mb <= 4096:
            raise ValueError(f"invalid window or size in {value!r}")
        return node, ip, user, "logs", ["logs", "--components", ",".join(comps), "--since", str(since), "--until", str(until),
                                        "--max-mb", str(mb)]
    args = ["sos", "--label", m.group("label"), "--min-free-gb", m.group("free")]
    if m.group("case") != "-":
        args += ["--case-id", m.group("case")]
    if m.group("all") == "1":
        args.append("--all-logs")
    return node, ip, user, "sos", args


@functools.lru_cache(maxsize=1)
def collector_b64():
    with open(COLLECTOR, "rb") as f:
        return base64.b64encode(f.read()).decode()


def remote_command(kind, args):
    """What runs on the node (as the TripleO user, the collector with sudo): the archive on stdout."""
    py = ("PY=$(command -v python3 || echo /usr/libexec/platform-python); "
          f"echo {collector_b64()} | base64 -d | sudo -n \"$PY\" - {' '.join(shlex.quote(a) for a in args)}")
    return f": wi-collect; set -o pipefail; {py}" + (" | gzip -c" if kind == "logs" else "")


def mgmt_command(mgmt, command):
    """command run on the management host of the site, as Ansible connects to it (sites.yml mgmt)."""
    mgmt = mgmt or {}
    if mgmt.get("connection") == "local":
        return f"bash -c {shlex.quote(command)}"
    host, user = str(mgmt.get("host") or ""), str(mgmt.get("user") or "")
    if not HOST_RE.match(host) or (user and not re.match(r"^[A-Za-z0-9_.-]+$", user)):
        raise ValueError("invalid management host in sites.yml")
    parts = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=6",
             "-p", str(int(mgmt.get("port") or 22))]
    if mgmt.get("private_key"):
        key = str(mgmt["private_key"])
        if not re.match(r"^[~A-Za-z0-9_./-]+$", key):
            raise ValueError("invalid mgmt.private_key in sites.yml")
        parts += ["-i", os.path.expanduser(key)]
    parts += shlex.split(str(mgmt.get("ssh_args") or "-o StrictHostKeyChecking=accept-new"))
    parts.append(f"{user}@{host}" if user else host)
    return " ".join(shlex.quote(p) for p in parts) + " " + shlex.quote(command)


def output_name(spec):
    node, _ip, _user, kind, _args = parse(spec)
    return node + SUFFIX[kind]


def transfer_command(spec, director_prefix, mgmt, bundle_dir):
    """The shell script (bash, on the portal server) that brings one node's archive into the bundle folder; its stdout
    for the analysis: "@@WI@@size <bytes>" and the end of the collector's stderr (with its manifest line)."""
    node, ip, user, kind, args = parse(spec)
    if not os.path.isabs(str(bundle_dir or "")):
        raise ValueError("invalid bundle folder")
    on_director = (f"{overcloud.SSH} -o ServerAliveInterval=30 -o ServerAliveCountMax=6 {user}@{ip} "
                   f"{shlex.quote(remote_command(kind, args))}")
    local = mgmt_command(mgmt, f"{director_prefix} {shlex.quote(on_director)}")
    out = shlex.quote(os.path.join(bundle_dir, node + SUFFIX[kind]))
    err = shlex.quote(os.path.join(bundle_dir, node + SUFFIX[kind] + ".err"))
    return (f"set -o pipefail\n{local} > {out} 2> {err}\nrc=$?\n"
            f"echo \"{MARK}size $(wc -c < {out} | tr -d ' ')\"\ntail -c 60000 {err}\nexit $rc")


def collect_results(results):
    """Ansible results of tasks/collect_files.yml (async_status, or a waited async loop) -> {key: {"rc", "out"}}."""
    out = {}
    for r in results or []:
        item = r.get("item") or {}
        if isinstance(item, dict) and "ansible_job_id" in item:   # async_status of an async job: the job's own item
            item = item.get("item") or {}
        key = str(item.get("key") or "")
        if not KEY_RE.match(key):
            continue
        text = str(r.get("stdout") or "")
        if not text and (r.get("msg") or r.get("stderr")):
            text = str(r.get("stderr") or r.get("msg"))
        rc = r.get("rc")
        if rc is None:
            rc = 1 if r.get("failed") else 0
        out[key] = {"rc": int(rc), "out": text}
    return out


def transfer(item):
    """{"rc", "size", "manifest", "errors"} of one node from its read."""
    text = str((item or {}).get("out") or "")
    size, manifest, errors = 0, {}, []
    for line in text.splitlines():
        if line.startswith(f"{MARK}size "):
            try:
                size = int(line.split()[-1])
            except ValueError:
                size = 0
        elif line.startswith(f"{MARK}manifest "):
            try:
                manifest = json.loads(line[len(MARK) + 9:])
            except ValueError:
                manifest = {}
        elif line.strip() and not re.match(r"^(collecting |logs/|journal/|info/|\$ )", line) and len(errors) < 12:
            errors.append(line.strip()[:300])
    return {"rc": (item or {}).get("rc"), "size": size, "manifest": manifest, "errors": errors}


# ---------------------------------------------------------------- shared by both checks
def free_kb(text):
    """Free KiB of the last df -Pk line."""
    for line in reversed(str(text or "").splitlines()):
        f = line.split()
        if len(f) >= 6 and f[3].isdigit():
            return int(f[3])
    return None


def site_time(ctx, epoch):
    tz = tz_of(ctx)
    return datetime.datetime.fromtimestamp(int(epoch), tz).strftime("%Y-%m-%d %H:%M %Z").replace("UTC+07:00", "WIB")


def tz_of(ctx):
    m = re.match(r"^([+-])(\d{2}):?(\d{2})$", str(ctx.get("timezone") or ""))
    if not m:
        return datetime.datetime.now().astimezone().tzinfo
    delta = datetime.timedelta(hours=int(m.group(2)), minutes=int(m.group(3)))
    return datetime.timezone(delta if m.group(1) == "+" else -delta)


def window(params, ctx):
    """(since, until) in seconds since the epoch: hours before the end (params until, site time; default: when the run
    started, ctx now)."""
    hours = int(params.get("hours") or 6)
    until = int(ctx.get("now") or 0) or int(datetime.datetime.now().timestamp())
    if params.get("until"):
        end = datetime.datetime.strptime(str(params["until"]), "%Y-%m-%d %H:%M").replace(tzinfo=tz_of(ctx))
        until = min(until, int(end.timestamp()))
    return until - hours * 3600, until


def targets_of(data, params, ctx, limit):
    """(found, targets, user, version, problem) for params scope (controllers / computes / all / named), nodes and
    instance (its compute is added)."""
    found, controllers, user, version, problem = inventory(data, ctx)
    scope = params.get("scope") or "controllers"
    if scope == "computes":
        targets = [n for n in found if n["role"] == "compute"]
    elif scope == "all":
        targets = list(found)
    elif scope == "named":
        targets = []
    else:
        targets = list(controllers)
    if scope != "controllers" and problem.startswith("No controller found"):
        problem = ""
    wanted = [overcloud.short(x) for x in str(params.get("nodes") or "").split(",") if x.strip()]
    server = json_of(source(data, "server")) or {}
    host = overcloud.short(server.get("OS-EXT-SRV-ATTR:hypervisor_hostname") or server.get("OS-EXT-SRV-ATTR:host") or "") \
        if isinstance(server, dict) else ""
    if host:
        wanted.append(host)
    for w in wanted:
        n = next((n for n in found if overcloud.short(n["name"]) == w or overcloud.short(n["name"]).endswith(w)), None)
        if n is None:
            problem = problem or f"{w} is not an overcloud node of this site."
        elif n not in targets:
            targets.append(n)
    if params.get("instance") and not host and not problem:
        problem = f"Instance {params['instance']}: its compute could not be read (openstack server show)."
    if found and not targets and not problem:
        problem = "No node in this choice: name the nodes (Node names)."
    if len(targets) > limit:
        problem = (f"{len(targets)} nodes chosen: at most {limit} per run. Name the nodes (scope named) or run it again "
                   "for the others.")
        targets = []
    return found, targets, user, version, problem


def phase1(params):
    out = {"undercloud": dict(overcloud.INVENTORY_READS)}
    if params.get("instance"):
        out["openstack"] = {"server": f"openstack server show {params['instance']} -f json"}
    return out


def room_step(r, data, nodes, need_gb, title, extra=None):
    """Free space in /var/tmp of each reached node -> the nodes with enough room."""
    rows, ok_nodes = [], []
    for i, n in nodes:
        kb = free_kb(text_of_key(data, f"tmp_{i}"))
        note = (extra or {}).get(i, "")
        enough = kb is not None and kb >= need_gb * 2 ** 20 and not note
        if enough:
            ok_nodes.append((i, n))
        rows.append([n["name"], human(kb * 1024) if kb is not None else "unknown", f"{need_gb} GB",
                     "yes" if enough else (note or "not enough free space")])
    status = "ok" if len(ok_nodes) == len(nodes) else "warn" if ok_nodes else "fail"
    r.step("room", title, status, f"{len(ok_nodes)} of {len(nodes)} node(s) can be collected.",
           {"columns": ["Node", "Free in /var/tmp", "Needed", "Collected"], "rows": rows},
           marks=[row[0] for row in rows if row[3] != "yes"])
    return ok_nodes


def text_of_key(data, key):
    item = source(data, key)
    return "" if unavailable(item) else str(item.get("out") or "")


# ---------------------------------------------------------------- Collect logs
class CollectLogs:
    """Every log line of a time window on chosen overcloud nodes, one archive per node in one bundle to download."""
    sources = ("undercloud", "openstack", "overcloud", "collect")
    phases = 3
    NEED_GB = 1

    @staticmethod
    def reads(phase, data, params, ctx):
        if phase == 1:
            return phase1(params)
        _f, targets, user, _v, problem = targets_of(data, params, ctx, MAX_NODES)
        if not targets:
            return {}
        if phase == 2:
            out = {}
            for i, n in enumerate(targets):
                out[f"reach_{i}"] = overcloud.read(n["name"], n["ip"], user, "reach")
                out[f"tmp_{i}"] = overcloud.read(n["name"], n["ip"], user, "tmpfree")
            return {"overcloud": out}
        since, until = window(params, ctx)
        comps = PRESETS.get(params.get("preset") or "all") or (params["preset"],)
        mb = int(params.get("max_mb") or 1024)
        out = {}
        for n in reached(data, "reach_", targets):
            i = targets.index(n)
            kb = free_kb(text_of_key(data, f"tmp_{i}"))
            if kb is not None and kb >= CollectLogs.NEED_GB * 2 ** 20:
                comp = [c for c in comps if n["role"] == "controller" or c not in overcloud.CONTROLLER_ONLY | {"heat", "horizon", "placement"}]
                out[f"logs_{i}"] = logs_spec(n["name"], n["ip"], user, comp, since, until, mb)
        return {"collect": out}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("collect-logs")
        _f, targets, user, version, problem = targets_of(data, params, ctx, MAX_NODES)
        if problem:
            r.step("nodes", "Overcloud nodes", "fail" if not targets else "warn", problem)
            if not targets:
                return r.done()
        down = reach_step(r, data, "reach_", targets, user, version, "Overcloud nodes")
        up = [(i, n) for i, n in enumerate(targets) if n not in down]
        if not up:
            return r.done("No node could be reached from the director: nothing was collected.")
        ready = room_step(r, data, up, CollectLogs.NEED_GB, "Room on the nodes (temporary files, removed at once)")
        since, until = window(params, ctx)
        rows, files, total, done = [], [], 0, 0
        for i, n in ready:
            item = source(data, f"logs_{i}")
            t = transfer(item)
            m = t["manifest"]
            ok = not unavailable(item) and t["rc"] == 0 and t["size"] > 0 and m.get("mode") == "logs"
            done += ok
            total += t["size"]
            why = "; ".join(t["errors"][:3]) or (unavailable(item) or f"exit {t['rc']}")
            rows.append([n["name"], "collected" if ok else f"failed: {why}"[:300], len(m.get("files") or []),
                         sum(int(f.get("lines") or 0) for f in m.get("files") or []), human(m.get("total_bytes") or 0),
                         human(t["size"]), ", ".join(m.get("missing") or []) or "-", len(m.get("skipped") or [])])
            for f in m.get("files") or []:
                files.append([n["name"], f.get("name"), f.get("lines"), human(f.get("bytes") or 0), f.get("note") or ""])
            for s in m.get("skipped") or []:
                files.append([n["name"], s.get("name"), "", "", f"not collected: {s.get('why')}"])
        status = "ok" if ready and done == len(ready) else "warn" if done else "fail"
        r.step("collected", "Logs collected per node", status,
               f"{done} of {len(ready)} node(s), window {site_time(ctx, since)} – {site_time(ctx, until)}"
               f" ({params.get('preset') or 'all'}): {human(total)} compressed.",
               {"columns": ["Node", "Result", "Files", "Lines", "Uncompressed", "Received (gzip)", "No files for", "Skipped"],
                "rows": rows}, marks=[row[0] for row in rows if row[1] != "collected"])
        if files:
            r.step("files", "Files in the bundle", "info", "Every file with its lines in the window (secrets masked on the node); "
                   "MANIFEST.txt of each node also has the sha256.",
                   {"columns": ["Node", "File", "Lines", "Size", "Note"], "rows": files})
        if done:
            r.recommend("Download the bundle with the button Download log bundle at the top of this page. It is a .tar with one "
                        ".tar.gz per node and MANIFEST.json; it is kept on the portal server for "
                        f"{ctx.get('keep_days', 7)} days.",
                        ["tar xf logs-*.tar", "for f in */*.logs.tar.gz; do mkdir -p \"${f%.logs.tar.gz}\" && tar xzf \"$f\" -C \"${f%.logs.tar.gz}\"; done",
                         "grep -rn ' ERROR ' */logs/containers/nova/   # e.g. the nova errors of every node"],
                        where="your workstation (Linux / macOS / WSL)")
        summary = (f"Log bundle: {done} of {len(targets)} node(s), {human(total)} (window {site_time(ctx, since)} – "
                   f"{site_time(ctx, until)}).") if done else "No log could be collected."
        return r.done(summary)


# ---------------------------------------------------------------- sos report
class SosReport:
    """Red Hat's sos report on a few overcloud nodes (one after the other), the archives in one bundle to download."""
    sources = ("undercloud", "openstack", "overcloud", "collect")
    phases = 3

    @staticmethod
    def need_gb(params):
        return 10 if params.get("all_logs") == "yes" else 5

    @staticmethod
    def reads(phase, data, params, ctx):
        if phase == 1:
            return phase1(params)
        _f, targets, user, _v, problem = targets_of(data, params, ctx, MAX_SOS_NODES)
        if not targets:
            return {}
        if phase == 2:
            out = {}
            for i, n in enumerate(targets):
                out[f"reach_{i}"] = overcloud.read(n["name"], n["ip"], user, "reach")
                out[f"tmp_{i}"] = overcloud.read(n["name"], n["ip"], user, "tmpfree")
                out[f"sosv_{i}"] = overcloud.read(n["name"], n["ip"], user, "sosver")
            return {"overcloud": out}
        need = SosReport.need_gb(params)
        out = {}
        label = f"run{int(ctx.get('run_id') or 0)}" if ctx.get("run_id") else "wi"
        for n in reached(data, "reach_", targets):
            i = targets.index(n)
            kb = free_kb(text_of_key(data, f"tmp_{i}"))
            if kb is not None and kb >= need * 2 ** 20 and sos_installed(data, i):
                out[f"sos_{i}"] = sos_spec(n["name"], n["ip"], user, label, params.get("case_id") or "",
                                           params.get("all_logs") == "yes", need)
        return {"collect": out}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("sos-report")
        _f, targets, user, version, problem = targets_of(data, params, ctx, MAX_SOS_NODES)
        if problem:
            r.step("nodes", "Overcloud nodes", "fail" if not targets else "warn", problem)
            if not targets:
                return r.done()
        down = reach_step(r, data, "reach_", targets, user, version, "Overcloud nodes")
        up = [(i, n) for i, n in enumerate(targets) if n not in down]
        if not up:
            return r.done("No node could be reached from the director: no sos report was made.")
        missing = {i: "sos is not installed (dnf install sos)" for i, _n in up if not sos_installed(data, i)}
        ready = room_step(r, data, up, SosReport.need_gb(params), "Room on the nodes and sos installed", missing)
        rows, done, total = [], 0, 0
        for i, n in ready:
            item = source(data, f"sos_{i}")
            t = transfer(item)
            m = t["manifest"]
            ok = not unavailable(item) and t["rc"] == 0 and t["size"] > 0 and bool(m.get("archive"))
            done += ok
            total += t["size"] if ok else 0
            why = m.get("error") or "; ".join(t["errors"][-3:]) or unavailable(item) or f"exit {t['rc']}"
            rows.append([n["name"], "made" if ok else f"failed: {why}"[:300], m.get("archive") or "-", human(t["size"]) if ok else "-",
                         m.get("sha256") or "-", f"{int(m.get('seconds') or 0) // 60} min" if ok else "-"])
        r.step("sos", "sos report per node", "ok" if ready and done == len(ready) else "warn" if done else "fail",
               f"{done} of {len(ready)} node(s), one after the other"
               + (f", case {params['case_id']}" if params.get("case_id") else "")
               + (", all logs (--all-logs)" if params.get("all_logs") == "yes" else "") + ".",
               {"columns": ["Node", "Result", "Archive", "Size", "sha256", "Took"], "rows": rows},
               marks=[row[0] for row in rows if row[1] != "made"])
        if done:
            r.recommend("Download the bundle with the button Download log bundle at the top of this page and attach each sosreport "
                        "archive to the Red Hat support case (Customer Portal, the case, Attach files). The bundle is a .tar "
                        "with the archives as sos wrote them; it is kept on the portal server for "
                        f"{ctx.get('keep_days', 7)} days.",
                        ["tar xf sos-*.tar", "sha256sum */sosreport-*.tar.*   # compare with the sha256 column"],
                        where="your workstation (Linux / macOS / WSL)", refs=["rh-sos-report"])
        return r.done(f"sos report: {done} of {len(targets)} node(s), {human(total)}." if done else "No sos report could be made.")


def sos_installed(data, i):
    text = text_of_key(data, f"sosv_{i}")
    return bool(re.search(r"^sos-\d", text, re.M))

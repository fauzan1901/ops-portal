"""VM disks on a compute (check compute-disks), read-only, for one compute and no instance ID: do the disks of its running
VMs still have their paths, what did its kernel log about removed SCSI devices and I/O errors, and which instance
directories does it keep without a domain?

Why (a real case): a live migration refused by its destination (DestinationDiskExists: a directory of the instance
was still there) is rolled back there, and the rollback disconnects volumes on the destination with the LUN numbers of
the source. NetApp numbers LUNs per host: on the destination that number can be the disk of ANOTHER VM. The kernel
removes its SCSI devices ("alua: Detached"), the multipath map is left without any path, the guest gets I/O errors and
its filesystem shuts down or goes read-only, for hours, until someone looks. Reads, on the compute (as the other
overcloud reads, through the director): the kernel lines of the last hours about removed devices, I/O errors and failed
paths, multipath -ll, the disks of every running domain, the instance directories of /var/lib/nova/instances; on the
director: the instances Nova has on that compute, and where Nova has each instance whose directory is left there.
Why the I/O errors are counted over the whole window and set against the start of each VM's QEMU (a real case): a
leftover map flushed at 15:26 gave dm-23 120 I/O errors a minute until 15:23; vm-004 came by live migration at 15:31 and
its disk got dm-23; the check named vm-004 with "396" errors (the 400 lines shown) and, given the node's short name, Nova
listed none of its instances (Nova keeps overcloud-novacomputeha-0.example.net): the Nova name is looked up in
openstack compute service list now, and a leftover directory whose server show names this compute is never offered.
Fixes (Run this fix, items ticked): the lost LUNs scanned again (wi_ops.py rescan-luns: only the removed SCSI addresses,
a device kept only with a WWID of a map that lost its paths) and leftover directories renamed aside (move-leftover).
"""
import datetime
import re
import shlex

from . import overcloud, wi_ops
from .common import Result, director, json_of, source, unavailable, worst
from .openstack import UUID, os_select
from .openstack_ops import HOST, node_of, short
from .overcloud_checks import inventory

q = shlex.quote
MAX_SHOW = 60          # leftover directories looked up in Nova (server show each), the others are listed only
SAFE_AGE = 30          # minutes: a directory changed since then may belong to a migration running now
KB = "the Knowledge Base page \"Live Migration Gagal - Attachment Ganda dan Data Koneksi Volume Basi\""
REMOVED = re.compile(r"(?:scsi|sd) (\d+):(\d+):(\d+):(\d+): (?:alua: Detached|\[sd[a-z]+\] Synchronizing SCSI cache)")
IOERR = re.compile(r"I/O error, dev (dm-\d+|sd[a-z]+)")
LOST = re.compile(r"(\S+): remaining active paths: 0")
PATH = re.compile(r"(\d+:\d+:\d+:\d+)\s+(sd[a-z]+)\s+\S+\s+(.*)$")
MAP = re.compile(r"^(\S+)(?: \((3[0-9a-f]{32})\))? (dm-\d+) ?(.*)$")


def epoch(stamp):
    """Seconds of a journalctl short-iso time (2026-10-31T15:23:37+0700), None for any other."""
    try:
        return datetime.datetime.strptime(str(stamp), "%Y-%m-%dT%H:%M:%S%z").timestamp()
    except ValueError:
        return None


def parse(text):
    """The output of the cd_disks read -> {"kernel": [lines], "removed": [(h, c, t, l)], "io": {device: errors},
    "io_last": {device: seconds of its last error}, "started": {domain: seconds its QEMU started}, "lost": {map name},
    "maps": {dm: {"wwid", "vendor", "paths", "failed", "sd": [...]}}, "domains": [(name, uuid)],
    "users": {dm: [(name, uuid, target)]}, "fs", "dirs": [{"uuid", "domain", "age", "files"}]}. The totals of @@kstat
    (the whole window) replace those counted on the last 400 kernel lines when the read gives them."""
    out = {"kernel": [], "removed": [], "io": {}, "io_last": {}, "started": {}, "lost": set(), "maps": {}, "domains": [],
           "users": {}, "fs": "", "dirs": []}
    section, current, dom, disks = "", None, None, []
    stat = {"io": {}, "removed": [], "lost": set(), "qemu": {}, "now": None, "seen": False}
    for line in str(text or "").splitlines():
        if line.strip() in ("@@kernel", "@@kstat", "@@maps", "@@domains", "@@dirs"):
            section = line.strip()[2:]
            stat["seen"] = stat["seen"] or section == "kstat"
            continue
        if section == "kstat":
            f = line.split()
            if len(f) == 5 and f[0] == "@@io" and f[2].isdigit():
                stat["io"][f[1]] = (int(f[2]), epoch(f[4]))
            elif len(f) == 2 and f[0] == "@@removed" and re.match(r"^\d+:\d+:\d+:\d+$", f[1]):
                a = tuple(int(x) for x in f[1].split(":"))
                if a not in stat["removed"]:
                    stat["removed"].append(a)
            elif len(f) == 2 and f[0] == "@@lost":
                stat["lost"].add(f[1])
            elif len(f) == 2 and f[0] == "@@now" and f[1].isdigit():
                stat["now"] = int(f[1])
            elif len(f) == 3 and f[0] == "@@qemu" and f[2].isdigit():
                stat["qemu"][f[1]] = int(f[2])
        elif section == "kernel" and line.strip():
            out["kernel"].append(line)
            m = REMOVED.search(line)
            if m and tuple(int(x) for x in m.groups()) not in out["removed"]:
                out["removed"].append(tuple(int(x) for x in m.groups()))
            m = IOERR.search(line)
            if m:
                out["io"][m.group(1)] = out["io"].get(m.group(1), 0) + 1
            m = LOST.search(line)
            if m:
                out["lost"].add(m.group(1))
        elif section == "maps":
            m = MAP.match(line)
            if m and not line.startswith(("size=", "|", "`", " ")):
                current = m.group(3)
                out["maps"][current] = {"wwid": m.group(2) or m.group(1), "vendor": m.group(4).strip(), "paths": 0, "failed": 0, "sd": []}
                continue
            m = PATH.search(line)
            if current and m:
                mp = out["maps"][current]
                mp["paths"] += 1
                mp["sd"].append(m.group(2))
                if re.search(r"failed|faulty|offline", m.group(3)):
                    mp["failed"] += 1
        elif section == "domains":
            m = re.match(r"^@@dom (\S+) ?(\S*)$", line)
            if m:
                dom = (m.group(1), m.group(2))
                out["domains"].append(dom)
                continue
            m = re.match(r"^@@disk (\S+) (/dev/\S+)$", line.strip())
            if m and dom:
                disks.append((dom, m.group(1), m.group(2)))
        elif section == "dirs":
            if line.startswith("@@fs "):
                out["fs"] = line[5:].strip().lower()
                continue
            f = line.split(" ", 4)
            if f[0] == "@@dir" and len(f) >= 4 and UUID.match(f[1]) and f[3].lstrip("-").isdigit():
                out["dirs"].append({"uuid": f[1], "domain": f[2] == "yes", "age": int(f[3]),
                                    "files": (f[4] if len(f) > 4 else "").strip(",")})
    if stat["seen"]:
        out["io"] = {d: n for d, (n, _last) in stat["io"].items()}
        out["io_last"] = {d: last for d, (_n, last) in stat["io"].items() if last}
        out["removed"] = stat["removed"]
        out["lost"] |= stat["lost"]
        if stat["now"]:
            out["started"] = {name: stat["now"] - age for name, age in stat["qemu"].items()}
    by_wwid = {mp["wwid"]: dm for dm, mp in out["maps"].items()}
    for (name, uuid), target, src in disks:
        dm = src.rsplit("/", 1)[-1] if src.startswith("/dev/dm-") else by_wwid.get(src.rsplit("-", 1)[-1].rsplit("/", 1)[-1])
        if dm:
            out["users"].setdefault(dm, []).append((name, uuid, target))
    return out


def dead(mp):
    """A multipath map left without any path (multipath shows ##,## for its vendor then)."""
    return mp["paths"] == 0 or "##" in mp["vendor"]


def days(minutes):
    return f"{minutes} min" if minutes < 120 else f"{minutes // 60} h" if minutes < 2880 else f"{minutes // 1440} days"


class ComputeDisks:
    sources = ("openstack", "undercloud", "overcloud")
    phases = 3

    @staticmethod
    def node(data, params, ctx):
        """(overcloud node of the compute, user, problem)."""
        found, _controllers, user, _version, problem = inventory(data, ctx)
        return node_of(str(params.get("compute") or ""), found), user, problem

    @staticmethod
    def nova_host(data, params, ctx):
        """The compute as Nova names it (openstack compute service list): the name given, else the one nova-compute host
        with the same short name or on the same overcloud node. DCA keeps FQDNs (overcloud-novacomputeha-0.example.net)
        and server list --host matches the whole name only: with the short name Nova listed none of its instances
       . The name given when no host matches."""
        host = str(params.get("compute") or "")
        hosts = [str(s.get("Host") or "") for s in json_of(source(data, "services")) or [] if isinstance(s, dict)]
        if host in hosts:
            return host
        same = [h for h in hosts if short(h) == short(host)]
        node = ComputeDisks.node(data, params, ctx)[0] if not same else None
        if node:
            found = inventory(data, ctx)[0]
            same = [h for h in hosts if (node_of(h, found) or {}).get("name") == node["name"]]
        return same[0] if len(same) == 1 else host

    @staticmethod
    def reads(phase, data, params, ctx):
        host = str(params.get("compute") or "")
        hours = int(params.get("hours") or 24)
        if not HOST.match(host) or not 1 <= hours <= 72:
            return {}
        if phase == 1:
            return {"openstack": {"services": "openstack compute service list --service nova-compute -f json"},
                    "undercloud": dict(overcloud.INVENTORY_READS)}
        node, user, _problem = ComputeDisks.node(data, params, ctx)
        if phase == 2:
            out = {"openstack": {"servers": f"openstack server list --all-projects --host {q(ComputeDisks.nova_host(data, params, ctx))} "
                                            "--long -f json"}}
            if node and node.get("ip") and user in overcloud.USERS:
                out["overcloud"] = {"disks": overcloud.read(node["name"], node["ip"], user, "cd_disks", hours)}
            return out
        # phase 3: where Nova has each instance whose directory is left here (not one Nova lists on this compute)
        seen = parse(source(data, "disks").get("out")) if not unavailable(source(data, "disks")) else {"dirs": []}
        here = {str(s.get("ID") or s.get("id") or "") for s in json_of(source(data, "servers")) or [] if isinstance(s, dict)}
        left = [d["uuid"] for d in seen["dirs"] if not d["domain"] and d["uuid"] not in here][:MAX_SHOW]
        return {"openstack": {f"srv_{u}": f"openstack server show {q(u)} -f json" for u in left}} if left else {}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("compute-disks")
        host = str(params.get("compute") or "")
        hours = int(params.get("hours") or 24)
        node, user, problem = ComputeDisks.node(data, params, ctx)
        item = source(data, "disks")
        if not node or not node.get("ip"):
            r.step("compute", "The compute", "fail", f"{host} is not in the overcloud node list of the undercloud"
                   + (f": {problem}" if problem else " (the name as in openstack compute service list)."))
            return r.done()
        if user not in overcloud.USERS or unavailable(item):
            r.step("compute", "The compute", "fail", f"{node['name']} ({node['ip']}) could not be read: "
                   + (unavailable(item) or problem or "no overcloud user (heat-admin / tripleo-admin)"))
            return r.done()
        seen = parse(item.get("out"))
        servers = {}
        for s in json_of(source(data, "servers")) or []:
            if isinstance(s, dict) and UUID.match(str(s.get("ID") or s.get("id") or "")):
                servers[str(s.get("ID") or s.get("id"))] = (str(s.get("Name") or s.get("name") or ""), str(s.get("Project ID") or s.get("project_id") or ""),
                                                           str(s.get("Status") or s.get("status") or ""))
        def who(uuid, name):   # noqa: E306  "<Nova name> (<domain>)" of a domain
            return f"{servers[uuid][0]} ({name})" if uuid in servers else name
        used = {dm: u for dm, u in seen["users"].items()}
        nhost = ComputeDisks.nova_host(data, params, ctx)
        known = any(isinstance(s, dict) and str(s.get("Host") or "") == nhost for s in json_of(source(data, "services")) or [])
        r.step("compute", "The compute", "ok" if known else "warn",
               f"{node['name']} ({node['ip']}): {len(seen['domains'])} running domain(s), {len(seen['maps'])} multipath map(s), "
               f"{len(seen['dirs'])} instance director{'y' if len(seen['dirs']) == 1 else 'ies'} on {seen['fs'] or 'an unknown filesystem'}; Nova lists {len(servers)} "
               f"instance(s) on {nhost}" + (f" (Nova's name of {host})" if nhost != host else "") + "."
               + ("" if known else f" {host} is not a nova-compute host of openstack compute service list"
                  + (f" ({unavailable(source(data, 'services'))})" if unavailable(source(data, "services")) else "")
                  + ": the instances shown by their domain name only, give the name as Nova has it for their Nova names."))

        # ---- 2. disks of running VMs left without any path
        lost = sorted((dm for dm in used if dm in seen["maps"] and dead(seen["maps"][dm])), key=lambda x: int(x[3:]))
        rows = []
        for dm in lost:
            mp = seen["maps"][dm]
            for name, uuid, target in used[dm]:
                rows.append([servers.get(uuid, ("-",))[0] or "-", uuid or "-", servers.get(uuid, ("", "-"))[1] or "-", target, dm, mp["wwid"]])
        r.step("nopath", "Disks of running VMs without any path", "fail" if lost else "ok",
               (f"CRITICAL: {len(lost)} disk(s) of running VMs have no path at all: their guests get I/O errors on every read "
                "and write, and their filesystems may be read-only or shut down (XFS) by now. "
                + (f"The kernel removed {len(seen['removed'])} SCSI device(s) in the last {hours} h: they can be scanned again "
                   "(the fix below)." if seen["removed"] else
                   f"No removed SCSI device is in the kernel log of the last {hours} h: run the check with more hours, or scan the "
                   "LUN of each by hand (its target and LUN from the volume's connection info).")
                if lost else "Every disk of the running VMs has at least one path."),
               {"columns": ["Instance", "UUID", "Project", "Disk", "Device", "WWID"], "rows": rows}, marks=[seen["maps"][dm]["wwid"] for dm in lost])

        # ---- 3. failed paths on disks of running VMs (still served by the others)
        weak = sorted((dm for dm in used if dm in seen["maps"] and not dead(seen["maps"][dm]) and seen["maps"][dm]["failed"]),
                      key=lambda x: int(x[3:]))
        r.step("failed", "Paths failed on disks of running VMs", "warn" if weak else "ok",
               (f"{len(weak)} disk(s) of running VMs have failed / faulty / offline paths (the other paths still serve them): "
                "one more path down and they have none." if weak else "No failed path on the disks of the running VMs."),
               {"columns": ["Instance", "Disk", "Device", "WWID", "Paths", "Failed"],
                "rows": [[", ".join(who(u, n) for n, u, _t in used[dm]), ", ".join(t for _n, _u, t in used[dm]), dm, seen["maps"][dm]["wwid"],
                          seen["maps"][dm]["paths"], seen["maps"][dm]["failed"]] for dm in weak]}, marks=weak)

        # ---- 4. kernel disk events of the window, by the VM that uses that device now; not when every domain on it
        # started after the last error there: the number was then another disk's (a real case: dm-23 of a map
        # flushed at 15:26 gave I/O errors until 15:23, vm-004 came at 15:31 and its disk got dm-23)
        sd_dm = {sd: dm for dm, mp in seen["maps"].items() for sd in mp["sd"]}
        hit, before = {}, {}
        for dev, n in seen["io"].items():
            dm = dev if dev.startswith("dm-") else sd_dm.get(dev, "")
            if dm in used:
                last = seen["io_last"].get(dev)
                starts = [seen["started"].get(name) for name, _u, _t in used[dm]]
                if last and starts and all(t and t > last for t in starts):
                    old = before.setdefault(dm, [0, last, min(starts)])
                    old[0], old[1] = old[0] + n, max(old[1], last)
                else:
                    hit[dm] = hit.get(dm, 0) + n
        st = "fail" if hit else "warn" if seen["removed"] or seen["io"] or seen["lost"] else "ok"
        r.step("kernel", f"Kernel disk events ({hours} h)", st,
               (f"{sum(seen['io'].values())} I/O error line(s), {len(seen['removed'])} SCSI device(s) removed"
                + (f", maps that lost their last path: {', '.join(sorted(seen['lost']))}" if seen["lost"] else "") + ". "
                + ("I/O errors on disks of running VMs: " + "; ".join(
                    dm + " (" + str(n) + "x, " + ", ".join(who(u, x) for x, u, _t in used[dm]) + ")" for dm, n in sorted(hit.items())) + ". "
                   if hit else "")
                + ("".join(f"The {n} I/O error(s) of {dm} ended before {', '.join(who(u, x) for x, u, _t in used[dm])} started on this "
                           f"compute ({round((start - last) / 60)} min later): they were another disk's that had the number {dm} then "
                           "(a map removed since), not this VM's. " for dm, (n, last, start) in sorted(before.items())))
                + "A dm number of the log may have been given to another disk since (a device removed and added again): "
                  "compare the WWID before acting." if st != "ok" else
                f"No removed SCSI device, I/O error or failed path in the kernel log of the last {hours} h."),
               evidence=seen["kernel"][-40:], marks=sorted(hit))

        # ---- 5. instance directories left without a domain
        rows, safe, here, others = [], [], [], []
        for d in [x for x in seen["dirs"] if not x["domain"]]:
            u = d["uuid"]
            if u in servers:
                nova, verdict = f"{nhost} ({servers[u][2]})", "Nova has it HERE without a domain: check it"
                here.append(u)
            else:
                it = source(data, f"srv_{u}")
                s = json_of(it) if not unavailable(it) else None
                if f"srv_{u}" not in data:
                    nova, verdict = "not looked up", f"not looked up (more than {MAX_SHOW})"
                elif isinstance(s, dict):
                    task = str(s.get("OS-EXT-STS:task_state") or "") or "-"
                    nova = f"{s.get('OS-EXT-SRV-ATTR:host') or '-'} ({s.get('status') or '?'}, task {task})"
                    verdict = ("a migration or task of it runs: not touched" if task != "-" or str(s.get("status")).upper() in ("MIGRATING", "RESIZE", "VERIFY_RESIZE")
                               else "SAFE")
                    if short(s.get("OS-EXT-SRV-ATTR:host")) in (short(nhost), short(host)):   # here after all (server list missed it)
                        verdict = "Nova has it HERE without a domain: check it"
                        here.append(u)
                elif re.search(r"No server with|could not be found|not found", unavailable(it) or "", re.I):
                    nova, verdict = "deleted", "SAFE"
                else:
                    nova, verdict = f"not read ({(unavailable(it) or '?')[:60]})", "not touched"
                if verdict == "SAFE" and (not seen["fs"] or seen["fs"] in wi_ops.SHARED_FS):
                    verdict = f"{seen['fs'] or 'unknown'} filesystem (shared?): not touched"
                if verdict == "SAFE" and d["age"] < SAFE_AGE:
                    verdict = f"changed {d['age']} min ago: not touched"
                if u not in here:
                    (safe if verdict == "SAFE" else others).append(u)
            rows.append([u, days(d["age"]), nova, d["files"] or "-", verdict])
        r.step("leftover", "Leftover instance directories", "fail" if here else "warn" if safe or others else "ok",
               ((f"{len(here)} director{'y' if len(here) == 1 else 'ies'} of instances Nova has on {nhost} itself without a domain: check each (Volume "
                 "connections of an instance) before anything else. " if here else "")
                + (f"{len(safe) + len(others)} director{'y' if len(safe) + len(others) == 1 else 'ies'} of instances that are not here: a live migration of one of them to "
                   f"{host} is refused (DestinationDiskExists), and the rollback of that refusal can disconnect the disks of other "
                   f"VMs here. {len(safe)} can be moved aside (renamed, never deleted)." if safe or others else "")
                if here or safe or others else f"Every instance directory of {host} has its domain here."),
               {"columns": ["Directory", "Age", "Nova: host (status)", "Files", "Verdict"], "rows": rows}, marks=here)

        # ---- how to fix it
        where = director(ctx)
        login = f"node {node['name']}={node['ip']} user {user}"
        if lost:
            keep = ",".join(list(dict.fromkeys(seen["maps"][dm]["wwid"] for dm in lost if wi_ops.WWID_RE.match(seen["maps"][dm]["wwid"])))[:16])
            addrs = ",".join(":".join(str(v) for v in a) for a in seen["removed"][:32])
            items = []
            for dm in lost:
                mp = seen["maps"][dm]
                usable = bool(addrs) and wi_ops.WWID_RE.match(mp["wwid"])
                items.append({"label": f"{', '.join(who(u, n) for n, u, _t in used[dm])} {', '.join(t for _n, _u, t in used[dm])} ({dm}, {mp['wwid']})",
                              "commands": [f"rescan-luns {mp['wwid']} addrs {addrs} keep {keep} {login}"] if usable else [],
                              "default": True,
                              "disabled": "" if usable else f"no removed SCSI address in the kernel log of the last {hours} h"})
            r.recommend(f"Give the disks without any path their paths back: the portal scans only the SCSI addresses the kernel "
                        f"removed on {node['name']} (and only where no device is now), keeps a new device only when its WWID is "
                        "the WWID of a map that lost its paths, deletes it again otherwise, and reads the map again. Then the "
                        f"owner of each VM checks its filesystem (see {KB}).",
                        [f"multipath -ll {seen['maps'][dm]['wwid']}   # on {node['name']}: no path" for dm in lost[:6]]
                        + ([f"echo '{c} {t} {l}' > /sys/class/scsi_host/host{h}/scan   # by hand, as root, then check the WWID of the new device"
                            for h, c, t, l in seen["removed"][:4]] if seen["removed"] else []),
                        warning="The guest of each VM may already have I/O errors or a read-only / shut-down filesystem: its owner "
                                "checks it. Reboot a VM only after the check \"Volume connections of an instance\" is clean for "
                                "it (a hard reboot with a stale connection info disconnects the disk of yet another VM).",
                        where=f"{node['name']}, as root (from the director: ssh {user}@{node['ip']})",
                        refs=["compute-disks", "volume-connections"],
                        items={"columns": ["Instance", "Disk", "Device", "WWID"],
                               "rows": [[", ".join(who(u, n) for n, u, _t in used[dm]), ", ".join(t for _n, _u, t in used[dm]), dm,
                                         seen["maps"][dm]["wwid"]] for dm in lost]},
                        action=os_select(items, target=node["name"], label="Re-scan the lost LUNs", noun="disks",
                                         lock="compute-disks", stop_on_failure=False, item_timeout=600, max_items=16))
        if weak:
            r.recommend(f"Find why paths failed on {node['name']}: an iSCSI session down, a storage LIF down, or a LUN no longer "
                        "mapped to this compute.",
                        [f"multipath -ll {seen['maps'][dm]['wwid']}" for dm in weak[:4]]
                        + ["iscsiadm -m session -P 1   # in the iscsid container when the host has no iscsiadm"],
                        where=f"{node['name']}, as root", refs=["compute-disks"])
        if hit and not lost:
            r.recommend("The disks with I/O errors in the window have their paths now, but their guests may still have a "
                        "read-only or shut-down filesystem: their owners check them (dmesg in the guest).",
                        [f"openstack console log show --lines 300 {u}" for dm in sorted(hit) for _n, u, _t in used[dm] if u][:6],
                        where=where, refs=["compute-disks"])
        if here:
            r.recommend(f"Check the instances Nova has on {host} without a domain there: they may be in ERROR or left by a "
                        "failed migration (run \"Volume connections of an instance\" for each); never move their directories.",
                        [f"openstack server show {u} -c status -c OS-EXT-STS:power_state -c OS-EXT-SRV-ATTR:host" for u in here[:6]],
                        where=where, refs=["volume-connections"])
        if safe:
            items = [{"label": f"{u} ({next(x[2] for x in rows if x[0] == u)}, {next(x[1] for x in rows if x[0] == u)})",
                      "commands": [f"move-leftover {u} {login}"], "default": True, "disabled": ""} for u in safe]
            r.recommend(f"Move the leftover instance directories of {node['name']} aside before instances move back to it: each "
                        "is read again (Nova, the directory, its domain, the filesystem) and renamed <dir>.leftover-<UTC>, never "
                        f"deleted, so a live migration to {host} is not refused and no rollback runs there (see {KB}).",
                        [f"mv /var/lib/nova/instances/{u} /var/lib/nova/instances/{u}.leftover-$(date -u +%Y%m%dT%H%M%SZ)   # as root"
                         for u in safe[:4]],
                        warning="Only directories of instances Nova has on another compute (or deleted), without a domain here, "
                                f"unchanged for {SAFE_AGE} minutes, on local storage are offered. Delete the renamed ones later, "
                                "once the migrations ran fine.",
                        where=f"{node['name']}, as root", refs=["compute-disks"],
                        items={"columns": ["Directory", "Age", "Nova: host (status)", "Files"],
                               "rows": [[x[0], x[1], x[2], x[3]] for x in rows if x[0] in safe]},
                        action=os_select(items, target=node["name"], label="Move the leftover directories aside",
                                         noun="directories", lock="compute-disks", stop_on_failure=False, item_timeout=300,
                                         max_items=200))
        return r.done()

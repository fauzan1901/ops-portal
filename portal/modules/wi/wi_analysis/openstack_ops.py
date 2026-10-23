"""Operation Automation checks of Acme Flex (OpenStack) that prepare a change on many items at once: the result lists the
items (images, instances), the operator ticks the ones to change, and the portal changes them one after the other
(playbooks/tasks/openstack_item.yml), each with an operation of wi_ops.py that checks the item again, changes it, follows
it until it ends and fixes what can be fixed safely (see wi_ops.py). The check itself only reads.

  image-housekeeping  Glance images that hold nothing (size 0: uploads that never finished, snapshots of volume-backed
                      instances whose data is in Cinder volume snapshots) and images of projects that no longer exist
  compute-drain       the instances of one compute as a list to tick: live migration one at a time (ACTIVE), cold migration
                      (SHUTOFF), what cannot move and why, and the compute service disabled / enabled around an emptying
"""
import re
import shlex

from . import overcloud
from .common import Result, director, human, json_of, source, to_float, unavailable
from .openstack import UUID, os_fix, os_select, pname, project_names
from .overcloud_checks import inventory

q = shlex.quote
HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
MAX_SHOW = 40          # image show / server show per run (the API of some sites answers slowly)
NOT_FINISHED = ("queued", "saving", "uploading", "importing", "killed", "deactivated")


def short(name):
    return str(name or "").split(".")[0].lower()


def days_since(iso, now_iso):
    from .openstack import minutes_since
    m = minutes_since(iso, now_iso)
    return None if m is None else m // 1440


def properties(value):
    """Image or flavor properties: a dict (python-openstackclient 5) or "k='v', k2='v2'" (4.0) -> dict."""
    if isinstance(value, dict):
        return {str(k): v for k, v in value.items()}
    out = {}
    for m in re.finditer(r"([A-Za-z0-9_:.-]+)='((?:[^'\\]|\\.)*)'", str(value or "")):
        out[m.group(1)] = m.group(2)
    return out


def bdm_snapshots(props):
    """Volume snapshot IDs of a snapshot image of a volume-backed instance (property block_device_mapping)."""
    raw = props.get("block_device_mapping")
    if not raw:
        return []
    ids = re.findall(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                     " ".join(re.findall(r"snapshot_id[\"']?\s*[:=]\s*[\"']?([0-9a-f-]{36})", str(raw))))
    return list(dict.fromkeys(ids))


def size_of(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# =========================================================================================== Image housekeeping
class ImageHousekeeping:
    """Glance images that can go: size 0 (an upload that never finished, an active image without data, or the snapshot
    of a volume-backed instance whose data is in Cinder volume snapshots), and images whose project was deleted. Images
    that are protected or used by an instance are listed, never offered."""
    sources = ("openstack",)
    phases = 2

    @staticmethod
    def reads(phase, data, params, ctx):
        if phase == 1:
            return {"openstack": {"images": "openstack image list --long -f json",
                                  "servers": "openstack server list --all-projects --long -f json",
                                  "projects": "openstack project list -f json",
                                  "snapshots": "openstack volume snapshot list --all-projects --long -f json",
                                  "now": "date -u +%Y-%m-%dT%H:%M:%SZ"}}
        images = json_of(source(data, "images"))
        if not isinstance(images, list):
            return {}
        names = project_names(data)
        wanted = []
        for i in images:
            if not isinstance(i, dict) or not UUID.match(str(i.get("ID") or "")):
                continue
            owner = str(i.get("Project") or i.get("Owner") or "")
            if size_of(i.get("Size")) in (0, None) or (names and owner and owner not in names):
                wanted.append(str(i["ID"]))
        return {"openstack": {f"img_{x}": f"openstack image show {x} -f json" for x in wanted[:MAX_SHOW]}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("image-housekeeping")
        item = source(data, "images")
        if unavailable(item):
            r.step("images", "Images (Glance)", "fail", f"openstack image list failed: {unavailable(item)}")
            return r.done()
        images = [i for i in json_of(item) or [] if isinstance(i, dict) and UUID.match(str(i.get("ID") or ""))]
        names = project_names(data)
        now = str(source(data, "now").get("out") or "").strip()
        min_days = int(params.get("days") or 1)
        only = str(params.get("project") or "").strip()
        servers_item = source(data, "servers")
        in_use = {}
        for s in json_of(servers_item) or [] if not unavailable(servers_item) else []:
            if isinstance(s, dict) and UUID.match(str(s.get("Image ID") or "")):
                in_use.setdefault(str(s["Image ID"]), []).append(str(s.get("Name") or s.get("ID")))
        snaps = {}
        for s in json_of(source(data, "snapshots")) or [] if not unavailable(source(data, "snapshots")) else []:
            if isinstance(s, dict):
                snaps[str(s.get("ID"))] = s
        by_status = {}
        for i in images:
            by_status[str(i.get("Status") or "?").lower()] = by_status.get(str(i.get("Status") or "?").lower(), 0) + 1
        empty_total = sum(1 for i in images if size_of(i.get("Size")) in (0, None))
        r.step("images", "Images (Glance)", "info",
               f"{len(images)} image(s): " + ", ".join(f"{n} {s}" for s, n in sorted(by_status.items()))
               + f"; {empty_total} with size 0 or no data."
               + ("" if not unavailable(servers_item) else f" The instances were not read ({unavailable(servers_item)}): "
                  "images in use cannot be told apart, nothing is offered."))
        candidates, kept, unread = [], [], 0
        for i in images:
            iid, size = str(i["ID"]), size_of(i.get("Size"))
            owner = str(i.get("Project") or i.get("Owner") or "")
            if only and only not in (owner, names.get(owner, "")):
                continue
            orphan = bool(names) and bool(owner) and owner not in names
            if size not in (0, None) and not orphan:
                continue
            detail_item = source(data, f"img_{iid}")
            if unavailable(detail_item):
                unread += 1
                continue
            d = json_of(detail_item) or {}
            props = properties(d.get("properties"))
            status = str(d.get("status") or i.get("Status") or "").lower()
            age = days_since(d.get("created_at") or d.get("updated_at"), now)
            snapshot_ids = bdm_snapshots(props)
            protected = str(d.get("protected", i.get("Protected"))).lower() == "true"
            visibility = str(d.get("visibility") or i.get("Visibility") or "")
            if size in (0, None) and snapshot_ids:
                kind = "Snapshot of a volume-backed instance (data in Cinder volume snapshots)"
            elif size in (0, None) and status in NOT_FINISHED:
                kind = f"Upload never finished ({status})"
            elif size in (0, None):
                kind = "Active but empty (size 0)"
            else:
                kind = f"Project deleted ({human(size)})"
            entry = {"id": iid, "name": str(d.get("name") or i.get("Name") or "(no name)"), "status": status, "size": size,
                     "owner": owner, "project": "deleted project " + owner if orphan else pname(names, owner),
                     "age": age, "kind": kind, "visibility": visibility, "snapshots": snapshot_ids,
                     "live_snapshots": [x for x in snapshot_ids if x in snaps], "orphan": orphan}
            why = ""
            if protected:
                why = "protected"
            elif iid in in_use:
                why = f"used by {len(in_use[iid])} instance(s): {', '.join(in_use[iid][:3])}"
            elif unavailable(servers_item):
                why = "instances not read"
            elif age is not None and age < min_days:
                why = f"created {age} day(s) ago (newer than {min_days})"
            elif status in ("saving", "uploading", "importing") and (age is None or age < 1):
                why = "upload may still run"
            if why:
                kept.append((entry, why))
            else:
                candidates.append(entry)
        empty = [c for c in candidates if not c["orphan"]]
        orphans = [c for c in candidates if c["orphan"]]
        row = lambda c: [c["name"], c["id"], c["kind"], human(c["size"]) if c["size"] else "0", c["project"],
                         f"{c['age']} days" if c["age"] is not None else "-", c["visibility"],
                         len(c["live_snapshots"]) if c["snapshots"] else "-"]
        cols = ["Image", "ID", "Kind", "Size", "Project", "Age", "Visibility", "Volume snapshots"]
        r.step("empty", "Images with size 0", "warn" if empty else "ok",
               (f"{len(empty)} image(s) hold no data and can be deleted"
                + (f" ({sum(1 for c in empty if c['snapshots'])} of them are snapshots of volume-backed instances: deleting "
                   "one also deletes its Cinder volume snapshots, which frees space and lets those volumes migrate)"
                   if any(c["snapshots"] for c in empty) else "") + "."
                if empty else "No image of size 0 to clean up.")
               + (f" {unread} image(s) were not read in this run (at most {MAX_SHOW}): run the check again after this clean-up."
                  if unread else ""),
               {"columns": cols, "rows": [row(c) for c in empty]})
        if names:
            r.step("orphans", "Images of projects that no longer exist", "warn" if orphans else "ok",
                   f"{len(orphans)} image(s) belong to a deleted project." if orphans else "None.",
                   {"columns": cols, "rows": [row(c) for c in orphans]})
        if kept:
            r.step("kept", "Not offered (kept)", "info", f"{len(kept)} image(s) of size 0 or of a deleted project are kept.",
                   {"columns": ["Image", "ID", "Kind", "Project", "Why kept"],
                    "rows": [[e["name"], e["id"], e["kind"], e["project"], why] for e, why in kept]})
        offered = empty + orphans
        if offered:
            items = []
            for c in offered:
                snaps_arg = ",".join(c["live_snapshots"]) if c["live_snapshots"] else "-"
                items.append({"label": c["name"] if c["name"] != "(no name)" else c["id"],
                              "commands": [f"delete-image {c['id']} expect {'any' if c['orphan'] else 'size0'} snapshots {snaps_arg}"],
                              "default": not c["orphan"] and not c["snapshots"] and c["visibility"] != "public"})
            manual = [f"openstack image delete {c['id']}   # {c['name']}, {c['kind']}" for c in offered[:30]]
            manual += [f"openstack volume snapshot delete {x}   # volume snapshot of image {c['name']}"
                       for c in offered for x in c["live_snapshots"]][:30]
            r.recommend("Delete the images that are no longer needed. Tick the images to delete: each is checked again right "
                        "before (still there, not protected, not used by an instance, still empty), deleted, and the volume "
                        "snapshots of an instance snapshot are deleted after it. Uploads that never finished are ticked; "
                        "instance snapshots, public images and images of deleted projects are not: tick them only when the "
                        "owner (PIC) agrees.",
                        manual, where=director(ctx),
                        items={"columns": cols, "rows": [row(c) for c in offered]},
                        warning="Deleting an image or a volume snapshot cannot be undone. An instance snapshot may be the "
                                "customer's only backup of that instance: confirm with the PIC and record it in the ticket.",
                        action=os_select(items, f"images of {ctx.get('site') or 'the site'}", "Delete selected images",
                                         "images", lock="images", stop_on_failure=False, item_timeout=1800))
        return r.done(None if offered or kept else "No image to clean up.")


# =========================================================================================== Compute drain (migration)
def node_of(host, nodes):
    """The overcloud node of a nova host: the same short name, else a compute node with the same number."""
    h = short(host)
    for n in nodes:
        if short(n["name"]) == h:
            return n
    num = re.search(r"(\d+)$", h)
    if num and "compute" in h:
        same = [n for n in nodes if "compute" in short(n["name"]) and re.search(r"(\d+)$", short(n["name"]))
                and int(re.search(r"(\d+)$", short(n["name"])).group(1)) == int(num.group(1))]
        if len(same) == 1:
            return same[0]
    return None


class ComputeDrain:
    """The instances of one compute as a list to tick: the operator chooses which ones move, then the portal moves them one
    at a time — ACTIVE ones with live migration, SHUTOFF ones with cold migration — each followed until it ends. The
    destination of each is the least used compute whose real CPU and RAM use (read on the computes right before that
    migration, RAM with the instance) stay under the limit (params max_usage, default 70 %); none: the instance is not
    moved. No allocation ratio is involved. What cannot move and why (Red Hat OpenStack Platform 17.1, migration
    constraints) is shown; the compute service can be disabled before an emptying and enabled again after. One list read
    (server list) and the usage of the computes (all at once), so the list appears fast even on a slow API."""
    sources = ("openstack", "undercloud", "overcloud")
    phases = 2
    MAX_NODES = 63
    # server list --long has no project column on python-openstackclient 4 (RHOSP 16.2); -c "Project ID" adds it on 5.x
    # (RHOSP 17.1) and is ignored by 4.x, which then needs server show for the project of each instance (phase 2).
    COLUMNS = ("ID", "Name", "Status", "Task State", "Power State", "Image Name", "Image ID", "Flavor Name", "Flavor ID",
               "Project ID")

    @staticmethod
    def servers(data):
        return [s for s in json_of(source(data, "servers")) or [] if isinstance(s, dict) and UUID.match(str(s.get("ID") or ""))]

    @staticmethod
    def reads(phase, data, params, ctx):
        host = str(params.get("compute") or "")
        if not HOST.match(host):
            return {}
        if phase == 1:
            cols = " ".join(f"-c {q(c)}" for c in ComputeDrain.COLUMNS)
            return {"openstack": {"services": "openstack compute service list --service nova-compute -f json",
                                  "servers": f"openstack server list --all-projects --host {q(host)} --long {cols} -f json",
                                  "projects": "openstack project list -f json",
                                  "flavors": "openstack flavor list --all --long -f json"},
                    "undercloud": dict(overcloud.INVENTORY_READS)}
        servers = ComputeDrain.servers(data)
        out = {}
        if servers and not any("Project ID" in s for s in servers):   # client 4.x: the project of each instance
            out["openstack"] = {f"srv_{s['ID']}": f"openstack server show {s['ID']} -f json" for s in servers[:MAX_SHOW]}
        found, _c, user, _v, _p = inventory(data, ctx)
        if user in overcloud.USERS:   # the real CPU / RAM use of the computes the instances can go to, read all at once
            reads = {}
            for i, (host, _zone) in enumerate(ComputeDrain.candidates(data, params)[:ComputeDrain.MAX_NODES]):
                n = node_of(host, found)
                if n and n.get("ip"):
                    reads[f"use_{i}"] = overcloud.read(n["name"], n["ip"], user, "usage")
            if reads:
                out["overcloud"] = reads
        return out

    @staticmethod
    def candidates(data, params):
        """[(host, zone)] of the computes the instances may go to: the destination named, else every enabled and up
        nova-compute but the one emptied, those of its availability zone first."""
        src, target = short(params.get("compute")), short(params.get("target"))
        services = [s for s in json_of(source(data, "services")) or [] if isinstance(s, dict)]
        zone = next((str(s.get("Zone") or "") for s in services if short(s.get("Host")) == src), "")
        out = [(str(s.get("Host")), str(s.get("Zone") or "")) for s in services
               if short(s.get("Host")) != src and str(s.get("Status") or "").lower() == "enabled"
               and str(s.get("State") or "").lower() == "up" and (not target or short(s.get("Host")) == target)]
        return sorted(out, key=lambda x: (x[1] != zone, x[0]))

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("compute-drain")
        host = str(params.get("compute") or "")
        src = short(host)
        svc_item = source(data, "services")
        if unavailable(svc_item):
            r.step("compute", "The compute", "fail", f"openstack compute service list failed: {unavailable(svc_item)}")
            return r.done()
        services = {}
        for s in json_of(svc_item) or []:
            if isinstance(s, dict):
                services[short(s.get("Host"))] = {"host": str(s.get("Host")), "status": str(s.get("Status") or "").lower(),
                                                   "state": str(s.get("State") or "").lower(), "zone": str(s.get("Zone") or "")}
        svc = services.get(src)
        if not svc:
            r.step("compute", "The compute", "fail", f"{host} is not a nova-compute host of {ctx.get('site') or 'this site'}. "
                   f"Known: {', '.join(sorted(v['host'] for v in services.values())[:15])}.")
            return r.done()
        if unavailable(source(data, "servers")):
            r.step("instances", f"Instances on {svc['host']}", "fail", f"openstack server list failed: {unavailable(source(data, 'servers'))}")
            return r.done()
        names = project_names(data)
        servers = ComputeDrain.servers(data)
        if svc["state"] != "up":
            r.step("compute", f"Compute {svc['host']}", "fail",
                   f"nova-compute of {svc['host']} is down ({svc['status']}): its {len(servers)} instance(s) cannot be live- or "
                   "cold-migrated. A failed compute is evacuated (openstack server evacuate) after it is fenced or powered off.")
            if servers:
                r.recommend(f"{svc['host']} is down: evacuate its instances only after the node is powered off or fenced (Red Hat: "
                            "Evacuating an instance). The portal does not run an evacuation.",
                            [f"openstack compute service set --disable --disable-reason 'down: evacuation' {svc['host']} nova-compute",
                             f"openstack server list --all-projects --host {svc['host']} --long"]
                            + [f"openstack server evacuate {s['ID']}   # {s.get('Name')}" for s in servers[:20]],
                            where=director(ctx), refs=["rhosp-migration", "rhosp-compute-down"])
            return r.done()
        # flavors (one list): size and the extra specs that block a live migration
        flavors = {}
        for f in json_of(source(data, "flavors")) or []:
            if isinstance(f, dict):
                for k in (f.get("ID"), f.get("Name")):
                    if k:
                        flavors[str(k)] = f
        found, _controllers, user, _version, _problem = inventory(data, ctx)
        live, cold, other = [], [], []
        for s in servers:
            sid = str(s["ID"])
            d = json_of(source(data, f"srv_{sid}")) or {}
            status = str(s.get("Status") or d.get("status") or "").upper()
            task = str(s.get("Task State") or d.get("OS-EXT-STS:task_state") or "")
            task = "" if task in ("None", "none", "-") else task
            fname = str(s.get("Flavor Name") or "")
            f = flavors.get(fname) or flavors.get(str(s.get("Flavor ID") or "")) or {}
            specs = properties(f.get("Properties"))
            ram, vcpus, disk = int(to_float(f.get("RAM")) or 0), int(to_float(f.get("VCPUs")) or 0), int(to_float(f.get("Disk")) or 0)
            image = str(s.get("Image Name") or s.get("Image ID") or "")
            on_volume = (not image) or "booted from volume" in image.lower() or image.startswith("N/A")
            notes, blocked = [], ""
            if any(k.startswith("pci_passthrough") for k in specs):
                blocked = "PCI passthrough: live migration not supported (cold migration only, with the instance shut off)"
            elif any(k.startswith("resources:VGPU") or k.startswith("resources:PGPU") for k in specs):
                blocked = "vGPU: live migration not supported (cold migration only, with the instance shut off)"
            if specs.get("hw:cpu_policy") == "dedicated" or "hw:numa_nodes" in specs or "hw:mem_page_size" in specs:
                notes.append("pinned CPU / NUMA / huge pages: the destination needs the same free resources")
            if not on_volume and disk:
                notes.append(f"local disk {disk} GiB: block migration, slower")
            if not f:
                notes.append(f"flavor {fname or '?'} not in the flavor list (deleted?)")
            entry = {"id": sid, "name": str(s.get("Name") or sid), "status": status, "task": task,
                     "power": str(s.get("Power State") or ""),
                     "project": pname(names, s.get("Project ID") or d.get("project_id")), "ram": ram, "vcpus": vcpus,
                     "flavor": fname or "?", "boot": "volume" if on_volume else "local disk", "notes": notes, "blocked": blocked}
            if task:
                entry["blocked"] = f"task {task} running"
            if entry["blocked"] and status != "SHUTOFF":
                other.append(entry)
            elif status in ("ACTIVE", "PAUSED"):
                live.append(entry)
            elif status == "SHUTOFF" and not task:
                entry["blocked"] = ""   # PCI passthrough / vGPU: a shut-off instance can be cold-migrated
                cold.append(entry)
            else:
                entry["blocked"] = entry["blocked"] or {
                    "ERROR": "ERROR: see the check Stuck instances and volumes", "MIGRATING": "already migrating",
                    "RESIZED": "waiting for a resize confirmation", "VERIFY_RESIZE": "waiting for a resize / migration confirmation"}.get(
                    status, f"{status}: migrate it after it is ACTIVE or SHUTOFF")
                other.append(entry)
        # destinations: the scheduler chooses (or the compute named); when one refuses, the other enabled and up computes
        # are tried, those of the same availability zone first
        target = str(params.get("target") or "").strip()
        if target:
            t = services.get(short(target))
            problem = ("is not a nova-compute host" if not t else "is the compute being emptied" if short(target) == src else
                       f"is {t['status']} / {t['state']}" if (t["status"], t["state"]) != ("enabled", "up") else "")
            if problem:
                r.step("target", f"Destination {target}", "fail", f"{target} {problem}: choose another destination or leave it "
                       "empty (the scheduler chooses).")
                return r.done()
            target = t["host"]
        limit = int(params.get("max_usage") or 70)
        cands = ComputeDrain.candidates(data, params)
        r.step("compute", f"Compute {svc['host']}", "warn" if other else "ok",
               f"nova-compute {svc['status']} and {svc['state']}, zone {svc['zone'] or '-'}; {len(servers)} instance(s): "
               f"{len(live)} can be live-migrated, {len(cold)} shut off (cold migration), {len(other)} cannot move now. "
               + (f"Destination: {target}, only while its CPU and RAM stay under {limit}%." if target else
                  f"Destination of each: the least used of {len(cands)} other compute(s) enabled and up whose CPU and RAM "
                  f"stay under {limit}%.")
               + (" The service is disabled: the scheduler places nothing here until it is enabled again." if svc["status"] == "disabled" else ""))
        how = {}
        for e in live:
            how[e["id"]] = "live migration"
        for e in cold:
            how[e["id"]] = "cold migration (shut off)"
        for e in other:
            how[e["id"]] = f"cannot move now: {e['blocked']}"
        order = {str(s['ID']): i for i, s in enumerate(servers)}   # as server list gives them
        everyone = sorted(live + cold + other, key=lambda e: order[e['id']])
        r.step("instances", f"Instances on {svc['host']}", "info" if servers else "ok",
               (f"Tick the instances to move under How to fix it (nothing is ticked: only the ones you tick move)."
                if live or cold else "No instance can be moved now." if servers else f"No instance is left on {svc['host']}."),
               {"columns": ["Instance", "ID", "Project", "Status", "Flavor", "Boot", "Move", "Notes"],
                "rows": [[e["name"], e["id"], e["project"], e["status"], f"{e['flavor']} ({e['vcpus']} vCPU, {e['ram'] // 1024} GiB)"
                          if e["vcpus"] else e["flavor"], e["boot"], how[e["id"]], "; ".join(e["notes"]) or "-"] for e in everyone]})
        # the destinations: real use now (read again right before each migration, then with the RAM of the instance)
        rows, under = [], 0
        for i, (h, zone) in enumerate(cands[:ComputeDrain.MAX_NODES]):
            item = source(data, f"use_{i}")
            u = overcloud.parse_usage(item.get("out")) if not unavailable(item) else None
            fits = bool(u) and u["cpu"] < limit and u["ram"] < limit
            under += fits
            rows.append([h, zone or "-", f"{u['cpu']:g}%" if u else "-", f"{u['ram']:g}%" if u else "-",
                         "yes" if fits else "no" if u else f"not read: {unavailable(item) or 'no ctlplane address'}"[:120]])
        if cands:
            r.step("destinations", f"Destinations: CPU and RAM under {limit}%", "ok" if under else "warn",
                   f"{under} of {len(rows)} compute(s) are under {limit}% CPU and RAM now (real use, read on each compute). "
                   "Right before each migration they are read again and the RAM of the instance is added: the least used one "
                   "that stays under the limit takes it; when none does, that instance is not moved (skipped)."
                   + ("" if len(cands) <= ComputeDrain.MAX_NODES else f" Only the first {ComputeDrain.MAX_NODES} computes are used."),
                   {"columns": ["Compute", "Zone", "CPU now", "RAM now", f"Under {limit}%"],
                    "rows": sorted(rows, key=lambda x: (x[4] != "yes", x[0]))},
                   marks=[x[0] for x in rows if x[4] != "yes"])
        else:
            r.step("destinations", "Destinations", "fail" if live or cold else "info",
                   f"No other compute is enabled and up{(' named ' + target) if target else ''}: nothing can move.")
        # the migrations need the ctlplane address of the computes: the usage read before each migration and virsh before a
        # reset of an instance left in ERROR
        retry = [h for h, _z in cands if short(h) != short(target)][:3]
        node_map = {}
        for h in [svc["host"]] + [h for h, _z in cands[:ComputeDrain.MAX_NODES]]:
            n = node_of(h, found)
            if n and n.get("ip"):
                node_map[short(h)] = n["ip"]
        nodes_arg = ",".join(f"{h}={ip}" for h, ip in node_map.items()) or "-"
        user_arg = user if user in overcloud.USERS and node_map else "-"
        measurable = nodes_arg != "-" and user_arg != "-" and len(node_map) > 1
        if (live or cold) and not measurable:
            r.step("nodes", "Overcloud node addresses", "fail",
                   "The ctlplane addresses of the computes could not be read from the undercloud: their CPU and RAM use "
                   "cannot be read, so no instance is moved from here.")
        timeout = int(params.get("timeout_minutes") or 60) * 60
        stall = "force" if params.get("stall") == "force-complete" else "abort"
        stop = params.get("on_failure", "stop") != "continue"
        where = director(ctx)
        cols = ["Instance", "ID", "Project", "Status", "Flavor", "Boot", "Notes"]
        row = lambda e: [e["name"], e["id"], e["project"], e["status"], f"{e['flavor']} ({e['vcpus']} vCPU, {e['ram'] // 1024} GiB)"
                         if e["vcpus"] else e["flavor"], e["boot"], "; ".join(e["notes"]) or "-"]
        dest = target or f"least used under {limit}%"
        if live and measurable and cands:
            items = [{"label": f"{e['name']} -> {dest}",
                      "commands": [f"live-migrate {e['id']} from {svc['host']} to {target or 'auto'} try {','.join(retry) or '-'} "
                                   f"timeout {timeout} stall {stall} nodes {nodes_arg} user {user_arg} under {limit} ram {e['ram']}"],
                      "default": False} for e in live]
            r.recommend(f"Live-migrate the instances you tick off {svc['host']}, one at a time. Nothing is ticked: tick the "
                        f"instances to move, then start. Each starts only when the one before has finished; "
                        + (f"the destination is {target} while its real CPU and RAM use stay under {limit}%" if target else
                           f"the destination of each is the least used compute whose real CPU and RAM use (read right before, RAM "
                           f"with the instance) stay under {limit}%")
                        + "; when none does, the instance is not moved (skipped, the next one still runs); when the destination "
                        f"refuses, the next compute under the limit is tried; a migration still running after {timeout // 60} minutes is "
                        + ("forced to complete (the instance pauses briefly)" if stall == "force" else "aborted (the instance keeps running here)")
                        + "; an instance left in ERROR is reset to ACTIVE only after virsh shows it running on its compute. "
                        + ("The run stops at the first instance that cannot be migrated." if stop else
                           "An instance that cannot be migrated is skipped; the run stops only when one needs a person."),
                        [f"openstack server migrate --live-migration {('--host ' + target + ' ') if target else ''}{e['id']}   # {e['name']}"
                         for e in live[:30]]
                        + [f"openstack server migration list --server {live[0]['id']}",
                           f"openstack server list --all-projects --host {svc['host']}"],
                        where=where, refs=["rhosp-migration", "nova-live-migration"],
                        items={"columns": cols, "rows": [row(e) for e in live]},
                        warning="A live migration copies the memory while the instance runs and pauses it for a moment at the "
                                "end; local disks are copied too (longer). Tell the customers (PIC) of these instances first and "
                                "run it outside busy hours.",
                        action=os_select(items, svc["host"], "Live-migrate selected", "instances", lock="migration",
                                         stop_on_failure=stop, item_timeout=timeout + 1800))
        if cold and measurable and cands:
            items = [{"label": f"{e['name']} -> {dest}",
                      "commands": [f"cold-migrate {e['id']} from {svc['host']} to {target or 'auto'} try {','.join(retry) or '-'} "
                                   f"timeout {timeout} nodes {nodes_arg} user {user_arg} under {limit} ram {e['ram']}"],
                      "default": False} for e in cold]
            r.recommend(f"Cold-migrate the shut-off instances you tick, one at a time: each is moved to the least used compute "
                        f"under {limit}% CPU and RAM (none: not moved), confirmed (VERIFY_RESIZE) and stays shut off there.",
                        [f"openstack server migrate {('--host ' + target + ' ') if target else ''}{e['id']}   # {e['name']}" for e in cold[:30]]
                        + [f"openstack server resize confirm {cold[0]['id']}   # when its status is VERIFY_RESIZE"],
                        where=where, refs=["rhosp-migration"],
                        items={"columns": cols, "rows": [row(e) for e in cold]},
                        warning="The instances stay shut off; start them only if their owner asks.",
                        action=os_select(items, svc["host"], "Cold-migrate selected", "instances", lock="migration",
                                         stop_on_failure=stop, item_timeout=timeout + 900))
        if svc["status"] == "enabled" and (live or cold):
            r.recommend(f"Only when {svc['host']} is emptied for maintenance: disable it before the migrations, so the scheduler "
                        "places no new instance on it meanwhile. Not needed to move a few instances. Enable it again after "
                        "the maintenance (the check shows how once it is empty).",
                        [f"openstack compute service set --disable --disable-reason 'Maintenance: drained by Operation Automation' "
                         f"{svc['host']} nova-compute",
                         f"openstack compute service list --service nova-compute --host {svc['host']}"],
                        where=where, refs=["rhosp-migration"],
                        action=os_fix([f"openstack compute service set --disable --disable-reason 'Maintenance: drained by Operation "
                                       f"Automation' {svc['host']} nova-compute",
                                       f"openstack compute service list --service nova-compute --host {svc['host']}"],
                                      svc["host"], label="Disable the compute"))
        if other:
            r.recommend(f"{len(other)} instance(s) on {svc['host']} cannot be moved now: see why for each.",
                        [f"openstack server show {e['id']} -c status -c OS-EXT-STS:task_state -c fault   # {e['name']}" for e in other[:20]],
                        where=where, refs=["rhosp-migration"],
                        items={"columns": ["Instance", "ID", "Project", "Status", "Why it stays"],
                               "rows": [[e["name"], e["id"], e["project"], e["status"], e["blocked"]] for e in other]})
        if svc["status"] == "disabled" and not servers:
            r.recommend(f"{svc['host']} is empty and disabled. When the maintenance is over, enable it again so the scheduler uses it.",
                        [f"openstack compute service set --enable {svc['host']} nova-compute"], where=where,
                        action=os_fix([f"openstack compute service set --enable {svc['host']} nova-compute",
                                       f"openstack compute service list --service nova-compute --host {svc['host']}"],
                                      svc["host"], label="Enable the compute"))
        n = len(live) + len(cold)
        return r.done(f"{len(servers)} instance(s) on {svc['host']}: {n} can be moved (tick them under How to fix it), "
                      f"{len(other)} cannot move now." if servers else f"No instance is left on {svc['host']}.")

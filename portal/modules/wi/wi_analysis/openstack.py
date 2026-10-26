"""Operation Automation checks of Acme Flex (OpenStack). Every command of a check only reads (list / show / get-pools / quota /
limits); the playbook refuses any other command (see wi_analysis.OPENSTACK_READ).

Data per check: openstack commands in phases (a later phase can use what an earlier one found), ONTAP REST GETs with
the site's read-only account, and TCP probes from the portal server. The fixes are commands with the IDs, names and
values found here, to run on the director. A fix that the WI lets an operator do on OpenStack also has an action
(os_fix): an operator with the permission "run OpenStack fixes" runs it from the result (Run this fix), only the changes
of wi_analysis.OPENSTACK_FIX; what deletes (snapshots, a retype replica, an instance) needs its ID or name typed. Steps
the WI keeps in the Service Portal (attach, Sync Instance, VPC / NAT Gateway, OpenVPN users) have no action.
"""
import ipaddress
import math
import re
import shlex

from .common import (Result, director, human, json_of, level, pct, property_tables, source, text_of, to_float,
                     unavailable, worst)

UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
CINDER_FIELDS = ("id,name,status,size,volume_type,os-vol-host-attr:host,os-vol-tenant-attr:tenant_id,"
                 "os-vol-mig-status-attr:migstat,created_at,updated_at")
# Default "old type -> new type" of the WIs (Snapshot volume error, VM failed to resize root disk, Backup scheduler);
# a site overrides it with openstack.legacy_volume_types in sites.yml (on some sites these names are active types).
DEFAULT_LEGACY_TYPES = {"standard": "fas500f-standard", "basic": "fas500f-basic", "premium": "affa-premium"}
TRANSITIONAL = {"creating", "attaching", "detaching", "deleting", "reserved", "retyping", "maintenance", "downloading",
                "uploading", "extending", "backing-up", "restoring-backup", "awaiting-transfer"}
ERROR_STATES = {"error", "error_deleting", "error_attaching", "error_detaching", "error_extending", "error_restoring",
                "error_managing"}
q = shlex.quote
RESET_WARNING = ("reset-state only changes the status in the Cinder database: confirm the real state first (Horizon, the "
                 "instance, the LUN), make sure a backup or snapshot exists, and coordinate any downtime with the customer.")


def os_fix(commands, target, confirm="", label="Run this fix"):
    """Action of a recommendation that the portal may run on OpenStack (Run this fix): the changes, without trailing
    comments, and reads that show the result. target: what changes (shown, and the key of the job); confirm: what the
    operator types before a deletion (an ID or a name)."""
    from . import openstack_fix_command   # the same check as the playbook: a wrong command fails here, in the tests
    cmds = [openstack_fix_command(c) for c in commands if c]
    return {"kind": "openstack", "commands": cmds, "target": target, "confirm": confirm or target, "label": label}


def os_select(items, target, label, noun, lock="", stop_on_failure=True, item_timeout=3600, max_items=40):
    """Action of a recommendation whose rows the operator ticks (the items table of the recommendation, row for row):
    items [{"label", "commands", "default", "disabled"}]. The portal runs the ticked items one after the other (one script
    on the director per item, playbooks/tasks/openstack_item.yml), each only with its own commands. lock: one fix of
    this kind per site at a time (e.g. "migration": never two migrations together). stop_on_failure: stop at the first
    item that is not done (exit 5 or 6); otherwise only at one that needs a person (exit 6, wi_ops.py)."""
    from . import openstack_fix_command
    out = []
    for it in items:
        cmds = [openstack_fix_command(c) for c in it.get("commands") or [] if c]
        disabled = str(it.get("disabled") or ("" if cmds else "nothing to run"))
        out.append({"label": str(it.get("label") or "")[:160], "commands": [] if disabled else cmds,
                    "default": bool(it.get("default")) and not disabled, "disabled": disabled})
    return {"kind": "openstack", "commands": [], "target": target, "confirm": "", "label": label,
            "select": {"items": out, "noun": noun, "lock": lock, "stop": [5, 6] if stop_on_failure else [6],
                       "timeout": int(item_timeout), "max": int(max_items)}}


def project_names(data):
    """{project ID: name} from `openstack project list -f json` (read "projects"), {} when it was not read."""
    items = json_of(source(data, "projects")) or []
    return ({str(x.get("ID") or x.get("id")): str(x.get("Name") or x.get("name") or "") for x in items if isinstance(x, dict)}
            if isinstance(items, list) else {})


def pname(names, pid):
    """A project as Horizon shows it: its name (the commands keep the ID); the ID when the name is unknown."""
    return names.get(str(pid)) or str(pid or "-")


# One volume at a time: the next retype / migration starts only when this one finished (WI). Seconds to wait for one.
RETYPE_WAIT = 7200
MIGRATE_WAIT = 14400


def table_rows(text):
    """A cinder/nova text table (+----+ | a | b | rows) -> list of dicts keyed by normalised header names."""
    header, rows = None, []
    for line in str(text or "").splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if header is None:
            header = [re.sub(r"\s+", "_", c.lower()) for c in cells]
            continue
        if len(cells) == len(header):
            rows.append(dict(zip(header, cells)))
    return rows


def pick(row, *names, default=""):
    for name in names:
        if name in row and row[name] not in (None, ""):
            return row[name]
    return default


def cinder_volumes(item):
    """Volumes from `cinder list --all-tenants --fields ...` (table) or `openstack volume list -f json`."""
    data = json_of(item) if text_of(item).lstrip().startswith("[") else None
    rows = data if isinstance(data, list) else table_rows(text_of(item))
    vols = []
    for r in rows:
        r = {str(k).lower().replace(" ", "_"): v for k, v in r.items()}
        vols.append({"id": pick(r, "id"), "name": pick(r, "name"), "status": str(pick(r, "status")).lower(),
                     "size": to_float(pick(r, "size")) or 0, "type": pick(r, "volume_type", "type"),
                     "host": pick(r, "os-vol-host-attr:host", "host"),
                     "project": pick(r, "os-vol-tenant-attr:tenant_id", "tenant_id", "project_id", "project"),
                     "migstat": str(pick(r, "os-vol-mig-status-attr:migstat", "migration_status")).lower(),
                     "updated": pick(r, "updated_at"), "created": pick(r, "created_at")})
    return vols


def pool_of(host):
    return str(host or "").split("#")[-1]


def minutes_since(iso, now_iso):
    """Minutes between two ISO times (tolerant: 'Z', fractions, no zone = UTC). None when unknown."""
    import datetime

    def parse(text):
        text = str(text or "").strip().replace("Z", "+00:00")
        if not text:
            return None
        try:
            value = datetime.datetime.fromisoformat(text)
        except ValueError:
            return None
        return value if value.tzinfo else value.replace(tzinfo=datetime.timezone.utc)
    a, b = parse(iso), parse(now_iso)
    return None if a is None or b is None else round((b - a).total_seconds() / 60)


def attachments(volume):
    """[{server_id, device}] of `openstack volume show -f json`."""
    items = volume.get("attachments") or []
    if isinstance(items, str):   # older clients print a repr string
        return [{"server_id": m.group(1), "device": ""} for m in re.finditer(r"'server_id': '([0-9a-f-]{36})'", items)]
    return [{"server_id": a.get("server_id") or a.get("server") or "", "device": a.get("device") or ""}
            for a in items if isinstance(a, dict)]


# =========================================================================================== Cinder volume over 80%
class CinderPoolUsage:
    """WI "Cinder Volume Over 80%": pool usage (space really used: ONTAP FlexVol, else Cinder total - free; never the
    allocated capacity, which is overcommitted, e.g. 2:1), the volumes and the old snapshots in the affected pools, and
    where to migrate them."""
    sources = ("openstack", "ontap")
    phases = 1
    at = {"pools": ["openstack", "ontap"]}   # steps read on more than the first source (diagram of the run page)

    @staticmethod
    def reads(phase, data, params, ctx):
        return {"openstack": {"pools": "cinder get-pools --detail",
                              "volumes": f"cinder list --all-tenants --fields {CINDER_FIELDS}",
                              "snapshots": "openstack volume snapshot list --all-projects --long -f json",
                              "projects": "openstack project list -f json",   # names, as Horizon shows them
                              "now": "date -u +%Y-%m-%dT%H:%M:%SZ"},   # age of the snapshots
                "ontap": {"flexvols": "/api/storage/volumes?fields=name,svm.name,state,space.size,space.used,"
                                      "space.available,space.snapshot.used,space.snapshot.reserve_percent&max_records=2000"}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("cinder-pool-usage")
        names = project_names(data)
        threshold = int(params.get("threshold") or 80)
        early = max(50, threshold - 10)
        only = str(params.get("pool") or "").strip().lower()
        pools_item, vols_item = source(data, "pools"), source(data, "volumes")
        if unavailable(pools_item):
            r.step("pools", "Identify the affected Cinder pools", "fail", f"cinder get-pools failed: {unavailable(pools_item)}")
            return r.done()
        snap_days = int(params.get("snapshot_days") or 14)
        flex_item = source(data, "flexvols")
        flexvols = {}
        if not unavailable(flex_item):
            for rec in (json_of(flex_item) or {}).get("records") or []:
                space = rec.get("space") or {}
                flexvols[rec.get("name")] = {"svm": (rec.get("svm") or {}).get("name", ""), "size": space.get("size"),
                                             "used": space.get("used"), "available": space.get("available"),
                                             "snap_used": (space.get("snapshot") or {}).get("used"), "state": rec.get("state")}
        pools = []
        for p in property_tables(text_of(pools_item)):
            name = p.get("name") or ""
            pool = p.get("pool_name") or pool_of(name)
            if only and only not in name.lower():
                continue
            total, free = to_float(p.get("total_capacity_gb")), to_float(p.get("free_capacity_gb"))
            cinder_pct = pct(total - free, total) if total and free is not None else None   # used, not allocated
            fv = flexvols.get(pool) or {}
            ontap_pct = pct(fv.get("used"), fv.get("size")) if fv else None
            used_pct = ontap_pct if ontap_pct is not None else cinder_pct
            pools.append({"host": name, "pool": pool, "backend": p.get("volume_backend_name", ""), "total_gb": total,
                          "free_gb": free, "cinder_pct": cinder_pct, "ontap_pct": ontap_pct, "used_pct": used_pct, "fv": fv,
                          "status": level(used_pct, early, threshold)})
        if not pools:
            r.step("pools", "Identify the affected Cinder pools", "warn",
                   f"No Cinder pool{' matches ' + repr(only) if only else ' was returned by cinder get-pools'}.")
            return r.done()
        pools.sort(key=lambda p: -(p["used_pct"] or 0))
        hot = [p for p in pools if p["status"] == "fail"]
        warm = [p for p in pools if p["status"] == "warn"]
        basis = ("ONTAP FlexVol used space (as the Grafana panel)" if flexvols else
                 f"space used in Cinder (total - free); ONTAP was not read: {unavailable(flex_item)}")
        r.step("pools", "Identify the affected Cinder pools", "fail" if hot else "warn" if warm else "ok",
               f"{len(hot)} pool(s) at or above {threshold}%, {len(warm)} at or above {early}% (early warning). Usage = {basis}. "
               "The allocated capacity is not used: it is overcommitted (e.g. 2:1).",
               {"columns": ["Pool", "Backend", "SVM", "ONTAP used", "Cinder used", "Free (Cinder)", "Total", "Status"],
                "rows": [[p["pool"], p["backend"], p["fv"].get("svm") or "-",
                          f"{p['ontap_pct']}%" if p["ontap_pct"] is not None else "-",
                          f"{p['cinder_pct']}%" if p["cinder_pct"] is not None else "-",
                          f"{p['free_gb']:.0f} GiB" if p["free_gb"] is not None else "-",
                          f"{p['total_gb']:.0f} GiB" if p["total_gb"] is not None else "-", p["status"].upper()] for p in pools]})
        affected = hot or warm
        vols = [] if unavailable(vols_item) else cinder_volumes(vols_item)
        if not affected:
            r.step("volumes", "Volumes in the affected pools", "skip", "No pool needs action.")
            r.step("snapshots", "Evaluate snapshots", "skip", "No pool needs action.")
            return r.done(f"All {len(pools)} Cinder pools are below {early}%.")
        if unavailable(vols_item):
            r.step("volumes", "Volumes in the affected pools", "warn", f"cinder list failed: {unavailable(vols_item)}")
        else:
            rows = []
            for p in affected:
                inside = sorted([v for v in vols if pool_of(v["host"]) == p["pool"]], key=lambda v: -v["size"])
                p["volumes"] = inside
                for v in inside[:10]:
                    rows.append([p["pool"], v["name"] or "(no name)", v["id"], f"{v['size']:.0f} GiB", v["status"], pname(names, v["project"])])
            r.step("volumes", "Volumes in the affected pools (largest first)", "info",
                   "; ".join(f"{p['pool']}: {len(p.get('volumes') or [])} volume(s), "
                             f"{sum(v['size'] for v in p.get('volumes') or []):.0f} GiB" for p in affected),
                   {"columns": ["Pool", "Volume", "ID", "Size", "Status", "Project"], "rows": rows})
        # Migration plan: biggest movable volumes to the emptiest pool of the same backend (same SVM first), until the
        # source pool is under the early-warning level, without pushing the target above it.
        snaps_all = json_of(source(data, "snapshots")) if not unavailable(source(data, "snapshots")) else []
        snaps_of = {}
        for x in snaps_all if isinstance(snaps_all, list) else []:
            if isinstance(x, dict) and UUID.match(str(x.get("ID") or "")):
                snaps_of.setdefault(str(x.get("Volume") or x.get("volume_id") or ""), []).append(x)
        for p in affected:
            targets = [t for t in pools if t["backend"] == p["backend"] and t["pool"] != p["pool"] and t["status"] == "ok"
                       and "test" not in t["pool"].lower()]
            same_svm = [t for t in targets if p["fv"].get("svm") and t["fv"].get("svm") == p["fv"].get("svm")]
            targets = same_svm or targets
            # WI: a volume with snapshots cannot be migrated: its approved snapshots are deleted first (ticked by the operator)
            snapped = lambda v: snaps_of.get(v["id"]) or (snaps_of.get(v["name"]) if v["name"] else None) or []
            movable = [v for v in (p.get("volumes") or []) if v["status"] in ("available", "in-use")]
            if not targets:
                r.recommend(f"No pool of backend {p['backend'] or '?'} has room below {early}% for volumes of {p['pool']}. "
                            "Plan a capacity addition with the storage team.")
                continue
            if not movable:
                continue
            ordered = sorted(targets, key=lambda x: x["used_pct"] or 0)
            t, alternates = ordered[0], ordered[1:3]
            need_gb = max(0.0, ((p["used_pct"] or 0) - early + 1) / 100.0 * (p["total_gb"] or 0))
            room_gb = max(0.0, (early - 1 - (t["used_pct"] or 0)) / 100.0 * (t["total_gb"] or 0))
            plan, moved = [], 0.0   # ticked by default: the biggest volumes without snapshots until the pool is under the early level
            for v in movable:
                if snapped(v) or moved >= need_gb or moved + v["size"] > room_gb:
                    continue
                plan.append(v)
                moved += v["size"]
            if not plan and not any(snapped(v) for v in movable[:1]):
                plan = movable[:1]
            offered = movable[:40]
            cmds = []
            for v in plan:
                cmds += [f"cinder migrate {v['id']} {q(t['host'])}   # {v['name'] or 'no name'}, {v['size']:.0f} GiB, {v['status']}",
                         f"watch -n 30 \"openstack volume show {v['id']} -c migration_status -c os-vol-host-attr:host -f value\""
                         f"   # until migration_status is success, before the next volume"]
            items = []
            for v in offered:
                snap_ids = [str(s.get("ID")) for s in snapped(v)]
                items.append({"label": f"{v['name'] or v['id']} ({v['size']:.0f} GiB)"
                                       + (f" + delete {len(snap_ids)} snapshot(s)" if snap_ids else ""),
                              "commands": [f"migrate-volume {v['id']} to {t['host']} try "
                                           f"{','.join(a['host'] for a in alternates) or '-'} timeout {MIGRATE_WAIT} "
                                           f"snapshots {','.join(snap_ids[:50]) or '-'}"],
                              "default": v in plan,
                              "disabled": f"{len(snap_ids)} snapshots: more than 50, delete them first" if len(snap_ids) > 50 else ""})
            in_use = [v for v in offered if v["status"] == "in-use"]
            with_snaps = [v for v in offered if snapped(v)]
            r.recommend(f"Migrate volumes from {p['pool']} ({p['used_pct']}%) to {t['pool']} ({t['used_pct']}%, same "
                        f"{'SVM' if same_svm else 'backend'}), one at a time, until {p['pool']} is under {early}%. Ticked: "
                        f"{len(plan)} volume(s), {moved:.0f} GiB, the biggest without snapshots. A volume with snapshots migrates "
                        "only after its snapshots are deleted: tick it only when the PIC approved deleting them (they are listed in "
                        "the Volume snapshots column, and deleted right before its migration). Each volume is checked again "
                        "first; the next starts when it ended; on a failure the temporary copy is cleaned up and "
                        f"{', '.join(a['pool'] for a in alternates) or 'no other pool'} is tried next. "
                        "In Horizon: Admin → Volumes → Migrate Volume.",
                        cmds, where=director(ctx), refs=["cinder-migration"],
                        items={"columns": ["Volume", "ID", "Size", "Status", "Project", "Volume snapshots"],
                               "rows": [[v["name"] or "(no name)", v["id"], f"{v['size']:.0f} GiB", v["status"], pname(names, v["project"]),
                                         len(snapped(v)) or "-"] for v in offered]},
                        warning=((f"{len(in_use)} volume(s) are in-use: they migrate online, but the copy loads the storage. Start "
                                  "outside busy hours and confirm with their PIC first. " if in_use else "")
                                 + (f"{len(with_snaps)} volume(s) have snapshots: deleting them cannot be undone (Backup "
                                    "Scheduler snapshots too). " if with_snaps else "")
                                 + "A migration takes minutes to hours; run the check again afterwards."),
                        action=os_select(items, f"{p['pool']} → {t['pool']}", "Migrate selected", "volumes",
                                         lock="volume-migration", stop_on_failure=True, item_timeout=MIGRATE_WAIT + 1800))
        snaps_item = source(data, "snapshots")
        if unavailable(snaps_item):
            r.step("snapshots", "Evaluate snapshots", "skip", f"Snapshots were not read: {unavailable(snaps_item)}")
        else:
            snaps = json_of(snaps_item) or []
            now = str(source(data, "now").get("out") or "").strip()
            by_volume = {}
            for s in snaps if isinstance(snaps, list) else []:
                by_volume.setdefault(str(s.get("Volume") or s.get("volume_id") or ""), []).append(s)
            rows, candidates, unknown = [], [], 0
            for p in affected:
                vols_here = p.get("volumes") or []
                found = [(v, s) for v in vols_here for key in {v["id"], v["name"]} if key for s in by_volume.get(key, [])]
                old = []
                for v, s in found:
                    age = minutes_since(s.get("Created At") or s.get("created_at"), now)
                    if age is None:
                        unknown += 1
                    elif age >= snap_days * 1440:
                        old.append((v, s, age // 1440))
                old.sort(key=lambda x: -x[2])
                candidates += old
                snap_used = p["fv"].get("snap_used")
                rows.append([p["pool"], len(vols_here), len(found), len(old),
                             f"{sum(to_float(s.get('Size')) or 0 for _, s, _ in old):.0f} GiB",
                             human(snap_used) if snap_used is not None else "-"])
            r.step("snapshots", "Evaluate snapshots", "warn" if candidates else "ok",
                   (f"{len(candidates)} snapshot(s) older than {snap_days} days in the affected pools: candidates to delete after "
                    "the volume owner (PIC) confirms. Newer snapshots are kept." if candidates else
                    f"No snapshot older than {snap_days} days in the affected pools: snapshots are not what to clean up.")
                   + (f" The age of {unknown} snapshot(s) is unknown (no creation time): they are not offered." if unknown else ""),
                   {"columns": ["Pool", "Volumes", "Cinder snapshots", f"Older than {snap_days} days", "Their size (Cinder)",
                                "Snapshot used (ONTAP)"], "rows": rows})
            # One recommendation per volume: its PIC approves its snapshots; the operator types the volume to delete them.
            by_vol = {}
            for v, s, days in candidates:
                by_vol.setdefault(v["id"], (v, []))[1].append((s, days))
            for v, snaps in list(by_vol.values())[:15]:
                vname = v["name"] or v["id"]
                cmds = [f"openstack volume snapshot delete {s.get('ID')}   # {s.get('Name')}, {s.get('Size')} GiB, {days} days old"
                        for s, days in snaps[:20]]
                r.recommend(f"Delete the old snapshots of volume {vname} (project {pname(names, v['project'])}) that its PIC no longer needs. "
                            f"{len(snaps)} snapshot(s) are older than {snap_days} days "
                            f"({sum(to_float(s.get('Size')) or 0 for s, _ in snaps):.0f} GiB); delete only the ones the PIC approved.",
                            cmds + [f"openstack volume snapshot list --all-projects --volume {v['id']}"],
                            where=director(ctx),
                            items={"columns": ["Snapshot", "ID", "Size", "Age"],
                                   "rows": [[s.get("Name") or "(no name)", s.get("ID"), f"{to_float(s.get('Size')) or 0:.0f} GiB",
                                             f"{days} days"] for s, days in snaps[:20]]},
                            warning="Deleting a snapshot cannot be undone (Backup Scheduler snapshots too: tell the customer). "
                                    "Record the PIC's approval in the ticket.",
                            action=os_fix(cmds + [f"openstack volume snapshot list --all-projects --volume {v['id']}"],
                                          f"snapshots of {vname}", confirm=vname, label="Delete these snapshots"))
            if len(by_vol) > 15:
                r.recommend(f"{len(by_vol) - 15} more volume(s) have old snapshots: run the check again after these.")
        return r.done()


# =========================================================================================== Legacy volume type
class VolumeTypeLegacy:
    """WIs "Volume Snapshot Error on the Backend", "VM Fails to Resize Root Disk", "Backup Scheduler Does Not Run
    Snapshot": volumes that still use an old volume type."""
    sources = ("openstack",)
    phases = 2

    @staticmethod
    def reads(phase, data, params, ctx):
        project = params.get("project") or ""
        if phase == 1:
            reads = {"types": "openstack volume type list --long -f json", "projects": "openstack project list -f json"}
            if project:
                reads["project"] = f"openstack project show {q(project)} -f json"
            return {"openstack": reads}
        pid = ((json_of(source(data, "project")) or {}).get("id") if project else "") or ""
        if project and not pid:
            return {}
        scope = f" --tenant {q(pid)}" if pid else ""
        # the snapshots: a volume with snapshots cannot be retyped with a migration (they are deleted first, when approved)
        return {"openstack": {"volumes": f"cinder list --all-tenants{scope} --fields {CINDER_FIELDS}",
                              "snapshots": "openstack volume snapshot list --all-projects --long -f json"}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("volume-type-legacy")
        names = project_names(data)
        legacy = ctx["legacy_volume_types"] if "legacy_volume_types" in ctx else DEFAULT_LEGACY_TYPES
        project = params.get("project") or ""
        if project:
            p_item = source(data, "project")
            if unavailable(p_item):
                r.step("project", "Find the project", "fail", f"Project {project} not found: {unavailable(p_item)}")
                return r.done()
            info = json_of(p_item) or {}
            r.step("project", "Find the project", "ok", f"{info.get('name')} ({info.get('id')})")
        if not legacy:
            r.step("types", "Old volume types of this site", "skip",
                   "No old volume types are configured for this site (openstack.legacy_volume_types in sites.yml).")
            return r.done()
        types_item = source(data, "types")
        known = {str(t.get("Name") or t.get("name")) for t in (json_of(types_item) or [])} if not unavailable(types_item) else set()
        missing_new = sorted({new for new in legacy.values() if known and new not in known})
        r.step("types", "Old volume types of this site", "warn" if missing_new else "ok",
               ", ".join(f"{old} → {new}" for old, new in legacy.items())
               + (f". Not found in OpenStack: {', '.join(missing_new)}" if missing_new else ""))
        vols_item = source(data, "volumes")
        if unavailable(vols_item):
            r.step("volumes", "Volumes on an old type", "fail", f"cinder list failed: {unavailable(vols_item)}")
            return r.done()
        vols = sorted([v for v in cinder_volumes(vols_item) if v["type"] in legacy], key=lambda v: (v["project"], v["name"]))
        counts = {}
        for v in vols:
            counts[v["type"]] = counts.get(v["type"], 0) + 1
        r.step("volumes", "Volumes on an old type", "warn" if vols else "ok",
               (f"{len(vols)} volume(s): " + ", ".join(f"{n} × {t} (→ {legacy[t]})" for t, n in sorted(counts.items()))
                + ". Snapshots, resize of the root disk and the Backup Scheduler can fail on these volumes.")
               if vols else f"No volume{' of this project' if project else ''} uses an old type.",
               {"columns": ["Volume", "ID", "Type", "Change to", "Size", "Status", "Project"],
                "rows": [[v["name"] or "(no name)", v["id"], v["type"], legacy[v["type"]], f"{v['size']:.0f} GiB", v["status"],
                          pname(names, v["project"])] for v in vols]})
        busy = [v for v in vols if v["status"] not in ("available", "in-use")]
        ready = [v for v in vols if v["status"] in ("available", "in-use")]
        snaps_item = source(data, "snapshots")
        snaps_all = json_of(snaps_item) if not unavailable(snaps_item) else []
        snaps_of = {}
        for x in snaps_all if isinstance(snaps_all, list) else []:
            if isinstance(x, dict) and UUID.match(str(x.get("ID") or "")):
                snaps_of.setdefault(str(x.get("Volume") or x.get("volume_id") or ""), []).append(x)
        snapped = lambda v: snaps_of.get(v["id"]) or (snaps_of.get(v["name"]) if v["name"] else None) or []
        if vols and unavailable(snaps_item):
            r.step("snapshots", "Snapshots of these volumes", "warn",
                   f"Snapshots were not read ({unavailable(snaps_item)}): a volume with snapshots cannot be retyped; the "
                   "operation checks them again before each volume.")
        elif vols:
            with_snaps = [v for v in vols if snapped(v)]
            r.step("snapshots", "Snapshots of these volumes", "warn" if with_snaps else "ok",
                   (f"{len(with_snaps)} volume(s) have snapshots ({sum(len(snapped(v)) for v in with_snaps)} in total): a volume "
                    "with snapshots cannot be retyped with a migration. Their snapshots are deleted first, when their PIC "
                    "approved it (tick the volume)." if with_snaps else "No snapshot: every volume can be retyped as it is."),
                   {"columns": ["Volume", "Snapshot", "Name", "Size", "Status", "Created"],
                    "rows": [[v["name"] or v["id"], str(x.get("ID")), str(x.get("Name") or "-"), f"{x.get('Size') or '-'} GiB",
                              str(x.get("Status") or "-"), str(x.get("Created At") or x.get("created_at") or "-")[:19]]
                             for v in with_snaps for x in snapped(v)]})
        projects = {}
        for v in ready:
            projects.setdefault(v["project"], []).append(v)
        for pid, pvols in list(projects.items())[:10]:   # one per project: each customer agrees its own time
            cmds, items = [], []
            for v in pvols[:40]:
                snap_ids = [str(x.get("ID")) for x in snapped(v)]
                cmds += [f"openstack volume snapshot delete {sid}   # snapshot of {v['name'] or 'no name'} (approved by the PIC)"
                         for sid in snap_ids]
                cmds += [f"cinder retype --migration-policy on-demand {v['id']} {q(legacy[v['type']])}   "
                         f"# {v['name'] or 'no name'}, {v['size']:.0f} GiB, {v['status']}",
                         f"openstack volume show {v['id']} -c volume_type -c status -c migration_status   "
                         f"# until status is {v['status']} again and migration_status success, before the next volume"]
                items.append({"label": f"{v['name'] or v['id']} ({v['size']:.0f} GiB, {v['status']})"
                                       + (f" + delete {len(snap_ids)} snapshot(s)" if snap_ids else ""),
                              "commands": [f"retype-volume {v['id']} to {legacy[v['type']]} timeout {RETYPE_WAIT} "
                                           f"snapshots {','.join(snap_ids[:50]) or '-'}"],
                              "default": not snap_ids,
                              "disabled": f"{len(snap_ids)} snapshots: more than 50, delete them first" if len(snap_ids) > 50 else ""})
            with_snaps = [v for v in pvols[:40] if snapped(v)]
            r.recommend(f"Change the volume type of {len(pvols)} volume(s) of project {pname(names, pid)}, one at a time. "
                        "Agree a time with the customer: the retype copies the data to the new pool; the next volume starts when the "
                        "previous one is back to its status with the new type. A volume with snapshots is retyped only after its "
                        "snapshots are deleted: tick it only when the PIC approved deleting them (Volume snapshots column; they are "
                        "deleted right before its retype). In Horizon: Project → Volumes → Change Volume Type, migration policy On "
                        "Demand (not possible in the Service Portal). Then retry the snapshot / resize / backup.",
                        cmds, where=director(ctx),
                        items={"columns": ["Volume", "ID", "Type", "Change to", "Size", "Status", "Volume snapshots"],
                               "rows": [[v["name"] or "(no name)", v["id"], v["type"], legacy[v["type"]], f"{v['size']:.0f} GiB", v["status"],
                                         len(snapped(v)) or "-"] for v in pvols[:40]]},
                        warning=((f"{len(with_snaps)} volume(s) have snapshots: deleting them cannot be undone (Backup Scheduler "
                                  "snapshots too). " if with_snaps else "")
                                 + "If a retype stops with the volume reserved or retyping, run the check \"Instances or volumes "
                                   "stuck\": it gives the rollback commands of the WI \"Rollback Volume Type\" for that volume."),
                        action=os_select(items, f"volume types of project {pname(names, pid)}", "Change the type of the ticked volumes",
                                         "volumes", lock="volume-migration", stop_on_failure=False, item_timeout=RETYPE_WAIT + 1800))
        if len(projects) > 10:
            r.recommend(f"{len(projects) - 10} more project(s) have volumes on an old type: run the check again per project.")
        if busy:
            r.recommend(f"{len(busy)} volume(s) on an old type are {', '.join(sorted({v['status'] for v in busy}))}: solve that first "
                        "(check \"Instances or volumes stuck\"), then change their type.")
        return r.done()


# =========================================================================================== Project quota
def quota_limits(item):
    """`openstack quota show -f json`: a dict, or a list of {"Resource", "Limit"} in newer clients."""
    data = json_of(item)
    if isinstance(data, list):
        return {str(x.get("Resource") or x.get("resource")): x.get("Limit", x.get("limit")) for x in data if isinstance(x, dict)}
    return data if isinstance(data, dict) else {}


def absolute_limits(item):
    data = json_of(item)
    if isinstance(data, list):
        return {str(x.get("Name") or x.get("name")): x.get("Value", x.get("value")) for x in data if isinstance(x, dict)}
    return data if isinstance(data, dict) else {}


class ProjectQuota:
    """WIs "Failed to Create a New Instance" and "VM Fails to Resize Root Disk": quota use of one project."""
    sources = ("openstack",)
    phases = 2
    # (label, usage key, limit key, quota key, option of `openstack quota set`, unit divisor)
    RESOURCES = {
        "compute": ("Compute quota (instances, vCPU, RAM)", [
            ("Instances", "totalInstancesUsed", "maxTotalInstances", "instances", "--instances", 1),
            ("vCPU", "totalCoresUsed", "maxTotalCores", "cores", "--cores", 1),
            ("RAM", "totalRAMUsed", "maxTotalRAMSize", "ram", "--ram", 1024)]),
        "storage": ("Block storage quota (volumes, GiB, snapshots)", [
            ("Volumes", "totalVolumesUsed", "maxTotalVolumes", "volumes", "--volumes", 1),
            ("Volume storage", "totalGigabytesUsed", "maxTotalVolumeGigabytes", "gigabytes", "--gigabytes", 1),
            ("Snapshots", "totalSnapshotsUsed", "maxTotalSnapshots", "snapshots", "--snapshots", 1)]),
    }

    @staticmethod
    def reads(phase, data, params, ctx):
        project = params.get("project") or ""
        if phase == 1:
            return {"openstack": {"project": f"openstack project show {q(project)} -f json"}}
        pid = (json_of(source(data, "project")) or {}).get("id") or ""
        if not pid:
            return {}
        return {"openstack": {"quota": f"openstack quota show {q(pid)} -f json",
                              "limits": f"openstack limits show --absolute --project {q(pid)} -f json",
                              "ports": f"openstack port list --project {q(pid)} -f json",
                              "fips": f"openstack floating ip list --project {q(pid)} -f json"}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("project-quota")
        p_item = source(data, "project")
        if unavailable(p_item):
            r.step("project", "Find the project", "fail", f"Project {params.get('project')} not found: {unavailable(p_item)}")
            return r.done()
        info = json_of(p_item) or {}
        pid, pname = info.get("id"), info.get("name")
        r.step("project", "Find the project", "ok", f"{pname} ({pid})")
        quota = quota_limits(source(data, "quota"))
        limits = absolute_limits(source(data, "limits"))
        ports = json_of(source(data, "ports"))
        fips = json_of(source(data, "fips"))
        sections = dict(ProjectQuota.RESOURCES)
        sections["network"] = ("Network quota (ports, floating IPs)", [
            ("Ports", None, None, "ports", "--ports", 1), ("Floating IPs", None, None, "floating-ips", "--floating-ips", 1)])
        counted = {"Ports": len(ports) if isinstance(ports, list) else None,
                   "Floating IPs": len(fips) if isinstance(fips, list) else None}
        raises = []
        for key, (title, items) in sections.items():
            rows = []
            for label, used_key, limit_key, quota_key, option, div in items:
                used = counted[label] if used_key is None else to_float(limits.get(used_key))
                limit = to_float(limits.get(limit_key)) if limit_key and limits.get(limit_key) is not None else to_float(
                    quota.get(quota_key, quota.get(quota_key.replace("-ips", "ip").replace("-", "_"), quota.get(quota_key.rstrip("s")))))
                if used is None or limit is None:
                    rows.append([label, "-", "-", "-", "skip"])
                    continue
                if limit < 0:
                    rows.append([label, f"{used / div:.0f}", "unlimited", "-", "ok"])
                    continue
                p = pct(used, limit) if limit else 100.0
                st = level(p, 90, 100)
                unit = " GiB" if div == 1024 or quota_key == "gigabytes" else ""
                rows.append([label, f"{used / div:.0f}{unit}", f"{limit / div:.0f}{unit}", f"{p}%", st])
                if st in ("fail", "warn"):
                    # Proposal: enough for 20% growth over today's use, at least one more unit than now.
                    new = max(limit + div, math.ceil(used * 1.2 / div) * div)
                    raises.append((label, option, int(new), int(limit), unit, div))
            rated = [x[4] for x in rows if x[4] != "skip"]
            status = worst(*rated) if rated else "skip"
            full = [x[0] for x in rows if x[4] == "fail"]
            near = [f"{x[0]} ({x[3]})" for x in rows if x[4] == "warn"]
            text = "; ".join(t for t in (f"Full: {', '.join(full)}" if full else "", f"Nearly full: {', '.join(near)}" if near else "") if t)
            r.step(key, title, status, (text + ".") if text else "Within quota." if rated else "Not available.",
                   {"columns": ["Resource", "In use", "Quota", "Use", "Status"], "rows": [x[:4] + [x[4].upper()] for x in rows]})
        if raises:
            cmds = [f"openstack quota set {opt} {new} {pid}   # {label}: {old // div}{unit} → {new // div}{unit}"
                    for label, opt, new, old, unit, div in raises] + [f"openstack quota show {pid}"]
            r.recommend(f"Tell the customer which quota of {pname} is full. After Sales approves the increase, raise exactly "
                        "these quotas (values = today's use + 20%; adjust to the approved package):",
                        cmds, where=director(ctx),
                        warning="Run only after Sales approved it. Compare with the quota in the Service Portal first: if the "
                                "portal shows other values, align OpenStack with the portal instead of raising it.",
                        action=os_fix(cmds, f"quota of {pname}", label="Raise these quotas"))
        return r.done()


# =========================================================================================== Stuck resources
class StuckResources:
    """WIs "Instance Stuck in Building Status" and "Rollback Volume Type": instances and volumes stuck in a
    transitional or error state, with the fix per instance and per volume."""
    sources = ("openstack",)
    phases = 2

    @staticmethod
    def reads(phase, data, params, ctx):
        project = params.get("project") or ""
        if phase == 1:
            scope = f"--project {q(project)}" if project else "--all-projects"
            return {"openstack": {"servers": f"openstack server list {scope} --long -f json",
                                  "volumes": f"cinder list --all-tenants --fields {CINDER_FIELDS}",
                                  "projects": "openstack project list -f json",
                                  "now": "date -u +%Y-%m-%dT%H:%M:%SZ"}}
        servers = json_of(source(data, "servers")) or []
        ids = [s.get("ID") for s in servers if isinstance(s, dict) and str(s.get("Status")).upper() in ("BUILD", "ERROR")
               and UUID.match(str(s.get("ID") or ""))][:15]
        reads = {f"server_{i}": f"openstack server show {q(i)} -f json" for i in ids}
        for v in cinder_volumes(source(data, "volumes")):
            if (v["status"] in TRANSITIONAL or v["migstat"] not in ("", "none", "success", "-")) and UUID.match(v["id"]):
                reads[f"volume_{v['id']}"] = f"openstack volume show {q(v['id'])} -f json"
        return {"openstack": dict(list(reads.items())[:30])}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("stuck-resources")
        names = project_names(data)
        older = int(params.get("older_than") or 30)
        now = str(source(data, "now").get("out") or "").strip()
        servers_item = source(data, "servers")
        if unavailable(servers_item):
            r.step("build", "Instances stuck in BUILD", "fail", f"server list failed: {unavailable(servers_item)}")
        else:
            details = {k[7:]: json_of(v) or {} for k, v in (data or {}).items() if k.startswith("server_") and isinstance(v, dict)}
            servers = [s for s in json_of(servers_item) or [] if isinstance(s, dict)]
            build, errors = [], []
            for s in servers:
                st = str(s.get("Status")).upper()
                if st not in ("BUILD", "ERROR"):
                    continue
                d = details.get(s.get("ID")) or {}
                age = minutes_since(d.get("created"), now)
                fault = (d.get("fault") or {}).get("message", "") if isinstance(d.get("fault"), dict) else str(d.get("fault") or "")
                item = {"id": s.get("ID"), "name": s.get("Name"), "host": d.get("OS-EXT-SRV-ATTR:host") or s.get("Host") or "-",
                        "age": age, "project": d.get("project_id") or s.get("Project ID") or "-", "fault": fault,
                        "nets": ", ".join((d.get("addresses") or {}).keys()) if isinstance(d.get("addresses"), dict) else ""}
                if st == "BUILD" and (age is None or age >= older):
                    build.append(item)
                elif st == "ERROR":
                    errors.append(item)
            cols = ["Instance", "ID", "Compute", "Age", "Project", "Fault"]
            row = lambda i: [i["name"], i["id"], i["host"], f"{i['age']} min" if i["age"] is not None else "-", pname(names, i["project"]), i["fault"][:160]]
            r.step("build", f"Instances in BUILD for {older} minutes or more", "fail" if build else "ok",
                   f"{len(build)} instance(s)." if build else "None.", {"columns": cols, "rows": [row(i) for i in build]})
            r.step("error", "Instances in ERROR", "warn" if errors else "ok", f"{len(errors)} instance(s)." if errors else "None.",
                   {"columns": cols, "rows": [row(i) for i in errors]})
            for i in build:
                r.recommend(f"{i['name']} has been building for {i['age'] if i['age'] is not None else '?'} minutes"
                            + (" without any network: it was created without a VPC" if not i["nets"] else "")
                            + ". Look at the instance actions, check the free ports of its VPC, then (with the customer) delete "
                            "it and create it again with a VPC that has free addresses.",
                            [f"openstack server event list {i['id']}",
                             f"openstack server show {i['id']} -c status -c OS-EXT-STS:task_state -c fault",
                             f"openstack network list --project {i['project']}",
                             f"openstack port list --project {i['project']} --long",
                             f"openstack server delete {i['id']}   # only after the customer agrees"],
                            where=director(ctx), warning="Delete only after the customer agreed; it is created again from the Service Portal.",
                            action=os_fix([f"require server {i['id']} status BUILD", f"openstack server delete {i['id']}", "sleep 5",
                                           f"openstack server list --project {i['project']}"],
                                          i["name"] or i["id"], label="Delete this instance"))
            for i in errors:
                capacity = "no valid host" in i["fault"].lower()
                r.recommend(f"{i['name']} is in ERROR: {i['fault'] or 'no fault message'}."
                            + (" No compute has room for its flavor in its availability zone: check the free capacity, "
                               "then rebuild it (or delete and create it again) with the customer." if capacity else ""),
                            ([f"openstack server show {i['id']} -c flavor -c OS-EXT-AZ:availability_zone -c fault",
                              "openstack hypervisor list --long",
                              "openstack hypervisor stats show"] if capacity else
                             [f"openstack server event list {i['id']}", f"openstack server show {i['id']} -c fault"])
                            + [f"openstack server delete {i['id']}   # only after the customer agrees"],
                            where=director(ctx), warning="Delete only after the customer agreed; it is created again from the Service Portal.",
                            action=os_fix([f"require server {i['id']} status ERROR", f"openstack server delete {i['id']}", "sleep 5",
                                           f"openstack server list --project {i['project']}"],
                                          i["name"] or i["id"], label="Delete this instance"))
        vols_item = source(data, "volumes")
        if unavailable(vols_item):
            r.step("volumes", "Volumes stuck in a transitional state", "fail", f"cinder list failed: {unavailable(vols_item)}")
            return r.done()
        vols = cinder_volumes(vols_item)
        by_id = {v["id"]: v for v in vols}
        shown = {k[7:]: json_of(v) or {} for k, v in (data or {}).items() if k.startswith("volume_") and isinstance(v, dict)}
        stuck, errs, migrating, markers = [], [], [], []
        replicas = {v["migstat"][7:] for v in vols if v["migstat"].startswith("target:")}
        for v in vols:
            age = minutes_since(v["updated"], now)
            v["age"] = age
            if v["migstat"].startswith("target:"):
                continue   # the temporary copy of a retype: shown with its original volume
            if v["status"] in TRANSITIONAL and (age is None or age >= older):
                stuck.append(v)
            elif v["status"] in ERROR_STATES:
                errs.append(v)
            if v["migstat"] in ("", "none", "success", "-") or not (age is None or age >= older):
                continue
            # migration_status "error" on a volume that is available / in-use, without a leftover replica: an old
            # migration or retype failed and Cinder rolled it back; the volume works where it is, only the marker stays.
            if v["migstat"] == "error" and v["status"] in ("available", "in-use") and v["id"] not in replicas:
                markers.append(v)
            else:
                migrating.append(v)
        cols = ["Volume", "ID", "Status", "Migration", "Since update", "Project"]
        row = lambda v: [v["name"] or "(no name)", v["id"], v["status"], v["migstat"] or "-",
                         f"{v['age']} min" if v["age"] is not None else "-", pname(names, v["project"])]
        r.step("volumes", f"Volumes in a transitional state for {older} minutes or more", "fail" if stuck else "ok",
               f"{len(stuck)} volume(s)." if stuck else "None.", {"columns": cols, "rows": [row(v) for v in stuck]})
        r.step("volume_errors", "Volumes in an error state", "warn" if errs else "ok", f"{len(errs)} volume(s)." if errs else "None.",
               {"columns": cols, "rows": [row(v) for v in errs]})
        r.step("migration", "Volume migrations / retypes not finished", "fail" if migrating else "ok",
               (f"{len(migrating)} volume(s): a migration or change of volume type still running, stuck, or failed with the "
                "volume in error or a replica left behind." if migrating else "None."),
               {"columns": cols, "rows": [row(v) for v in migrating]})
        markers.sort(key=lambda v: -(v["age"] or 0))
        r.step("migration_markers", "Old failed migrations (marker only)", "info" if markers else "ok",
               (f"{len(markers)} volume(s) are {'/'.join(sorted({v['status'] for v in markers}))} with migration_status error: "
                "an earlier migration or retype failed and Cinder rolled it back. The volume works on its current pool; only "
                "the marker stays until the next migration. Not a problem: nothing to delete." if markers else "None."),
               {"columns": cols, "rows": [row(v) for v in markers]})
        if markers:
            r.recommend(f"Optional: clear the old migration marker of the {len(markers)} volume(s) above, so later checks and "
                        "Horizon show them clean. The status stays what it is now (explicit --state); nothing moves.",
                        [f"cinder reset-state --state {v['status']} --reset-migration-status {v['id']}   # {v['name'] or 'no name'}"
                         for v in markers[:30]], where=director(ctx), warning=RESET_WARNING,
                        action=os_fix([x for v in markers[:30] for x in (f"require volume {v['id']} migration_status error",
                                                                          f"require volume {v['id']} status {v['status']}",
                                                                          f"cinder reset-state --state {v['status']} --reset-migration-status {v['id']}")],
                                      f"migration markers of {min(len(markers), 30)} volume(s)",
                                      label="Clear the markers"))
        for v in [x for x in stuck if x not in migrating]:
            att = attachments(shown.get(v["id"]) or {})
            cmds = [f"openstack volume show {v['id']} -c status -c attachments -c migration_status"]
            if v["status"] in ("attaching", "reserved") and not att:
                text = (f"{v['name'] or v['id']} has been {v['status']} for {v['age']} minutes without an attachment: the attach "
                        "never finished. Put it back to available, then attach it again from the Service Portal.")
                cmds += [f"cinder reset-state --state available --attach-status detached {v['id']}"]
            elif v["status"] == "detaching" or att:
                server = att[0]["server_id"] if att else ""
                text = (f"{v['name'] or v['id']} has been {v['status']} for {v['age']} minutes"
                        + (f" and is still attached to instance {server}" if server else " without an attachment record")
                        + (". Detach it in Horizon (the instance must usually be powered off — confirm with the customer), then "
                           "attach it again from the Service Portal." if server else
                           ": the detach finished on the instance; put it back to available (WI 6.C), then attach it again "
                           "from the Service Portal."))
                if server:
                    cmds += [f"openstack server show {server} -c name -c status -c OS-EXT-STS:power_state",
                             f"openstack server stop {server}   # only after the customer agrees",
                             f"openstack server remove volume {server} {v['id']}"]
                else:
                    cmds += [f"cinder reset-state --state available --attach-status detached {v['id']}"]
            else:
                text = f"{v['name'] or v['id']} has been {v['status']} for {v['age']} minutes: look at the cinder-volume log, then escalate to i3/L2."
                cmds += [f"sudo grep {v['id']} /var/log/containers/cinder/cinder-volume.log | tail -20   # on the controllers"]
            changes = []
            if any(c.startswith("cinder reset-state") for c in cmds):   # only while still stuck and not attached
                changes = [f"require volume {v['id']} status {v['status']}", f"require volume {v['id']} attachments none",
                           f"cinder reset-state --state available --attach-status detached {v['id']}"]
            elif any(c.startswith("openstack server remove volume") for c in cmds):
                server = next(c.split()[-2] for c in cmds if c.startswith("openstack server remove volume"))
                changes = [f"require volume {v['id']} status {v['status']}", f"openstack server stop {server}",
                           f"wait server {server} status SHUTOFF 180", f"openstack server remove volume {server} {v['id']}",
                           f"wait volume {v['id']} status available 180"]
            r.recommend(text, cmds, where=director(ctx),
                        warning=(RESET_WARNING if any("reset-state" in c for c in cmds) else
                                 "The instance is stopped first: ask the customer before. Start it again afterwards if the "
                                 "customer wants (openstack server start)." if changes else ""),
                        action=os_fix(changes + [cmds[0]], v["name"] or v["id"],
                                      label="Reset to available" if "cinder reset-state" in changes[-1] else "Stop the instance and detach")
                        if changes else None)
        for v in migrating:
            replica = next((x for x in vols if x["migstat"] == f"target:{v['id']}"), None)
            att = attachments(shown.get(v["id"]) or {})
            back = "in-use --attach-status attached" if att else "available --attach-status detached"
            cmds = [f"openstack volume show {v['id']} -c status -c migration_status -c volume_type"]
            if replica:
                cmds += [f"cinder reset-state --state available --attach-status detached --reset-migration-status {replica['id']}"
                         f"   # replica {replica['name']}, type {replica['type']}",
                         f"cinder delete {replica['id']}"]
            cmds += [f"cinder reset-state --state {back} --reset-migration-status {v['id']}   # original volume"]
            if replica and replica["type"]:
                cmds += [f"cinder retype --migration-policy on-demand {v['id']} {q(replica['type'])}   # retry later, with the customer"]
            rollback = ([f"require volume {replica['id']} migration_status target:{v['id']}"] if replica else []) \
                + [c.split("   #")[0] for c in cmds[1:] if not c.startswith("cinder retype")]   # not the retry
            r.recommend(f"Rollback of the failed retype of {v['name'] or v['id']} (WI \"Rollback Volume Type\", as root on the "
                        f"controller with overcloudrc): {'remove the replica ' + replica['id'] + ', ' if replica else ''}then set the "
                        f"original volume back to {'in-use (it is attached)' if att else 'available'}.",
                        cmds, where=director(ctx), warning=RESET_WARNING,
                        action=os_fix(rollback + ["sleep 5", cmds[0]], v["name"] or v["id"],
                                      confirm=replica["id"] if replica else "", label="Roll back the retype"))
        return r.done()


# =========================================================================================== Volume attach
class VolumeAttach:
    """WIs "Volume Cannot Be Attached Again" and "Storage Cannot Be Attached Again After Being Detached in the Service
    Portal": where the volume is still attached, the state of that instance, and the exact detach / reset / attach."""
    sources = ("openstack",)
    phases = 2

    @staticmethod
    def reads(phase, data, params, ctx):
        vid = params.get("volume") or ""
        if phase == 1:
            reads = {"volume": f"openstack volume show {q(vid)} -f json", "now": "date -u +%Y-%m-%dT%H:%M:%SZ",
                     "projects": "openstack project list -f json"}
            if params.get("instance"):
                reads["target"] = f"openstack server show {q(params['instance'])} -f json"
            return {"openstack": reads}
        vol = json_of(source(data, "volume")) or {}
        servers = sorted({a["server_id"] for a in attachments(vol) if UUID.match(a["server_id"])})
        return {"openstack": {f"server_{s}": f"openstack server show {q(s)} -f json" for s in servers[:4]}} if servers else {}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("volume-attach")
        names = project_names(data)
        vid = params.get("volume")
        item = source(data, "volume")
        if unavailable(item):
            r.step("volume", "Find the volume", "fail", f"Volume {vid} not found: {unavailable(item)}")
            return r.done()
        vol = json_of(item) or {}
        status = str(vol.get("status") or "").lower()
        now = str(source(data, "now").get("out") or "").strip()
        age = minutes_since(vol.get("updated_at"), now)
        att = attachments(vol)
        name = vol.get("name") or vid
        project = vol.get("os-vol-tenant-attr:tenant_id") or vol.get("project_id") or "-"
        r.step("volume", "Volume status in Cinder (Horizon)", "ok" if status == "available" and not att else
               "fail" if status in TRANSITIONAL or status in ERROR_STATES else "warn",
               f"{name} ({vid}) is {status}" + (f" since {age} min" if age is not None else "")
               + f", {len(att)} attachment(s), project {pname(names, project)}, type {vol.get('type') or vol.get('volume_type') or '-'}.")
        servers = {}
        for a in att:
            s = json_of(source(data, f"server_{a['server_id']}")) or {}
            servers[a["server_id"]] = s
        if att:
            r.step("attachments", "Still attached in Horizon", "fail" if status != "in-use" or params.get("instance") else "warn",
                   "; ".join(f"{(servers.get(a['server_id']) or {}).get('name') or a['server_id']} as {a['device'] or '?'} "
                             f"({(servers.get(a['server_id']) or {}).get('status') or '?'}, power "
                             f"{(servers.get(a['server_id']) or {}).get('OS-EXT-STS:power_state') or '?'})" for a in att)
                   + ". The Service Portal shows it detached, but OpenStack still has it on this instance.",
                   {"columns": ["Instance", "ID", "Device", "Status", "Power"],
                    "rows": [[(servers.get(a["server_id"]) or {}).get("name") or "-", a["server_id"], a["device"] or "-",
                              (servers.get(a["server_id"]) or {}).get("status") or "-",
                              (servers.get(a["server_id"]) or {}).get("OS-EXT-STS:power_state") or "-"] for a in att]})
        else:
            r.step("attachments", "Still attached in Horizon", "ok", "No attachment: the volume is free in OpenStack.")
        target = json_of(source(data, "target")) or {}
        if params.get("instance"):
            ok = target.get("id") and str(target.get("status")).upper() in ("ACTIVE", "SHUTOFF")
            same_project = target.get("project_id") in (None, project)
            r.step("target", "Instance to attach to", "ok" if ok and same_project else "fail",
                   (f"{target.get('name')} ({target.get('id')}) is {target.get('status')}"
                    + ("" if same_project else f", but in project {target.get('project_id')} (not {project})") + ".")
                   if target.get("id") else f"Instance {params['instance']} not found: {unavailable(source(data, 'target'))}")
        where = director(ctx)
        attach_to = target.get("id") if target.get("id") else ""
        attach_cmd = (f"openstack server add volume {attach_to} {vid}   # or attach it from the Service Portal"
                      if attach_to else "# then attach it again from the Service Portal (Storage → Attach)")
        if att:
            for a in att:
                s = servers.get(a["server_id"]) or {}
                running = str(s.get("status")).upper() == "ACTIVE"
                r.recommend(f"Detach {name} from {s.get('name') or a['server_id']} in Horizon (or with the commands below)"
                            + (". The instance is running: if the detach does not finish, power it off first — ask the customer "
                               "before stopping it" if running else "") + ", then attach it again.",
                            [f"openstack server remove volume {a['server_id']} {vid}",
                             f"openstack volume show {vid} -c status -c attachments"]
                            + ([f"openstack server stop {a['server_id']}   # only if the detach hangs, after the customer agrees",
                                f"openstack server remove volume {a['server_id']} {vid}"] if running else [])
                            + [attach_cmd], where=where,
                            warning="Then attach it again from the Service Portal, so that the portal records stay right.",
                            action=os_fix([f"require volume {vid} status in-use", f"openstack server remove volume {a['server_id']} {vid}",
                                           f"wait volume {vid} status available 120",
                                           f"openstack volume show {vid} -c status -c attachments"], name, label="Detach it"))
        elif status in ("attaching", "reserved"):
            r.recommend(f"{name} is {status} without any attachment: the last attach never finished. Put it back to available, "
                        "then attach it again.",
                        [f"cinder reset-state --state available --attach-status detached {vid}",
                         f"openstack volume show {vid} -c status", attach_cmd], where=where, warning=RESET_WARNING,
                        action=os_fix([f"require volume {vid} status {status}", f"require volume {vid} attachments none",
                                       f"cinder reset-state --state available --attach-status detached {vid}",
                                       f"openstack volume show {vid} -c status -c attachments"], name, label="Reset to available"))
        elif status == "detaching":
            r.recommend(f"{name} is stuck detaching without an attachment record: put it back to available and attach it again.",
                        [f"cinder reset-state --state available --attach-status detached {vid}", attach_cmd],
                        where=where, warning=RESET_WARNING,
                        action=os_fix([f"require volume {vid} status {status}", f"require volume {vid} attachments none",
                                       f"cinder reset-state --state available --attach-status detached {vid}",
                                       f"openstack volume show {vid} -c status -c attachments"], name, label="Reset to available"))
        elif status in ERROR_STATES:
            r.recommend(f"{name} is in {status}: do not reset it blindly. Check the cinder-volume log for this volume and "
                        "escalate to i3 / L2 with the output.",
                        [f"openstack volume show {vid}",
                         f"sudo grep {vid} /var/log/containers/cinder/cinder-volume.log | tail -50   # on the controllers"],
                        where=where)
        elif status == "available":
            r.recommend(f"{name} is available and free: attach it.", [attach_cmd], where=where)
        return r.done()


# =========================================================================================== Instance network
def sg_allows(rules, port, protocol="tcp"):
    """Ingress rules (security group rule list --long) that allow port/protocol from anywhere or some address."""
    hits = []
    for rule in rules:
        if str(rule.get("Direction") or rule.get("direction") or "").lower() != "ingress":
            continue
        proto = str(rule.get("IP Protocol") or rule.get("protocol") or "").lower()
        if proto not in ("", "none", "any", protocol):
            continue
        rng = str(rule.get("Port Range") or rule.get("port_range") or "")
        if proto in ("", "none", "any") or not rng:
            ok = True
        else:
            m = re.match(r"^(\d+)(?::(\d+))?$", rng.replace(" ", ""))
            ok = bool(m) and int(m.group(1)) <= port <= int(m.group(2) or m.group(1))
        if ok:
            hits.append(rule.get("IP Range") or rule.get("remote_ip_prefix") or rule.get("Remote Security Group") or "any")
    return hits


def icmp_allowed(rules):
    return any(str(r.get("Direction") or "").lower() == "ingress"
               and str(r.get("IP Protocol") or "").lower() in ("icmp", "", "none", "any") for r in rules)


def pool_size(subnet):
    total = 0
    for pool in subnet.get("allocation_pools") or []:
        try:
            total += int(ipaddress.ip_address(pool["end"])) - int(ipaddress.ip_address(pool["start"])) + 1
        except (KeyError, ValueError, TypeError):
            pass
    return total


def fixed_ips(port):
    value = port.get("fixed_ips") or port.get("Fixed IP Addresses") or []
    if isinstance(value, str):   # older clients: "ip_address='10.253.0.5', subnet_id='...'"
        return [{"ip_address": m.group(1), "subnet_id": m.group(2)}
                for m in re.finditer(r"ip_address='([^']+)', subnet_id='([^']+)'", value)]
    return [x for x in value if isinstance(x, dict)]


class InstanceNetwork:
    """WIs "Instance Cannot Connect (SSH, HTTPS, Ping)", "Floating IP Cannot Be Attached", "Instance Cannot
    Connect Through the Metro Network" and the alert "Custom Port TCP <SITE> <PORT> is DOWN": an instance (by ID or
    by its IP), its ports, security groups, floating IPs, subnet room, and a TCP test from the portal server."""
    sources = ("openstack", "tcp")
    phases = 5
    at = {"tcp": ["tcp"]}   # the TCP test runs from the portal server, not on OpenStack

    @staticmethod
    def reads(phase, data, params, ctx):
        instance, ip, port = params.get("instance") or "", params.get("ip") or "", int(params.get("port") or 0)
        if phase == 1:
            osc = {"osc": "openstack --version",   # client version: server migrate --live-migration since 3.19
                   "projects": "openstack project list -f json"}
            if instance:
                return {"openstack": {"server": f"openstack server show {q(instance)} -f json",
                                      "external": "openstack network list --external -f json", **osc}}
            return {"openstack": {"fip": f"openstack floating ip list --floating-ip-address {q(ip)} --long -f json",
                                  "fixed": f"openstack port list --fixed-ip ip-address={q(ip)} --long -f json",
                                  "external": "openstack network list --external -f json", **osc}}
        server = json_of(source(data, "server")) or {}
        if phase == 2:
            if server.get("id"):
                return {}
            port_id = ""
            fip = json_of(source(data, "fip")) or []
            fixed = json_of(source(data, "fixed")) or []
            if isinstance(fip, list) and fip:
                port_id = fip[0].get("Port") or ""
            elif isinstance(fixed, list) and fixed:
                port_id = fixed[0].get("ID") or ""
            return {"openstack": {"ip_port": f"openstack port show {q(port_id)} -f json"}} if UUID.match(str(port_id)) else {}
        if phase == 3:
            if not server.get("id"):
                device = (json_of(source(data, "ip_port")) or {}).get("device_id") or ""
                if not UUID.match(str(device)):
                    return {}
                return {"openstack": {"server2": f"openstack server show {q(device)} -f json",
                                      "ports": f"openstack port list --server {q(device)} -f json"}}
            return {"openstack": {"ports": f"openstack port list --server {q(server['id'])} -f json"}}
        if phase == 4:   # details of every port (security groups, network), its floating IPs and its subnets
            ports = json_of(source(data, "ports")) or []
            reads = {}
            for i, p in enumerate([p for p in ports if isinstance(p, dict)][:4]):
                pid = p.get("ID") or p.get("id")
                if not UUID.match(str(pid or "")):
                    continue
                reads[f"port_{i}"] = f"openstack port show {q(pid)} -f json"
                reads[f"pfip_{i}"] = f"openstack floating ip list --port {q(pid)} -f json"
                for f in fixed_ips(p)[:2]:
                    if UUID.match(str(f.get("subnet_id") or "")):
                        reads[f"subnet_{f['subnet_id']}"] = f"openstack subnet show {q(f['subnet_id'])} -f json"
            return {"openstack": reads} if reads else {}
        # phase 5: the rules of every security group of the ports (by ID: names like "default" exist in every
        # project), and the TCP test from the portal server
        reads, tcp = {}, {}
        groups = set()
        for k, v in (data or {}).items():
            if k.startswith("port_") and isinstance(v, dict):
                groups.update(str(g) for g in ((json_of(v) or {}).get("security_group_ids") or []) if UUID.match(str(g)))
        for gid in sorted(groups)[:8]:
            reads[f"sg_{gid}"] = f"openstack security group rule list {q(gid)} --long -f json"
            reads[f"sgname_{gid}"] = f"openstack security group show {q(gid)} -f json"
        if port and (ip or params.get("probe_ip")):
            tcp["probe"] = {"host": params.get("probe_ip") or ip, "port": port}
        return {"openstack": reads, "tcp": tcp}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("instance-network")
        names = project_names(data)
        port, ip = int(params.get("port") or 0), params.get("ip") or ""
        where = director(ctx)
        server = json_of(source(data, "server")) or json_of(source(data, "server2")) or {}
        if not server.get("id"):
            why = unavailable(source(data, "server")) if params.get("instance") else (
                f"no floating IP or fixed IP {ip} in OpenStack ({unavailable(source(data, 'fip')) or 'not found'})")
            r.step("instance", "Find the instance", "fail", f"Instance not found: {why}")
            if ip and "probe" in (data or {}):
                InstanceNetwork._probe(r, data, ip, port)
            return r.done()
        sid, sname = server.get("id"), server.get("name")
        status = str(server.get("status") or "").upper()
        power = server.get("OS-EXT-STS:power_state") or server.get("power_state") or ""
        host = server.get("OS-EXT-SRV-ATTR:host") or "-"
        project = server.get("project_id") or ""
        r.facts.update(instance=sname, instance_id=sid, compute=host)
        r.step("instance", "Instance status in Acme Flex", "ok" if status == "ACTIVE" else "fail",
               f"{sname} ({sid}) is {status}, power {power or '-'}, on compute {host}, project {pname(names, project) if project else '-'}.")
        if status == "SHUTOFF":
            r.recommend(f"{sname} is stopped: start it (with the customer's agreement), then open the console and wait for the "
                        "boot before testing again.",
                        [f"openstack server start {sid}", f"openstack server show {sid} -c status -c OS-EXT-STS:power_state",
                         f"openstack console url show {sid}"], where=where,
                        action=os_fix([f"require server {sid} status SHUTOFF", f"openstack server start {sid}",
                                       f"wait server {sid} status ACTIVE 120",
                                       f"openstack server show {sid} -c status -c OS-EXT-STS:power_state"], sname, label="Start it"))
        elif status == "ERROR":
            r.recommend(f"{sname} is in ERROR: run the check \"Instances or volumes stuck\" for the fault and the fix.")
        ports = [json_of(v) or {} for k, v in sorted((data or {}).items()) if k.startswith("port_") and isinstance(v, dict)]
        fips = []
        for k, v in sorted((data or {}).items()):
            if k.startswith("pfip_") and isinstance(v, dict):
                fips += [f for f in (json_of(v) or []) if isinstance(f, dict)]
        rows, room = [], []
        for p in ports:
            for f in fixed_ips(p):
                sub = json_of(source(data, f"subnet_{f.get('subnet_id')}")) or {}
                rows.append([p.get("name") or p.get("id"), f.get("ip_address"), sub.get("cidr") or f.get("subnet_id"),
                             p.get("status"), ", ".join(x.get("Floating IP Address", "") for x in fips if x.get("Port") == p.get("id")) or "-"])
                size = pool_size(sub)
                if size:
                    room.append((sub.get("name") or sub.get("id"), sub.get("cidr"), size))
        down = [x for x in rows if str(x[3]).upper() not in ("ACTIVE", "")]
        r.step("ports", "Network interfaces, IP addresses and floating IPs", "warn" if down or not rows else "ok",
               (f"{len(rows)} address(es)" + (f"; {len(down)} port(s) not ACTIVE" if down else "")
                + ("; no floating IP: public access needs one (VPC Simple: on the interface; VPC Expert: through the "
                   "NAT Gateway; VPC Isolated: not possible)" if not fips else "")) if rows else "No port found.",
               {"columns": ["Port", "IP address", "Subnet", "Status", "Floating IP"], "rows": rows})
        external = [n for n in (json_of(source(data, "external")) or []) if isinstance(n, dict)]
        if not fips and ports and status == "ACTIVE" and port:
            ext = external[0].get("Name") if external else "<public network>"
            r.recommend(f"{sname} has no floating IP. For a VPC Simple, create one in project {pname(names, project)} and attach it (VPC Expert: "
                        "add a DNAT on the NAT Gateway instead; VPC Isolated cannot be reached from outside).",
                        [f"FIP=$(openstack floating ip create --project {project} -f value -c floating_ip_address {q(ext)})",
                         f"openstack server add floating ip {sid} \"$FIP\"", f"openstack server show {sid} -c addresses"],
                        where=where)
        rules, missing, ids = {}, [], {}
        for k, v in (data or {}).items():
            if k.startswith("sg_") and isinstance(v, dict):
                gid = k[3:]
                name = (json_of(source(data, f"sgname_{gid}")) or {}).get("name") or gid
                ids[name] = gid
                if unavailable(v):
                    missing.append(name)
                else:
                    rules[name] = [x for x in (json_of(v) or []) if isinstance(x, dict)]
        if port:
            allowed = {name: sg_allows(rs, port) for name, rs in rules.items()}
            open_in = [f"{n} ({', '.join(map(str, a))})" for n, a in allowed.items() if a]
            r.step("security_groups", f"Security groups allow TCP {port} (ingress)", "ok" if open_in else "fail",
                   (f"Allowed by: {'; '.join(open_in)}." if open_in else
                    f"No security group of the instance allows TCP {port}: {', '.join(rules) or 'no security group'}.")
                   + (f" Not read: {', '.join(missing)}." if missing else ""),
                   {"columns": ["Security group", "Direction", "Protocol", "Port range", "Source"],
                    "rows": [[n, x.get("Direction"), x.get("IP Protocol") or "any", x.get("Port Range") or "any",
                              x.get("IP Range") or x.get("Remote Security Group") or "-"] for n, rs in rules.items() for x in rs
                             if str(x.get("Direction")).lower() == "ingress"]})
            if not open_in and rules:
                # The instance's own group (not "default", which is shared by every instance of the project) first.
                sg = next((n for n in rules if n != "default"), next(iter(rules)))
                source_cidr = "0.0.0.0/0" if ip else "<source CIDR of the client>"
                r.recommend(f"Allow TCP {port} in security group {sg} ({ids.get(sg)}) of {sname}"
                            + (" (the alert comes from UptimeRobot on the internet: 0.0.0.0/0, or only the UptimeRobot "
                               "addresses)" if ip else "") + ".",
                            [f"openstack security group rule create --ingress --ethertype IPv4 --protocol tcp --dst-port {port} "
                             f"--remote-ip {source_cidr} --description {q(f'TCP {port} for {sname}')} {ids.get(sg)}",
                             f"openstack security group rule list {ids.get(sg)} --long"], where=where,
                            warning="Open the port only to the sources that need it (least privilege); record the change in the ticket.",
                            action=os_fix([f"openstack security group rule create --ingress --ethertype IPv4 --protocol tcp "
                                           f"--dst-port {port} --remote-ip {source_cidr} --description {q(f'TCP {port} for {sname}')} "
                                           f"{ids.get(sg)}", f"openstack security group rule list {ids.get(sg)} --long"],
                                          f"security group {sg} of {sname}", label=f"Allow TCP {port}")
                            if ip and UUID.match(str(ids.get(sg) or "")) and re.match(r"^[A-Za-z0-9 _.:-]{1,64}$", f"TCP {port} for {sname}")
                            else None)
        if rules:
            icmp = any(icmp_allowed(rs) for rs in rules.values())
            r.step("icmp", "Security groups allow ping (ICMP)", "ok" if icmp else "warn",
                   "ICMP is allowed." if icmp else "No ingress ICMP rule: ping from outside will fail even when the VM is up.")
            if not icmp:
                sg = next((n for n in rules if n != "default"), next(iter(rules)))
                r.recommend(f"Allow ping to {sname} (only when the customer wants it).",
                            [f"openstack security group rule create --ingress --protocol icmp --remote-ip 0.0.0.0/0 {ids.get(sg)}"],
                            where=where,
                            action=os_fix([f"openstack security group rule create --ingress --protocol icmp --remote-ip 0.0.0.0/0 {ids.get(sg)}",
                                           f"openstack security group rule list {ids.get(sg)} --long"],
                                          f"security group {sg} of {sname}", label="Allow ping")
                            if UUID.match(str(ids.get(sg) or "")) else None)
        if room:
            r.step("subnets", "Free addresses in the subnets (VPC)", "info",
                   "; ".join(f"{n} {c}: pool of {s} addresses" for n, c, s in room))
        if "probe" in (data or {}):
            InstanceNetwork._probe(r, data, ip or params.get("probe_ip"), port)
        if status == "ACTIVE" and port:
            r.recommend(f"Inside {sname} (console in Horizon / Service Portal): check that the service listens on {port}, that the "
                        "OS firewall allows it, and that the VM reaches the internet.",
                        [f"sudo ss -lntp | grep ':{port} '",
                         "sudo systemctl list-units --type=service --state=running | head -40",
                         f"curl -sv --max-time 5 http://127.0.0.1:{port}/ -o /dev/null",
                         f"sudo iptables -S INPUT | grep -E -- '--dport {port}|REJECT|DROP'; sudo nft list ruleset 2>/dev/null | grep -E 'dport {port}|reject|drop'",
                         "ping -c 4 8.8.8.8", "ip route"],
                        where=f"console of {sname}")
        m = re.search(r"(\d+)\.(\d+)", text_of(source(data, "osc")) or "")
        live_ok = bool(m) and (int(m.group(1)), int(m.group(2))) >= (3, 19)
        if status == "ACTIVE":
            r.recommend(f"Metro does not work while VPC Simple does: move {sname} off compute {host} (with the customer); if it "
                        "works there, report compute " + host + " to the Network team (ACI path / policy for Metro).",
                        [f"openstack server migrate --live-migration {sid}",
                         f"openstack server show {sid} -c OS-EXT-SRV-ATTR:host -c status"], where=where,
                        warning="A live migration briefly pauses the VM: agree the time with the customer.",
                        action=os_fix([f"require server {sid} status ACTIVE", f"openstack server migrate --live-migration {sid}",
                                       f"wait server {sid} status ACTIVE 300",
                                       f"openstack server show {sid} -c OS-EXT-SRV-ATTR:host -c status"], sname,
                                      label="Live-migrate it") if live_ok else None)
        return r.done()

    @staticmethod
    def _probe(r, data, ip, port):
        probe = source(data, "probe")
        if probe.get("skipped"):
            r.step("tcp", f"TCP {ip}:{port} from the portal server", "skip", probe["skipped"])
            return
        ok = bool(probe.get("ok"))
        r.step("tcp", f"TCP {ip}:{port} from the portal server", "ok" if ok else "fail",
               f"Connected in {probe.get('elapsed', '?')} s." if ok else
               f"No connection: {probe.get('msg') or 'timeout'}. UptimeRobot will also see the port as DOWN.")

"""Guest LVs active on computes (check host-lvm), read-only, for one compute or every compute of the site: did the LVM of
a compute activate the LVs of a guest on its Cinder volumes, and does its LVM filter keep guest volumes off at all?

Why (a real case): on a compute whose LVM accepts every device (no global_filter, or a|.*|), the host activates the
LVs of a guest on the first iSCSI path of a volume before multipathd claims it. os-brick takes that LV for the volume's
multipath device: the domain runs on the guest's own inner LV (the guest sees its disk shifted; its LVM is not found after
a reboot, its filesystem breaks: dcbvm-mdt01, app-staging, storage-vm), or, with LVM on a partition, multipath builds
no map and the disk runs on one SCSI path (cias-development-db-01, BIGIP, 155-NMS-Nokia). An LV left on the map of a disk
makes Nova's flush of that map fail when the disk is disconnected (migration, detach, hard reboot: nfs-vm-1).
Reads, as root on each compute through the director (as the other overcloud reads): the LVM filter, every LVM LV and
multipath map of the host and the disks of its running domains (wi_ops.HOST_LVS); on the director: the instance names.
Also: the disks of running VMs left without any running path (their guests get I/O errors), a path counting only when
its device runs and multipath has it active; and iSCSI path devices in no map (left by a disconnect that did not finish:
a later connection of a LUN at that address takes the dead device instead of a new one, a real case).
Fixes (Run this fix, items ticked): disks without path scanned again from Nova's target and LUN of each (wi_ops.py
rescan-disk: only that LUN on that target's sessions, only where no device is, a new device kept only with the map's
WWID), guest LVs released (release-lv: read again and checked on the compute, only the host's mapping removed, nothing
written to the volume, each freed path back to its map), leftover multipath maps flushed (flush-map) and dead path
devices in no map deleted (delete-path: read again, only when no read of it answers). An LV a running instance uses as its disk is never released while it runs: stop the instance first.
The portal's live migration does the same for the instance it moves (before: its source; after: its destination).
"""
import re
import shlex

from . import lun_guard, overcloud, wi_ops
from .common import Result, director, json_of, source, unavailable
from .openstack import UUID, os_select
from .openstack_ops import HOST, node_of, short
from .overcloud_checks import inventory

q = shlex.quote
MAX_COMPUTES = 40   # computes read in one run (in parallel, each once)
FILTER_HINT = ("TripleO parameter LVMFilterEnabled: true (with LVMFilterAllowlist for the host's own disks), or "
               "global_filter = [ \"a|<host disks>|\", \"r|.*|\" ] in /etc/lvm/lvm.conf; check first whether the host's own "
               "root uses LVM")


def filter_safe(seen):
    """Does the LVM of the compute keep guest volumes off: its global_filter rejects every device it does not name, or it
    uses an LVM devices file."""
    value, present = seen["devicesfile"]
    return bool(wi_ops.LVM_REJECT_ALL.search(seen["filter"] or "")) or (value == "1" and present == "present")


def under(x):
    """What an LV sits on, in words."""
    parts = []
    for kind, dev, disk, wwid in x["on"]:
        if kind == "map":
            parts.append(f"map {disk}" + (f" (partition {dev})" if dev != disk else ""))
        elif kind == "path":
            parts.append(f"{'partition ' + dev + ' of ' if dev != disk else ''}path {disk}" + (f" ({wwid})" if wwid else ""))
        elif kind == "gone":
            parts.append(f"{dev} (removed)")
    return ", ".join(parts) or "nothing (its devices are gone)"


class HostLvm:
    sources = ("openstack", "undercloud", "overcloud", "ontap")
    phases = 2
    at = {"lun_copies": ["overcloud", "ontap"]}   # the LUN copy guard (lun_guard.py)

    @staticmethod
    def targets(data, params, ctx):
        """(computes to read, user, problem, how many computes there are)."""
        found, _controllers, user, _version, problem = inventory(data, ctx)
        want = str(params.get("compute") or "").strip()
        if not found:
            return [], user, problem, 0
        if want:
            node = node_of(want, found)
            if not node:
                return [], user, f"{want} is not in the overcloud node list of the undercloud (the name as in openstack compute service list).", 0
            return [node], user, "", 1
        computes = [n for n in found if n["role"] == "compute"]
        return computes[:MAX_COMPUTES], user, "" if computes else "No compute in the overcloud node list.", len(computes)

    @staticmethod
    def reads(phase, data, params, ctx):
        return lun_guard.merge(HostLvm.own_reads(phase, data, params, ctx), lun_guard.reads(phase, data, ctx))

    @staticmethod
    def own_reads(phase, data, params, ctx):
        want = str(params.get("compute") or "").strip()
        if want and not HOST.match(want):
            return {}
        if phase == 1:
            listing = "openstack server list --all-projects -f json -c ID -c Name" + (f" --host {q(want)}" if want else "")
            return {"openstack": {"servers": listing}, "undercloud": dict(overcloud.INVENTORY_READS)}
        targets, user, problem, _total = HostLvm.targets(data, params, ctx)
        if problem or not targets or user not in overcloud.USERS:
            return {}
        return {"overcloud": {f"use_hl_{i}": overcloud.read(n["name"], n["ip"], user, "hl_lvm") for i, n in enumerate(targets)}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("host-lvm")
        guard = lun_guard.index(data, ctx)   # a VM to move whose volume's LUN has a FlexClone copy: checked first
        targets, user, problem, total = HostLvm.targets(data, params, ctx)
        if problem or not targets:
            r.step("computes", "The computes and their LVM filter", "fail", problem or "No compute to read.")
            return r.done()
        if user not in overcloud.USERS:
            r.step("computes", "The computes and their LVM filter", "fail", "No overcloud user (heat-admin / tripleo-admin).")
            return r.done()
        names = {}
        for s in json_of(source(data, "servers")) or []:
            if isinstance(s, dict) and UUID.match(str(s.get("ID") or s.get("id") or "")):
                names[str(s.get("ID") or s.get("id"))] = str(s.get("Name") or s.get("name") or "")

        rows, unread, unsafe, nodes = [], [], [], []
        for i, n in enumerate(targets):
            item = source(data, f"use_hl_{i}")
            out = "" if unavailable(item) else str(item.get("out") or "")
            if unavailable(item) or "@@domains" not in out:
                unread.append(n["name"])
                rows.append([n["name"], n["ip"], (unavailable(item) or "no answer")[:120], "-", "-", "-", "-"])
                continue
            seen = wi_ops.parse_host_lvs(out)
            lvs = wi_ops.guest_lvs(seen)
            safe = filter_safe(seen)
            if not safe:
                unsafe.append(n["name"])
            nodes.append((n, seen, lvs))
            rows.append([n["name"], n["ip"], "read", seen["filter"] or "not set (accepts every device)",
                         " ".join(seen["devicesfile"]).strip() or "-", "yes" if safe else "NO", len(lvs)])
        r.step("computes", "The computes and their LVM filter",
               "fail" if len(unread) == len(targets) else "warn" if unread or unsafe else "ok",
               f"{len(targets) - len(unread)} of {len(targets)} compute(s) read as {user}"
               + (f" (only the first {len(targets)} of {total}: name one compute to read another)" if total > len(targets) else "") + ". "
               + (f"The LVM of {len(unsafe)} compute(s) accepts guest volumes ({', '.join(short(x) for x in unsafe)}): they can "
                  "activate the LVs of a guest whose volume is connected there (a live migration, an attach, a start)."
                  if unsafe else "Every compute read keeps guest volumes off (global_filter r|.*| or an LVM devices file)."),
               {"columns": ["Compute", "ctlplane", "Read", "LVM global_filter", "Devices file", "Keeps guest volumes off", "Guest LVs"],
                "rows": rows}, marks=unread + unsafe)

        def who(seen, dom):
            uuid = seen["domains"].get(dom, "")
            return (f"{names[uuid]} ({dom})" if uuid in names else dom), uuid

        runs, on_disk, left, busy, maps, raw, lost, loose, alive = [], [], [], [], [], [], [], [], []
        for n, seen, lvs in nodes:
            for dm, m in sorted(seen["maps"].items(), key=lambda x: int(x[0][3:])):
                if m["running"] == 0 and dm in seen["disks"]:
                    lost += [(n, dm, m, who(seen, dom), t) for dom, t in seen["disks"][dm]]
            for x in lvs:
                users = [(who(seen, dom), t) for dom, t in x["users"]]
                if x["kind"] == "runs-on":
                    runs += [(n, x, inst, uuid, t) for (inst, uuid), t in users]
                elif x["kind"] == "busy":
                    busy.append((n, x, users))
                elif x["kind"] == "disk":
                    on_disk.append((n, x, users))
                else:
                    left.append((n, x))
            maps += [(n, dm, wwid) for dm, wwid in wi_ops.dead_maps(seen)]
            for sd, addr, wwid, st, rd in wi_ops.loose_paths(seen):
                # a device that answers a read is a LUN still mapped to this compute, not a dead path: never offered for a
                # delete (DCA ha-0 sdhh / sdhi, LUN 58: the delete refused them, rightly, in fix #118)
                if rd == "ok":
                    alive.append((n, sd, addr, wwid, st))
                else:
                    loose.append((n, sd, addr, wwid, st + (", no answer to a read" if rd == "none" else ", read failed" if rd else "")))
            for dev, users in sorted(seen["disks"].items()):
                if re.match(r"^sd[a-z]+$", dev):
                    raw += [(n, who(seen, dom), t, dev) for dom, t in users]

        r.step("runs-on", "VMs running on a guest LV (critical)", "fail" if runs else "ok",
               (f"CRITICAL: {len(runs)} disk(s) of running VMs are an LV of the guest that the compute activated, not the "
                "volume's multipath map: the guest sees its own inner LV as that disk, shifted, and writes through it. Its "
                "LVM is not found after a reboot, its filesystem breaks; detach, hard reboot and start fail at multipath -f. "
                "Stop the VM (its owner agrees), release the LV, start it." if runs else
                "No running VM uses a guest LV as its disk."),
               {"columns": ["Instance", "UUID", "Compute", "Disk", "LV", "Under it"],
                "rows": [[inst, uuid or "-", short(n["name"]), t, f"{x['dm']} {x['name']}", under(x)] for n, x, inst, uuid, t in runs]},
               marks=[x["dm"] for _n, x, _i, _u, _t in runs])
        r.step("no-path", "Disks of running VMs without any path", "fail" if lost else "ok",
               (f"CRITICAL: {len(lost)} disk(s) of running VMs have no running path: their guests get I/O errors on every "
                "read and write, and their filesystems may be read-only or shut down by now. The paths can be scanned again "
                "from Nova's target and LUN of each disk (the fix below), also when the kernel log no longer has their removal."
                if lost else "Every disk of the running VMs read has at least one running path."),
               {"columns": ["Instance", "UUID", "Compute", "Disk", "Device", "WWID", "Path devices"],
                "rows": [[inst, uuid or "-", short(n["name"]), t, dm, m["wwid"], f"{m['total']} (none running)"]
                         for n, dm, m, (inst, uuid), t in lost]},
               marks=[m["wwid"] for _n, _d, m, _w, _t in lost])
        r.step("on-disks", "Guest LVs on the disks of running VMs", "warn" if on_disk else "ok",
               (f"{len(on_disk)} LV(s) of guests sit on the map, a path or a partition of a disk of a running VM. The VM keeps "
                "running on its map, but Nova cannot flush that map when the disk is disconnected (live migration, detach, "
                "hard reboot), and the LV holds a path the map should have. Release them: only the host's mapping goes, the "
                "VM keeps running, nothing is written to the volume. (The portal's live migration releases them by itself "
                "for the instance it moves.)" if on_disk else "No guest LV sits on a disk of a running VM."),
               {"columns": ["Compute", "Instance", "Disk", "LV", "Under it"],
                "rows": [[short(n["name"]), ", ".join(i for (i, _u), _t in users), ", ".join(dict.fromkeys(t for _w, t in users)),
                          f"{x['dm']} {x['name']}", under(x)] for n, x, users in on_disk]},
               marks=[x["dm"] for _n, x, _u in on_disk])
        r.step("one-path", "Disks of running VMs on one SCSI path", "warn" if raw else "ok",
               (f"{len(raw)} disk(s) of running VMs run on a single SCSI device without a multipath map (LVM of the compute "
                "on a partition of it when multipath came, or a second path never found): one more path failure and the "
                "guest gets I/O errors. A live migration to a compute whose LVM keeps guest volumes off connects them on a "
                "map again." if raw else "Every disk of the running VMs read is on a multipath map."),
               {"columns": ["Compute", "Instance", "Disk", "Device"],
                "rows": [[short(n["name"]), inst, t, dev] for n, (inst, _u), t, dev in raw]}, marks=[dev for _n, _w, _t, dev in raw])
        r.step("leftover", "Leftover guest LVs, multipath maps and path devices", "warn" if left or busy or maps or loose or alive else "ok",
               (f"{len(left)} guest LV(s) on nothing a running VM uses (a volume no longer used on that compute, a removed "
                f"device), {len(busy)} guest LV(s) opened or held on the host, {len(maps)} multipath map(s) without a running "
                f"path that nothing uses, {len(loose)} iSCSI path device(s) in no map. They make the next connection of "
                "those volumes on that compute fail or pick the LV; a LUN connected later at the address of a dead path "
                "device runs on that dead device (a live migration to that compute hangs, its VM cannot start there)."
                + (f" Also {len(alive)} working iSCSI device(s) in no map: a LUN still mapped to that compute that no map and "
                   "no VM uses (not a dead path, nothing to delete on the compute)." if alive else "")
                if left or busy or maps or loose or alive else "No leftover guest LV, multipath map or path device."),
               {"columns": ["Compute", "Device", "What", "Under it / WWID"],
                "rows": [[short(n["name"]), f"{x['dm']} {x['name']}", "guest LV, nothing uses it", under(x)] for n, x in left]
                + [[short(n["name"]), f"{x['dm']} {x['name']}", f"guest LV {x['why']}", under(x)] for n, x, _u in busy]
                + [[short(n["name"]), dm, "multipath map without a running path", wwid] for n, dm, wwid in maps]
                + [[short(n["name"]), sd, f"iSCSI path device in no map ({addr}, {st})", wwid or "-"] for n, sd, addr, wwid, st in loose]
                + [[short(n["name"]), sd, f"working iSCSI device in no map, LUN still mapped here ({addr}, {st})", wwid or "-"]
                   for n, sd, addr, wwid, st in alive]},
               marks=[x["dm"] for _n, x in left] + [dm for _n, dm, _w in maps] + [sd for _n, sd, _a, _w, _s in loose])

        # ---- how to fix it
        where = director(ctx)
        login = lambda n: f"node {n['name']}={n['ip']} user {user}"   # noqa: E731
        if runs:
            r.recommend("Stop each VM that runs on a guest LV (its owner agrees first), release the LV with this check (run it "
                        "again once the VM is shut off: the LV is offered then), and start the VM: Nova connects the volume "
                        "on its multipath map again. Then the owner checks the guest's filesystems (fsck) and LVM.",
                        [f"openstack server stop {uuid}" for _n, _x, _i, uuid, _t in runs if uuid][:6]
                        + [f"openstack server start {uuid}   # after the release" for _n, _x, _i, uuid, _t in runs if uuid][:6],
                        warning="Never live-migrate, detach or hard-reboot such a VM before: the portal refuses its live "
                                "migration, and a detach or hard reboot fails at multipath -f on the LV.",
                        where=where, refs=["host-lvm"],
                        items={"columns": ["Instance", "Compute", "Disk", "LV"],
                               "rows": [[inst, short(n["name"]), t, f"{x['dm']} {x['name']}"] for n, x, inst, _u, t in runs]})
        if lost:
            items = [{"label": f"{inst} {t} ({short(n['name'])} {dm}, {m['wwid']})",
                      "commands": [f"rescan-disk {uuid} wwid {m['wwid']} {login(n)}"]
                      if UUID.match(uuid or "") and wi_ops.WWID_RE.match(m["wwid"]) and not m["total"] else [],
                      "default": True,
                      "disabled": "" if UUID.match(uuid or "") and wi_ops.WWID_RE.match(m["wwid"]) and not m["total"] else
                      ("its path devices are there but not running: a session or storage problem, a scan does not help"
                       if m["total"] else "no instance UUID or WWID")}
                     for n, dm, m, (inst, uuid), t in lost]
            r.recommend("Give the disks without any path their paths back: for each, the portal reads the map again, reads "
                        "Nova's target and LUN of that disk on a controller, scans only that LUN on the sessions of that "
                        "target and only where no device is now (a device there is never touched), keeps a new device only "
                        "with the WWID of the map, deletes it again otherwise, and reads the map again. Then the owner of each "
                        "VM checks its filesystem.",
                        [f"multipath -ll {m['wwid']}   # on {short(n['name'])}: no running path" for n, _dm, m, _w, _t in lost[:6]],
                        warning="The guest of each VM may already have I/O errors or a read-only / shut-down filesystem: its "
                                "owner checks it. Reboot a VM only after the check \"Volume connections of an instance\" is clean "
                                "for it (a hard reboot with a stale connection info disconnects the disk of yet another VM).",
                        where="each compute, as root (from the director); Nova's connection on a controller", refs=["host-lvm", "compute-disks"],
                        items={"columns": ["Instance", "Disk", "Compute", "Device", "WWID"],
                               "rows": [[inst, t, short(n["name"]), dm, m["wwid"]] for n, dm, m, (inst, _u), t in lost]},
                        action=os_select(items, target=", ".join(sorted({short(n["name"]) for n, _d, _m, _w, _t in lost})),
                                         label="Re-scan the disks without path", noun="disks", lock="host-lvm",
                                         stop_on_failure=False, item_timeout=600, max_items=100))
        if on_disk or left or busy:
            items = []
            for n, x, users in on_disk:
                items.append({"label": f"{short(n['name'])} {x['dm']} {x['name']} (on {', '.join(dict.fromkeys(t for _w, t in users))} of "
                                       f"{', '.join(dict.fromkeys(i for (i, _u), _t in users))})",
                              "commands": [f"release-lv {x['uuid']} {login(n)}"] if wi_ops.LV_UUID_RE.match(x["uuid"]) else [],
                              "default": True, "disabled": "" if wi_ops.LV_UUID_RE.match(x["uuid"]) else "unusual LV UUID: release it by hand"})
            for n, x in left:
                items.append({"label": f"{short(n['name'])} {x['dm']} {x['name']} (leftover, on {under(x)})",
                              "commands": [f"release-lv {x['uuid']} {login(n)}"] if wi_ops.LV_UUID_RE.match(x["uuid"]) else [],
                              "default": True, "disabled": "" if wi_ops.LV_UUID_RE.match(x["uuid"]) else "unusual LV UUID: release it by hand"})
            for n, x, _u in busy:
                items.append({"label": f"{short(n['name'])} {x['dm']} {x['name']}", "commands": [], "default": False,
                              "disabled": f"{x['why']}: find what uses it first"})
            r.recommend("Release the guest LVs the computes activated: each is read again on its compute (opened 0 times, held "
                        "by nothing, no disk of a running VM, only on iSCSI devices), removed from the host (dmsetup remove: "
                        "only the host's mapping, nothing is written to the volume), and each freed path goes back to the map "
                        "of its WWID. The VMs keep running. Run the check again afterwards: maps left without a path are offered "
                        "then.",
                        [f"dmsetup info -c {x['name']}   # on {short(n['name'])}, as root" for n, x, _u in on_disk[:3]]
                        + [f"dmsetup remove {x['name']}   # by hand, only when opened 0 times" for n, x, _u in on_disk[:2]],
                        warning="A disk on one SCSI path stays so after its LV is released: move that VM to a compute whose "
                                "LVM keeps guest volumes off. An LV comes back on a compute without an LVM filter whenever a "
                                "volume is connected there again: run this check before each batch of migrations to it.",
                        where="each compute, as root (from the director)", refs=["host-lvm"],
                        items={"columns": ["Compute", "LV", "On"],
                               "rows": [[short(n["name"]), f"{x['dm']} {x['name']}", under(x)] for n, x, _u in on_disk]
                               + [[short(n["name"]), f"{x['dm']} {x['name']}", under(x)] for n, x in left]},
                        action=os_select(items, target=", ".join(sorted({short(n["name"]) for n, _x, _u in on_disk} | {short(n["name"]) for n, _x in left})),
                                         label="Release the guest LVs", noun="LVs", lock="host-lvm", stop_on_failure=False,
                                         item_timeout=300, max_items=200))
        if maps:
            items = [{"label": f"{short(n['name'])} {dm} ({wwid})", "commands": [f"flush-map {wwid} {login(n)}"], "default": True,
                      "disabled": ""} for n, dm, wwid in maps]
            r.recommend("Flush the multipath maps left without a running path that nothing uses: each is read again on its "
                        "compute (no running path, opened 0 times, held by nothing, no disk of a running VM), then multipath -f.",
                        [f"multipath -ll {wwid}   # on {short(n['name'])}: no path" for n, _dm, wwid in maps[:4]],
                        where="each compute, as root (from the director)", refs=["host-lvm", "compute-disks"],
                        items={"columns": ["Compute", "Map", "WWID"], "rows": [[short(n["name"]), dm, wwid] for n, dm, wwid in maps]},
                        action=os_select(items, target=", ".join(sorted({short(n["name"]) for n, _d, _w in maps})),
                                         label="Flush the leftover maps", noun="maps", lock="host-lvm", stop_on_failure=False,
                                         item_timeout=300, max_items=200))
        if loose:
            items = [{"label": f"{short(n['name'])} {sd} ({addr}{', ' + wwid if wwid else ''})",
                      "commands": [f"delete-path {sd} addr {addr} wwid {wwid or '-'} {login(n)}"], "default": True, "disabled": ""}
                     for n, sd, addr, wwid, _st in loose]
            r.recommend("Delete the iSCSI path devices left in no map: each is read again on its compute (still that SCSI "
                        "address and WWID, held by nothing, open by no process, not mounted, no disk of a domain, also a "
                        "paused one; read again 20 s later), and deleted (echo 1 > device/delete, as os-brick does on a "
                        "disconnect) only when a read of its first block does not answer: a working device is left. The "
                        "iSCSI session stays; nothing is written to the LUN. The next connection at that address then gets "
                        "a new device.",
                        [f"cat /sys/block/{sd}/device/state; multipath -ll | grep -w {sd}   # on {short(n['name'])}"
                         for n, sd, _a, _w, _s in loose[:4]],
                        warning="Run it when no live migration, attach or start goes to that compute at the same time.",
                        where="each compute, as root (from the director)", refs=["host-lvm", "compute-disks"],
                        items={"columns": ["Compute", "Device", "SCSI address", "State", "WWID"],
                               "rows": [[short(n["name"]), sd, addr, st, wwid or "-"] for n, sd, addr, wwid, st in loose]},
                        action=os_select(items, target=", ".join(sorted({short(n["name"]) for n, _s, _a, _w, _t in loose})),
                                         label="Delete the dead path devices", noun="path devices", lock="host-lvm",
                                         stop_on_failure=False, item_timeout=300, max_items=200))
        if alive:
            serials = sorted({w[len("3600a0980"):] for _n, _s, _a, w, _t in alive if w.startswith("3600a0980")})
            r.recommend("Find the volume of each LUN still mapped to a compute that nothing there uses. The devices answer "
                        "reads, so they are no dead paths and nothing is deleted on the compute (a rescan would bring them "
                        "back while the LUN stays mapped). Look the LUN up on the storage by its serial (the WWID without "
                        "3600a0980): when its volume is attached on another compute or deleted, the mapping to this compute is "
                        "a leftover of a disconnect that did not finish there, and is removed on the storage with a change "
                        "approval; when its volume is attached here, check that instance.",
                        [f"lun show -serial-hex {x} -fields path,mapped   # ONTAP: the LUN of that WWID" for x in serials[:4]]
                        + [f"lun mapped show -path <path above>   # ONTAP: the igroups it is mapped to" ] if serials else [],
                        where="the ONTAP cluster of the backend (read-only commands)", refs=["host-lvm"],
                        items={"columns": ["Compute", "Device", "SCSI address", "WWID"],
                               "rows": [[short(n["name"]), sd, addr, wwid or "-"] for n, sd, addr, wwid, _st in alive]})
        if raw:
            held = [uuid for _n, (_i, uuid), _t, _d in raw if uuid and lun_guard.reason_for_instance(guard, uuid)]
            r.recommend("Move each VM with a disk on one SCSI path to a compute whose LVM keeps guest volumes off (name it as "
                        "the destination of the live migration): the disk is connected on a multipath map there.",
                        [f"openstack server migrate --live-migration {uuid}   # with a destination of this check marked yes"
                         for _n, (_i, uuid), _t, _d in raw if uuid][:4],
                        where=where, refs=["host-lvm"],
                        warning=(f"{', '.join(held[:4])}: a LUN of its volumes is also in another FlexVol (a FlexClone "
                                 "copy) or cannot be checked: check lun-map-audit before moving it." if held else ""))
            lun_guard.step(r, guard)
        if unsafe:
            r.recommend(f"Set an LVM filter on {', '.join(short(x) for x in unsafe)} so that the host never activates the LVs "
                        "of guest volumes (a change of the compute's configuration: plan it in a maintenance window).",
                        ["lvmconfig --type full devices/global_filter   # on each compute: what it is now", FILTER_HINT],
                        warning="Until then, the portal's live migration moves a VM with LVM on its disks only to computes "
                                "marked yes here, and releases guest LVs before and after each migration.",
                        where="each compute (TripleO: the overcloud templates)", refs=["host-lvm"])
        return r.done()

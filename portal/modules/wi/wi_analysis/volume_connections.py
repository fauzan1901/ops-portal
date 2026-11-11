"""Volume connections of an instance (check volume-connections), read-only: are the volumes of one instance connected
where it runs, and is anything left over that makes its next reboot or migration hit another instance's disk?

What a failed live migration can leave (a real case; Red Hat 7138031, Platform9 "iSCSI BDM corruption"):
  - a second Cinder attachment of a volume that is not multiattach: the next migration, unshelve or attachment update is
    refused ("duplicate connectors"), a cold migration then leaves the instance in ERROR;
  - Nova's block device mapping (BDM) pointing at the attachment and the LUN number of another host: NetApp numbers LUNs per
    host, so on the instance's compute that number can be ANOTHER instance's disk. A hard reboot, start, delete, rebuild or
    migration first disconnects the volume with that info (os-brick flushes the device): the other instance gets I/O
    errors and remounts its filesystem read-only;
  - a port still bound with "migrating_to";
  - libvirt unable to take the job of the domain (a reconnect of virtqemud that never ended): every migration fails;
  - a volume Nova keeps that Cinder no longer has by its ID, while the domain runs on another volume (vm-c3,
    2026-11-02: a Cinder volume migration that never completed; its target, named after the volume, is the disk; Nova's
    stored connection names a LUN that is not that disk). Every Nova action on its volumes fails (HTTP 404), the
    instance page in Horizon fails, and a stop / start or hard reboot connects the LUN Nova keeps.
Reads: the instance and its ports (director), Nova's BDM, Cinder's attachments and every Cinder row naming its volumes
(SELECT on the galera container of a controller, never the connection_info itself: it holds the CHAP secret), the
domain and the device of each LUN on its compute (with the LUN numbers of the disks' paths and the compute's initiator),
on NetApp (when the site has ONTAP): the LUN the compute's igroup maps at the LUN numbers of each disk's paths (read by
its UUID, its serial compared with the disk's; a search of every LUN by serial took over 60 s in production) and
what it maps at the LUN numbers Nova keeps, and the nova-compute lines of the last 24 hours about migrations and volume
connections.
"""
import json
import re
import shlex
import urllib.parse

from . import overcloud
from .common import Result, director, json_of, source, unavailable
from .openstack import UUID
from .openstack_ops import node_of, short
from .overcloud_checks import inventory

q = shlex.quote
MAX_VOLUMES = 8
MAX_PORTS = 8
LOG_HOURS = 24
POWER = {"0": "no state", "1": "running", "3": "paused", "4": "shut down", "6": "crashed", "7": "suspended"}
LOCK = re.compile(r"cannot acquire state change lock", re.I)
NOT_DEFINED = re.compile(r"failed to get domain|Domain not found|no domain with matching", re.I)


def power(value):
    """Nova's power state as a word (python-openstackclient 4 gives the number, 5 the name)."""
    text = str(value if value is not None else "").strip()
    return POWER.get(text, text.lower().replace("nostate", "no state").replace("shutdown", "shut down") or "?")


def instance_of(data):
    s = json_of(source(data, "srv"))
    return s if isinstance(s, dict) else {}


def port_ids(data):
    out = []
    for p in json_of(source(data, "ports")) or []:
        pid = str((p or {}).get("ID") or (p or {}).get("id") or "") if isinstance(p, dict) else ""
        if UUID.match(pid) and pid not in out:
            out.append(pid)
    return out[:MAX_PORTS]


def attached_ids(server):
    """Volume IDs of the instance as server show gives them (a list of {"id"} on client 5, text on client 4)."""
    return list(dict.fromkeys(re.findall(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                                         json.dumps(server.get("volumes_attached") or ""))))[:MAX_VOLUMES]


def db_rows(data):
    """{"bdm": [...], "att": [...], "mig": [...], "vol": [...]} from the vc_db read (tab separated rows tagged by their
    first field)."""
    out = {"bdm": [], "att": [], "mig": [], "vol": []}
    item = source(data, "db")
    if unavailable(item):
        return out
    for line in str(item.get("out") or "").splitlines():
        f = line.split("\t")
        if f[0] == "bdm" and len(f) >= 9:
            lun = f[6] if f[6].isdigit() else ""
            out["bdm"].append({"volume": f[1], "attachment": f[2], "device": f[3], "type": f[4], "iqn": f[5], "lun": lun,
                               "luns": f[7], "path": f[8]})
        elif f[0] == "att" and len(f) >= 8:
            out["att"].append({"volume": f[1], "id": f[2], "status": f[3].lower(), "host": f[4], "connector": f[5],
                               "connected": f[6] == "1", "server": f[7]})
        elif f[0] == "mig" and len(f) >= 7:
            out["mig"].append({"id": f[1], "type": f[2], "status": f[3].lower(), "source": f[4], "dest": f[5], "created": f[6]})
        elif f[0] == "vol" and len(f) >= 11:
            out["vol"].append({"id": f[1], "deleted": f[2] not in ("0", ""), "deleted_at": f[3], "name_id": f[4], "name": f[5],
                               "status": f[6].lower(), "attach": f[7].lower(), "migstat": f[8], "host": f[9], "updated": f[10]})
    return out


def domain_of(data):
    """{"state", "uuid", "disks": {target: {"source", "dm", "wwid", "luns"}}, "job", "initiator"} from the vc_domain
    read (luns: the LUN numbers of the paths of the disk)."""
    out = {"state": "", "uuid": "", "disks": {}, "job": "", "initiator": ""}
    for line in str(source(data, "dom").get("out") or "").splitlines():
        if line.startswith("@@state "):
            out["state"] = line[8:].strip()
        elif line.startswith("@@uuid "):
            out["uuid"] = line[7:].strip()
        elif line.startswith("@@job "):
            out["job"] = line[6:].strip()
        elif line.startswith("@@initiator "):
            out["initiator"] = line[12:].strip() if IQN.match(line[12:].strip()) else ""
        elif line.startswith("@@disk "):
            f = line.split()
            if len(f) >= 5:
                out["disks"][f[1]] = {"source": f[2], "dm": f[3], "wwid": f[4],
                                      "luns": [x for x in (f[5] if len(f) >= 6 else "").split(",") if x.isdigit()]}
    return out


IQN = re.compile(r"^iqn\.\d{4}-\d{2}\.[A-Za-z0-9.:_-]{1,200}$")
NETAPP_NAA = "3600a0980"   # NAA of a NetApp LUN: 3 + 600a0980 (OUI) + the hex of its 12 character serial


def netapp_serial(wwid):
    """The serial of a NetApp LUN from its multipath WWID (lun show -serial), '' for any other device."""
    w = str(wwid or "")
    if not w.startswith(NETAPP_NAA) or len(w) != len(NETAPP_NAA) + 24:
        return ""
    try:
        return bytes.fromhex(w[len(NETAPP_NAA):]).decode("ascii")
    except ValueError:
        return ""


def q_ontap(value):
    """A value in an ONTAP query: every character but letters and digits percent-encoded (ONTAP reads * | ! as operators;
    the answer is compared exactly)."""
    return "".join(c if c.isalnum() else "%%%02X" % ord(c) for c in str(value))


def records(data, key):
    item = source(data, key)
    if unavailable(item):
        return None
    doc = json_of(item)
    return doc.get("records") or [] if isinstance(doc, dict) else None


def one(data, key):
    """The object of an ONTAP read by its UUID (GET /api/storage/luns/<uuid>), None when it was not read."""
    item = source(data, key)
    if unavailable(item):
        return None
    doc = json_of(item)
    return doc if isinstance(doc, dict) and doc.get("name") else None


def netapp_disks(dom):
    """The disks of the domain on NetApp LUNs whose LUN numbers on the compute are known."""
    return [d for d in list(dom["disks"].values())[:MAX_VOLUMES]
            if netapp_serial(d.get("wwid")) and re.match(r"^dm-\d+$", d["dm"]) and d["luns"]]


def lun_uuid(path):
    """The Cinder volume (ID or name_id) a NetApp LUN path is named after: /vol/<flexvol>/volume-<uuid>."""
    m = re.search(r"/volume-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$", str(path or ""))
    return m.group(1) if m else ""


def lun_of(data, lun, iqn):
    """({dm: wwid} of the devices of LUN lun of target iqn on the compute, [(domain, uuid, dm)] of every domain disk)."""
    devices, users = {}, []
    for line in str(source(data, f"lun_{lun}").get("out") or "").splitlines():
        f = line.split()
        if line.startswith("@@path ") and len(f) >= 5 and f"-{iqn}-lun-{lun}" in f[1] and f[3] != "-":
            devices[f[3]] = f[4]
        elif line.startswith("@@use ") and len(f) >= 4:
            users.append((f[1], f[2], f[3].rsplit("/", 1)[-1]))
    return devices, users


def same_host(a, b):
    return bool(a) and bool(b) and short(a) == short(b)


def volume_facts(data, rows, sid, host, dom):
    """For each volume Nova keeps (BDM): is it in Cinder by its ID (the API answers its ID, not another volume found by
    name), the Cinder rows naming it, the disk the domain runs on for its device (dm, WWID, LUN numbers of its paths),
    the NetApp LUN of that disk (the one the compute's igroup maps at those LUN numbers whose serial is the disk's) and
    the Cinder volume that LUN is named after, and what the compute's igroup maps at the LUN number Nova keeps. [{...}]
    in the order of the BDM."""
    groups = records(data, "na_igroup")
    out = []
    for b in rows["bdm"][:MAX_VOLUMES]:
        v = b["volume"]
        f = {"volume": v, "device": b["device"], "lun": b["lun"], "api": "unknown", "api_text": "", "row": None, "named": [],
             "disk": {}, "serial": "", "na": None, "na_text": "", "runs_on": "", "runs_row": None, "runs_att": None,
             "map": None, "missing": False, "igroup": "", "mismatch": False}
        item = source(data, f"vol_{v}")
        vol = json_of(item)
        if isinstance(vol, dict) and vol.get("id"):
            f["api"] = "id" if vol["id"] == v else "name"
            f["api_text"] = "" if vol["id"] == v else (f"{vol['id']} ({str(vol.get('status') or '?').lower()}, migration "
                                                         f"{vol.get('migration_status') or vol.get('os-vol-mig-status-attr:migstat') or 'none'})")
        elif re.search(r"No volume with a name or ID|could not be found|\(HTTP 404\)", str((item or {}).get("out") or ""), re.I):
            f["api"] = "gone"
        own = [x for x in rows["vol"] if x["id"] == v]
        f["row"] = own[0] if own else None
        f["named"] = [x for x in rows["vol"] if x["id"] != v and not x["deleted"]
                      and (x["name"] == v or x["migstat"] == f"target:{v}" or x["name_id"] == v)]
        f["missing"] = f["api"] in ("name", "gone") or bool(f["row"] and f["row"]["deleted"])
        f["disk"] = dom["disks"].get(b["device"].rsplit("/", 1)[-1]) or {}
        f["serial"] = netapp_serial(f["disk"].get("wwid"))
        if f["serial"] and f["disk"].get("dm"):
            dm, at = f["disk"]["dm"], ",".join(f["disk"].get("luns") or [])
            maps = records(data, f"na_dmap_{dm}")
            luns = [one(data, f"na_lun_{dm}_{i}") for i in range(len((maps or [])[:4]))]
            exact = [x for x in luns if x and str(x.get("serial_number") or "") == f["serial"]]
            if exact:
                f["na"] = exact[0]
                f["na_text"] = str(exact[0]["name"])
            elif maps == []:
                f["na"], f["mismatch"] = {}, True
                f["na_text"] = f"nothing mapped at LUN {at} (igroup {', '.join(str(g.get('name')) for g in groups or [])})"
            elif maps and any(luns):
                f["na"], f["mismatch"] = {}, True
                f["na_text"] = (f"no LUN with serial {f['serial']} at LUN {at}: mapped there "
                                + ", ".join(str(x["name"]) for x in luns if x))
            else:
                why = ("the LUN numbers of its paths are not known" if not at else
                       "the compute's initiator was not read" if not dom["initiator"] else
                       unavailable(source(data, "na_igroup")) if groups is None else
                       "NetApp has no igroup with the compute's initiator" if not groups else
                       unavailable(source(data, f"na_dmap_{dm}")) if maps is None else
                       unavailable(source(data, f"na_lun_{dm}_0")))
                f["na_text"] = f"not read ({why})" if why else "not read"
            if exact:
                u = lun_uuid(f["na_text"])
                live = [x for x in rows["vol"] if not x["deleted"] and u and (x["name_id"] or x["id"]) == u]
                f["runs_on"] = live[0]["id"] if live else u
                f["runs_row"] = live[0] if live else None
                f["runs_att"] = next((a for a in rows["att"] if a["volume"] == f["runs_on"] and a["server"] == sid), None)
        if groups is not None and groups and b["lun"]:
            f["igroup"] = ", ".join(str(g.get("name") or "?") for g in groups[:2])
            maps = records(data, f"na_map_{b['lun']}")
            f["map"] = None if maps is None else ", ".join(str((m.get("lun") or {}).get("name") or "?") for m in maps) or ""
        out.append(f)
    return out


class VolumeConnections:
    sources = ("openstack", "undercloud", "overcloud", "ontap")
    phases = 5

    @staticmethod
    def nodes(data, ctx):
        """(compute node of the instance, first controller, user, problem) from the undercloud reads of phase 1."""
        found, controllers, user, _version, problem = inventory(data, ctx)
        host = str(instance_of(data).get("OS-EXT-SRV-ATTR:host") or "")
        node = node_of(host, found) if host else None
        ctl = next((c for c in controllers if c.get("ip")), None)
        return node, ctl, user, problem, found

    @staticmethod
    def reads(phase, data, params, ctx):
        sid = str(params.get("instance") or "")
        if not UUID.match(sid):
            return {}
        if phase == 1:
            return {"openstack": {"srv": f"openstack server show {q(sid)} -f json",
                                  "ports": f"openstack port list --server {q(sid)} -f json"},
                    "undercloud": dict(overcloud.INVENTORY_READS)}
        server = instance_of(data)
        node, ctl, user, _problem, found = VolumeConnections.nodes(data, ctx)
        inst = str(server.get("OS-EXT-SRV-ATTR:instance_name") or "")
        ok_user = user in overcloud.USERS
        if phase == 2:
            out = {"openstack": {f"port_{p}": f"openstack port show {q(p)} -f json" for p in port_ids(data)}}
            out["openstack"].update({f"vol_{v}": f"openstack volume show {q(v)} -f json" for v in attached_ids(server)})
            oc = {}
            if ok_user and ctl:
                oc["db"] = overcloud.read(ctl["name"], ctl["ip"], user, "vc_db", sid)
            if ok_user and node and node.get("ip"):
                if overcloud.INSTANCE_RE.match(inst):
                    oc["dom"] = overcloud.read(node["name"], node["ip"], user, "vc_domain", inst)
                oc[f"log_{node['name']}"] = overcloud.read(node["name"], node["ip"], user, "vc_log", LOG_HOURS)
            if oc:
                out["overcloud"] = oc
            return out
        rows = db_rows(data)
        if phase == 5:   # NetApp: each LUN mapped at the LUN numbers of a disk, by its UUID (a lookup, not a search)
            na = {}
            for d in netapp_disks(domain_of(data)):
                for i, m in enumerate((records(data, f"na_dmap_{d['dm']}") or [])[:4]):
                    u = str((m.get("lun") or {}).get("uuid") or "")
                    if UUID.match(u):
                        na[f"na_lun_{d['dm']}_{i}"] = (f"/api/storage/luns/{u}"
                                                       "?fields=name,svm.name,serial_number,status.state,status.mapped,space.size")
            return {"ontap": na} if na else {}
        if phase == 4:   # NetApp: what the compute's igroup maps at the LUN numbers Nova keeps, and at those of each disk
            names = [str(g.get("name") or "") for g in (records(data, "na_igroup") or [])[:2] if g.get("name")]
            if not names:
                return {}
            group = "igroup.name=" + "|".join(q_ontap(n) for n in names)
            fields = "&fields=lun.name,lun.uuid,logical_unit_number,igroup.name,svm.name"
            na = {f"na_map_{lun}": f"/api/protocols/san/lun-maps?{group}&logical_unit_number={lun}{fields}"
                  for lun in sorted({b["lun"] for b in rows["bdm"] if b["lun"]})[:MAX_VOLUMES]}
            na.update({f"na_dmap_{d['dm']}": f"/api/protocols/san/lun-maps?{group}&logical_unit_number="
                                             f"{'|'.join(d['luns'][:4])}{fields}" for d in netapp_disks(domain_of(data))})
            return {"ontap": na}
        # phase 3: what the database named: the volumes not read yet, the device of each LUN on the compute, the log of
        # the computes of the last migration; on NetApp the compute's igroup
        out = {"openstack": {f"vol_{b['volume']}": f"openstack volume show {q(b['volume'])} -f json"
                             for b in rows["bdm"][:MAX_VOLUMES] if UUID.match(b["volume"]) and f"vol_{b['volume']}" not in data}}
        oc = {}
        if ok_user and node and node.get("ip"):
            for lun in sorted({b["lun"] for b in rows["bdm"] if b["lun"]})[:MAX_VOLUMES]:
                oc[f"lun_{lun}"] = overcloud.read(node["name"], node["ip"], user, "vc_lun", lun)
        if ok_user and rows["mig"]:
            for h in (rows["mig"][0]["source"], rows["mig"][0]["dest"]):
                n = node_of(h, found) if h else None
                if n and n.get("ip") and f"log_{n['name']}" not in data:
                    oc[f"log_{n['name']}"] = overcloud.read(n["name"], n["ip"], user, "vc_log", LOG_HOURS)
        if oc:
            out["overcloud"] = oc
        dom = domain_of(data)
        na = {}
        if dom["initiator"]:
            na["na_igroup"] = f"/api/protocols/san/igroups?initiators.name={q_ontap(dom['initiator'])}&fields=name,svm.name"
        if na:
            out["ontap"] = na
        return out if out["openstack"] or oc or na else {}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("volume-connections")
        sid = str(params.get("instance") or "")
        item = source(data, "srv")
        if unavailable(item):
            r.step("instance", "The instance", "fail", f"Instance {sid} not found: {unavailable(item)}")
            return r.done()
        s = instance_of(data)
        name = str(s.get("name") or sid)
        host = str(s.get("OS-EXT-SRV-ATTR:host") or "")
        status, task = str(s.get("status") or "").upper(), str(s.get("OS-EXT-STS:task_state") or "") or "-"
        pw = power(s.get("OS-EXT-STS:power_state"))
        vm_state = str(s.get("OS-EXT-STS:vm_state") or "").lower() or status.lower()
        fault = s.get("fault")
        fault = str(fault.get("message") if isinstance(fault, dict) else fault or "")
        node, ctl, user, problem, _found = VolumeConnections.nodes(data, ctx)
        rows = db_rows(data)
        db_item = source(data, "db")
        last = rows["mig"][0] if rows["mig"] else None
        failed_mig = last and last["status"] in ("error", "failed")
        detail = (f"{name} is {status} (vm_state {vm_state}, power {pw}, task {task}) on {host or 'no compute'}"
                  + (", locked" if str(s.get("locked")).lower() == "true" else "") + (f"; fault: {fault[:200]}" if fault else "") + ".")
        if failed_mig:
            detail += (f" Its last migration ({last['type'] or 'migration'} {last['id']}, {last['source']} -> {last['dest']}) ended "
                       f"{last['status']}.")
        st = "fail" if status == "ERROR" else "warn" if status == "ACTIVE" and pw != "running" else "ok"
        if status == "ACTIVE" and pw != "running":
            detail += " Nova says ACTIVE, but no domain runs it (a reset to ACTIVE does not start anything)."
        r.step("instance", "The instance", st, detail,
               {"columns": ["Migration", "Type", "Status", "Source", "Destination", "Created"],
                "rows": [[m["id"], m["type"] or "-", m["status"], m["source"] or "-", m["dest"] or "-", m["created"]] for m in rows["mig"]]})
        where = director(ctx)
        if not ctl or user not in overcloud.USERS:
            why = problem or "no controller reachable from the undercloud node list"
        else:
            why = unavailable(db_item) if unavailable(db_item) else ""

        # ---- 2. Cinder attachments of every volume
        dom_early = domain_of(data)
        facts = volume_facts(data, rows, sid, host, dom_early) if not why else []
        gone_ids = {f["volume"] for f in facts if f["missing"]}
        volumes = list(dict.fromkeys([b["volume"] for b in rows["bdm"]] + attached_ids(s)))[:MAX_VOLUMES]
        multi = {}
        for v in volumes:
            vol = json_of(source(data, f"vol_{v}")) or {}
            multi[v] = str(vol.get("multiattach")).lower() == "true" if isinstance(vol, dict) else False
        bdm_att = {b["volume"]: b["attachment"] for b in rows["bdm"]}
        extra = []   # (volume, attachment) of a non-multiattach volume with more than one attachment
        if why:
            r.skip("attachments", "Cinder attachments of the volumes", f"The database of a controller was not read: {why}")
        elif not volumes:
            r.step("attachments", "Cinder attachments of the volumes", "ok", f"{name} has no volume.")
        else:
            att_rows, dup, none = [], [], []
            for v in volumes:
                atts = [a for a in rows["att"] if a["volume"] == v]
                if not atts:
                    att_rows.append([v, "-", "not in Cinder by its ID (next step)" if v in gone_ids else "none", "-", "-", "-"])
                    if v not in gone_ids:
                        none.append(v)
                if len(atts) > 1 and not multi.get(v):
                    dup.append(v)
                    extra += [(v, a) for a in atts if a["id"] != bdm_att.get(v)]
                for a in atts:
                    att_rows.append([v, a["id"], a["status"], a["host"] or a["connector"] or "-", "yes" if a["connected"] else "no",
                                     "yes" if a["id"] == bdm_att.get(v) else "no"])
            r.step("attachments", "Cinder attachments of the volumes", "fail" if dup or none or gone_ids else "ok",
                   (f"{len(dup)} volume(s) that are not multiattach have more than one Cinder attachment: Cinder refuses the next "
                    "attachment update of a migration, unshelve or reboot (\"duplicate connectors detected\"), and a migration can "
                    "leave the instance in ERROR. " if dup else "")
                   + (f"{len(none)} volume(s) without any Cinder attachment: {', '.join(none)}. " if none else "")
                   + (f"{len(gone_ids)} volume(s) of Nova are not in Cinder by their ID (see the next step). " if gone_ids else "")
                   or f"{len(volumes)} volume(s), each with one attachment (or multiattach).",
                   {"columns": ["Volume", "Attachment", "Status", "Host", "Connected", "Nova uses it"], "rows": att_rows},
                   marks=dup + none + sorted(gone_ids))

        # ---- 2b. each volume in Cinder by its ID, and the disk the domain runs on (NetApp)
        missing = [f for f in facts if f["missing"]]
        astray = [f for f in facts if not f["missing"] and f["runs_on"]
                  and f["runs_on"] not in (f["volume"], (f["row"] or {}).get("name_id") or f["volume"])]
        shifted = [f for f in facts if f["lun"] and f["disk"].get("luns") and f["lun"] not in f["disk"]["luns"]]
        stale = [f for f in facts if f["mismatch"]]
        na_read = any(f["na"] is not None for f in facts) or records(data, "na_igroup") is not None
        if why:
            r.skip("records", "The volumes in Cinder by their ID, and the disk the domain runs on (NetApp)",
                   f"The database of a controller was not read: {why}")
        elif facts:
            vrows = []
            for f in facts:
                row = f["row"]
                in_cinder = ("yes" if f["api"] == "id" and not (row and row["deleted"]) else
                             f"NO: deleted {row['deleted_at'] or ''}".strip() if row and row["deleted"] else
                             f"NO: the API answers {f['api_text']} (a volume named so)" if f["api"] == "name" else
                             "NO (404)" if f["api"] == "gone" else "not read")
                named = "; ".join(f"{x['id']} ({x['status']}, {x['attach']}" + (f", migration {x['migstat']}" if x["migstat"] else "")
                                  + ")" for x in f["named"]) or "-"
                disk = (f"{f['disk'].get('dm')} ({f['disk'].get('wwid')}), LUN {','.join(f['disk'].get('luns') or []) or '?'}"
                        if f["disk"] else "-")
                runs = (f"{f['runs_on']}" + (f" ({f['runs_row']['status']}"
                                             + (f", attachment {f['runs_att']['id']} {f['runs_att']['status']} on "
                                                f"{short(f['runs_att']['host'] or f['runs_att']['connector'])}" if f["runs_att"] else "")
                                             + ")" if f["runs_row"] else " (no live Cinder row)")) if f["runs_on"] else "-"
                nova_map = ("-" if not f["lun"] else "not read" if f["map"] is None else
                            f"{f['map'] or 'nothing mapped'} (igroup {f['igroup']})")
                vrows.append([f["volume"], in_cinder, named, disk, f["na_text"] or (f"serial {f['serial']}" if f["serial"] else "-"),
                              runs, f"LUN {f['lun'] or '-'}: {nova_map}"])
            st = ("fail" if missing or astray or shifted else
                  "warn" if stale or facts and not na_read and any(f["serial"] for f in facts) else "ok")
            parts = []
            for f in missing[:2]:
                row = f["row"]
                parts.append(
                    f"Nova's volume {f['volume']} ({f['device']}) is not in Cinder by its ID"
                    + (f" (its row was deleted {row['deleted_at']})" if row and row["deleted"] else
                       f" (the API answers another volume found by name: {f['api_text']})" if f["api"] == "name" else "")
                    + (f". The domain runs {f['device']} on {f['disk'].get('dm')} (LUN {','.join(f['disk'].get('luns') or []) or '?'}), "
                       f"NetApp LUN {f['na_text']}: Cinder volume {f['runs_on']}"
                       + (f", {f['runs_row']['status']}" if f["runs_row"] else "")
                       + (f", migration {f['runs_row']['migstat']}" if f["runs_row"] and f["runs_row"]["migstat"] else "")
                       + (f", attached to this instance ({f['runs_att']['id']})" if f["runs_att"] else "")
                       if f["runs_on"] else
                       f". The disk the domain runs it on is serial {f['serial'] or '?'} on NetApp (lun show -serial)"
                       if f["disk"] else "")
                    + ": a Cinder volume migration that never completed, or a record deleted under a running instance. Every "
                      "Nova action on this volume fails (HTTP 404), and Horizon cannot open the instance page")
            for f in astray[:2]:
                parts.append(f"The domain runs {f['device']} on NetApp LUN {f['na_text']} (Cinder {f['runs_on']}), not on Nova's "
                             f"volume {f['volume']}")
            for f in shifted[:2]:
                parts.append(f"Nova's stored connection of {f['volume']} names LUN {f['lun']}; the paths of the disk the domain runs "
                             f"on are LUN {','.join(f['disk']['luns'])}"
                             + (f"; on NetApp the igroup {f['igroup']} of this compute maps "
                                + (f"{f['map']} at LUN {f['lun']}" if f["map"] else f"nothing at LUN {f['lun']}") if f["map"] is not None else ""))
            for f in stale[:2]:
                parts.append(f"The paths of {f['device']} ({f['disk'].get('dm')}, serial {f['serial']}) are LUN "
                             f"{','.join(f['disk']['luns'])} on the compute, but on NetApp: {f['na_text']}. The compute keeps "
                             "paths of a LUN that is no longer mapped to it at that number")
            compared = [f for f in facts if f["na"] is not None]
            text = (". ".join(parts) + (". Do not stop / start, hard reboot, resize, migrate or evacuate it: Nova would connect "
                                        "the LUN it keeps, not the disk the instance runs on." if missing or astray or shifted else
                                        ". Check the LUN mappings of this compute on NetApp before any stop / start or migration of "
                                        "it.")) if parts else (
                "Each volume is in Cinder by its ID"
                + (f", and the NetApp LUN of each disk read ({len(compared)}) is named after its volume." if compared else
                   " (NetApp not read: the LUN behind each disk is not compared)." if any(f["serial"] for f in facts) else "."))
            r.step("records", "The volumes in Cinder by their ID, and the disk the domain runs on (NetApp)", st, text,
                   {"columns": ["Nova's volume", "In Cinder by ID", "Other Cinder rows naming it", "Disk the domain runs",
                                "NetApp LUN of that disk", "Cinder volume of that LUN", "Nova's LUN on this compute (NetApp)"],
                    "rows": vrows}, marks=[f["volume"] for f in missing + astray + shifted + stale])

        # ---- 3. Nova's BDM against Cinder
        bdm_bad, neutral = [], []
        if why:
            r.skip("bdm", "Nova's connection of each volume (block device mapping)", f"The database of a controller was not read: {why}")
        elif rows["bdm"]:
            brows = []
            for b in rows["bdm"]:
                a = next((x for x in rows["att"] if x["id"] == b["attachment"]), None)
                a_host = (a or {}).get("host") or (a or {}).get("connector") or ""
                if b["type"] == "local":
                    neutral.append(b)
                    note = "neutral (a repair is in progress): refresh it before the instance starts"
                elif not a:
                    note = "its attachment no longer exists in Cinder"
                elif a["status"] != "attached":
                    note = f"its attachment is {a['status']}, not attached"
                elif not same_host(a_host, host):
                    note = f"its attachment is connected to {a_host or 'no host'}, not to {host}"
                else:
                    note = "ok"
                if note != "ok" and b["type"] != "local":
                    bdm_bad.append((b, note))
                brows.append([b["volume"], b["device"] or "-", b["attachment"] or "-", (a or {}).get("status") or "missing",
                              a_host or "-", b["type"] or "-", b["lun"] or "-", b["path"] or "-", note])
            st = "fail" if bdm_bad else "warn" if neutral else "ok"
            r.step("bdm", "Nova's connection of each volume (block device mapping)", st,
                   (f"The connection Nova keeps is not the one of {host} for {len(bdm_bad)} volume(s): "
                    + "; ".join(f"{b['volume']}: {n}" for b, n in bdm_bad[:3])
                    + ". On its next start, hard reboot or migration Nova uses this connection: it disconnects the LUN it names "
                      "on the compute, then cannot connect the volume." if bdm_bad else
                    "The connection info of " + ", ".join(b["volume"] for b in neutral) + " is neutral (driver_volume_type local, "
                    "a repair in progress): the instance cannot start before nova-manage volume_attachment refresh."
                    if neutral else f"Each volume is on the attachment of {host}, attached."),
                   {"columns": ["Volume", "Device", "Attachment", "Its status", "Its host", "Type", "LUN", "Device path", "Note"],
                    "rows": brows}, marks=[b["attachment"] for b, _n in bdm_bad])
        else:
            r.step("bdm", "Nova's connection of each volume (block device mapping)", "ok", f"{name} has no volume in Nova.")

        # ---- 4. the disks on the compute: the device of each BDM LUN, and who uses it
        dom = domain_of(data)
        defined = bool(dom["state"]) and not NOT_DEFINED.search(dom["state"])
        others, wrong = [], []
        dom_item = source(data, "dom")
        if not node or not node.get("ip") or user not in overcloud.USERS:
            r.skip("devices", "Disks of the instance on its compute", f"{host or 'Its compute'} cannot be read from the director: "
                   + (problem or "no ctlplane address in the undercloud node list"))
        elif unavailable(dom_item):
            r.skip("devices", f"Disks of the instance on {host}", f"virsh on {node['name']} did not answer: {unavailable(dom_item)}")
        else:
            drows, statuses = [], []
            for b in rows["bdm"]:
                target = b["device"].rsplit("/", 1)[-1]
                disk = dom["disks"].get(target) or {}
                if b["type"] != "iscsi" or not b["lun"]:
                    drows.append([b["volume"], target or "-", disk.get("dm") or "-", f"{b['type'] or '?'} (not compared)", "-"])
                    continue
                if unavailable(source(data, f"lun_{b['lun']}")):
                    drows.append([b["volume"], target, disk.get("dm") or "-", f"LUN {b['lun']}: not read", "-"])
                    statuses.append("warn")
                    continue
                devices, users = lun_of(data, b["lun"], b["iqn"])
                used = [(x, u, dm) for x, u, dm in users if dm in devices]
                foreign = [(x, u, dm) for x, u, dm in used if u != sid]
                lun_text = ", ".join(f"{dm} ({w})" for dm, w in devices.items()) or "no device"
                if foreign:
                    others += [(b, x, u, dm, devices.get(dm, "")) for x, u, dm in foreign]
                    statuses.append("fail")
                elif devices and disk.get("dm") and disk["dm"] not in devices:
                    wrong.append((b, disk["dm"], lun_text))
                    statuses.append("fail")
                elif not devices and disk.get("dm"):
                    wrong.append((b, disk["dm"], "no device"))
                    statuses.append("fail")
                elif not devices and not defined:
                    statuses.append("warn")
                else:
                    statuses.append("ok")
                drows.append([b["volume"], target, f"{disk.get('dm') or '-'} ({disk.get('wwid') or '-'})" if disk else "-",
                              f"LUN {b['lun']}: {lun_text}", ", ".join(f"{x} ({u})" for x, u, _dm in used) or "nobody"])
            st = max(statuses, key=lambda x: {"fail": 2, "warn": 1, "ok": 0}[x]) if statuses else "ok"
            if others:
                b, x, u, dm, w = others[0]
                text = (f"CRITICAL: the LUN {b['lun']} of target {b['iqn']} that Nova keeps for volume {b['volume']} is, on {node['name']}, "
                        f"the disk {dm} ({w}) of ANOTHER instance: {u} (domain {x}). A hard reboot, start, delete, rebuild or "
                        f"migration of {name} disconnects that disk first (os-brick flushes it): the other instance gets I/O errors "
                        "and remounts its filesystem read-only.")
            elif wrong:
                b, dm, lun_text = wrong[0]
                text = (f"The domain of {name} uses {dm} for {b['device']}, but the LUN {b['lun']} Nova keeps is {lun_text} on "
                        f"{node['name']}: Nova's connection info is not the one the domain runs on.")
            elif st == "warn":
                text = (f"The domain of {name} is not defined on {node['name']} and no device of its LUN(s) is connected there yet: "
                        "a start connects them (expected after a refresh).")
            else:
                text = f"Domain {dom['state'] or '-'}; every disk is the LUN Nova keeps, used by this instance only."
            r.step("devices", f"Disks of the instance on {host}", st, text,
                   {"columns": ["Volume", "Disk", "Domain uses", "Nova's LUN on this compute", "Used by"], "rows": drows},
                   marks=[u for _b, _x, u, _dm, _w in others] or [dm for _b, dm, _t in wrong])

        # ---- 5. ports
        prows, moving, elsewhere = [], [], []
        migrating = "migrat" in task
        for p in port_ids(data):
            pv = json_of(source(data, f"port_{p}")) or {}
            prof = pv.get("binding_profile") or pv.get("binding:profile") or {}
            if isinstance(prof, str):
                m = re.search(r"migrating_to='?([A-Za-z0-9_.-]+)", prof)
                target = m.group(1) if m else ""
            else:
                target = str((prof or {}).get("migrating_to") or "")
            bhost = str(pv.get("binding_host_id") or pv.get("binding:host_id") or "")
            if target and not migrating:
                moving.append((p, target))
            if bhost and host and not same_host(bhost, host) and not migrating:
                elsewhere.append((p, bhost))
            prows.append([p, pv.get("name") or "-", pv.get("status") or "-", bhost or "(not shown)", pv.get("binding_vif_type") or "-",
                          f"migrating_to {target}" if target else "-"])
        if prows:
            st = "fail" if elsewhere else "warn" if moving else "ok"
            r.step("ports", "Ports of the instance", st,
                   (f"{len(elsewhere)} port(s) bound to another compute than {host}: its network does not come up there. " if elsewhere else "")
                   + (f"{len(moving)} port(s) still carry migrating_to (left by a migration that did not roll back): on OVN the port "
                      "may wait for the destination." if moving else "")
                   or f"{len(prows)} port(s) bound to {host}, no migration leftover.",
                   {"columns": ["Port", "Name", "Status", "Binding host", "VIF type", "Binding profile"], "rows": prows},
                   marks=[p for p, _t in moving + elsewhere])
        else:
            r.step("ports", "Ports of the instance", "ok", f"{name} has no port.")

        # ---- 6. libvirt job lock
        locked = False
        if unavailable(dom_item) or not dom["state"]:
            r.skip("joblock", "Can libvirt take a job on the domain", "The domain was not read (see Disks).")
        elif not defined:
            r.step("joblock", "Can libvirt take a job on the domain", "info", f"The domain is not defined on {host}: nothing to lock.")
        elif LOCK.search(dom["job"]):
            locked = True
            r.step("joblock", "Can libvirt take a job on the domain", "fail",
                   f"libvirt cannot take the job of the domain on {host}: {dom['job'][:300]}. A reconnect of virtqemud that never "
                   "ended holds it (monitor=init-…): QEMU does not answer libvirt, so every live migration fails and leaves the "
                   "instance in ERROR, and a stop may hang.", marks=["state change lock"])
        else:
            r.step("joblock", "Can libvirt take a job on the domain", "ok", f"domjobinfo answers: {dom['job'][:160] or 'no job'}.")

        # ---- 7. nova-compute log: the lines of this instance, and os-brick flush failures of its disks or of the LUNs Nova
        # keeps for it (they name the multipath WWID, not the instance)
        wwids = {d["wwid"] for d in dom["disks"].values() if d.get("wwid") not in (None, "", "-")}
        for b in rows["bdm"]:
            if b["lun"]:
                wwids |= {w for w in lun_of(data, b["lun"], b["iqn"])[0].values() if w and w != "-"}
        lines = []
        for key in sorted(k for k in data if k.startswith("log_")):
            it = source(data, key)
            if unavailable(it):
                continue
            for line in str(it.get("out") or "").splitlines():
                if sid in line or ("Flushing" in line and any(w in line for w in wwids)):
                    lines.append(f"{key[4:]}: {line[:300]}")
        r.step("log", f"nova-compute log ({LOG_HOURS} h): migration and volume errors", "info" if lines else "ok",
               (f"{len(lines)} line(s) about this instance or the devices of its LUNs." if lines else
                "No line about a failed migration or volume connection of this instance."), evidence=lines[-40:])

        # ---- how to fix it (manual: the order proven in production)
        locked_now = defined and LOCK.search(dom["job"]) is not None
        bad_bdm = [b for b, _n in bdm_bad] + [o[0] for o in others] + [w[0] for w in wrong]
        node_name = node["name"] if node else (host or "<compute>")
        # a volume Nova keeps that Cinder no longer has: the refresh below would ask Cinder for it (HTTP 404); Nova is
        # first pointed at the volume the domain runs on (NetApp named it), then refreshed the same way
        found = [f for f in missing if f["runs_on"] and f["runs_row"] and f["runs_att"]]
        for f in found[:1]:
            v, x, att = f["volume"], f["runs_on"], f["runs_att"]["id"]
            b = next(b for b in rows["bdm"] if b["volume"] == v)
            r.recommend(
                f"Do not stop / start, hard reboot, resize, migrate or evacuate {name} before this repair (Nova would connect LUN "
                f"{f['lun'] or '?'}, not its disk). Point Nova's volume {v} at the volume the instance runs on, {x} (NetApp "
                f"{f['na_text']}), with its attachment {att}, then refresh the connection with the instance stopped. A database "
                "change: with the approval of the owner, in a window, ideally with Red Hat support.",
                ([f"cinder reset-state --reset-migration-status {x}   # 1. its migration status ({f['runs_row']['migstat']}) cleared"]
                 if f["runs_row"]["migstat"] else [])
                + [f"# 2. on a controller, as root, umask 077 (the row holds the CHAP secret: never print it)",
                   f"podman exec $(podman ps -q -f name=galera-bundle | head -1) mysql -N -B -e \"SELECT * FROM nova.block_device_mapping "
                   f"WHERE instance_uuid='{sid}' AND volume_id='{v}' AND deleted=0\" > /root/bdm-{sid}.backup",
                   f"openstack server stop {sid}   # 3. power off only (customer approval first)",
                   f"podman exec $(podman ps -q -f name=galera-bundle | head -1) mysql -e \"UPDATE nova.block_device_mapping SET "
                   f"volume_id='{x}', attachment_id='{att}', connection_info='{{\\\"driver_volume_type\\\": \\\"local\\\", "
                   f"\\\"data\\\": {{}}, \\\"serial\\\": \\\"{x}\\\"}}' WHERE instance_uuid='{sid}' AND volume_id='{v}' "
                   f"AND attachment_id='{b['attachment']}' AND deleted=0 LIMIT 1; SELECT ROW_COUNT();\"   # 4. must say 1",
                   f"podman exec -u root nova_compute nova-manage volume_attachment get_connector --json > /tmp/connector.json   "
                   f"# 5. on {node_name}, as root: its host must be {host}",
                   f"podman exec -u root nova_api nova-manage --config-file /etc/nova/nova.conf --config-file /tmp/cinder-auth.conf "
                   f"volume_attachment refresh {sid} {x} /tmp/connector.json   # 6. on the controller, as root",
                   f"openstack server start {sid}   # 7. only after this check, run again, shows {x} in Cinder by ID and its LUN as the disk"],
                where=f"A controller and {node_name} as root, and the {where} (see the comments)",
                warning=("nova-manage runs without a token: put the [cinder] auth options (auth_type = password, auth_url, "
                         "username, password, project_name, user_domain_name, project_domain_name from [keystone_authtoken] of "
                         "nova.conf) into a root-only /tmp/cinder-auth.conf inside nova_api, delete it after. The refresh makes a "
                         f"new attachment of {x} for {host} and deletes {att}. The guest sees the disk serial {x} after the start "
                         f"(it was {v}): only /dev/disk/by-id/virtio-… paths in the guest change. A boot volume's image metadata "
                         f"stays on the deleted row of {v}: copy it with cinder image-metadata {x} set if Nova needs it."),
                refs=["volume-connections"])
        repoint = list({b["volume"]: b for b in bad_bdm + neutral if b["volume"] not in gone_ids}.values())
        if repoint:
            b = repoint[0]
            vol, att = b["volume"], b["attachment"]
            leftovers = [a for v, a in extra if v == vol]
            r.recommend(
                (f"Do not hard reboot, start, delete, rebuild or migrate {name} now. " if others else "")
                + "Repoint Nova's connection of the volume to its compute, with the instance stopped: back up the BDM row, stop, "
                "neutralize the BDM, delete the leftover attachments, refresh the attachment, check, start.",
                [f"# 1. on a controller, as root, umask 077 (the row holds the CHAP secret: never print it)",
                 f"podman exec $(podman ps -q -f name=galera-bundle | head -1) mysql -N -B -e \"SELECT id, attachment_id, connection_info "
                 f"FROM nova.block_device_mapping WHERE instance_uuid='{sid}' AND volume_id='{vol}' AND deleted=0\" > /root/bdm-{sid}.backup",
                 f"openstack server stop {sid}   # 2. power off only: nothing is disconnected (customer approval first)",
                 f"podman exec $(podman ps -q -f name=galera-bundle | head -1) mysql -e \"UPDATE nova.block_device_mapping SET "
                 f"connection_info='{{\\\"driver_volume_type\\\": \\\"local\\\", \\\"data\\\": {{}}, \\\"serial\\\": \\\"{vol}\\\"}}' "
                 f"WHERE instance_uuid='{sid}' AND volume_id='{vol}' AND attachment_id='{att}' AND deleted=0 LIMIT 1; SELECT ROW_COUNT();\""
                 "   # 3. must say 1: its disconnect is now a no-op"]
                + [f"cinder --os-volume-api-version 3.27 attachment-delete {a['id']}   # 4. leftover ({a['status']}, "
                   f"host {a['host'] or a['connector'] or '-'}), only with the instance stopped" for a in leftovers]
                + [f"podman exec -u root nova_compute nova-manage volume_attachment get_connector --json > /tmp/connector.json   "
                   f"# 5. on {node_name}, as root: its host must be {host}",
                   f"podman exec -u root nova_api nova-manage --config-file /etc/nova/nova.conf --config-file /tmp/cinder-auth.conf "
                   f"volume_attachment refresh {sid} {vol} /tmp/connector.json   # 6. on the controller, as root (see the warning)",
                   f"openstack server start {sid}   # 7. only after this check, run again, shows the new LUN used by no other instance"],
                where=f"A controller and {node_name} as root, and the {where} (see the comments)",
                warning=(("libvirt cannot take the job of its domain (see that step): fix libvirt first, the stop needs it. "
                          if locked_now else "")
                         + "nova-manage runs without a token: nova_api has no [cinder] auth options (\"Unknown auth type: None\"); put "
                         "auth_type = password and auth_url, username, password, project_name, user_domain_name, project_domain_name "
                         "copied from [keystone_authtoken] of nova.conf into a root-only /tmp/cinder-auth.conf inside the container "
                         "(podman cp the connector there too), delete both after. nova-manage refresh first runs remove_volume_connection "
                         "with the BDM's connection info: that is why step 3 comes first. A leftover attachment connected to "
                         f"{host} itself leaves its multipath device there with failed paths after the delete: once no domain "
                         "uses it, flush it (multipath -f <its WWID, step 4>) before the refresh. If the instance then stops at \"Boot failed: "
                         "not a bootable disk\", its sector 0 is damaged: compare it with volumes made from the same image "
                         "(volume_image_metadata image_id) before writing anything."),
                refs=["volume-connections"])
        elif extra:
            r.recommend("Delete the leftover Cinder attachment with the Cinder API: the one that is not Nova's (BDM) and is not "
                        f"connected to {host}, where the instance runs. First make sure no domain on its host uses the LUN.",
                        [f"cinder --os-volume-api-version 3.27 attachment-list --all-tenants --volume-id {v}" for v in dict.fromkeys(v for v, _a in extra)]
                        + [f"cinder --os-volume-api-version 3.27 attachment-delete {a['id']}   # {a['status']}, host "
                           f"{a['host'] or a['connector'] or '-'}" for _v, a in extra
                           if not same_host(a["host"] or a["connector"], host)],
                        where=where, warning="Never delete Nova's attachment nor the one of the host where the domain runs while it runs.",
                        refs=["volume-connections"])
        if moving:
            r.recommend("Remove the migrating_to left on the ports (no migration of the instance runs: task_state is not migrating).",
                        [f"openstack port unset --binding-profile migrating_to {p}   # was migrating_to {t}" for p, t in moving],
                        where=where)
        if locked:
            r.recommend(f"Fix libvirt on {node_name} before any migration of {name}: its QEMU does not answer libvirt.",
                        [f"podman ps --filter name=nova_virtqemud --format '{{{{.Names}}}} {{{{.Status}}}}'   # on {node_name}: when "
                         "virtqemud restarted (it reconnects to every QEMU)",
                         f"ps -o pid,stat,lstart,wchan:32 -p $(pgrep -f 'guest={s.get('OS-EXT-SRV-ATTR:instance_name')},')"
                         "   # D = QEMU waits on storage"],
                        where=f"{node_name}, as root",
                        warning="A restart of virtqemud or a hard reboot of the instance affects the customer: get their approval. "
                                "If a reconnect fails, libvirt kills the VM.", refs=["nova-live-migration"])
        return r.done()

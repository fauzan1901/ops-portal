"""NetApp LUN mappings of the computes against Cinder (check lun-map-audit), read-only: does every LUN number NetApp maps
to a compute belong to a live Cinder attachment of that compute, is every attachment the LUN of its own volume, and
does any instance run on a copy of its LUN inside a FlexClone?

Why (a real case): the igroup of overcloud-novacomputeha-8 mapped 61 LUN numbers; 29 were live Cinder attachments
of ha-8, the other 32 LUNs of DCAOPNSTACK_CINDER_15_vol with no attachment and no device there (a rescan of ha-8's
sessions would show it the disks of other volumes). Volume 0d6e2b34, attached on ha-8 at LUN 28, ran on
/vol/snap_cinder_vol_clone_1/volume-1e7f3c45: a FlexClone of CINDER_15 made on 26 Jun 2025 from the
snapshot of 24 Jun 2025, which holds a copy of every LUN of its parent under the same name. The original LUN in
CINDER_15 stayed mapped to another compute. Cinder's NetApp driver finds a LUN by its name; with copies of the same name
in the SVM it may map a copy (on an attach, a live migration) and unmap another (on the detach of the source).
Per compute (its igroups are the igroups holding its iSCSI initiator):
  - attachments that run on a copy of their LUN in a FlexVol other than the volume's Cinder pool (a FlexClone), with the
    Nova action that made the attachment, before or after the clone was made, the serial of the device on the compute;
  - NetApp mappings with no live Cinder attachment at that number, and what the LUN's volume is now;
  - attachments whose number maps a LUN named after neither the volume ID nor its _name_id, or nothing;
  - SCSI devices on the compute at numbers NetApp does not map for it, and whether a running domain uses them;
  - LUN names in more than one FlexVol of the SVM; FlexClones Cinder reports as pools; igroups without a node.
Reads: on NetApp the SVM(s) whose iSCSI target Cinder uses (lists only: LUN maps, LUN names, volumes with their clone
parent and create time, igroups; then the serial of the few LUNs a finding names, by UUID: a search by serial took over
60 s on DCA); Cinder's live attachments and volumes and the Nova action of each attachment (SELECT on the galera
container of a controller; of connection_info only the target IQN and LUN); on every node its initiator, its iSCSI
devices (sysfs) and the disks of its running domains. Nothing is changed and nothing is proposed: the owner decides.
"""
import collections
import datetime
import re
import time

from . import overcloud
from .common import Result, json_of, source, unavailable
from .lun_guard import flexvol, pool   # noqa: F401 (also used by the LUN copy guard)
from .overcloud_checks import inventory
from .volume_connections import netapp_serial, q_ontap, records

UUID_ANY = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
LUN_NAME = re.compile(rf"^volume-({UUID_ANY})$")
MAX_SERIALS = 60
NEAR = 2   # hours: the Nova action within this of the attachment's creation made it
TIMEOUT = "&return_timeout=45"   # ONTAP answers with what it has and a next link before the portal's 60 s read timeout
MOVES = {"live-migration": "live migration", "migrate": "cold migration", "resize": "resize", "attach_volume": "attach",
         "unshelve": "unshelve", "evacuate": "evacuate", "swap_volume": "volume swap", "rebuild": "rebuild"}


def short(name):
    return overcloud.short(name)


def disp(name):
    n = str(name or "")
    return n[10:] if n.startswith("overcloud-") else n


def lun_vid(path):
    m = LUN_NAME.match(str(path or "").rsplit("/", 1)[-1])
    return m.group(1) if m else ""


def ckey(klass):
    """The kind of a "what its volume is now" text, without hosts and numbers (to count them)."""
    if klass.startswith("copy in ") and ": " in klass:
        head, rest = klass.split(": ", 1)
        return f"{head}: {ckey(rest)}"
    return re.split(r" on | LUN ", klass)[0]


def utc(text):
    """A naive UTC datetime from a database time ("2026-10-01 00:59:00", UTC) or an ONTAP time (ISO 8601 with offset)."""
    t = str(text or "").strip()
    if not t:
        return None
    try:
        d = datetime.datetime.fromisoformat(t.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d.astimezone(datetime.timezone.utc).replace(tzinfo=None) if d.tzinfo else d


def db_rows(data):
    """{"att": [...], "vol": {id: {...}}, "org": {attachment: {...}}, "kept": oldest deleted attachment} of lm_db."""
    out = {"att": [], "vol": {}, "org": {}, "kept": ""}
    for line in str(source(data, "db").get("out") or "").splitlines():
        f = line.split("\t")
        if f[0] == "att" and len(f) >= 11:
            out["att"].append({"id": f[1], "vol": f[2], "inst": f[3], "status": f[4].lower(), "node": short(f[5]), "init": f[6].lower(),
                               "iqn": f[7].lower(), "lun": f[8], "created": f[9], "attached": f[10]})
        elif f[0] == "vol" and len(f) >= 8:
            out["vol"][f[1]] = {"id": f[1], "name_id": f[2] or f[1], "status": f[3].lower(), "host": f[4], "size": f[5],
                                "mig": f[6], "name": f[7]}
        elif f[0] == "org" and len(f) >= 5:
            act, mig, prev = f[2].split("|"), f[3].split("|"), f[4].split("|")
            out["org"][f[1]] = {"action": act[0] if len(act) == 3 else "", "req": act[1] if len(act) == 3 else "",
                                "start": act[2] if len(act) == 3 else "",
                                "mig": mig if len(mig) == 5 else [], "prev": prev if len(prev) == 6 else []}
        elif f[0] == "min" and len(f) >= 2:
            out["kept"] = f[1]
    return out


def node_rows(data, found):
    """{short name: {"name", "role", "init", "devs": [...], "uses": {device: [instance (domain target)]}, "why"}}."""
    out = {}
    for n in found:
        if n.get("role") not in ("compute", "controller"):
            continue
        item = source(data, f"lmn_{n['name']}")
        x = {"name": n["name"], "role": n["role"], "init": "", "devs": [], "uses": collections.defaultdict(list),
             "why": unavailable(item)}
        for line in str(item.get("out") or "").splitlines():
            f = line.split()
            if line.startswith("@@node ") and len(f) >= 3:
                x["init"] = f[2].lower()
            elif line.startswith("@@dev ") and len(f) >= 7 and f[2].rsplit(":", 1)[-1].isdigit():
                x["devs"].append({"sd": f[1], "lun": int(f[2].rsplit(":", 1)[-1]), "state": f[3], "tgt": f[4].lower(),
                                  "wwid": f[5], "dm": f[6]})
            elif line.startswith("@@use ") and len(f) >= 5:
                x["uses"][f[1]].append(f"{f[2]} ({f[3]} {f[4] if len(f) > 4 else ''})".replace(" )", ")"))
        out[short(n["name"])] = x
    return out


def svm_targets(data):
    """{SVM name: its iSCSI target name} from the iSCSI services, None when they were not read."""
    recs = records(data, "na_iscsi")
    if recs is None:
        return None
    return {str((r.get("svm") or {}).get("name") or ""): str((r.get("target") or {}).get("name") or "").lower()
            for r in recs if isinstance(r, dict) and (r.get("svm") or {}).get("name")}


def chosen_svms(data):
    """The SVMs whose iSCSI target the live attachments use ([] when that cannot be told: read without an SVM filter)."""
    targets = svm_targets(data)
    used = {a["iqn"] for a in db_rows(data)["att"] if a["status"] == "attached" and a["iqn"]}
    return sorted(s for s, t in (targets or {}).items() if t in used)


def ontap_sets(data):
    """The keys suffixes of the ONTAP list reads of phase 3 that were planned."""
    return sorted({k.split("_", 2)[2] for k in data if k.startswith("na_maps_")})


def model(data, ctx):
    """Everything read, joined: the facts the reads of phase 4 and the analysis use."""
    found, controllers, user, _version, problem = inventory(data, ctx)
    d = db_rows(data)
    nodes = node_rows(data, found)
    M = {"found": found, "controllers": controllers, "user": user, "problem": problem, "db": d, "nodes": nodes,
         "maps": [], "luns": {}, "vols": {}, "igroups": {}, "na_why": [], "more": []}
    for s in ontap_sets(data):
        for kind in ("maps", "luns", "vols", "igroups"):
            key = f"na_{kind}_{s}"
            item = source(data, key)
            if item.get("more"):
                M["more"].append(f"{key}: {item['more']}")
            recs = records(data, key)
            if recs is None:
                M["na_why"].append(f"{key}: {unavailable(item)}")
                continue
            for r in recs:
                if not isinstance(r, dict):
                    continue
                svm = str((r.get("svm") or {}).get("name") or s)
                if kind == "maps":
                    path = str((r.get("lun") or {}).get("name") or "")
                    if path and str(r.get("logical_unit_number", "")).isdigit():
                        M["maps"].append({"svm": svm, "igroup": str((r.get("igroup") or {}).get("name") or ""),
                                          "lun": int(r["logical_unit_number"]), "path": path,
                                          "uuid": str((r.get("lun") or {}).get("uuid") or "")})
                elif kind == "luns" and r.get("name"):
                    M["luns"][str(r["name"])] = str(r.get("uuid") or "")
                elif kind == "vols" and r.get("name"):
                    c = r.get("clone") or {}
                    M["vols"][str(r["name"])] = {"created": str(r.get("create_time") or ""),
                                                 "clone": bool(c.get("is_flexclone")),
                                                 "parent": str((c.get("parent_volume") or {}).get("name") or ""),
                                                 "snapshot": str((c.get("parent_snapshot") or {}).get("name") or "")}
                elif kind == "igroups" and r.get("name"):
                    M["igroups"][f"{svm} {r['name']}"] = [str(i.get("name") if isinstance(i, dict) else i).lower()
                                                          for i in r.get("initiators") or [] if i]
    targets = svm_targets(data) or {}
    svms = chosen_svms(data)
    M["svms"] = svms
    M["svm_iqns"] = {targets[s] for s in svms if targets.get(s)}
    if not M["svm_iqns"]:
        c = collections.Counter(a["iqn"] for a in d["att"] if a["status"] == "attached" and a["iqn"].startswith("iqn."))
        M["svm_iqns"] = {c.most_common(1)[0][0]} if c else set()
    return M


def findings(M, data=None):
    """The findings of every section from the model (data: the serials of phase 4 when read)."""
    d, nodes, vols = M["db"], M["nodes"], M["db"]["vol"]
    by_name = collections.defaultdict(list)   # the ID in a LUN name -> the live volumes with that ID or _name_id
    for v in vols.values():
        by_name[v["id"]].append(v)
        if v["name_id"] != v["id"]:
            by_name[v["name_id"]].append(v)
    atts_of = collections.defaultdict(list)
    for a in d["att"]:
        atts_of[a["vol"]].append(a)
    for n, x in nodes.items():   # a node not read: its initiator as Cinder's connector of its attachments gives it
        if not x["init"]:
            c = collections.Counter(a["init"] for a in d["att"] if a["node"] == n and a["init"])
            if c:
                x["init"], x["init_from"] = c.most_common(1)[0][0], "Cinder"
    init_nodes = collections.defaultdict(list)
    for n, x in nodes.items():
        if x["init"]:
            init_nodes[x["init"]].append(n)
    groups_of = collections.defaultdict(list)
    for g, inits in M["igroups"].items():
        for i in inits:
            for n in init_nodes.get(i, []):
                groups_of[n].append(g)
    maps_of = collections.defaultdict(list)
    mapped_at = collections.defaultdict(list)   # LUN path -> [(compute(s) or igroup, LUN number)]
    group_nodes = {g: sorted({n for i in inits for n in init_nodes.get(i, [])}) for g, inits in M["igroups"].items()}
    for m in M["maps"]:
        g = f"{m['svm']} {m['igroup']}"
        maps_of[g].append(m)
        mapped_at[m["path"]].append(("/".join(disp(x) for x in group_nodes.get(g, [])) or m["igroup"], m["lun"]))
    copies = collections.defaultdict(set)   # LUN name -> its paths in the SVM
    for path in list(M["luns"]) + [m["path"] for m in M["maps"]]:
        copies[path.rsplit("/", 1)[-1]].add(path)
    serials = {}   # LUN UUID -> serial (phase 4)
    for k in (data or {}):
        if k.startswith("na_ser_"):
            doc = json_of(source(data, k)) if not unavailable(source(data, k)) else None
            if isinstance(doc, dict) and doc.get("uuid"):
                serials[str(doc["uuid"])] = str(doc.get("serial_number") or "")
    path_uuid = dict(M["luns"])
    for m in M["maps"]:
        if m["uuid"]:
            path_uuid.setdefault(m["path"], m["uuid"])

    def where(path):
        return "; ".join(f"{flexvol(p)}: " + (", ".join(f"{x} LUN {l}" for x, l in mapped_at.get(p, [])) or "not mapped")
                         for p in sorted(copies.get(path.rsplit("/", 1)[-1]) or {path}))

    def vtext(v):
        al = atts_of.get(v["id"], [])
        return (f"{v['id']}" + (f" (_name_id {v['name_id']})" if v["name_id"] != v["id"] else "") + f" {v['status']}, pool {pool(v['host'])}"
                + (f", migration {v['mig']}" if v["mig"] not in ("", "success") else "")
                + ("; " + ", ".join(f"{a['status']} on {disp(a['node'])} LUN {a['lun'] or '-'}" for a in al[:3]) if al else "; no attachment"))

    def what_now(x, n):
        if not x:
            return "not a Cinder LUN name", ""
        vs = by_name.get(x, [])
        if not vs:
            return "no live volume (deleted, or never Cinder)", ""
        cur = [v for v in vs if v["name_id"] == x]
        if not cur:
            return "old LUN of a migrated volume", "; ".join(vtext(v) for v in vs)
        al = [a for v in cur for a in atts_of.get(v["id"], [])]
        mine = [a for a in al if a["node"] == n]
        if mine:
            return "attachment here " + ", ".join(f"{a['status']} LUN {a['lun'] or '-'}" for a in mine), "; ".join(vtext(v) for v in cur)
        live = sorted({disp(a["node"]) for a in al if a["status"] == "attached"})
        if live:
            return "IN USE on " + ", ".join(live), "; ".join(vtext(v) for v in cur)
        return f"volume {cur[0]['status']}, not attached", "; ".join(vtext(v) for v in cur)

    def devices(n, lun):
        g = collections.OrderedDict()
        for x in nodes[n]["devs"]:
            if x["lun"] == lun and x["tgt"] in M["svm_iqns"]:
                g.setdefault((x["wwid"], x["dm"]), []).append(x)
        return [{"wwid": w, "dm": dm, "serial": netapp_serial(w), "paths": [f"{p['sd']}({p['state']})" for p in ps],
                 "users": nodes[n]["uses"].get(dm) or nodes[n]["uses"].get(ps[0]["sd"]) or []} for (w, dm), ps in g.items()]

    def devtext(devs):
        return "; ".join(f"{x['dm']} serial {x['serial'] or x['wwid']} ({' '.join(x['paths'])})"
                         + (f" used by {', '.join(x['users'])}" if x["users"] else " not used by a running domain") for x in devs) or "none"

    F = {"copy": [], "orphan": [], "mismatch": [], "device": [], "rows": [], "groups_of": groups_of, "init_nodes": init_nodes,
         "copies": copies, "mapped_at": mapped_at, "where": where, "path_uuid": path_uuid, "serials": serials, "by_name": by_name}
    for n in sorted(nodes, key=lambda s: [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", s)]):
        x = nodes[n]
        if x["role"] != "compute":
            continue
        nmap = collections.defaultdict(list)
        for g in groups_of.get(n, []):
            for m in maps_of.get(g, []):
                nmap[m["lun"]].append(m)
        attached = collections.defaultdict(list)
        for a in d["att"]:
            if a["node"] == n and a["status"] == "attached" and a["iqn"] in M["svm_iqns"] and a["lun"].isdigit():
                attached[int(a["lun"])].append(a)
        devs = collections.defaultdict(list)
        for dv in x["devs"]:
            if dv["tgt"] in M["svm_iqns"]:
                devs[dv["lun"]].append(dv)
        cnt = collections.Counter()
        for lun in sorted(nmap):   # mappings with no attachment at their number
            if attached.get(lun):
                continue
            for m in nmap[lun]:
                xid = lun_vid(m["path"])
                klass, now = what_now(xid, n)
                cur = [v for v in by_name.get(xid, []) if v["name_id"] == xid]
                if cur and flexvol(m["path"]) not in {pool(v["host"]) for v in cur}:
                    klass = f"copy in {flexvol(m['path'])}: {klass}"
                F["orphan"].append({"node": n, "lun": lun, "path": m["path"], "igroup": m["igroup"], "class": klass, "now": now,
                                    "devices": devtext(devices(n, lun)), "where": where(m["path"]) if len(copies.get(m["path"].rsplit("/", 1)[-1], ())) > 1 else ""})
                cnt["orphan"] += 1
        for lun in sorted(attached):
            for a in attached[lun]:
                v = vols.get(a["vol"])
                names = {a["vol"]} | ({v["name_id"]} if v else set())
                here = nmap.get(lun, [])
                good = [m for m in here if lun_vid(m["path"]) in names]
                if good:
                    if v and all(flexvol(m["path"]) != pool(v["host"]) for m in good):
                        m = good[0]
                        fv = flexvol(m["path"])
                        o = d["org"].get(a["id"]) or {}
                        cv = M["vols"].get(fv) or {}
                        made, cmade = utc(a["created"]), utc(cv.get("created"))
                        side = ("-" if not (made and cmade) else "after" if made > cmade else "BEFORE")
                        orig = f"/vol/{pool(v['host'])}/{m['path'].rsplit('/', 1)[-1]}"
                        dv = devices(n, lun)
                        ser_copy, ser_orig = serials.get(m["uuid"], ""), serials.get(path_uuid.get(orig, ""), "")
                        on = ("no device" if not dv else
                              ", ".join("the COPY" if ser_copy and s["serial"] == ser_copy else "the original" if ser_orig and s["serial"] == ser_orig
                                        else f"serial {s['serial'] or '?'}" + ("" if ser_copy else " (copy serial not read)") for s in dv))
                        F["copy"].append({"node": n, "lun": lun, "att": a, "vol": v, "path": m["path"], "uuid": m["uuid"], "clone": fv,
                                          "cv": cv, "org": o, "side": side, "orig": orig, "orig_uuid": path_uuid.get(orig, ""),
                                          "orig_where": ", ".join(f"{w} LUN {l}" for w, l in mapped_at.get(orig, [])) or
                                          ("not mapped" if orig in M["luns"] else "not in the SVM"),
                                          "device": on, "devices": devtext(dv), "where": where(m["path"])})
                        cnt["copy"] += 1
                    continue
                own = sorted(f"LUN {mm['lun']} {mm['path']}" for l2, lst in nmap.items() for mm in lst if lun_vid(mm["path"]) in names)
                for m in here or [None]:
                    y = lun_vid(m["path"]) if m else ""
                    F["mismatch"].append({"node": n, "lun": lun, "att": a, "vol": v, "path": m["path"] if m else "",
                                          "mapped_vol": what_now(y, n)[1] if m else "", "own": "; ".join(own) or "not mapped at any number",
                                          "devices": devtext(devices(n, lun))})
                    cnt["mismatch"] += 1
        for lun in sorted(devs):
            if lun in nmap:
                continue
            dv = devices(n, lun)
            F["device"].append({"node": n, "lun": lun, "devices": devtext(dv), "used": any(z["users"] for z in dv)})
            cnt["device"] += 1
        F["rows"].append([disp(n), (x["init"] + (" (from Cinder)" if x.get("init_from") else "")) if x["init"] else "-", ", ".join(g.split(" ", 1)[-1] for g in groups_of.get(n, [])) or "none",
                          sum(len(v) for v in nmap.values()), sum(len(v) for v in attached.values()), len(devs),
                          cnt["copy"], cnt["orphan"], cnt["mismatch"], cnt["device"], x["why"] or "read"])
    return F


class LunMapAudit:
    sources = ("openstack", "undercloud", "overcloud", "ontap")
    phases = 4

    @staticmethod
    def reads(phase, data, params, ctx):
        if phase == 1:
            return {"openstack": {"pools": "cinder get-pools"}, "undercloud": dict(overcloud.INVENTORY_READS),
                    "ontap": {"na_iscsi": "/api/protocols/san/iscsi/services?fields=svm.name,target.name"}}
        found, controllers, user, _version, _problem = inventory(data, ctx)
        if phase == 2:
            if user not in overcloud.USERS:
                return {}
            oc = {}
            ctl = next((c for c in controllers if c.get("ip")), None)
            if ctl:
                oc["db"] = overcloud.read(ctl["name"], ctl["ip"], user, "lm_db")
            for n in found:
                if n.get("role") in ("compute", "controller") and n.get("ip"):
                    oc[f"lmn_{n['name']}"] = overcloud.read(n["name"], n["ip"], user, "lm_node")
            return {"overcloud": oc} if oc else {}
        if phase == 3:   # NetApp: the lists of the SVM(s) whose target Cinder uses (all SVMs when that cannot be told)
            svms = chosen_svms(data)
            sets = {str(i): f"svm.name={q_ontap(s)}&" for i, s in enumerate(svms)} or {"all": ""}
            na = {}
            for k, f in sets.items():
                na[f"na_maps_{k}"] = f"/api/protocols/san/lun-maps?{f}fields=lun.name,lun.uuid,logical_unit_number,igroup.name,svm.name{TIMEOUT}"
                na[f"na_luns_{k}"] = f"/api/storage/luns?{f}fields=name,svm.name{TIMEOUT}"
                na[f"na_vols_{k}"] = f"/api/storage/volumes?{f}fields=name,svm.name,create_time,clone{TIMEOUT}"
                na[f"na_igroups_{k}"] = f"/api/protocols/san/igroups?{f}fields=name,svm.name,initiators{TIMEOUT}"
            return {"ontap": na}
        if phase == 4:   # NetApp: the serial of each copy an attachment runs on and of its original, by UUID
            F = findings(model(data, ctx))
            uuids = []
            for c in F["copy"]:
                uuids += [c["uuid"], c["orig_uuid"]]
            uuids = [u for u in dict.fromkeys(uuids) if re.fullmatch(UUID_ANY, u or "")][:MAX_SERIALS]
            return {"ontap": {f"na_ser_{i}": f"/api/storage/luns/{u}?fields=name,serial_number" for i, u in enumerate(uuids)}} if uuids else {}
        return {}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("lun-map-audit")
        M = model(data, ctx)
        d, nodes = M["db"], M["nodes"]
        db_why = unavailable(source(data, "db"))
        if M["problem"] or M["user"] not in overcloud.USERS:
            why = M["problem"] or "the overcloud user (heat-admin / tripleo-admin) is not known"
        else:
            why = db_why if db_why else ""
        computes = [n for n, x in nodes.items() if x["role"] == "compute"]
        down = [disp(x["name"]) for x in nodes.values() if x["why"]]
        na_read = bool(M["maps"]) and bool(M["igroups"])
        detail = (f"Cinder: {len(d['att'])} live attachment(s) ({sum(1 for a in d['att'] if a['status'] == 'attached')} attached), "
                  f"{len(d['vol'])} live volume(s)" + (f"; deleted attachments kept since {d['kept']}" if d["kept"] else "")
                  + f". Nodes: {len(nodes) - len(down)} of {len(nodes)} read ({len(computes)} computes)"
                  + (f", not read: {', '.join(down[:6])}" if down else "")
                  + f". NetApp: SVM {', '.join(M['svms']) or '(every SVM: the iSCSI services did not name the one Cinder uses)'}, target "
                  + f"{', '.join(sorted(M['svm_iqns'])) or '?'}: {len(M['maps'])} LUN map(s), {len(M['luns'])} LUN(s), {len(M['vols'])} volume(s), "
                  + f"{len(M['igroups'])} igroup(s)." + (f" Lists read only in part: {'; '.join(M['more'])}." if M["more"] else "")
                  + (f" Not read: {'; '.join(M['na_why'][:3])}." if M["na_why"] else ""))
        if why:
            r.step("sources", "What was read", "fail", f"The database of a controller was not read: {why}. " + detail)
            return r.done()
        if not na_read:
            r.step("sources", "What was read", "fail", "NetApp was not read (the Snapshot Restore account of the site, read-only REST): "
                   + ("; ".join(M["na_why"][:3]) or unavailable(source(data, "na_iscsi")) or "no LUN map or igroup") + ". " + detail)
            return r.done()
        F = findings(M, data)
        r.step("sources", "What was read", "warn" if down or M["more"] else "ok", detail,
               {"columns": ["Compute", "Initiator", "igroup(s)", "NetApp maps", "Attached (Cinder)", "LUN numbers with a device",
                            "On a clone copy", "Maps without attachment", "Number maps another LUN", "Devices not mapped", "Node read"],
                "rows": F["rows"]}, marks=[row[0] for row in F["rows"] if row[6] or row[8]])

        # ---- attachments on a copy of their LUN in a FlexClone
        cp = F["copy"]
        rows = []
        now = datetime.datetime.fromtimestamp(int(ctx.get("now") or time.time()), datetime.timezone.utc).replace(tzinfo=None)
        recent = [c for c in cp if now - datetime.timedelta(hours=24) < (utc(c["att"]["created"]) or datetime.datetime.min) <= now
                  + datetime.timedelta(hours=1)]
        came = collections.Counter(disp(short(c["org"]["prev"][1])) if c["org"].get("prev") else "?" for c in recent)
        for c in sorted(cp, key=lambda c: c["att"]["created"], reverse=True):   # the newest first: today's migrations on top
            a, v, o, cv = c["att"], c["vol"], c["org"], c["cv"]
            made_by = (f"{MOVES.get(o.get('action'), o.get('action'))} {o.get('start', '')[:16]}" if o.get("action") else "no Nova action within 2 h")
            prev = o.get("prev") or []
            mig = o.get("mig") or []
            rows.append([v["id"], v["size"], v["name"][:24], a["inst"], disp(c["node"]), c["lun"], c["path"],
                         (f"{cv.get('parent') or '?'} @ {cv.get('snapshot') or '?'}, made {cv.get('created') or '?'}" if cv.get("clone")
                          else f"made {cv.get('created') or '?'} (not a FlexClone)"),
                         a["created"], made_by, c["side"], c["device"], c["orig_where"],
                         (f"{disp(short(prev[1]))} LUN {prev[2] or '-'}, made {prev[3][:16]}, detached {prev[4][:16] or '-'}" if prev else "-"),
                         (f"{mig[0]} {mig[1]} {disp(short(mig[2]))} -> {disp(short(mig[3]))} {mig[4][:16]}" if mig else "-")])
        by_action = collections.Counter(MOVES.get(c["org"].get("action"), c["org"].get("action") or "none") for c in cp)
        by_side = collections.Counter(c["side"] for c in cp)
        by_clone = collections.Counter(c["clone"] for c in cp)
        r.step("clone_copies", "Instances running on a copy of their LUN in a FlexClone", "fail" if cp else "ok",
               (f"{len(cp)} attached volume(s) run on a LUN of the right name in a FlexVol that is not their Cinder pool"
                + (f" ({len(recent)} of them attached in the last 24 hours, coming from: "
                   + ", ".join(f"{k} {n}" for k, n in came.most_common()) + ")" if recent else "")
                + ": a FlexClone holds "
                "a copy of every LUN of its parent, from the snapshot it was made of, under the same name. The instance reads and writes "
                "that copy, not the volume's LUN in its pool. By clone: " + ", ".join(f"{k} {n}" for k, n in by_clone.most_common())
                + ". The attachment was made by: " + ", ".join(f"{k} {n}" for k, n in by_action.most_common())
                + "; after / before the clone was made: " + ", ".join(f"{k} {n}" for k, n in by_side.most_common())
                + ". An attachment made after the clone by a migration or an attach points at Cinder mapping the copy by its name; one made "
                "before it, at a mapping changed on NetApp by hand. Nothing is changed by this check: the owner decides what is the "
                "live data. Do not migrate, attach, detach or restart cinder-volume on these meanwhile.") if cp else
               "No attachment runs on a LUN outside its volume's Cinder pool.",
               {"columns": ["Volume", "GiB", "Name", "Instance", "Compute", "LUN", "Copy it runs on", "Clone of (snapshot), made",
                            "Attachment made (UTC)", "Made by", "vs clone", "Device on the compute is", "Original LUN mapped to",
                            "Before: attachment", "Last migration"], "rows": rows},
               marks=[c["vol"]["id"] for c in cp])

        # ---- mappings without a live attachment
        orph = F["orphan"]
        by = collections.Counter((disp(o["node"]), flexvol(o["path"])) for o in orph)
        kinds = collections.Counter(ckey(o["class"]) for o in orph)
        used = [o for o in orph if "used by" in o["devices"]]
        r.step("orphans", "NetApp mappings with no live Cinder attachment", "fail" if used else "warn" if orph else "ok",
               (f"{len(orph)} LUN number(s) mapped to a compute with no live Cinder attachment of that compute at that number: a rescan of "
                "its iSCSI sessions (an attach, a live migration to it, a path repair) shows it these disks, and LVM or multipath on "
                "the host may open a disk another instance writes. By compute and FlexVol: "
                + ", ".join(f"{n} {fv} {k}" for (n, fv), k in by.most_common(12)) + ". What the LUN's volume is now: "
                + ", ".join(f"{k} {n}" for k, n in kinds.most_common()) + "."
                + (f" {len(used)} of them have a device there that a running domain uses." if used else "")) if orph else
               "Every LUN number NetApp maps to a compute is a live Cinder attachment of that compute.",
               {"columns": ["Compute", "LUN", "LUN path", "igroup", "What its volume is now", "Volume", "Device on the compute",
                            "Every LUN of this name"],
                "rows": [[disp(o["node"]), o["lun"], o["path"], o["igroup"], o["class"], o["now"], o["devices"], o["where"]] for o in orph]},
               marks=[o["path"] for o in used])

        # ---- attachments whose number maps another LUN or nothing
        mm = F["mismatch"]
        r.step("mismatch", "Attachments whose LUN number maps another LUN or nothing", "fail" if mm else "ok",
               (f"{len(mm)} live attachment(s) whose LUN number, for their compute, maps a LUN named after neither the volume ID nor its "
                "_name_id, or nothing: the instance may run on another volume's disk, or lose its disk at the next rescan.") if mm else
               "Every attachment's LUN number maps the LUN of its own volume (its ID or _name_id).",
               {"columns": ["Compute", "LUN", "Volume (Cinder)", "Instance", "NetApp maps there", "That LUN's volume", "This volume's own LUN",
                            "Device on the compute"],
                "rows": [[disp(x["node"]), x["lun"], x["att"]["vol"], x["att"]["inst"], x["path"] or "nothing", x["mapped_vol"] or "-",
                          x["own"], x["devices"]] for x in mm]}, marks=[x["att"]["vol"] for x in mm])

        # ---- devices at numbers NetApp does not map
        dv = F["device"]
        busy = [x for x in dv if x["used"]]
        r.step("devices", "Devices on the computes at LUN numbers NetApp does not map", "fail" if busy else "warn" if dv else "ok",
               (f"{len(dv)} LUN number(s) with a SCSI device on a compute but no NetApp mapping for it at that number"
                + (f"; {len(busy)} used by a running domain (its I/O fails or goes to whatever the number maps next)" if busy else
                   "; none used by a running domain (stale paths: removing them is a host change for the owner)") + ".") if dv else
               "Every device on the computes' sessions to the SVM is at a number NetApp maps for that compute.",
               {"columns": ["Compute", "LUN", "Device(s)"], "rows": [[disp(x["node"]), x["lun"], x["devices"]] for x in dv]},
               marks=[str(x["lun"]) for x in busy])

        # ---- LUN names in more than one FlexVol
        dup = {name: ps for name, ps in F["copies"].items() if len({flexvol(p) for p in ps}) > 1}
        pools = {pool(v["host"]) for v in d["vol"].values()}
        fvs = collections.defaultdict(collections.Counter)
        for name, ps in F["copies"].items():
            for p in ps:
                c = fvs[flexvol(p)]
                c["luns"] += 1
                c["dup"] += name in dup
                c["mapped"] += bool(F["mapped_at"].get(p))
        frows = []
        for fv, c in sorted(fvs.items(), key=lambda x: (x[0] in pools, x[0])):
            if not (c["dup"] or (M["vols"].get(fv) or {}).get("clone")):
                continue
            v = M["vols"].get(fv) or {}
            frows.append([fv, "Cinder pool" if fv in pools else "FlexClone" if v.get("clone") else "other",
                          f"{v.get('parent') or '-'} @ {v.get('snapshot') or '-'}" if v.get("clone") else "-", v.get("created") or "-",
                          c["luns"], c["dup"], c["mapped"]])
        stray = sum(c["mapped"] for fv, c in fvs.items() if fv not in pools)
        r.step("duplicates", "LUN names in more than one FlexVol (FlexClone copies)", "warn" if stray else "info" if dup else "ok",
               (f"{len(dup)} LUN name(s) exist in more than one FlexVol of the SVM; {stray} LUN(s) outside a Cinder pool are mapped to an "
                "igroup. Cinder's NetApp driver finds a LUN by its name: with copies of the same name it may map or unmap a copy instead "
                "of the volume's LUN. A clone cleanup must leave every copy an instance runs on (see above).") if dup else
               "Every LUN name exists in one FlexVol only.",
               {"columns": ["FlexVol", "Kind", "Clone of (snapshot)", "Made", "LUNs", "Named like a LUN elsewhere", "Mapped"], "rows": frows},
               marks=[row[0] for row in frows if row[1] != "Cinder pool" and row[6]])

        # ---- Cinder pools and igroups
        out, st = [], "ok"
        pool_names = re.findall(r"\|\s*name\s*\|\s*(\S+#\S+)\s*\|", str(source(data, "pools").get("out") or ""))
        clone_pools = sorted(p for p in pool_names if (M["vols"].get(pool(p)) or {}).get("clone"))
        if clone_pools:
            st = "warn"
            out.append(f"Cinder reports {len(clone_pools)} FlexClone(s) as pools ({', '.join(clone_pools[:4])}): new volumes, retypes "
                       "and migrations may be placed in a clone (netapp_pool_name_search_pattern of the backend)")
        known = set(F["init_nodes"])
        noone = [(g, i) for g, i in M["igroups"].items() if not any(x in known for x in i) and any(m for m in M["maps"] if f"{m['svm']} {m['igroup']}" == g)]
        if noone:
            st = "warn"
            out.append(f"{len(noone)} igroup(s) with mappings hold no initiator of an overcloud node read now: "
                       + ", ".join(g.split(" ", 1)[-1] for g, _i in noone[:6]))
        for n in computes:
            if len(F["groups_of"].get(n, [])) != 1:
                st = "warn"
                out.append(f"{disp(n)} ({nodes[n]['init'] or 'initiator not read'}) is in {len(F['groups_of'].get(n, []))} igroup(s)")
            other = [a for a in d["att"] if a["node"] == n and a["init"] and nodes[n]["init"] and a["init"] != nodes[n]["init"]]
            if other:
                st = "warn"
                out.append(f"{disp(n)}: {len(other)} live attachment(s) made with another initiator than its own now")
        r.step("pools", "Cinder pools and igroups", st, ". ".join(out) + "." if out else
               ("Cinder reports no FlexClone as a pool" if pool_names else "Cinder's pools were not read")
               + "; every igroup with mappings belongs to a node read; each compute is in one igroup.")
        return r.done()

#!/usr/bin/env bash
# Read-only: the NetApp LUN mappings of every compute of a site against Cinder's live attachments and the SCSI devices on
# the compute (a real case: igroup openstack-2f804d56 of overcloud-novacomputeiha-8 maps 61 LUN numbers; 29 match a
# live Cinder attachment of iha-8, the other 32 are LUNs of DCAOPNSTACK_CINDER_15_vol with no attachment and no device:
# a rescan of iha-8's sessions would show it the disks of other volumes). The igroups of a compute are the igroups that
# hold its iSCSI initiator. Per compute:
#   1. NetApp mappings with no live Cinder attachment at that LUN number for that compute, with what the LUN's volume is now;
#   2. Cinder attachments (attached) whose LUN number maps a LUN named after neither the volume ID nor its _name_id
#      (2b: maps nothing); as a note, a LUN named right but in a FlexVol other than the volume's Cinder pool;
#   3. SCSI devices on the compute's sessions to the SVM at LUN numbers NetApp does not map for it (3b, when the file has
#      the LUN serials: a device at a mapped number that shows another LUN; the kernel keeps the WWID of its last scan);
#   2c. attachments that run on a COPY of their LUN in another FlexVol (a FlexClone holds every LUN of its parent under the
#      same name; a real case: 0d6e2b34 on iha-8 LUN 28 runs on /vol/snap_cinder_vol_clone_1/volume-1e7f3c45,
#      a clone of 24 Jun 2025, while the original in CINDER_15 stays mapped to another compute);
#   4. igroups that hold no initiator of an overcloud node, computes with no or several igroups, attachments whose connector
#      initiator is not the compute's initiator now, attachments to another target (not audited);
#   5. LUN names that exist in more than one FlexVol, and which copy is mapped to which compute.
# Then (unless --no-history), for every finding, when it was last touched: every Cinder row naming its volume (deleted ones
# too), their attachments (connector host and initiator, LUN, attach / detach / delete times), Nova's block device
# mappings, the Nova actions and migrations of their instances (for 2c: which action made the current attachment, before
# or after the clone was created), the cinder-api / cinder-volume lines of all controllers and the nova-compute lines of
# the compute that name them, the portal's volume migration / retype fixes on the site, the pools Cinder reports, the
# NetApp options of cinder.conf (named keys only) and the LUN table code of the installed NetApp driver.
# NetApp is not read here: the operator runs these ONTAP commands and saves their whole output in one file on the bastion
#   set -rows 0
#   vserver iscsi show -vserver <SVM> -fields target-name
#   igroup show -vserver <SVM> -fields initiator
#   lun mapped show -vserver <SVM> -fields igroup,lun-id,path
#   lun show -vserver <SVM> -fields serial                       (every LUN: section 5, 3b, the LUN of a device)
#   volume show -vserver <SVM> -fields create-time
#   volume clone show -vserver <SVM> -fields parent-volume,parent-snapshot
# SELECT / sysfs / virsh domblklist / grep of logs only. Of connection_info only the target IQN and LUN are selected (it
# holds the CHAP secret); log lines are masked for secrets. Times of the databases are UTC.
# Same path as the portal: portal service account -> management host -> director -> controller (galera, logs) / computes.
# Run on the bastion:  sudo bash ~/lun-map-audit.sh <SITE> <ONTAP output file> [--no-history]
# Again from the data a run saved (no overcloud access, no sudo):  bash ~/lun-map-audit.sh --reanalyze <its .raw folder>
set -u
SVC=opsportal
PY=/opt/ops-portal/.venv/bin/python
DB=/var/lib/ops-portal/portal.db
TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT

# ---- the comparison, on the bastion: ontap (parse the file), analyze (sections 1-4), portal (fixes), history
IFS= read -r -d '' AUDIT <<'PYEOF' || true
import collections, datetime, json, os, re, sqlite3, sys

U = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
NETAPP = "3600a0980"
ATT = ("id", "vol", "inst", "status", "ahost", "chost", "cinit", "iqn", "lun", "attached", "updated", "created")
VOL = ("id", "name_id", "status", "astat", "mig", "host", "size", "updated", "created", "name")
HVOL = ("id", "name_id", "deleted", "deleted_at", "status", "astat", "mig", "host", "size", "created", "updated", "name")
HATT = ("id", "vol", "deleted", "deleted_at", "inst", "status", "ahost", "chost", "cinit", "lun", "attached", "detached",
        "created", "updated")
HBDM = ("vol", "inst", "deleted", "deleted_at", "attachment", "created", "updated", "lun")
HACT = ("inst", "action", "req", "start", "finish", "user", "host", "ideleted", "iname")
HMIG = ("inst", "id", "type", "status", "source", "dest", "created", "updated")
MOVES = ("live-migration", "live_migration", "migrate", "resize", "evacuate", "unshelve", "attach_volume", "swap_volume", "rebuild",
         "confirmResize", "revertResize")
KIND = {"1": "NetApp map, no live attachment", "2": "attachment, its number maps another LUN",
        "2b": "attachment, its number maps nothing", "2c": "attachment runs on a FlexClone copy", "3": "device, number not mapped",
        "3b": "device shows another LUN"}


def short(h):
    h = (h or "").strip()
    return h.split(".")[0].lower() if h and h != "-" else "-"


def natural(s):
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", s)]


def lun_vid(path):
    m = re.fullmatch(r"volume-(" + U + ")", (path or "").rsplit("/", 1)[-1])
    return m.group(1) if m else None


def flexvol(path):
    p = path.split("/")
    return p[2] if len(p) > 3 and p[1] == "vol" else "?"


def pool(host):
    return host.split("#")[-1] if host and "#" in host else "?"


def serial(wwid):
    if not wwid.startswith(NETAPP) or len(wwid) != 33:
        return None
    try:
        return bytes.fromhex(wwid[9:]).decode("latin-1")
    except ValueError:
        return None


def tsv(line, cols):
    f = line.rstrip("\n").split("\t")[1:]
    return dict(zip(cols, f)) if len(f) >= len(cols) else None


def when(t):
    try:
        return datetime.datetime.strptime(t[:19], "%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return None


def ckey(text):   # the kind of a class text, without its IDs and hosts
    return re.split(r" \(| on |: ", text)[0]


def disp(n):
    return n[10:] if n.startswith("overcloud-") else n


def name_of(v):   # the LUN a live volume uses now: volume-<_name_id> after a migration or retype, else volume-<ID>
    return v["name_id"] if v.get("name_id") not in (None, "", "-") else v["id"]


# ---------------- ontap: the operator's output of the ONTAP commands, as tables with a header and a dash line
def take(o, r):
    vs = r.get("vserver", "")
    if {"path", "igroup", "lun-id"} <= r.keys():
        if r["path"].startswith("/vol/") and r["lun-id"].isdigit():
            o["maps"].append([vs, r["igroup"], int(r["lun-id"]), r["path"]])
            return True
    elif {"igroup", "initiator"} <= r.keys():
        inits = [i.strip().lower() for i in r["initiator"].split(",") if i.strip() not in ("", "-")]
        if all(i.startswith(("iqn.", "eui.", "naa.")) or re.fullmatch(r"([0-9a-f]{2}:){7}[0-9a-f]{2}", i) for i in inits):
            o["igroups"][f"{vs} {r['igroup']}"] = inits
            return True
    elif "path" in r and ("serial" in r or "serial-hex" in r):
        s = r.get("serial")
        if "serial-hex" in r:
            try:
                s = bytes.fromhex(r["serial-hex"]).decode("latin-1")
            except ValueError:
                s = None
        if r["path"].startswith("/vol/") and s and len(s) == 12:
            o["serials"][r["path"]] = s
            return True
    elif "target-name" in r:
        if r["target-name"].startswith("iqn."):
            o["targets"][vs] = r["target-name"].lower()
            return True
    elif {"flexclone", "parent-volume"} <= r.keys():
        o["clones"][r["flexclone"]] = {"parent": r["parent-volume"], "snapshot": r.get("parent-snapshot", "-")}
        return True
    elif {"volume", "create-time"} <= r.keys():
        o["created"][r["volume"]] = r["create-time"]
        return True
    return False


def ontime(t):   # an ONTAP time ("Thu Jun 26 08:35:21 2025", the cluster's own time zone)
    try:
        return datetime.datetime.strptime(" ".join((t or "").split()[:5]), "%a %b %d %H:%M:%S %Y")
    except ValueError:
        return None


def ontap(path, out):
    lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    tok = [l.split() for l in lines]
    dash = [i for i in range(1, len(lines)) if tok[i] and all(set(t) == {"-"} for t in tok[i]) and len(tok[i - 1]) == len(tok[i])]
    o = {"maps": [], "igroups": {}, "serials": {}, "targets": {}, "clones": {}, "created": {}}
    skipped, sections = [], []
    for k, d in enumerate(dash):
        cols = [c.lower() for c in tok[d - 1]]
        n = 0
        for line in lines[d + 1:dash[k + 1] - 1 if k + 1 < len(dash) else len(lines)]:
            t = line.split()
            if not t or "::>" in line or re.match(r"\d+ entr(y|ies) (was|were) displayed", line.strip()):
                continue
            if len(t) > len(cols):
                t = t[:len(cols) - 1] + [" ".join(t[len(cols) - 1:])]
            if len(t) == len(cols) and take(o, dict(zip(cols, t))):
                n += 1
            else:
                skipped.append(line)
        sections.append(f"[{' '.join(cols)}] {n} row(s)")
    json.dump(o, open(out, "w"))
    groups = {(m[0], m[1]) for m in o["maps"]}
    print(f"== ONTAP file {path}: {'; '.join(sections) or 'no table found'}")
    print(f"   {len(o['maps'])} mappings in {len(groups)} igroup(s) (vserver {', '.join(sorted({m[0] for m in o['maps']})) or '-'}); "
          f"{len(o['igroups'])} igroup(s) with their initiators; {len(o['serials'])} LUN serial(s); "
          f"SVM target: {', '.join(f'{k} {v}' for k, v in o['targets'].items()) or 'not in the file'}; "
          f"{len(o['created'])} volume create time(s); {len(o['clones'])} FlexClone(s)")
    for line in skipped[:5]:
        print(f"   not understood: {line[:200]}")
    if len(skipped) > 5:
        print(f"   ... {len(skipped)} line(s) not understood in all")
    miss = sorted(f"{vs} {g}" for vs, g in groups if f"{vs} {g}" not in o["igroups"])
    if miss:
        print(f"   !! {len(miss)} igroup(s) with mappings are not in the igroup output (their computes cannot be named): {', '.join(miss[:5])}")
    if not o["maps"]:
        print("No 'lun mapped show -fields igroup,lun-id,path' table in the file: nothing to compare.")
        return 1
    if not o["igroups"]:
        print("No 'igroup show -fields initiator' table in the file: the igroups cannot be matched to the computes.")
        return 1
    return 0


def copies_in(copies, fv):
    return [p_ for ps in copies.values() for p_ in ps if flexvol(p_) == fv]


# ---------------- analyze: sections 1-5 from ontap.json and p1.txt
def read_p1(raw):
    s = {"nodes": {}, "devs": collections.defaultdict(list), "uses": collections.defaultdict(lambda: collections.defaultdict(list)),
         "atts": [], "vols": {}, "errs": [], "other": [], "stamps": []}
    for line in open(os.path.join(raw, "p1.txt"), encoding="utf-8", errors="replace"):
        line = line.rstrip("\n")
        f = line.split()
        if line.startswith("att\t"):
            r = tsv(line, ATT)
            if r:
                s["atts"].append(r)
        elif line.startswith("vol\t"):
            r = tsv(line, VOL)
            if r:
                s["vols"][r["id"]] = r
        elif line.startswith("@@node ") and len(f) >= 4:
            s["nodes"][f[2].lower()] = {"role": f[1], "fqdn": f[3], "init": (f[4] if len(f) > 4 else "-").lower()}
        elif line.startswith("@@dev ") and len(f) == 10:
            n, sd, hctl, st, tgt, wwid, size, dm, dmname = f[1:]
            lun = hctl.rsplit(":", 1)[-1]
            if lun.isdigit():
                s["devs"][n.lower()].append({"sd": sd, "hctl": hctl, "lun": int(lun), "state": st, "tgt": tgt.lower(), "wwid": wwid,
                                     "size": size, "dm": dm, "dmname": dmname})
        elif line.startswith("@@use ") and len(f) >= 6:
            s["uses"][f[1].lower()][f[2]].append(f"{f[3]} ({f[4]} {f[5]})")
        elif line.startswith(("@@begin", "@@end")):
            s["stamps"].append(line[2:])
        elif line.startswith("@@err"):
            s["errs"].append(line[6:])
        elif line.strip():
            s["other"].append(line)
    return s


def analyze(raw, work):
    o = json.load(open(os.path.join(raw, "ontap.json")))
    p = read_p1(raw)
    nodes, devs, uses, atts, vols = p["nodes"], p["devs"], p["uses"], p["atts"], p["vols"]
    print(f"\n== Overcloud read {' .. '.join(p['stamps'])}: {sum(1 for d in nodes.values() if d['role'] == 'compute')} compute(s), "
          f"{sum(1 for d in nodes.values() if d['role'] == 'controller')} controller(s); Cinder: {len(atts)} live attachment(s) "
          f"({sum(1 for a in atts if a['status'] == 'attached')} attached), {len(vols)} live volume(s)")
    for e in p["errs"]:
        print(f"   !! {e[:300]}")
    for line in p["other"][:8]:
        print(f"   (other output) {line[:300]}")
    if not atts or not nodes:
        print("Cinder or the nodes could not be read: nothing to compare.")
        return 1
    svm = set(o["targets"].values())
    if not svm:
        c = collections.Counter(a["iqn"].lower() for a in atts if a["status"] == "attached" and a["iqn"].startswith("iqn."))
        svm = {c.most_common(1)[0][0]} if c else set()
        print(f"   No target name in the ONTAP file: the SVM is taken as the target of most attachments: {', '.join(svm)}")
    by_name = collections.defaultdict(list)   # the ID in a LUN name -> live volumes with that ID or _name_id
    for v in vols.values():
        by_name[v["id"]].append(v)
        if v["name_id"] not in ("-", "", v["id"]):
            by_name[v["name_id"]].append(v)
    for a in atts:
        a["node"] = short(a["chost"]) if a["chost"] != "-" else short(a["ahost"])
        a["iqn"] = a["iqn"].lower()
    host_atts, atts_of = collections.defaultdict(list), collections.defaultdict(list)
    for a in atts:
        host_atts[a["node"]].append(a)
        atts_of[a["vol"]].append(a)
    maps_of = collections.defaultdict(list)
    for vs, g, lun, path in o["maps"]:
        maps_of[f"{vs} {g}"].append((lun, path))
    init_nodes = collections.defaultdict(list)
    for n, d in nodes.items():
        if d["init"] != "-":
            init_nodes[d["init"]].append(n)
    groups_of = collections.defaultdict(list)
    for g, inits in o["igroups"].items():
        for i in inits:
            for n in init_nodes.get(i, []):
                groups_of[n].append(g)
    path_of_serial = {s: p_ for p_, s in o["serials"].items()}
    clones, created = o.get("clones", {}), o.get("created", {})
    group_nodes = {g: sorted({n for i in inits for n in init_nodes.get(i, [])}) for g, inits in o["igroups"].items()}
    mapped_at = collections.defaultdict(list)   # LUN path -> [(compute(s) or igroup, LUN number)]
    for vs, g, lun, path in o["maps"]:
        mapped_at[path].append(("/".join(disp(x) for x in group_nodes.get(f"{vs} {g}", [])) or g, lun))
    copies = collections.defaultdict(set)   # LUN name -> its paths in the SVM
    for path in list(o["serials"]) + [m[3] for m in o["maps"]]:
        copies[path.rsplit("/", 1)[-1]].add(path)

    def fvdesc(fv):
        c = clones.get(fv)
        return fv + (f" [FlexClone of {c['parent']} @ {c['snapshot']}]" if c else "") + (f" created {created[fv]}" if fv in created else "")

    def copiesdesc(path):   # every LUN of that name and where it is mapped
        return "; ".join(f"{flexvol(p_)}: " + (", ".join(f"{x} LUN {l}" for x, l in mapped_at.get(p_, [])) or "not mapped")
                         for p_ in sorted(copies.get(path.rsplit("/", 1)[-1]) or {path}))

    def vdesc(v):
        s = v["id"] + (f" (_name_id {v['name_id']})" if v["name_id"] not in ("-", "", v["id"]) else "")
        s += f" {v['status']}/{v['astat']}" + (f" migration {v['mig']}" if v["mig"] not in ("-", "", "success") else "")
        s += f", pool {pool(v['host'])}, {v['size']} GiB, updated {v['updated']}, '{v['name'][:30]}'"
        al = atts_of.get(v["id"], [])
        s += ("; attachments: " + ", ".join(f"{a['status']} {a['node']} LUN {a['lun']}" for a in al[:4]) + (f" +{len(al) - 4}" if len(al) > 4 else "")
              ) if al else "; no live attachment"
        return s

    def luninfo(x):   # the live volume(s) a LUN name points at
        if not x:
            return ["not named volume-<ID>: not a LUN Cinder made"]
        vs = by_name.get(x, [])
        return [vdesc(v) for v in vs] or [f"no live Cinder volume has ID or _name_id {x} (deleted, or never a Cinder volume)"]

    def devdesc(n, lun):
        g = collections.OrderedDict()
        for d in devs.get(n, []):
            if d["lun"] == lun and d["tgt"] in svm:
                g.setdefault((d["wwid"], d["dm"], d["dmname"], d["size"]), []).append(f"{d['sd']}({d['state']})")
        out = []
        for (wwid, dm, dmname, size), sds in g.items():
            ser = serial(wwid)
            at = path_of_serial.get(ser) if ser else None
            u = uses[n].get(dm) or uses[n].get(sds[0].split("(")[0]) or []
            out.append(f"{' '.join(sds)} WWID {wwid}" + (f" serial {ser}" if ser else "") + (f" = {at}" if at else "")
                       + f", {int(size) // 2 ** 30 if size.isdigit() else size} GiB, map {dm}"
                       + (f", used by {', '.join(u)}" if u else ", used by no running domain"))
        return out

    def cls1(x, n):   # why a mapped LUN has no attachment on this compute: what its volume is now
        if not x:
            return "not a Cinder LUN name"
        vs = by_name.get(x, [])
        if not vs:
            return "no live volume (deleted or never Cinder)"
        cur = [v for v in vs if name_of(v) == x]
        if not cur:
            return "old LUN of a migrated volume (Cinder uses volume-" + "/".join(name_of(v)[:8] for v in vs) + ")"
        al = [a for v in cur for a in atts_of.get(v["id"], [])]
        mine = [a for a in al if a["node"] == n]
        if mine:
            return "attachment here: " + ", ".join(f"{a['status']} LUN {a['lun']}" for a in mine)
        live = sorted({a["node"] for a in al if a["status"] == "attached"})
        if live:
            return "IN USE on " + ", ".join(live)
        if al:
            return "attachment(s) " + ", ".join(f"{a['status']} on {a['node']}" for a in al)
        return f"volume {cur[0]['status']}, no attachment"

    findings, rows, sec = [], [], {k: [] for k in ("1", "2", "2b", "2c", "3", "3b")}
    computes = sorted((n for n, d in nodes.items() if d["role"] == "compute"), key=natural)
    for n in computes:
        init = nodes[n]["init"]
        gs = groups_of.get(n, [])
        nmap = collections.defaultdict(list)
        for g in gs:
            for lun, path in maps_of.get(g, []):
                nmap[lun].append((path, g.split(" ", 1)[-1]))
        A = host_atts.get(n, [])
        attached = collections.defaultdict(list)
        for a in A:
            if a["status"] == "attached" and a["iqn"] in svm and a["lun"].isdigit():
                attached[int(a["lun"])].append(a)
        D = collections.defaultdict(list)
        for d in devs.get(n, []):
            if d["tgt"] in svm:
                D[d["lun"]].append(d)
        cnt = collections.Counter()

        def add(kind, lun, text, ids, path="", igroup="", klass="", att="", **extra):
            f = {"kind": kind, "node": n, "lun": lun, "path": path, "igroup": igroup, "class": klass,
                 "ids": sorted({i for i in ids if i and re.fullmatch(U, i)}), "atts": [att] if att else [], "init": init}
            f.update(extra)
            findings.append(f)
            sec[kind].append((f, text))
            cnt[kind] += 1

        for lun in sorted(nmap):
            for path, g in nmap[lun]:
                x = lun_vid(path)
                here = attached.get(lun, [])
                if here:   # this number has an attachment: section 2 judges whether it is this LUN
                    continue
                k = cls1(x, n)
                cur = [v for v in by_name.get(x, []) if name_of(v) == x]
                if cur and flexvol(path) not in {pool(v["host"]) for v in cur}:
                    k = f"copy in {flexvol(path)}; {k}"
                add("1", lun, [f"LUN {lun} {path} (igroup {g}): {k}"] + [f"   LUN's volume: {s}" for s in luninfo(x)]
                    + ([f"   every LUN of this name: {copiesdesc(path)}"] if len(copies.get(path.rsplit('/', 1)[-1], ())) > 1 else [])
                    + [f"   device here: {s}" for s in devdesc(n, lun) or ["none"]],
                    [x] + [v["id"] for v in by_name.get(x, [])], path, g, k)
        for lun in sorted(attached):
            for a in attached[lun]:
                v = vols.get(a["vol"])
                names = {a["vol"]} | ({v["name_id"]} if v and v["name_id"] not in ("-", "") else set())
                here = nmap.get(lun, [])
                good = [p_ for p_, g in here if lun_vid(p_) in names]
                vtxt = vdesc(v) if v else f"{a['vol']} (no live volume row)"
                if good:
                    if v and all(flexvol(p_) != pool(v["host"]) for p_ in good):
                        fv = flexvol(good[0])
                        add("2c", lun, [f"LUN {lun} {good[0]}: volume {a['vol']} ({v['status']}, Cinder pool {pool(v['host'])}, "
                                        f"{v['size']} GiB, '{v['name'][:30]}') runs on the copy in {fvdesc(fv)}",
                                        f"   attachment {a['id']} of instance {a['inst']}, created {a['created']}, attached {a['attached']}",
                                        f"   every LUN of this name: {copiesdesc(good[0])}"]
                            + [f"   device here: {s}" for s in devdesc(n, lun) or ["none"]],
                            [a["vol"], v["name_id"]], good[0], att=a["id"], klass=f"copy in {fv}", vol=a["vol"], inst=a["inst"],
                            clone=fv, clone_created=created.get(fv, ""), att_created=a["created"], vname=v["name"][:30], size=v["size"],
                            orig=copiesdesc(f"/vol/{pool(v['host'])}/{good[0].rsplit('/', 1)[-1]}"))
                    continue
                own = sorted(f"LUN {m} {p_}" for m, lst in nmap.items() for p_, g in lst if lun_vid(p_) in names)
                base = [f"   attachment {a['id']} of instance {a['inst']} since {a['attached']}; volume {vtxt}",
                        "   this volume's own LUN for this compute: " + ("; ".join(own) if own else "not mapped at any number")]
                dv = [f"   device here: {s}" for s in devdesc(n, lun) or ["none"]]
                if here:
                    for p_, g in here:
                        y = lun_vid(p_)
                        add("2", lun, [f"LUN {lun} maps {p_} (igroup {g}), Cinder says volume {a['vol']}"] + base
                            + [f"   mapped LUN's volume: {s}" for s in luninfo(y)] + dv,
                            [a["vol"], v["name_id"] if v else "", y] + [w["id"] for w in by_name.get(y, [])], p_, g, att=a["id"])
                else:
                    add("2b", lun, [f"LUN {lun}: Cinder says volume {a['vol']}, NetApp maps nothing at {lun} for this compute"] + base + dv,
                        [a["vol"], v["name_id"] if v else ""], att=a["id"])
        for lun in sorted(D):
            if lun not in nmap:
                at = [path_of_serial.get(serial(d["wwid"]) or "") for d in D[lun]]
                y = next((lun_vid(t) for t in at if t), None)
                add("3", lun, [f"LUN {lun}: device(s) on the compute, NetApp maps nothing at {lun} for it"]
                    + [f"   device: {s}" for s in devdesc(n, lun)] + ([f"   its LUN's volume: {s}" for s in luninfo(y)] if y else []),
                    [y] + [w["id"] for w in by_name.get(y, [])] if y else [])
            elif o["serials"]:
                want = {o["serials"].get(p_) for p_, g in nmap[lun]} - {None}
                bad = [d for d in D[lun] if want and serial(d["wwid"]) and serial(d["wwid"]) not in want]
                if bad:
                    add("3b", lun, [f"LUN {lun} maps {', '.join(p_ for p_, g in nmap[lun])} (serial {', '.join(sorted(want))}), "
                                    f"but the device(s) keep another WWID"] + [f"   device: {s}" for s in devdesc(n, lun)],
                        [lun_vid(p_) for p_, g in nmap[lun]])
        nd = sum(1 for lun in D)
        rows.append((n, init, ",".join(g.split(" ", 1)[-1][:22] for g in gs) or "NONE", sum(len(x) for x in nmap.values()),
                     sum(len(x) for x in attached.values()), nd, cnt))

    print(f"\n== Per compute (SVM target {', '.join(sorted(svm))}): NetApp mappings for its igroup(s), Cinder attachments (attached) "
          "to the SVM, LUN numbers with a device; findings by section")
    print(f"   {'compute':32} {'initiator':40} {'igroup(s)':24} {'maps':>5} {'att':>5} {'dev':>5} {'1':>4} {'2':>4} {'2b':>4} {'2c':>4} {'3':>4} {'3b':>4}")
    for n, init, gs, nm, na, nd, c in rows:
        print(f"   {n:32} {init:40} {gs:24} {nm:5} {na:5} {nd:5} {c['1']:4} {c['2']:4} {c['2b']:4} {c['2c']:4} {c['3']:4} {c['3b']:4}")
    titles = {"1": "1. NetApp mappings with no live Cinder attachment at that LUN number for that compute",
              "2": "2. Attachments (attached) whose LUN number maps a LUN named after neither the volume ID nor its _name_id",
              "2b": "2b. Attachments (attached) whose LUN number NetApp does not map for the compute",
              "3": "3. SCSI devices at LUN numbers NetApp does not map for the compute",
              "3b": "3b. SCSI devices at a mapped LUN number that keep another LUN's WWID (needs the LUN serials)",
              "2c": "2c. Attachments (attached) that run on a COPY of their LUN in a FlexVol other than the volume's Cinder pool (a FlexClone)"}
    for k in ("1", "2", "2b", "2c", "3", "3b"):
        print(f"\n== {titles[k]}: {len(sec[k])}" + ("" if o["serials"] or k != "3b" else " (no LUN serials in the ONTAP file: not checked)"))
        last = None
        for f, text in sec[k]:
            if f["node"] != last:
                last = f["node"]
                if k == "1":
                    byvol = collections.Counter(flexvol(x["path"]) for x, t in sec[k] if x["node"] == last)
                    bycls = collections.Counter(ckey(x["class"]) for x, t in sec[k] if x["node"] == last)
                    print(f"-- {last}: by FlexVol {dict(byvol)}; by what the volume is now {dict(bycls)}")
                else:
                    print(f"-- {last}")
            for t in text:
                print("   " + t[:600])

    print("\n== 4. igroups and initiators")
    known = set(init_nodes)
    noone = [(g, inits) for g, inits in o["igroups"].items() if not any(i in known for i in inits) and maps_of.get(g)]
    print(f"   igroups with mappings that hold no initiator of an overcloud node read now: {len(noone)}")
    for g, inits in sorted(noone, key=lambda x: -len(maps_of[x[0]]))[:30]:
        fv = collections.Counter(flexvol(p_) for l_, p_ in maps_of[g])
        print(f"      {g.split(' ', 1)[-1]}: {len(maps_of[g])} mapping(s) {dict(fv.most_common(4))}, initiator(s) {', '.join(inits) or 'none'}")
    for g, inits in o["igroups"].items():
        owners = sorted({n for i in inits for n in init_nodes.get(i, [])})
        if len(owners) > 1:
            print(f"   !! igroup {g.split(' ', 1)[-1]} holds initiators of {len(owners)} nodes: {', '.join(owners)}")
    for i, ns in init_nodes.items():
        if len(ns) > 1:
            print(f"   !! initiator {i} is on {len(ns)} nodes: {', '.join(ns)}")
    for n in computes:
        if len(groups_of.get(n, [])) != 1:
            print(f"   !! {n} ({nodes[n]['init']}) is in {len(groups_of.get(n, []))} igroup(s): "
                  f"{', '.join(g.split(' ', 1)[-1] for g in groups_of.get(n, [])) or '-'}")
    for n in computes:
        A = host_atts.get(n, [])
        other = [a for a in A if a["cinit"] not in ("-", "") and a["cinit"].lower() != nodes[n]["init"]]
        if other:
            print(f"   !! {n}: {len(other)} live attachment(s) were made with another initiator than its own now "
                  f"({nodes[n]['init']}): " + ", ".join(f"{a['id'][:8]} {a['cinit']}" for a in other[:3]))
        tg = collections.Counter(a["iqn"] for a in A if a["iqn"] not in svm and a["iqn"] != "-")
        if tg:
            print(f"   {n}: {sum(tg.values())} live attachment(s) to another target (not audited): {dict(tg)}")
        nc = collections.Counter(a["status"] for a in A if a["status"] != "attached")
        if nc:
            print(f"   {n}: live attachment(s) not attached: {dict(nc)}")
    hosts = set(nodes)
    lost = collections.Counter(a["node"] for a in atts if a["node"] not in hosts and a["status"] == "attached")
    if lost:
        print(f"   attached attachments on hosts that are not overcloud nodes read now: {dict(lost.most_common(8))}")

    print("\n== 5. LUN names in more than one FlexVol of the SVM" + ("" if o["serials"] else " (no lun show in the ONTAP file: only mapped LUNs are known)"))
    dup = {name: ps for name, ps in copies.items() if len({flexvol(p_) for p_ in ps}) > 1}
    print(f"   {len(dup)} LUN name(s) exist in more than one FlexVol")
    fvs = collections.defaultdict(lambda: collections.Counter())
    for path in set(o["serials"]) | {m[3] for m in o["maps"]}:
        c = fvs[flexvol(path)]
        c["luns"] += 1
        c["dup"] += path.rsplit("/", 1)[-1] in dup
        c["mapped"] += bool(mapped_at.get(path))
    pools = {pool(v["host"]) for v in vols.values()}
    for fv, c in sorted(fvs.items(), key=lambda x: (x[0] in pools, x[0])):
        if c["dup"] or fv in clones:
            ig = {x for p_ in copies_in(copies, fv) for x, l in mapped_at.get(p_, [])}
            print(f"   {fvdesc(fv)}{' (a Cinder pool)' if fv in pools else ''}: {c['luns']} LUN(s), {c['dup']} share a name with "
                  f"another FlexVol, {c['mapped']} mapped" + (f" to {len(ig)} compute(s)/igroup(s)" if ig else ""))
    att_paths = {f["path"] for f in findings if f["kind"] == "2c"}
    stray = []
    for name, ps in sorted(dup.items()):
        x = lun_vid(name)
        home = {pool(v["host"]) for v in by_name.get(x, [])}
        for p_ in sorted(ps):
            if mapped_at.get(p_) and flexvol(p_) not in home and p_ not in att_paths:
                stray.append((p_, x))
    print(f"   mapped copies outside the volume's Cinder pool that no attachment uses (2c lists the used ones): {len(stray)}")
    for p_, x in stray[:150]:
        print(f"      {p_}: {copiesdesc(p_)}; volume now: {' | '.join(luninfo(x))[:250]}")
    if len(stray) > 150:
        print(f"      ... {len(stray) - 150} more")

    json.dump({"findings": findings}, open(os.path.join(work, "findings.json"), "w"))
    ids = sorted({i for f in findings for i in f["ids"] if re.fullmatch(U, i)})
    open(os.path.join(work, "ids.txt"), "w").write("\n".join(ids) + ("\n" if ids else ""))
    fnodes = sorted({f["node"] for f in findings}, key=natural)
    open(os.path.join(work, "nodes.txt"), "w").write("\n".join(fnodes) + ("\n" if fnodes else ""))
    print(f"\n== {len(findings)} finding(s) on {len(fnodes)} compute(s); {len(ids)} ID(s) for the history")
    return 0


# ---------------- portal: the volume migration and retype fixes of the site, from the portal's database (read-only)
def portal(db, site, out):
    res = {"fixes": [], "error": ""}
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        q = con.execute("SELECT a.id, a.ts, a.finished, a.status, a.username, a.commands, a.output, a.error, r.id AS run, r.check_id "
                        "FROM wi_actions a JOIN wi_runs r ON r.id = a.run_id WHERE r.site = ? AND (a.commands LIKE '%migrate-volume %' "
                        "OR a.commands LIKE '%retype-volume %') ORDER BY a.id", (site,))
        for r in q:
            try:
                cmds = json.loads(r["commands"] or "[]")
            except ValueError:
                cmds = []
            try:
                steps = json.loads(r["output"] or "[]")
                steps = steps if isinstance(steps, list) else []
            except ValueError:
                steps = []
            items = []
            for c in cmds:
                c = str(c)
                if not c.startswith(("migrate-volume ", "retype-volume ")):
                    continue
                t = c.split()
                st = next((s for s in steps if isinstance(s, dict) and s.get("command") == c), {})
                text = str(st.get("out") or "")
                result = next((l for l in reversed(text.splitlines()) if l.startswith("RESULT ")), "")
                src = re.search(r", on (\S+)\s*$", text, re.M)
                items.append({"op": t[0], "vol": t[1] if len(t) > 1 else "", "to": t[t.index("to") + 1] if "to" in t[:-1] else "",
                              "rc": st.get("rc"), "from": src.group(1) if src else "", "result": result[:300],
                              "attempts": [l.strip()[:200] for l in text.splitlines() if re.match(r"\s*(Attempt \d|Automatic fix|The migration of)", l)][:6]})
            res["fixes"].append({"id": r["id"], "ts": r["ts"], "finished": r["finished"], "status": r["status"], "user": r["username"],
                                 "run": r["run"], "check": r["check_id"], "error": (r["error"] or "")[:300], "items": items})
    except Exception as e:   # the portal database is optional for the audit
        res["error"] = f"{type(e).__name__}: {e}"
    json.dump(res, open(out, "w"))
    return 0


# ---------------- history: when each finding was last touched
def history(raw, work):
    F = json.load(open(os.path.join(work, "findings.json")))["findings"]
    hv, ha, hb, hc, hm, logs, win, mins, errs, code = [], [], [], [], [], [], [], [], [], []
    for line in open(os.path.join(raw, "p2.txt"), encoding="utf-8", errors="replace"):
        line = line.rstrip("\n")
        for tag, cols, lst in (("hvol\t", HVOL, hv), ("hatt\t", HATT, ha), ("hbdm\t", HBDM, hb), ("hact\t", HACT, hc), ("hmig\t", HMIG, hm)):
            if line.startswith(tag):
                r = tsv(line, cols)
                if r:
                    lst.append(r)
                break
        else:
            if line.startswith("hmin\t"):
                mins = line.split("\t")[1:]
            elif line.startswith("@@log "):
                f = line.split(" ", 3)
                if len(f) == 4:
                    logs.append((f[1], f[2], f[3]))
            elif line.startswith("@@logwin "):
                win.append(line[9:])
            elif line.startswith(("@@code ", "@@pool ")):
                code.append(line)
            elif line.startswith("@@err") or (line.strip() and not line.startswith("@@")):
                errs.append(line)
    pj = os.path.join(raw, "p3.json")
    portal_ = json.load(open(pj)) if os.path.exists(pj) else {"fixes": [], "error": "not read"}
    print("\n\n######## History of the findings")
    if mins:
        print(f"   Cinder keeps deleted volumes since {mins[0]}, deleted attachments since {mins[1]}; Nova actions since "
              f"{mins[2] if len(mins) > 2 else '-'} (older rows were purged or archived)")
    for w in win:
        print(f"   log {w}")
    for e in errs[:10]:
        print(f"   !! {e[:300]}")
    rows_of = collections.defaultdict(list)
    for r in hv:
        rows_of[r["id"]].append(r)
        if r["name_id"] not in ("-", ""):
            rows_of[r["name_id"]].append(r)
    att_of, bdm_of, act_of = collections.defaultdict(list), collections.defaultdict(list), collections.defaultdict(list)
    for a in ha:
        att_of[a["vol"]].append(a)
    for b in hb:
        bdm_of[b["vol"]].append(b)
    for c in hc:
        act_of[c["inst"]].append(c)
    mig_of = collections.defaultdict(list)
    for m in hm:
        mig_of[m["inst"]].append(m)
    items_of = collections.defaultdict(list)
    for fx in portal_.get("fixes") or []:
        for it in fx["items"]:
            items_of[it["vol"]].append((fx, it))

    def touch(a):
        return max((t for t in (a["deleted_at"], a["detached"], a["updated"], a["attached"], a["created"]) if when(t)), default="-")

    summary = collections.defaultdict(list)
    for f in F:
        n, ids = f["node"], set(f["ids"])
        rows = {r["id"]: r for i in ids for r in rows_of.get(i, [])}
        vids = set(rows) | ids
        A = sorted({a["id"]: a for v in vids for a in att_of.get(v, [])}.values(), key=lambda a: a["created"])
        here = [a for a in A if n in (short(a["chost"]), short(a["ahost"])) or (a["cinit"].lower() == f["init"] and f["init"] != "-")]
        print(f"\n-- [{f['kind']}] {n} LUN {f['lun']} {f['path'] or ''} {('(' + f['class'] + ')') if f['class'] else ''}")
        for r in sorted(rows.values(), key=lambda r: r["created"]):
            print(f"   Cinder volume {r['id']}{' DELETED ' + r['deleted_at'] if r['deleted'] not in ('0', '') else ''}: _name_id {r['name_id']}, "
                  f"{r['status']}/{r['astat']}, migration {r['mig']}, pool {pool(r['host'])}, created {r['created']}, updated {r['updated']}, '{r['name'][:30]}'")
        if not rows:
            print("   Cinder: no row (deleted ones included) names " + ", ".join(sorted(i[:8] for i in ids)))
        for a in here[-5:]:
            print(f"   on {n}: attachment {a['id']} {a['status']}{' DELETED ' + a['deleted_at'] if a['deleted'] not in ('0', '') else ''}, "
                  f"instance {a['inst']}, LUN {a['lun']}, attach {a['attached']}, detach {a['detached']}, updated {a['updated']}, "
                  f"connector {short(a['chost'])} {a['cinit']}")
        if len(here) > 5:
            print(f"   on {n}: {len(here) - 5} older attachment(s) not shown")
        if not here:
            print(f"   on {n}: no Cinder attachment row of these volumes (deleted ones included) names this compute or its initiator")
        else:
            last = max(here, key=touch)
            print(f"   ON {n} LAST TOUCHED: {touch(last)} (attachment {last['id'][:8]}, {last['status']})")
        rest = [a for a in A if a not in here]
        if rest:
            a = rest[-1]
            print(f"   elsewhere: {len(rest)} attachment(s); the latest {a['id'][:8]} {a['status']} on {short(a['chost'])} LUN {a['lun']} "
                  f"created {a['created']}{' deleted ' + a['deleted_at'] if a['deleted'] not in ('0', '') else ''}")
        insts = {a["inst"] for a in here if a["inst"] != "-"}
        for b in sorted((b for v in vids for b in bdm_of.get(v, []) if b["inst"] in insts or not insts), key=lambda b: b["created"])[-4:]:
            print(f"   Nova BDM: instance {b['inst']}, volume {b['vol'][:8]}, attachment {b['attachment'][:8]}, LUN {b['lun']}, created {b['created']}, "
                  f"updated {b['updated']}{', DELETED ' + b['deleted_at'] if b['deleted'] not in ('0', '') else ''}")
        times = [when(t) for a in here for t in (a["attached"], a["detached"], a["deleted_at"]) if when(t)]
        near = [c for i in insts for c in act_of.get(i, []) if when(c["start"]) and any(abs((when(c["start"]) - t).total_seconds()) <= 7200 for t in times)]
        for c in sorted(near, key=lambda c: c["start"])[-8:]:
            print(f"   Nova action of {c['inst'][:8]} ({c['iname'][:24]}, host now {c['host']}): {c['action']} {c['req']} {c['start']} .. {c['finish']} user {c['user'][:8]}")
        keys = vids | set(f.get("atts") or []) | {a["id"] for a in here}
        L = sorted((l for l in logs if any(k in l[2] for k in keys) and (l[1].startswith("cinder") or l[0] == n)), key=lambda l: l[2][:23])
        if L:
            print(f"   log lines naming them: {len(L)} ({', '.join(f'{k} {v}' for k, v in collections.Counter(l[1] for l in L).items())}); the first and the last:")
            for l in (L if len(L) <= 8 else L[:2] + [None] + L[-6:]):
                print("      ..." if l is None else f"      {l[0]} {l[1]}: {l[2][:330]}")
        else:
            print("   log lines naming them: none in the logs kept")
        origin = None
        if f["kind"] == "2c":
            for a in A[-12:]:
                print(f"   attachment {a['id'][:8]} {a['status']}{' (deleted ' + a['deleted_at'] + ')' if a['deleted'] not in ('0', '') else ''}: "
                      f"{disp(short(a['chost']))} LUN {a['lun']}, created {a['created']}, attach {a['attached']}, detach {a['detached']}, instance {a['inst'][:8]}")
            if len(A) > 12:
                print(f"   ... {len(A) - 12} older attachment(s)")
            for m in sorted((m for i in insts for m in mig_of.get(i, [])), key=lambda m: m["created"])[-6:]:
                print(f"   Nova migration {m['id']} {m['type']} {m['status']}: {disp(m['source'])} -> {disp(m['dest'])}, {m['created']} .. {m['updated']}")
            cur = next((a for a in A if a["id"] in (f.get("atts") or [])), None)
            t = when(cur["created"]) if cur else None
            moves = sorted((c for c in act_of.get(f.get("inst", ""), []) if t and when(c["start"])
                            and abs((when(c["start"]) - t).total_seconds()) <= 7200), key=lambda c: abs((when(c["start"]) - t).total_seconds()))
            ct = ontime(f.get("clone_created"))
            origin = (f"{moves[0]['action']} {moves[0]['req']} {moves[0]['start']}" if moves else "no Nova action within 2 h")
            side = "-" if not (t and ct) else "AFTER" if t > ct + datetime.timedelta(hours=8) else "BEFORE" if t < ct - datetime.timedelta(hours=8) else "same day"
            print(f"   CURRENT ATTACHMENT {f['atts'][0][:8] if f.get('atts') else '?'} created {cur['created'] if cur else '?'} (UTC) by: {origin}; "
                  f"the clone was created {f.get('clone_created') or '?'} (ONTAP time): {side} the clone existed")
            print(f"   every LUN of this name and where it is mapped: {f.get('orig') or '?'}")
            ms = sorted(mig_of.get(f.get("inst", ""), []), key=lambda m: m["created"])
            lastm = f"{ms[-1]['created'][:16]} {ms[-1]['type'][:4]} {disp(ms[-1]['source'])}->{disp(ms[-1]['dest'])}" if ms else "none kept"
            origin = (f, cur, moves[0]["action"] if moves else "none", side, lastm)
        for v in sorted(vids):
            for fx, it in items_of.get(v, []):
                print(f"   PORTAL fix #{fx['id']} ({fx['ts']}, {fx['user']}, {fx['status']}): {it['op']} {v[:8]} from {it['from'] or '?'} to "
                      f"{it['to']}, exit {it['rc']}: {it['result'][:200]}")
        last = max(here, key=touch) if here else None
        summary[(n, f["kind"])].append((f, touch(last) if last else "-", last, near))
        if origin:
            summary[("*", "2c-origin")].append(origin)

    org = summary.pop(("*", "2c-origin"), [])
    if org:
        print(f"\n== 2c: volumes running on a FlexClone copy: {len(org)}")
        print(f"   by the Nova action that made the current attachment: {dict(collections.Counter(x[2] for x in org).most_common())}")
        print(f"   current attachment made before / after the clone was created: {dict(collections.Counter(x[3] for x in org).most_common())}")
        print(f"   by clone: {dict(collections.Counter(x[0]['clone'] for x in org).most_common())}")
        print(f"   {'volume':36} {'GiB':>5} {'instance':36} {'compute':18} {'LUN':>4} {'attachment made (UTC)':21} {'by':16} {'vs clone':9} "
              f"{'last Nova migration (UTC)':44} clone")
        for f, c, a, s, lastm in sorted(org, key=lambda x: x[1]["created"] if x[1] else ""):
            print(f"   {f['vol']:36} {f.get('size', ''):>5} {f.get('inst', ''):36} {disp(f['node']):18} {f['lun']:4} "
                  f"{(c['created'] if c else '?'):21} {a:16} {s:9} {lastm:44} {f['clone']}")
    print("\n== Pattern of the findings (per compute and section)")
    for (n, k), lst in sorted(summary.items(), key=lambda x: (natural(x[0][0]), x[0][1])):
        days = collections.Counter(t[:10] for f, t, a, c in lst)
        insts = collections.Counter(a["inst"][:8] for f, t, a, c in lst if a)
        acts = collections.Counter(c["action"] for f, t, a, cs in lst for c in cs)
        fv = collections.Counter(flexvol(f["path"]) for f, t, a, c in lst if f["path"])
        ts = sorted(t for f, t, a, c in lst if t != "-")
        print(f"-- {n} [{k}] {KIND.get(k, k)}: {len(lst)}; FlexVol {dict(fv)}; last touched on this compute by day {dict(sorted(days.items()))}"
              + (f", from {ts[0]} to {ts[-1]}" if ts else ""))
        if insts:
            print(f"   their last attachment here was of instance(s) {dict(insts.most_common(6))}; Nova actions near: {dict(acts.most_common(6))}")

    print(f"\n== Portal volume migration / retype fixes on the site" + (f" (portal database: {portal_['error']})" if portal_.get("error") else ""))
    fl = set(i for f in F for i in f["ids"])
    for fx in portal_.get("fixes") or []:
        pairs = collections.Counter(f"{pool(it['from']) if '#' in it['from'] else it['from'] or '?'} -> {pool(it['to']) if '#' in it['to'] else it['to']}" for it in fx["items"])
        hits = [it for it in fx["items"] if it["vol"] in fl]
        print(f"   fix #{fx['id']} (run #{fx['run']} {fx['check']}): {fx['ts']} .. {fx['finished'] or '-'}, {fx['status']}, by {fx['user']}, "
              f"{len(fx['items'])} item(s) {dict(pairs)}" + (f"; {len(hits)} item(s) on a volume of the findings" if hits else ""))
        for it in fx["items"]:
            if it["rc"] not in (0, "0") or it["vol"] in fl:
                print(f"      {it['op']} {it['vol']} -> {it['to']}: exit {it['rc']}, {it['result'][:200]}")
    if not portal_.get("fixes"):
        print("   none")
    print("\n== Cinder: the pools it reports, the NetApp options of cinder.conf (named keys only), the LUN table code of the installed driver")
    for line in code:
        print("   " + line[7:][:220])
    return 0


if __name__ == "__main__":
    m, a = sys.argv[1], sys.argv[2:]
    sys.exit({"ontap": lambda: ontap(*a), "analyze": lambda: analyze(*a), "portal": lambda: portal(*a),
              "history": lambda: history(*a)}[m]())
PYEOF
printf '%s' "$AUDIT" > "$TMP/audit.py"
audit() { "$PY" -I "$TMP/audit.py" "$@"; }

if [ "${1:-}" = "--reanalyze" ]; then
  RAW="${2:-}"
  [ -r "$RAW/ontap.json" ] && [ -r "$RAW/p1.txt" ] || { echo "Saved data: the .raw folder of a run (ontap.json, p1.txt)"; exit 1; }
  echo "Read-only, $(date -Is): again from the data saved in $RAW"
  audit analyze "$RAW" "$TMP" || exit 1
  [ -r "$RAW/p2.txt" ] && audit history "$RAW" "$TMP"
  exit 0
fi

SITE="${1:-}"
ONTAP="${2:-}"
HIST=1
[ "${3:-}" = "--no-history" ] && HIST=0
case "$SITE" in DCB|DCA|DCC) ;; *) echo "Site: DCB, DCA or DCC"; exit 1;; esac
[ -f "$ONTAP" ] && [ -r "$ONTAP" ] || { echo "ONTAP output file: the saved output of the ONTAP commands (see the head of this script)"; exit 1; }
[ "$(id -u)" = 0 ] || { echo "Run it with sudo (the portal service account's SSH access and the portal database)"; exit 1; }
STAMP=$(date +%Y%m%d-%H%M%S)
OUT="/home/deploy/lun-map-audit-$SITE-$STAMP.txt"
RAW="/home/deploy/lun-map-audit-$SITE-$STAMP.raw"
mkdir -m 700 "$RAW" || exit 1

read -r MGMT_HOST MGMT_PORT MGMT_USER MGMT_KEY DIR_HOST DIR_USER DIR_PORT RC < <("$PY" - "$SITE" <<'EOF'
import sys, yaml
c = yaml.safe_load(open("/etc/ops-portal/sites.yml"))["sites"][sys.argv[1]]
m, d = c.get("mgmt") or {}, c.get("director") or {}
print(m.get("host", "-"), m.get("port", 22), m.get("user") or "-", m.get("private_key") or "-",
      d.get("host", "-"), d.get("user") or "stack", d.get("port", 22), d.get("overcloudrc") or "~/overcloudrc")
EOF
)
OPTS=(-o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new -p "$MGMT_PORT")
[ "$MGMT_KEY" != "-" ] && OPTS+=(-i "$MGMT_KEY")
TARGET="$MGMT_HOST"
[ "$MGMT_USER" != "-" ] && TARGET="$MGMT_USER@$MGMT_HOST"
director() {   # director: runs stdin on the director, as the portal does
  sudo -u "$SVC" -H ssh "${OPTS[@]}" "$TARGET" "ssh -o BatchMode=yes -o ConnectTimeout=15 -o LogLevel=ERROR -p $DIR_PORT $DIR_USER@$DIR_HOST bash -s" 2>&1 \
    | grep -v 'post-quantum\|store now, decrypt\|openssh.com/pq\|server may need to be upgraded'
}

# ---- on the director: the nodes of the inventory, root on a node, SQL on the galera container of the first controller
IFS= read -r -d '' PRELUDE <<'EOF' || true
set -u
INV=$(ls ~/overcloud-deploy/*/tripleo-ansible-inventory.yaml ~/config-download/*/tripleo-ansible-inventory.yaml \
  ~/tripleo-ansible-inventory.yaml 2>/dev/null | head -1)
LIST=$(python3 - "${INV:-/nonexistent}" <<'PY'
import sys, yaml
try:
    inv = yaml.safe_load(open(sys.argv[1])) or {}
except Exception:
    inv = {}
seen = set()
for group, body in inv.items():
    for host, hv in ((body or {}).get("hosts") or {}).items() if isinstance(body, dict) else []:
        name = host.split(".")[0].lower()
        role = "compute" if "compute" in name else "controller" if "controller" in name else ""
        if role and isinstance(hv, dict) and name not in seen:
            seen.add(name)
            print(role, name, hv.get("ctlplane_ip") or hv.get("ansible_host") or "-", hv.get("ansible_ssh_user") or "-")
PY
)
[ -n "$LIST" ] || { echo "@@err no compute or controller in the inventory ${INV:-(none found)}"; exit 1; }
DEFUSR=$(grep -q '17\.' /etc/rhosp-release 2>/dev/null && echo tripleo-admin || echo heat-admin)
CTL=$(awk '$1 == "controller" {print $2; exit}' <<< "$LIST")
asroot() {   # asroot <short name>: runs stdin as root on the node
  local R N IP USR
  read -r R N IP USR < <(awk -v n="$1" '$2 == n' <<< "$LIST")
  [ -n "${IP:-}" ] && [ "$IP" != "-" ] || { echo "@@err $1: no address in the inventory"; return 1; }
  [ "$USR" = "-" ] && USR=$DEFUSR
  ssh -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$USR@$IP" "sudo -n bash -s"
}
sql() { printf 'podman exec $(podman ps -q -f name=galera-bundle | head -1) mysql -N -B -e %q\n' "$1" | asroot "$CTL"; }
alln() {   # alln <roles> <script>: the script on every node of those roles at once (ROLE set), outputs one node after another
  local T R N IP USR
  T=$(mktemp -d)
  while read -r R N IP USR; do
    [[ " $1 " == *" $R "* ]] || continue
    ( printf 'ROLE=%s\n%s\n' "$R" "$2" | asroot "$N" > "$T/$N" 2>&1 || echo "@@err $N: exit $?" >> "$T/$N" ) &
  done <<< "$LIST"
  wait
  cat "$T"/* 2>/dev/null
  rm -rf "$T"
}
EOF

# ---- on each node as root: its initiator; on a compute every SCSI device on an iSCSI session and the disks of the
# running domains (sysfs and virsh domblklist only)
IFS= read -r -d '' ONNODE <<'EOF' || true
N=$(hostname -s)
echo "@@node $ROLE $N $(hostname -f) $(sed -n 's/^InitiatorName=//p' /etc/iscsi/initiatorname.iscsi 2>/dev/null | head -1)"
[ "$ROLE" = compute ] || exit 0
for b in /sys/block/sd*; do
  [ -e "$b/device" ] || continue
  p=$(readlink -f "$b/device")
  s=$(printf '%s\n' "$p" | grep -o 'session[0-9]*' | head -1)
  [ -n "$s" ] || continue
  h=$(ls "$b/holders" 2>/dev/null | head -1)
  echo "@@dev $N ${b##*/} ${p##*/} $(cat "$b/device/state" 2>/dev/null || echo -) $(cat /sys/class/iscsi_session/$s/targetname 2>/dev/null || echo -)" \
    "$(sed -E 's/^naa\./3/' "$b/device/wwid" 2>/dev/null || echo -) $(( $(cat "$b/size" 2>/dev/null || echo 0) * 512 )) ${h:--}" \
    "$( [ -n "$h" ] && cat "/sys/block/$h/dm/name" 2>/dev/null || echo -)"
done
c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$')
[ -n "$c" ] || { echo "@@err $N: no libvirt container"; exit 0; }
podman exec "$c" sh -c 'for x in $(virsh -c qemu:///system list --name); do u=$(virsh -c qemu:///system domuuid $x 2>/dev/null); virsh -c qemu:///system domblklist $x 2>/dev/null | awk -v x=$x -v u=$u "\$2 ~ /^\/dev\// {print \$1, \$2, x, u}"; done' |
  while read -r t s x u; do echo "@@use $N $(basename "$(readlink -f "$s")") $u $x $t"; done
EOF

IFS= read -r -d '' REMOTE1 <<'EOF' || true
echo "@@begin $(date -Is)"
IFS= read -r -d '' Q <<'SQL' || true
SELECT 'att', a.id, a.volume_id, IFNULL(a.instance_uuid,'-'), IFNULL(a.attach_status,'-'), IFNULL(a.attached_host,'-'),
 IFNULL(JSON_VALUE(a.connector,'$.host'),'-'), IFNULL(JSON_VALUE(a.connector,'$.initiator'),'-'),
 IFNULL(JSON_VALUE(a.connection_info,'$.target_iqn'),IFNULL(JSON_VALUE(a.connection_info,'$.data.target_iqn'),'-')),
 IFNULL(JSON_VALUE(a.connection_info,'$.target_lun'),IFNULL(JSON_VALUE(a.connection_info,'$.data.target_lun'),'-')),
 IFNULL(a.attach_time,'-'), IFNULL(a.updated_at,'-'), a.created_at
FROM cinder.volume_attachment a WHERE a.deleted=0;
SELECT 'vol', id, IFNULL(_name_id,'-'), IFNULL(status,'-'), IFNULL(attach_status,'-'), IFNULL(migration_status,'-'), IFNULL(host,'-'),
 IFNULL(size,'-'), IFNULL(updated_at,'-'), created_at, IFNULL(LEFT(display_name,40),'')
FROM cinder.volumes WHERE deleted=0;
SQL
sql "$Q"
alln "compute controller" "$ONNODE"
echo "@@end $(date -Is)"
EOF

# ---- history: every row naming the IDs of the findings (deleted ones too), then the log lines naming them
IFS= read -r -d '' LOGS <<'EOF' || true
F=$(mktemp)
printf '%s\n' $G > "$F"
N=$(hostname -s)
S="cinder-api cinder-volume"
[ "$ROLE" = compute ] && S=nova-compute
for s in $S; do
  d=/var/log/containers/${s%%-*}
  files=$(ls -tr $d/$s.log* 2>/dev/null)
  if [ -z "$files" ]; then echo "@@logwin $N $s: none"; continue; fi
  echo "@@logwin $N $s: $(zcat -f $(printf '%s\n' $files | head -1) 2>/dev/null | head -1 | cut -c1-19) .. $(tail -n 1 $d/$s.log 2>/dev/null | cut -c1-19)"
  zcat -f $files 2>/dev/null | grep -F -f "$F" | grep -v -E ' GET http|"GET /|/volumes/[0-9a-f-]{36} returned with HTTP 200' \
    | sed -E "s/(auth_password|password|secret|target_secret|chap_secret)(['\"]?[[:space:]]*[:=][[:space:]]*['\"]?)[^'\",} ]+/\1\2***/g" \
    | cut -c1-400 | tail -n 20000 | sed "s/^/@@log $N $s /"
done
rm -f "$F"
EOF

IFS= read -r -d '' REMOTE2 <<'EOF' || true
UUID='^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'
inlist() { printf "'%s'," "$@" | sed 's/,$//'; }
IFS= read -r -d '' Q <<'SQL' || true
SELECT 'hmin', IFNULL((SELECT MIN(deleted_at) FROM cinder.volumes WHERE deleted=1),'-'),
 IFNULL((SELECT MIN(deleted_at) FROM cinder.volume_attachment WHERE deleted=1),'-'), IFNULL((SELECT MIN(created_at) FROM nova.instance_actions),'-');
SELECT 'hvol', id, IFNULL(_name_id,'-'), deleted, IFNULL(deleted_at,'-'), IFNULL(status,'-'), IFNULL(attach_status,'-'),
 IFNULL(migration_status,'-'), IFNULL(host,'-'), IFNULL(size,'-'), created_at, IFNULL(updated_at,'-'), IFNULL(LEFT(display_name,40),'')
FROM cinder.volumes WHERE id IN (@L@) OR _name_id IN (@L@) OR migration_status IN (@T@);
SQL
Q=${Q//@L@/$(inlist $IDS)}
H=$(sql "${Q//@T@/$(for i in $IDS; do printf "'target:%s'," "$i"; done | sed 's/,$//')}")
printf '%s\n' "$H"
# every volume row naming them (a migration source or target included), then their attachments and Nova's mappings
V=$( { printf '%s\n' $IDS; printf '%s\n' "$H" | awk -F'\t' '$1 == "hvol" {print $2; print $3}'; } | grep -E "$UUID" | sort -u)
IFS= read -r -d '' Q <<'SQL' || true
SELECT 'hatt', a.id, a.volume_id, a.deleted, IFNULL(a.deleted_at,'-'), IFNULL(a.instance_uuid,'-'), IFNULL(a.attach_status,'-'),
 IFNULL(a.attached_host,'-'), IFNULL(JSON_VALUE(a.connector,'$.host'),'-'), IFNULL(JSON_VALUE(a.connector,'$.initiator'),'-'),
 IFNULL(JSON_VALUE(a.connection_info,'$.target_lun'),IFNULL(JSON_VALUE(a.connection_info,'$.data.target_lun'),'-')),
 IFNULL(a.attach_time,'-'), IFNULL(a.detach_time,'-'), a.created_at, IFNULL(a.updated_at,'-')
FROM cinder.volume_attachment a WHERE a.volume_id IN (@V@);
SELECT 'hbdm', b.volume_id, b.instance_uuid, b.deleted, IFNULL(b.deleted_at,'-'), IFNULL(b.attachment_id,'-'), b.created_at,
 IFNULL(b.updated_at,'-'), IFNULL(JSON_VALUE(b.connection_info,'$.data.target_lun'),'-')
FROM nova.block_device_mapping b WHERE b.destination_type='volume' AND b.volume_id IN (@V@);
SQL
B=$(sql "${Q//@V@/$(inlist $V)}")
printf '%s\n' "$B"
I=$(printf '%s\n' "$B" | awk -F'\t' '$1 == "hatt" {print $6} $1 == "hbdm" {print $3}' | grep -E "$UUID" | sort -u)
if [ -n "$I" ]; then
  IFS= read -r -d '' Q <<'SQL' || true
SELECT 'hact', ia.instance_uuid, ia.action, IFNULL(ia.request_id,'-'), ia.start_time, IFNULL(ia.finish_time,'-'), IFNULL(ia.user_id,'-'),
 IFNULL(i.host,'-'), IFNULL(i.deleted,'-'), IFNULL(LEFT(i.hostname,40),'')
FROM nova.instance_actions ia LEFT JOIN nova.instances i ON i.uuid = ia.instance_uuid WHERE ia.instance_uuid IN (@I@);
SQL
  sql "${Q//@I@/$(inlist $I)}"
  IFS= read -r -d '' Q <<'SQL' || true
SELECT 'hmig', m.instance_uuid, m.id, IFNULL(m.migration_type,'-'), IFNULL(m.status,'-'), IFNULL(m.source_compute,'-'),
 IFNULL(m.dest_compute,'-'), m.created_at, IFNULL(m.updated_at,'-') FROM nova.migrations m WHERE m.instance_uuid IN (@I@);
SQL
  sql "${Q//@I@/$(inlist $I)}"
fi
# the pools Cinder reports (is a FlexClone a pool?), the NetApp options (named keys only: never a password) and the code
# that builds the driver's LUN table (keyed by LUN name?)
( source $RC >/dev/null 2>&1 && cinder get-pools 2>&1 | awk -F'|' '/ name /{gsub(/ /, "", $3); print "@@pool pool " $3} !/ name /&&!/^\+/&&!/Property/{print "@@pool " $0}' )
asroot "$CTL" <<'CODE' | sed 's/^/@@code /'
awk '/^\[/ {sec = $0; next} /^[[:space:]]*(enabled_backends|volume_backend_name|volume_driver|netapp_storage_family|netapp_storage_protocol|netapp_vserver|netapp_pool_name_search_pattern|netapp_lun_ostype)[[:space:]]*=/ {print "conf", FILENAME, sec, $0}' \
  /var/lib/config-data/puppet-generated/cinder/etc/cinder/cinder.conf /var/lib/config-data/puppet-generated/cinder/etc/cinder/cinder.conf.d/*.conf 2>/dev/null | head -40
c=$(podman ps --format '{{.Names}}' | grep -m1 -x cinder_api)
[ -n "$c" ] || { echo "no cinder_api container"; exit 0; }
podman exec "$c" rpm -q openstack-cinder 2>&1 | head -1
podman exec "$c" sh -c 'd=$(python3 -c "import os, cinder.volume.drivers.netapp.dataontap as m; print(os.path.dirname(m.__file__))"); for f in block_base.py block_cmode.py client/client_cmode.py; do grep -n -E -A16 "def (_extract_and_populate_luns|_get_lun_list|get_lun_list|_get_lun_from_table|_add_lun_to_table)\b" $d/$f | sed "s|^|$f:|"; done' 2>&1 | cut -c1-200 | head -160
CODE
# the log lines naming the volumes or their attachments: cinder-api and cinder-volume of every controller, nova-compute of
# the computes with a finding
G=$( { printf '%s\n' $V; printf '%s\n' "$B" | awk -F'\t' '$1 == "hatt" {print $2}'; } | grep -E "$UUID" | sort -u)
LIST=$(awk -v n=" $NODES " '$1 == "controller" || index(n, " " $2 " ")' <<< "$LIST")
alln "compute controller" "$(printf 'G=%q\n%s' "$G" "$LOGS")"
EOF

{
  echo "Read-only, $(date -Is), site $SITE, ONTAP file $ONTAP; management host $MGMT_HOST, director $DIR_USER@$DIR_HOST (keys are not printed)"
  audit ontap "$ONTAP" "$RAW/ontap.json" || exit 1
  echo "== Reading Cinder and every compute (a few minutes) ..."
  printf 'ONNODE=%q\n%s\n%s\n' "$ONNODE" "$PRELUDE" "$REMOTE1" | director > "$RAW/p1.txt"
  audit analyze "$RAW" "$TMP" || exit 1
  if [ "$HIST" = 1 ] && [ -s "$TMP/ids.txt" ]; then
    echo "== Reading the history of the findings (the databases, then the logs: a few minutes) ..."
    printf 'IDS=%q\nNODES=%q\nLOGS=%q\nRC=%s\n%s\n%s\n' "$(tr '\n' ' ' < "$TMP/ids.txt")" "$(tr '\n' ' ' < "$TMP/nodes.txt")" "$LOGS" "$RC" \
      "$PRELUDE" "$REMOTE2" | director > "$RAW/p2.txt"
    audit portal "$DB" "$SITE" "$RAW/p3.json"
    audit history "$RAW" "$TMP"
  fi
} 2>&1 | tee "$OUT"
chown -R deploy: "$OUT" "$RAW"
chmod 600 "$RAW"/* 2>/dev/null
echo "Saved: $OUT (data: $RAW)"

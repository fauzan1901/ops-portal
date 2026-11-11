"""LUN copy guard of the checks that move or detach a volume (spec docs/superpowers/specs/2026-11-11-lun-copy-guard-design.md).

Why (a real case): the Cinder NetApp driver finds a LUN by its name (volume-<_name_id or id>). When a FlexClone of a
pool (snap_..._clone_152) holds a LUN of the same name in the same SVM, a migration, an attach or an attachment update can
map that copy, and the instance then runs on old data. The checks that offer such a change (a live or cold migration, a
volume migration or retype, a detach) ask this module first: while the LUN of one of the volumes also exists in another
FlexVol of its SVM, is not in its pool, is not found, or cannot be read, the item or fix is manual. An operator may tick
it (through the review); an automatic action of an alert rule never takes it.

Reads (read-only, never the OpenStack API, so the lists stay fast): one SELECT on the galera container of a controller
(overcloud.lun_guard_db_command: attachments and volumes, never connection_info) and one ONTAP list of every LUN with its
SVM. Copies are counted per SVM: a LUN of the same name in another SVM (a SnapMirror / DR destination) is not one.
Nothing is read on a site without NetApp (ctx["netapp"] false): the guard is off there."""
import collections

from . import overcloud
from .common import json_of, source, text_of, unavailable
from .overcloud_checks import inventory

DB, LUNS = "lg_db", "lg_luns"
LUNS_PATH = "/api/storage/luns?fields=name,svm.name&return_timeout=45"
STEP = ("lun_copies", "LUN copies on NetApp (FlexClone)")
MAX_REASON = 160   # what os_select / os_fix keep of a manual reason


def flexvol(path):
    """The FlexVol of a LUN path /vol/<FlexVol>/<LUN> ("?" when it is not one)."""
    p = str(path or "").split("/")
    return p[2] if len(p) > 3 and p[1] == "vol" else "?"


def pool(host):
    """The pool of a Cinder host host@backend#pool ("?" without one)."""
    return str(host).split("#")[-1] if "#" in str(host or "") else "?"


def merge(*reads):
    """{source: {key: command}} of several planners in one."""
    out = {}
    for r in reads:
        for src, items in (r or {}).items():
            out.setdefault(src, {}).update(items)
    return out


def reads(phase, data, ctx, first=1):
    """The guard's reads of this phase: the director's inventory in phase `first`, the Cinder database (when a controller
    and its user are known) and the LUN list of NetApp in the phase after; nothing on a site without NetApp."""
    if not ctx.get("netapp"):
        return {}
    if phase == first:
        return {"undercloud": dict(overcloud.INVENTORY_READS)}
    if phase != first + 1:
        return {}
    out = {"ontap": {LUNS: LUNS_PATH}}
    _found, controllers, user, _version, _problem = inventory(data, ctx)
    ctl = next((c for c in controllers if c.get("ip")), None)
    if ctl and user in overcloud.USERS:
        out["overcloud"] = {DB: overcloud.read(ctl["name"], ctl["ip"], user, "lun_guard_db")}
    return out


class Guard:
    """What the guard read: state off (no NetApp) / read / unread (why), the verdict of each volume, the volumes attached
    to each instance, and the items it made manual (hits: (instance or "", volume, reason))."""

    def __init__(self, state, why=""):
        self.state, self.why = state, why
        self.volumes, self.instances, self.hits = {}, {}, []
        self.shown = False   # step() ran: a fix offered in a loop adds the step once


def verdict(where, pools, lun, pl):
    """{"verdict", "lun", "pool", "svm", "where"} of one LUN name: where = {SVM: {LUN name: {FlexVol}}}, pools = the
    FlexVols that hold a LUN."""
    holders = {svm: names[lun] for svm, names in where.items() if lun in names}
    home = sorted(svm for svm, fvs in holders.items() if pl in fvs)
    base = {"lun": lun, "pool": pl, "svm": home[0] if home else "", "where": []}
    if home:
        others = sorted({fv for svm in home for fv in holders[svm] if fv != pl})
        return dict(base, verdict="copy", where=others) if others else dict(base, verdict="ok")
    found = sorted({fv for fvs in holders.values() for fv in fvs})
    if found:
        return dict(base, verdict="not-in-pool", svm=sorted(holders)[0], where=found)
    return dict(base, verdict="missing" if pl in pools else "not-netapp")


def index(data, ctx):
    """The Guard of a run from its reads lg_db and lg_luns."""
    if not ctx.get("netapp"):
        return Guard("off")
    db, item = source(data, DB), source(data, LUNS)
    if unavailable(db):
        return Guard("unread", "Cinder database not read")
    if unavailable(item):
        return Guard("unread", "NetApp not read")
    if item.get("more") or item.get("next"):   # next: the page rounds ran out (merge_pages), a copy may be unread
        return Guard("unread", "NetApp list read only in part")
    doc = json_of(item)
    recs = doc.get("records") if isinstance(doc, dict) else None
    if not isinstance(recs, list):
        return Guard("unread", "NetApp not read")
    where = collections.defaultdict(lambda: collections.defaultdict(set))
    for r in recs:
        svm = r.get("svm") if isinstance(r, dict) else None
        path = str(r.get("name") or "") if isinstance(r, dict) else ""
        name = str(svm.get("name") or "") if isinstance(svm, dict) else ""
        if name and flexvol(path) != "?":
            where[name][path.rsplit("/", 1)[-1]].add(flexvol(path))
    pools = {fv for names in where.values() for fvs in names.values() for fv in fvs}
    g = Guard("read")
    for line in text_of(db).splitlines():
        f = [x.strip() for x in line.split("\t")]
        if f[0] == "att" and len(f) >= 4 and f[2] and f[3].lower() == "attached":
            g.instances.setdefault(f[2], []).append(f[1])
        elif f[0] == "vol" and len(f) >= 5 and f[1]:
            g.volumes[f[1]] = verdict(where, pools, f"volume-{f[2] or f[1]}", pool(f[3]))
    return g


def _text(v):
    lun, also = v["lun"], ", ".join(v["where"])
    if v["verdict"] == "copy":
        return f"LUN {lun} also in {also}: check lun-map-audit, then tick it"
    if v["verdict"] == "not-in-pool":
        return f"LUN {lun} is not in its pool {v['pool']} but in {also}: check lun-map-audit"
    if v["verdict"] == "missing":
        return f"LUN {lun} not found on NetApp: check lun-map-audit"
    return ""


def _unread(g, inst, vid):
    reason = f"{g.why}: LUN copies unknown"
    g.hits.append((inst, vid, reason))
    return reason


def reason_for_volume(g, vid):
    """Why a change of this volume is manual ("" when it is not)."""
    if g.state == "off":
        return ""
    if g.state == "unread":
        return _unread(g, "", vid)
    reason = _text(g.volumes[vid]) if vid in g.volumes else ""
    if reason:
        g.hits.append(("", vid, reason))
    return reason[:MAX_REASON]


def reason_for_instance(g, iid):
    """Why moving this instance is manual: its first volume with a finding, plus how many more ("" when none)."""
    if g.state == "off":
        return ""
    if g.state == "unread":
        return _unread(g, iid, "")
    bad = [(vid, _text(g.volumes[vid])) for vid in g.instances.get(iid, []) if vid in g.volumes and _text(g.volumes[vid])]
    if not bad:
        return ""
    for vid, text in bad:
        g.hits.append((iid, vid, text))
    suffix = f" (+{len(bad) - 1} more)" if len(bad) > 1 else ""
    return f"volume {bad[0][0][:8]}: {bad[0][1]}"[:MAX_REASON - len(suffix)] + suffix


def mark(items, g, kind):
    """Makes manual (and not ticked) every item of os_select whose instance ("instance") or volume ("volume") the guard
    stops; its ID is the second word of its first command. Returns how many it marked."""
    marked = 0
    for it in items:
        words = str((it.get("commands") or [""])[0]).split()
        if len(words) < 2:
            continue
        reason = (reason_for_instance if kind == "instance" else reason_for_volume)(g, words[1])
        if reason:
            it["manual"] = "; ".join(x for x in (str(it.get("manual") or ""), reason) if x)
            it["default"] = False
            marked += 1
    return marked


def step(r, g):
    """The step "LUN copies on NetApp (FlexClone)" of a check, and what to do when it found something."""
    key, title = STEP
    if g.shown:
        return
    g.shown = True
    if g.state == "off":
        r.step(key, title, "info", "No NetApp pool on this site (no ONTAP in sites.yml): the guard does not apply.")
        return
    hits = list(dict.fromkeys(g.hits))
    if g.state == "unread":
        r.step(key, title, "warn", f"{g.why}: whether a LUN of these volumes also exists in a FlexClone is unknown, so "
               f"{len(hits)} change(s) offered here are manual: an operator may tick them, an automatic action never takes them.")
    elif hits:
        rows = [[inst or "-", vid, g.volumes[vid]["lun"], g.volumes[vid]["pool"], ", ".join(g.volumes[vid]["where"]) or "-",
                 g.volumes[vid]["verdict"]] for inst, vid, _reason in hits]
        r.step(key, title, "warn", f"{len(hits)} volume(s) of the changes offered here have a LUN that is also in another "
               "FlexVol of its SVM, is not in its pool, or is not found. Cinder finds a LUN by its name, so a migration, a "
               "retype or an attachment update may map the other one: these changes are manual (an operator may tick "
               "them, an automatic action never takes them).",
               {"columns": ["Instance", "Volume", "LUN", "Pool", "Also in / found in", "Finding"], "rows": rows})
    else:
        r.step(key, title, "ok", f"{len(g.volumes)} Cinder volume(s) compared with the LUNs of NetApp: no change offered here "
               "has a LUN in another FlexVol of its SVM.")
        return
    r.recommend("Run the check lun-map-audit before ticking a manual change: it shows the LUN each compute has mapped and "
                "whether an instance already runs on a copy. Remove or rename the copy (with the storage owner) before an "
                "automatic action may take the change again.", where="Runbook Automation (this site)")

"""Product templates as users edit them (Fabric -> Templates), stored in the portal database.

product_templates.json ships the default template of each built-in product per site (Acme Flex, Acme Prime, RHOSO).
Saving a product on one site stores that site's full list of groups in aci_templates; Reset to default sets the row
back to NULL, so the product follows the shipped file again. Products added by users are kept in aci_products and start
empty on every site. A template change never changes anything on APIC: it only decides which paths fill the binding
table when someone picks the product on Static Port.

Every change is written in the same transaction as its record in the change history (aci_audit, action "template"),
with the template before and after, so History always shows who changed what. `version` counts the changes of one
product on one site: a save names the version it started from and is refused when someone saved in between.
"""
import json
import re
import sqlite3

from . import aci, audit, product_templates

PERMISSION = "aci-templates"
MAX_GROUPS = 30
MAX_PATHS = 1000
MAX_CUSTOM_PRODUCTS = 20
TEXT_RE = re.compile(r"^[^\x00-\x1f\x7f]+$")
SCHEMA = """
CREATE TABLE IF NOT EXISTS aci_products (
    id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    platform TEXT NOT NULL,
    mode TEXT NOT NULL,
    immediacy TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created TEXT NOT NULL,
    updated_by TEXT,
    updated TEXT
);
CREATE TABLE IF NOT EXISTS aci_templates (
    site TEXT NOT NULL,
    product TEXT NOT NULL,
    groups TEXT,
    version INTEGER NOT NULL,
    updated_by TEXT NOT NULL,
    updated TEXT NOT NULL,
    PRIMARY KEY (site, product)
);
"""


def init():
    with audit._db() as conn:
        conn.executescript(SCHEMA)


def can_edit(user):
    """Administrators, and accounts with the permission "ACI: edit product templates" ticked on the Users page."""
    return bool(user) and (user.get("role") == "admin" or PERMISSION in (user.get("modules") or []))


# ---------------- Reading ----------------
def _products(conn):
    """Built-in products (product_templates.json) followed by the products users added, in the order they were added."""
    items = [{"id": pid, "label": meta.get("label", pid), "platform": meta.get("platform", ""),
              "mode": aci.MODES.get(meta.get("mode", "regular"), "regular"),
              "immediacy": meta.get("immediacy") if meta.get("immediacy") in aci.IMMEDIACY else "immediate", "custom": False}
             for pid, meta in product_templates.load().get("products", {}).items()]
    builtin = {p["id"] for p in items}
    for row in conn.execute("SELECT * FROM aci_products ORDER BY created, id"):
        if row["id"] not in builtin:
            items.append({"id": row["id"], "label": row["label"], "platform": row["platform"], "mode": row["mode"],
                          "immediacy": row["immediacy"], "custom": True, "created_by": row["created_by"], "created": row["created"],
                          "updated_by": row["updated_by"], "updated": row["updated"]})
    return items


def products():
    with audit._db() as conn:
        return _products(conn)


def product(product_id):
    return next((p for p in products() if p["id"] == product_id), None)


def label(product_id):
    """Label of a product (built-in or added), or None; never raises, for the audit record of a static-port change."""
    try:
        found = product(product_id) if product_id else None
    except (ValueError, OSError, sqlite3.Error):
        return None
    return found["label"] if found else None


def _state(conn, site, meta, shipped):
    """Template of one product on one site: the stored groups, else the shipped default (built-in products only)."""
    row = conn.execute("SELECT * FROM aci_templates WHERE site = ? AND product = ?", (site, meta["id"])).fetchone()
    edited = bool(row and row["groups"] is not None)
    default = [] if meta["custom"] else shipped.get(meta["id"], [])
    groups = json.loads(row["groups"]) if edited else [{"name": g["name"], "default": g["default"], "paths": list(g["paths"])} for g in default]
    return {**meta, "groups": groups, "version": row["version"] if row else 0, "edited": edited,
            "updated_by": row["updated_by"] if row else None, "updated": row["updated"] if row else None,
            "default_paths": sum(len(g["paths"]) for g in default)}


def _shipped(site):
    return {p["id"]: p["groups"] for p in product_templates.for_site(site)}


def for_site(site):
    """Every product with its template on this site (what Static Port offers), with version and who changed it last."""
    shipped = _shipped(site)
    with audit._db() as conn:
        return [_state(conn, site, meta, shipped) for meta in _products(conn)]


def state(site, product_id):
    found = next((p for p in for_site(site) if p["id"] == product_id), None)
    if not found:
        raise ValueError(f"Unknown product: '{product_id}'")
    return found


# ---------------- Validation ----------------
def check_text(value, label, max_len, required=True):
    value = " ".join(str(value or "").split())
    if not value:
        if required:
            raise ValueError(f"{label} is required")
        return ""
    if len(value) > max_len or not TEXT_RE.match(value):
        raise ValueError(f"{label} is invalid (max {max_len} characters)")
    return value


def normalize(body):
    """The editor's tables -> [{"name", "default", "paths": [tdn, ...]}]. Body: {"groups": [{"name", "default"}],
    "physical": [{"group": <index>, "pod", "node", "interface"}], "paths": [{"group": <index>, "tdn"}]}.
    Every error is collected, like the binding table of Static Port."""
    raw_groups = body.get("groups")
    if not isinstance(raw_groups, list):
        raise ValueError("No groups sent")
    if len(raw_groups) > MAX_GROUPS:
        raise ValueError(f"At most {MAX_GROUPS} groups per product")
    errors, groups, names = [], [], set()
    for i, g in enumerate(raw_groups, 1):
        g = g if isinstance(g, dict) else {}
        try:
            name = check_text(g.get("name"), "Group name", 80)
            if name.lower() in names:
                raise ValueError(f"the name '{name}' is used twice")
            names.add(name.lower())
        except ValueError as e:
            errors.append(f"Group {i}: {e}")
            name = f"Group {i}"
        groups.append({"name": name, "default": g.get("default") is True, "paths": []})

    def group_of(row):
        index = row.get("group")
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < len(groups):
            raise ValueError("choose a group")
        return groups[index]

    seen = {}
    for kind, rows in (("physical", body.get("physical")), ("paths", body.get("paths"))):
        for i, row in enumerate(rows or [], 1):
            where = f"{'Physical/PC' if kind == 'physical' else 'vPC/TDN'} row {i}"
            row = row if isinstance(row, dict) else {}
            try:
                group = group_of(row)
                if kind == "physical":
                    pod = aci.positive_int(row.get("pod") or 1, "Pod")
                    node = aci.positive_int(row.get("node"), "Node")
                    interface = str(row.get("interface") or "").strip()
                    if interface.lower().startswith("eth"):
                        interface = "eth" + interface[3:]
                    if not aci.INTERFACE_RE.match(interface):
                        raise ValueError(f"Invalid interface / PC: '{interface}'")
                    tdn = f"topology/pod-{pod}/paths-{node}/pathep-[{interface}]"
                else:
                    tdn = str(row.get("tdn") or "").strip()
                    if not (aci.PHYSICAL_TDN_RE.match(tdn) or aci.VPC_TDN_RE.match(tdn)):
                        raise ValueError(f"Invalid path TDN: '{tdn}'")
            except ValueError as e:
                errors.append(f"{where}: {e}")
                continue
            if tdn in seen:
                errors.append(f"Path {tdn} is in the template more than once (groups '{seen[tdn]}' and '{group['name']}')")
                continue
            seen[tdn] = group["name"]
            group["paths"].append(tdn)
    if len(seen) > MAX_PATHS:
        errors.append(f"At most {MAX_PATHS} paths per product")
    for g in groups:
        if not g["paths"]:
            errors.append(f"Group '{g['name']}' has no paths. Add paths to it or remove the group.")
    if errors:
        raise ValueError("\n".join(errors))
    return groups


def diff(before, after):
    """What a save changes: every path of before and after with its status (new, delete, moved, same), the group
    changes, and the counts."""
    old = {t: g["name"] for g in before for t in g["paths"]}
    new = {t: g["name"] for g in after for t in g["paths"]}
    items = []
    for t, group in new.items():
        if t not in old:
            items.append({"tdn": t, "status": "new", "group": group})
        elif old[t] != group:
            items.append({"tdn": t, "status": "moved", "group": group, "before_group": old[t]})
        else:
            items.append({"tdn": t, "status": "same", "group": group})
    items += [{"tdn": t, "status": "delete", "group": group} for t, group in old.items() if t not in new]
    old_groups = {g["name"]: g for g in before}
    new_groups = {g["name"]: g for g in after}
    groups = [{"name": n, "status": "new", "default": g["default"]} for n, g in new_groups.items() if n not in old_groups]
    groups += [{"name": n, "status": "delete", "default": g["default"]} for n, g in old_groups.items() if n not in new_groups]
    groups += [{"name": n, "status": "change", "default": g["default"]} for n, g in new_groups.items()
               if n in old_groups and old_groups[n]["default"] != g["default"]]
    order = [g["name"] for g in after if g["name"] in old_groups]
    reordered = order != [g["name"] for g in before if g["name"] in new_groups]
    summary = {s: sum(i["status"] == s for i in items) for s in ("new", "delete", "moved", "same")}
    summary["groups"] = len(groups) + (1 if reordered else 0)
    return {"items": items, "groups": groups, "reordered": reordered, "summary": summary,
            "changed": bool(summary["new"] or summary["delete"] or summary["moved"] or summary["groups"])}


def summary_text(d, before, after):
    s = d["summary"]
    parts = [f"{s['new']} added" if s["new"] else "", f"{s['delete']} removed" if s["delete"] else "",
             f"{s['moved']} moved" if s["moved"] else "", f"{s['groups']} group change{'s' if s['groups'] != 1 else ''}" if s["groups"] else ""]
    count = lambda groups: sum(len(g["paths"]) for g in groups)
    return f"{', '.join(p for p in parts if p) or 'no change'} ({count(before)} → {count(after)} paths)"


# ---------------- Changes ----------------
def _record(conn, username, site, apic, target, product_label, summary, details, client_ip):
    return audit.record(conn, username, site, apic, "template", target, product_label, summary, details, client_ip)


def default_groups(site, product_id):
    """The shipped default of a built-in product on a site (what Reset to default brings back)."""
    return [{"name": g["name"], "default": g["default"], "paths": list(g["paths"])} for g in _shipped(site).get(product_id, [])]


def check_version(current, version):
    try:
        version = int(version)
    except (TypeError, ValueError):
        raise ValueError("The template version is missing; reload the page")
    if version != current["version"]:
        who = f" by {current['updated_by']} at {current['updated']}" if current["updated_by"] else ""
        raise ValueError(f"The {current['label']} template of this site was changed{who} after you opened it. "
                         "Discard your changes to load the newest version, then edit again.")


def save(site, product_id, groups, version, username, client_ip, apic="", reset=False):
    """Store the groups of one product on one site (reset: back to the shipped default) and record it in the history.
    Returns (record id, summary)."""
    shipped = _shipped(site)
    with audit._write_lock, audit._db() as conn:
        meta = next((p for p in _products(conn) if p["id"] == product_id), None)
        if not meta:
            raise ValueError(f"Unknown product: '{product_id}'")
        current = _state(conn, site, meta, shipped)
        check_version(current, version)
        if reset:
            if meta["custom"]:
                raise ValueError(f"{meta['label']} was added by a user and has no default template")
            if not current["edited"]:
                raise ValueError(f"The {meta['label']} template of {site} is already the default")
            groups = default_groups(site, product_id)
        d = diff(current["groups"], groups)
        if not reset and not d["changed"]:
            raise ValueError("Nothing to save: the template is the same as the saved one")
        now = audit.now()
        conn.execute("INSERT INTO aci_templates (site, product, groups, version, updated_by, updated) VALUES (?, ?, ?, ?, ?, ?)"
                     " ON CONFLICT (site, product) DO UPDATE SET groups = excluded.groups, version = excluded.version,"
                     " updated_by = excluded.updated_by, updated = excluded.updated",
                     (site, product_id, None if reset else json.dumps(groups, ensure_ascii=False), current["version"] + 1, username, now))
        summary = ("reset to the default template: " if reset else "") + summary_text(d, current["groups"], groups)
        details = {"kind": "reset" if reset else "save", "paths": [i for i in d["items"] if i["status"] != "same"],
                   "groups": d["groups"], "reordered": d["reordered"], "before": current["groups"], "after": groups,
                   "version": current["version"] + 1}
        record_id = _record(conn, username, site, apic, f"templates/{site}/{product_id}", meta["label"], summary, details, client_ip)
    return record_id, summary


def check_product(body, exclude=None):
    """{"label", "platform", "mode", "immediacy"} of a product a user adds or changes; the label must be unique."""
    label = check_text(body.get("label"), "Product name", 40)
    platform = check_text(body.get("platform"), "Platform", 40, required=False)
    mode = aci.MODES.get(str(body.get("mode") or "regular").strip().lower())
    if not mode:
        raise ValueError(f"Unknown mode: '{body.get('mode')}' (trunk/regular, native, untagged)")
    immediacy = aci.choice(str(body.get("immediacy") or "immediate").lower(), aci.IMMEDIACY, "Immediacy")
    if any(p["label"].lower() == label.lower() and p["id"] != exclude for p in products()):
        raise ValueError(f"A product named '{label}' already exists")
    return {"label": label, "platform": platform, "mode": mode, "immediacy": immediacy}


def _new_id(conn, label):
    taken = {p["id"] for p in _products(conn)} | set(product_templates.load().get("products", {}))
    base = re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")[:28] or "product"
    candidate, n = base, 2
    while candidate in taken:
        candidate, n = f"{base}-{n}", n + 1
    return candidate


def add_product(body, username, client_ip):
    """A product of its own (e.g. a new platform): on every site, with an empty template. Returns (id, record id)."""
    meta = check_product(body)
    with audit._write_lock, audit._db() as conn:
        if conn.execute("SELECT count(*) FROM aci_products").fetchone()[0] >= MAX_CUSTOM_PRODUCTS:
            raise ValueError(f"At most {MAX_CUSTOM_PRODUCTS} added products")
        product_id = _new_id(conn, meta["label"])
        conn.execute("INSERT INTO aci_products (id, label, platform, mode, immediacy, created_by, created) VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (product_id, meta["label"], meta["platform"], meta["mode"], meta["immediacy"], username, audit.now()))
        record_id = _record(conn, username, "", "", f"products/{product_id}", meta["label"],
                            f"product added: {meta['label']}" + (f" ({meta['platform']})" if meta["platform"] else ""),
                            {"kind": "product-add", "product": {"id": product_id, **meta}}, client_ip)
    return product_id, record_id


def _custom(conn, product_id):
    row = conn.execute("SELECT * FROM aci_products WHERE id = ?", (product_id,)).fetchone()
    if not row:
        if product_id in product_templates.load().get("products", {}):
            raise ValueError("Built-in products (from product_templates.json) cannot be renamed or deleted")
        raise ValueError(f"Unknown product: '{product_id}'")
    return dict(row)


def update_product(product_id, body, username, client_ip):
    meta = check_product(body, exclude=product_id)
    with audit._write_lock, audit._db() as conn:
        before = _custom(conn, product_id)
        before = {k: before[k] for k in ("label", "platform", "mode", "immediacy")}
        if before == meta:
            raise ValueError("Nothing to save: the product settings are unchanged")
        conn.execute("UPDATE aci_products SET label = ?, platform = ?, mode = ?, immediacy = ?, updated_by = ?, updated = ? WHERE id = ?",
                     (meta["label"], meta["platform"], meta["mode"], meta["immediacy"], username, audit.now(), product_id))
        changed = ", ".join(f"{k} {before[k] or '—'} → {meta[k] or '—'}" for k in meta if before[k] != meta[k])
        return _record(conn, username, "", "", f"products/{product_id}", meta["label"], f"product changed: {changed}",
                       {"kind": "product-change", "product": {"id": product_id, **meta}, "before": before}, client_ip)


def delete_product(product_id, username, client_ip):
    """Delete a product users added, with its templates on every site (kept in the history record)."""
    with audit._write_lock, audit._db() as conn:
        meta = _custom(conn, product_id)
        templates = {row["site"]: json.loads(row["groups"]) for row in
                     conn.execute("SELECT site, groups FROM aci_templates WHERE product = ? AND groups IS NOT NULL ORDER BY site", (product_id,))}
        conn.execute("DELETE FROM aci_templates WHERE product = ?", (product_id,))
        conn.execute("DELETE FROM aci_products WHERE id = ?", (product_id,))
        counts = ", ".join(f"{site} {sum(len(g['paths']) for g in groups)}" for site, groups in templates.items())
        return _record(conn, username, "", "", f"products/{product_id}", meta["label"],
                       f"product deleted: {meta['label']}" + (f" (paths per site: {counts})" if counts else ""),
                       {"kind": "product-delete", "product": {k: meta[k] for k in ("id", "label", "platform", "mode", "immediacy")},
                        "templates": templates}, client_ip)

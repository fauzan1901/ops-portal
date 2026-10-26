"""Templates of Operation Automation: checks an administrator makes on the portal (button Create template), without
writing Ansible. A template has a name, the activity and product it is listed under, the host group it runs on (the
groups of Hosts & SSH and sites.yml) and its steps. A step is one command, with the rules that rate its output:
Problem if the output contains a text, Warning if it contains one, Problem if it does not contain one, and Problem when
the command fails. The portal makes the run itself: the same playbook, host connection and result page as every check.

What a step does comes from the command itself, never from what the author says (classify):
  read    every command of the step is a known read command (READ) used with read options, without writing a file
          (no "> file", tee, sed -i, -o file...) and without command substitution: it runs with the check, on the
          host chosen at launch, with the SSH credential of that host
  change  anything else. It never runs with the check: the result offers the change steps as a fix (all of them in
          order, one script, stopping at the first that fails), which needs the fix permission, a host whose SSH
          credential allows fixes (Hosts & SSH) and the host name typed by the operator (risk high)
A step may wait before the next one (Wait before the next step, up to MAX_WAIT seconds, MAX_WAITS in all): between two
read steps inside the check; after a change step inside the fix, the last of these holding the check that runs again
after the fix (time for a service to come back). Huawei routers stay read-only: their templates only have display
commands, and no waits. Only administrators create, change and
delete templates (each change is in the portal events); every user of the module runs them.
"""
import contextlib
import datetime
import json
import os
import re
import sqlite3

import settings

from . import catalog
from .wi_analysis.template import MAX_WAIT, MAX_WAITS, classify, wait_text, waits

PREFIX = "tpl-"
ID_RE = re.compile(r"^tpl-[a-z0-9-]{1,56}$")
GROUPS = {   # host group -> (label, shell of the change steps); huawei: no change steps
    "linux": ("Linux VMs", "sh"), "cdn": ("Acme CDN VMs", "sh"), "repo": ("Repository VMs", "sh"),
    "dns": ("DNS recursors", "sh"), "siem": ("SIEM collectors and forwarders", "sh"), "esxi": ("ESXi hosts", "sh"),
    "gb200": ("GB200 compute trays", "sh"), "vyos": ("VyOS gateways", "vyos"), "huawei": ("Huawei routers", ""),
}
READ_ONLY_GROUPS = ("huawei",)
MAX_STEPS = 20
MAX_COMMAND = 1000
MAX_PATTERN = 200


@contextlib.contextmanager
def _db():
    os.makedirs(os.path.dirname(os.path.abspath(settings.DB_PATH)), exist_ok=True)
    conn = sqlite3.connect(settings.DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def _now():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def init():
    with _db() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS wi_templates (
            id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, summary TEXT, activity TEXT NOT NULL, category TEXT NOT NULL,
            grp TEXT NOT NULL, steps TEXT NOT NULL, created TEXT, created_by TEXT, updated TEXT, updated_by TEXT)""")


# ---------------- storage ----------------
def _slug(name):
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", name.lower())).strip("-")[:48] or "template"


def _row(r):
    item = {k: r[k] for k in ("id", "name", "summary", "activity", "category", "created", "created_by", "updated", "updated_by")}
    item["group"] = r["grp"]
    try:
        item["steps"] = json.loads(r["steps"] or "[]")
    except ValueError:
        item["steps"] = []
    for s in item["steps"]:   # what a step does always comes from its command as the portal reads it now
        s["mode"], s["why"] = classify(s.get("command"), item["group"])
    return item


def all_templates():
    with _db() as db:
        return [_row(r) for r in db.execute("SELECT * FROM wi_templates ORDER BY name COLLATE NOCASE")]


def get(template_id):
    if not ID_RE.match(str(template_id or "")):
        return None
    with _db() as db:
        r = db.execute("SELECT * FROM wi_templates WHERE id = ?", (template_id,)).fetchone()
    return _row(r) if r else None


NESTED_REPEAT = re.compile(r"\((?:[^()\\]|\\.)*[+*}](?:[^()\\]|\\.)*\)[+*{]")


def _pattern(value, label):
    value = str(value or "").strip()
    if len(value) > MAX_PATTERN:
        raise ValueError(f"{label}: at most {MAX_PATTERN} characters.")
    if value:
        try:
            re.compile(value)
        except re.error as e:
            raise ValueError(f"{label}: not a valid text or pattern ({e}).") from None
        if NESTED_REPEAT.search(value):   # (a+)+ and the like can take minutes on a long output
            raise ValueError(f"{label}: a repeated group that itself repeats, such as (a+)+, is not allowed: write it without "
                             "the outer repetition.")
    return value


def clean(body):
    """A template from the form, validated: ValueError with the reason otherwise."""
    body = body if isinstance(body, dict) else {}
    name = " ".join(str(body.get("name") or "").split())
    if not 3 <= len(name) <= 80:
        raise ValueError("Name: 3 to 80 characters.")
    summary = " ".join(str(body.get("summary") or "").split())
    if len(summary) > 500:
        raise ValueError("Description: at most 500 characters.")
    activity = str(body.get("activity") or "")
    if activity not in catalog.ACTIVITY_IDS:
        raise ValueError("Choose an activity.")
    category = str(body.get("category") or "")
    if category not in [c["id"] for c in catalog.CATALOG["categories"]]:
        raise ValueError("Choose a product.")
    group = str(body.get("group") or "")
    if group not in GROUPS:
        raise ValueError("Choose the host group the template runs on.")
    steps_in = body.get("steps") if isinstance(body.get("steps"), list) else []
    if not 1 <= len(steps_in) <= MAX_STEPS:
        raise ValueError(f"A template has 1 to {MAX_STEPS} steps.")
    steps = []
    for i, s in enumerate(steps_in, 1):
        s = s if isinstance(s, dict) else {}
        title = " ".join(str(s.get("title") or "").split())
        command = str(s.get("command") or "").strip()
        if not 1 <= len(title) <= 80:
            raise ValueError(f"Step {i}: a title of 1 to 80 characters.")
        if not command or len(command) > MAX_COMMAND or "\n" in command or "\x00" in command:
            raise ValueError(f"Step {i}: one command line of at most {MAX_COMMAND} characters.")
        mode, why = classify(command, group)
        if mode == "change" and group in READ_ONLY_GROUPS:
            raise ValueError(f"Step {i}: {GROUPS[group][0]} stay read-only: {why}.")
        try:
            wait = int(s.get("wait") or 0)
        except (TypeError, ValueError):
            raise ValueError(f"Step {i}, Wait before the next step: a whole number of seconds or minutes.") from None
        if not 0 <= wait <= MAX_WAIT:
            raise ValueError(f"Step {i}, Wait before the next step: 0 to {wait_text(MAX_WAIT)}.")
        if wait and group in READ_ONLY_GROUPS:
            raise ValueError(f"Step {i}: {GROUPS[group][0]} run each command on its own connection, without waits.")
        steps.append({"title": title, "command": command, "wait": wait,
                      "problem_if": _pattern(s.get("problem_if"), f"Step {i}, Problem if the output contains"),
                      "warning_if": _pattern(s.get("warning_if"), f"Step {i}, Warning if the output contains"),
                      "expect": _pattern(s.get("expect"), f"Step {i}, Problem if the output does not contain"),
                      "fail_on_error": s.get("fail_on_error") is not False})
    if sum(s["wait"] for s in steps) > MAX_WAITS:
        raise ValueError(f"The waits of a template add up to at most {wait_text(MAX_WAITS)}.")
    return {"name": name, "summary": summary, "activity": activity, "category": category, "group": group, "steps": steps}


def save(actor, body, template_id=None):
    t = clean(body)
    now = _now()
    with _db() as db:
        same = db.execute("SELECT id FROM wi_templates WHERE name = ? COLLATE NOCASE", (t["name"],)).fetchone()
        if same and same["id"] != template_id:
            raise ValueError(f"A template named {t['name']!r} already exists.")
        if template_id:
            if not db.execute("SELECT 1 FROM wi_templates WHERE id = ?", (template_id,)).fetchone():
                raise LookupError("Template not found.")
            db.execute("UPDATE wi_templates SET name = ?, summary = ?, activity = ?, category = ?, grp = ?, steps = ?, "
                       "updated = ?, updated_by = ? WHERE id = ?",
                       (t["name"], t["summary"], t["activity"], t["category"], t["group"], json.dumps(t["steps"]), now, actor,
                        template_id))
            return template_id
        base = PREFIX + _slug(t["name"])
        new_id, n = base, 2
        built_in = {c["id"] for c in catalog.CATALOG["checks"]}
        while new_id in built_in or db.execute("SELECT 1 FROM wi_templates WHERE id = ?", (new_id,)).fetchone():
            new_id, n = f"{base}-{n}", n + 1
        db.execute("INSERT INTO wi_templates (id, name, summary, activity, category, grp, steps, created, created_by, updated,"
                   " updated_by) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                   (new_id, t["name"], t["summary"], t["activity"], t["category"], t["group"], json.dumps(t["steps"]), now,
                    actor, now, actor))
        return new_id


def delete(template_id):
    with _db() as db:
        if not db.execute("DELETE FROM wi_templates WHERE id = ?", (template_id,)).rowcount:
            raise LookupError("Template not found.")


# ---------------- as a check of the catalog ----------------
def as_check(t):
    """The catalog entry of a template: listed, launched and run like every check (basis "template")."""
    reads = [s for s in t["steps"] if s["mode"] == "read"]
    pause = waits(t["steps"], t["group"])
    changes = [s for s in t["steps"] if s["mode"] == "change"]
    summary = t["summary"] or f"Template: {len(reads)} read step(s)" + (f", {len(changes)} change step(s) after confirmation" if changes else "") + "."
    does = t["summary"] if t["summary"] and len(t["summary"]) <= 100 else (
        f"Runs {len(t['steps'])} command(s) on one of the {GROUPS[t['group']][0]} and rates the output")
    return {
        "id": t["id"], "category": t["category"], "activity": t["activity"], "title": t["name"], "summary": summary,
        "does": does, "fix": bool(changes), "collect": False,
        "status": "ready", "basis": "template", "wi": [], "reason": "",
        "steps": [s["title"] + (" (change, after confirmation)" if s["mode"] == "change" else "")
                  + (f", then wait {wait_text(pause[s['mode']][i])}" if i in pause[s["mode"]] else "")
                  for i, s in enumerate(t["steps"], 1)],
        "params": [{"name": "host", "label": f"Host ({GROUPS[t['group']][0]})", "type": "host", "groups": [t["group"]],
                    "required": True}],
        "needs": [f"hosts:{t['group']}"], "uses": [],
        "template": {"group": t["group"], "steps": t["steps"], "created_by": t["created_by"], "updated": t["updated"],
                     "updated_by": t["updated_by"]},
    }


def read_wait(check):
    """The seconds the check of a template waits between its read steps (added to the time limit of the run)."""
    t = check.get("template") or {}
    return sum(waits(t.get("steps") or [], str(t.get("group") or ""))["read"].values())


def checks():
    return [as_check(t) for t in all_templates()]


def context(t):
    """What the run needs of the template (wi_ctx["template"]): read in the playbook by wi_analysis.template."""
    return {"id": t["id"], "group": t["group"], "shell": GROUPS[t["group"]][1],
            "steps": [dict({k: s[k] for k in ("title", "command", "problem_if", "warning_if", "expect", "fail_on_error", "mode")},
                           wait=int(s.get("wait") or 0)) for s in t["steps"]]}

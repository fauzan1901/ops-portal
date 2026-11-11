"""Engineer review of every fix an operator runs from a check result (the owner's decision of 2026-11-10): pre-check,
then review by an engineer, then the operator runs it, within a short time.

  1. The operator presses Run this fix: nothing runs yet. The portal runs the check again now, with the same parameters
     (the pre-check: a check, so read-only), and records a fix request "Pre-check running".
  2. When the pre-check has ended, its result must still offer the same fix with the same commands (a trailing
     "   # comment" aside: it only shows values), every ticked item must still be there with the same commands and able to
     run, and the requester must still be allowed to run it. Then the request waits for review; otherwise it ends as
     "Pre-check failed", with why. A request waits at most as long as its pre-check is recent (fixes.MAX_AGE_MINUTES).
  3. An engineer (permission wi-fix-review on the Users page, or an administrator) approves or rejects it; a rejection
     needs a note. Nobody reviews their own request, administrators included.
  4. Approved: the requester has Run now for `minutes` (default 15; administrators set 5 to 30: the owner refused 60),
     never past the freshness of the pre-check. Later the request expires: a new pre-check and a new review. Run now runs
     the fix of the pre-check's result (the commands the engineer saw), shown with the run it was asked from; the typed
     confirmation of a high-risk fix and the checks inside a fix (require / wait) still apply.
The automatic actions of alert rules do not come here: the owner approved them on the rule (alerts.py), and they run as
the robot account. Every step is in the activity log (modules/wi): wi.fix_request, wi.fix_precheck, wi.fix_approve,
wi.fix_reject, wi.fix_withdraw, wi.fix_expired, then wi.fix as before.

Table wi_fix_requests (and wi_fix_review_settings) in the portal database.
"""
import contextlib
import datetime
import json
import os
import re
import sqlite3

import settings

from . import fixes

PERMISSION = "wi-fix-review"
DEFAULT_MINUTES = 15
MIN_MINUTES, MAX_MINUTES = 5, 30
OPEN = ("prechecking", "waiting", "approved", "starting")
STATES = {"prechecking": "Pre-check running", "waiting": "Waiting for review", "approved": "Approved", "starting": "Starting",
          "ran": "Ran", "rejected": "Rejected", "precheck_failed": "Pre-check failed", "expired": "Expired",
          "withdrawn": "Withdrawn"}
MAX_NOTE = 500
COMMENT = re.compile(r"\s{2,}#\s.*$")   # as wi_analysis.openstack_fix_command: the trailing comment of a command
FIELDS = ("id", "ts", "username", "client_ip", "site", "check_id", "check_title", "host", "run_id", "rec_index", "title", "kind",
          "target", "risk", "label", "noun", "precheck_run_id", "precheck_index", "precheck_finished", "precheck_status",
          "precheck_summary", "status", "reason", "reviewed_by", "reviewed_at", "review_note", "approved_until", "action_id",
          "ran_at", "updated")
JSON_FIELDS = {"selected": [], "items": [], "commands": [], "fingerprint": {}, "precheck_selected": [], "precheck_commands": [],
               "precheck_notes": []}


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
    return datetime.datetime.now().astimezone()


def _iso(t):
    return t.isoformat(timespec="seconds")


def _time(text):
    try:
        t = datetime.datetime.fromisoformat(str(text or ""))
    except ValueError:
        return None
    return t if t.tzinfo else t.astimezone()


def init():
    """Create the tables. A pre-check that was running when the portal stopped cannot end any more (its run is unknown):
    those requests fail; a Run now that was starting expires (look at Runs). Returns the requests changed."""
    with _db() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS wi_fix_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, username TEXT NOT NULL, client_ip TEXT,
            site TEXT NOT NULL, check_id TEXT NOT NULL, check_title TEXT NOT NULL DEFAULT '', host TEXT NOT NULL DEFAULT '',
            run_id INTEGER NOT NULL, rec_index INTEGER NOT NULL, title TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL DEFAULT '',
            target TEXT NOT NULL DEFAULT '', risk TEXT NOT NULL DEFAULT 'normal', label TEXT NOT NULL DEFAULT '',
            noun TEXT NOT NULL DEFAULT '', selected TEXT NOT NULL DEFAULT '[]', items TEXT NOT NULL DEFAULT '[]',
            commands TEXT NOT NULL DEFAULT '[]', fingerprint TEXT NOT NULL DEFAULT '{}',
            precheck_run_id INTEGER, precheck_index INTEGER, precheck_selected TEXT NOT NULL DEFAULT '[]',
            precheck_commands TEXT NOT NULL DEFAULT '[]', precheck_finished TEXT, precheck_status TEXT,
            precheck_summary TEXT NOT NULL DEFAULT '', precheck_notes TEXT NOT NULL DEFAULT '[]',
            status TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '', reviewed_by TEXT, reviewed_at TEXT, review_note TEXT,
            approved_until TEXT, action_id INTEGER, ran_at TEXT, updated TEXT)""")
        db.execute("CREATE INDEX IF NOT EXISTS wi_fix_requests_run ON wi_fix_requests(run_id)")
        db.execute("CREATE INDEX IF NOT EXISTS wi_fix_requests_status ON wi_fix_requests(status, site)")
        db.execute("""CREATE TABLE IF NOT EXISTS wi_fix_review_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL,
            updated TEXT, updated_by TEXT)""")
        stale = [_row(r) for r in db.execute("SELECT * FROM wi_fix_requests WHERE status IN ('prechecking', 'starting')")]
        now = _iso(_now())
        db.execute("UPDATE wi_fix_requests SET status = 'precheck_failed', reason = 'The portal stopped during the pre-check: "
                   "press Run this fix again.', updated = ? WHERE status = 'prechecking'", (now,))
        db.execute("UPDATE wi_fix_requests SET status = 'expired', reason = 'The portal stopped while the fix was starting: "
                   "look at the run whether it started; otherwise ask again.', updated = ? WHERE status = 'starting'", (now,))
    return stale


# ---------------- who ----------------
def can_review(user):
    """An engineer: an administrator, or an account with the permission wi-fix-review."""
    return bool(user) and (user.get("role") == "admin" or PERMISSION in (user.get("modules") or []))


def same_person(a, b):
    return str(a or "").strip().lower() == str(b or "").strip().lower()


# ---------------- settings ----------------
def get_settings():
    with _db() as db:
        r = db.execute("SELECT value, updated, updated_by FROM wi_fix_review_settings WHERE key = 'minutes'").fetchone()
    try:
        minutes = int(r["value"]) if r else DEFAULT_MINUTES
    except ValueError:
        minutes = DEFAULT_MINUTES
    minutes = minutes if MIN_MINUTES <= minutes <= MAX_MINUTES else DEFAULT_MINUTES
    return {"minutes": minutes, "min": MIN_MINUTES, "max": MAX_MINUTES, "default": DEFAULT_MINUTES,
            "updated": r["updated"] if r else "", "updated_by": r["updated_by"] if r else ""}


def save_settings(data, actor):
    """How long Run now stays valid after an approval. Returns (before, after) minutes."""
    d = data if isinstance(data, dict) else {}
    try:
        minutes = int(d.get("minutes"))
    except (TypeError, ValueError):
        raise ValueError(f"Run now stays valid: a whole number of minutes, {MIN_MINUTES} to {MAX_MINUTES}.") from None
    if not MIN_MINUTES <= minutes <= MAX_MINUTES:
        raise ValueError(f"Run now stays valid {MIN_MINUTES} to {MAX_MINUTES} minutes after the approval (the owner refused 60: "
                         "a longer time lets the state change after the review).")
    before = get_settings()["minutes"]
    with _db() as db:
        db.execute("INSERT INTO wi_fix_review_settings (key, value, updated, updated_by) VALUES ('minutes', ?, ?, ?) "
                   "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated = excluded.updated, updated_by = excluded.updated_by",
                   (str(minutes), _iso(_now()), actor))
    return before, minutes


# ---------------- the same fix ----------------
def normalize(commands):
    """Commands as compared: without trailing comments (they show values, e.g. "3 days old") and empty lines."""
    out = []
    for c in commands or []:
        text = COMMENT.sub("", str(c)).strip()
        if text and not text.startswith("#"):
            out.append(text)
    return out


def fingerprint(action, state):
    """What makes a fix the same fix: kind, where, its button and its commands (a fix with items to tick: what they are
    called; each item is compared by its own commands). ONTAP: the LIF operation; VyOS: the image and the target."""
    action = action or {}
    fp = {"kind": state["kind"], "target": state["target"], "label": state["label"]}
    if state.get("selectable"):
        fp["noun"] = state["noun"]
    else:
        fp["commands"] = normalize(state["commands"])
    if state["kind"] == "ontap":
        fp.update({k: action.get(k) for k in ("op", "uuid", "lif", "enable")})
    if state["kind"] in fixes.VYOS_KINDS:
        up = action.get("upgrade") or {}
        fp["upgrade"] = {k: up.get(k) for k in ("image", "target", "rollback_image", "hwid", "absent", "old_image")}
    return fp


def compare(fp, wanted, candidates):
    """The fix of the pre-check that is the one asked for. fp: the fingerprint asked for; wanted: the ticked items
    [{"label", "commands"}] (None: a fix without items); candidates: [(index, action, state)] of the pre-check's result for
    the requester. Returns (index, state, selected, notes, problems): selected are the indexes of the ticked items in the
    pre-check's result; problems empty when it may go to review."""
    same = [(i, a, st) for i, a, st in candidates if fingerprint(a, st) == fp]
    if not same:
        near = [(i, st) for i, a, st in candidates
                if st["kind"] == fp["kind"] and st["target"] == fp["target"] and st["label"] == fp["label"]]
        if near and wanted is None:
            now = normalize(near[0][1]["commands"])
            return None, None, [], [], ["The pre-check still offers this fix, but with other commands: "
                                        + "; ".join(now[:5]) + ("; …" if len(now) > 5 else "")
                                        + ". Ask again from the pre-check's result if they are right."]
        return None, None, [], [], ["The pre-check no longer offers this fix (the problem may be gone, or what was found has "
                                    "changed): open its result."]
    index, action, st = same[0]
    if not st["available"]:
        return index, st, [], [], [f"The fix cannot run from the pre-check's result: {st['reason']}"]
    if wanted is None:
        return index, st, [], ["The pre-check offers the same fix with the same commands."], []
    items = st.get("items") or []
    by_cmds = {}
    for k, it in enumerate(items):
        by_cmds.setdefault(json.dumps(normalize(it.get("commands"))), []).append(k)
    selected, problems = [], []
    for w in wanted:
        key = json.dumps(normalize(w.get("commands")))
        ks = [k for k in by_cmds.get(key, []) if k not in selected] if normalize(w.get("commands")) else []
        if ks:
            selected.append(ks[0])
            continue
        named = [it for it in items if it.get("label") == w.get("label")]
        if named and named[0].get("disabled"):
            problems.append(f"{w.get('label')} cannot run now: {named[0]['disabled']}")
        elif named:
            problems.append(f"{w.get('label')}: its commands changed")
        else:
            problems.append(f"{w.get('label')} is no longer in the result")
    noun = st.get("noun") or "items"
    if not problems:
        try:
            fixes.selection(action, sorted(selected))
        except ValueError as e:
            problems.append(str(e))
    if problems:
        return index, st, [], [], [f"Ticked {noun} that changed: " + "; ".join(problems[:8])
                                   + (f"; and {len(problems) - 8} more" if len(problems) > 8 else "") + "."]
    n = len(selected)
    return index, st, sorted(selected), [f"The pre-check offers the same fix; the {n} ticked {noun} are still there with the "
                                         "same commands and can run."], []


# ---------------- storage ----------------
def _row(r):
    item = {k: r[k] for k in FIELDS}
    for k, default in JSON_FIELDS.items():
        try:
            item[k] = json.loads(r[k]) if r[k] else default
        except ValueError:
            item[k] = default
    item["state"] = STATES.get(item["status"], item["status"])
    return item


def begin(user, record, index, title, state, fp, selected, items, client):
    """Record a request (status prechecking); its pre-check is started next."""
    now = _iso(_now())
    with _db() as db:
        cur = db.execute(
            "INSERT INTO wi_fix_requests (ts, username, client_ip, site, check_id, check_title, host, run_id, rec_index, title, kind,"
            " target, risk, label, noun, selected, items, commands, fingerprint, status, updated)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (now, user["username"], client, record["site"], record["check_id"], record.get("check_title") or "", record.get("host") or "",
             record["id"], index, str(title or "")[:500], state["kind"], state["target"], state["risk"], state["label"],
             state.get("noun") or "", json.dumps(selected or []), json.dumps(items or []), json.dumps(state["commands"]),
             json.dumps(fp), "prechecking", now))
        return cur.lastrowid


def get(request_id):
    with _db() as db:
        r = db.execute("SELECT * FROM wi_fix_requests WHERE id = ?", (request_id,)).fetchone()
    return _row(r) if r else None


def _set(request_id, when=None, **fields):
    """Change a request; when: the status it must still have (None: any). True when it changed."""
    fields = {k: (json.dumps(v) if k in JSON_FIELDS else v) for k, v in fields.items() if k in FIELDS or k in JSON_FIELDS}
    fields["updated"] = _iso(_now())
    sql = f"UPDATE wi_fix_requests SET {', '.join(f'{k} = ?' for k in fields)} WHERE id = ?"
    args = [*fields.values(), request_id]
    if when:
        when = (when,) if isinstance(when, str) else tuple(when)
        sql += f" AND status IN ({','.join('?' * len(when))})"
        args += list(when)
    with _db() as db:
        return db.execute(sql, args).rowcount > 0


def open_for(run_id, rec_index):
    """The open request (pre-check running, waiting, approved) of this fix of this run, or None."""
    with _db() as db:
        r = db.execute(f"SELECT * FROM wi_fix_requests WHERE run_id = ? AND rec_index = ? AND status IN ({','.join('?' * len(OPEN))}) "
                       "ORDER BY id DESC LIMIT 1", (run_id, rec_index, *OPEN)).fetchone()
    return _row(r) if r else None


def precheck_started(request_id, precheck_run_id):
    _set(request_id, "prechecking", precheck_run_id=precheck_run_id)


def precheck_ended(request_id, run, index, state, selected, notes, problems):
    """The pre-check ended: waiting (no problems) or precheck_failed. False when the request had left prechecking."""
    fields = {"precheck_run_id": run["id"], "precheck_finished": run.get("finished") or _iso(_now()), "precheck_status": run.get("status"),
              "precheck_summary": str(run.get("summary") or run.get("error") or "")[:1000], "precheck_notes": notes + problems,
              "precheck_index": index, "precheck_selected": selected}
    if state:
        fields.update(precheck_commands=state["commands"], risk=state["risk"])
    if problems:
        fields.update(status="precheck_failed", reason=" ".join(problems)[:1000])
    else:
        fields.update(status="waiting", reason="")
    return _set(request_id, "prechecking", **fields)


def fresh_until(item):
    """Until when the pre-check of a request is recent enough to run a fix from (fixes.MAX_AGE_MINUTES)."""
    t = _time(item.get("precheck_finished"))
    return t + datetime.timedelta(minutes=fixes.MAX_AGE_MINUTES) if t else None


def approve(request_id, reviewer, note):
    """Approve a request waiting for review. Returns the request. ValueError / PermissionError (own request)."""
    item = get(request_id)
    if not item:
        raise LookupError("Fix request not found")
    if same_person(item["username"], reviewer):
        raise PermissionError("You asked for this fix: another engineer reviews it (nobody approves their own request).")
    if item["status"] != "waiting":
        raise ValueError(f"Fix request #{request_id} is {item['state'].lower()}: only a request waiting for review can be approved.")
    now, fresh = _now(), fresh_until(item)
    if not fresh or fresh <= now:
        raise ValueError(f"The pre-check of fix request #{request_id} is older than {fixes.MAX_AGE_MINUTES} minutes: it expires; "
                         "the operator asks again for a new pre-check.")
    minutes = get_settings()["minutes"]
    until = min(now + datetime.timedelta(minutes=minutes), fresh)
    if not _set(request_id, "waiting", status="approved", reviewed_by=reviewer, reviewed_at=_iso(now),
                review_note=str(note or "").strip()[:MAX_NOTE], approved_until=_iso(until)):
        raise ValueError(f"Fix request #{request_id} was changed meanwhile: open it again.")
    return get(request_id)


def reject(request_id, reviewer, note):
    item = get(request_id)
    if not item:
        raise LookupError("Fix request not found")
    if same_person(item["username"], reviewer):
        raise PermissionError("You asked for this fix: another engineer reviews it. To drop it, withdraw it.")
    note = " ".join(str(note or "").split())
    if len(note) < 3:
        raise ValueError("Reject: write why in the note (the operator reads it).")
    if item["status"] != "waiting":
        raise ValueError(f"Fix request #{request_id} is {item['state'].lower()}: only a request waiting for review can be rejected.")
    if not _set(request_id, "waiting", status="rejected", reviewed_by=reviewer, reviewed_at=_iso(_now()), review_note=note[:MAX_NOTE],
                reason=f"Rejected by {reviewer}: {note[:MAX_NOTE]}"):
        raise ValueError(f"Fix request #{request_id} was changed meanwhile: open it again.")
    return get(request_id)


def withdraw(request_id, username):
    """The requester drops an open request (not while its fix is starting)."""
    item = get(request_id)
    if not item:
        raise LookupError("Fix request not found")
    if not same_person(item["username"], username):
        raise PermissionError(f"Only {item['username']}, who asked for it, can withdraw fix request #{request_id}.")
    if not _set(request_id, ("prechecking", "waiting", "approved"), status="withdrawn", reason=f"Withdrawn by {username}."):
        raise ValueError(f"Fix request #{request_id} is {item['state'].lower()}: it can no longer be withdrawn.")
    return get(request_id)


def claim(request_id):
    """Run now: approved -> starting, once (two clicks never start the fix twice). False when it was not approved."""
    return _set(request_id, "approved", status="starting")


def release(request_id):
    """The fix did not start (e.g. the confirmation was not typed right): approved again, until the same time."""
    return _set(request_id, "starting", status="approved")


def ran(request_id, action_id):
    _set(request_id, "starting", status="ran", action_id=action_id, ran_at=_iso(_now()), reason="")


def failed_start(request_id, reason):
    """The pre-check or the fix could not start at all."""
    _set(request_id, None, status="precheck_failed" if (get(request_id) or {}).get("status") == "prechecking" else "expired",
         reason=str(reason)[:1000])


def expire_due(now=None):
    """Requests whose time is over: approved past approved_until, waiting with a pre-check older than
    fixes.MAX_AGE_MINUTES. Returns them as they are now (expired, with why)."""
    now = now or _now()
    out = []
    with _db() as db:
        rows = [_row(r) for r in db.execute("SELECT * FROM wi_fix_requests WHERE status IN ('approved', 'waiting')")]
    for item in rows:
        if item["status"] == "approved":
            until = _time(item["approved_until"])
            if until and until <= now:
                why = (f"The approval by {item['reviewed_by']} ended at {until.strftime('%H:%M')} without Run now: a new pre-check "
                       "and review are needed.")
                if _set(item["id"], "approved", status="expired", reason=why):
                    out.append(dict(item, status="expired", state=STATES["expired"], reason=why))
        else:
            fresh = fresh_until(item)
            if fresh and fresh <= now:
                why = (f"Not reviewed while its pre-check was recent ({fixes.MAX_AGE_MINUTES} minutes): a new pre-check and review are "
                       "needed.")
                if _set(item["id"], "waiting", status="expired", reason=why):
                    out.append(dict(item, status="expired", state=STATES["expired"], reason=why))
    return out


def query(status="", site="", username="", limit=50, offset=0, run_id=None):
    where, args = [], []
    if status == "open":
        where.append(f"status IN ({','.join('?' * len(OPEN))})")
        args += list(OPEN)
    elif status:
        if status not in STATES:
            raise ValueError("Unknown status")
        where.append("status = ?")
        args.append(status)
    for column, value in (("site", site), ("username", username)):
        if value:
            where.append(f"{column} = ?")
            args.append(value)
    if run_id is not None:
        where.append("(run_id = ? OR precheck_run_id = ?)")
        args += [int(run_id), int(run_id)]
    sql = (" WHERE " + " AND ".join(where)) if where else ""
    limit, offset = max(1, min(int(limit), 200)), max(0, int(offset))
    with _db() as db:
        total = db.execute(f"SELECT COUNT(*) FROM wi_fix_requests{sql}", args).fetchone()[0]
        items = [_row(r) for r in db.execute(f"SELECT * FROM wi_fix_requests{sql} ORDER BY id DESC LIMIT ? OFFSET ?", args + [limit, offset])]
        users = [r[0] for r in db.execute("SELECT DISTINCT username FROM wi_fix_requests ORDER BY username LIMIT 500")]
    return {"items": items, "total": total, "users": users}


def by_actions(action_ids):
    """{action id: request} of the fixes that ran from an approved request."""
    ids = [int(x) for x in action_ids or []][:500]
    if not ids:
        return {}
    with _db() as db:
        rows = db.execute(f"SELECT * FROM wi_fix_requests WHERE action_id IN ({','.join('?' * len(ids))})", ids).fetchall()
    return {r["action_id"]: _row(r) for r in rows}


def waiting_counts(now=None):
    """{site: requests waiting for review whose pre-check is still recent} (also before expire_due wrote them)."""
    now = now or _now()
    with _db() as db:
        rows = db.execute("SELECT site, precheck_finished FROM wi_fix_requests WHERE status = 'waiting'").fetchall()
    out = {}
    for r in rows:
        fresh = fresh_until({"precheck_finished": r["precheck_finished"]})
        if fresh and fresh > now:
            out[r["site"]] = out.get(r["site"], 0) + 1
    return out

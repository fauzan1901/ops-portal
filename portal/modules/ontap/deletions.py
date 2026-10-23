"""Deletion of the old volume after a restore, ONLY with administrator approval.

The restore succeeded and the operator ticked the option in Review: the original volume is scheduled, due = finished +
N hours (sites.yml openstack.delete_after_hours, default 72). After it is due, administrators get a notification in
the portal (badge in the masthead and the Approvals menu) and choose:
  - Approve delete: the dialog runs Check first (OpenStack + the LUN on NetApp), then the job delete_volume.yml checks
    again (the volume still exists, same project, status available, not attached, no Cinder snapshots, LUN readable
    on NetApp) and runs openstack volume delete, without --force/--cascade. Detach and delete detaches the volume from
    the instance first (not for a boot disk). A volume that no longer exists in OpenStack and NetApp is recorded as
    already deleted;
  - Keep: the volume is not deleted;
  - Postpone: the due time is moved back.
Nothing is deleted automatically. Every decision is recorded (this table + the portal activity log).

Status: scheduled (waiting to be due; once due it shows as "awaiting"), deleting (job running), deleted, kept,
failed (the check or the deletion failed; it can be approved again, postponed, or kept).
"""
import contextlib
import datetime
import os
import sqlite3

from .history import DB_PATH

DEFAULT_HOURS = 72
OPEN = ("scheduled", "failed")          # still waiting for a decision
FIELDS = ("id", "restore_id", "site", "volume_id", "volume_name", "project_id", "project_name", "new_volume_id",
          "new_volume_name", "restored_by", "lun_path", "lun_svm", "lun_ref_id", "created", "due", "status", "decided_by",
          "decided_at", "note", "job_id", "error", "checked_at", "check_result")


@contextlib.contextmanager
def _db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def _now():
    return datetime.datetime.now().astimezone()


def _iso(dt):
    return dt.isoformat(timespec="seconds")


def init():
    with _db() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS deletions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, restore_id INTEGER NOT NULL UNIQUE, site TEXT NOT NULL,
            volume_id TEXT NOT NULL, volume_name TEXT, project_id TEXT, project_name TEXT, new_volume_id TEXT,
            new_volume_name TEXT, restored_by TEXT, created TEXT NOT NULL, due TEXT NOT NULL, status TEXT NOT NULL,
            decided_by TEXT, decided_at TEXT, note TEXT, job_id TEXT, error TEXT, log TEXT, checked_at TEXT,
            check_result TEXT)""")
        db.execute("CREATE INDEX IF NOT EXISTS deletions_due ON deletions(status, due)")
        # LUN of the old volume at restore time (checked again on NetApp before it is deleted).
        columns = [r[1] for r in db.execute("PRAGMA table_info(deletions)")]
        for column in ("lun_path", "lun_svm", "lun_ref_id"):
            if column not in columns:
                db.execute(f"ALTER TABLE deletions ADD COLUMN {column} TEXT")
        # The previous process stopped while a deletion was running: the result is unknown, so it must be checked again.
        db.execute("UPDATE deletions SET status='failed', error='The web app stopped while the deletion was running; "
                   "click Check to see whether the volume still exists' WHERE status='deleting'")


def state(row, now=None):
    """Status for display: 'awaiting' = scheduled and already due."""
    now = now or _now()
    if row["status"] == "scheduled" and datetime.datetime.fromisoformat(row["due"]) <= now:
        return "awaiting"
    return row["status"]


def _item(row, now=None):
    item = {k: row[k] for k in FIELDS if k in row.keys()}
    item["state"] = state(row, now)
    return item


def schedule(restore_id, record, hours=DEFAULT_HOURS):
    """Schedule the original volume from a restore history record (successful restore). Fine if already scheduled."""
    now = _now()
    due = now + datetime.timedelta(hours=float(hours))
    with _db() as db:
        cur = db.execute(
            "INSERT OR IGNORE INTO deletions (restore_id, site, volume_id, volume_name, project_id, project_name, new_volume_id,"
            " new_volume_name, restored_by, lun_path, lun_svm, lun_ref_id, created, due, status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (restore_id, record["site"], record["volume_id"], record.get("volume_name") or "", record.get("source_project_id") or "",
             record.get("source_project_name") or "", record.get("new_volume_id") or "", record.get("new_volume_name") or "",
             record.get("username") or "", record.get("lun_path") or "", record.get("lun_svm") or "", record.get("lun_ref_id") or "",
             _iso(now), _iso(due), "scheduled"))
        return cur.lastrowid or None


def get(deletion_id):
    with _db() as db:
        row = db.execute("SELECT * FROM deletions WHERE id = ?", (deletion_id,)).fetchone()
    return (dict(_item(row), log=row["log"] or "") if row else None)


def for_restore(restore_id):
    with _db() as db:
        row = db.execute("SELECT * FROM deletions WHERE restore_id = ?", (restore_id,)).fetchone()
    return _item(row) if row else None


def query(view="open", limit=200):
    """view: open (awaiting + scheduled + failed + deleting), awaiting, done (deleted + kept), all."""
    now = _now()
    with _db() as db:
        rows = db.execute("SELECT * FROM deletions ORDER BY due ASC, id ASC LIMIT ?", (max(1, min(int(limit), 1000)),)).fetchall()
    items = [_item(r, now) for r in rows]
    if view == "open":
        items = [i for i in items if i["state"] in ("awaiting", "failed", "deleting", "scheduled")]
    elif view == "awaiting":
        items = [i for i in items if i["state"] in ("awaiting", "failed")]
    elif view == "done":
        items = sorted((i for i in items if i["state"] in ("deleted", "kept")), key=lambda i: i["decided_at"] or "", reverse=True)
    return items


def summary():
    """Count per display status; 'awaiting' (including failed ones that are already due) = needs an admin decision."""
    now = _now()
    with _db() as db:
        rows = db.execute("SELECT * FROM deletions WHERE status IN ('scheduled', 'failed', 'deleting')").fetchall()
    counts = {"awaiting": 0, "scheduled": 0, "failed": 0, "deleting": 0}
    for row in rows:
        counts[state(row, now)] += 1
    counts["needs_decision"] = counts["awaiting"] + counts["failed"]
    return counts


def _decide(deletion_id, allowed, **values):
    """Change the status only when the current status is one of `allowed` (no clash with another decision)."""
    sets = ", ".join(f"{k}=?" for k in values)
    with _db() as db:
        cur = db.execute(f"UPDATE deletions SET {sets} WHERE id=? AND status IN ({','.join('?' * len(allowed))})",
                         (*values.values(), deletion_id, *allowed))
        return cur.rowcount == 1


def start_delete(deletion_id, actor):
    """Approve: only after it is due (or after a failed attempt)."""
    item = get(deletion_id)
    if not item:
        raise LookupError("Deletion not found")
    if item["state"] not in ("awaiting", "failed"):
        raise ValueError({"scheduled": f"The volume is due for deletion on {item['due']}; it cannot be approved before that.",
                          "deleting": "The deletion is already running.", "deleted": "The volume was already deleted.",
                          "kept": "The volume was kept; it is not deleted."}.get(item["state"], "The deletion cannot be approved now."))
    if not _decide(deletion_id, OPEN, status="deleting", decided_by=actor, decided_at=_iso(_now()), error=""):
        raise ValueError("The deletion was changed by someone else. Reload the page.")
    return item


def set_job(deletion_id, job_id):
    with _db() as db:
        db.execute("UPDATE deletions SET job_id=? WHERE id=?", (job_id, deletion_id))


def finish_delete(deletion_id, job):
    result = job.get("result") or {}
    ok = job["status"] == "success" and result.get("deleted")
    with _db() as db:
        db.execute("UPDATE deletions SET status=?, error=?, log=?, note=COALESCE(NULLIF(?, ''), note) WHERE id=? AND status='deleting'",
                   ("deleted" if ok else "failed", "" if ok else (job.get("error") or result.get("error") or "the deletion failed"),
                    "\n".join(job.get("lines", [])), result.get("note", "") if ok else "", deletion_id))
    return ok


def keep(deletion_id, actor, note=""):
    if not _decide(deletion_id, OPEN, status="kept", decided_by=actor, decided_at=_iso(_now()), note=note[:500]):
        raise ValueError("Only a scheduled, awaiting or failed deletion can be kept.")


def postpone(deletion_id, actor, hours):
    item = get(deletion_id)
    if not item or item["status"] not in OPEN:
        raise ValueError("Only a scheduled, awaiting or failed deletion can be postponed.")
    base = max(_now(), datetime.datetime.fromisoformat(item["due"]))
    due = _iso(base + datetime.timedelta(hours=int(hours)))
    note = f"postponed by {actor} to {due}"
    if not _decide(deletion_id, OPEN, status="scheduled", due=due, note=note, error=""):
        raise ValueError("The deletion was changed by someone else. Reload the page.")
    return due


def save_check(deletion_id, result):
    """Result of the Check button (job delete_volume.yml check_only), kept so it can be shown again."""
    import json
    with _db() as db:
        db.execute("UPDATE deletions SET checked_at=?, check_result=? WHERE id=?",
                   (_iso(_now()), json.dumps(result or {}), deletion_id))

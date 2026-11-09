"""Restore history (SQLite): who, when, volume, snapshot, project, result, and the full Ansible log.

The record is written BEFORE the restore job runs; if it cannot be written, the restore is cancelled.
Restoring several volumes of one instance at once = one group (restore_groups): each volume is still one restore
(one job) with a group_id, run one after the other; the group records the order, the status per volume, and the
action after it.
"""
import contextlib
import csv
import datetime
import io
import json
import os
import sqlite3
import threading

import settings

# One SQLite database for the whole portal (tables restores and restore_groups belong to this module).
DB_PATH = settings.DB_PATH
STATUSES = ("running", "success", "failed", "unknown")
FIELDS = ("id", "ts", "finished", "username", "site", "volume_id", "volume_name", "snapshot", "snapshot_time", "project_id",
          "project_name", "restore_path", "new_volume_id", "new_volume_name", "volume_type", "move_flexvol", "cinder_pool",
          "post_action", "post_result", "delete_after", "transfer_id", "status", "error", "client_ip", "job_id", "group_id")
# Group: running -> success (all volumes and their actions succeeded), partial (all volumes were restored, some actions
# after the restore failed), failed (one restore failed: the next volumes were not run), unknown (the web app stopped
# in the middle of the group).
GROUP_STATUSES = ("running", "success", "partial", "failed", "unknown")
_group_lock = threading.Lock()


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
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def init():
    with _db() as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("""CREATE TABLE IF NOT EXISTS restores (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, finished TEXT, username TEXT NOT NULL, site TEXT NOT NULL,
            volume_id TEXT NOT NULL, volume_name TEXT, snapshot TEXT NOT NULL, snapshot_time TEXT, project_id TEXT,
            project_name TEXT, restore_path TEXT, new_volume_id TEXT, new_volume_name TEXT, transfer_id TEXT,
            status TEXT NOT NULL, error TEXT, log TEXT, client_ip TEXT)""")
        db.execute("CREATE INDEX IF NOT EXISTS restores_ts ON restores(ts)")
        # New columns for the database of an earlier version: the job ID so the job page can follow a running restore,
        # the volume type used by cinder manage, the target FlexVol of the lun move, the Cinder pool chosen by the
        # operator, and the action after the restore with its result (post_result: "ok: ..." or "failed: ...").
        columns = [r[1] for r in db.execute("PRAGMA table_info(restores)")]
        for column in ("job_id", "volume_type", "move_flexvol", "cinder_pool", "post_action", "post_result", "delete_after",
                       "group_id"):
            if column not in columns:
                db.execute(f"ALTER TABLE restores ADD COLUMN {column} {'INTEGER' if column == 'group_id' else 'TEXT'}")
        db.execute("""CREATE TABLE IF NOT EXISTS restore_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, finished TEXT, username TEXT NOT NULL, site TEXT NOT NULL,
            instance_id TEXT, instance_name TEXT, snapshot TEXT NOT NULL, snapshot_time TEXT, project_id TEXT,
            project_name TEXT, post_action TEXT, status TEXT NOT NULL, error TEXT, client_ip TEXT, members TEXT NOT NULL)""")
        # Groups that were running when the process stopped: volumes that had not started are not run any more.
        for row in db.execute("SELECT id, members FROM restore_groups WHERE status='running'").fetchall():
            members = json.loads(row["members"])
            for m in members:
                if m.get("status") == "waiting":
                    m.update(status="skipped", note="not started: the web app stopped during the group")
                elif m.get("status") == "running":
                    m["status"] = "unknown"
            db.execute("UPDATE restore_groups SET status='unknown', finished=?, error=?, members=? WHERE id=?",
                       (_now(), "The web app stopped during the group; check the volumes that were not finished",
                        json.dumps(members), row["id"]))
        # The previous process stopped during a restore: the final result is unknown. Returned for the activity log.
        interrupted = [dict(r) for r in db.execute("SELECT id, username, site, volume_id, client_ip FROM restores WHERE status='running'")]
        db.execute("UPDATE restores SET status='unknown', finished=?, error='The web app stopped while the restore was running; "
                   "check the LUN and volume in ONTAP and OpenStack' WHERE status='running'", (_now(),))
    return interrupted


def begin(username, site, plan, client_ip, group_id=None):
    with _db() as db:
        cur = db.execute(
            "INSERT INTO restores (ts, username, site, volume_id, volume_name, snapshot, snapshot_time, project_id, project_name,"
            " restore_path, new_volume_name, volume_type, move_flexvol, cinder_pool, post_action, delete_after, status, client_ip,"
            " group_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (_now(), username, site, plan["volume"]["id"], plan["volume"]["name"], plan["snapshot"]["name"],
             plan["snapshot"]["local_time"], plan["project"]["id"], plan["project"]["name"], plan["restore_path"],
             plan.get("new_volume_name", ""), plan.get("volume_type", ""), plan.get("move_flexvol", ""),
             plan.get("cinder_pool", ""), plan.get("post_action", ""), int(plan.get("delete_after") or 0), "running", client_ip,
             group_id))
        return cur.lastrowid


def set_job(record_id, job_id):
    with _db() as db:
        db.execute("UPDATE restores SET job_id=? WHERE id=?", (job_id, record_id))


def post_result_text(result):
    """Result of the action after the restore, for the history: 'ok: ...', 'failed: ...', or '' if there is none."""
    after = (result or {}).get("after_restore") or {}
    if not after.get("action"):
        return ""
    if not after.get("ok"):
        return f"failed: {after.get('error') or 'no message'}"
    if after["action"] == "attach":
        return f"ok: attached to {after.get('server_name') or after.get('server_id')} as {after.get('device') or '?'}"
    more = len(after.get("volumes") or [])
    return (f"ok: instance {after.get('server_name')} ({after.get('server_id')}) {after.get('status') or ''}".strip()
            + (f", with {more} more volume{'' if more == 1 else 's'} attached" if more else ""))


def finish(record_id, job):
    result = job.get("result") or {}
    new_volume = result.get("new_volume") or {}
    with _db() as db:
        # restore_path follows the job result: after a lun move, the -restore LUN is in the FlexVol of the chosen pool.
        db.execute("UPDATE restores SET finished=?, status=?, error=?, new_volume_id=?, new_volume_name=COALESCE(NULLIF(?, ''), new_volume_name),"
                   " restore_path=COALESCE(NULLIF(?, ''), restore_path), transfer_id=?, post_result=?, log=?"
                   " WHERE id=? AND status='running'",
                   (_now(), job["status"], job.get("error", ""), new_volume.get("id", ""), new_volume.get("name", ""),
                    result.get("restore_path", ""), (result.get("transfer") or {}).get("id", ""), post_result_text(result),
                    "\n".join(job.get("lines", [])), record_id))


def _where(username="", site="", status="", q=""):
    where, args = [], []
    for column, value in (("username", username), ("site", site), ("status", status)):
        if value:
            where.append(f"{column} = ?")
            args.append(value)
    if q:
        where.append("(volume_id LIKE ? OR new_volume_id LIKE ? OR volume_name LIKE ? OR project_name LIKE ? OR project_id LIKE ? OR snapshot LIKE ?)")
        args += [f"%{q}%"] * 6
    return ("WHERE " + " AND ".join(where)) if where else "", args


def query(limit=50, offset=0, username="", site="", status="", q=""):
    clause, args = _where(username, site, status, q)
    with _db() as db:
        total = db.execute(f"SELECT COUNT(*) FROM restores {clause}", args).fetchone()[0]
        rows = db.execute(f"SELECT {', '.join(FIELDS)} FROM restores {clause} ORDER BY id DESC LIMIT ? OFFSET ?",
                          args + [max(1, min(int(limit), 500)), max(0, int(offset))]).fetchall()
        users = [r[0] for r in db.execute("SELECT DISTINCT username FROM restores ORDER BY username")]
    return {"total": total, "items": [dict(r) for r in rows], "users": users}


def get(record_id):
    with _db() as db:
        row = db.execute("SELECT * FROM restores WHERE id = ?", (record_id,)).fetchone()
    return dict(row) if row else None


# ---------------- Group: several volumes of one instance ----------------
def begin_group(username, site, info, members, client_ip):
    """info: instance_id, instance_name, snapshot, snapshot_time, project_id, project_name, post_action. members: one dict
    per volume in the order they run (volume_id, volume_name, device, role, new_volume_name, cinder_pool, status, ...)."""
    with _db() as db:
        cur = db.execute(
            "INSERT INTO restore_groups (ts, username, site, instance_id, instance_name, snapshot, snapshot_time, project_id,"
            " project_name, post_action, status, client_ip, members) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (_now(), username, site, info.get("instance_id", ""), info.get("instance_name", ""), info["snapshot"],
             info.get("snapshot_time", ""), info.get("project_id", ""), info.get("project_name", ""),
             info.get("post_action", ""), "running", client_ip, json.dumps(members)))
        return cur.lastrowid


def update_group_member(group_id, index, **fields):
    with _group_lock, _db() as db:
        row = db.execute("SELECT members FROM restore_groups WHERE id = ?", (group_id,)).fetchone()
        members = json.loads(row["members"])
        members[index].update(fields)
        db.execute("UPDATE restore_groups SET members = ? WHERE id = ?", (json.dumps(members), group_id))


def finish_group(group_id, status, error=""):
    with _group_lock, _db() as db:
        db.execute("UPDATE restore_groups SET status = ?, error = ?, finished = ? WHERE id = ? AND status = 'running'",
                   (status, error, _now(), group_id))


def get_group(group_id):
    with _db() as db:
        row = db.execute("SELECT * FROM restore_groups WHERE id = ?", (group_id,)).fetchone()
    if not row:
        return None
    group = dict(row)
    group["members"] = json.loads(group["members"])
    return group


# CSV export of the Jobs page (same filters), oldest first. Column title -> field.
CSV_COLUMNS = (("ID", "id"), ("Started", "ts"), ("Finished", "finished"), ("User", "username"), ("Client IP", "client_ip"),
               ("Site", "site"), ("Status", "status"), ("Volume ID", "volume_id"), ("Volume name", "volume_name"),
               ("Snapshot", "snapshot"), ("Snapshot time", "snapshot_time"), ("Project ID", "project_id"),
               ("Project name", "project_name"), ("New volume ID", "new_volume_id"), ("New volume name", "new_volume_name"),
               ("Volume type", "volume_type"), ("Cinder pool", "cinder_pool"), ("lun move to FlexVol", "move_flexvol"),
               ("Action after the restore", "post_action"), ("Result of the action", "post_result"),
               ("Delete original after (hours)", "delete_after"), ("Transfer ID", "transfer_id"), ("Group", "group_id"),
               ("Error", "error"))


def all_rows(username="", site="", status="", q=""):
    clause, args = _where(username, site, status, q)
    with _db() as db:
        return [dict(r) for r in db.execute(f"SELECT {', '.join(FIELDS)} FROM restores {clause} ORDER BY id", args)]


def _cell(value):
    """A cell that a spreadsheet does not run as a formula (text starting with = + - @ tab CR)."""
    if value is None:
        return ""
    text = str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def to_csv(rows):
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow([title for title, _ in CSV_COLUMNS])
    for row in rows:
        writer.writerow([_cell(row.get(field)) for _, field in CSV_COLUMNS])
    return out.getvalue()

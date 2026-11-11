"""Terminal sessions of the Web Terminal module: one ssh process per session on a pseudo-terminal of the portal server.

The browser never holds a connection open per terminal: it posts what is typed (input), the size of the terminal
(resize), and asks for new output of all its sessions at once (poll, one long request per page). Output is kept in a
buffer (the last BUFFER bytes, so a reloaded page draws the screen again) and in the session's recording file.

A session ends when ssh exits, when its user or an administrator ends it, when nothing was typed or printed for
IDLE seconds, when no page asked for its output for DETACHED seconds (the page was closed), after MAX_SECONDS, and
when the portal stops (sessions live in memory; a restart ends them all, the history then says so).

Tables (portal database): shell_sessions (history: who, which host, when, how it ended, the recording file),
shell_snippets (saved commands: personal, or shared by an administrator with every Shell user).
"""
import base64
import contextlib
import datetime
import fcntl
import logging
import os
import re
import secrets
import select
import shutil
import signal
import sqlite3
import struct
import subprocess
import sys
import termios
import threading
import time

import settings

log = logging.getLogger("portal.shell")

BUFFER = 512 * 1024
MAX_POLL_BYTES = 256 * 1024
MAX_INPUT = 64 * 1024
LINGER = 0.25   # s: streaming output is sent in batches (see Manager.poll)
WATCH_SEEN = 30   # s: an administrator watching / joined counts as present while its page asked for output this recently
IDLE = int(os.environ.get("TERMINAL_IDLE_MINUTES", "30")) * 60
DETACHED = int(os.environ.get("TERMINAL_DETACHED_MINUTES", "10")) * 60
MAX_SECONDS = int(os.environ.get("TERMINAL_MAX_HOURS", "12")) * 3600
MAX_TOTAL = int(os.environ.get("TERMINAL_MAX_SESSIONS", "20"))
MAX_PER_USER = int(os.environ.get("TERMINAL_MAX_PER_USER", "8"))
KEEP_DAYS = int(os.environ.get("TERMINAL_KEEP_DAYS", "30"))
RECORD_MAX = int(os.environ.get("TERMINAL_RECORD_MAX_MB", "50")) * 1024 * 1024
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[()][A-Za-z0-9]|\x1b[=>78DEHMNOZc]|\x0f|\x0e")


def folder(*parts):
    path = os.path.join(settings.DATA_DIR, "shell", *parts)
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def _now():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


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


def init():
    """Tables; sessions still open in the history (the portal stopped meanwhile) are closed; old recordings removed."""
    with _db() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS shell_sessions (
            id TEXT PRIMARY KEY, username TEXT NOT NULL, site TEXT, target TEXT, label TEXT, address TEXT, account TEXT,
            client_ip TEXT, started TEXT NOT NULL, ended TEXT, status TEXT NOT NULL, reason TEXT, exit_code INTEGER,
            bytes INTEGER NOT NULL DEFAULT 0, recording TEXT, root INTEGER NOT NULL DEFAULT 0)""")
        db.execute("CREATE INDEX IF NOT EXISTS shell_sessions_started ON shell_sessions(started)")
        db.execute("""CREATE TABLE IF NOT EXISTS shell_snippets (
            id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL, shared INTEGER NOT NULL DEFAULT 0, name TEXT NOT NULL,
            command TEXT NOT NULL, updated TEXT, updated_by TEXT)""")
        stale = [dict(r) for r in db.execute("SELECT id, username, label FROM shell_sessions WHERE status = 'open'")]
        db.execute("UPDATE shell_sessions SET status = 'closed', ended = ?, reason = 'The portal stopped while the session was "
                   "open' WHERE status = 'open'", (_now(),))
    shutil.rmtree(os.path.join(settings.DATA_DIR, "shell", "run"), ignore_errors=True)   # key files of ended sessions
    cleanup()
    return stale


def cleanup(now=None):
    """Recordings older than KEEP_DAYS are removed (the history row stays)."""
    limit = (now or time.time()) - KEEP_DAYS * 86400
    with _db() as db:
        for row in db.execute("SELECT id, recording FROM shell_sessions WHERE recording IS NOT NULL AND recording != ''").fetchall():
            path = os.path.join(folder("recordings"), os.path.basename(row["recording"]))
            try:
                old = os.path.getmtime(path) < limit
            except OSError:
                old = True
            if old:
                with contextlib.suppress(OSError):
                    os.remove(path)
                db.execute("UPDATE shell_sessions SET recording = '' WHERE id = ?", (row["id"],))


# ---------------- history ----------------
HISTORY_FIELDS = ("id", "username", "site", "target", "label", "address", "account", "client_ip", "started", "ended",
                  "status", "reason", "exit_code", "bytes", "root")


def history(username=None, site="", limit=200, before=""):
    sql, args = "SELECT *, (recording IS NOT NULL AND recording != '') AS has_recording FROM shell_sessions WHERE 1=1", []
    if username:
        sql += " AND username = ?"
        args.append(username)
    if site:
        sql += " AND site = ?"
        args.append(site)
    if before:
        sql += " AND started < ?"
        args.append(before)
    sql += " ORDER BY started DESC, rowid DESC LIMIT ?"   # same second: the one opened last first
    args.append(max(1, min(int(limit), 1000)))
    with _db() as db:
        rows = db.execute(sql, args).fetchall()
    return [dict({k: r[k] for k in HISTORY_FIELDS}, recording=bool(r["has_recording"]), root=bool(r["root"])) for r in rows]


def history_row(sid):
    with _db() as db:
        row = db.execute("SELECT * FROM shell_sessions WHERE id = ?", (sid,)).fetchone()
    return dict(row) if row else None


def recording_path(row):
    if not row or not row.get("recording"):
        return ""
    path = os.path.join(folder("recordings"), os.path.basename(row["recording"]))
    return path if os.path.exists(path) else ""


def plain_text(data):
    """A recording as text: escape sequences removed, carriage returns and backspaces applied per line."""
    text = ANSI.sub("", data.decode("utf-8", "replace"))
    lines = []
    for raw in text.replace("\r\n", "\n").split("\n"):
        line = ""
        for part in raw.split("\r"):   # a carriage return rewrites the line from its start
            line = part + line[len(part):]
        while "\x08" in line:   # a backspace: the character before it is overwritten
            at = line.index("\x08")
            line = line[:max(0, at - 1)] + line[at + 1:]
        lines.append("".join(ch for ch in line if ch == "\t" or ch >= " "))
    return "\n".join(lines)


# ---------------- snippets ----------------
def snippets(username):
    with _db() as db:
        rows = db.execute("SELECT * FROM shell_snippets WHERE owner = ? OR shared = 1 ORDER BY shared, lower(name)", (username,)).fetchall()
    return [dict(r, shared=bool(r["shared"])) for r in rows]


def save_snippet(user, body, snippet_id=None):
    name = str(body.get("name") or "").strip()[:80]
    command = str(body.get("command") or "").replace("\r\n", "\n").strip("\n")
    shared = bool(body.get("shared"))
    if not name:
        raise ValueError("Give the snippet a name")
    if not command.strip():
        raise ValueError("The command is empty")
    if len(command) > 8000:
        raise ValueError("The command is too long (at most 8000 characters)")
    if shared and user["role"] != "admin":
        raise ValueError("Only administrators share snippets with every Shell user")
    with _db() as db:
        if snippet_id is None:
            return db.execute("INSERT INTO shell_snippets (owner, shared, name, command, updated, updated_by) VALUES (?,?,?,?,?,?)",
                              (user["username"], int(shared), name, command, _now(), user["username"])).lastrowid
        row = db.execute("SELECT owner, shared FROM shell_snippets WHERE id = ?", (snippet_id,)).fetchone()
        if not row:
            raise LookupError("Snippet not found")
        if not _may_edit(user, row):
            raise ValueError("Only its owner (or an administrator, for a shared snippet) changes this snippet")
        db.execute("UPDATE shell_snippets SET name = ?, command = ?, shared = ?, updated = ?, updated_by = ? WHERE id = ?",
                   (name, command, int(shared), _now(), user["username"], snippet_id))
        return snippet_id


def delete_snippet(user, snippet_id):
    with _db() as db:
        row = db.execute("SELECT owner, shared, name FROM shell_snippets WHERE id = ?", (snippet_id,)).fetchone()
        if not row:
            raise LookupError("Snippet not found")
        if not _may_edit(user, row):
            raise ValueError("Only its owner (or an administrator, for a shared snippet) removes this snippet")
        db.execute("DELETE FROM shell_snippets WHERE id = ?", (snippet_id,))
        return row["name"]


def _may_edit(user, row):
    return user["role"] == "admin" if row["shared"] else row["owner"] == user["username"]


# ---------------- live sessions ----------------
class Session:
    def __init__(self, sid, user, target, client):
        self.id = sid
        self.user = user
        self.target = target
        self.client = client
        self.created = self.last_io = self.last_poll = self.last_input = time.time()
        self.buf = bytearray()
        self.start = 0           # offset of buf[0] in the whole output
        self.state = "connecting"
        self.exit_code = None
        self.reason = ""
        self.cols, self.rows = 120, 32
        self.proc = None
        self.fd = None
        self.folder = ""
        self.record = None
        self.recorded = 0
        self.sudo_password = None
        self.password_auth = False
        self.watch_until = 0.0   # become root: the sudo prompt is answered until then
        self.root = False
        self.finished = False
        self.ended_by = ""      # set when the portal ends the session (its user, an administrator, the limits)
        self.admin = False      # opened by an administrator (every host; Shell → Access does not apply)
        self.watchers = {}      # administrator -> {"mode": "watch" | "join", "seen": time}: see Manager.watch
        self.watch_version = 0  # changes when someone starts or stops watching: the pages of the session are told
        self.lock = threading.Lock()
        self.record_lock = threading.Lock()

    @property
    def end(self):
        return self.start + len(self.buf)

    def info(self):
        t = self.target
        return {"id": self.id, "user": self.user, "target": t["id"], "site": t["site"], "name": t["name"],
                "category": t["category"], "category_label": t["category_label"], "address": t["address"],
                "account": t["user"], "become": bool(t["become"]) and (t["privilege"] == "sudo" or self.sudo_password is not None),
                "state": self.state, "exit_code": self.exit_code, "reason": self.reason, "client": self.client,
                "started": datetime.datetime.fromtimestamp(self.created).astimezone().isoformat(timespec="seconds"),
                "last_io": datetime.datetime.fromtimestamp(self.last_io).astimezone().isoformat(timespec="seconds"),
                "root": self.root, "cols": self.cols, "rows": self.rows, "watchers": self.present()}

    def present(self, now=None):
        """Administrators watching or joined now: [{"user", "mode"}]."""
        now = now or time.time()
        return [{"user": u, "mode": w["mode"]} for u, w in sorted(self.watchers.items()) if now - w["seen"] <= WATCH_SEEN]

    def may_type(self, username):
        return username == self.user or (self.watchers.get(username) or {}).get("mode") == "join"


class Manager:
    def __init__(self, on_end=None, still_allowed=None):
        self.cond = threading.Condition()
        self.items = {}
        self.on_end = on_end or (lambda session: None)
        # still_allowed(session): may its user still open its host (Web Terminal → Access, temporary access)? No: it ends.
        self.still_allowed = still_allowed
        self._reaper = None

    # ---- opening ----
    def open(self, user, target, spec, client, cols=120, rows=32, admin=False):
        with self.cond:
            live = [s for s in self.items.values() if s.state != "closed"]
            if len(live) >= MAX_TOTAL:
                raise ValueError(f"{MAX_TOTAL} shell sessions are open on the portal: end one first")
            if sum(1 for s in live if s.user == user) >= MAX_PER_USER:
                raise ValueError(f"You have {MAX_PER_USER} sessions open: end one first")
            sid = secrets.token_hex(8)
            session = Session(sid, user, target, client)
            session.admin = bool(admin)
            self.items[sid] = session
        session.cols, session.rows = _size(cols, 120), _size(rows, 32)
        session.folder = spec.get("folder") or ""
        session.sudo_password = spec.get("sudo_password")
        # Only the sudo prompt of the account itself, at the end of the output (not a host reached onwards from this one).
        session.sudo_prompt = re.compile(rb"\[sudo\] password for " + re.escape(str(spec.get("sudo_user") or "").encode()) + rb": ?\Z")
        session.password_auth = spec.get("password") is not None
        name = f"{time.strftime('%Y%m%d-%H%M%S')}-{sid}.log"
        session.record = open(os.path.join(folder("recordings"), name), "wb")
        with _db() as db:
            db.execute("INSERT INTO shell_sessions (id, username, site, target, label, address, account, client_ip, started, status, "
                       "recording) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                       (sid, user, target["site"], target["id"], f"{target['site']} · {target['category_label']} · {target['name']}",
                        target["address"], target["user"], client, _now(), "open", name))
        try:
            self._spawn(session, spec)
        except Exception as e:
            self._finish(session, 255, f"Could not start: {e}")
            raise ValueError(f"The session could not start: {e}")
        threading.Thread(target=self._read, args=(session,), name=f"shell-{sid}", daemon=True).start()
        self._start_reaper()
        return session

    def _spawn(self, session, spec):
        master, slave = os.openpty()
        read_end = write_end = None
        try:
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", session.rows, session.cols, 0, 0))
            # The terminal stays in its normal (cooked) mode: ssh sends these modes to the host's own terminal and only
            # then puts this one in raw mode (sshpass copies them to its terminal for ssh). A raw terminal here would
            # reach the host as "no echo, no line editing": nothing typed is shown and bash's Ctrl+R, arrows and Tab
            # stop working.
            argv = list(spec["argv"])
            pass_fds = ()
            if spec.get("password") is not None:
                read_end, write_end = os.pipe()
                argv = [str(read_end) if a == "{pass_fd}" else a for a in argv]
                pass_fds = (read_end,)
            env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", settings.DATA_DIR),
                   "TERM": "xterm-256color", "LANG": "C.UTF-8", **(spec.get("env") or {})}
            # sh opens the terminal by its name after setsid, so it becomes the controlling terminal of ssh (Linux):
            # passwords and host key questions of ssh, and the window size, work as in a real terminal.
            wrapper = ["/bin/sh", "-c", 'tty=$1; shift; exec "$@" <"$tty" >"$tty" 2>&1', "sh", os.ttyname(slave), *argv]
            session.proc = subprocess.Popen(wrapper, stdin=slave, stdout=slave, stderr=slave, start_new_session=True,
                                            pass_fds=pass_fds, env=env, cwd=session.folder or None, close_fds=True)
            if write_end is not None:
                os.write(write_end, spec["password"].encode() + b"\n")
        except Exception:
            os.close(master)
            raise
        finally:
            for fd in (read_end, write_end):   # the child has its own copy of the read end
                if fd is not None:
                    os.close(fd)
            os.close(slave)
        session.fd = master
        session.state = "open"

    # ---- output ----
    def _read(self, session):
        fd = session.fd
        while True:
            try:
                ready, _, _ = select.select([fd], [], [], 1.0)
            except (OSError, ValueError):
                break
            if not ready:
                if session.proc.poll() is not None and not self._pending(fd):
                    break
                continue
            try:
                data = os.read(fd, 65536)
            except OSError:   # EIO: the other side of the terminal is closed (ssh exited)
                break
            if not data:
                break
            self._output(session, data)
        try:
            code = session.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(OSError):
                os.killpg(session.proc.pid, signal.SIGKILL)
            code = session.proc.wait()
        self._finish(session, code, session.reason or ("The connection ended" if code == 0 else _exit_reason(code, session)))

    @staticmethod
    def _pending(fd):
        try:
            return bool(select.select([fd], [], [], 0)[0])
        except (OSError, ValueError):
            return False

    def _output(self, session, data):
        with self.cond:
            session.buf += data
            if len(session.buf) > BUFFER:
                drop = len(session.buf) - BUFFER
                del session.buf[:drop]
                session.start += drop
            session.last_io = time.time()
            self.cond.notify_all()
        if session.record and session.recorded < RECORD_MAX:
            chunk = data[:RECORD_MAX - session.recorded]
            with session.record_lock:
                session.record.write(chunk)
                session.record.flush()
            session.recorded += len(chunk)
            if session.recorded >= RECORD_MAX:
                self._mark(session, "recording stopped: the size limit was reached")
        if session.watch_until and session.sudo_password is not None:
            if time.time() > session.watch_until:
                session.watch_until = 0.0
            elif session.sudo_prompt.search(bytes(session.buf[-200:])):
                session.watch_until = 0.0
                self._write(session, session.sudo_password.encode() + b"\r")

    @staticmethod
    def _mark(session, text):
        """A note of the portal in the recording only (never on the terminal of the session)."""
        with session.record_lock:
            if session.record and not session.record.closed:
                session.record.write(f"\r\n\x1b[2m[portal {time.strftime('%H:%M:%S')}: {text}]\x1b[0m\r\n".encode())
                session.record.flush()

    def watch(self, session, username, mode):
        """An administrator watches (read-only) or joins (types too) a session of another user, or leaves it. Its user
        sees who is there (status bar); the recording gets a note."""
        if session.state != "open" and mode != "leave":
            raise ValueError("The session has ended")
        if username == session.user:
            raise ValueError("This is your own session: open it from Terminals")
        with self.cond:
            old = (session.watchers.get(username) or {}).get("mode")
            if mode == "leave":
                session.watchers.pop(username, None)
            else:
                session.watchers[username] = {"mode": mode, "seen": time.time()}
            session.watch_version += 1
            self.cond.notify_all()
        if mode != old:
            self._mark(session, {"watch": f"{username} watches this session (read-only)",
                                 "join": f"{username} joined this session and can type",
                                 "leave": f"{username} left this session"}[mode])

    def _finish(self, session, code, reason):
        """The end of a session: files closed, history and activity written, THEN the pages are told (state closed)."""
        with self.cond:
            if session.finished:
                return
            session.finished = True
        session.exit_code, session.reason = code, reason
        if session.fd is not None:
            with contextlib.suppress(OSError):
                os.close(session.fd)
        if session.record:
            with contextlib.suppress(OSError):
                session.record.close()
        if session.folder:
            shutil.rmtree(session.folder, ignore_errors=True)
        # failed: ssh could not connect (255 within a minute), not a session ended from the portal (ssh also says 255)
        failed = code == 255 and time.time() - session.created < 60 and not session.ended_by
        try:   # whatever fails here, the pages are still told that the session ended (below)
            with _db() as db:
                db.execute("UPDATE shell_sessions SET ended = ?, status = ?, reason = ?, exit_code = ?, bytes = ?, root = ? "
                           "WHERE id = ?", (_now(), "failed" if failed else "closed", reason[:500], code, session.end,
                                            int(session.root), session.id))
            self.on_end(session)
        except Exception:
            log.exception("shell: end of session %s", session.id)
        with self.cond:
            session.state = "closed"
            self.cond.notify_all()

    # ---- the browser ----
    def get(self, sid):
        return self.items.get(str(sid or ""))

    def live(self, user=None):
        with self.cond:
            return [s for s in self.items.values() if s.state != "closed" and (user is None or s.user == user)]

    def write(self, session, text):
        data = str(text).encode("utf-8", "replace")
        if len(data) > MAX_INPUT:
            raise ValueError("Too much text at once")
        if session.state != "open":
            raise ValueError("The session has ended")
        self._write(session, data)
        session.last_io = session.last_input = time.time()

    def _write(self, session, data):
        with session.lock:
            view = memoryview(data)
            while view:
                try:
                    n = os.write(session.fd, view)
                except BlockingIOError:
                    time.sleep(0.01)
                    continue
                except OSError:
                    return
                view = view[n:]

    def resize(self, session, cols, rows):
        session.cols, session.rows = _size(cols, session.cols), _size(rows, session.rows)
        if session.state != "open":
            return
        with contextlib.suppress(OSError):
            fcntl.ioctl(session.fd, termios.TIOCSWINSZ, struct.pack("HHHH", session.rows, session.cols, 0, 0))
        if not sys.platform.startswith("linux"):   # Linux: the kernel signals the controlling terminal's processes
            with contextlib.suppress(OSError, ProcessLookupError):
                os.kill(session.proc.pid, signal.SIGWINCH)

    def become_root(self, session):
        """sudo -i in the session; with a sudo password, the portal answers the sudo prompt (once, within 15 s)."""
        if session.state != "open":
            raise ValueError("The session has ended")
        if session.sudo_password is not None:
            session.watch_until = time.time() + 15
        session.root = True
        self._write(session, b"sudo -i\r")
        session.last_io = session.last_input = time.time()

    def close(self, session, reason="Ended by the user"):
        if session.state == "closed":
            return
        session.reason = session.ended_by = reason
        try:
            os.killpg(session.proc.pid, signal.SIGHUP)
        except (OSError, ProcessLookupError, AttributeError):
            return
        threading.Thread(target=self._kill_later, args=(session,), daemon=True).start()

    @staticmethod
    def _kill_later(session, delay=3):
        time.sleep(delay)
        if session.proc and session.proc.poll() is None:
            with contextlib.suppress(OSError, ProcessLookupError):
                os.killpg(session.proc.pid, signal.SIGKILL)

    def poll(self, cursors, wait=20.0, linger=LINGER, viewer=None):
        """New output of the sessions {sid: offset}: as soon as one has something new or changed state, else after wait s.
        Output that streams by itself (nothing typed for a second: tail -f, top, a long log) is gathered for up to
        `linger` s, so a page asks a few times a second instead of once per line; what answers a key is sent at once.
        viewer: the account asking. An administrator asking for a session of someone else is a watcher: it keeps its
        watch alive but not the session (that ends as usual when its own pages are gone)."""
        now = time.time()
        deadline = now + max(0.0, min(float(wait), 25.0))
        linger_until = None
        with self.cond:
            # Once per request (not on every wake-up): a watcher who left meanwhile is not brought back by its last request.
            for sid in cursors:
                s = self.items.get(sid)
                if not s:
                    continue
                if viewer and viewer != s.user:
                    if viewer not in s.watchers:
                        s.watchers[viewer] = {"mode": "watch"}
                        s.watch_version += 1
                    s.watchers[viewer]["seen"] = now
                else:
                    s.last_poll = now
            versions = {sid: self.items[sid].watch_version for sid in cursors if sid in self.items}
            while True:
                now = time.time()
                out = {}
                for sid, offset in cursors.items():
                    s = self.items.get(sid)
                    if not s:
                        out[sid] = {"state": "gone"}
                        continue
                    if s.end > offset or s.state == "closed" or offset < 0:
                        out[sid] = (s, offset)
                if out:
                    streaming = all(isinstance(v, tuple) and v[0].state == "open" and v[1] >= 0
                                    and now - v[0].last_input > 1.0 for v in out.values())
                    pending = sum(v[0].end - max(v[1], v[0].start) for v in out.values() if isinstance(v, tuple))
                    if linger_until is None:
                        linger_until = now + linger
                    if not streaming or pending >= MAX_POLL_BYTES // 2 or now >= linger_until:
                        return {sid: self._chunk(*v) if isinstance(v, tuple) else v for sid, v in out.items()}
                    self.cond.wait(linger_until - now)
                    continue
                changed = [sid for sid, v in versions.items() if sid in self.items and self.items[sid].watch_version != v]
                if changed or now >= deadline:   # no output: who is watching (and that the session is still there)
                    return {sid: self._light(self.items[sid]) for sid in cursors if sid in self.items}
                self.cond.wait(deadline - now)

    @staticmethod
    def _light(s):
        return {"state": s.state, "root": s.root, "watchers": s.present()}

    @staticmethod
    def _chunk(s, offset):
        offset = s.start if offset < 0 else offset
        truncated = offset < s.start
        first = max(offset, s.start)
        data = bytes(s.buf[first - s.start:first - s.start + MAX_POLL_BYTES])
        return {"data": base64.b64encode(data).decode(), "offset": first + len(data), "more": first + len(data) < s.end,
                "truncated": truncated, "state": s.state, "exit_code": s.exit_code, "reason": s.reason, "root": s.root,
                "watchers": s.present()}

    # ---- housekeeping ----
    def _start_reaper(self):
        if self._reaper and self._reaper.is_alive():
            return
        self._reaper = threading.Thread(target=self._reap_loop, name="shell-reaper", daemon=True)
        self._reaper.start()

    def _reap_loop(self):
        last_cleanup = time.time()
        while True:
            time.sleep(15)
            self.reap()
            if time.time() - last_cleanup > 6 * 3600:
                last_cleanup = time.time()
                with contextlib.suppress(Exception):
                    cleanup()

    def reap(self, now=None):
        now = now or time.time()
        for s in self.live():
            if self.still_allowed and not s.admin and not self.still_allowed(s):
                self.close(s, "Access to this host ended (removed or expired on Shell → Access)")
            elif now - s.last_io > IDLE:
                self.close(s, f"Nothing was typed or shown for {IDLE // 60} minutes")
            elif now - s.last_poll > DETACHED:
                self.close(s, f"No page showed this session for {DETACHED // 60} minutes")
            elif now - s.created > MAX_SECONDS:
                self.close(s, f"The session reached its limit of {MAX_SECONDS // 3600} hours")
        with self.cond:   # ended sessions stay a while for the page that shows them, then go
            for sid in [k for k, s in self.items.items() if s.state == "closed" and now - s.last_io > 600 and now - s.last_poll > 120]:
                del self.items[sid]

    def stop_all(self, reason="The portal is stopping"):
        for s in self.live():
            self.close(s, reason)


def _size(value, default):
    try:
        return max(10, min(int(value), 500))
    except (TypeError, ValueError):
        return default


def _exit_reason(code, session):
    """What the end of ssh means, from its exit code and the last lines it printed."""
    tail = plain_text(bytes(session.buf[-600:])).strip().splitlines()
    last = next((l.strip() for l in reversed(tail) if l.strip()), "")
    if code == 255:
        return f"SSH failed: {last[:300]}" if last else "SSH failed (exit code 255)"
    if code == 5 and session.password_auth:   # sshpass: the password was refused
        return "Wrong password"
    return f"The connection ended (exit code {code})"

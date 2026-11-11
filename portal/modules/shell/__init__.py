"""Shell module (/terminal/): SSH terminals in the browser to the hosts the portal already knows, like Termius or
MobaXterm: a host tree per site (OpenStack management host and director, ONTAP, APIC, the hosts groups of sites.yml and
every host of Runbook Automation -> Hosts & SSH, except ESXi: VMware Cloud stays read-only), tabs, split panes,
snippets, copy and paste.

The portal server opens the SSH connection with the account the administrator stored (the browser never sees an address,
a key or a password). Access is the module "Web Terminal" on the Users page; it is never part of "all modules" (it must be
ticked), administrators always have it. An operator opens only the hosts an administrator gave the account on the page
Access (a site, a product of a site, or single hosts; access.py), nothing by default; administrators open every host.
Every session is in the activity log and its output is recorded
(TERMINAL_KEEP_DAYS days). In Session history operators see their own sessions and recordings, administrators every
session; administrators can also watch an open session of another user live (read-only), join it (type too) and end it.
With Duo SSO and sso.step_up_minutes set (off by default), opening a terminal, joining a session and becoming root need
a Duo step-up first (portal_auth.Portal.step_up: a new Duo SSO sign-in, valid that long; local accounts are exempt).
Needs the Runbook Automation module (its hosts and credentials).
"""
import base64
import functools
import hashlib
import logging
import os
import re
import shutil
import tempfile
import time

from flask import Blueprint, jsonify, make_response, render_template, request

import portal_auth
import sites
from core import PORTAL, register

from . import access, sessions, targets

log = logging.getLogger("portal.shell")
HERE = os.path.dirname(os.path.abspath(__file__))
MODULE = "shell"
TITLE = "Web Terminal"
SID_RE = re.compile(r"^[0-9a-f]{16}$")

blueprint = Blueprint(MODULE, __name__, url_prefix="/terminal", template_folder="templates", static_folder="static",
                      static_url_path="/static")


def _end(session):
    """Activity entry when a session ends."""
    seconds = int(time.time() - session.created)
    failed = session.exit_code == 255 and seconds < 60
    PORTAL.store.event(session.user, "shell.failed" if failed else "shell.close", _label(session.target),
                       f"Session {session.id}: {session.reason} ({_duration(seconds)}, {session.end} bytes shown"
                       f"{', became root' if session.root else ''})", session.client)


def _still_allowed(session):
    try:
        return access.allowed({"role": "operator", "username": session.user}, session.target)
    except Exception:   # the database could not be read now: decided at the next look
        return True


MANAGER = sessions.Manager(on_end=_end, still_allowed=_still_allowed)


def _running():
    return [{"id": s.id, "title": f"Web Terminal: {_label(s.target)} ({s.user})", "user": s.user} for s in MANAGER.live()]


register(MODULE, TITLE, "SSH terminals to every host of the portal (OpenStack, ONTAP, APIC, VyOS, CDN, DNS, Linux…), "
         "with tabs, split panes, snippets and recorded sessions.", "/terminal/", "terminal", running_jobs=_running, explicit=True)

access.init()
for _stale in sessions.init():
    PORTAL.store.event(_stale["username"], "shell.close", _stale["label"] or "",
                       f"Session {_stale['id']}: the portal stopped while the session was open", "")


def _ui_version():
    digest = hashlib.sha256()
    for name in ("static/term.js", "static/term.css", "static/guides.js", "templates/shell/index.html",
                 "../../static/guide.js", "../../static/guide.css"):
        with open(os.path.join(HERE, name), "rb") as f:
            digest.update(f.read())
    return digest.hexdigest()[:12]


UI_VERSION = _ui_version()


def _label(target):
    return f"{target['site']} {target['category_label']} {target['name']} ({target['address']})"


def _duration(seconds):
    h, rest = divmod(int(seconds), 3600)
    return f"{h}h {rest // 60:02d}m" if h else f"{rest // 60}m {rest % 60:02d}s"


def json_body():
    body = request.get_json(silent=True)   # only application/json (extra protection against CSRF)
    return body if isinstance(body, dict) else {}


def session_payload():
    payload = PORTAL.payload()
    user = payload["user"]
    allowed = bool(user and MODULE in user["modules"])
    return {"ui_version": UI_VERSION, **payload, "allowed": allowed, "is_admin": bool(user and user["role"] == "admin"),
            "sites": list(sites.sites()) if allowed else [], "keep_days": sessions.KEEP_DAYS,
            "limits": {"per_user": sessions.MAX_PER_USER, "idle_minutes": sessions.IDLE // 60,
                       "detached_minutes": sessions.DETACHED // 60}}


def json_api(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        try:
            return jsonify(ok=True, **view(*args, **kwargs))
        except portal_auth.NotSignedIn as e:
            return jsonify(ok=False, error=str(e), session=session_payload()), 401
        except portal_auth.StepUpRequired as e:   # the page confirms with Duo (popup), then asks again
            return jsonify(ok=False, error=str(e), step_up=e.url), 403
        except portal_auth.Forbidden as e:
            return jsonify(ok=False, error=str(e)), 403
        except (ValueError, LookupError, portal_auth.CredentialError) as e:
            return jsonify(ok=False, error=str(e)), 400
    return wrapper


def _mine(sid, admin_too=False, typing=False):
    """A live session of the signed-in user. admin_too: an administrator may act on a session of anyone; typing: an
    administrator who joined the session (Manager.watch, mode join) may type into it."""
    user = PORTAL.require(MODULE)
    session = MANAGER.get(sid) if SID_RE.match(str(sid or "")) else None
    allowed = session and (session.user == user["username"] or (admin_too and user["role"] == "admin")
                           or (typing and session.may_type(user["username"])))
    if not allowed:
        raise LookupError("This session is not open (it ended, or it belongs to someone else)")
    return user, session


# ---------------- page ----------------
@blueprint.get("/")
def index():
    return render_template("shell/index.html", ui_version=UI_VERSION)


@blueprint.get("/api/session")
def session():
    return jsonify(ok=True, **session_payload())


@blueprint.get("/api/targets")
@json_api
def target_list():
    """The hosts this account may open: every host for an administrator, the ones given on Access for an operator."""
    user = PORTAL.require(MODULE)
    every = targets.all_targets()
    if user["role"] == "admin":
        return {"targets": every, "sites": list(sites.sites()), "restricted": False}
    mine = access.rules(user["username"])
    return {"targets": [t for t in every if access.allows(mine, t)], "sites": list(sites.sites()), "restricted": True}


# ---------------- terminals ----------------
@blueprint.get("/api/sessions")
@json_api
def session_list():
    """Open sessions of the signed-in user; ?all=1 for an administrator: of everyone."""
    user = PORTAL.require(MODULE)
    everyone = request.args.get("all") == "1" and user["role"] == "admin"
    return {"sessions": [s.info() for s in MANAGER.live(None if everyone else user["username"])]}


@blueprint.post("/api/sessions")
@json_api
def session_open():
    user = PORTAL.require(MODULE)
    body = json_body()
    target = targets.find(body.get("target"))
    if not access.allowed(user, target):
        raise portal_auth.Forbidden(f"{target['site']} · {target['name']} is not one of your hosts: an administrator gives "
                                    "hosts on Shell → Access.")
    step_up = PORTAL.step_up(user, "Opening a terminal")
    work = tempfile.mkdtemp(prefix="s-", dir=sessions.folder("run"))   # 0700: key files of this session
    try:
        spec = targets.connection(target, work)
    except Exception:
        shutil.rmtree(work, ignore_errors=True)
        raise
    spec["folder"] = work
    client = PORTAL.client_address()
    try:
        s = MANAGER.open(user["username"], target, spec, client, body.get("cols"), body.get("rows"), admin=user["role"] == "admin")
    except Exception:
        shutil.rmtree(work, ignore_errors=True)   # a refused session (limit) leaves no key file behind
        raise
    PORTAL.store.event(user["username"], "shell.open", _label(target),
                       f"Session {s.id} as {target['user'] or 'the default account'}"
                       f"{(' via ' + target['via']) if target['via'] else ''}{(' · ' + step_up) if step_up else ''}", client)
    return {"session": s.info()}


@blueprint.get("/api/poll")
@json_api
def session_poll():
    """New output of several sessions of this user at once: c=<id>:<offset>,... (offset -1: everything still buffered).
    Waits up to `wait` seconds for something new."""
    user = PORTAL.require(MODULE)
    cursors = {}
    for part in str(request.args.get("c") or "").split(",")[:16]:
        sid, _, offset = part.partition(":")
        if SID_RE.match(sid):
            s = MANAGER.get(sid)
            if s and s.user != user["username"] and user["role"] != "admin":
                continue
            try:
                cursors[sid] = int(offset)
            except ValueError:
                continue
    if not cursors:
        return {"sessions": {}}
    try:
        wait = float(request.args.get("wait") or 20)
    except ValueError:
        wait = 20
    return {"sessions": MANAGER.poll(cursors, wait, viewer=user["username"])}


@blueprint.post("/api/sessions/<sid>/input")
@json_api
def session_input(sid):
    _user, s = _mine(sid, typing=True)
    MANAGER.write(s, json_body().get("data") or "")
    return {}


@blueprint.post("/api/sessions/<sid>/resize")
@json_api
def session_resize(sid):
    user, s = _mine(sid, admin_too=True)
    if s.user == user["username"]:   # the size of the terminal is its user's; a watcher's window does not change it
        body = json_body()
        MANAGER.resize(s, body.get("cols"), body.get("rows"))
    return {}


@blueprint.post("/api/sessions/<sid>/watch")
@json_api
def session_watch(sid):
    """Administrators: watch a session of another user live (read-only), join it (type too) or leave it. Its user sees
    who is there; the activity log and the recording say so."""
    user = PORTAL.admin()
    mode = str(json_body().get("mode") or "watch")
    if mode not in ("watch", "join", "leave"):
        raise ValueError("mode: watch, join or leave")
    _user, s = _mine(sid, admin_too=True)
    step_up = PORTAL.step_up(user, "Joining a session") if mode == "join" else ""
    MANAGER.watch(s, user["username"], mode)
    if mode != "leave":
        PORTAL.store.event(user["username"], f"shell.{mode}", _label(s.target),
                           f"Session {s.id} of {s.user}: " + ("watched live (read-only)" if mode == "watch"
                                                              else "joined (can type into it)")
                           + (f" · {step_up}" if step_up else ""), PORTAL.client_address())
    return {"session": s.info()}


@blueprint.post("/api/sessions/<sid>/root")
@json_api
def session_root(sid):
    user, s = _mine(sid)
    if not s.info()["become"]:
        raise ValueError("This host's credential cannot become root from the portal")
    step_up = PORTAL.step_up(user, "Become root")
    MANAGER.become_root(s)
    PORTAL.store.event(user["username"], "shell.root", _label(s.target),
                       f"Session {s.id}: sudo -i{(' · ' + step_up) if step_up else ''}", PORTAL.client_address())
    return {}


@blueprint.delete("/api/sessions/<sid>")
@json_api
def session_close(sid):
    user, s = _mine(sid, admin_too=True)
    if s.user != user["username"]:
        MANAGER.close(s, f"Ended by the administrator {user['username']}")
        PORTAL.store.event(user["username"], "shell.terminate", _label(s.target), f"Session {s.id} of {s.user} ended",
                           PORTAL.client_address())
    else:
        MANAGER.close(s)
    return {}


# ---------------- access: which hosts each operator may open (administrators) ----------------
@blueprint.get("/api/access")
@json_api
def access_view():
    """Accounts that may use Shell, with the hosts given to each (administrators open every host), and every host."""
    me = PORTAL.admin()
    given = access.all_grants()
    accounts = []
    for u in PORTAL.users_view(me)["users"]:
        if MODULE not in (u.get("modules") or []):
            continue
        mine = given.get(u["username"], [])
        accounts.append({"username": u["username"], "display_name": u.get("display_name") or "", "source": u["source"],
                         "role": u["role"], "enabled": u["enabled"], "grants": mine,
                         "rules": [g["rule"] for g in mine if g["active"]]})
    return {"accounts": accounts, "targets": targets.all_targets(), "sites": list(sites.sites()), "max_days": access.MAX_DAYS}


@blueprint.put("/api/access/<username>")
@json_api
def access_save(username):
    me = PORTAL.admin()
    body = json_body()
    before, after = access.set_rules(username, body.get("grants", body.get("rules")), me["username"])
    key = lambda gs: [(g["rule"], g.get("expires", ""), g.get("ticket", "")) for g in gs]
    if key(before) != key(after):
        PORTAL.store.event(me["username"], "shell.access", username,
                           f"Shell hosts of {username}: {access.describe(before)} → {access.describe(after)}",
                           PORTAL.client_address())
    MANAGER.reap()   # sessions to hosts no longer given end now
    return {"grants": after, "rules": [g["rule"] for g in after]}


# ---------------- history and recordings ----------------
def _history_row(sid):
    """A session of the history: one's own, or of anyone for an administrator."""
    user = PORTAL.require(MODULE)
    row = sessions.history_row(sid) if SID_RE.match(str(sid or "")) else None
    if not row or (row["username"] != user["username"] and user["role"] != "admin"):
        raise LookupError("Session not found")
    return user, row


@blueprint.get("/api/history")
@json_api
def history_list():
    """Sessions, newest first: an operator's own ones; an administrator's view has everyone (?user= and ?site= filter)."""
    user = PORTAL.require(MODULE)
    who = user["username"] if user["role"] != "admin" else str(request.args.get("user") or "")
    return {"items": sessions.history(who or None, str(request.args.get("site") or ""), request.args.get("limit") or 200,
                                      str(request.args.get("before") or "")),
            "live": [s.id for s in MANAGER.live()], "keep_days": sessions.KEEP_DAYS}


@blueprint.get("/api/history/<sid>/recording")
@json_api
def history_recording(sid):
    """The recorded output (the last 2 MB at most) for the player."""
    user, row = _history_row(sid)
    path = sessions.recording_path(row)
    if not path:
        raise LookupError(f"No recording (removed after {sessions.KEEP_DAYS} days)")
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        f.seek(max(0, size - 2 * 1024 * 1024))
        data = f.read()
    if row["username"] != user["username"]:
        PORTAL.store.event(user["username"], "shell.recording", row["label"] or "", f"Recording of session {sid} of {row['username']} viewed",
                           PORTAL.client_address())
    return {"data": base64.b64encode(data).decode(), "size": size, "truncated": size > len(data), "session": {
        k: row[k] for k in sessions.HISTORY_FIELDS}}


@blueprint.get("/export/history/<sid>.txt")
def history_text(sid):
    try:
        user, row = _history_row(sid)
        path = sessions.recording_path(row)
        if not path:
            raise LookupError(f"No recording (removed after {sessions.KEEP_DAYS} days)")
    except portal_auth.NotSignedIn as e:
        return jsonify(ok=False, error=str(e)), 401
    except portal_auth.Forbidden as e:
        return jsonify(ok=False, error=str(e)), 403
    except LookupError as e:
        return jsonify(ok=False, error=str(e)), 404
    with open(path, "rb") as f:
        text = sessions.plain_text(f.read())
    head = (f"# Shell session {row['id']}: {row['label']}\n# {row['username']} from {row['client_ip'] or '-'}, "
            f"{row['started']} - {row['ended'] or 'open'}\n# {row['reason'] or ''}\n\n")
    if row["username"] != user["username"]:
        PORTAL.store.event(user["username"], "shell.recording", row["label"] or "", f"Recording of session {sid} of {row['username']} downloaded",
                           PORTAL.client_address())
    resp = make_response(head + text)
    resp.headers["Content-Type"] = "text/plain; charset=utf-8"
    resp.headers["Content-Disposition"] = f'attachment; filename="shell-{row["started"][:10]}-{row["id"]}.txt"'
    return resp


# ---------------- snippets ----------------
@blueprint.get("/api/snippets")
@json_api
def snippet_list():
    user = PORTAL.require(MODULE)
    return {"snippets": sessions.snippets(user["username"])}


@blueprint.post("/api/snippets")
@json_api
def snippet_add():
    user = PORTAL.require(MODULE)
    return {"id": sessions.save_snippet(user, json_body())}


@blueprint.put("/api/snippets/<int:snippet_id>")
@json_api
def snippet_update(snippet_id):
    user = PORTAL.require(MODULE)
    return {"id": sessions.save_snippet(user, json_body(), snippet_id)}


@blueprint.delete("/api/snippets/<int:snippet_id>")
@json_api
def snippet_delete(snippet_id):
    user = PORTAL.require(MODULE)
    sessions.delete_snippet(user, snippet_id)
    return {}

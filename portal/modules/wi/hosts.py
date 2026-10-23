"""SSH access of Operation Automation, managed by administrators on the page Hosts & SSH (SQLite, portal database):

  wi_ssh_credentials  a name, a username and a private key or a password (encrypted with the portal vault, never shown or
                      returned again), how the account becomes root, and whether it may run fixes
  wi_hosts            the VMs and devices of each site and product group (cdn, dns, vyos, linux, ...) and the credential
                      they use; they join the hosts groups of sites.yml, so every host check can choose them. A host
                      without an address the portal can reach goes through a jump host (jump_id): another host of
                      the same site, reached directly, that opens the SSH connection onwards (ssh -W, one hop)
  wi_actions          every fix run from a check result: who, which commands, on which host, the output, the check
                      run again afterwards

Only fixed commands of a check result run on a host (never text from the browser). sites.yml hosts keep their read-only
account and never run fixes.
"""
import base64
import contextlib
import datetime
import hashlib
import ipaddress
import json
import os
import re
import socket
import sqlite3

import settings
import sites

GROUPS = {  # product group -> label (the hosts groups the catalog uses)
    "cdn": "Acme CDN VMs", "repo": "Repository VMs", "dns": "DNS recursors", "vyos": "VyOS gateways",
    "linux": "Linux VMs", "siem": "SIEM collectors and forwarders", "esxi": "ESXi hosts", "gb200": "GB200 compute trays",
    "huawei": "Huawei routers",
}
PRIVILEGES = {
    "root": "Logs in as root",
    "sudo": "sudo without a password (NOPASSWD)",
    "sudo_password": "sudo with the login password",
    "none": "No sudo: only commands of this user",
}
AUTHS = {"key": "Private key", "password": "Password"}
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
USER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}$")
ADDRESS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}$")
KEY_RE = re.compile(r"^-----BEGIN [A-Z ]*PRIVATE KEY-----\n[\s\S]+\n-----END [A-Z ]*PRIVATE KEY-----\n?$")
MAX_SECRET = 16384


@contextlib.contextmanager
def _db():
    os.makedirs(os.path.dirname(os.path.abspath(settings.DB_PATH)), exist_ok=True)
    conn = sqlite3.connect(settings.DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def _now():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def init():
    """Create the tables; fixes still marked running (the portal stopped meanwhile) become unknown."""
    with _db() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS wi_ssh_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, username TEXT NOT NULL, auth TEXT NOT NULL,
            secret TEXT NOT NULL, privilege TEXT NOT NULL, fixes INTEGER NOT NULL DEFAULT 0, updated TEXT, updated_by TEXT)""")
        db.execute("""CREATE TABLE IF NOT EXISTS wi_hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, site TEXT NOT NULL, grp TEXT NOT NULL, name TEXT NOT NULL,
            address TEXT NOT NULL, port INTEGER NOT NULL DEFAULT 22,
            credential_id INTEGER REFERENCES wi_ssh_credentials(id), note TEXT, updated TEXT, updated_by TEXT,
            UNIQUE(site, name))""")
        db.execute("""CREATE TABLE IF NOT EXISTS wi_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER NOT NULL, rec_index INTEGER NOT NULL, title TEXT,
            risk TEXT, target TEXT, commands TEXT, username TEXT NOT NULL, client_ip TEXT, ts TEXT NOT NULL, finished TEXT,
            status TEXT NOT NULL, output TEXT, error TEXT, job_id TEXT, verify_run_id INTEGER)""")
        if "jump_id" not in [r[1] for r in db.execute("PRAGMA table_info(wi_hosts)")]:
            db.execute("ALTER TABLE wi_hosts ADD COLUMN jump_id INTEGER")
        if "fingerprint" not in [r[1] for r in db.execute("PRAGMA table_info(wi_ssh_credentials)")]:
            db.execute("ALTER TABLE wi_ssh_credentials ADD COLUMN fingerprint TEXT NOT NULL DEFAULT ''")
        db.execute("CREATE INDEX IF NOT EXISTS wi_actions_run ON wi_actions(run_id)")
        db.execute("UPDATE wi_actions SET status = 'unknown', finished = ?, error = 'The portal stopped while the fix was "
                   "running: check the host.' WHERE status = 'running'", (_now(),))


# ---------------- SSH credentials ----------------
KEY_TYPES = {"ssh-ed25519": "ED25519", "ssh-rsa": "RSA", "ecdsa-sha2-nistp256": "ECDSA", "ecdsa-sha2-nistp384": "ECDSA",
             "ecdsa-sha2-nistp521": "ECDSA", "ssh-dss": "DSA"}


def key_fingerprint(text):
    """"ED25519 SHA256:..." of a private key, as `ssh-keygen -l` shows its public key (not secret: it identifies the key
    in authorized_keys). ValueError when the key cannot be read."""
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives import serialization
    data = str(text or "").strip().encode() + b"\n"
    try:
        key = (serialization.load_ssh_private_key(data, password=None) if b"OPENSSH PRIVATE KEY" in data
               else serialization.load_pem_private_key(data, password=None))
        kind, blob = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).split()[:2]
    except (ValueError, TypeError, UnsupportedAlgorithm) as e:
        raise ValueError(f"The private key cannot be read ({str(e).splitlines()[0][:80] or type(e).__name__}): paste the whole "
                         "key file, without a passphrase")
    digest = base64.b64encode(hashlib.sha256(base64.b64decode(blob)).digest()).decode().rstrip("=")
    return f"{KEY_TYPES.get(kind.decode(), kind.decode())} SHA256:{digest}"


def credentials(vault=None):
    """SSH credentials without their secret; the fingerprint of a stored key (older rows get it on the first listing)."""
    with _db() as db:
        rows = db.execute("""SELECT c.id, c.name, c.username, c.auth, c.privilege, c.fixes, c.updated, c.updated_by,
                             c.fingerprint, (SELECT COUNT(*) FROM wi_hosts h WHERE h.credential_id = c.id) AS hosts
                             FROM wi_ssh_credentials c ORDER BY c.name""").fetchall()
        out = [dict(r, fixes=bool(r["fixes"])) for r in rows]
        for c in out:
            if vault is not None and c["auth"] == "key" and not c["fingerprint"]:
                secret = db.execute("SELECT secret FROM wi_ssh_credentials WHERE id = ?", (c["id"],)).fetchone()["secret"]
                try:
                    c["fingerprint"] = key_fingerprint(vault.decrypt(secret))
                except Exception:   # unreadable key or vault: shown as such, the job reports the details
                    c["fingerprint"] = "unreadable key"
                db.execute("UPDATE wi_ssh_credentials SET fingerprint = ? WHERE id = ?", (c["fingerprint"], c["id"]))
    return out


def save_credential(vault, actor, body, cred_id=None):
    """Add (cred_id None) or change a credential. On a change, an empty secret keeps the stored one."""
    name = str(body.get("name") or "").strip()
    username = str(body.get("username") or "").strip()
    auth = str(body.get("auth") or "")
    privilege = str(body.get("privilege") or "")
    secret = str(body.get("secret") or "").replace("\r\n", "\n")
    if not NAME_RE.match(name):
        raise ValueError("Name: letters, digits, '.', '_' or '-' (up to 63)")
    if not USER_RE.match(username):
        raise ValueError("Username is not valid")
    if auth not in AUTHS:
        raise ValueError("Choose a private key or a password")
    if privilege not in PRIVILEGES:
        raise ValueError("Choose how the account becomes root")
    if privilege == "sudo_password" and auth != "password":
        raise ValueError("sudo with the login password needs password sign-in")
    if len(secret) > MAX_SECRET:
        raise ValueError("The key or password is too long")
    if secret and auth == "key" and not KEY_RE.match(secret.strip() + "\n"):
        raise ValueError("Paste the whole private key, from -----BEGIN … PRIVATE KEY----- to -----END … PRIVATE KEY-----")
    if secret and auth == "key" and "ENCRYPTED" in secret:
        raise ValueError("The private key has a passphrase: use a key without one, or password sign-in")
    fingerprint = key_fingerprint(secret) if secret and auth == "key" else ""
    if cred_id is None and not secret:
        raise ValueError("The private key or the password is required")
    fixes = 1 if body.get("fixes") else 0
    with _db() as db:
        if cred_id is None:
            try:
                cur = db.execute("INSERT INTO wi_ssh_credentials (name, username, auth, secret, privilege, fixes, updated, "
                                 "updated_by, fingerprint) VALUES (?,?,?,?,?,?,?,?,?)",
                                 (name, username, auth, vault.encrypt(secret.strip() + ("\n" if auth == "key" else "")),
                                  privilege, fixes, _now(), actor, fingerprint))
            except sqlite3.IntegrityError:
                raise ValueError(f"A credential named {name} already exists")
            return cur.lastrowid
        row = db.execute("SELECT auth FROM wi_ssh_credentials WHERE id = ?", (cred_id,)).fetchone()
        if not row:
            raise LookupError("Credential not found")
        if not secret and row["auth"] != auth:
            raise ValueError("Changing between key and password needs the new key or password")
        try:
            if secret:
                db.execute("UPDATE wi_ssh_credentials SET name=?, username=?, auth=?, secret=?, privilege=?, fixes=?, updated=?, "
                           "updated_by=?, fingerprint=? WHERE id=?",
                           (name, username, auth, vault.encrypt(secret.strip() + ("\n" if auth == "key" else "")),
                            privilege, fixes, _now(), actor, fingerprint, cred_id))
            else:
                db.execute("UPDATE wi_ssh_credentials SET name=?, username=?, privilege=?, fixes=?, updated=?, updated_by=? "
                           "WHERE id=?", (name, username, privilege, fixes, _now(), actor, cred_id))
        except sqlite3.IntegrityError:
            raise ValueError(f"A credential named {name} already exists")
        return cred_id


def delete_credential(cred_id):
    with _db() as db:
        used = db.execute("SELECT COUNT(*) FROM wi_hosts WHERE credential_id = ?", (cred_id,)).fetchone()[0]
        if used:
            raise ValueError(f"{used} host(s) still use this credential: give them another one first")
        row = db.execute("SELECT name FROM wi_ssh_credentials WHERE id = ?", (cred_id,)).fetchone()
        if not row:
            raise LookupError("Credential not found")
        db.execute("DELETE FROM wi_ssh_credentials WHERE id = ?", (cred_id,))
        return row["name"]


def secret_of(vault, cred_id):
    """{"username", "auth", "secret", "privilege", "fixes"} of a credential, for a job (environment only)."""
    with _db() as db:
        row = db.execute("SELECT * FROM wi_ssh_credentials WHERE id = ?", (cred_id,)).fetchone()
    if not row:
        raise LookupError("The SSH credential of this host was removed")
    return {"username": row["username"], "auth": row["auth"], "secret": vault.decrypt(row["secret"]),
            "privilege": row["privilege"], "fixes": bool(row["fixes"])}


# ---------------- hosts ----------------
def ssh_proxy(address, resolve=True):
    """host:port of the web proxy (WI_SSH_PROXY, e.g. the Squid of pfSense) when SSH to this address must go through it:
    a public address while the portal server has no direct route to the internet. Private addresses stay direct.
    A name is resolved (resolve=False: unknown -> ""); a name that does not resolve goes through the proxy."""
    proxy = os.environ.get("WI_SSH_PROXY", "").strip()
    if not proxy:
        return ""
    try:
        ip = ipaddress.ip_address(str(address))
    except ValueError:
        if not resolve:
            return ""
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(str(address)))
        except (OSError, ValueError):
            return proxy
    return proxy if ip.is_global else ""


def _check_jump(site, jump_id, host_id, db):
    """A jump host is a host of the same site with a credential, reached directly (one hop), not the host itself."""
    if jump_id is None:
        return
    if host_id is not None and jump_id == host_id:
        raise ValueError("A host cannot be its own jump host")
    if host_id is not None and db.execute("SELECT 1 FROM wi_hosts WHERE jump_id = ?", (host_id,)).fetchone():
        raise ValueError("Other hosts connect through this host, so it cannot use a jump host itself")
    row = db.execute("SELECT name, site, jump_id, credential_id FROM wi_hosts WHERE id = ?", (jump_id,)).fetchone()
    if not row or row["site"] != site:
        raise ValueError(f"Choose a jump host of site {site}")
    if row["jump_id"]:
        raise ValueError(f"{row['name']} itself goes through a jump host: choose a host the portal reaches directly")
    if not row["credential_id"]:
        raise ValueError(f"{row['name']} has no SSH credential: give it one before using it as a jump host")


def _check_host(site, grp, name, address, port, cred_id, db):
    if site not in sites.sites():
        raise ValueError(f"Unknown site {site}")
    if grp not in GROUPS:
        raise ValueError("Choose a product group")
    if not NAME_RE.match(name):
        raise ValueError(f"Name {name!r}: letters, digits, '.', '_' or '-' (up to 63)")
    if not ADDRESS_RE.match(address):
        raise ValueError(f"Address {address!r} is not a host name or an IP address")
    if not (1 <= port <= 65535):
        raise ValueError("SSH port must be 1-65535")
    if cred_id is not None and not db.execute("SELECT 1 FROM wi_ssh_credentials WHERE id = ?", (cred_id,)).fetchone():
        raise ValueError("Choose an existing SSH credential")


def hosts(site=""):
    sql = """SELECT h.id, h.site, h.grp, h.name, h.address, h.port, h.credential_id, h.note, h.updated, h.updated_by,
             h.jump_id, j.name AS jump, c.name AS credential, c.username, c.auth, c.privilege, c.fixes,
             (SELECT COUNT(*) FROM wi_hosts x WHERE x.jump_id = h.id) AS jumped
             FROM wi_hosts h LEFT JOIN wi_ssh_credentials c ON c.id = h.credential_id
             LEFT JOIN wi_hosts j ON j.id = h.jump_id"""
    with _db() as db:
        rows = db.execute(sql + (" WHERE h.site = ?" if site else "") + " ORDER BY h.site, h.grp, h.name",
                          (site,) if site else ()).fetchall()
    return [dict(r, fixes=bool(r["fixes"]), proxy=bool(not r["jump_id"] and ssh_proxy(r["address"], resolve=False)))
            for r in rows]


def _int(value, label, default=None):
    if value in (None, ""):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{label} must be a number")


def save_host(actor, body, host_id=None):
    site, grp = str(body.get("site") or ""), str(body.get("group") or "")
    name, address = str(body.get("name") or "").strip(), str(body.get("address") or "").strip()
    port = _int(body.get("port"), "SSH port", 22)
    cred_id = _int(body.get("credential_id"), "Credential")
    jump_id = _int(body.get("jump_id"), "Jump host")
    note = str(body.get("note") or "").strip()[:200]
    with _db() as db:
        _check_host(site, grp, name, address, port, cred_id, db)
        if host_id is not None and not db.execute("SELECT 1 FROM wi_hosts WHERE id = ?", (host_id,)).fetchone():
            raise LookupError("Host not found")
        _check_jump(site, jump_id, host_id, db)
        if host_id is not None:
            moved = db.execute("SELECT COUNT(*) FROM wi_hosts WHERE jump_id = ? AND site != ?", (host_id, site)).fetchone()[0]
            if moved:
                raise ValueError(f"{moved} host(s) of the old site connect through this host: change them first")
        try:
            if host_id is None:
                cur = db.execute("INSERT INTO wi_hosts (site, grp, name, address, port, credential_id, note, updated, updated_by, "
                                 "jump_id) VALUES (?,?,?,?,?,?,?,?,?,?)",
                                 (site, grp, name, address, port, cred_id, note, _now(), actor, jump_id))
                return cur.lastrowid
            db.execute("UPDATE wi_hosts SET site=?, grp=?, name=?, address=?, port=?, credential_id=?, note=?, updated=?, "
                       "updated_by=?, jump_id=? WHERE id=?",
                       (site, grp, name, address, port, cred_id, note, _now(), actor, jump_id, host_id))
            return host_id
        except sqlite3.IntegrityError:
            raise ValueError(f"{name} already exists on site {site}")


def add_many(actor, body):
    """Many hosts at once: one per line, "name address [port]" (or "name,address,port"). All or nothing."""
    site, grp = str(body.get("site") or ""), str(body.get("group") or "")
    cred_id = _int(body.get("credential_id"), "Credential")
    jump_id = _int(body.get("jump_id"), "Jump host")
    lines = [l.strip() for l in str(body.get("lines") or "").splitlines() if l.strip() and not l.strip().startswith("#")]
    if not lines:
        raise ValueError("Add one host per line: name address [port]")
    if len(lines) > 500:
        raise ValueError("At most 500 hosts at once")
    rows = []
    for n, line in enumerate(lines, 1):
        parts = [p for p in re.split(r"[\s,;]+", line) if p]
        if len(parts) not in (2, 3):
            raise ValueError(f"Line {n}: write name address [port]")
        rows.append((parts[0], parts[1], _int(parts[2], f"Line {n}: port") if len(parts) == 3 else 22))
    with _db() as db:
        for name, address, port in rows:
            _check_host(site, grp, name, address, port, cred_id, db)
        _check_jump(site, jump_id, None, db)
        try:
            for name, address, port in rows:
                db.execute("INSERT INTO wi_hosts (site, grp, name, address, port, credential_id, note, updated, updated_by, "
                           "jump_id) VALUES (?,?,?,?,?,?,?,?,?,?)",
                           (site, grp, name, address, port, cred_id, "", _now(), actor, jump_id))
        except sqlite3.IntegrityError as e:
            raise ValueError(f"A host already exists on site {site} ({e}); nothing was added")
    return len(rows)


def delete_host(host_id):
    with _db() as db:
        row = db.execute("SELECT site, name FROM wi_hosts WHERE id = ?", (host_id,)).fetchone()
        if not row:
            raise LookupError("Host not found")
        used = db.execute("SELECT COUNT(*) FROM wi_hosts WHERE jump_id = ?", (host_id,)).fetchone()[0]
        if used:
            raise ValueError(f"{used} host(s) connect through {row['name']}: give them another jump host first")
        db.execute("DELETE FROM wi_hosts WHERE id = ?", (host_id,))
        return f"{row['name']} ({row['site']})"


def members(site, grp):
    """{name: address} of the portal hosts of a site and group (joined to the hosts groups of sites.yml)."""
    with _db() as db:
        rows = db.execute("SELECT name, address FROM wi_hosts WHERE site = ? AND grp = ? ORDER BY name", (site, grp)).fetchall()
    return {r["name"]: r["address"] for r in rows}


def target(site, groups, value):
    """The portal host named (or addressed) by value in one of the groups: the job target without any secret."""
    wanted = str(value or "").strip()
    address_only = re.sub(r":\d+$", "", wanted) if wanted.count(":") == 1 else wanted
    with _db() as db:
        for grp in groups:
            row = db.execute("""SELECT h.*, c.name AS credential, c.username, c.auth, c.privilege, c.fixes FROM wi_hosts h
                                LEFT JOIN wi_ssh_credentials c ON c.id = h.credential_id
                                WHERE h.site = ? AND h.grp = ? AND (h.name = ? OR h.address = ? OR h.address = ?)""",
                             (site, grp, wanted, wanted, address_only)).fetchone()
            if row:
                out = {"name": row["name"], "address": row["address"], "group": row["grp"], "port": row["port"],
                       "connection": "ssh", "source": "portal", "credential_id": row["credential_id"],
                       "credential": row["credential"] or "", "user": row["username"] or "", "auth": row["auth"] or "",
                       "privilege": row["privilege"] or "none", "fixes": bool(row["fixes"]), "sudo": False}
                if not row["jump_id"] and ssh_proxy(row["address"]):
                    out["proxy"] = ssh_proxy(row["address"])
                if row["jump_id"]:
                    jump = db.execute("""SELECT h.name, h.address, h.port, h.credential_id, c.username, c.auth FROM wi_hosts h
                                         LEFT JOIN wi_ssh_credentials c ON c.id = h.credential_id WHERE h.id = ?""",
                                      (row["jump_id"],)).fetchone()
                    if jump:
                        out["jump"] = {"name": jump["name"], "address": jump["address"], "port": jump["port"],
                                       "credential_id": jump["credential_id"], "user": jump["username"] or "",
                                       "auth": jump["auth"] or ""}
                        if ssh_proxy(jump["address"]):
                            out["jump"]["proxy"] = ssh_proxy(jump["address"])
                return out
    return None


def jump_secrets(vault, target):
    """Environment of the job for the jump host of a target: its private key (WI_SSH_JUMP_SECRET, written to a 0600
    file by the playbook) or its password (SSHPASS, read by sshpass -e in the ProxyCommand)."""
    jump = (target or {}).get("jump")
    if not jump:
        return {}
    if not jump.get("credential_id"):
        raise ValueError(f"The jump host {jump['name']} has no SSH credential: give it one on Hosts & SSH.")
    cred = secret_of(vault, jump["credential_id"])
    if cred["auth"] == "password":
        return {"SSHPASS": cred["secret"]}
    return {"WI_SSH_JUMP_SECRET": cred["secret"].rstrip("\n") + "\n"}   # OpenSSH refuses a key file without the last newline


# ---------------- fixes run from a check result ----------------
ACTION_FIELDS = ("id", "run_id", "rec_index", "title", "risk", "target", "username", "client_ip", "ts", "finished", "status",
                 "error", "job_id", "verify_run_id")


def action_begin(run_id, index, title, risk, target_name, commands, username, client_ip):
    with _db() as db:
        cur = db.execute("INSERT INTO wi_actions (run_id, rec_index, title, risk, target, commands, username, client_ip, ts, "
                         "status) VALUES (?,?,?,?,?,?,?,?,?,?)", (run_id, index, title, risk, target_name, json.dumps(commands),
                                                                   username, client_ip, _now(), "running"))
        return cur.lastrowid


def action_set(action_id, **fields):
    allowed = {"job_id", "status", "output", "error", "finished", "verify_run_id"}
    fields = {k: v for k, v in fields.items() if k in allowed}
    if not fields:
        return
    with _db() as db:
        db.execute(f"UPDATE wi_actions SET {', '.join(f'{k} = ?' for k in fields)} WHERE id = ?", (*fields.values(), action_id))


def action_finish(action_id, status, output, error=""):
    action_set(action_id, status=status, output=json.dumps(output), error=error, finished=_now())


def _action_row(r):
    item = {k: r[k] for k in ACTION_FIELDS}
    item["commands"] = json.loads(r["commands"] or "[]")
    try:
        item["output"] = json.loads(r["output"]) if r["output"] else []
    except ValueError:
        item["output"] = []
    return item


def action(action_id):
    with _db() as db:
        row = db.execute("SELECT * FROM wi_actions WHERE id = ?", (action_id,)).fetchone()
    return _action_row(row) if row else None


def running_actions():
    """The fixes running now, with the check, site and target of the run they were started from."""
    with _db() as db:
        rows = db.execute("""SELECT a.id, a.run_id, a.rec_index, a.title, a.target, a.username, a.ts, r.check_id, r.check_title,
                                    r.site, r.host FROM wi_actions a LEFT JOIN wi_runs r ON r.id = a.run_id
                             WHERE a.status = 'running' ORDER BY a.id""").fetchall()
    return [dict(r) for r in rows]


def actions_by_runs(run_ids):
    """{run_id: [{"id", "status", "title"}]} of the fixes started from these runs (the Runs list)."""
    ids = [int(x) for x in run_ids or []][:500]
    if not ids:
        return {}
    with _db() as db:
        rows = db.execute(f"SELECT id, run_id, status, title FROM wi_actions WHERE run_id IN ({','.join('?' * len(ids))}) ORDER BY id",
                          ids).fetchall()
    out = {}
    for r in rows:
        out.setdefault(r["run_id"], []).append({"id": r["id"], "status": r["status"], "title": r["title"]})
    return out


def actions_of_run(run_id):
    with _db() as db:
        rows = db.execute("SELECT * FROM wi_actions WHERE run_id = ? ORDER BY id", (run_id,)).fetchall()
    return [_action_row(r) for r in rows]

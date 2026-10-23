"""BMCs of Operation Automation, managed by administrators on the page BMC (SQLite, portal database):

  wi_bmc_credentials  a name, the username and password of a BMC web account (encrypted with the portal vault, never shown
                      or returned again); one credential can serve many BMCs
  wi_bmcs             the BMC of each server: its management IP (the address of the BMC web page), the HTTPS port, the
                      vendor and the credential it uses

The checks read a BMC with the Redfish API over HTTPS on that address (GET only), with the same account as its web page:
no SSH. A BMC account with the read-only role is enough (Lenovo XCC: Read-Only; Inspur: User).
"""
import contextlib
import datetime
import ipaddress
import os
import re
import sqlite3

import settings
import sites
from portal_auth import normalize_address

VENDORS = {"": "Detect (Redfish)", "lenovo": "Lenovo (XClarity Controller)", "inspur": "Inspur", "other": "Other (Redfish)"}
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
USER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}$")
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,252}$")
MAX_SECRET = 512


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
    with _db() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS wi_bmc_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, username TEXT NOT NULL, secret TEXT NOT NULL,
            updated TEXT, updated_by TEXT)""")
        db.execute("""CREATE TABLE IF NOT EXISTS wi_bmcs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, site TEXT NOT NULL, name TEXT NOT NULL, address TEXT NOT NULL,
            port INTEGER NOT NULL DEFAULT 443, vendor TEXT NOT NULL DEFAULT '',
            credential_id INTEGER REFERENCES wi_bmc_credentials(id), note TEXT, updated TEXT, updated_by TEXT,
            UNIQUE(site, name))""")


# ---------------- credentials ----------------
def credentials():
    with _db() as db:
        rows = db.execute("""SELECT c.id, c.name, c.username, c.updated, c.updated_by,
                             (SELECT COUNT(*) FROM wi_bmcs b WHERE b.credential_id = c.id) AS bmcs
                             FROM wi_bmc_credentials c ORDER BY c.name""").fetchall()
    return [dict(r) for r in rows]


def save_credential(vault, actor, body, cred_id=None):
    """Add (cred_id None) or change a BMC credential. On a change, an empty password keeps the stored one."""
    name = str(body.get("name") or "").strip()
    username = str(body.get("username") or "").strip()
    secret = str(body.get("secret") or "")
    if not NAME_RE.match(name):
        raise ValueError("Name: letters, digits, '.', '_' or '-' (up to 63)")
    if not USER_RE.match(username):
        raise ValueError("Username is not valid")
    if len(secret) > MAX_SECRET or "\n" in secret:
        raise ValueError("The password is not valid")
    if cred_id is None and not secret:
        raise ValueError("The password is required")
    with _db() as db:
        try:
            if cred_id is None:
                cur = db.execute("INSERT INTO wi_bmc_credentials (name, username, secret, updated, updated_by) VALUES (?,?,?,?,?)",
                                 (name, username, vault.encrypt(secret), _now(), actor))
                return cur.lastrowid
            if not db.execute("SELECT 1 FROM wi_bmc_credentials WHERE id = ?", (cred_id,)).fetchone():
                raise LookupError("Credential not found")
            if secret:
                db.execute("UPDATE wi_bmc_credentials SET name=?, username=?, secret=?, updated=?, updated_by=? WHERE id=?",
                           (name, username, vault.encrypt(secret), _now(), actor, cred_id))
            else:
                db.execute("UPDATE wi_bmc_credentials SET name=?, username=?, updated=?, updated_by=? WHERE id=?",
                           (name, username, _now(), actor, cred_id))
            return cred_id
        except sqlite3.IntegrityError:
            raise ValueError(f"A BMC credential named {name} already exists")


def delete_credential(cred_id):
    with _db() as db:
        used = db.execute("SELECT COUNT(*) FROM wi_bmcs WHERE credential_id = ?", (cred_id,)).fetchone()[0]
        if used:
            raise ValueError(f"{used} BMC(s) still use this credential: give them another one first")
        row = db.execute("SELECT name FROM wi_bmc_credentials WHERE id = ?", (cred_id,)).fetchone()
        if not row:
            raise LookupError("Credential not found")
        db.execute("DELETE FROM wi_bmc_credentials WHERE id = ?", (cred_id,))
        return row["name"]


def secret_of(vault, cred_id):
    """{"username", "password"} of a BMC credential, for a job (environment only)."""
    with _db() as db:
        row = db.execute("SELECT username, secret FROM wi_bmc_credentials WHERE id = ?", (cred_id,)).fetchone()
    if not row:
        raise LookupError("The BMC credential was removed")
    return {"username": row["username"], "password": vault.decrypt(row["secret"])}


# ---------------- BMCs ----------------
def parse_address(value):
    """(host, port) from what an administrator types or pastes: an IP, a name, host:port or the URL of the BMC web page."""
    text = normalize_address(value)
    host, port = text, None
    m = re.fullmatch(r"(.+):(\d{1,5})", text)
    if m:
        host, port = m.group(1), int(m.group(2))
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        if not HOST_RE.match(host) or host.replace(".", "").isdigit():
            raise ValueError(f"Address {value!r}: the management IP of the BMC (or its name)")
    return host, port


def _check(site, name, port, vendor, cred_id, db):
    if site not in sites.sites():
        raise ValueError(f"Unknown site {site}")
    if not NAME_RE.match(name):
        raise ValueError(f"Name {name!r}: letters, digits, '.', '_' or '-' (up to 63)")
    if not 1 <= port <= 65535:
        raise ValueError("HTTPS port must be 1-65535")
    if vendor not in VENDORS:
        raise ValueError("Choose a vendor")
    if cred_id is not None and not db.execute("SELECT 1 FROM wi_bmc_credentials WHERE id = ?", (cred_id,)).fetchone():
        raise ValueError("Choose an existing BMC credential")


def _int(value, label, default=None):
    if value in (None, ""):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{label} must be a number")


def bmcs(site=""):
    sql = """SELECT b.id, b.site, b.name, b.address, b.port, b.vendor, b.credential_id, b.note, b.updated, b.updated_by,
             c.name AS credential, c.username FROM wi_bmcs b LEFT JOIN wi_bmc_credentials c ON c.id = b.credential_id"""
    with _db() as db:
        rows = db.execute(sql + (" WHERE b.site = ?" if site else "") + " ORDER BY b.site, b.name",
                          (site,) if site else ()).fetchall()
    return [dict(r) for r in rows]


def save_bmc(actor, body, bmc_id=None):
    site, name = str(body.get("site") or ""), str(body.get("name") or "").strip()
    address, typed_port = parse_address(body.get("address"))
    port = _int(body.get("port"), "HTTPS port", None) or typed_port or 443
    vendor = str(body.get("vendor") or "")
    cred_id = _int(body.get("credential_id"), "Credential")
    note = str(body.get("note") or "").strip()[:200]
    with _db() as db:
        _check(site, name, port, vendor, cred_id, db)
        try:
            if bmc_id is None:
                cur = db.execute("INSERT INTO wi_bmcs (site, name, address, port, vendor, credential_id, note, updated, updated_by) "
                                 "VALUES (?,?,?,?,?,?,?,?,?)", (site, name, address, port, vendor, cred_id, note, _now(), actor))
                return cur.lastrowid
            if not db.execute("SELECT 1 FROM wi_bmcs WHERE id = ?", (bmc_id,)).fetchone():
                raise LookupError("BMC not found")
            db.execute("UPDATE wi_bmcs SET site=?, name=?, address=?, port=?, vendor=?, credential_id=?, note=?, updated=?, "
                       "updated_by=? WHERE id=?", (site, name, address, port, vendor, cred_id, note, _now(), actor, bmc_id))
            return bmc_id
        except sqlite3.IntegrityError:
            raise ValueError(f"{name} already exists on site {site}")


def add_many(actor, body):
    """Many BMCs at once: one per line, "name address" (address = management IP, optionally :port). All or nothing."""
    site, vendor = str(body.get("site") or ""), str(body.get("vendor") or "")
    cred_id = _int(body.get("credential_id"), "Credential")
    lines = [l.strip() for l in str(body.get("lines") or "").splitlines() if l.strip() and not l.strip().startswith("#")]
    if not lines:
        raise ValueError("Add one BMC per line: name address")
    if len(lines) > 1000:
        raise ValueError("At most 1000 BMCs at once")
    rows = []
    for n, line in enumerate(lines, 1):
        parts = [p for p in re.split(r"[\s,;]+", line) if p]
        if len(parts) != 2:
            raise ValueError(f"Line {n}: write name address")
        try:
            host, port = parse_address(parts[1])
        except ValueError as e:
            raise ValueError(f"Line {n}: {e}")
        rows.append((parts[0], host, port or 443))
    with _db() as db:
        for name, _host, port in rows:
            try:
                _check(site, name, port, vendor, cred_id, db)
            except ValueError as e:
                raise ValueError(f"{name}: {e}")
        try:
            for name, host, port in rows:
                db.execute("INSERT INTO wi_bmcs (site, name, address, port, vendor, credential_id, note, updated, updated_by) "
                           "VALUES (?,?,?,?,?,?,?,?,?)", (site, name, host, port, vendor, cred_id, "", _now(), actor))
        except sqlite3.IntegrityError as e:
            raise ValueError(f"A BMC already exists on site {site} ({e}); nothing was added")
    return len(rows)


def delete_bmc(bmc_id):
    with _db() as db:
        row = db.execute("SELECT site, name FROM wi_bmcs WHERE id = ?", (bmc_id,)).fetchone()
        if not row:
            raise LookupError("BMC not found")
        db.execute("DELETE FROM wi_bmcs WHERE id = ?", (bmc_id,))
        return f"{row['name']} ({row['site']})"


def members(site):
    """{name: address} of the BMCs of a site (the hosts group "bmc" of the checks)."""
    with _db() as db:
        rows = db.execute("SELECT name, address FROM wi_bmcs WHERE site = ? ORDER BY name", (site,)).fetchall()
    return {r["name"]: r["address"] for r in rows}


def target(site, value):
    """The BMC of the site named (or addressed) by value: the job target, without any secret."""
    wanted = str(value or "").strip()
    try:
        address = parse_address(wanted)[0]
    except ValueError:
        address = wanted
    with _db() as db:
        row = db.execute("""SELECT b.*, c.name AS credential, c.username FROM wi_bmcs b
                            LEFT JOIN wi_bmc_credentials c ON c.id = b.credential_id
                            WHERE b.site = ? AND (b.name = ? OR b.address = ?)""", (site, wanted, address)).fetchone()
    if not row:
        return None
    return {"name": row["name"], "address": row["address"], "port": row["port"], "group": "bmc", "connection": "redfish",
            "source": "bmc", "vendor": row["vendor"] or "", "credential_id": row["credential_id"],
            "credential": row["credential"] or "", "user": row["username"] or ""}

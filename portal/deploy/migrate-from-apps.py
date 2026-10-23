#!/usr/bin/env python3
"""Moves ACI Web UI (aci_webui) and ONTAP Restore Web UI (ontap_restore) into the Ops Portal (run as root).

  migrate-from-apps.py config [--hostname NAME] [--port 8080]
      /etc/ops-portal from the old configuration, only the files that are missing:
      sites.yml (ONTAP sites.yml + the APIC of every site from ACI_SITES), auth.yml (the ACI one: same port, Duo redirect
      to https://NAME:PORT/auth/...), authproxy-ldap-ca.pem, keys/openstack_mgmt, product_templates.json.
  migrate-from-apps.py data [--admin USER ...] [--wi-for-all]
      Into a NEW portal database (the portal created its tables and is stopped): users (modules from the app they came
      from), local accounts, service accounts (decrypted with the old key, encrypted with the portal key), activity, ACI
      changes (aci_audit) and ONTAP restores, groups and scheduled deletions.
  migrate-from-apps.py check
      Counts in the portal database and a decryption test of every service account (nothing printed but OK / FAILED).

Prints names, counts and fingerprints only: never a password, secret or key. Uses the Python of the ONTAP Restore venv
(cryptography, PyYAML) or the portal venv.
"""
import argparse
import datetime
import hashlib
import os
import re
import shutil
import sqlite3
import sys

import yaml
from cryptography.fernet import Fernet

# Paths can be moved for a test run (MIGRATE_ROOT=/tmp/x prefixes every path; MIGRATE_OWNER = owner of written files).
ROOT = os.environ.get("MIGRATE_ROOT", "")
ACI_DB, ACI_ETC = ROOT + "/var/lib/aci_webui/audit.db", ROOT + "/etc/aci_webui"
ONTAP_DB, ONTAP_ETC = ROOT + "/var/lib/ontap_restore/restore.db", ROOT + "/etc/ontap_restore"
PORTAL_ETC, PORTAL_DATA = ROOT + "/etc/ops-portal", ROOT + "/var/lib/ops-portal"
PORTAL_DB = os.path.join(PORTAL_DATA, "portal.db")
SERVICE_USER = os.environ.get("MIGRATE_OWNER", "opsportal")
OLD_KNOWN_HOSTS = ROOT + "/var/lib/ontap_restore/.ssh/known_hosts"


def chown(path, user, group):
    if not ROOT:   # a test run (MIGRATE_ROOT) keeps the owner of the files
        shutil.chown(path, user, group)


def say(text):
    print(f"   {text}", flush=True)


def read_ro(path):
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    return db


def env_value(path, name):
    for line in open(path, encoding="utf-8"):
        if line.startswith(f"{name}="):
            return line.split("=", 1)[1].strip().strip('"')
    return ""


def install(path, text=None, src=None, mode=0o640, group=SERVICE_USER):
    """Write a file (text or a copy of src) owned by root:<service group>."""
    tmp = path + ".new"
    if src:
        shutil.copyfile(src, tmp)
    else:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(text)
    os.chmod(tmp, mode)
    chown(tmp, "root", group)
    os.replace(tmp, path)


def fingerprint(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()[:16]


# ------------------------------------------------------------------------------------------------- configuration
def config(args):
    os.makedirs(os.path.join(PORTAL_ETC, "keys"), exist_ok=True)
    os.makedirs(os.path.join(PORTAL_ETC, "tls"), exist_ok=True)
    os.chmod(os.path.join(PORTAL_ETC, "tls"), 0o700)
    chown(os.path.join(PORTAL_ETC, "keys"), "root", SERVICE_USER)
    os.chmod(os.path.join(PORTAL_ETC, "keys"), 0o750)
    base = f"https://{args.hostname}:{args.port}"

    # sites.yml: ONTAP Restore sites + APIC of each site from ACI_SITES
    target = os.path.join(PORTAL_ETC, "sites.yml")
    if os.path.exists(target):
        say(f"kept {target}")
    else:
        old = yaml.safe_load(open(os.path.join(ONTAP_ETC, "sites.yml"))) or {}
        sites = old.get("sites") or {k: v for k, v in old.items() if isinstance(v, dict)}
        apic = {}
        for part in env_value(os.path.join(ACI_ETC, "aci-webui.env"), "ACI_SITES").split(","):
            name, _, host = part.partition("=")
            if name.strip() and host.strip():
                apic[name.strip()] = host.strip()
        for name, host in apic.items():
            sites.setdefault(name, {})["apic"] = {"host": host}
        for cfg in sites.values():
            mgmt = cfg.get("mgmt") or {}
            if mgmt.get("private_key"):
                mgmt["private_key"] = os.path.join(PORTAL_ETC, "keys", os.path.basename(mgmt["private_key"]))
        text = ("# Ops Portal sites (moved from ONTAP Restore sites.yml and the ACI_SITES of ACI Web UI on "
                f"{datetime.date.today()}).\n# Operation Automation settings per site (vcenter, nsxt, hosts, wi, vcd at the top level) "
                "are described in /opt/ops-portal/sites.example.yml.\n"
                + yaml.safe_dump({"sites": sites}, sort_keys=False, default_flow_style=False))
        install(target, text)
        say(f"created {target}: sites {', '.join(sites)}; APIC {', '.join(f'{k}={v}' for k, v in apic.items())}")

    # auth.yml: the one of ACI Web UI (port 8080), Duo redirects to the portal address, paths to /etc/ops-portal
    target = os.path.join(PORTAL_ETC, "auth.yml")
    aci_auth, ontap_auth = os.path.join(ACI_ETC, "auth.yml"), os.path.join(ONTAP_ETC, "auth.yml")
    a, o = yaml.safe_load(open(aci_auth)) or {}, yaml.safe_load(open(ontap_auth)) or {}

    def flat(d, p=""):
        out = {}
        for k, v in (d or {}).items():
            out.update(flat(v, f"{p}{k}.") if isinstance(v, dict) else {f"{p}{k}": v})
        return out
    fa, fo = flat(a), flat(o)
    differ = sorted(k for k in set(fa) | set(fo) if fa.get(k) != fo.get(k))
    say(f"auth.yml of ACI and ONTAP differ in: {', '.join(differ) or 'nothing'} (the ACI one is used)")
    for key in ("sso.redirect_uri", "duo.redirect_uri"):
        if fa.get(key):
            say(f"old {key} (ACI): {fa[key]}")
    if os.path.exists(target):
        say(f"kept {target}")
    else:
        section, lines = "", []
        for line in open(aci_auth, encoding="utf-8").read().splitlines():
            top = re.match(r"^([A-Za-z_]+):", line)
            if top:
                section = top.group(1)
            m = re.match(r"^(\s+redirect_uri:\s*)(\S.*)?$", line)
            if m and section in ("sso", "duo"):
                line = f'{m.group(1)}"{base}/auth/{section}/callback"'
            lines.append(line.replace("/etc/aci_webui/", "/etc/ops-portal/"))
        install(target, "\n".join(lines) + "\n")
        say(f"created {target}: Duo redirect {base}/auth/sso/callback and {base}/auth/duo/callback")
    admins = sorted(set(a.get("admins") or []) | set(o.get("admins") or []))
    say(f"administrators in auth.yml: {', '.join(admins) or '(none)'}")

    for name, src, mode in (("authproxy-ldap-ca.pem", os.path.join(ACI_ETC, "authproxy-ldap-ca.pem"), 0o644),
                            ("product_templates.json", os.path.join(ACI_ETC, "product_templates.json"), 0o644)):
        target = os.path.join(PORTAL_ETC, name)
        if os.path.exists(target):
            say(f"kept {target}")
        elif os.path.exists(src):
            install(target, src=src, mode=mode)
            say(f"copied {src} -> {target}")
    keys = os.path.join(ONTAP_ETC, "keys")
    for name in sorted(os.listdir(keys)) if os.path.isdir(keys) else []:
        target = os.path.join(PORTAL_ETC, "keys", name)
        if os.path.exists(target):
            say(f"kept {target}")
        else:
            install(target, src=os.path.join(keys, name), mode=0o640)
            say(f"copied SSH key {name} (fingerprint {fingerprint(target)})")
    known = OLD_KNOWN_HOSTS
    if os.path.exists(known):
        os.makedirs(os.path.join(PORTAL_DATA, ".ssh"), exist_ok=True)
        target = os.path.join(PORTAL_DATA, ".ssh", "known_hosts")
        if not os.path.exists(target):
            shutil.copyfile(known, target)
        for p in (os.path.join(PORTAL_DATA, ".ssh"), target):
            chown(p, SERVICE_USER, SERVICE_USER)
        os.chmod(os.path.join(PORTAL_DATA, ".ssh"), 0o700)
        os.chmod(target, 0o600)
        say("copied known_hosts of the management hosts")


# ------------------------------------------------------------------------------------------------- data
def columns(db, table):
    return [r[1] for r in db.execute(f"PRAGMA table_info({table})")]


def copy_rows(src, dst, src_table, dst_table):
    """Every row of src_table into dst_table (same ids: references between tables stay valid)."""
    cols = [c for c in columns(src, src_table) if c in columns(dst, dst_table)]
    rows = src.execute(f"SELECT {', '.join(cols)} FROM {src_table} ORDER BY id").fetchall()
    dst.executemany(f"INSERT INTO {dst_table} ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
                    [tuple(r) for r in rows])
    return len(rows)


def data(args):
    if not os.path.exists(PORTAL_DB):
        sys.exit(f"{PORTAL_DB} does not exist: start the portal once so it creates its tables.")
    aci, ontap = read_ro(ACI_DB), read_ro(ONTAP_DB)
    p = sqlite3.connect(PORTAL_DB)
    p.row_factory = sqlite3.Row
    used = {t: p.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            for t in ("portal_users", "portal_local_users", "service_credentials", "aci_audit", "restores", "deletions")}
    if any(used.values()):
        sys.exit(f"{PORTAL_DB} is not empty ({used}); the migration only fills a new database.")
    now = datetime.datetime.now().astimezone().isoformat(timespec="seconds")

    # users: one row per AD account, modules from the app(s) the account was in
    users = {}
    for source, module in ((aci, "aci"), (ontap, "ontap")):
        for r in source.execute("SELECT * FROM portal_users"):
            u = users.setdefault(r["username"].lower(), {"username": r["username"].lower(), "role": "operator", "display_name": "",
                                                          "enabled": 0, "created": r["created"], "created_by": r["created_by"],
                                                          "last_login": None, "modules": set()})
            u["modules"].add(module)
            if r["role"] == "admin":
                u["role"] = "admin"
            u["display_name"] = u["display_name"] or (r["display_name"] or "")
            u["enabled"] = max(u["enabled"], int(r["enabled"] or 0))
            if r["created"] and r["created"] < u["created"]:
                u["created"], u["created_by"] = r["created"], r["created_by"]
            u["last_login"] = max(filter(None, [u["last_login"], r["last_login"]]), default=None)
    for name in args.admin or []:
        if name.lower() in users:
            users[name.lower()]["role"] = "admin"
    for u in users.values():
        if args.wi_for_all:
            u["modules"].add("wi")
        u["modules"] = "*" if u["role"] == "admin" else ",".join(sorted(u["modules"]))
    p.executemany("INSERT INTO portal_users (username, role, display_name, enabled, created, created_by, last_login, modules) "
                  "VALUES (:username, :role, :display_name, :enabled, :created, :created_by, :last_login, :modules)",
                  sorted(users.values(), key=lambda u: u["username"]))
    admins = sorted(u["username"] for u in users.values() if u["role"] == "admin")
    say(f"users: {len(users)} ({len(admins)} admin: {', '.join(admins)})")
    for module in ("aci", "ontap", "wi"):
        n = sum(1 for u in users.values() if u["modules"] == "*" or module in u["modules"].split(","))
        say(f"  module {module}: {n} users")

    # local accounts: the same name in both apps -> the most recently changed password
    local = {}
    for source in (aci, ontap):
        for r in source.execute("SELECT * FROM portal_local_users"):
            old = local.get(r["username"])
            if old is None or (r["password_changed"] or "") > (old["password_changed"] or ""):
                local[r["username"]] = dict(r)
    same = {}
    for name in local:
        hashes = {row["password_hash"] for src in (aci, ontap) for row in src.execute(
            "SELECT password_hash FROM portal_local_users WHERE username = ?", (name,))}
        same[name] = len(hashes) == 1
    cols = [c for c in columns(p, "portal_local_users") if c != "modules"]
    p.executemany(f"INSERT INTO portal_local_users ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
                  [tuple(r.get(c) for c in cols) for r in local.values()])
    for name, r in local.items():
        say(f"local account {name} ({r['role']}): " + ("same password in both apps" if same[name] else
            f"different passwords in the two apps: the one changed last ({r['password_changed']}) is kept"))

    # service accounts: decrypt with the old key, encrypt with the portal key
    portal_key = Fernet(open(os.path.join(PORTAL_ETC, "credentials.key"), "rb").read().strip())
    n = 0
    for source, key_file in ((aci, os.path.join(ACI_ETC, "credentials.key")), (ontap, os.path.join(ONTAP_ETC, "credentials.key"))):
        old_key = Fernet(open(key_file, "rb").read().strip())
        for r in source.execute("SELECT * FROM service_credentials ORDER BY name"):
            secret = portal_key.encrypt(old_key.decrypt(r["secret"].encode())).decode()
            p.execute("INSERT INTO service_credentials (name, username, secret, updated, updated_by) VALUES (?, ?, ?, ?, ?)",
                      (r["name"], r["username"], secret, r["updated"], r["updated_by"]))
            say(f"service account {r['name']} ({r['username']}) moved")
            n += 1

    # activity of both apps, in time order
    events = [("aci", r) for r in aci.execute("SELECT * FROM portal_events")] + [("ontap", r) for r in ontap.execute("SELECT * FROM portal_events")]
    events.sort(key=lambda e: e[1]["ts"])
    p.executemany("INSERT INTO portal_events (ts, actor, action, target, detail, client_ip) VALUES (?, ?, ?, ?, ?, ?)",
                  [(r["ts"], r["actor"], r["action"], r["target"], (f"[{m}] " + (r["detail"] or "")).strip(), r["client_ip"])
                   for m, r in events])
    p.execute("INSERT INTO portal_events (ts, actor, action, target, detail, client_ip) VALUES (?, ?, ?, ?, ?, ?)",
              (now, os.environ.get("SUDO_USER") or "root", "portal.migrated", "aci_webui, ontap_restore",
               f"{len(users)} users, {n} service accounts moved into the Ops Portal", ""))
    say(f"activity: {len(events)} events")

    say(f"ACI changes: {copy_rows(aci, p, 'audit', 'aci_audit')}")
    for table in ("restore_groups", "restores", "deletions"):
        say(f"ONTAP {table}: {copy_rows(ontap, p, table, table)}")
    p.commit()
    chown(PORTAL_DB, SERVICE_USER, SERVICE_USER)


def check(args):
    p = read_ro(PORTAL_DB)
    for t in ("portal_users", "portal_local_users", "service_credentials", "portal_events", "aci_audit", "restores",
              "restore_groups", "deletions"):
        say(f"{t}: {p.execute(f'SELECT COUNT(*) FROM {t}').fetchone()[0]}")
    key = Fernet(open(os.path.join(PORTAL_ETC, "credentials.key"), "rb").read().strip())
    bad = 0
    for r in p.execute("SELECT name, secret FROM service_credentials ORDER BY name"):
        try:
            key.decrypt(r["secret"].encode())
            say(f"service account {r['name']}: decrypts OK")
        except Exception:
            bad += 1
            say(f"service account {r['name']}: FAILED to decrypt")
    if bad:
        sys.exit(1)


if __name__ == "__main__":
    if os.geteuid() != 0 and not ROOT:
        sys.exit("Run as root (sudo).")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("config")
    c.add_argument("--hostname", required=True)
    c.add_argument("--port", default="8080")
    d = sub.add_parser("data")
    d.add_argument("--admin", action="append")
    d.add_argument("--wi-for-all", action="store_true")
    sub.add_parser("check")
    a = ap.parse_args()
    {"config": config, "data": data, "check": check}[a.cmd](a)

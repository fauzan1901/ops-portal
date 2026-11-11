#!/usr/bin/env python3
"""Adds an OpenStack site (management host + director) to the portal's sites.yml, run by the operator on the bastion:

    sudo python3 ~/sites-add-openstack.py DEV --mgmt 172.26.115.101 --director 172.26.115.100 \\
         --key /etc/ops-portal/keys/openstack_dev                    # shows the change only
    sudo python3 ~/sites-add-openstack.py ... --apply                     # writes it (backup sites.yml.bak-<time> first)

Options: --user (SSH user on the management host, default admin), --director-user (default stack), --timezone
(default +07:00). The site is appended at the end of the `sites:` mapping; nothing else of the file changes (comments
and order stay). A site that already exists is never changed. The result must still be valid YAML with the new site
exactly as given, otherwise the backup is put back. The portal reads sites.yml again by itself (no restart): the site
shows in the site tabs, and Shell lists <site>:mgmt and <site>:director (the director is reached FROM the management
host with ssh <director-user>@<director>, as for the other sites). The key file is only checked (it must exist and
be readable by the portal), never read or printed.
"""
import argparse
import datetime
import difflib
import grp
import ipaddress
import os
import pwd
import re
import shutil
import stat
import sys

import yaml

PATH = os.environ.get("SITES_FILE") or "/etc/ops-portal/sites.yml"   # SITES_FILE: a copy, for a try
OPS_USER = "opsportal"


def args():
    p = argparse.ArgumentParser(description="Add an OpenStack site to sites.yml")
    p.add_argument("site")
    p.add_argument("--mgmt", required=True)
    p.add_argument("--director", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--user", default="admin")
    p.add_argument("--director-user", default="stack")
    p.add_argument("--timezone", default="+07:00")
    p.add_argument("--apply", action="store_true")
    a = p.parse_args()
    if not re.fullmatch(r"[A-Z][A-Z0-9_-]{1,15}", a.site):
        sys.exit(f"{a.site}: a site name is 2-16 capitals, digits, _ or - (e.g. DEV)")
    for name in ("mgmt", "director"):
        try:
            ipaddress.ip_address(getattr(a, name))
        except ValueError:
            sys.exit(f"--{name} {getattr(a, name)}: not an IP address")
    for name in ("user", "director_user"):
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", getattr(a, name)):
            sys.exit(f"--{name.replace('_', '-')} {getattr(a, name)}: not a user name")
    if not re.fullmatch(r"/[A-Za-z0-9_./-]+", a.key) or ".." in a.key:
        sys.exit(f"--key {a.key}: an absolute path of a key file")
    if not re.fullmatch(r"[+-]\d{2}:\d{2}", a.timezone):
        sys.exit(f"--timezone {a.timezone}: e.g. +07:00")
    return a


def block(a, indent):
    want = {"timezone": a.timezone,
            "mgmt": {"host": a.mgmt, "user": a.user, "port": 22, "private_key": a.key},
            "director": {"host": a.director, "user": a.director_user, "overcloudrc": "~/overcloudrc"}}
    text = (f"\n{indent}{a.site}:\n"
            f"{indent}  timezone: \"{a.timezone}\"\n"
            f"{indent}  mgmt: {{host: \"{a.mgmt}\", user: {a.user}, port: 22, private_key: {a.key}}}\n"
            f"{indent}  director: {{host: \"{a.director}\", user: {a.director_user}, overcloudrc: \"~/overcloudrc\"}}\n")
    return text, want


def plan(text, a):
    data = yaml.safe_load(text) or {}
    sites = data.get("sites") if isinstance(data, dict) else None
    if not isinstance(sites, dict):
        sys.exit(f"{PATH}: no 'sites:' mapping")
    if a.site in sites:
        sys.exit(f"{a.site} is already in {PATH}: nothing changed (edit it by hand if it must change)")
    lines = text.splitlines(keepends=True)
    start = next((i for i, l in enumerate(lines) if re.match(r"^sites:\s*(#.*)?$", l)), None)
    if start is None:
        sys.exit(f"{PATH}: 'sites:' is not a block mapping")
    end, indent = len(lines), None
    for i in range(start + 1, len(lines)):
        line = lines[i]
        if re.match(r"^\S", line) and not line.startswith("#"):
            end = i   # the next top-level key
            break
        m = re.match(r"^(\s+)[A-Za-z0-9_-]+:", line)
        if m and indent is None:
            indent = m.group(1)
    while end > start + 1 and not lines[end - 1].strip():   # after the last site, before blank lines
        end -= 1
    new_block, want = block(a, indent or "  ")
    if lines[end - 1:end] and not lines[end - 1].endswith("\n"):
        lines[end - 1] += "\n"
    return "".join(lines[:end]) + new_block + "".join(lines[end:]), want


def check(text, a, want):
    data = yaml.safe_load(text)
    got = data["sites"].get(a.site)
    return "" if got == want else f"{a.site} reads as {got!r}"


def key_note(path):
    """The key file must exist and be readable by the portal (owner opsportal, mode 600): checked, never read."""
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return f"WARNING: {path} does not exist: Shell cannot open {path} until it is there."
    except PermissionError:
        return f"WARNING: {path} cannot be checked (run with sudo)."
    owner = pwd.getpwuid(st.st_uid).pw_name
    group = grp.getgrgid(st.st_gid).gr_name
    mode = stat.S_IMODE(st.st_mode)
    readable = owner == OPS_USER or (group == OPS_USER and mode & 0o040)
    note = f"key {path}: {owner}:{group} {mode:o}"
    if not readable:
        note += f" -- WARNING: the portal ({OPS_USER}) cannot read it: sudo chown {OPS_USER}:{OPS_USER} {path} && sudo chmod 600 {path}"
    elif mode & 0o077 and owner == OPS_USER:
        note += f" -- ssh refuses a key others can read: sudo chmod 600 {path}"
    return note


def main():
    a = args()
    with open(PATH, encoding="utf-8") as f:
        text = f.read()
    new, want = plan(text, a)
    sys.stdout.writelines(difflib.unified_diff(text.splitlines(True), new.splitlines(True), PATH, PATH + " (new)"))
    print("\n" + key_note(a.key))
    problem = check(new, a, want)
    if problem:
        sys.exit(f"Not written, the result is not right: {problem}")
    if not a.apply:
        print("\nOnly shown. Write it with --apply at the end.")
        return
    backup = f"{PATH}.bak-{datetime.datetime.now():%Y%m%d-%H%M%S}"
    shutil.copy2(PATH, backup)
    with open(PATH, "w", encoding="utf-8") as f:   # same file: owner and mode stay
        f.write(new)
    with open(PATH, encoding="utf-8") as f:
        try:
            problem = check(f.read(), a, want)
        except yaml.YAMLError as e:
            problem = str(e)
    if problem:
        shutil.copy2(backup, PATH)
        sys.exit(f"The written file was not right ({problem}): {backup} put back.")
    print(f"\nWritten. Backup: {backup}. The portal reads sites.yml again by itself: {a.site} is in the site tabs, and Shell "
          f"lists {a.site}:mgmt and {a.site}:director.")


if __name__ == "__main__":
    main()

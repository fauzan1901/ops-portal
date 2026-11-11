#!/usr/bin/env python3
"""Adds the Nessus scanner of every site to the portal's sites.yml (key tenable), run by the operator on the bastion:

    sudo python3 ~/nessus-sites-tenable.py            # shows the change only
    sudo python3 ~/nessus-sites-tenable.py --apply    # writes it (backup sites.yml.bak-<time> first)

Only one line is inserted right under each site name; nothing else of the file changes (comments and order stay). A site
that already has a tenable key is left as it is. The result must still be valid YAML with the scanners in place,
otherwise the backup is put back. The portal reads sites.yml again by itself (no restart).
"""
import datetime
import difflib
import os
import re
import shutil
import sys

import yaml

PATH = os.environ.get("SITES_FILE") or "/etc/ops-portal/sites.yml"   # SITES_FILE: a copy, for a try
# Linked scanners of Tenable (Settings -> Sensors -> Linked Scanners), 10 Nov 2026; networks are added later, once checked
TENABLE = {
    "DCB": '{scanner: "tenable-scanner-dcb", groups: ["SG-DCB"]}',
    "DCA": '{scanner: "tenable-scanner-dca"}',
    "DCC": '{scanner: "tenable-scanner-dcc"}',
}


def plan(text):
    """The new text and what was done per site."""
    lines = text.splitlines(keepends=True)
    data = yaml.safe_load(text) or {}
    sites = data.get("sites") if isinstance(data, dict) else None
    if not isinstance(sites, dict):
        sys.exit(f"{PATH}: no 'sites:' mapping")
    done, out, in_sites = {}, [], False
    for i, line in enumerate(lines):
        out.append(line)
        if re.match(r"^sites:\s*(#.*)?$", line):
            in_sites = True
            continue
        if in_sites and re.match(r"^\S", line) and not line.startswith("#"):
            in_sites = False   # the next top-level key
        m = re.match(r"^(\s+)([A-Za-z0-9_-]+):\s*(#.*)?$", line) if in_sites else None
        if not m or m.group(2) not in TENABLE or m.group(2) in done:
            continue
        site = m.group(2)
        if not isinstance(sites.get(site), dict):
            done[site] = "skipped: not a mapping in sites.yml"
        elif "tenable" in sites[site]:
            done[site] = "already has tenable: left as it is"
        else:
            child = re.match(r"^(\s+)\S", next((l for l in lines[i + 1:] if l.strip() and not l.lstrip().startswith("#")), m.group(1) + "  x"))
            indent = child.group(1) if child and len(child.group(1)) > len(m.group(1)) else m.group(1) + "  "
            out.append(f"{indent}tenable: {TENABLE[site]}\n")
            done[site] = "added"
    for site in TENABLE:
        done.setdefault(site, "not in sites.yml")
    return "".join(out), done


def check(text):
    data = yaml.safe_load(text)
    for site, value in TENABLE.items():
        got = (data["sites"].get(site) or {}).get("tenable") if isinstance(data["sites"].get(site), dict) else None
        want = yaml.safe_load(value)
        if got is not None and got != want and site in data["sites"]:
            return f"{site}: tenable is {got!r}"
    return ""


def main():
    apply = "--apply" in sys.argv[1:]
    with open(PATH, encoding="utf-8") as f:
        text = f.read()
    new, done = plan(text)
    for site, what in done.items():
        print(f"{site}: {what}")
    if new == text:
        print("Nothing to change.")
        return
    sys.stdout.writelines(difflib.unified_diff(text.splitlines(True), new.splitlines(True), PATH, PATH + " (new)"))
    problem = check(new)
    if problem:
        sys.exit(f"Not written, the result is not right: {problem}")
    if not apply:
        print("\nOnly shown. Write it with: sudo python3 " + os.path.abspath(sys.argv[0]) + " --apply")
        return
    backup = f"{PATH}.bak-{datetime.datetime.now():%Y%m%d-%H%M%S}"
    shutil.copy2(PATH, backup)
    with open(PATH, "w", encoding="utf-8") as f:   # same file: owner and mode stay
        f.write(new)
    with open(PATH, encoding="utf-8") as f:
        try:
            problem = check(f.read())
        except yaml.YAMLError as e:
            problem = str(e)
    if problem:
        shutil.copy2(backup, PATH)
        sys.exit(f"The written file was not right ({problem}): {backup} put back.")
    print(f"\nWritten. Backup: {backup}. The portal reads sites.yml again by itself.")


if __name__ == "__main__":
    main()

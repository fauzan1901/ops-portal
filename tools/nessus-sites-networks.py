#!/usr/bin/env python3
"""Sets the management networks of a site (sites.yml tenable.networks) for the portal's Nessus module, run by the
operator on the bastion:

    sudo python3 ~/nessus-sites-networks.py DCB 172.26.32.0/24,172.26.112.0/23,172.26.252.0/24            # shows it
    sudo python3 ~/nessus-sites-networks.py DCB 172.26.32.0/24,172.26.112.0/23,172.26.252.0/24 --apply    # writes it
    (several sites at once: DCB <networks> DCA <networks> ...)

Only the one-line `tenable: {...}` of each site named changes (tools/nessus-sites-tenable.py wrote it): its networks
are set to exactly these (replaced when it had some); comments, order and every other key stay. Only private IPv4
networks (10/8, 172.16/12, 192.168/16) are accepted: the scanners scan management networks only. The result must
still be valid YAML with these networks, otherwise the backup (sites.yml.bak-<time>) is put back. The portal reads
sites.yml again by itself (no restart): a scan whose targets are all inside them can then be launched, also every new
scan made in Tenable later.
"""
import datetime
import difflib
import ipaddress
import os
import re
import shutil
import sys

import yaml

PATH = os.environ.get("SITES_FILE") or "/etc/ops-portal/sites.yml"   # SITES_FILE: a copy, for a try


def networks(text):
    out = []
    for x in re.split(r"[\s,]+", text.strip()):
        if not x:
            continue
        try:
            n = ipaddress.ip_network(x, strict=False)
        except ValueError:
            sys.exit(f"{x}: not a network (e.g. 172.26.32.0/24)")
        if n.version != 4 or not n.is_private:
            sys.exit(f"{x}: only private IPv4 management networks are accepted")
        if str(n) not in out:
            out.append(str(n))
    if not out:
        sys.exit("No network given")
    return out


def plan(text, wanted):
    """The new text and what was done per site."""
    data = yaml.safe_load(text) or {}
    sites = data.get("sites") if isinstance(data, dict) else None
    if not isinstance(sites, dict):
        sys.exit(f"{PATH}: no 'sites:' mapping")
    lines = text.splitlines(keepends=True)
    done, site, in_sites, site_indent = {}, None, False, None
    for i, line in enumerate(lines):
        if re.match(r"^sites:\s*(#.*)?$", line):
            in_sites = True
            continue
        if in_sites and re.match(r"^\S", line) and not line.startswith("#"):
            in_sites, site = False, None
        if not in_sites:
            continue
        m = re.match(r"^(\s+)([A-Za-z0-9_-]+):\s*(#.*)?$", line)
        if m and (site_indent is None or len(m.group(1)) <= site_indent):
            site, site_indent = m.group(2), len(m.group(1))
            continue
        t = re.match(r"^(\s+)tenable:\s*\{(.*)\}\s*(#.*)?$", line)
        if not t or site not in wanted or site in done or len(t.group(1)) <= (site_indent or 0):
            continue
        body = re.sub(r",?\s*networks:\s*\[[^\]]*\]", "", t.group(2)).strip().rstrip(",")
        nets = ", ".join(f'"{n}"' for n in wanted[site])
        lines[i] = f"{t.group(1)}tenable: {{{body}{', ' if body else ''}networks: [{nets}]}}" + (f"  {t.group(3)}" if t.group(3) else "") + "\n"
        done[site] = "networks set"
    for s in wanted:
        if s not in done:
            done[s] = ("not in sites.yml" if s not in sites else
                       "has no one-line tenable: {...} (add the scanner first: nessus-sites-tenable.py)")
    return "".join(lines), done


def check(text, wanted):
    data = yaml.safe_load(text)
    for s, nets in wanted.items():
        got = ((data["sites"].get(s) or {}).get("tenable") or {}).get("networks") if isinstance(data["sites"].get(s), dict) else None
        if got is not None and got != nets:
            return f"{s}: tenable.networks is {got!r}"
    return ""


def main():
    args = [a for a in sys.argv[1:] if a != "--apply"]
    if not args or len(args) % 2:
        sys.exit(__doc__)
    wanted = {args[k].upper(): networks(args[k + 1]) for k in range(0, len(args), 2)}
    with open(PATH, encoding="utf-8") as f:
        text = f.read()
    new, done = plan(text, wanted)
    for s, what in done.items():
        print(f"{s}: {what}")
    if new == text:
        print("Nothing to change.")
        return
    sys.stdout.writelines(difflib.unified_diff(text.splitlines(True), new.splitlines(True), PATH, PATH + " (new)"))
    problem = check(new, wanted)
    if problem:
        sys.exit(f"Not written, the result is not right: {problem}")
    if "--apply" not in sys.argv[1:]:
        print("\nOnly shown. Write it with --apply at the end.")
        return
    backup = f"{PATH}.bak-{datetime.datetime.now():%Y%m%d-%H%M%S}"
    shutil.copy2(PATH, backup)
    with open(PATH, "w", encoding="utf-8") as f:   # same file: owner and mode stay
        f.write(new)
    with open(PATH, encoding="utf-8") as f:
        try:
            problem = check(f.read(), wanted)
        except yaml.YAMLError as e:
            problem = str(e)
    if problem:
        shutil.copy2(backup, PATH)
        sys.exit(f"The written file was not right ({problem}): {backup} put back.")
    print(f"\nWritten. Backup: {backup}. The portal reads sites.yml again by itself: press Refresh on Nessus → Scans.")


if __name__ == "__main__":
    main()

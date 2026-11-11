#!/usr/bin/env python3
"""Add openstack settings of one site to sites.yml when they are missing; existing values are never changed.

    sudo /opt/ops-portal/.venv/bin/python site-settings.py /etc/ops-portal/sites.yml DCA overcommit_ratio=2 \
        "hidden_volume_types=[premium, standard]"

Only the lines of that site are edited (comments and the layout of the rest stay), in the style the site already uses:
`openstack: {...}` on one line, an indented `openstack:` block, or a new `openstack: {...}` line. The result is read back
as YAML before it is written: every other site and every other key must be unchanged. A backup is kept next to the file.
"""
import datetime
import re
import shutil
import sys

import yaml


def flow(value):
    """A value in YAML flow style, as the rest of sites.yml writes it: 2, [premium, standard]."""
    return yaml.safe_dump(value, default_flow_style=True, width=1000).strip().removesuffix("...").strip()


def site_block(lines, site):
    """(first, end) line numbers of the site's block under `sites:` (end is exclusive, without trailing blank lines)."""
    start = next((i for i, line in enumerate(lines) if re.match(rf"^([ \t]+){re.escape(site)}:[ \t]*(#.*)?\r?\n?$", line)), None)
    if start is None:
        raise SystemExit(f"   Site {site} is not in sites.yml; nothing changed.")
    indent = len(lines[start]) - len(lines[start].lstrip())
    end = start + 1
    while end < len(lines):
        text = lines[end]
        if text.strip() and not text.lstrip().startswith("#") and len(text) - len(text.lstrip()) <= indent:
            break
        end += 1
    while end > start + 1 and not lines[end - 1].strip():
        end -= 1
    return start, end, indent


def add_settings(text, site, wanted):
    """New text with the missing keys of wanted added to sites.<site>.openstack, and the list of keys added."""
    data = yaml.safe_load(text) or {}
    current = ((data.get("sites") or {}).get(site) or {})
    have = current.get("openstack") or {}
    missing = {k: v for k, v in wanted.items() if k not in have}
    if not missing:
        return text, []
    lines = text.splitlines(keepends=True)
    start, end, indent = site_block(lines, site)
    item = ", ".join(f"{k}: {flow(v)}" for k, v in missing.items())
    for i in range(start + 1, end):
        one_line = re.match(r"^([ \t]+openstack:[ \t]*\{)(.*?)(\}[ \t]*)(#.*)?(\r?\n)?$", lines[i])
        if one_line:
            head, inner, close, comment, newline = one_line.groups()
            inner = inner.strip()
            lines[i] = f"{head}{inner + ', ' if inner else ''}{item}{close.rstrip()}{' ' + comment if comment else ''}{newline or ''}"
            break
        block = re.match(r"^([ \t]+)openstack:[ \t]*(#.*)?(\r?\n)?$", lines[i])
        if block:
            child = next((len(lines[j]) - len(lines[j].lstrip()) for j in range(i + 1, end) if lines[j].strip()
                          and not lines[j].lstrip().startswith("#")), len(block.group(1)) + 2)
            lines[i + 1:i + 1] = [f"{' ' * child}{k}: {flow(v)}\n" for k, v in missing.items()]
            break
    else:
        pad = " " * (indent + 2)
        if not lines[end - 1].endswith("\n"):
            lines[end - 1] += "\n"
        lines.insert(end, f"{pad}openstack: {{{item}}}\n")
    new_text = "".join(lines)
    # Read back: only these keys of this site may differ.
    new = yaml.safe_load(new_text) or {}
    expected = yaml.safe_load(text) or {}
    expected["sites"][site] = dict(expected["sites"][site] or {})
    expected["sites"][site]["openstack"] = {**have, **missing}
    if new != expected:
        raise SystemExit("   The edited sites.yml does not read back as expected; nothing changed. Edit it by hand.")
    return new_text, list(missing)


def main(argv):
    if len(argv) < 4:
        raise SystemExit(__doc__)
    path, site = argv[1], argv[2]
    wanted = {}
    for arg in argv[3:]:
        key, _, value = arg.partition("=")
        if not re.fullmatch(r"[a-z_]+", key) or not value:
            raise SystemExit(f"Invalid setting: {arg} (key=value)")
        wanted[key] = yaml.safe_load(value)
    with open(path, encoding="utf-8") as f:
        text = f.read()
    new_text, added = add_settings(text, site, wanted)
    have = ((yaml.safe_load(text) or {}).get("sites") or {}).get(site, {}).get("openstack") or {}
    for key in wanted:
        if key not in added:
            print(f"   {site}: {key} is already set ({flow(have.get(key))}); not changed.")
    if not added:
        return
    backup = f"{path}.bak-{datetime.datetime.now():%Y%m%d-%H%M%S}"
    shutil.copy2(path, backup)
    with open(path, "w", encoding="utf-8") as f:   # same file: owner and mode stay
        f.write(new_text)
    print(f"   {site}: added {', '.join(f'{k}: {flow(wanted[k])}' for k in added)} (backup {backup})")


if __name__ == "__main__":
    main(sys.argv)

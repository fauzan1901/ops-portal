"""Which site a scan and a finding belong to, and the hard rule of this module: the Nessus scanners scan only the
management networks of their site.

sites.yml, per site (optional):
    tenable: {scanner: "<name of the linked Nessus scanner in Tenable>", groups: ["<scanner group>"], networks: [...]}
  scanner    a scan belongs to the site whose scanner is the scan's info.scanner_name (any case)
  groups     scanner groups of that scanner (Sensors -> Scanner Groups): a scan run by a group names the group there
  networks   the management networks the scanner of this site may scan; a finding belongs to the site whose network
             holds its asset.ipv4 (the longest prefix when networks of two sites overlap), else to no site ("Other")

The portal launches a scan only when every one of its targets is provably inside the networks of the scan's site: an
address, a network or a range outside them (even partly), a host name (it cannot be checked before the scanner resolves
it), a scan without a target list (target groups, tags) and a scan of a scanner that is no site's are refused, for
administrators too. A Verify fix scans exactly one IPv4 address inside those networks (alt_targets).
"""
import ipaddress
import re

import sites

MAX_LISTED = 10   # offending targets named in a message
# Targets of a Tenable scan besides its address list (info of GET /scans/{id}): the portal cannot see which hosts they
# hold, so a scan that has any of them is never launched from the portal.
OTHER_TARGETS = {"tag_targets": "asset tags", "target_groups": "target groups", "file_targets": "a target file",
                 "asset_lists": "asset lists", "target_list_uuids": "target lists"}


def other_targets(info):
    """The kinds of targets of a scan the portal cannot check, e.g. ["asset tags"]."""
    info = info if isinstance(info, dict) else {}
    return [label for key, label in OTHER_TARGETS.items() if info.get(key) not in (None, "", [], {}, 0)]


def config():
    """{site: {"scanner": str, "networks": [ip_network], "problems": [str]}} for every site of sites.yml, in file order."""
    out = {}
    for name, cfg in sites.sites().items():
        t = cfg.get("tenable") if isinstance(cfg, dict) else None
        t = t if isinstance(t, dict) else {}
        nets, problems = [], []
        raw = t.get("networks") or []
        for value in raw if isinstance(raw, list) else [raw]:
            try:
                nets.append(ipaddress.ip_network(str(value).strip(), strict=False))
            except ValueError:
                problems.append(f"{name}: tenable.networks entry {str(value)[:60]!r} is not a network (e.g. 10.248.0.0/24)")
        groups = t.get("groups") or []
        groups = [str(g).strip() for g in (groups if isinstance(groups, list) else [groups]) if str(g).strip()]
        out[name] = {"scanner": str(t.get("scanner") or "").strip(), "groups": groups, "networks": nets, "problems": problems}
    return out


def fingerprint(cfg=None):
    """Changes when a site's networks change (the stored findings are mapped to their sites again)."""
    cfg = config() if cfg is None else cfg
    return ";".join(f"{s}={','.join(sorted(str(n) for n in c['networks']))}" for s, c in cfg.items())


def site_of_scanner(scanner_name, cfg=None):
    name = str(scanner_name or "").strip().lower()
    if not name:
        return ""
    cfg = config() if cfg is None else cfg
    return next((s for s, c in cfg.items()
                 if name in {n.lower() for n in [c["scanner"], *c.get("groups", [])] if n}), "")


def network_of_ip(ip, cfg=None):
    """(site, network) whose management network holds this address (longest prefix; equal ones: the first in sites.yml),
    ("", "") when none does."""
    try:
        addr = ipaddress.ip_address(str(ip or "").strip())
    except ValueError:
        return "", ""
    cfg = config() if cfg is None else cfg
    best, found, length = "", "", -1
    for site, c in cfg.items():
        for net in c["networks"]:
            if net.version == addr.version and addr in net and net.prefixlen > length:
                best, found, length = site, str(net), net.prefixlen
    return best, found


def site_of_ip(ip, cfg=None):
    """The site whose management network holds this address (longest prefix; equal ones: the first in sites.yml)."""
    return network_of_ip(ip, cfg)[0]


def scanner_stamp(cfg=None):
    """Changes when a site's scanner or scanner groups change (findings placed by their scanner move)."""
    cfg = config() if cfg is None else cfg
    return ";".join(f"{s}={c['scanner']}/{','.join(c.get('groups') or [])}" for s, c in cfg.items())


def guess_scanners(site, names):
    """Scanner (group) names of Tenable with the site name as a word ("tenable-scanner-dcb", "SG-DCB" for DCB): only a
    suggestion for a site that names no scanner yet; findings are never placed by a guess."""
    want = str(site or "").lower()
    return sorted({n for n in names if n and want in re.split(r"[^a-z0-9]+", n.lower())}, key=str.lower)


def parse_targets(text):
    """The targets of a scan (comma, space or line separated) as [{"text", "kind": ip|network|range|name, "blocks"}];
    blocks are the networks an entry covers (a range is split into aligned networks)."""
    out = []
    for item in re.split(r"[\s,;]+", str(text or "").strip()):
        if not item:
            continue
        entry = {"text": item, "kind": "name", "blocks": []}
        try:
            if "-" in item:
                first, _, last = item.partition("-")
                start = ipaddress.ip_address(first.strip())
                if "." not in last and ":" not in last and start.version == 4:   # 10.253.128.1-20: the last octet
                    end = ipaddress.ip_address(".".join(str(start).split(".")[:3] + [str(int(last))]))
                else:
                    end = ipaddress.ip_address(last.strip())
                if end.version != start.version or end < start:
                    raise ValueError(item)
                entry.update(kind="range", blocks=list(ipaddress.summarize_address_range(start, end)))
            elif "/" in item:
                entry.update(kind="network", blocks=[ipaddress.ip_network(item, strict=False)])
            else:
                entry.update(kind="ip", blocks=[ipaddress.ip_network(ipaddress.ip_address(item))])
        except ValueError:
            entry.update(kind="name", blocks=[])   # a host name (or anything that is not an address): cannot be checked
        out.append(entry)
    return out


def _inside(blocks, nets):
    """Every block inside the networks: networks next to each other are joined first, so a block that spans two of
    them counts as inside (collapse_addresses merges aligned neighbours, so a covered block is a subnet of one)."""
    joined = {4: list(ipaddress.collapse_addresses([n for n in nets if n.version == 4])),
              6: list(ipaddress.collapse_addresses([n for n in nets if n.version == 6]))}
    return bool(blocks) and all(any(b.subnet_of(n) for n in joined[b.version]) for b in blocks)


def _overlaps(blocks, nets):
    return any(b.version == n.version and b.overlaps(n) for b in blocks for n in nets)


def networks_text(nets):
    return ", ".join(str(n) for n in nets) or "none"


def proposals(items, cfg=None):
    """What sites.yml lacks for the scans Tenable has, for a person to add (the portal never applies it): per site whose
    scans are not all inside its management networks, their private IPv4 targets outside them, exactly as the scans
    name them (an address stays one address; a public address is never proposed): {site: {"scanner", "networks",
    "scans"}}; and the scanners of scans of no site with the site their name suggests: {"": {"scanners": {name: site}}}.
    Once tenable.networks is in sites.yml (read again by itself), a new scan of those networks can be launched at once."""
    cfg = config() if cfg is None else cfg
    out = {}
    for site, c in cfg.items():
        blocks, n = [], 0
        for i in items:
            if i.get("site") != site:
                continue
            new = [b for e in parse_targets(i.get("targets")) for b in e["blocks"]
                   if b.version == 4 and b.is_private and not _inside([b], c["networks"])]
            n += bool(new)
            blocks += new
        if blocks:
            out[site] = {"scanner": c["scanner"] or next((i["scanner"] for i in items if i.get("site") == site), ""),
                         "networks": [str(b) for b in ipaddress.collapse_addresses(blocks)], "scans": n}
    loose = sorted({i["scanner"] for i in items if i.get("scanner") and not i.get("site")}, key=str.lower)
    guess = {name: next((s for s in cfg if name in guess_scanners(s, [name])), "") for name in loose}
    if guess:
        out[""] = {"scanners": guess}
    return out


def check_scan(site, targets_text, cfg=None, scanner="", other=()):
    """May the portal launch a scan of this site with these targets? {"ok", "reason", "outside": [entries], "networks"}.
    other: kinds of targets besides the address list (other_targets()), which make the scan unlaunchable here."""
    cfg = config() if cfg is None else cfg
    nets = (cfg.get(site) or {}).get("networks") or [] if site else []
    result = {"ok": False, "reason": "", "outside": [], "networks": [str(n) for n in nets]}
    if not site:
        result["reason"] = (f"The scanner {scanner or '(none)'} of this scan is not the scanner of any site "
                            "(sites.yml tenable.scanner): the portal cannot tell which management networks it may scan.")
        return result
    if not nets:
        result["reason"] = (f"{site} has no management networks in sites.yml (tenable.networks): the portal launches a scan "
                            "only when every target is inside them.")
        return result
    if other:
        result["reason"] = (f"This scan also targets {', '.join(other)}, which the portal cannot check against the "
                            f"management networks of {site}: use address lists only to launch it here.")
        return result
    entries = parse_targets(targets_text)
    if not entries:
        result["reason"] = ("This scan has no target list the portal can check (target groups or asset tags): only a scan "
                            f"with addresses or networks inside the management networks of {site} can be launched here.")
        return result
    bad = []
    for e in entries:
        if e["kind"] == "name":
            bad.append(f"{e['text']} (a host name: cannot be checked)")
        elif not _inside(e["blocks"], nets):
            bad.append(f"{e['text']} ({'partly outside' if _overlaps(e['blocks'], nets) else 'outside'})")
    result["outside"] = bad
    if bad:
        more = f" and {len(bad) - MAX_LISTED} more" if len(bad) > MAX_LISTED else ""
        result["reason"] = (f"Targets outside the management networks of {site} ({networks_text(nets)}): "
                            f"{', '.join(bad[:MAX_LISTED])}{more}. The scanners scan only management networks.")
        return result
    result.update(ok=True, reason=f"Management networks of {site} only ({networks_text(nets)})")
    return result


def check_ip(site, ip, cfg=None):
    """A Verify fix: "" when ip is one IPv4 address inside the management networks of site, else the reason."""
    cfg = config() if cfg is None else cfg
    try:
        addr = ipaddress.IPv4Address(str(ip or "").strip())
    except ValueError:
        return "Enter one IPv4 address (a Verify fix scans exactly one host)."
    nets = (cfg.get(site) or {}).get("networks") or [] if site else []
    if not site:
        return "The scanner of this scan is not the scanner of any site (sites.yml tenable.scanner)."
    if not nets:
        return f"{site} has no management networks in sites.yml (tenable.networks)."
    if not _inside([ipaddress.ip_network(addr)], nets):
        return (f"{addr} is outside the management networks of {site} ({networks_text(nets)}): the scanners scan only "
                "management networks.")
    return ""

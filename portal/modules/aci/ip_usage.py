"""IP address usage of the EPG subnets (read-only): the IPs APIC learned on the client endpoints of each EPG (fvCEp /
fvIp, the "Client Endpoints" tab of an EPG in APIC), the gateways of its bridge domain (and EPG) subnets, and the
addresses that are free.

Only endpoints with an IP count: an EPG that only sees MAC addresses (layer 2, for example MPLS) has no learned IP and
is left out by default. An address is in use when APIC learned it on ANY endpoint of the fabric (several EPGs can share
one bridge domain), or when it is a gateway of the subnet. An address that is not learned now may still belong to a
silent or switched-off host, so every learned IP is also kept in the portal database (aci_ip_seen) with the time it
was last seen: a free address seen in the last RECENT_DAYS days is shown as "seen recently" and never suggested.
"""
import bisect
import collections
import csv
import datetime
import io
import ipaddress
import os
import re
import threading
import time

from . import aci, audit
from .report import safe_cell

RECENT_DAYS = int(os.environ.get("ACI_IP_RECENT_DAYS", "30"))
CACHE_SECONDS = 60
MAX_LISTED = 65536          # bigger subnets: counts and suggestions only, no list of free ranges
SUGGEST = 10
CEP_RE = re.compile(r"^(uni/tn-([^/]+)/ap-([^/]+)/epg-([^/]+))/cep-([^/]+)")
SCHEMA = """
CREATE TABLE IF NOT EXISTS aci_ip_seen (
    site TEXT NOT NULL,
    ip TEXT NOT NULL,
    epg_dn TEXT NOT NULL,
    mac TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    PRIMARY KEY (site, ip, epg_dn)
);
CREATE INDEX IF NOT EXISTS aci_ip_seen_ip ON aci_ip_seen (site, ip);
"""
_cache, _cache_lock = {}, threading.Lock()


def init():
    with audit._db() as conn:
        conn.executescript(SCHEMA)


# ---------------- APIC ----------------
def endpoints(api, site):
    """Every learned endpoint IP of the fabric: {ip: [{"epg_dn", "tenant", "app", "epg", "mac", "encap", "path",
    "source"}]}. Read with three class queries and kept CACHE_SECONDS per site."""
    with _cache_lock:
        hit = _cache.get(site)
        if hit and time.time() - hit[0] < CACHE_SECONDS:
            return hit[1]
    ceps = {a["dn"]: a for a in aci.attrs_of(aci.query_all(api, "/api/node/class/fvCEp.json"), "fvCEp")}
    paths = {}
    for a in aci.attrs_of(aci.query_all(api, "/api/node/class/fvRsCEpToPathEp.json"), "fvRsCEpToPathEp"):
        paths.setdefault(_parent(a["dn"]), a.get("tDn", ""))
    found = {}

    def add(ip, cep_dn):
        m = CEP_RE.match(cep_dn)
        cep = ceps.get(cep_dn, {})
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            return
        if not m or ip in ("0.0.0.0", "::"):
            return
        entry = {"epg_dn": m[1], "tenant": m[2], "app": m[3], "epg": m[4], "mac": cep.get("mac") or m[5],
                 "encap": cep.get("encap", ""), "path": paths.get(cep_dn, ""), "source": cep.get("lcC", "")}
        items = found.setdefault(ip, [])
        if not any(e["epg_dn"] == entry["epg_dn"] and e["mac"] == entry["mac"] for e in items):
            items.append(entry)

    for a in aci.attrs_of(aci.query_all(api, "/api/node/class/fvIp.json"), "fvIp"):
        add(a.get("addr", ""), _parent(a["dn"]))
    for dn, a in ceps.items():   # the primary IP of an endpoint, when APIC has no fvIp child for it
        if a.get("ip"):
            add(a["ip"], dn)
    record_seen(site, found)
    with _cache_lock:
        _cache[site] = (time.time(), found)
    return found


def _parent(dn):
    depth = 0
    for i in range(len(dn) - 1, -1, -1):
        if dn[i] == "]":
            depth += 1
        elif dn[i] == "[":
            depth -= 1
        elif dn[i] == "/" and depth == 0:
            return dn[:i]
    return ""


def subnets_of_epgs(api, tenant="", app="", epg=""):
    """[(epg_dn, tenant, app, epg, bd_dn, [subnet ip "11.8.158.1/24", ...])] of the EPGs in the filters. The subnets
    are those of the EPG's bridge domain (in its tenant, else in tenant common) and of the EPG itself."""
    prefix, exact = aci.report_scope(tenant, app, epg)
    if exact:
        path = f"/api/node/mo/{prefix}.json?query-target=self"
        epgs = aci.attrs_of(aci.query_all(api, path), "fvAEPg")
        rel_path = f"/api/node/mo/{prefix}.json?query-target=children&target-subtree-class=fvRsBd"
    elif prefix:
        scope_dn = prefix.rsplit("/", 1)[0]
        epgs = aci.attrs_of(aci.query_all(api, f"/api/node/mo/{scope_dn}.json?query-target=subtree&target-subtree-class=fvAEPg"), "fvAEPg")
        rel_path = f"/api/node/mo/{scope_dn}.json?query-target=subtree&target-subtree-class=fvRsBd"
    else:
        epgs = aci.attrs_of(aci.query_all(api, "/api/node/class/fvAEPg.json"), "fvAEPg")
        rel_path = "/api/node/class/fvRsBd.json"
    bd_of = {_parent(a["dn"]): a for a in aci.attrs_of(aci.query_all(api, rel_path), "fvRsBd")}
    subnets = {}
    for a in aci.attrs_of(aci.query_all(api, "/api/node/class/fvSubnet.json"), "fvSubnet"):
        subnets.setdefault(_parent(a["dn"]), []).append(a.get("ip", ""))
    out = []
    for e in epgs:
        m = aci.EPG_DN_RE.match(e.get("dn", ""))
        if not m:
            continue
        rel = bd_of.get(e["dn"], {})
        bd_dn = rel.get("tDn") or ""
        if not bd_dn and rel.get("tnFvBDName"):
            own = f"uni/tn-{m[1]}/BD-{rel['tnFvBDName']}"
            bd_dn = own if own in subnets or m[1] == "common" else f"uni/tn-common/BD-{rel['tnFvBDName']}"
            if bd_dn not in subnets:
                bd_dn = own
        out.append((e["dn"], m[1], m[2], m[3], bd_dn, subnets.get(bd_dn, []) + subnets.get(e["dn"], [])))
    return out


# ---------------- history of learned IPs ----------------
def record_seen(site, found):
    now = audit.now()
    rows = [(site, ip, e["epg_dn"], e["mac"], now, now) for ip, items in found.items() for e in items]
    if not rows:
        return
    with audit._write_lock, audit._db() as conn:
        conn.executemany("INSERT INTO aci_ip_seen (site, ip, epg_dn, mac, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?)"
                         " ON CONFLICT (site, ip, epg_dn) DO UPDATE SET mac = excluded.mac, last_seen = excluded.last_seen", rows)


def seen_since(site, days=RECENT_DAYS):
    """{ip: last time it was learned} for the IPs seen on this site in the last `days` days."""
    since = (datetime.datetime.now().astimezone() - datetime.timedelta(days=days)).isoformat(timespec="seconds")
    with audit._db() as conn:
        return {r["ip"]: r["last"] for r in conn.execute(
            "SELECT ip, max(last_seen) AS last FROM aci_ip_seen WHERE site = ? AND last_seen >= ? GROUP BY ip", (site, since))}


# ---------------- usage ----------------
def compact(addresses):
    """Sorted IPv4 addresses as ranges: 11.8.158.2-11.8.158.5, 11.8.158.9."""
    out, run = [], []
    for ip in sorted(addresses, key=int):
        if run and int(ip) == int(run[-1]) + 1:
            run.append(ip)
            continue
        if run:
            out.append(str(run[0]) if len(run) == 1 else f"{run[0]}-{run[-1]}")
        run = [ip]
    if run:
        out.append(str(run[0]) if len(run) == 1 else f"{run[0]}-{run[-1]}")
    return out


def scope_of(network):
    if network.version != 4:
        return "private" if network.is_private else "public"
    shared = ipaddress.ip_network("100.64.0.0/10")   # carrier-grade NAT: not public
    return "private" if network.is_private or network.subnet_of(shared) else "public"


def usage(api, site, tenant="", app="", epg=""):
    """One row per EPG and subnet in the filters: learned IPs of this EPG, gateways, free addresses (with the ones
    seen recently and suggestions), and the learned IPs of the EPG outside its subnets."""
    learned = endpoints(api, site)
    recent = seen_since(site)
    by_epg = collections.defaultdict(dict)   # epg dn -> {ip: [its endpoints with that IP]}
    for ip, items in learned.items():
        for e in items:
            by_epg[e["epg_dn"]].setdefault(ip, []).append(e)
    index = {"learned": _sorted_v4(learned), "recent": _sorted_v4(recent)}
    rows = []
    for epg_dn, tn, ap, name, bd_dn, subnet_ips in subnets_of_epgs(api, tenant, app, epg):
        mine = by_epg.get(epg_dn, {})
        networks = {}
        for value in subnet_ips:
            try:
                iface = ipaddress.ip_interface(value)
            except ValueError:
                continue
            networks.setdefault(iface.network, set()).add(iface.ip)
        covered = set()
        for network, gateways in sorted(networks.items(), key=lambda x: (x[0].version, x[0])):
            here = {ip: items for ip, items in mine.items() if ipaddress.ip_address(ip) in network}
            covered |= set(here)
            row = {"site": site, "tenant": tn, "app": ap, "epg": name, "epg_dn": epg_dn, "bd": bd_dn.rsplit("/BD-", 1)[-1],
                   "bd_dn": bd_dn, "subnet": str(network), "gateways": sorted(str(g) for g in gateways), "scope": scope_of(network),
                   "version": network.version, "learned": len(here), "endpoints": _endpoint_rows(here, recent)}
            row.update(_free(network, gateways, learned, index, epg_dn))
            rows.append(row)
        outside = {ip: items for ip, items in mine.items() if ip not in covered}
        if outside:
            scope = "public" if any(scope_of(ipaddress.ip_network(ip)) == "public" for ip in outside) else "private"
            rows.append({"site": site, "tenant": tn, "app": ap, "epg": name, "epg_dn": epg_dn, "bd": bd_dn.rsplit("/BD-", 1)[-1],
                         "bd_dn": bd_dn, "subnet": "", "gateways": [], "scope": scope, "version": 4, "learned": len(outside),
                         "endpoints": _endpoint_rows(outside, recent), "size": None, "free": None, "used_elsewhere": 0,
                         "seen_recently": [], "suggest": [], "free_ranges": [], "free_listed": False})
    rows.sort(key=lambda r: (r["tenant"], r["app"], r["epg"], r["version"], r["subnet"] == "",
                             ipaddress.ip_network(r["subnet"]) if r["subnet"] else ipaddress.ip_network("0.0.0.0/32")))
    return rows


def _endpoint_rows(here, recent):
    rows = []
    for ip, items in sorted(here.items(), key=lambda x: ipaddress.ip_address(x[0])):
        for e in items:
            rows.append({"ip": ip, "mac": e["mac"], "encap": e["encap"], "path": e["path"], "interface": interface(e["path"]),
                         "source": e["source"], "last_seen": recent.get(ip, "")})
    return rows


def interface(tdn):
    """topology/pod-1/protpaths-118-119/pathep-[VPC-25G-CLOUD-A-PG] -> Pod-1/Node-118-119/VPC-25G-CLOUD-A-PG, as APIC shows it."""
    m = re.match(r"^topology/pod-(\d+)/(?:paths|protpaths)-([\d-]+)(?:/ext(?:prot)?paths-([\d-]+))?/pathep-\[(.+)\]$", tdn or "")
    if not m:
        return tdn or ""
    return f"Pod-{m[1]}/Node-{m[2]}" + (f"/FEX-{m[3]}" if m[3] else "") + f"/{m[4]}"


def _sorted_v4(ips):
    """Sorted integer values of the IPv4 addresses among ips, for range lookups with bisect."""
    out = []
    for ip in ips:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if a.version == 4:
            out.append(int(a))
    return sorted(out)


def _within(values, network):
    lo, hi = int(network.network_address), int(network.broadcast_address)
    return [ipaddress.IPv4Address(v) for v in values[bisect.bisect_left(values, lo):bisect.bisect_right(values, hi)]]


def _free(network, gateways, learned, index, epg_dn):
    """Free addresses of an IPv4 subnet: not a gateway and learned on no endpoint of the fabric. The ones learned in the
    last RECENT_DAYS days are kept apart (seen recently) and never suggested."""
    if network.version != 4 or network.prefixlen >= 31:
        return {"size": network.num_addresses if network.version == 4 else None, "free": None, "used_elsewhere": 0,
                "seen_recently": [], "suggest": [], "free_ranges": [], "free_listed": False}
    size = network.num_addresses - 2
    used = set(_within(index["learned"], network))
    elsewhere = sum(1 for ip in used if not any(e["epg_dn"] == epg_dn for e in learned[str(ip)]))
    taken = used | {g for g in gateways if g in network}
    recently = [ip for ip in _within(index["recent"], network) if ip not in taken]
    free_count = size - len([t for t in taken if t != network.network_address and t != network.broadcast_address])
    listed = network.num_addresses <= MAX_LISTED
    recent_set = set(recently)
    suggest, free = [], []
    for ip in network.hosts():
        if ip in taken:
            continue
        if listed:
            free.append(ip)
        if ip not in recent_set and len(suggest) < SUGGEST:
            suggest.append(str(ip))
        if not listed and len(suggest) >= SUGGEST:
            break
    return {"size": size, "free": free_count, "used_elsewhere": elsewhere, "seen_recently": [str(ip) for ip in recently],
            "suggest": suggest, "free_ranges": compact(free) if listed else [], "free_listed": listed}


CSV_HEADER = ["Site", "Tenant", "Application Profile", "EPG", "Bridge Domain", "Subnet", "Scope", "Address", "Status", "MAC",
              "Encapsulation", "Interface", "Learning Source", "Last Seen (portal)"]


def to_csv(rows):
    """One line per learned IP, gateway, IP seen recently, and range of free addresses."""
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(CSV_HEADER)
    for r in rows:
        base = [r["site"], r["tenant"], r["app"], r["epg"], r["bd"], r["subnet"] or "(no subnet)", r["scope"]]
        for g in r["gateways"]:
            w.writerow([safe_cell(v) for v in base + [g, "gateway", "", "", "", "", ""]])
        for e in r["endpoints"]:
            w.writerow([safe_cell(v) for v in base + [e["ip"], "learned", e["mac"], e["encap"], e["interface"], e["source"], e["last_seen"]]])
        for ip in r["seen_recently"]:
            w.writerow([safe_cell(v) for v in base + [ip, "seen recently", "", "", "", "", ""]])
        for block in r["free_ranges"]:
            w.writerow([safe_cell(v) for v in base + [block, "free", "", "", "", "", ""]])
    return out.getvalue()

"""Built-in (default) static port templates per product (Acme Flex, Acme Prime, RHOSO) and per site.

Data source: product_templates.json (can be replaced through the env var ACI_TEMPLATES_FILE). The file is re-read on
every request. A template that a user changes through Fabric -> Templates is stored in the portal database
(template_store.py) and replaces the built-in template for that product & site; Reset to default goes back to this file.

Format of a template group:
    {"name": "...", "default": true, "pod": 1,
     "ports": [{"node": 111, "interfaces": "eth1/1-10, eth1/16-24"}],
     "vpcs":  [{"nodes": "109-110", "policy_groups": ["Openstack-Traffic-N-PG", ...]}]}
"""
import json
import os
import re

from . import aci

TEMPLATE_FILE = os.environ.get("ACI_TEMPLATES_FILE", os.path.join(os.path.dirname(os.path.abspath(__file__)), "product_templates.json"))
RANGE_RE = re.compile(r"^(.*/)(\d+)-(\d+)$")
NODES_RE = re.compile(r"^\d+-\d+$")
PRODUCT_ID_RE = re.compile(r"^[a-z0-9_-]{1,32}$")


def expand_interfaces(text):
    """'eth1/1-3, eth1/5, Po-Solarwinds' -> ['eth1/1', 'eth1/2', 'eth1/3', 'eth1/5', 'Po-Solarwinds']."""
    names = []
    for part in str(text or "").split(","):
        part = part.strip()
        if not part:
            continue
        match = RANGE_RE.match(part)
        if match:
            start, end = int(match.group(2)), int(match.group(3))
            if end < start:
                raise ValueError(f"Interface range is reversed: '{part}'")
            names += [f"{match.group(1)}{i}" for i in range(start, end + 1)]
        elif aci.INTERFACE_RE.match(part):
            names.append(part)
        else:
            raise ValueError(f"Invalid interface format: '{part}' (e.g. eth1/1-10)")
    return names


def group_paths(group):
    """All path TDNs in one template group."""
    pod = int(group.get("pod", 1))
    paths = []
    for port in group.get("ports", []):
        node = int(port["node"])
        paths += [f"topology/pod-{pod}/paths-{node}/pathep-[{name}]" for name in expand_interfaces(port["interfaces"])]
    for vpc in group.get("vpcs", []):
        nodes = str(vpc["nodes"]).strip()
        if not NODES_RE.match(nodes):
            raise ValueError(f"Invalid vPC node pair: '{nodes}' (e.g. 109-110)")
        paths += [f"topology/pod-{pod}/protpaths-{nodes}/pathep-[{pg}]" for pg in vpc["policy_groups"]]
    for tdn in paths:
        if not (aci.PHYSICAL_TDN_RE.match(tdn) or aci.VPC_TDN_RE.match(tdn)):
            raise ValueError(f"Invalid template path: '{tdn}'")
    if not paths:
        raise ValueError(f"Group '{group.get('name')}' has no ports or vPCs")
    return paths


def load(path=None):
    try:
        with open(path or TEMPLATE_FILE, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return {"products": {}, "sites": {}}
    except json.JSONDecodeError as e:
        raise ValueError(f"product_templates.json is invalid: {e}")
    for pid in data.get("products", {}):
        if not PRODUCT_ID_RE.match(pid):
            raise ValueError(f"Invalid product ID in product_templates.json: '{pid}'")
    return data


def for_site(site, path=None):
    """List of products with their path groups for one site; a product without a template on that site has empty groups."""
    data = load(path)
    site_templates = data.get("sites", {}).get(site, {})
    products = []
    for pid, meta in data.get("products", {}).items():
        groups = []
        for group in site_templates.get(pid, []):
            try:
                groups.append({"name": str(group["name"]), "default": bool(group.get("default", True)), "paths": group_paths(group)})
            except (KeyError, TypeError, ValueError) as e:
                raise ValueError(f"Template {pid}, site {site}, group '{group.get('name', '?')}': {e}")
        products.append({
            "id": pid,
            "label": meta.get("label", pid),
            "platform": meta.get("platform", ""),
            "mode": aci.MODES.get(meta.get("mode", "regular"), "regular"),
            "immediacy": meta.get("immediacy", "immediate") if meta.get("immediacy") in aci.IMMEDIACY else "immediate",
            "groups": groups,
        })
    return products

"""Sites (sites.yml), shared by every module and passed to the Ansible playbooks as -e @sites.yml.

Per site (DCB, DCA, DCC, ...), each module reads its own keys:
  apic                 ACI (host of the APIC)
  ontap, mgmt, director, openstack   ONTAP Restore and Operation Automation (OpenStack via management host -> director)
  vcenter, nsxt        Operation Automation (VMware), hosts only; the read-only accounts are entered on Administration -> Credentials
  hosts                Operation Automation: SSH groups (cdn, dns, vyos, ...) read with a key file, see sites.example.yml

Shared by every site (top level, next to sites:):
  vcd                  vCloud Director: one instance serves every site (one read-only account, ro-vcd)
"""
import os
import threading

import yaml

import settings

_lock = threading.Lock()
_cache = {"stamp": None, "sites": {}, "shared": {}}


def sites():
    """Sites from sites.yml, in file order. Re-read automatically when the file changes."""
    try:
        st = os.stat(settings.SITES_FILE)
        stamp = (st.st_mtime_ns, st.st_size)
    except OSError:
        return {}
    with _lock:
        if _cache["stamp"] != stamp:
            with open(settings.SITES_FILE, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            _cache.update(stamp=stamp, sites={str(k): v or {} for k, v in dict(data.get("sites") or {}).items()},
                          shared={str(k): v for k, v in data.items() if k != "sites" and isinstance(v, dict)})
        return _cache["sites"]


def shared(key):
    """A section of sites.yml shared by every site (top level, e.g. vcd); {} when absent."""
    sites()
    return dict(_cache["shared"].get(key) or {})


def get(name):
    """Configuration of one site; ValueError for an unknown site (the browser only ever sends a site name)."""
    all_sites = sites()
    if name not in all_sites:
        raise ValueError(f"Unknown site: {name!r}")
    return all_sites[name]

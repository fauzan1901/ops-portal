"""Service accounts Operation Automation reads with (Administration -> Credentials) and their connection tests.

Targets of this module, for every site; the administrator sets the address of the system with the account (the
address replaces the host in sites.yml, see site_config):
    ro-vcenter:<site>   vCenter (role Read-only)                    test: POST + DELETE /api/session
    ro-nsxt:<site>      NSX-T Manager (role Auditor)                test: GET /policy/api/v1/infra/tier-1s
    ro-vcd              vCloud Director provider (View-only role,   test: POST /cloudapi/1.0.0/sessions/provider,
                        user written user@System): ONE instance for   DELETE /cloudapi/1.0.0/sessions/current
                        every site
ONTAP is read with the ONTAP Restore account of the site (ontap:<site>, cluster ontap.host in sites.yml; only GET
requests here): no account of its own.
"""
import base64
import json
import ssl
import urllib.error
import urllib.request

import sites
from core import PORTAL

# (need in catalog.yml, key in sites.yml, label)
KINDS = (("ontap", "ontap", "ONTAP"), ("ro-vcenter", "vcenter", "vCenter read-only"),
         ("ro-nsxt", "nsxt", "NSX-T read-only"), ("ro-vcd", "vcd", "vCloud Director read-only"))
OWN = ("ro-vcenter", "ro-nsxt", "ro-vcd")   # accounts (and addresses) of this module on the Credentials page
VCD_API = "37.0"
SHARED = ("ro-vcd",)   # one system for every site: the account is named without a site


def credential_name(kind, site):
    if kind == "ontap":
        return f"ontap:{site}"   # the ONTAP Restore account of the site
    return kind if kind in SHARED else f"{kind}:{site}"


def site_config(site):
    """Configuration of a site for this module: sites.yml, the vCloud Director shared by every site (top level of
    sites.yml) unless the site names its own, and the addresses set on the Credentials page."""
    cfg = dict(sites.get(str(site or "")))
    if not cfg.get("vcd") and sites.shared("vcd"):
        cfg["vcd"] = sites.shared("vcd")
    for kind, key, _label in KINDS:
        if kind in OWN:
            address = PORTAL.address(credential_name(kind, site))
            if address:
                cfg[key] = dict(cfg.get(key) or {}, host=address)
    return cfg


def vcd_version(site_cfg):
    return str((site_cfg.get("vcd") or {}).get("api_version") or VCD_API)


def _target(kind, key, label, site, default_cfg):
    name = credential_name(kind, site)
    default = str((default_cfg.get(key) or {}).get("host") or "")
    target = {"name": name, "label": label + (f" {site}" if site else " (every site)"), "kind": kind, "site": site,
              "host": PORTAL.address(name) or default, "host_default": default, "address": True}
    if kind == "ro-vcd":
        target["username_suffix"] = "@System"   # provider accounts sign in as user@System
    return target


def targets():
    """vCenter and NSX-T of every site and the one vCloud Director, with or without an address yet."""
    out = []
    for site, cfg in sites.sites().items():
        out += [_target(kind, key, label, site, cfg) for kind, key, label in KINDS if kind in OWN and kind not in SHARED]
    out.append(_target("ro-vcd", "vcd", "vCloud Director read-only", "", {"vcd": sites.shared("vcd")}))
    return out


def config_of(target):
    """The configuration the test of a target uses: its site, or the shared vCloud Director."""
    if target["kind"] in SHARED:
        vcd = sites.shared("vcd")
        address = PORTAL.address(target["name"])
        return {"vcd": dict(vcd, host=address) if address else vcd}
    return site_config(target["site"])


def base_url(site_cfg, key):
    host = str((site_cfg.get(key) or {}).get("host") or "")
    return host if host.startswith("https://") else f"https://{host}"


def _request(url, method, username, password, verify, headers=None, timeout=15, want_headers=False):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    auth = {"Authorization": "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()} if username else {}
    req = urllib.request.Request(url, method=method, headers={**auth, "Accept": "application/json", **(headers or {})},
                                 data=b"" if method == "POST" else None)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read().decode() or "null"
            data = json.loads(body) if body.strip()[:1] in "[{\"" else body
            return (resp.status, data, dict(resp.headers)) if want_headers else (resp.status, data)
    except urllib.error.HTTPError as e:
        e.close()
        raise ValueError(f"HTTP {e.code} from {url.split('/')[2]}" + (" (wrong username or password)" if e.code == 401 else ""))
    except (urllib.error.URLError, OSError) as e:
        raise ValueError(f"{url.split('/')[2]} is not reachable: {getattr(e, 'reason', e)}")


def test(target, username, password):
    cfg = config_of(target)
    key = dict((k, v) for k, v, _ in KINDS)[target["kind"]]
    if not (cfg.get(key) or {}).get("host"):
        raise ValueError(f"Set the address of {target['label']} first")
    verify = bool((cfg.get(key) or {}).get("validate_certs", False))
    base = base_url(cfg, key)
    if target["kind"] == "ro-vcenter":
        _, token = _request(f"{base}/api/session", "POST", username, password, verify)
        try:
            _request(f"{base}/api/session", "DELETE", username, password, verify, {"vmware-api-session-id": str(token)})
        except ValueError:
            pass
        return "vCenter accepted the account (session opened and closed)"
    if target["kind"] == "ro-vcd":
        if "@" not in username:
            raise ValueError("Write the provider account as user@System")
        accept = {"Accept": f"application/json;version={vcd_version(cfg)}"}
        _, data, headers = _request(f"{base}/cloudapi/1.0.0/sessions/provider", "POST", username, password, verify, accept,
                                    want_headers=True)
        token = next((v for k, v in headers.items() if k.lower() == "x-vmware-vcloud-access-token"), "")
        if not token:
            raise ValueError("vCloud Director answered without an access token")
        try:
            _request(f"{base}/cloudapi/1.0.0/sessions/current", "DELETE", "", "", verify,
                     {**accept, "Authorization": f"Bearer {token}"})
        except ValueError:
            pass
        org = ((data or {}).get("org") or {}).get("name", "") if isinstance(data, dict) else ""
        return f"vCloud Director accepted the provider account{f' (organization {org})' if org else ''}; session closed"
    _, data = _request(f"{base}/policy/api/v1/infra/tier-1s", "GET", username, password, verify)
    count = len((data or {}).get("results") or []) if isinstance(data, dict) else 0
    return f"NSX-T Manager accepted the account ({count} Tier-1 gateway(s) visible)"

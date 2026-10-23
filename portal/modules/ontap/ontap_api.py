"""ONTAP REST calls made directly by the Web UI (read-only): the service account test on Settings -> Credentials and
the snapshot list. Every change (restore-file, cinder manage, transfer) is made by the Ansible playbooks.
"""
import base64
import json
import os
import re
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

from .config import RESTORE_SUFFIX

LOGIN_TIMEOUT = int(os.environ.get("ONTAP_LOGIN_TIMEOUT_SECONDS", "15"))
ZONE_RE = re.compile(r"^([+-])(\d{2}):?(\d{2})$")
# FlexVols from cloning/reclaim: not a Cinder pool, they hold LUN copies (same as the playbook filter lun_candidates).
IGNORE_FLEXVOL_REGEX = r"clone|reclaimed"
# ONTAP is always contacted directly; the http(s)_proxy variables of the server are ignored.
_NO_PROXY = urllib.request.ProxyHandler({})


class OntapError(RuntimeError):
    """ONTAP refused the request or cannot be reached."""


class OntapAuthError(OntapError):
    """ONTAP refused the username or password (HTTP 401)."""


class LunNotFound(ValueError):
    """There is no LUN volume-<id> in the ONTAP of this site."""


def call(site, user, password, path, timeout=30):
    ontap = site.get("ontap") or {}
    ctx = ssl.create_default_context() if ontap.get("validate_certs") else ssl._create_unverified_context()
    opener = urllib.request.build_opener(_NO_PROXY, urllib.request.HTTPSHandler(context=ctx))
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    req = urllib.request.Request(f"https://{ontap.get('host')}{path}",
                                 headers={"Authorization": f"Basic {token}", "Accept": "application/json"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        with e:
            if e.code == 401:
                raise OntapAuthError("wrong ONTAP username or password")
            try:
                message = json.loads(e.read().decode())["error"]["message"]
            except (ValueError, KeyError, TypeError):
                message = e.reason
            raise OntapError(f"ONTAP HTTP {e.code}: {message}")
    except Exception as e:
        raise OntapError(f"ONTAP {ontap.get('host')} is not reachable: {getattr(e, 'reason', e)}")


def cluster(site, user, password):
    data = call(site, user, password, "/api/cluster?fields=name,version", timeout=LOGIN_TIMEOUT)
    return {"name": data.get("name", ""), "version": (data.get("version") or {}).get("full", "")}


def _zone(offset):
    match = ZONE_RE.match(str(offset or "+07:00").strip())
    if not match:
        return timezone(timedelta(hours=7))
    delta = timedelta(hours=int(match.group(2)), minutes=int(match.group(3)))
    return timezone(delta if match.group(1) == "+" else -delta)


def _parse(value):
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def volume_snapshots(site, user, password, lun_id):
    """The LUN volume-<lun_id>, its FlexVol, and all snapshots of the FlexVol (newest first, with the local time of the
    site). lun_id is normally the OpenStack volume ID; for a volume that was migrated/retyped, its name_id."""
    found = call(site, user, password, f"/api/storage/luns?name=*volume-{lun_id}&fields=name,svm.name,location.volume.name,"
                 "location.volume.uuid,space.size,space.used,status.state,status.mapped&max_records=20").get("records") or []
    # Clone/reclaimed FlexVols (from cloning, not a Cinder pool) hold copies of the LUN with the same name: ignored.
    ignore = re.compile((site.get("ontap") or {}).get("ignore_flexvol_regex") or IGNORE_FLEXVOL_REGEX, re.IGNORECASE)
    found = [l for l in found if not ignore.search(((l.get("location") or {}).get("volume") or {}).get("name") or "")]
    if not found:
        raise LunNotFound(f"LUN volume-{lun_id} was not found in ONTAP. Check the volume ID and the site.")
    if len(found) > 1:
        raise ValueError("More than one LUN matches: " + ", ".join(l["name"] for l in found))
    lun = found[0]
    vol_uuid = lun["location"]["volume"]["uuid"]
    vol = call(site, user, password, f"/api/storage/volumes/{vol_uuid}?fields=name,state,space.available,space.size,svm.name")
    snaps = call(site, user, password, f"/api/storage/volumes/{vol_uuid}/snapshots?fields=name,create_time&max_records=5000").get("records") or []
    restore_path = lun["name"] + RESTORE_SUFFIX
    existing = call(site, user, password, f"/api/storage/luns?name={restore_path}&fields=name").get("num_records", 0)
    zone = _zone(site.get("timezone"))
    snapshots = [{"name": s["name"], "create_time": s["create_time"],
                  "local_time": _parse(s["create_time"]).astimezone(zone).strftime("%Y-%m-%d %H:%M"),
                  "schedule": s["name"].split(".", 1)[0] if "." in s["name"] else "manual"}
                 for s in sorted(snaps, key=lambda s: _parse(s["create_time"]), reverse=True)]
    space = lun.get("space") or {}
    return {
        "lun": {"name": lun["name"], "svm": lun["svm"]["name"], "flexvol": lun["location"]["volume"]["name"],
                "size": space.get("size"), "used": space.get("used", space.get("size")),
                "state": (lun.get("status") or {}).get("state"), "mapped": (lun.get("status") or {}).get("mapped")},
        "flexvol": {"name": vol.get("name"), "state": vol.get("state"),
                    "available": (vol.get("space") or {}).get("available"), "size": (vol.get("space") or {}).get("size")},
        "snapshots": snapshots,
        "restore_path": restore_path,
        "restore_path_exists": int(existing or 0) > 0,
    }

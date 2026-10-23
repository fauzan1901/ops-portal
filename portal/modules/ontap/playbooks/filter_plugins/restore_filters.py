"""Jinja filters for the restore playbooks: parse OpenStack CLI output and pick ONTAP snapshots."""
import ast
import json
import operator
import os
import re
import shlex
from datetime import datetime, timedelta, timezone

from ansible.errors import AnsibleFilterError

GIB = 1024 ** 3
UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
CINDER_ID_RE = re.compile(r"^\|\s*id\s*\|\s*(" + UUID + r")\s*\|", re.M)
ZONE_RE = re.compile(r"^([+-])(\d{2}):?(\d{2})$")


def extract_json(text):
    """First JSON object/array in command output; surrounding warning lines are ignored."""
    text = str(text or "")
    decoder = json.JSONDecoder()
    for i, ch in enumerate(text):
        if ch in "{[":
            try:
                return decoder.raw_decode(text[i:])[0]
            except ValueError:
                continue
    raise AnsibleFilterError("Output does not contain JSON: " + text.strip()[:300])


def cinder_table_id(text):
    """Volume ID from the `cinder manage` output table."""
    match = CINDER_ID_RE.search(str(text or ""))
    if not match:
        raise AnsibleFilterError("New volume ID not found in cinder manage output: " + str(text).strip()[:300])
    return match.group(1)


def _zone(offset):
    match = ZONE_RE.match(str(offset or "+00:00").strip())
    if not match:
        raise AnsibleFilterError(f"Invalid time zone: '{offset}' (example +07:00)")
    delta = timedelta(hours=int(match.group(2)), minutes=int(match.group(3)))
    return timezone(delta if match.group(1) == "+" else -delta)


def _parse(value):
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def snapshot_choices(snapshots, restore_time="", tz="+07:00"):
    """Snapshots newest first, with local time, plus a recommendation: the last snapshot created <= restore_time."""
    zone = _zone(tz)
    items = []
    for snap in snapshots or []:
        created = _parse(snap["create_time"])
        items.append({"name": snap["name"], "create_time": snap["create_time"],
                      "local_time": created.astimezone(zone).strftime("%Y-%m-%d %H:%M"), "_ts": created.timestamp()})
    items.sort(key=lambda s: s["_ts"], reverse=True)
    recommended = ""
    if str(restore_time or "").strip():
        text = str(restore_time).strip().replace("T", " ")[:16]
        try:
            target = datetime.strptime(text, "%Y-%m-%d %H:%M").replace(tzinfo=zone)
        except ValueError:
            raise AnsibleFilterError(f"Invalid restore time format: '{restore_time}' (example 2025-12-17 19:05)")
        recommended = next((s["name"] for s in items if s["_ts"] <= target.timestamp()), "")
    for snap in items:
        del snap["_ts"]
    return {"snapshots": items, "recommended": recommended}


NAME_ID_KEYS = ("os-vol-mig-status-attr:name_id", "name_id", "_name_id")
UUID_RE = re.compile("^" + UUID + "$")


def volume_name_id(volume):
    """Cinder name_id from `openstack volume show`: the ID used by the backend name (LUN volume-<name_id>) after the
    volume was migrated or retyped. Empty when absent, equal to the volume ID, or not a UUID."""
    if not isinstance(volume, dict):
        return ""
    volume_id = str(volume.get("id") or "").strip().lower()
    for key in NAME_ID_KEYS:
        value = str(volume.get(key) or "").strip().lower()
        if value and value != volume_id and UUID_RE.match(value):
            return value
    return ""


POOL_ROW_RE = re.compile(r"^\|\s*(.*?)\s*\|\s*(.*?)\s*\|\s*$")


def _cap_value(text):
    """Capability value from a cinder table: list/dict/bool/None become Python values, everything else stays text."""
    if text[:1] in "[{" or text in ("True", "False", "None"):
        try:
            return ast.literal_eval(text)
        except (ValueError, SyntaxError):
            pass
    return text


def cinder_pools(text):
    """`cinder get-pools --detail` table -> {pool name (host@backend#pool): capabilities}."""
    pools, current, last = {}, None, None
    for line in str(text or "").splitlines():
        match = POOL_ROW_RE.match(line)
        if not match:
            continue
        key, value = match.groups()
        if key == "Property" and value == "Value":
            current, last = {}, None
        elif current is not None and key:
            current[key] = value
            last = key
            if key == "name":
                pools[value] = current
        elif current is not None and last:   # long value continued on the next line
            current[last] += "\n" + value
    return {name: {k: _cap_value(v) for k, v in caps.items()} for name, caps in pools.items()}


def _bool_from_string(value):
    """Like oslo strutils.bool_from_string (anything other than a 'true' value is False)."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "t", "true", "on", "y", "yes")


# Extra spec operators, as in cinder/scheduler/filters/extra_specs_ops.py.
SPEC_OPS = {
    "=": lambda x, y: float(x) >= float(y),
    "<in>": lambda x, y: y in x,
    "<is>": lambda x, y: _bool_from_string(x) is _bool_from_string(y),
    "==": lambda x, y: float(x) == float(y),
    "!=": lambda x, y: float(x) != float(y),
    ">=": lambda x, y: float(x) >= float(y),
    "<=": lambda x, y: float(x) <= float(y),
    "s==": operator.eq, "s!=": operator.ne, "s<": operator.lt, "s<=": operator.le, "s>": operator.gt, "s>=": operator.ge,
}


def _spec_match(value, req):
    """Port of Cinder extra_specs_ops.match: a pool capability value against one extra spec requirement."""
    words = str(req).split()
    op = words.pop(0) if words else None
    method = SPEC_OPS.get(op)
    if op != "<or>" and not method:
        return value == req
    if value is None:
        return False
    if op == "<or>":   # <or> a <or> b
        while words:
            if words.pop(0) == value:
                return True
            if words:
                words.pop(0)
        return False
    if not words:
        return False
    try:
        return bool(method(value, words[0]))
    except (TypeError, ValueError):
        return False


def _type_mismatch(specs, caps):
    """Why the type fails the Cinder scheduler CapabilitiesFilter on this pool; '' when it passes.
    The scheduler runs this filter during cinder manage: a failing type leaves the volume in error_managing."""
    for key, req in specs.items():
        scope = key.split(":")
        if len(scope) > 1 and scope[0] != "capabilities":
            continue   # vendor extra spec (e.g. netapp:qos_policy_group) is used by the driver, not checked by the scheduler
        if scope[0] == "capabilities":
            scope = scope[1:]
        cap = caps
        for part in scope:
            if not isinstance(cap, dict) or part not in cap:
                return f"pool has no capability {key}"
            cap = cap[part]
        if not any(_spec_match(value, req) for value in (cap if isinstance(cap, list) else [cap])):
            if key == "volume_backend_name":
                return f"type is for backend {req}, LUN is on backend {cap}"
            return f"requirement {key}={req} does not match the pool ({cap})"
    return ""


def _type_specs(value):
    """Properties column of `openstack volume type list --long`: a dict (newer OSC) or text "k='v', k2='v2'" (older OSC)."""
    if isinstance(value, dict):
        return {str(k): str(v) for k, v in value.items()}
    return dict(re.findall(r"([^\s=,']+)='([^']*)'", str(value or "")))


FILTER_FUNCTION_RE = re.compile(r"^\s*capabilities\.utilization\s*<\s*([0-9.]+)\s*$")


def _filter_ok(caps):
    """Pool passes the NetApp driver's default filter_function ("capabilities.utilization < 70") when DriverFilter
    is enabled. Other forms are not evaluated (treated as passing); only used to pick the safest target FlexVol."""
    match = FILTER_FUNCTION_RE.match(str(caps.get("filter_function") or ""))
    try:
        return not match or float(caps.get("utilization")) < float(match.group(1))
    except (TypeError, ValueError):
        return True


MOVE_FLEXVOL_REGEX = r"^(?!.*test).*_[0-9]+(_vol)?$"   # lun move targets: numbered production pools (..._VOL_05, ..._12_vol)
IGNORE_FLEXVOL_REGEX = r"clone|reclaimed"   # cloned/reclaimed FlexVols: not Cinder pools, hold LUN copies
POOL_MAX_USED_PERCENT = 85


def _ignored(name, ignore_regex):
    return bool(re.search(ignore_regex or IGNORE_FLEXVOL_REGEX, str(name or ""), re.IGNORECASE))


def lun_candidates(records, cinder_pool="", ignore_regex=IGNORE_FLEXVOL_REGEX):
    """LUNs found by *volume-<id> that may belong to this Cinder volume. LUNs in clone/reclaimed FlexVols (copies with
    the same name, not Cinder pools) are ignored; if more than one remains, the one in the volume's Cinder pool wins."""
    luns = [l for l in records or [] if not _ignored(((l.get("location") or {}).get("volume") or {}).get("name"), ignore_regex)]
    in_pool = [l for l in luns if ((l.get("location") or {}).get("volume") or {}).get("name") == cinder_pool]
    return in_pool if len(luns) > 1 and in_pool else luns


def _number(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _natural(text):
    return [int(x) if x.isdigit() else x.lower() for x in re.split(r"(\d+)", str(text))]


def _pool_item(name, caps, current, flexvol, vols, svm, need, limit, allowed, ratio=1.0):
    """One Cinder pool with its capacity (Cinder get-pools, ONTAP FlexVol) and why it cannot take the volume ('' = it can).
    Used = what Cinder allocated on the pool against its capacity: total x the overcommit ratio of the site (1 = no
    overcommit). Without allocated_capacity_gb: total - free from Cinder, else the FlexVol space from ONTAP."""
    total, free = _number(caps.get("total_capacity_gb")), _number(caps.get("free_capacity_gb"))
    allocated = _number(caps.get("allocated_capacity_gb"))
    capacity = round(total * ratio, 1) if total else None
    vol = next((v for v in vols if (v.get("svm") or {}).get("name") == svm), None)
    shown = vol or (vols[0] if vols else None)   # for display: the FlexVol of that name even when it is in another SVM
    space = (shown or {}).get("space") or {}
    available, size = int(space.get("available") or 0), int(space.get("size") or 0)
    if capacity and allocated is not None:
        used_pct, basis = round(allocated / capacity * 100, 1), "allocated"
    elif total and free is not None:
        used_pct, basis = round(max(0.0, total - free) / total * 100, 1), "free"
    elif size:
        used_pct, basis = round(max(0, size - available) / size * 100, 1), "ontap"
    else:
        used_pct, basis = None, ""
    utilization = _number(caps.get("utilization"))
    item = {"host": name, "flexvol": flexvol, "backend": str(caps.get("volume_backend_name") or ""), "current": current,
            "test": not allowed.search(flexvol), "total_gb": total, "free_gb": free, "allocated_gb": allocated,
            "capacity_gb": capacity, "ratio": ratio, "basis": basis,
            "provisioned_gb": _number(caps.get("provisioned_capacity_gb")),
            "max_over_subscription_ratio": _number(caps.get("max_over_subscription_ratio")),
            "used_pct": used_pct, "utilization": utilization, "filter_ok": _filter_ok(caps),
            "svm": ((shown or {}).get("svm") or {}).get("name", ""), "state": (shown or {}).get("state", ""),
            "ontap_available": available, "ontap_size": size, "reason": ""}
    if not current and item["test"]:
        item["reason"] = "test or unnumbered pool, not a restore target"
    elif not vol:
        other = next((((v.get("svm") or {}).get("name")) for v in vols), None)
        item["reason"] = f"FlexVol is in another SVM ({other})" if other else "FlexVol could not be read from ONTAP"
    elif vol.get("state") != "online":
        item["reason"] = f"FlexVol is {vol.get('state') or 'not online'}"
    elif used_pct is not None and used_pct >= limit:
        item["reason"] = f"full: {used_pct:.1f}% used (limit {limit:g}%)"
    elif available < need:
        item["reason"] = f"not enough free space ({available / GIB:.1f} GiB free, the LUN has {need / GIB:.1f} GiB of data)"
    item["selectable"] = not item["reason"]
    return item


def _overcommit(value):
    ratio = _number(value)
    return ratio if ratio and ratio > 0 else 1.0


def pool_choices(types, pools_text, host, type_name="", flexvols=None, svm="", need_bytes=0,
                 max_used_percent=POOL_MAX_USED_PERCENT, flexvol_regex=MOVE_FLEXVOL_REGEX, ignore_regex=IGNORE_FLEXVOL_REGEX,
                 overcommit_ratio=1, original_type=None):
    """Cinder pools the restored volume can be managed into with volume type type_name, for the operator to pick one in
    Review (nothing is chosen automatically). With the original type (type_name == original_type, or original_type None):
    the backend of the LUN pool (the tier) and the Cinder CapabilitiesFilter rules of that type. With another type the
    operator chose: the backend (volume_backend_name) and rules of that type; the LUN pool is listed only when it
    fits that type. The pool of the LUN needs no lun move; another pool is reached with lun move (same SVM) before
    cinder manage.

    A pool can be picked when its FlexVol is in the SVM of the LUN and online, used below max_used_percent (Cinder
    total/free capacity; ONTAP when Cinder does not report it) and has need_bytes free (the used data of the LUN).
    Test/unnumbered pools (outside flexvol_regex, e.g. ..._VOL_TEST50) are listed but never a lun move target;
    clone/reclaimed FlexVols (ignore_regex) are not Cinder pools and are left out.
    When the pool capabilities cannot be read, only the pool of the LUN is offered.
    flexvols: ONTAP /api/storage/volumes records (name, svm.name, state, space.available, space.size).
    overcommit_ratio: Cinder capacity x this = what may be allocated on a pool (sites.yml openstack.overcommit_ratio)."""
    pools = cinder_pools(pools_text) if pools_text else {}
    current = pools.get(host)
    specs = {}
    for t in types or []:
        if type_name and type_name in (str(t.get("Name") or ""), str(t.get("ID") or "")):
            specs = _type_specs(t.get("Properties"))
    same_type = original_type is None or type_name == original_type
    backend = (str((current or {}).get("volume_backend_name") or specs.get("volume_backend_name") or "") if same_type
               else str(specs.get("volume_backend_name") or ""))
    allowed = re.compile(flexvol_regex or MOVE_FLEXVOL_REGEX, re.IGNORECASE)
    need, limit, ratio = int(need_bytes or 0), float(max_used_percent or POOL_MAX_USED_PERCENT), _overcommit(overcommit_ratio)
    by_name = {}
    for vol in flexvols or []:
        by_name.setdefault(vol.get("name"), []).append(vol)
    host_pool = str(host).split("#")[-1]
    items = []
    if current is None:
        if same_type:
            items.append(_pool_item(host, {}, True, host_pool, by_name.get(host_pool, []), svm, need, limit, allowed, ratio))
    else:
        for name, caps in pools.items():
            flexvol = str(caps.get("pool_name") or name.split("#")[-1])
            wrong_backend = (same_type or backend) and str(caps.get("volume_backend_name") or "") != backend
            if not (name == host and same_type) and (_ignored(flexvol, ignore_regex) or wrong_backend
                                                     or (specs and _type_mismatch(specs, caps))):
                continue
            items.append(_pool_item(name, caps, name == host, flexvol, by_name.get(flexvol, []), svm, need, limit, allowed, ratio))
    items.sort(key=lambda i: (not i["current"], _natural(i["flexvol"])))
    return {"host": host, "pool_found": current is not None, "type": type_name, "backend": backend, "same_type": same_type,
            "max_used_percent": limit, "overcommit_ratio": ratio, "selectable": sum(1 for i in items if i["selectable"]),
            "pools": items}


def type_choices(types, pools_text, host, original_type="", flexvols=None, svm="", need_bytes=0,
                 max_used_percent=POOL_MAX_USED_PERCENT, flexvol_regex=MOVE_FLEXVOL_REGEX, ignore_regex=IGNORE_FLEXVOL_REGEX,
                 overcommit_ratio=1, hidden=None):
    """Volume types the restored volume can get in Review, each with its pools (pool_choices): the original type first,
    then every other PUBLIC type that has a Cinder pool on this site passing its CapabilitiesFilter rules. Left out:
    private types, __DEFAULT__, and the types in hidden (sites.yml openstack.hidden_volume_types, per site: e.g. the old
    DCA types premium/standard "Dont use this volume type again", which are active types on DCB and DCC). The original
    type is always listed. A type whose pools are all unusable (another SVM, full, test pool) is listed with selectable
    0 so the operator sees why it cannot be chosen."""
    options, seen = [], set()
    hidden = {str(h) for h in hidden or []}
    for t in types or []:
        name = str(t.get("Name") or "")
        if not name or name in seen:
            continue
        original = name == original_type
        public = t.get("Is Public", True)
        public = public if isinstance(public, bool) else _bool_from_string(public)
        if not original and (name == "__DEFAULT__" or name in hidden or not public):
            continue
        choice = pool_choices(types, pools_text, host, name, flexvols, svm, need_bytes, max_used_percent, flexvol_regex,
                              ignore_regex, overcommit_ratio, original_type)
        if not original and not choice["pools"]:
            continue
        seen.add(name)
        options.append({"name": name, "id": str(t.get("ID") or ""), "description": str(t.get("Description") or ""),
                        "public": public, "original": original, "backend": choice["backend"],
                        "selectable": choice["selectable"], "pools": choice})
    if original_type not in seen:   # the type list could not be read: the original type with the pools of the LUN backend
        choice = pool_choices(types, pools_text, host, original_type, flexvols, svm, need_bytes, max_used_percent,
                              flexvol_regex, ignore_regex, overcommit_ratio, original_type)
        options.append({"name": original_type, "id": "", "description": "", "public": True, "original": True,
                        "backend": choice["backend"], "selectable": choice["selectable"], "pools": choice})
    options.sort(key=lambda o: (not o["original"], o["name"].lower()))
    return options


def pool_flexvols(pools_text, host, ignore_regex=IGNORE_FLEXVOL_REGEX):
    """FlexVol names of every Cinder pool (for one ONTAP query), the LUN pool included, clones/reclaimed left out."""
    names = [str(caps.get("pool_name") or name.split("#")[-1]) for name, caps in (cinder_pools(pools_text) if pools_text else {}).items()]
    names = [n for n in names if not _ignored(n, ignore_regex)] + [str(host).split("#")[-1]]
    return list(dict.fromkeys(names))


# ---------------- Batch: several OpenStack commands in one connection to the director ----------------
BATCH_MARK_RE = re.compile(r"\n?@@OSB rc=(\d+)@@\r?\n?")


PARALLEL_READS = 4   # read-only batch commands that run at the same time (sites.yml openstack.parallel_reads)


def parallel_width(value):
    """How many commands of a read-only batch run at the same time, from sites.yml openstack.parallel_reads: not set or
    true = 4, a number (at most 8), false/0/1 = one after the other. Anything else: one after the other."""
    if value is None or value == "":
        return PARALLEL_READS
    if isinstance(value, bool):
        return PARALLEL_READS if value else 1
    text = str(value).strip().lower()
    if text in ("true", "yes", "on"):
        return PARALLEL_READS
    try:
        return max(1, min(8, int(text)))
    except ValueError:
        return 1


def batch_script(commands, width=1):
    """Shell for tasks/openstack_batch.yml: every command in its own subshell (an export stays inside it), stderr with
    stdout, followed by a marker with its exit code.
    width > 1 (read-only batches only, see parallel_width): up to `width` commands at the same time, each writing its
    output and exit code to its own file in a private temporary folder (mktemp -d, mode 700, removed at the end); then
    the outputs are printed in the order of the commands, exactly as when they run one after the other. When no
    temporary folder can be made, the commands run one after the other."""
    cmds = [c["cmd"] if isinstance(c, dict) else str(c) for c in commands or []]
    if not cmds:
        return "true"
    sequential = " ".join(f"( {cmd} ) 2>&1; printf '\\n@@OSB rc=%s@@\\n' \"$?\";" for cmd in cmds)
    width = int(width or 1)
    if width <= 1 or len(cmds) == 1:
        return "{ " + sequential + " }"
    waves = []
    for start in range(0, len(cmds), width):
        jobs = [f"{{ ({cmd}) >\"$d/{i}\" 2>&1; echo $? >\"$d/{i}.rc\"; }} &" for i, cmd in enumerate(cmds[start:start + width], start)]
        waves.append(" ".join(jobs) + " wait;")
    show = (f"for i in {' '.join(str(i) for i in range(len(cmds)))}; do cat \"$d/$i\" 2>/dev/null; "
            "printf '\\n@@OSB rc=%s@@\\n' \"$(cat \"$d/$i.rc\" 2>/dev/null || echo 255)\"; done;")
    return ("{ if d=$(mktemp -d 2>/dev/null); then trap 'rm -rf \"$d\"' EXIT; " + " ".join(waves) + " " + show
            + " rm -rf \"$d\"; else " + sequential + " fi; }")


def batch_results(text, commands):
    """Output of openstack_batch.yml per command key: {'results': {key: {'rc', 'out', 'ok'}}, 'failed': [messages of
    required commands that failed], 'complete': every command ran}."""
    parts = BATCH_MARK_RE.split(str(text or ""))
    outputs = [(int(parts[i + 1]), parts[i]) for i in range(0, len(parts) - 1, 2)]
    results, failed = {}, []
    for index, c in enumerate(commands or []):
        c = c if isinstance(c, dict) else {"key": str(index), "cmd": str(c)}
        rc, out = outputs[index] if index < len(outputs) else (-1, "")
        results[c["key"]] = {"rc": rc, "out": out, "ok": rc == 0}
        if rc != 0 and not c.get("optional"):
            lines = [line.strip() for line in out.strip().splitlines() if line.strip()]
            failed.append(f"{c.get('label') or c['key']}: " + (" ".join(lines[-3:]) if lines else f"exit code {rc}")[:500])
    return {"results": results, "failed": failed, "complete": len(outputs) >= len(commands or [])}


def batch_json(entry, default=None):
    """JSON of one batch result, or default when the command failed or printed no JSON."""
    if not isinstance(entry, dict) or entry.get("rc") != 0:
        return default
    try:
        return extract_json(entry.get("out"))
    except AnsibleFilterError:
        return default


def show_commands(ids, resource, prefix, optional=True):
    """Batch commands `openstack <resource> show <id> -f json` for each unique ID, keyed <prefix><id>."""
    return [{"key": f"{prefix}{i}", "cmd": f"openstack {resource} show {shlex.quote(str(i))} -f json", "optional": optional}
            for i in dict.fromkeys(str(x) for x in ids or [] if str(x or "").strip())]


def batch_objects(osb, prefix):
    """{id: parsed JSON} of the batch results whose key starts with prefix (see show_commands); failed ones are left out."""
    found = {}
    for key, entry in ((osb or {}).get("results") or {}).items():
        if key.startswith(prefix):
            data = batch_json(entry)
            if isinstance(data, dict):
                found[key[len(prefix):]] = data
    return found


# ---------------- OpenStack CLI values (older OSC prints text, newer OSC lists/dicts) ----------------
KV_RE = re.compile(r"([A-Za-z0-9_:.-]+)='([^']*)'")
ROOT_DEVICE_RE = re.compile(r"^/dev/(v|s|xv|h)da$")
ATTACHABLE_STATUSES = ("ACTIVE", "SHUTOFF", "PAUSED", "SUSPENDED", "SHELVED", "SHELVED_OFFLOADED")


def _records(value, key="id"):
    """A list of dicts from a list, a dict, or OSC text such as "id='a'\nid='b'" or "ip_address='x', subnet_id='y'"."""
    if value is None or value == "":
        return []
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [v if isinstance(v, dict) else {key: str(v)} for v in value]
    text = str(value)
    if not KV_RE.search(text):
        return [{key: part.strip().strip("'\"")} for part in re.split(r"[,\n]", text) if part.strip()]
    records = []
    for line in text.splitlines():
        current = {}
        for k, v in KV_RE.findall(line):
            if k in current:
                records.append(current)
                current = {}
            current[k] = v
        if current:
            records.append(current)
    return records


def _ids(value):
    ids = []
    for r in _records(value):
        vid = str(r.get("id") or r.get("ID") or "").strip()
        if vid:
            ids.append(vid)
    return ids


def _addresses(value):
    """{network name: [IPs]} from a dict or OSC text "net-a=10.253.0.5, fd00::5; net-b=192.168.255.10"."""
    if isinstance(value, dict):
        return {str(k): [str(a.get("addr") if isinstance(a, dict) else a) for a in (v if isinstance(v, list) else [v])]
                for k, v in value.items()}
    result = {}
    for part in str(value or "").split(";"):
        if "=" in part:
            net, ips = part.split("=", 1)
            result[net.strip()] = [ip.strip() for ip in ips.split(",") if ip.strip()]
    return result


def _flavor_ref(value):
    """What `server show` tells about the flavor: a dict (compute API 2.47+: original_name, vcpus...; 2.1: id, links)
    or text "name (id)"."""
    if isinstance(value, dict):
        return {"id": str(value.get("id") or ""), "name": str(value.get("original_name") or value.get("name") or ""),
                "vcpus": value.get("vcpus"), "ram": value.get("ram"), "disk": value.get("disk")}
    match = re.match(r"^\s*(.*?)\s*\(([^()]+)\)\s*$", str(value or ""))
    return {"id": match.group(2), "name": match.group(1)} if match else {"id": "", "name": str(value or "").strip()}


def _flag(value, default=True):
    if value is None or value == "":
        return default
    return _bool_from_string(value)


def _props(value):
    """Properties (key -> text) from a dict or OSC text "k='v', k2='v2'"."""
    if isinstance(value, dict):
        return {str(k): str(v) for k, v in value.items() if v is not None and not isinstance(v, (dict, list))}
    return dict(KV_RE.findall(str(value or "")))


def flavor_ref(server):
    """Flavor ID (or name when the compute API only gives the name) of `openstack server show`, for `flavor show`."""
    ref = _flavor_ref((server or {}).get("flavor"))
    return ref["id"] or ref["name"]


def port_ids(rows):
    """IDs from `openstack port list -f json` rows."""
    return [str(r.get("ID") or r.get("id")) for r in rows or [] if r.get("ID") or r.get("id")]


def volume_attachment(volume):
    """[server_id, device] of the first attachment in `openstack volume show`, or ['', '']."""
    for att in _records((volume or {}).get("attachments"), "server_id"):
        if att.get("server_id"):
            return [str(att["server_id"]), str(att.get("device") or "")]
    return ["", ""]


def _is_root(device, root=""):
    return device == root if root else bool(ROOT_DEVICE_RE.match(str(device or "")))


def instance_summary(server, ports=None, port_details=None, flavor=None, networks=None, volume=None, server_volumes=None,
                     groups=None):
    """The instance a volume is attached to, as the wizard shows it and as a new instance copies it: flavor, network
    interfaces in order (network, subnets, IPs, MAC, security groups, port security, vNIC type), AZ, key pair,
    properties, and its volumes with their role (boot disk, or extended disk such as vdb).
    Inputs are parsed `-f json` outputs: server show, port list --server --long (rows), port show per port ID,
    flavor show, network show per network ID, server volume list (rows; optional), security group list (rows)."""
    server, port_details, networks, flavor = server or {}, port_details or {}, networks or {}, flavor or {}
    addresses = _addresses(server.get("addresses"))
    ref = _flavor_ref(server.get("flavor"))
    flavor_info = {"id": str(flavor.get("id") or ref["id"]), "name": str(flavor.get("name") or ref["name"]),
                   "vcpus": flavor.get("vcpus", ref.get("vcpus")), "ram_mb": flavor.get("ram", ref.get("ram")),
                   "disk_gb": flavor.get("disk", ref.get("disk")), "found": bool(flavor),
                   "public": _flag(flavor.get("os-flavor-access:is_public", flavor.get("is_public")), True)}
    group_names = {str(g.get("ID") or g.get("id")): str(g.get("Name") or g.get("name") or "") for g in groups or []}
    port_items = []
    for row in ports or []:
        pid = str(row.get("ID") or row.get("id") or "")
        detail = port_details.get(pid) or {}
        fixed = _records(detail.get("fixed_ips") or row.get("Fixed IP Addresses") or row.get("fixed_ips"), "ip_address")
        ips = [str(r.get("ip_address") or "") for r in fixed if r.get("ip_address")]
        subnets = list(dict.fromkeys(str(r.get("subnet_id")) for r in fixed if r.get("subnet_id")))
        net_id = str(detail.get("network_id") or "")
        net_name = str((networks.get(net_id) or {}).get("name") or "") or next(
            (name for name, addrs in addresses.items() if set(addrs) & set(ips)), "")
        sg_ids = _ids(detail.get("security_group_ids") if "security_group_ids" in detail else row.get("Security Groups"))
        port_items.append({"id": pid, "name": str(detail.get("name") or row.get("Name") or ""), "network_id": net_id,
                           "network_name": net_name, "subnet_ids": subnets, "ips": ips,
                           "mac": str(detail.get("mac_address") or row.get("MAC Address") or ""),
                           "security_group_ids": sg_ids, "security_groups": [group_names.get(g) or g for g in sg_ids],
                           "port_security": _flag(detail.get("port_security_enabled"), True),
                           "vnic_type": str(detail.get("binding_vnic_type") or detail.get("binding:vnic_type") or "normal")})
    image = server.get("image")
    booted_from_volume = (not image or (isinstance(image, str) and ("booted from volume" in image.lower() or image.strip() == "N/A"))
                          or (isinstance(image, dict) and not image.get("id")))
    root = str(server.get("OS-EXT-SRV-ATTR:root_device_name") or "")
    devices = {}
    for row in server_volumes or []:
        vid = str(row.get("Volume ID") or row.get("volumeId") or row.get("ID") or "")
        if vid:
            devices[vid] = str(row.get("Device") or row.get("device") or "")
    volume_id = str((volume or {}).get("id") or "")
    if volume_id:
        devices.setdefault(volume_id, volume_attachment(volume)[1])
    vols = []
    for vid in list(dict.fromkeys(_ids(server.get("volumes_attached")) + list(devices))):
        device = devices.get(vid, "")
        role = "" if not device else "boot" if booted_from_volume and _is_root(device, root) else "extended"
        vols.append({"id": vid, "device": device, "role": role, "this": vid == volume_id})
    vols.sort(key=lambda v: (v["device"] == "", v["device"]))
    return {"id": str(server.get("id") or ""), "name": str(server.get("name") or ""), "status": str(server.get("status") or ""),
            "project_id": str(server.get("project_id") or server.get("tenant_id") or ""),
            "availability_zone": str(server.get("OS-EXT-AZ:availability_zone") or ""),
            "host": str(server.get("OS-EXT-SRV-ATTR:host") or ""), "key_name": str(server.get("key_name") or ""),
            "created": str(server.get("created") or ""), "booted_from_volume": booted_from_volume,
            "image": "" if booted_from_volume else str(image.get("name") or image.get("id") if isinstance(image, dict) else image),
            "config_drive": _flag(server.get("config_drive"), False), "root_device": root, "flavor": flavor_info,
            "addresses": addresses, "properties": _props(server.get("properties") or server.get("metadata")),
            "security_groups": [str(r.get("name") or r.get("id") or "") for r in _records(server.get("security_groups"), "name")],
            "ports": port_items, "volumes": vols}


def volume_role(volume, instance=None):
    """How the volume is used: 'boot' (root disk of an instance booted from volume, e.g. vda), 'extended' (another disk
    such as vdb) or 'detached' (not attached), with the device and the instance ID."""
    server_id, device = volume_attachment(volume)
    if not server_id:
        return {"role": "detached", "device": "", "server_id": ""}
    instance = instance or {}
    boot = _is_root(device, instance.get("root_device") or "") and instance.get("booted_from_volume", True)
    return {"role": "boot" if boot else "extended", "device": device, "server_id": server_id}


def server_choices(servers, original_id=""):
    """Instances of the target project for "attach to an instance": rows of `openstack server list -f json`."""
    items = []
    for row in servers or []:
        sid = str(row.get("ID") or row.get("id") or "")
        status = str(row.get("Status") or row.get("status") or "")
        items.append({"id": sid, "name": str(row.get("Name") or row.get("name") or ""), "status": status,
                      "original": bool(original_id) and sid == original_id, "attachable": status.upper() in ATTACHABLE_STATUSES})
    items.sort(key=lambda i: i["name"].lower())
    return items


NAME_SAFE_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def instance_name(base, suffix="", limit=63):
    """Name for the new instance: letters, digits, _ . - only, starting with a letter or digit, at most `limit` long."""
    head = NAME_SAFE_RE.sub("-", str(base or "")).strip("-._") or "instance"
    tail = NAME_SAFE_RE.sub("-", str(suffix or "")).strip("-")
    tail = f"-{tail}" if tail else ""
    return head[:max(1, limit - len(tail))].rstrip("-._") + tail


def target_network_commands(project):
    """Batch commands that read the networks a new instance in `project` can use: the project's own networks (its VPCs)
    with their subnets, and the shared networks. All optional: without them the original networks are used as before."""
    q = shlex.quote(str(project))
    return [{"key": "tnets", "label": f"networks of project {project}", "cmd": f"openstack network list --project {q} --long -f json",
             "optional": True},
            {"key": "tsubnets", "label": f"subnets of project {project}", "cmd": f"openstack subnet list --project {q} --long -f json",
             "optional": True},
            {"key": "snets", "label": "shared networks", "cmd": "openstack network list --share --long -f json", "optional": True}]


def _row(row, *keys):
    """The first value of `keys` in an OSC -f json row (column titles differ between versions: "ID"/"id")."""
    for key in keys:
        if key in row and row[key] is not None:
            return row[key]
    return ""


def network_options(osb, project):
    """Networks of target_network_commands that a new instance in `project` can use, own networks (VPCs) first, then the
    shared ones: [{id, name, own, shared, external, status, up, subnets: [{id, name, cidr, ip_version}]}]. Subnets of
    shared networks belong to another project: only their IDs are known. read = False when the own networks could not
    be read; the original networks are then used as before."""
    results = (osb or {}).get("results") or {}
    own_rows = batch_json(results.get("tnets"), None)
    if not isinstance(own_rows, list):
        return {"read": False, "networks": []}
    subnets = {}
    for row in batch_json(results.get("tsubnets"), []) or []:
        sid = str(_row(row, "ID", "id"))
        if sid:
            subnets[sid] = {"id": sid, "name": str(_row(row, "Name", "name")), "cidr": str(_row(row, "Subnet", "cidr")),
                            "ip_version": str(_row(row, "IP Version", "ip_version"))}
    items = {}
    for rows, own in ((own_rows, True), (batch_json(results.get("snets"), []) or [], False)):
        for row in rows:
            nid = str(_row(row, "ID", "id"))
            if not nid or nid in items:
                continue
            owner = str(_row(row, "Project", "project_id", "tenant_id"))
            items[nid] = {"id": nid, "name": str(_row(row, "Name", "name")) or nid, "own": own or owner == str(project),
                          "shared": _flag(_row(row, "Shared", "shared"), False),
                          "external": str(_row(row, "Router Type", "router:external")).lower() in ("external", "true"),
                          "status": str(_row(row, "Status", "status")),
                          "up": str(_row(row, "State", "admin_state_up")).upper() not in ("DOWN", "FALSE"),
                          "subnets": [subnets.get(s) or {"id": s, "name": "", "cidr": "", "ip_version": ""}
                                      for s in _ids(_row(row, "Subnets", "subnets"))]}
    for item in items.values():
        item["subnets"].sort(key=lambda s: (s["ip_version"] != "4", _natural(s["name"] or s["cidr"] or s["id"])))
    ordered = sorted(items.values(), key=lambda n: (not n["own"], _natural(n["name"])))
    return {"read": True, "networks": ordered}


def new_instance_plan(instance, role, target_project, networks=None, name="", target_networks=None, choices=None, strict=False):
    """A new instance in the target project that boots from the restored volume, with the settings of the existing
    instance: flavor, AZ, properties, config drive, and one new port per original port (new IP addresses; the original
    keeps its own), with the same vNIC type.
    Network of every port: the original network when the target project can use it (its own network or a shared one),
    otherwise the only network of the target project, otherwise the operator chooses one in Review (target_networks =
    network_options; choices = [{network_id, subnet_id}] in port order). On the original network the port keeps the
    original subnets; on another network it gets the chosen subnet (default: the first IPv4 subnet).
    New ports always have port security on when they have an IP address, so the copy cannot use the addresses of the
    running original. Same project: the security groups of the original port; another project: its default group.
    strict (restore run): a port without a usable network is a reason instead of a choice left to the operator.
    possible = False with a reason when it cannot be done."""
    instance, networks = instance or {}, networks or {}
    reasons, warnings = [], []
    same_project = str(instance.get("project_id") or "") == str(target_project or "")
    known = target_networks if isinstance(target_networks, dict) and target_networks.get("read") else None
    options = (known or {}).get("networks") or []
    by_id = {n["id"]: n for n in options}
    own = [n for n in options if n.get("own")]
    choices = choices if isinstance(choices, list) else []
    if role != "boot":
        reasons.append("the volume is not the boot disk of an instance")
    flavor = instance.get("flavor") or {}
    if not flavor.get("id"):
        reasons.append("the flavor of the existing instance could not be read")
    elif not flavor.get("found"):
        reasons.append(f"flavor {flavor.get('name') or flavor.get('id')} no longer exists")
    elif not flavor.get("public", True) and not same_project:
        warnings.append(f"flavor {flavor.get('name')} is private: the target project must have access to it")
    ports = []
    for index, port in enumerate(instance.get("ports") or [], 1):
        nid = port.get("network_id")
        if not nid:
            reasons.append(f"the network of port {port.get('id')} could not be read")
            continue
        info = networks.get(nid) or {}
        label = port.get("network_name") or info.get("name") or nid
        if known is None:   # the networks of the target project are unknown: the original network, as before
            usable = True
            if not same_project and info and not _flag(info.get("shared"), False) \
                    and str(info.get("project_id") or info.get("tenant_id") or "") != str(target_project):
                warnings.append(f"network {label} belongs to another project and is not shared: creating its port fails "
                                "unless it is shared with the target project (RBAC)")
        else:
            usable = nid in by_id
        default = nid if usable else (own[0]["id"] if len(own) == 1 else "")
        choice = choices[index - 1] if index - 1 < len(choices) and isinstance(choices[index - 1], dict) else {}
        chosen = str(choice.get("network_id") or "").strip() or default
        wanted_subnet = str(choice.get("subnet_id") or "").strip()
        where = f"network interface {index} ({label})"
        subnet_ids, has_ip, problem = [], bool(port.get("ips")), ""
        if not chosen:
            if not options:
                problem = f"{where}: network {label} cannot be used in the target project, and the project has no network"
            elif strict:
                problem = f"{where}: choose a network of the target project"
        elif chosen == nid and usable:
            subnet_ids = port.get("subnet_ids") or []
            if wanted_subnet and wanted_subnet not in subnet_ids:
                problem = f"{where}: subnet {wanted_subnet} is not a subnet of the original port"
        elif chosen not in by_id:
            problem = f"{where}: network {chosen} is not a network of the target project or a shared network"
        else:
            subnets = by_id[chosen]["subnets"]
            has_ip = bool(subnets)
            if wanted_subnet:
                subnet_ids = [wanted_subnet] if wanted_subnet in [s["id"] for s in subnets] else []
                if not subnet_ids:
                    problem = f"{where}: subnet {wanted_subnet} is not on network {by_id[chosen]['name']}"
            else:   # the first IPv4 subnet; subnets of a shared network are unknown: OpenStack picks one
                subnet_ids = [s["id"] for s in subnets if s.get("ip_version") == "4"][:1]
        if problem:
            reasons.append(problem)
        normal = (port.get("vnic_type") or "normal") == "normal"
        security = has_ip and normal or (not normal and port.get("port_security", True))
        if not port.get("port_security", True) and security:
            warnings.append(f"port {index} ({label}): port security is off on the original port; the new port has it on "
                            "(anti-spoofing), with the security groups below")
        original_groups = [{"id": g, "name": n} for g, n in zip(port.get("security_group_ids") or [], port.get("security_groups") or [])]
        groups = original_groups if same_project and security else []
        on_original = chosen == nid
        ports.append({"index": index, "network_id": chosen,
                      "network_name": label if on_original else (by_id.get(chosen) or {}).get("name") or chosen,
                      "subnet_ids": subnet_ids, "original_network_id": nid, "original_network_name": label,
                      "original_subnet_ids": port.get("subnet_ids") or [], "original_usable": usable, "default_network_id": default,
                      "original_port_id": port.get("id") or "", "original_ips": port.get("ips") or [],
                      "original_port_security": port.get("port_security", True), "original_security_groups": original_groups,
                      "port_security": security, "security_groups": groups, "vnic_type": port.get("vnic_type") or "normal"})
    if not ports and not reasons:
        reasons.append("the existing instance has no network interface to copy")
    if not same_project:
        warnings.append("another project: the default security group of the target project is used")
    notes = ["new IP addresses; the existing instance keeps its own",
             "the new instance runs a copy of the original disk (same hostname, users and services): check that it "
             "does not clash with the running original, e.g. scheduled jobs or addresses configured inside the OS"]
    if instance.get("key_name"):
        notes.append(f"key pair {instance['key_name']} is not set again (key pairs belong to a user); the disk keeps its authorized keys")
    props = {k: v for k, v in (instance.get("properties") or {}).items() if re.match(r"^[A-Za-z0-9_.:-]{1,255}$", k) and len(v) <= 255}
    return {"possible": not reasons, "reason": "; ".join(dict.fromkeys(reasons)), "warnings": list(dict.fromkeys(warnings)),
            "notes": notes, "flavor": flavor, "availability_zone": instance.get("availability_zone") or "",
            "config_drive": bool(instance.get("config_drive")), "properties": props, "ports": ports,
            "source_id": instance.get("id") or "", "source_name": instance.get("name") or "", "default_name": name,
            "same_project": same_project, "networks_read": known is not None, "network_options": options,
            "choose": [p["index"] for p in ports if not p["network_id"]]}


def port_create_args(port, instance_name_value, description=""):
    """Arguments (quoted) of `openstack port create` for one port of new_instance_plan."""
    args = ["--network", shlex.quote(port["network_id"])]
    for subnet in port.get("subnet_ids") or []:
        args += ["--fixed-ip", shlex.quote(f"subnet={subnet}")]
    if port.get("vnic_type") and port["vnic_type"] != "normal":
        args += ["--vnic-type", shlex.quote(port["vnic_type"])]
    if port.get("port_security"):
        args.append("--enable-port-security")
        for group in port.get("security_groups") or []:
            args += ["--security-group", shlex.quote(group["id"])]
    else:
        args += ["--disable-port-security", "--no-security-group"]
    if description:
        args += ["--description", shlex.quote(description)]
    args.append(shlex.quote(f"{instance_name_value}-port{port['index']}"))
    return " ".join(args)


def extra_devices(extra_volumes):
    """Device names (vdb, vdc, ...) for the other volumes of a new instance, in the given order: the original device
    when it is a free /dev/vdX name, otherwise the next free letter."""
    wanted = [os.path.basename(str((v or {}).get("device") or "")) for v in extra_volumes or []]
    taken, names = {"vda"}, []
    for name in wanted:
        if re.fullmatch(r"vd[b-z]", name) and name not in taken:
            taken.add(name)
            names.append(name)
        else:
            names.append("")
    free = (f"vd{c}" for c in "bcdefghijklmnopqrstuvwxyz" if f"vd{c}" not in taken)
    return [name or next(free) for name in names]


def server_create_args(plan, volume_id, port_ids, name, extra_properties=None, extra_volumes=None):
    """Arguments (quoted) of `openstack server create` for new_instance_plan: boot from the restored volume. extra_volumes
    ([{id, device}]): more volumes attached when the instance is created, so its first boot already sees them."""
    args = ["--flavor", shlex.quote(plan["flavor"]["id"]), "--volume", shlex.quote(volume_id)]
    for device, vol in zip(extra_devices(extra_volumes), extra_volumes or []):
        args += ["--block-device-mapping", shlex.quote(f"{device}={vol['id']}:volume::false")]
    for pid in port_ids:
        args += ["--nic", shlex.quote(f"port-id={pid}")]
    if plan.get("availability_zone"):
        args += ["--availability-zone", shlex.quote(plan["availability_zone"])]
    if plan.get("config_drive"):
        args += ["--config-drive", "True"]
    props = dict(plan.get("properties") or {})
    props.update(extra_properties or {})
    for key, value in props.items():
        args += ["--property", shlex.quote(f"{key}={value}")]
    args.append(shlex.quote(name))
    return " ".join(args)


def extra_volume_problems(extra_volumes, found, project_id):
    """Why the other restored volumes cannot be attached to a new instance (empty list = all fine). found: {id: volume
    show} of those volumes (batch_objects)."""
    problems = []
    for vol in extra_volumes or []:
        data = (found or {}).get(str(vol.get("id"))) or {}
        if not data:
            problems.append(f"volume {vol.get('id')} not found")
        elif str(data.get("os-vol-tenant-attr:tenant_id") or data.get("project_id") or "") != project_id:
            problems.append(f"volume {vol.get('id')} is not in the target project")
        elif str(data.get("status")) != "available":
            problems.append(f"volume {vol.get('id')} is {data.get('status')}")
    return problems


def port_create_commands(ports, name, env=""):
    """Batch commands (tasks/openstack_batch.yml) that create the ports of new_instance_plan, all optional so that the
    ports already created can be deleted again when one fails (see created_ports)."""
    commands = []
    for port in ports or []:
        args = port_create_args(port, name, f"restore of port {port.get('original_port_id') or '-'}")
        commands.append({"key": f"port{port['index']}", "label": f"port {port['index']} ({port.get('network_name') or port['network_id']})",
                         "cmd": f"{env} openstack port create {args} -f json".strip(), "optional": True})
    return commands


def created_ports(osb, ports):
    """{'ids': IDs of the ports created by port_create_commands, in order; 'failed': why the others were not created}."""
    ids, failed = [], []
    results = (osb or {}).get("results") or {}
    for port in ports or []:
        entry = results.get(f"port{port['index']}") or {}
        data = batch_json(entry, {})
        if isinstance(data, dict) and data.get("id"):
            ids.append(str(data["id"]))
        else:
            lines = [line.strip() for line in str(entry.get("out") or "").splitlines() if line.strip()]
            failed.append(f"port {port['index']} ({port.get('network_name') or port['network_id']}): "
                          + (" ".join(lines[-2:])[:300] if lines else "not created"))
    return {"ids": ids, "failed": failed}


# ---------------- Delete the old volume (Approvals menu) ----------------
def attachment_server_ids(volume):
    """Instance IDs the volume is attached to (all attachments)."""
    return list(dict.fromkeys(str(a.get("server_id")) for a in _records((volume or {}).get("attachments"), "server_id")
                              if a.get("server_id")))


def attached_volumes(server):
    """[{"id", "delete_on_termination": True|False|None}] of `openstack --os-compute-api-version 2.3 server show`
    (volumes_attached: a list of dicts on python-openstackclient 5, "delete_on_termination='True', id='...'" on 4.0;
    None when the client did not show it)."""
    out = []
    for r in _records((server or {}).get("volumes_attached"), "id"):
        dot = r.get("delete_on_termination")
        out.append({"id": str(r.get("id") or ""), "delete_on_termination": None if dot is None or dot == "" else _flag(dot, False)})
    return [v for v in out if v["id"]]


def deletion_attachments(volume, servers=None, keep_volume_id="", expect_project=""):
    """Attachments of the volume to delete and what can be done with each: detach it (a data disk), or — the boot disk
    of an instance booted from this volume, which Nova never detaches — delete that instance first. The instance may be
    deleted only when it is in the project of the restore, no task runs on it, the restored volume is not attached to
    it and no other disk of it would be deleted with it (delete on termination). With delete on termination set for this
    volume, Nova deletes the volume together with the instance."""
    servers = servers or {}
    items = []
    for att in _records((volume or {}).get("attachments"), "server_id"):
        sid, device = str(att.get("server_id") or ""), str(att.get("device") or "")
        server = servers.get(sid) or {}
        inst = instance_summary(server) if server else {}
        boot = bool(server) and _is_root(device, inst.get("root_device") or "") and inst.get("booted_from_volume", True)
        name = inst.get("name") or sid
        reason = ("attached outside Nova (no instance)" if not sid
                  else f"instance {sid} could not be read" if not server
                  else f"boot disk ({device}) of instance {name}" if boot else "")
        vols = attached_volumes(server)
        this = next((v for v in vols if v["id"] == str((volume or {}).get("id") or "")), {})
        others = [v for v in vols if v["id"] != str((volume or {}).get("id") or "")]
        task = str(server.get("OS-EXT-STS:task_state") or "")
        task = "" if task.lower() in ("", "none", "-") else task
        why_not = ""
        if boot:
            if expect_project and inst.get("project_id") and inst.get("project_id") != str(expect_project):
                why_not = f"instance {name} is in project {inst.get('project_id')}, not in the project of the restore"
            elif task:
                why_not = f"task {task} is running on instance {name}"
            elif keep_volume_id and any(v["id"] == str(keep_volume_id) for v in others):
                why_not = f"the restored volume {keep_volume_id} is attached to instance {name}"
            elif this.get("delete_on_termination") is None and vols:
                why_not = f"delete on termination of the volume on instance {name} could not be read"
            elif any(v["delete_on_termination"] for v in others):
                why_not = ("deleting instance " + name + " would also delete volume(s) "
                           + ", ".join(v["id"] for v in others if v["delete_on_termination"]) + " (delete on termination)")
        items.append({"server_id": sid, "server_name": inst.get("name", ""), "server_status": inst.get("status", ""),
                      "project_id": inst.get("project_id", ""), "device": device, "boot": boot, "detachable": not reason,
                      "reason": (reason + (f": {why_not}" if why_not else ": the instance is deleted first")) if boot else reason,
                      "instance_deletable": boot and not why_not,
                      "delete_on_termination": bool(this.get("delete_on_termination")),
                      "other_volumes": [v["id"] for v in others]})
    return items


def lun_lookup_result(results, pool="", ignore_regex=IGNORE_FLEXVOL_REGEX):
    """LUNs of a volume from `uri` loop results (GET /api/storage/luns?name=*volume-<ref>): read (every call answered),
    error, and the LUNs without clone/reclaimed copies, preferring the Cinder pool (FlexVol) when there are several."""
    records, errors, seen = [], [], set()
    for res in results or []:
        if res.get("skipped"):
            continue
        if res.get("status") != 200:
            msg = ((res.get("json") or {}).get("error") or {}).get("message") or res.get("msg") or "no answer"
            errors.append(f"HTTP {res.get('status', '-')}: {msg}")
            continue
        for rec in (res.get("json") or {}).get("records") or []:
            if rec.get("uuid") not in seen:
                seen.add(rec.get("uuid"))
                records.append(rec)
    luns = lun_candidates(records, pool, ignore_regex)
    return {"read": not errors, "error": "; ".join(errors), "luns": [
        {"name": l.get("name", ""), "uuid": l.get("uuid", ""), "svm": (l.get("svm") or {}).get("name", ""),
         "flexvol": ((l.get("location") or {}).get("volume") or {}).get("name", ""),
         "size": int((l.get("space") or {}).get("size") or 0), "used": int((l.get("space") or {}).get("used") or 0),
         "state": (l.get("status") or {}).get("state", ""), "mapped": bool((l.get("status") or {}).get("mapped"))} for l in luns]}


def _lun_text(lun):
    return (f"LUN {lun['name']} (SVM {lun['svm']}): {lun['size'] / GIB:.1f} GiB, {lun['used'] / GIB:.1f} GiB used, "
            f"{lun['state'] or 'state unknown'}, {'mapped' if lun['mapped'] else 'not mapped'}")


def deletion_checks(volume, expect_project, gone=False, volume_error="", snapshots=None, snapshots_read=True,
                    attachments=None, lun=None):
    """Whether the original volume of a restore can be deleted: the Approvals page shows this before an administrator
    decides, and delete_volume.yml evaluates it again right before deleting.
      - OpenStack: the volume still exists, in the project of the restore, available and not attached, no snapshots;
      - NetApp: its LUN (volume-<ID> or volume-<name_id>) is read from ONTAP. No LUN is only a warning while the volume
        exists (only the OpenStack volume is removed); a LUN without an OpenStack volume is an orphan and is never
        touched by this portal.
    Returns checks, verdict flags (can_delete, can_detach, gone: already deleted in OpenStack AND NetApp, orphan) and
    a summary."""
    volume, lun = volume or {}, lun or {"read": False, "error": "not checked", "luns": []}
    luns, vid = lun.get("luns") or [], str((volume or {}).get("id") or "")
    netapp = ("NetApp could not be checked: " + (lun.get("error") or "no answer")) if not lun.get("read") \
        else "; ".join(_lun_text(l) for l in luns) if luns else "No LUN of this volume in NetApp"
    result = {"checks": [], "warnings": [], "can_delete": False, "can_detach": False, "can_delete_instance": False,
              "gone": False, "orphan": False,
              "lun_read": bool(lun.get("read")), "luns": luns, "attachments": attachments or []}
    if gone:
        result["orphan"] = bool(luns)
        result["gone"] = bool(lun.get("read")) and not luns
        result["checks"] = [{"key": "exists", "ok": False, "detail": "The volume no longer exists in OpenStack"},
                            {"key": "netapp", "ok": result["gone"], "detail": netapp}]
        result["summary"] = ("The volume no longer exists in OpenStack and its LUN is not in NetApp: it was already deleted "
                             "(for example by the team that ran the restore)." if result["gone"]
                             else "The volume no longer exists in OpenStack, but its LUN is still in NetApp (" + netapp
                             + "). This portal does not delete LUNs: check it in ONTAP." if result["orphan"]
                             else "The volume no longer exists in OpenStack; " + netapp + ".")
        return result
    if volume_error:
        result["checks"] = [{"key": "exists", "ok": False, "detail": f"The volume could not be read: {volume_error}"}]
        result["summary"] = f"The volume could not be read: {volume_error}"
        return result
    status = str(volume.get("status") or "")
    atts = attachments or []
    where = ", ".join(f"{a['server_name'] or a['server_id']} ({a['server_status'] or '?'}) as {a['device'] or '?'}" for a in atts)
    checks = [
        {"key": "exists", "ok": True, "detail": f"Volume {volume.get('name') or vid} exists ({volume.get('size', '?')} GB, "
                                                 f"type {volume.get('type') or '-'}, status {status or '?'})"},
        {"key": "project", "ok": str(volume.get("os-vol-tenant-attr:tenant_id") or "") == str(expect_project),
         "detail": f"Still in project {expect_project}" if str(volume.get("os-vol-tenant-attr:tenant_id") or "") == str(expect_project)
         else f"Now in project {volume.get('os-vol-tenant-attr:tenant_id') or '?'}, not {expect_project} as at the restore: check it manually"},
        {"key": "detached", "ok": status == "available" and not atts,
         "detail": "Status available, not attached" if status == "available" and not atts
         else f"Attached to {where}" if atts else f"Status {status or '?'}: only an available volume can be deleted"},
        {"key": "snapshots", "ok": bool(snapshots_read) and not (snapshots or []),
         "detail": ("No Cinder snapshots" if not snapshots else f"{len(snapshots)} Cinder snapshot(s): delete them first")
         if snapshots_read else "The snapshots of the volume could not be read"},
        {"key": "netapp", "ok": bool(lun.get("read")), "detail": netapp},
    ]
    if lun.get("read") and not luns:
        result["warnings"].append("No LUN of this volume was found in NetApp: deleting removes only the OpenStack volume.")
    result["checks"] = checks
    blocking = [c for c in checks if not c["ok"]]
    result["can_delete"] = not blocking
    result["can_detach"] = (bool(atts) and status == "in-use" and all(a["detachable"] for a in atts)
                            and all(c["key"] == "detached" for c in blocking))
    # the boot disk of one instance: that instance is deleted first, then the volume (or Nova deletes it with the instance)
    result["can_delete_instance"] = (len(atts) == 1 and status == "in-use" and bool(atts[0].get("instance_deletable"))
                                     and all(c["key"] == "detached" for c in blocking))
    if result["can_delete"]:
        result["summary"] = f"Volume {vid} can be deleted."
    elif result["can_detach"]:
        result["summary"] = f"Volume {vid} is attached to {where}; it can be detached and then deleted."
    elif result["can_delete_instance"]:
        a = atts[0]
        result["summary"] = (f"Volume {vid} is the boot disk ({a['device']}) of instance {a['server_name'] or a['server_id']} "
                             f"({a['server_status'] or '?'}): the instance can be deleted first, then the volume"
                             + (" (delete on termination: Nova deletes the volume with the instance; the portal checks that it is gone)."
                                if a.get("delete_on_termination") else "."))
    else:
        reasons = [c["detail"] for c in blocking]
        reasons += [a["reason"] for a in atts if a.get("reason")]
        result["summary"] = f"Volume {vid} cannot be deleted now: " + "; ".join(dict.fromkeys(reasons))
    return result


IMAGE_KEY_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,255}$")


def image_properties(volume):
    """volume_image_metadata of `openstack volume show` that can be set on the restored volume (image properties that
    decide how an instance boots from it: hw_firmware_type, hw_disk_bus, os_type...)."""
    value = (volume or {}).get("volume_image_metadata")
    props = _props(value) if not isinstance(value, str) else dict(KV_RE.findall(value))
    return {k: v for k, v in props.items() if IMAGE_KEY_RE.match(k) and 0 < len(v) <= 255}


def image_property_args(props):
    return " ".join(f"--image-property {shlex.quote(f'{k}={v}')}" for k, v in sorted((props or {}).items()))


class FilterModule:
    def filters(self):
        return {"extract_json": extract_json, "cinder_table_id": cinder_table_id, "snapshot_choices": snapshot_choices,
                "volume_name_id": volume_name_id, "cinder_pools": cinder_pools, "lun_candidates": lun_candidates,
                "pool_choices": pool_choices, "batch_script": batch_script, "batch_results": batch_results,
                "parallel_width": parallel_width,
                "batch_json": batch_json, "volume_attachment": volume_attachment, "instance_summary": instance_summary,
                "volume_role": volume_role, "server_choices": server_choices, "instance_name": instance_name,
                "new_instance_plan": new_instance_plan, "port_create_args": port_create_args,
                "target_network_commands": target_network_commands, "network_options": network_options,
                "server_create_args": server_create_args, "extra_volume_problems": extra_volume_problems,
                "type_choices": type_choices, "pool_flexvols": pool_flexvols,
                "image_properties": image_properties,
                "image_property_args": image_property_args, "show_commands": show_commands,
                "batch_objects": batch_objects, "flavor_ref": flavor_ref, "port_ids": port_ids,
                "port_create_commands": port_create_commands, "created_ports": created_ports,
                "attachment_server_ids": attachment_server_ids, "deletion_attachments": deletion_attachments,
                "lun_lookup_result": lun_lookup_result, "deletion_checks": deletion_checks}

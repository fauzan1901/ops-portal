"""Files of Operation Automation that can be downloaded (permission "collect logs", wi-logs; administrators always):

  raw/run-<id>.json.gz      every command / REST path / probe a check read and its full output (secrets masked)
  raw/fix-<id>.txt.gz       the full output of a fix (the run page keeps only the end of each command)
  raw/*.pending.json        what a playbook wrote before the portal masked it (removed when the job ends)
  bundles/run-<id>/         log bundles of the checks "Collect logs" and "sos report": what each node sent (one archive
                            per node), then one .tar with MANIFEST.json and the node archives unchanged (finalize_bundle)

Everything is deleted KEEP_DAYS (default 7) after it was written; a new collection is refused while the disk of the portal
server has less than MIN_FREE_GB free or the bundles already take MAX_BUNDLES_GB.
"""
import datetime
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import tarfile
import time
import zipfile

import settings

PERMISSION = "wi-logs"
ROOT = os.path.join(settings.DATA_DIR, "wi-files")
KEEP_DAYS = int(os.environ.get("WI_FILES_KEEP_DAYS", "7"))
MIN_FREE_GB = float(os.environ.get("WI_FILES_MIN_FREE_GB", "5"))
MAX_BUNDLES_GB = float(os.environ.get("WI_BUNDLES_MAX_GB", "40"))
NODE_FILE = re.compile(r"^(?P<node>[A-Za-z0-9][A-Za-z0-9_.-]{0,80})\.(?P<kind>logs\.tar\.gz|sos\.archive)$")
NO_PERMISSION = ("Your account cannot collect logs or download raw outputs and log bundles. An administrator can allow it on "
                 "the Users page (Operation Automation: collect logs).")


def can_collect(user):
    """May this account run log collections and download raw outputs and bundles."""
    return bool(user) and (user.get("role") == "admin" or PERMISSION in (user.get("modules") or []))


def _dir(*parts):
    path = os.path.join(ROOT, *parts)
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def cleanup(now=None):
    """Delete what is older than KEEP_DAYS. Returns the number of files and folders removed."""
    now = now or time.time()
    limit = now - KEEP_DAYS * 86400
    removed = 0
    for sub in ("raw", "bundles"):
        base = os.path.join(ROOT, sub)
        if not os.path.isdir(base):
            continue
        for name in os.listdir(base):
            path = os.path.join(base, name)
            try:   # a pending file (not masked yet) of a job that never finished: after a day
                if os.path.getmtime(path) < (now - 86400 if name.endswith(".pending.json") else limit):
                    (shutil.rmtree if os.path.isdir(path) else os.remove)(path)
                    removed += 1
            except OSError:
                continue
    return removed


_last_cleanup = [0.0]


def cleanup_now_and_then():
    """cleanup() at most once an hour (called when a run starts)."""
    if time.time() - _last_cleanup[0] >= 3600:
        _last_cleanup[0] = time.time()
        cleanup()


def _size(path):
    total = 0
    for dirpath, _dirs, names in os.walk(path):
        for n in names:
            try:
                total += os.path.getsize(os.path.join(dirpath, n))
            except OSError:
                pass
    return total


def ensure_room():
    """ValueError when a new log collection must not start (little free disk, or the bundles already take their share)."""
    cleanup()
    os.makedirs(ROOT, exist_ok=True)
    free = shutil.disk_usage(ROOT).free / 2 ** 30
    if free < MIN_FREE_GB:
        raise ValueError(f"The portal server has only {free:.1f} GB free (at least {MIN_FREE_GB:g} GB is needed for a log "
                         f"collection). Older bundles are deleted after {KEEP_DAYS} days.")
    used = _size(os.path.join(ROOT, "bundles")) / 2 ** 30
    if used > MAX_BUNDLES_GB:
        raise ValueError(f"Log bundles already take {used:.1f} GB (limit {MAX_BUNDLES_GB:g} GB). They are deleted "
                         f"{KEEP_DAYS} days after they were made.")


def expires(path):
    try:
        return datetime.datetime.fromtimestamp(os.path.getmtime(path) + KEEP_DAYS * 86400).astimezone().isoformat(timespec="minutes")
    except OSError:
        return ""


# ---------------------------------------------------------------- raw output of checks and fixes
def pending(kind, item_id):
    """Where the playbook writes what it read / the full output of a fix (not masked yet): keep_run / keep_fix mask it,
    compress it and remove this file as soon as the job ends."""
    return os.path.join(_dir("raw"), f"{kind}-{int(item_id)}.pending.json")


def progress_path(action_id):
    """Progress of a fix with ticked items: written by playbooks/tasks/openstack_item.yml before and after each item."""
    return os.path.join(_dir("raw"), f"progress-{int(action_id)}.json")


def progress(action_id):
    try:
        with open(progress_path(action_id), encoding="utf-8") as f:
            value = json.load(f)
        return value if isinstance(value, dict) else None
    except (OSError, ValueError):
        return None


def _take(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def keep_run(run_id, check_id, params, ctx):
    """After a check: what it read (pending file of the playbook) -> raw/run-<id>.json.gz with the command of each key."""
    from . import wi_analysis
    data = _take(pending("run", run_id))
    if not isinstance(data, dict):
        return False
    try:
        commands = wi_analysis.commands_run(check_id, data, params or {}, ctx or {})
    except Exception:   # the commands are a help; the outputs are kept anyway
        commands = {}
    save_raw_run(run_id, data, commands)
    return True


def fix_text(data, commands):
    """The full output of a fix: every command with its exit code and output (items one after the other)."""
    from . import wi_analysis
    data = data or {}

    def script(stdout, stderr, cmds):
        found = wi_analysis.batch(stdout or "", [f"a{i}" for i in range(1, len(cmds) + 1)])
        parts = []
        for i, cmd in enumerate(cmds, 1):
            item = found.get(f"a{i}") or {}
            if "rc" not in item:
                parts.append(f"$ {cmd}\n(not run)")
                continue
            parts.append(f"$ {cmd}\n(exit {item['rc']})\n{item.get('out') or ''}")
        rest = [l for l in str(stdout or "").splitlines() if not l.startswith(wi_analysis.MARK)]
        if not any("rc" in (found.get(f"a{i}") or {}) for i in range(1, len(cmds) + 1)) and rest:
            parts.append("\n".join(rest))
        if str(stderr or "").strip():
            parts.append("stderr / connection:\n" + str(stderr).strip())
        return "\n\n".join(parts)
    if data.get("items"):
        return "\n\n".join(f"===== Item {i}/{len(data['items'])}: {it.get('label')}\n\n"
                            + script(it.get("stdout"), it.get("stderr"), it.get("commands") or [])
                            for i, it in enumerate(data["items"], 1))
    return script(data.get("stdout"), data.get("stderr"), list(commands or []))


def keep_fix(action_id, commands):
    data = _take(pending("fix", action_id))
    if not isinstance(data, dict):
        return False
    save_fix_output(action_id, fix_text(data, commands))
    return True


SECRET_KEY = re.compile(r"pass(word|wd|phrase)?$|secret|psk|pre_?shared|token|private_?key|api_?key|community|auth_?key",
                        re.I)


def mask_json(value):
    """A REST answer with the values of secret fields (password, psk, token, ...) masked; the rest unchanged."""
    if isinstance(value, dict):
        return {k: "********" if SECRET_KEY.search(str(k)) and isinstance(v, str) and v else mask_json(v) for k, v in value.items()}
    if isinstance(value, list):
        return [mask_json(v) for v in value]
    return value


def save_raw_run(run_id, raw, commands):
    """Keep what a check read (key -> item) with the command / path of each key (source -> key -> command): command
    output masked as on the run page, REST answers as JSON with their secret fields masked."""
    from .wi_analysis import screens
    where = {key: (src, cmd) for src, items in (commands or {}).items() for key, cmd in (items or {}).items()}
    items = []
    for key, item in (raw or {}).items():
        item = item if isinstance(item, dict) else {"out": str(item)}
        src, cmd = where.get(key, ("", ""))
        entry = {"key": key, "source": src, "command": str(cmd)}
        for k in ("rc", "status", "skipped", "msg"):
            if k in item:
                entry[k] = item[k] if k in ("rc", "status") else screens.redact(str(item[k]))
        if "json" in item:
            entry["json"] = mask_json(item["json"])
        else:
            entry["out"] = screens.redact(str(item.get("out") or item.get("body") or ""))
        items.append(entry)
    with gzip.open(os.path.join(_dir("raw"), f"run-{int(run_id)}.json.gz"), "wt", encoding="utf-8") as f:
        json.dump({"run": int(run_id), "saved": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
                   "items": items}, f)


def raw_data(run_id):
    """The reads of a run as the analysis sees them ({key: {"rc", "out"} | {"status", "json"} | {"skipped"}}), masked."""
    raw = raw_run(run_id) or {"items": []}
    return {it["key"]: {k: v for k, v in it.items() if k in ("rc", "status", "skipped", "msg", "out", "json")}
            for it in raw["items"]}


def raw_path(run_id):
    return os.path.join(ROOT, "raw", f"run-{int(run_id)}.json.gz")


def raw_run(run_id):
    path = raw_path(run_id)
    if not os.path.exists(path):
        return None
    with gzip.open(path, "rt", encoding="utf-8") as f:
        return json.load(f)


def save_fix_output(action_id, text):
    from .wi_analysis import screens
    if not text:
        return
    with gzip.open(os.path.join(_dir("raw"), f"fix-{int(action_id)}.txt.gz"), "wt", encoding="utf-8") as f:
        f.write(screens.redact(str(text)))


def fix_output(action_id):
    path = os.path.join(ROOT, "raw", f"fix-{int(action_id)}.txt.gz")
    if not os.path.exists(path):
        return None
    with gzip.open(path, "rt", encoding="utf-8") as f:
        return f.read()


def safe_name(text):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", str(text or ""))[:80].strip("_") or "item"


def raw_zip(record, fixes=(), extra=None):
    """The raw output of a run as a zip: README, result.json, ansible.log, one file per read (command and full output),
    the full output of each fix run from it, and extra files of the check (e.g. every log entry as CSV)."""
    from .wi_analysis import screens
    raw = raw_run(record["id"]) or {"items": []}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        lines = [f"Operation Automation run #{record['id']}: {record.get('check_title')}", f"Site: {record.get('site')}",
                 f"Host: {record.get('host') or '-'}", f"Parameters: {json.dumps(record.get('params') or {}, sort_keys=True)}",
                 f"Started: {record.get('ts')}  Finished: {record.get('finished') or '-'}  By: {record.get('username')}",
                 f"Status: {record.get('status')}  {record.get('summary') or record.get('error') or ''}", "",
                 "reads/<source>/<key>.txt   each command or probe of the check and its full output",
                 "reads/<source>/<key>.json  each REST answer (ONTAP, vCenter, NSX-T, vCloud Director, Redfish) with its path",
                 "export/*.csv                every entry of an event log, when the check reads one",
                 "result.json                 the result shown on the run page", "ansible.log                 the Ansible output",
                 "fixes/fix-<id>.txt          the full output of each fix run from this result",
                 "Secrets (passwords, keys, tokens, password hashes) are masked."]
        if not raw["items"]:
            lines.append(f"The reads of this run are no longer kept (they are deleted after {KEEP_DAYS} days) or were not saved.")
        z.writestr("README.txt", "\n".join(lines) + "\n")
        z.writestr("result.json", json.dumps(record.get("result") or {}, indent=2, ensure_ascii=False))
        z.writestr("ansible.log", screens.redact(record.get("log") or ""))
        for it in raw["items"]:
            base = f"reads/{safe_name(it.get('source') or 'other')}/{safe_name(it['key'])}"
            if "json" in it:   # a REST answer: the path and the JSON
                z.writestr(base + ".json", json.dumps({"path": it.get("command"), "status": it.get("status"), "answer": it["json"]},
                                                      indent=2, ensure_ascii=False))
                continue
            state = (f"(not read: {it['skipped']})" if it.get("skipped") else
                     f"(exit {it['rc']})" if "rc" in it else f"(HTTP {it.get('status')} {it.get('msg') or ''})".rstrip())
            z.writestr(base + ".txt", (f"$ {it['command']}\n" if it.get("command") else "") + state + "\n\n" + (it.get("out") or ""))
        for a in fixes:
            text = fix_output(a["id"])
            if text is None:
                text = "\n\n".join(f"$ {s.get('command')}\n(exit {s.get('rc')})\n{s.get('out') or ''}" for s in a.get("output") or [])
            z.writestr(f"fixes/fix-{a['id']}.txt", f"Fix #{a['id']} by {a.get('username')} at {a.get('ts')}: {a.get('status')}\n"
                                                    f"{a.get('title') or ''}\n\n{text}")
        for name, text in (extra or {}).items():
            z.writestr(f"export/{safe_name(name)}", text)
    return buf.getvalue()


# ---------------------------------------------------------------- log bundles
def bundle_dir(run_id):
    return _dir("bundles", f"run-{int(run_id)}")


def bundle(run_id):
    """{"name", "path", "size", "expires"} of the finished bundle of a run, or None."""
    base = os.path.join(ROOT, "bundles", f"run-{int(run_id)}")
    if not os.path.isdir(base):
        return None
    for name in sorted(os.listdir(base)):
        if re.match(r"^(logs|sos)-[A-Za-z0-9_.-]+\.tar$", name):
            path = os.path.join(base, name)
            return {"name": name, "path": path, "size": os.path.getsize(path), "expires": expires(path)}
    return None


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _manifest_of(err_text):
    for line in reversed(err_text.splitlines()):
        if line.startswith("@@WI@@manifest "):
            try:
                return json.loads(line[15:])
            except ValueError:
                return {}
    return {}


def finalize_bundle(record, result):
    """One archive of what the nodes sent, without compressing it again: logs-<site>-run<id>-<time>.tar with
    <node>/<node>.logs.tar.gz per node (the log files, MANIFEST.txt), or sos-<site>-run<id>-<time>.tar with
    <node>/sosreport-....tar.xz as sos wrote it; MANIFEST.json and README.txt at the top. The per-node files are moved
    into it (removed). Returns the bundle info, or None when no node sent anything."""
    base = os.path.join(ROOT, "bundles", f"run-{int(record['id'])}")
    if not os.path.isdir(base):
        return None
    parts = sorted(n for n in os.listdir(base) if NODE_FILE.match(n))
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    nodes = []
    for n in parts:
        m = NODE_FILE.match(n)
        path = os.path.join(base, n)
        err = ""
        if os.path.exists(path + ".err"):
            with open(path + ".err", encoding="utf-8", errors="replace") as f:
                err = f.read()
        info = _manifest_of(err)
        size = os.path.getsize(path)
        sos = m.group("kind") == "sos.archive"
        arc = info.get("archive") if sos else f"{m.group('node')}.logs.tar.gz"
        if sos and not re.match(r"^sosreport-[A-Za-z0-9_.-]+\.tar(\.(xz|gz|bz2|zst))?$", str(arc or "")):
            arc = f"{m.group('node')}.sos-archive"
        tail = [l for l in err.splitlines() if l.strip() and not l.startswith("@@WI@@")][-20:]
        nodes.append({"node": m.group("node"), "kind": "sos" if sos else "logs", "file": arc, "path": path, "size": size,
                      "sha256": _sha256(path) if size else "", "complete": bool(info) and size > 0 and not info.get("error"),
                      "error": info.get("error") or ("" if size else "nothing received"), "log": tail,
                      **({"files": len(info.get("files") or []), "uncompressed": info.get("total_bytes"),
                          "missing": info.get("missing")} if not sos else {"sos_sha256": info.get("sha256")})})
    sent = [x for x in nodes if x["size"]]
    if not sent:
        for x in nodes:
            for p in (x["path"], x["path"] + ".err"):
                if os.path.exists(p):
                    os.remove(p)
        return None
    sos = any(x["kind"] == "sos" for x in sent)
    res = result or {}
    manifest = {"run": record["id"], "site": record.get("site"), "check": record.get("check_title"),
                "params": record.get("params"), "by": record.get("username"), "made": stamp, "status": record.get("status"),
                "summary": res.get("summary") or record.get("summary") or record.get("error"),
                "nodes": [{k: v for k, v in x.items() if k != "path"} for x in nodes]}
    readme = (f"Operation Automation run #{record['id']} ({record.get('site')}): {record.get('check_title')}\n"
              f"Made {stamp} by {record.get('username')}. {manifest['summary'] or ''}\n\n"
              + ("Each <node>/ folder has the sos report archive as sos wrote it: attach it to the Red Hat case.\n" if sos else
                 "Each <node>/ folder has <node>.logs.tar.gz: the log lines of the time window (secrets masked on the node)\n"
                 "and MANIFEST.txt (lines, bytes and sha256 of every file).\n"
                 "  tar xf <this file>; cd <node>; tar xzf <node>.logs.tar.gz\n")
              + "MANIFEST.json: the parameters, the result and the sha256 of every archive.\n")
    name = f"{'sos' if sos else 'logs'}-{safe_name(record.get('site'))}-run{int(record['id'])}-{stamp}.tar"
    out = os.path.join(base, name)
    with tarfile.open(out + ".part", "w") as tar:
        for arcname, text in (("README.txt", readme), ("MANIFEST.json", json.dumps(manifest, indent=2, ensure_ascii=False))):
            data = text.encode()
            info = tarfile.TarInfo(arcname)
            info.size, info.mtime, info.mode = len(data), time.time(), 0o644
            tar.addfile(info, io.BytesIO(data))
        for x in sent:
            tar.add(x["path"], arcname=f"{x['node']}/{x['file']}", recursive=False)
    os.replace(out + ".part", out)
    for x in nodes:
        for p in (x["path"], x["path"] + ".err"):
            if os.path.exists(p):
                os.remove(p)
    return {"name": name, "size": os.path.getsize(out), "expires": expires(out), "nodes": len(sent)}

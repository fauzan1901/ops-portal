#!/usr/bin/env python3
"""Log collection on one overcloud node (RHOSP 16.2 / 17.1), started by the portal through the director:

    ssh <user>@<ctlplane> 'echo <this file, base64> | base64 -d | sudo -n python3 - <mode> ...'

It only reads: log files, the journal, and (mode sos) runs Red Hat's own `sos report`. What it collects goes to stdout
as one archive, so nothing stays on the node:

  logs  --components nova,neutron,... --since <epoch> --until <epoch> --max-mb <MB per node>
        A plain tar (the director side compresses it with gzip): every line of the log files of the components written
        in the time window, rotated files (.1, -YYYYMMDD, .gz) included, lines without a timestamp (tracebacks) kept
        with the line before them; the journal of pacemaker / corosync / pcsd, the kernel and iscsid / multipathd; a
        few facts of the node (info/). Secrets (passwords, tokens, URL credentials, password hashes) are masked before
        the lines leave the node. MANIFEST.txt lists every file with its lines, bytes and sha256.
  sos   --label <text> [--case-id <n>] [--all-logs] --min-free-gb <GB>
        `sos report --batch` into a new folder under /var/tmp, then the archive itself to stdout and the folder removed.

stderr: progress, then one line "@@WI@@manifest <json>" for the portal. Exit 0 done, 3 not started (no room, no sos),
4 failed. Python 3.6 (RHEL 8 platform-python) and later.
"""
import argparse
import datetime
import glob
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import time

MARK = "@@WI@@"
FILE_CAP = 256 * 2 ** 20   # one file at most (the newest lines are kept)

# Log files of each component (relative to the root); rotated copies (.1, .2.gz, -20261019) are found next to them.
FILES = {
    "nova": ["var/log/containers/nova/*.log"],
    "placement": ["var/log/containers/placement/*.log"],
    "libvirt": ["var/log/containers/libvirt/*.log", "var/log/containers/libvirt/qemu/*.log", "var/log/libvirt/qemu/*.log"],
    "neutron": ["var/log/containers/neutron/*.log"],
    "ovn": ["var/log/containers/openvswitch/*.log", "var/log/openvswitch/*.log"],
    "cinder": ["var/log/containers/cinder/*.log"],
    "glance": ["var/log/containers/glance/*.log"],
    "keystone": ["var/log/containers/keystone/*.log"],
    "heat": ["var/log/containers/heat/*.log"],
    "horizon": ["var/log/containers/horizon/*.log", "var/log/containers/httpd/*/*error*log"],
    "rabbitmq": ["var/log/containers/rabbitmq/*.log"],
    "galera": ["var/log/containers/mysql/*.log"],
    "haproxy": ["var/log/containers/haproxy/*.log"],
    "pacemaker": ["var/log/pacemaker/*.log", "var/log/cluster/*.log", "var/log/pacemaker.log"],
    "system": ["var/log/messages"],
}
JOURNAL = {
    "pacemaker": ["-u", "pacemaker", "-u", "corosync", "-u", "pcsd"],
    "kernel": ["-k"],
    "iscsi": ["-u", "iscsid", "-u", "multipathd", "-u", "tripleo_iscsid"],
}
COMPONENTS = sorted(set(FILES) | set(JOURNAL))

# Secrets are masked line by line (only lines containing one of the hints are searched, for speed).
HINTS = ("pass", "secret", "token", "key", "://", "$", "gaaaaa", "authorization")
MASKS = [
    (re.compile(r"((?:password|passwd|secret|token|api[_-]?key|private[_-]?key|auth[_-]?key|admin_pass)['\"]?\s*[=:]\s*u?)"
                r"('[^']*'|\"[^\"]*\"|[^\s,;}&)]+)", re.I), r"\1********"),
    (re.compile(r"(\b[a-z][a-z0-9+.-]*://[^:/\s@]+:)[^@\s/]+@", re.I), r"\1********@"),
    (re.compile(r"\$(?:1|5|6|y|2[aby])\$[^\s'\":]{8,}"), "********"),
    (re.compile(r"\bgAAAAA[0-9A-Za-z_=-]{30,}"), "gAAAAA********"),
    (re.compile(r"((?:X-Auth-Token|X-Subject-Token|X-Service-Token|Authorization)['\"]?\s*[:=]\s*['\"]?(?:Bearer |Basic )?)"
                r"[^\s'\",}]+", re.I), r"\1********"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*", re.I), "-----BEGIN PRIVATE KEY----- ********"),
]

ISO = re.compile(r"^\[?(\d{4})-(\d{2})-(\d{2})[ T]+(\d{1,2}):(\d{2}):(\d{2})(?:[.,]\d+)?\s?(Z|[+-]\d{2}:?\d{2})?")
SYSLOG = re.compile(r"^([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2})\b")
APACHE = re.compile(r"^\[[A-Z][a-z]{2} ([A-Z][a-z]{2}) (\d{1,2}) (\d{2}):(\d{2}):(\d{2})(?:\.\d+)? (\d{4})\]")
MONTHS = {m: i for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}


def log(msg):
    sys.stderr.write(msg.rstrip() + "\n")
    sys.stderr.flush()


def mask(line):
    low = line.lower()
    if not any(h in low for h in HINTS):
        return line
    for rx, repl in MASKS:
        line = rx.sub(repl, line)
    return line


def stamp_of(line, year, now):
    """Seconds since the epoch of a log line's timestamp (local time unless the line says Z / +hh:mm), or None."""
    m = ISO.match(line)
    if m:
        y, mo, d, h, mi, s, tz = m.groups()
        try:
            t = datetime.datetime(int(y), int(mo), int(d), int(h), int(mi), int(s))
        except ValueError:
            return None
        if tz:
            off = 0 if tz == "Z" else (1 if tz[0] == "+" else -1) * (int(tz[1:3]) * 3600 + int(tz[-2:]) * 60)
            return (t - datetime.datetime(1970, 1, 1)).total_seconds() - off
        return time.mktime(t.timetuple())
    m = SYSLOG.match(line) or APACHE.match(line)
    if m:
        g = m.groups()
        mo = MONTHS.get(g[0])
        if not mo:
            return None
        y = int(g[5]) if len(g) > 5 else year
        try:
            value = time.mktime(datetime.datetime(y, mo, int(g[1]), int(g[2]), int(g[3]), int(g[4])).timetuple())
        except ValueError:
            return None
        if len(g) == 5 and value > now + 86400:   # syslog has no year: December lines read in January
            value = time.mktime(datetime.datetime(y - 1, mo, int(g[1]), int(g[2]), int(g[3]), int(g[4])).timetuple())
        return value
    return None


def log_files(root, patterns):
    """The files of the patterns and their rotated copies (x.log.1, x.log.2.gz, x.log-20261019(.gz)), newest first (when
    the limit of the node is reached, the oldest are left out)."""
    found = set()
    for pattern in patterns:
        path = os.path.join(root, pattern)
        found |= set(glob.glob(path)) | set(glob.glob(path + ".[0-9]*")) | set(glob.glob(path + "-[0-9]*"))

    def mtime(p):
        try:
            return os.path.getmtime(p)
        except OSError:
            return 0
    return sorted((p for p in found if os.path.isfile(p) and not os.path.islink(p)), key=mtime, reverse=True)


def opener(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    if path.endswith((".xz", ".bz2", ".zst")):
        return None
    return io.open(path, "r", encoding="utf-8", errors="replace")


class Writer:
    """The plain tar on stdout; each member is first written to a temporary file (its size must be known)."""

    def __init__(self, max_bytes, tmp):
        self.tar = tarfile.open(fileobj=sys.stdout.buffer, mode="w|", format=tarfile.PAX_FORMAT)
        self.max_bytes, self.total, self.tmp = max_bytes, 0, tmp
        self.files, self.skipped = [], []

    def room(self):
        return self.max_bytes - self.total

    def add_lines(self, name, lines, note=""):
        """lines: an iterator of text lines (already filtered). Keeps the newest FILE_CAP bytes."""
        h = hashlib.sha256()
        count = 0
        with tempfile.TemporaryFile(dir=self.tmp) as f:
            for line in lines:
                data = mask(line).encode("utf-8", "replace")
                f.write(data)
                count += 1
            size = f.tell()
            if not count:
                return 0
            cap = min(FILE_CAP, max(0, self.room()))
            start = max(0, size - cap)
            if start:
                f.seek(start)
                f.readline()   # from the next whole line
                start = f.tell()
                note = (note + "; " if note else "") + f"first {start} bytes dropped (limit)"
            f.seek(start)
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = size - start, int(time.time()), 0o644
            # the sha256 of what is in the archive
            pos = f.tell()
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
            f.seek(pos)
            self.tar.addfile(info, f)
        self.total += info.size
        self.files.append({"name": name, "lines": count, "bytes": info.size, "sha256": h.hexdigest(), "note": note})
        return info.size

    def add_text(self, name, text):
        self.add_lines(name, iter(str(text).splitlines(True)))

    def close(self, manifest):
        rows = [f"{x['name']}\t{x['lines']} lines\t{x['bytes']} bytes\tsha256 {x['sha256']}" + (f"\t{x['note']}" if x["note"] else "")
                for x in self.files]
        rows += [f"{x['name']}\tnot collected: {x['why']}" for x in self.skipped]
        data = ("\n".join([f"# {k}: {v}" for k, v in manifest.items() if not isinstance(v, (list, dict))] + rows) + "\n").encode()
        info = tarfile.TarInfo("MANIFEST.txt")
        info.size, info.mtime, info.mode = len(data), int(time.time()), 0o644
        self.tar.addfile(info, io.BytesIO(data))
        self.tar.close()
        sys.stdout.buffer.flush()


def window_lines(path, since, until, state):
    """The lines of a file written in [since, until]; lines without a timestamp follow the line before them. A file in
    which no timestamp is recognised gives nothing here (state["stamps"] stays 0: the caller keeps its end instead)."""
    year, now = datetime.datetime.now().year, time.time()
    f = opener(path)
    if f is None:
        return
    inside = False
    with f:
        for line in f:
            t = stamp_of(line, year, now)
            if t is not None:
                state["stamps"] += 1
                inside = since <= t <= until
                if t > until + 900:   # a log is written in time order: the rest of the file is after the window
                    break
            if inside:
                yield line


def tail_lines(path, max_bytes):
    f = opener(path)
    if f is None:
        return
    with f:
        if not path.endswith(".gz"):
            try:
                size = os.path.getsize(path)
                if size > max_bytes:
                    f.seek(size - max_bytes)
                    f.readline()
            except (OSError, io.UnsupportedOperation):
                pass
        for line in f:
            yield line


def journal(args, since, until):
    cmd = ["journalctl", "--no-pager", "-o", "short-iso", "--since", f"@{int(since)}", "--until", f"@{int(until)}"] + args
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True, errors="replace")
    except (OSError, TypeError):
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True)
        except OSError:
            return None
    return p


def run_text(cmd):
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT, universal_newlines=True, timeout=60)
    except subprocess.CalledProcessError as e:
        return e.output or f"exit {e.returncode}"
    except (OSError, subprocess.TimeoutExpired) as e:
        return f"not available: {e}"


def collect_logs(a):
    root = a.root
    tmp = a.tmp if os.path.isdir(a.tmp) else tempfile.gettempdir()
    w = Writer(a.max_mb * 2 ** 20, tmp)
    since, until = float(a.since), float(a.until)
    comps = [c for c in a.components.split(",") if c in COMPONENTS]
    missing = []
    log(f"collecting {', '.join(comps)} from {time.strftime('%Y-%m-%d %H:%M:%S %z', time.localtime(since))} "
        f"to {time.strftime('%Y-%m-%d %H:%M:%S %z', time.localtime(until))}")
    w.add_text("info/node.txt", "\n".join([f"hostname: {socket.gethostname()}",
                                           f"collected: {time.strftime('%Y-%m-%d %H:%M:%S %z')}",
                                           f"window: {int(since)} - {int(until)} (seconds since the epoch)",
                                           f"timezone: {time.strftime('%Z %z')}",
                                           "uptime: " + run_text(["uptime"]).strip()]) + "\n")
    if root == "/":
        w.add_text("info/containers.txt", run_text(["podman", "ps", "-a", "--format", "{{.Names}}\t{{.Status}}\t{{.Image}}"]))
        w.add_text("info/df.txt", run_text(["df", "-hP", "-x", "tmpfs", "-x", "devtmpfs", "-x", "overlay"]))
    seen = set()
    for comp in comps:
        found = 0
        for path in log_files(root, FILES.get(comp, [])):
            real = os.path.realpath(path)
            if real in seen:
                continue
            seen.add(real)
            found += 1
            name = "logs/" + os.path.relpath(path, root).replace("var/log/", "", 1)
            name = name[:-3] if name.endswith(".gz") else name
            try:
                if os.path.getmtime(path) < since:
                    continue   # last written before the window
            except OSError:
                continue
            if w.room() <= 0:
                w.skipped.append({"name": name, "why": f"the limit of {a.max_mb} MB for this node was reached"})
                continue
            if opener(path) is None:
                w.skipped.append({"name": name, "why": "compression not supported here"})
                continue
            state = {"stamps": 0}
            try:
                size = w.add_lines(name, window_lines(path, since, until, state))
                if not state["stamps"]:   # no timestamp recognised: the end of the file
                    size = w.add_lines(name, tail_lines(path, 16 * 2 ** 20), "no timestamps recognised: the last 16 MB")
            except (OSError, EOFError, ValueError) as e:
                w.skipped.append({"name": name, "why": f"could not be read: {e}"})
                continue
            log(f"{name}: {size} bytes")
        for key in [comp] if comp in JOURNAL else []:
            p = journal(JOURNAL[key], since, until)
            if p is None:
                w.skipped.append({"name": f"journal/{key}.log", "why": "journalctl is not available"})
                continue
            found += 1
            try:
                size = w.add_lines(f"journal/{key}.log", p.stdout)
            finally:
                p.stdout.close()
                p.wait()
            log(f"journal/{key}.log: {size} bytes")
        if not found:
            missing.append(comp)
    manifest = {"node": socket.gethostname(), "mode": "logs", "since": int(since), "until": int(until), "components": comps,
                "missing": missing, "files": [{k: x[k] for k in ("name", "lines", "bytes", "note")} for x in w.files][:600],
                "skipped": w.skipped[:200], "total_bytes": w.total, "max_bytes": w.max_bytes}
    w.close({"node": manifest["node"], "since": int(since), "until": int(until), "components": ",".join(comps),
             "missing": ",".join(missing) or "-", "total_bytes": w.total})
    log(MARK + "manifest " + json.dumps(manifest, separators=(",", ":")))
    return 0


def collect_sos(a):
    tmp_root = a.tmp
    try:
        free = shutil.disk_usage(tmp_root).free
    except OSError as e:
        log(f"{tmp_root}: {e}")
        return 3
    if free < a.min_free_gb * 2 ** 30:
        log(MARK + "manifest " + json.dumps({"node": socket.gethostname(), "mode": "sos", "error":
                                             f"only {free / 2 ** 30:.1f} GB free in {tmp_root} (at least {a.min_free_gb} GB is needed)"}))
        return 3
    binary = shutil.which("sos")
    cmd = [binary, "report"] if binary else ([shutil.which("sosreport")] if shutil.which("sosreport") else None)
    if not cmd:
        log(MARK + "manifest " + json.dumps({"node": socket.gethostname(), "mode": "sos", "error": "sos is not installed (dnf install sos)"}))
        return 3
    work = tempfile.mkdtemp(prefix="wi-sos-", dir=tmp_root)

    def clean(*_args):
        shutil.rmtree(work, ignore_errors=True)
        sys.exit(4)
    for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGPIPE):
        signal.signal(sig, clean)
    cmd += ["--batch", "--tmp-dir", work, "--label", a.label]
    if a.case_id:
        cmd += ["--case-id", a.case_id]
    if a.all_logs:
        cmd += ["--all-logs"]
    log("$ " + " ".join(cmd))
    started = time.time()
    try:
        rc = subprocess.call(cmd, stdout=sys.stderr, stderr=sys.stderr, stdin=subprocess.DEVNULL)
        archives = [p for p in glob.glob(os.path.join(work, "sosreport-*.tar*")) if not p.endswith((".sha256", ".md5"))]
        if rc != 0 or not archives:
            log(MARK + "manifest " + json.dumps({"node": socket.gethostname(), "mode": "sos", "error": f"sos report ended with exit {rc}"
                                                 + ("" if archives else ", no archive")}))
            return 4
        path = archives[0]
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
                sys.stdout.buffer.write(chunk)
        sys.stdout.buffer.flush()
        log(MARK + "manifest " + json.dumps({"node": socket.gethostname(), "mode": "sos", "archive": os.path.basename(path),
                                             "bytes": os.path.getsize(path), "sha256": h.hexdigest(),
                                             "seconds": int(time.time() - started), "command": " ".join(cmd)}))
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main(argv=None):
    p = argparse.ArgumentParser(prog="wi_collect")
    sub = p.add_subparsers(dest="mode")
    lg = sub.add_parser("logs")
    lg.add_argument("--components", required=True)
    lg.add_argument("--since", required=True, type=int)
    lg.add_argument("--until", required=True, type=int)
    lg.add_argument("--max-mb", dest="max_mb", type=int, default=1024)
    lg.add_argument("--root", default="/")
    lg.add_argument("--tmp", default="/var/tmp")
    so = sub.add_parser("sos")
    so.add_argument("--label", required=True)
    so.add_argument("--case-id", dest="case_id", default="")
    so.add_argument("--all-logs", dest="all_logs", action="store_true")
    so.add_argument("--min-free-gb", dest="min_free_gb", type=int, default=5)
    so.add_argument("--tmp", default="/var/tmp")
    a = p.parse_args(argv)
    if a.mode == "logs":
        if not re.match(r"^[a-z,]{1,200}$", a.components) or not 1 <= a.max_mb <= 8192 or a.until <= a.since:
            log("invalid arguments")
            return 3
        return collect_logs(a)
    if a.mode == "sos":
        if not re.match(r"^[A-Za-z0-9]{1,30}$", a.label) or (a.case_id and not re.match(r"^\d{1,12}$", a.case_id)):
            log("invalid arguments")
            return 3
        return collect_sos(a)
    p.print_usage(sys.stderr)
    return 3


if __name__ == "__main__":
    sys.exit(main())

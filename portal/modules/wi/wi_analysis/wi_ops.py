#!/usr/bin/env python3
"""Changes of Operation Automation that take more than one command: they run ON THE OPENSTACK DIRECTOR as admin (after
`source overcloudrc`), one item (instance, volume or image) per call, start the change, watch it until it ends and fix
what can be fixed safely on the way.

wi_analysis.os_action_script embeds this file in the fix script (`python3 -c`, standard library only: Python 3.6 on
RHOSP 16.2, 3.9 on 17.1); the fake cloud of the tests runs it with its own runner, clock and sleep. The command line
was validated by wi_analysis.OPENSTACK_FIX before it got here and is validated again by parse():

  live-migrate <server> from <host> to <host|auto> try <hosts|-> timeout <s> stall <abort|force> nodes <host=ip,..|-> user <user|->
               [under <percent> ram <MB>]
  cold-migrate <server> from <host> to <host|auto> try <hosts|-> timeout <s> [nodes <host=ip,..|-> user <user|-> under <percent> ram <MB>]
  migrate-volume <volume> to <host@backend#pool> try <pools|-> timeout <s> snapshots <snapshot ids|->
  delete-image <image> expect <size0|any> snapshots <snapshot ids|->

Exit code: 0 done (or nothing left to do); 5 not done, but the item is healthy where it was, so the next item may run;
6 a person must look (the item is not in a clean state, or the platform itself fails): the fix stops there; 7 skipped
on purpose (no destination under the usage limit): the item stays where it is and the next item always runs.

Destination under a usage limit (under <percent> ram <MB>): right before the migration, the real CPU use (/proc/stat over
2 seconds) and memory use (MemTotal - MemAvailable, plus the RAM of this instance) of every enabled and up compute of
"nodes" are read on the computes themselves (ssh from the director, all at once); the instance goes to the least used
compute that stays under the limit for both, the next ones when it refuses. No such compute: the instance is not moved.
Every OpenStack command it runs is printed ("$ ..."), and so is every automatic fix ("Automatic fix: ..."); the last
line is "RESULT ok|failed|attention: ...".

Sources of the rules: Red Hat OpenStack Platform 17.1 "Configuring the Compute service for instance creation", chapter
Migrating virtual machine instances between Compute nodes (constraints, `openstack server migrate --live-migration
[--host]`, `server migration list/show/abort/force complete`, cold migration and `server resize confirm`); upstream nova
"Live-migrate instances" (progress = memory remaining, abort, force-complete pauses the instance); Red Hat "Migrating a
volume between back ends" (available or in-use, no snapshots, not in a group, not replicated, a multiattach volume on
one instance at most) and the WI "Rollback Volume Type" (the temporary copy of a failed migration: reset-state, delete).

What is fixed automatically:
  live migration  the destination refuses it (no valid host, CPU not compatible, not enough resources, compute down,
                  pre-check error): the instance stays on its source, the next destination is tried (3 at most);
                  it does not finish within the timeout: abort (the instance stays on its source) or, with stall force,
                  force-complete (the instance pauses until the copy ends);
                  the instance is left in ERROR, or in MIGRATING without a running migration: reset to ACTIVE only when
                  virsh shows its domain running on the compute Nova records and on no other compute that was involved
  cold migration  the destination refuses it: next destination; VERIFY_RESIZE is confirmed
  volume          snapshots: the ones approved in the check are deleted first (a volume with snapshots cannot migrate);
                  a new snapshot stops it; a snapshot left in error_deleting is reset to available and deleted once more;
                  migration error: the temporary copy (migration_status target:<volume>) is reset and deleted, then the
                  next pool is tried (no other pool: the same one once more)
  image           checked again (not protected, not used by an instance, still empty), deleted, then the volume
                  snapshots of a snapshot image (block_device_mapping) are deleted
"""
import json
import re
import shlex
import subprocess
import sys
import time

OK, FAILED, ATTENTION, SKIPPED = 0, 5, 6, 7
LABEL = {OK: "ok", FAILED: "failed", ATTENTION: "attention", SKIPPED: "skipped"}
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
POOL_RE = re.compile(r"^[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+#[A-Za-z0-9_.-]+$")
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
INSTANCE_RE = re.compile(r"^instance-[0-9a-f]{8}$")
USERS = ("heat-admin", "tripleo-admin")
SSH = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=no",
       "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR"]
NOVA_LIVE = "2.30"   # live migration to a host the scheduler checks; server migration show / abort / force complete
NOVA_COLD = "2.56"   # cold migration to a given host
MAX_ATTEMPTS = 3
LIVE_ACTIONS = ("live-migration", "live_migration")
COLD_ACTIONS = ("migrate", "resize")
# The destination refused the migration (the instance stays where it is): another destination may accept it.
DESTINATION = re.compile(
    r"no valid host|novalidhost|migrationprecheckerror|migration pre-check error|cpu doesn'?t have compatibility"
    r"|unacceptable cpu info|invalidcpuinfo|not compatible with|incompatible cpu|computeresourcesunavailable"
    r"|insufficient compute resources|computeserviceunavailable|is not up|unavailable at this time|destinationdiskexists"
    r"|migrationschedulerrpcerror|unabletomigratetoself|destinationhypervisortooold|invalidhypervisortype"
    r"|messagingtimeout|timed out waiting for a reply|no valid backend|not enough space|insufficient free space"
    r"|capacityfilter|reached the limit", re.I)
# Problems of the platform itself (the same failure on every destination): a person checks them.
PLATFORM = re.compile(
    r"host key verification failed|permission denied|connection refused|unable to connect to server|cannot recv data"
    r"|nova_migration|port 2022|unable to attach|os_brick|os-brick|iscsi|multipath|binding failed|portbindingfailed"
    r"|portupdatefailed|keystone|token", re.I)


class Done(Exception):
    """The end of one item: exit code and the RESULT line."""

    def __init__(self, rc, message):
        Exception.__init__(self, message)
        self.rc, self.message = rc, message


def short(host):
    return str(host or "").split(".")[0].lower()


def first_line(text, limit=300):
    for line in str(text or "").splitlines():
        line = line.strip()
        if line and not line.startswith("$ "):
            return line[:limit]
    return ""


def last_error(text):
    """The most useful line of a traceback or an error text: the last line naming an exception or an error."""
    lines = [l.strip() for l in str(text or "").splitlines() if l.strip()]
    for line in reversed(lines):
        if re.search(r"(Error|Exception|error|refused|failed|Failed)", line) and not line.startswith(("File ", "Traceback")):
            return line[:400]
    return (lines[-1] if lines else "")[:400]


def minutes(seconds):
    seconds = int(max(0, seconds))
    return f"{seconds // 60} min {seconds % 60} s" if seconds >= 60 else f"{seconds} s"


def nonempty(value):
    return value not in (None, "", "None", "none", "-", "null")


def field(d, *names):
    for name in names:
        if isinstance(d, dict) and nonempty(d.get(name)):
            return d.get(name)
    return ""


def table(text):
    """Rows of a client text table ("| a | b |"), keyed by lower-case header names with "_" for spaces; a two-column
    Property / Value table also gives {property: value} as the single row "properties"."""
    header, rows, props = None, [], {}
    for line in str(text or "").splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if header is None:
            header = [re.sub(r"\s+", "_", c.lower()) for c in cells]
            continue
        if len(cells) == len(header):
            row = dict(zip(header, cells))
            rows.append(row)
            if header[:2] == ["property", "value"]:
                props[row["property"].lower().replace(" ", "_")] = row["value"]
    return rows, props


def lower_keys(d):
    return {re.sub(r"[\s-]+", "_", str(k).lower()): v for k, v in (d or {}).items()} if isinstance(d, dict) else {}


# ---------------------------------------------------------------- parsing of the command line
def _hosts(value):
    if value == "-":
        return []
    items = value.split(",")
    if not all(HOST_RE.match(h) for h in items):
        raise ValueError(f"invalid host list {value!r}")
    return items


def _pools(value):
    if value == "-":
        return []
    items = value.split(",")
    if not all(POOL_RE.match(p) for p in items):
        raise ValueError(f"invalid pool list {value!r}")
    return items


def _ids(value):
    if value == "-":
        return []
    items = value.split(",")
    if not all(UUID_RE.match(i) for i in items):
        raise ValueError(f"invalid ID list {value!r}")
    return items


def _nodes(value):
    if value == "-":
        return {}
    out = {}
    for pair in value.split(","):
        host, _, ip = pair.partition("=")
        if not HOST_RE.match(host) or not IP_RE.match(ip):
            raise ValueError(f"invalid node address {pair!r}")
        out[short(host)] = ip
    return out


def _seconds(value):
    if not value.isdigit() or not 10 <= int(value) <= 86400:
        raise ValueError(f"invalid timeout {value!r}")
    return int(value)


def _one_of(*options):
    def check(value):
        if value not in options:
            raise ValueError(f"{value!r} is not one of {', '.join(options)}")
        return value
    return check


def _host(value):
    if not HOST_RE.match(value):
        raise ValueError(f"invalid host {value!r}")
    return value


def _host_or_auto(value):
    return value if value == "auto" else _host(value)


def _pool(value):
    if not POOL_RE.match(value):
        raise ValueError(f"invalid pool {value!r}")
    return value


def _user(value):
    if value != "-" and value not in USERS:
        raise ValueError(f"invalid overcloud user {value!r}")
    return "" if value == "-" else value


def _percent(value):
    if not value.isdigit() or not 10 <= int(value) <= 99:
        raise ValueError(f"invalid usage limit {value!r}")
    return int(value)


def _mb(value):
    if not value.isdigit() or len(value) > 8:
        raise ValueError(f"invalid RAM {value!r}")
    return int(value)


# A trailing part of a grammar may be left out (command lines of results made before it existed): OPTIONAL gives the
# value of each keyword then.
OPTIONAL = {"nodes": {}, "user": "", "under": 0, "ram": 0}
GRAMMAR = {
    "live-migrate": [("from", _host), ("to", _host_or_auto), ("try", _hosts), ("timeout", _seconds),
                     ("stall", _one_of("abort", "force")), ("nodes", _nodes), ("user", _user), ("under", _percent), ("ram", _mb)],
    "cold-migrate": [("from", _host), ("to", _host_or_auto), ("try", _hosts), ("timeout", _seconds), ("nodes", _nodes),
                     ("user", _user), ("under", _percent), ("ram", _mb)],
    "migrate-volume": [("to", _pool), ("try", _pools), ("timeout", _seconds), ("snapshots", _ids)],
    "delete-image": [("expect", _one_of("size0", "any")), ("snapshots", _ids)],
}


def parse(argv):
    """{"verb", "id", <keyword>: value} of a command line; ValueError when anything is not exactly as GRAMMAR says."""
    argv = list(argv)
    if len(argv) < 2 or argv[0] not in GRAMMAR:
        raise ValueError("unknown operation " + " ".join(argv[:1]))
    if not UUID_RE.match(argv[1]):
        raise ValueError(f"invalid ID {argv[1]!r}")
    spec = GRAMMAR[argv[0]]
    given = (len(argv) - 2) // 2
    if len(argv) % 2 or given > len(spec) or any(k not in OPTIONAL for k, _ in spec[given:]):
        raise ValueError(f"{argv[0]}: wrong number of arguments")
    out = {"verb": argv[0], "id": argv[1]}
    for i, (key, check) in enumerate(spec):
        if i >= given:
            out[key] = OPTIONAL[key]
            continue
        word, value = argv[2 + 2 * i], argv[3 + 2 * i]
        if word != key:
            raise ValueError(f"{argv[0]}: expected {key!r}, got {word!r}")
        out[key] = check(value)
    if out.get("under") and not out.get("nodes"):
        raise ValueError(f"{argv[0]}: under needs the nodes to measure")
    return out


# ---------------------------------------------------------------- the clients on the director
class Director:
    """Runs the OpenStack clients (and ssh to the overcloud nodes) on the director. runner(argv, timeout) -> (rc, output);
    clock() -> seconds; sleep(seconds); write(line)."""

    def __init__(self, runner=None, clock=None, sleep=None, write=None):
        self.runner = runner or self._subprocess
        self.clock = clock or time.time
        self.sleep = sleep or time.sleep
        self.write = write or self._print
        self._modern = None
        self.names = {}

    @staticmethod
    def _print(line):
        sys.stdout.write(line + "\n")
        sys.stdout.flush()

    @staticmethod
    def _subprocess(argv, timeout):
        try:
            proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        except OSError as e:
            return 127, str(e)
        try:
            out, _ = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            return 124, f"no answer after {timeout} s"
        return proc.returncode, out

    def say(self, text):
        self.write(str(text))

    def run(self, argv, show=True, lines=6, timeout=900):
        """Run one command; show: print it ("$ ...") with the first lines of its output (and its exit code if not 0)."""
        if show:
            self.say("$ " + " ".join(shlex.quote(str(a)) for a in argv))
        rc, out = self.runner([str(a) for a in argv], timeout)
        out = str(out or "").strip()
        if show and lines and out:
            text = out.splitlines()
            for line in text[:lines]:
                self.say("  " + line[:300])
            if len(text) > lines:
                self.say(f"  … ({len(text) - lines} more lines)")
        if show and rc != 0:
            self.say(f"  (exit {rc})")
        return rc, out

    def read(self, argv, show=False, timeout=900):
        """A read with -f json: (value or None, rc, output); shown as the command only (the JSON stays out of the log)."""
        rc, out = self.run(list(argv) + ["-f", "json"], show=show, lines=0, timeout=timeout)
        if rc != 0:
            return None, rc, out
        try:
            return json.loads(out), rc, out
        except ValueError:
            return None, 1, out

    # ---- client generation: python-openstackclient 5.5 (RHOSP 17.1) has server migration list / show / abort / force
    # complete and server migrate --live-migration --host; older clients (4.0 on RHOSP 16.2) use the nova client.
    def modern(self):
        if self._modern is None:
            rc, out = self.run(["openstack", "--version"], show=False)
            m = re.search(r"(\d+)\.(\d+)", out or "")
            self._modern = bool(m) and (int(m.group(1)), int(m.group(2))) >= (5, 5)
        return self._modern

    # ---- compute
    def server(self, sid, show=False):
        """The instance as Nova sees it now, None when it does not exist, {"unknown": reason} when the API failed."""
        value, rc, out = self.read(["openstack", "server", "show", sid], show=show)
        if rc != 0 or not isinstance(value, dict):
            if re.search(r"no server|could not be found|not found", out or "", re.I):
                return None
            return {"unknown": first_line(out) or f"exit {rc}"}
        fault = value.get("fault")
        return {"name": str(value.get("name") or sid), "status": str(value.get("status") or "").upper(),
                "task": str(field(value, "OS-EXT-STS:task_state", "task_state")).lower(),
                "host": str(field(value, "OS-EXT-SRV-ATTR:host", "compute_host", "host")),
                "instance": str(field(value, "OS-EXT-SRV-ATTR:instance_name", "instance_name")),
                "fault": str((fault or {}).get("message") if isinstance(fault, dict) else fault or "")}

    def computes(self):
        """{short host: (status, state)} of nova-compute (self.names: {short host: host as nova names it})."""
        value, rc, _ = self.read(["openstack", "compute", "service", "list", "--service", "nova-compute"])
        out, self.names = {}, {}
        for s in value or []:
            if isinstance(s, dict):
                host = str(s.get("Host") or s.get("host") or "")
                out[short(host)] = (str(s.get("Status") or s.get("status") or "").lower(),
                                    str(s.get("State") or s.get("state") or "").lower())
                self.names[short(host)] = host
        return out

    def usage(self, nodes, user):
        """{short host: {"cpu": %, "used_kb", "total_kb"} or {"error": why}} of the computes (ssh from the director, all at
        once): the CPU use over 2 seconds (/proc/stat) and the memory in use (MemTotal - MemAvailable)."""
        import threading
        out = {}

        def one(host, ip):
            rc, text = self.runner(SSH + [f"{user}@{ip}", USAGE_COMMAND], 60)
            out[host] = parse_usage(text) if rc == 0 else None
            if out[host] is None:
                out[host] = {"error": first_line(text) or f"exit {rc}"}
        threads = [threading.Thread(target=one, args=(h, ip)) for h, ip in nodes.items()]
        for t in threads:
            t.start()
        for t in threads:
            t.join(90)
        return {h: out.get(h) or {"error": "no answer"} for h in nodes}

    def migrations(self, sid):
        """Migrations of an instance, newest first: [{"id", "status", "type", "dest", "source", "created"}]."""
        if self.modern():
            value, rc, _ = self.read(["openstack", "--os-compute-api-version", NOVA_LIVE, "server", "migration", "list",
                                      "--server", sid])
            rows = [lower_keys(x) for x in value or [] if isinstance(x, dict)]
        else:
            rc, out = self.run(["nova", "--os-compute-api-version", NOVA_LIVE, "migration-list", "--instance-uuid", sid],
                               show=False)
            rows = table(out)[0] if rc == 0 else []
        found = []
        for r in rows:
            mid = str(r.get("id") or "")
            if not mid.isdigit():
                continue
            found.append({"id": int(mid), "status": str(r.get("status") or "").lower(),
                          "type": str(r.get("migration_type") or r.get("type") or "").lower(),
                          "dest": str(r.get("dest_compute") or ""), "source": str(r.get("source_compute") or ""),
                          "created": str(r.get("created_at") or "")})
        return sorted(found, key=lambda m: -m["id"])

    def memory_left(self, sid, mid):
        """Bytes of memory still to copy in a running live migration (None when unknown)."""
        if self.modern():
            value, rc, _ = self.read(["openstack", "--os-compute-api-version", NOVA_LIVE, "server", "migration", "show",
                                      sid, str(mid)])
            props = lower_keys(value) if isinstance(value, dict) else {}
        else:
            rc, out = self.run(["nova", "--os-compute-api-version", NOVA_LIVE, "server-migration-show", sid, str(mid)],
                               show=False)
            props = table(out)[1] if rc == 0 else {}
        for key, val in props.items():
            if "memory" in key and "remaining" in key and str(val).isdigit():
                return int(val)
        return None

    def live_start(self, sid, host):
        if self.modern():
            return self.run(["openstack", "--os-compute-api-version", NOVA_LIVE, "server", "migrate", "--live-migration"]
                            + (["--host", host] if host else []) + [sid])
        return self.run(["nova", "--os-compute-api-version", NOVA_LIVE, "live-migration", sid] + ([host] if host else []))

    def cold_start(self, sid, host):
        if self.modern():
            return self.run(["openstack", "--os-compute-api-version", NOVA_COLD, "server", "migrate"]
                            + (["--host", host] if host else []) + [sid])
        return self.run(["nova", "--os-compute-api-version", NOVA_COLD, "migrate"] + (["--host", host] if host else []) + [sid])

    def confirm(self, sid):
        if self.modern():
            return self.run(["openstack", "server", "resize", "confirm", sid])
        return self.run(["openstack", "server", "resize", "--confirm", sid])

    def abort(self, sid, mid):
        if self.modern():
            return self.run(["openstack", "--os-compute-api-version", NOVA_LIVE, "server", "migration", "abort", sid, str(mid)])
        return self.run(["nova", "--os-compute-api-version", NOVA_LIVE, "live-migration-abort", sid, str(mid)])

    def force_complete(self, sid, mid):
        if self.modern():
            return self.run(["openstack", "--os-compute-api-version", NOVA_LIVE, "server", "migration", "force", "complete",
                             sid, str(mid)])
        return self.run(["nova", "--os-compute-api-version", NOVA_LIVE, "live-migration-force-complete", sid, str(mid)])

    def diagnose(self, sid, actions):
        """Why the last of these instance actions failed: the error lines of its events (admins see the traceback)."""
        events, rc, _ = self.read(["openstack", "server", "event", "list", sid])
        if not isinstance(events, list):
            return ""
        wanted = [e for e in events if isinstance(e, dict) and str(e.get("Action") or e.get("action") or "") in actions]
        if not wanted:
            return ""
        latest = max(wanted, key=lambda e: str(e.get("Start Time") or e.get("start_time") or ""))
        req = str(latest.get("Request ID") or latest.get("request_id") or "")
        if not req:
            return ""
        detail, rc, _ = self.read(["openstack", "server", "event", "show", sid, req], show=True)
        texts = []
        for e in (detail or {}).get("events") or []:
            if isinstance(e, dict) and str(e.get("result") or "").lower() in ("error", "failed"):
                texts.append(f"{e.get('event') or ''}: {last_error(e.get('traceback') or e.get('details') or '')}".strip(": "))
        return "\n".join(texts)

    def domain_state(self, ip, user, instance):
        """virsh domstate of an instance on an overcloud node (ssh through the director, as TripleO does): running,
        "shut off", absent (not defined there) or unknown: <why>."""
        inner = ("c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$'); "
                 "[ -n \"$c\" ] || { echo 'no libvirt container'; exit 7; }; "
                 f"podman exec \"$c\" virsh -c qemu:///system domstate {instance}")
        self.say(f"$ ssh {user}@{ip} sudo podman exec <nova_virtqemud|nova_libvirt> virsh domstate {instance}")
        rc, out = self.run(SSH + [f"{user}@{ip}", "sudo -n sh -c " + shlex.quote(inner)], show=False, timeout=120)
        text = (out or "").strip().lower()
        if rc == 0 and text:
            state = text.splitlines()[-1].strip()
        elif "failed to get domain" in text or "domain not found" in text:
            state = "absent"
        else:
            state = "unknown: " + (first_line(out) or f"exit {rc}")
        self.say(f"  {state}")
        return state

    def reset_active(self, sid):
        return self.run(["openstack", "server", "set", "--state", "active", sid])

    # ---- block storage and images
    def volume(self, vid, show=False):
        value, rc, out = self.read(["openstack", "volume", "show", vid], show=show)
        if rc != 0 or not isinstance(value, dict):
            if re.search(r"no volume|could not be found|not found", out or "", re.I):
                return None
            return {"unknown": first_line(out) or f"exit {rc}"}
        return {"name": str(value.get("name") or vid), "status": str(value.get("status") or "").lower(),
                "migstat": str(field(value, "migration_status", "os-vol-mig-status-attr:migstat")).lower(),
                "host": str(field(value, "os-vol-host-attr:host", "host")),
                "attachments": value.get("attachments") or [],
                "multiattach": str(value.get("multiattach")).lower() == "true",
                "group": str(field(value, "group_id", "consistencygroup_id")),
                "replication": str(field(value, "replication_status")).lower()}

    def snapshots_of(self, vid):
        value, rc, _ = self.read(["openstack", "volume", "snapshot", "list", "--all-projects", "--volume", vid], show=True)
        if rc != 0:
            raise Done(ATTENTION, "the snapshots of the volume could not be listed: nothing was changed")
        return [{"id": str(s.get("ID") or s.get("id")), "status": str(s.get("Status") or s.get("status") or "").lower(),
                 "name": str(s.get("Name") or s.get("name") or "")}
                for s in value or [] if isinstance(s, dict) and str(s.get("Volume") or s.get("volume_id") or vid) == vid]

    def snapshot(self, sid):
        value, rc, out = self.read(["openstack", "volume", "snapshot", "show", sid])
        if rc != 0 or not isinstance(value, dict):
            return None if re.search(r"no snapshot|could not be found|not found", out or "", re.I) else {"status": "unknown"}
        return {"status": str(value.get("status") or "").lower(), "name": str(value.get("name") or "")}

    def wait(self, check, timeout, every=15):
        """Poll check() (True: done) every `every` seconds up to timeout; True when done."""
        end = self.clock() + timeout
        while True:
            if check():
                return True
            if self.clock() >= end:
                return False
            self.sleep(every)


# ---------------------------------------------------------------- live migration
USAGE_COMMAND = ("head -n 1 /proc/stat; grep -E '^(MemTotal|MemAvailable):' /proc/meminfo; sleep 2; head -n 1 /proc/stat")


def parse_usage(text):
    """The output of USAGE_COMMAND -> {"cpu": % busy over the 2 seconds, "used_kb", "total_kb"}, or None."""
    cpu = [list(map(int, l.split()[1:])) for l in str(text or "").splitlines() if re.match(r"^cpu\s+\d", l)]
    mem = dict(re.findall(r"^(MemTotal|MemAvailable):\s+(\d+)", str(text or ""), re.M))
    if len(cpu) < 2 or "MemTotal" not in mem or "MemAvailable" not in mem or int(mem["MemTotal"]) <= 0:
        return None
    a, b = cpu[0], cpu[-1]
    idle = lambda v: v[3] + (v[4] if len(v) > 4 else 0)   # noqa: E731  idle + iowait
    total = sum(b) - sum(a)
    busy = total - (idle(b) - idle(a))
    total_kb, avail_kb = int(mem["MemTotal"]), int(mem["MemAvailable"])
    return {"cpu": round(100.0 * busy / total, 1) if total > 0 else 0.0, "used_kb": total_kb - avail_kb, "total_kb": total_kb}


def destinations(d, a, name, src, services):
    """The computes under the usage limit for this instance, the least used first (Done SKIPPED when none)."""
    limit, ram_kb = a["under"], a["ram"] * 1024
    if a["to"] != "auto":
        pool = {short(a["to"]): a["nodes"].get(short(a["to"]))}
    else:
        pool = {h: ip for h, ip in a["nodes"].items() if h != src and services.get(h) == ("enabled", "up")}
    unmeasured = [h for h, ip in pool.items() if not ip]
    pool = {h: ip for h, ip in pool.items() if ip}
    d.say(f"Usage of {len(pool)} compute(s) now (real use, read on each compute; RAM with the {a['ram'] // 1024} GiB of {name}), "
          f"limit {limit}% for CPU and RAM:")
    found = d.usage(pool, a["user"] or "heat-admin") if pool else {}
    ok, why = [], []
    for h in sorted(found):
        u = found[h]
        if "error" in u:
            d.say(f"  {h}: not measured ({u['error']})")
            why.append(f"{h} not measured")
            continue
        ram = round(100.0 * (u["used_kb"] + ram_kb) / u["total_kb"], 1)
        fits = u["cpu"] < limit and ram < limit
        d.say(f"  {h}: CPU {u['cpu']:g}%, RAM {ram:g}% -> {'can take it' if fits else 'over the limit'}")
        if fits:
            ok.append((max(u["cpu"], ram), h))
        else:
            why.append(f"{h} CPU {u['cpu']:g}% RAM {ram:g}%")
    for h in unmeasured:
        why.append(f"{h} has no ctlplane address")
    if not ok:
        raise Done(SKIPPED, f"not moved: no compute stays under {limit}% CPU and RAM with {name} "
                            f"({'; '.join(why[:6]) or 'no enabled and up compute'}). {name} stays on {a['from']}")
    ok.sort()
    return [d.names.get(h, h) for _, h in ok]


def live_migrate(d, a):
    sid, src = a["id"], short(a["from"])
    s = d.server(sid, show=True)
    if s is None:
        raise Done(OK, "the instance no longer exists: nothing to do")
    if s.get("unknown"):
        raise Done(ATTENTION, f"the instance could not be read ({s['unknown']}): nothing was changed")
    name = s["name"]
    d.say(f"{name}: status {s['status']}, task {s['task'] or '-'}, on {s['host'] or '-'}")
    if short(s["host"]) != src:
        if s["status"] in ("ACTIVE", "PAUSED") and not s["task"]:
            raise Done(OK, f"{name} is already on {s['host']}: nothing to do")
        raise Done(FAILED, f"{name} is on {s['host'] or 'no compute'} with status {s['status']}, not on {a['from']}: "
                           "nothing was changed")
    if s["status"] not in ("ACTIVE", "PAUSED") or s["task"]:
        raise Done(FAILED, f"{name} is {s['status']}{' (' + s['task'] + ')' if s['task'] else ''}: a live migration needs "
                           "ACTIVE without a running task; nothing was changed")
    services = d.computes()
    if a.get("under"):
        targets = destinations(d, a, name, src, services)
    else:
        targets = ([None] if a["to"] == "auto" else [a["to"]]) + [h for h in a["try"] if short(h) not in (short(a["to"]), src)]
    last, tried = "", 0
    for target in targets:
        if tried >= MAX_ATTEMPTS:
            break
        if target and services.get(short(target)) != ("enabled", "up"):
            d.say(f"Skip {target}: nova-compute is {'/'.join(services.get(short(target)) or ('not listed',))}")
            continue
        tried += 1
        d.say(f"Attempt {tried}: live migration of {name} to {target or 'a compute chosen by the scheduler'}")
        started = d.clock()
        rc, out = d.live_start(sid, target)
        if rc != 0:
            last = last_error(out) or f"exit {rc}"
            if DESTINATION.search(out or ""):
                d.say(f"Automatic fix: the destination refused it ({last}); {name} did not move, the next destination is tried")
                continue
            raise Done(FAILED, f"the live migration was refused: {last}. Nothing changed: {name} is still on {a['from']}")
        outcome, info = watch_live(d, a, sid, src, started)
        if outcome == "done":
            raise Done(OK, f"{name} is on {info} (live migration took {minutes(d.clock() - started)})")
        if outcome == "gone":
            raise Done(OK, f"{name} was deleted during the migration: nothing left to do")
        if outcome == "back":
            why = d.diagnose(sid, LIVE_ACTIONS) or info
            last = last_error(why) or info
            if info.startswith("aborted"):
                raise Done(FAILED, f"{info}; {name} keeps running on {a['from']}. Try again outside busy hours, or with "
                                   "stall force (pauses the instance until the copy ends)")
            if DESTINATION.search(why or "") and not PLATFORM.search(why or ""):
                d.say(f"Automatic fix: the destination refused it ({last}); {name} is back on {a['from']}, the next destination is tried")
                continue
            hint = " The compute nodes cannot reach each other for the migration (SSH on port 2022, libvirt, storage or " \
                   "network binding): check nova_migration_target and the nova-compute log of both computes." \
                if PLATFORM.search(why or "") else ""
            raise Done(FAILED, f"the live migration failed and was rolled back: {last}. {name} keeps running on {a['from']}.{hint}")
        recover(d, a, sid, info)   # error / stuck: ends with Done
    raise Done(FAILED, f"no destination accepted {name}: {last or 'no enabled and up compute in the list'}. It keeps running "
                       f"on {a['from']}")


def watch_live(d, a, sid, src, started):
    """Follow a live migration: ("done", host), ("back", why), ("error", fault), ("stuck", why) or ("gone", "")."""
    acted, unknown, reported, last_left, mig = "", 0, started, None, None
    while True:
        elapsed = d.clock() - started
        d.sleep(10 if elapsed < 300 else 20 if elapsed < 1800 else 30)
        elapsed = d.clock() - started
        s = d.server(sid)
        if s is None:
            return "gone", ""
        if s.get("unknown"):
            unknown += 1
            if unknown >= 20:
                return "stuck", f"the API did not answer 20 times in a row ({s['unknown']})"
            continue
        unknown = 0
        if s["status"] in ("ACTIVE", "PAUSED") and not s["task"]:
            if short(s["host"]) != src:
                return "done", s["host"]
            migs = [m for m in d.migrations(sid) if m["type"] in ("", "live-migration")]
            latest = migs[0] if migs else None
            if latest and latest["status"] in ("error", "failed", "cancelled", "aborted"):
                return "back", (f"aborted after {minutes(a['timeout'])} (timeout)" if acted == "abort"
                                else f"migration {latest['id']} ended {latest['status']}")
            if elapsed >= 180:
                return "back", ("aborted after the timeout" if acted == "abort" else
                                f"no migration started or it ended {latest['status'] if latest else 'without a record'}")
            continue   # accepted, not yet started
        if s["status"] == "ERROR":
            return "error", s["fault"] or "status ERROR"
        if s["status"] != "MIGRATING" and s["task"] not in ("migrating",):
            if elapsed > a["timeout"] + 900:
                return "stuck", f"status {s['status']} task {s['task'] or '-'}"
            continue
        if mig is None or d.clock() - reported >= 120:
            migs = [m for m in d.migrations(sid) if m["type"] in ("", "live-migration")]
            running = [m for m in migs if m["status"] in ("queued", "preparing", "running", "post-migrating", "accepted")]
            mig = running[0] if running else None
            if not running and migs and migs[0]["status"] in ("error", "failed") and elapsed > 300:
                return "stuck", f"MIGRATING while migration {migs[0]['id']} is {migs[0]['status']}"
            if mig and d.clock() - reported >= 120:
                left = d.memory_left(sid, mig["id"])
                trend = "" if left is None or last_left is None else " (not decreasing)" if left >= last_left else ""
                d.say(f"  {minutes(elapsed)}: migration {mig['id']} {mig['status']}"
                      + (f", {left / 2 ** 30:.2f} GiB memory left{trend}" if left is not None else ""))
                last_left, reported = left, d.clock()
        if elapsed > a["timeout"] and not acted:
            if mig:
                if a["stall"] == "force":
                    d.say(f"Automatic fix: not finished after {minutes(a['timeout'])}: force-complete (the instance pauses "
                          "until the memory copy ends)")
                    d.force_complete(sid, mig["id"])
                    acted = "force"
                else:
                    d.say(f"Automatic fix: not finished after {minutes(a['timeout'])}: abort (the instance stays on its source)")
                    d.abort(sid, mig["id"])
                    acted = "abort"
            else:
                acted = "none"
        if elapsed > a["timeout"] + 900:
            return "stuck", f"still MIGRATING {minutes(elapsed)} after the start" + (f" ({acted} sent)" if acted else "")


def recover(d, a, sid, why):
    """An instance left in ERROR, or MIGRATING without a running migration: reset it to ACTIVE only when its domain runs
    on the compute Nova records and on no other compute involved (virsh through the director). Ends with Done."""
    s = d.server(sid, show=True) or {}
    if s.get("status") in ("ACTIVE", "PAUSED") and not s.get("task"):
        if short(s.get("host")) != short(a["from"]):
            raise Done(OK, f"{s.get('name')} is on {s.get('host')}")
        raise Done(FAILED, f"{s.get('name')} is back on {a['from']} after: {why}")
    name, host, instance = s.get("name") or sid, s.get("host") or "", s.get("instance") or ""
    state = f"{s.get('status')}{' (' + s['task'] + ')' if s.get('task') else ''}"
    d.say(f"{name} is {state} on {host or '-'} after: {why}")
    involved = []
    dests = [m["dest"] for m in d.migrations(sid)[:1] if m["dest"]]   # where the scheduler sent it (destination "auto")
    for h in [host, a["from"]] + dests + ([] if dests else [a["to"]]):
        if h and h != "auto" and short(h) not in [short(x) for x in involved]:
            involved.append(h)
    if not a["nodes"] or not a["user"] or not INSTANCE_RE.match(instance) or not host:
        raise Done(ATTENTION, f"{name} is left {state} on {host or 'no compute'} and the portal cannot check where its "
                              f"domain runs (no overcloud node addresses). Check with virsh domstate {instance or '<instance>'} "
                              f"on {', '.join(involved)}; reset it to ACTIVE (openstack server set --state active {sid}) "
                              "only if it runs on the compute Nova records.")
    states = {}
    for h in involved:
        ip = a["nodes"].get(short(h))
        states[short(h)] = d.domain_state(ip, a["user"], instance) if ip else "unknown: no address"
    shown = ", ".join(f"{h}: {st}" for h, st in states.items())
    running = [h for h, st in states.items() if st == "running"]
    unknown = [h for h, st in states.items() if st.startswith("unknown") and h != short(host)]
    if running == [short(host)] and not unknown:
        if s.get("status") == "MIGRATING":
            busy = [m for m in d.migrations(sid) if m["status"] in ("queued", "preparing", "running", "post-migrating")]
            if busy:
                raise Done(ATTENTION, f"{name} is still migrating (migration {busy[0]['id']} {busy[0]['status']}) after the "
                                      "timeout: nothing was reset. Follow it with openstack server migration list")
        d.say(f"Automatic fix: virsh shows {instance} running on {host} only ({shown}): reset {name} to ACTIVE")
        rc, out = d.reset_active(sid)
        after = d.server(sid, show=True) or {}
        if rc != 0 or after.get("status") != "ACTIVE":
            raise Done(ATTENTION, f"reset to ACTIVE did not work ({last_error(out) or after.get('status')}): check {name}")
        if short(after.get("host")) != short(a["from"]):
            raise Done(OK, f"{name} reset to ACTIVE on {after.get('host')} (it runs there; the migration had finished)")
        raise Done(FAILED, f"{name} reset to ACTIVE on {a['from']}, where it keeps running; it was not migrated ({last_error(why)})")
    raise Done(ATTENTION, f"{name} is left {state}; virsh: {shown}. Nothing was reset: the domain does not run on the compute "
                          f"Nova records ({host}) alone. Check both computes and the nova-compute logs before any reset "
                          "(Red Hat support if the domain runs elsewhere)")


# ---------------------------------------------------------------- cold migration (instances that are shut off)
def cold_migrate(d, a):
    sid, src = a["id"], short(a["from"])
    s = d.server(sid, show=True)
    if s is None:
        raise Done(OK, "the instance no longer exists: nothing to do")
    if s.get("unknown"):
        raise Done(ATTENTION, f"the instance could not be read ({s['unknown']}): nothing was changed")
    name = s["name"]
    if short(s["host"]) != src:
        if s["status"] == "SHUTOFF" and not s["task"]:
            raise Done(OK, f"{name} is already on {s['host']}: nothing to do")
        raise Done(FAILED, f"{name} is on {s['host'] or 'no compute'} with status {s['status']}: nothing was changed")
    if s["status"] != "SHUTOFF" or s["task"]:
        raise Done(FAILED, f"{name} is {s['status']}: a cold migration here is only for instances that are SHUTOFF; "
                           "nothing was changed")
    services = d.computes()
    if a.get("under"):
        targets = destinations(d, a, name, src, services)
    else:
        targets = ([None] if a["to"] == "auto" else [a["to"]]) + [h for h in a["try"] if short(h) not in (short(a["to"]), src)]
    last, tried = "", 0
    for target in targets:
        if tried >= MAX_ATTEMPTS:
            break
        if target and services.get(short(target)) != ("enabled", "up"):
            d.say(f"Skip {target}: nova-compute is {'/'.join(services.get(short(target)) or ('not listed',))}")
            continue
        tried += 1
        d.say(f"Attempt {tried}: cold migration of {name} to {target or 'a compute chosen by the scheduler'}")
        started = d.clock()
        rc, out = d.cold_start(sid, target)
        if rc != 0:
            last = last_error(out) or f"exit {rc}"
            if DESTINATION.search(out or ""):
                d.say(f"Automatic fix: the destination refused it ({last}); the next destination is tried")
                continue
            raise Done(FAILED, f"the cold migration was refused: {last}. Nothing changed: {name} is on {a['from']}")
        state = {}

        def resized():
            s2 = d.server(sid)
            state["s"] = s2
            return s2 is None or (not s2.get("unknown") and (s2["status"] in ("VERIFY_RESIZE", "ERROR") or
                                                             (s2["status"] == "SHUTOFF" and not s2["task"]
                                                              and d.clock() - started > 60)))
        if not d.wait(resized, a["timeout"], 15):
            raise Done(ATTENTION, f"{name} did not reach VERIFY_RESIZE within {minutes(a['timeout'])}: check it "
                                  "(openstack server show, server migration list)")
        s2 = state["s"]
        if s2 is None:
            raise Done(OK, f"{name} was deleted during the migration: nothing left to do")
        if s2["status"] == "ERROR":
            raise Done(ATTENTION, f"{name} is in ERROR after the cold migration: {s2['fault'] or 'no fault message'}. "
                                  "It was shut off: check its disks on both computes before resetting its state")
        if s2["status"] == "SHUTOFF":   # rolled back to the source
            why = d.diagnose(sid, COLD_ACTIONS)
            last = last_error(why) or "rolled back"
            if DESTINATION.search(why or ""):
                d.say(f"Automatic fix: the destination refused it ({last}); the next destination is tried")
                continue
            raise Done(FAILED, f"the cold migration failed: {last}. {name} is still on {a['from']}")
        d.say(f"{name} is VERIFY_RESIZE on {s2['host']}: confirm the migration")
        rc, out = d.confirm(sid)
        if rc != 0:
            raise Done(ATTENTION, f"the migration of {name} could not be confirmed ({last_error(out)}): confirm or revert it "
                                  f"(openstack server resize confirm {sid})")
        done = {}

        def confirmed():
            s3 = d.server(sid)
            done["s"] = s3
            return s3 is None or (not s3.get("unknown") and s3["status"] in ("SHUTOFF", "ERROR") and not s3["task"])
        if not d.wait(confirmed, 600, 10) or (done["s"] or {}).get("status") != "SHUTOFF":
            raise Done(ATTENTION, f"{name} did not return to SHUTOFF after the confirmation: check it")
        raise Done(OK, f"{name} is on {done['s']['host']} (cold migration took {minutes(d.clock() - started)}; it stays shut off)")
    raise Done(FAILED, f"no destination accepted {name}: {last or 'no enabled and up compute in the list'}")


# ---------------------------------------------------------------- volume migration (Cinder)
def delete_snapshots(d, ids, label):
    """Delete these volume snapshots and wait until they are gone; one retry for error_deleting (reset to available).
    Returns the IDs that could not be deleted."""
    for sid in ids:
        d.run(["openstack", "volume", "snapshot", "delete", sid])
    left = list(ids)

    def gone():
        left[:] = [x for x in left if d.snapshot(x) is not None]
        return not left
    if d.wait(gone, 1800, 15):
        d.say(f"{len(ids)} snapshot(s) of {label} deleted")
        return []
    retry = [x for x in left if (d.snapshot(x) or {}).get("status") == "error_deleting"]
    for x in retry:
        d.say(f"Automatic fix: snapshot {x} is error_deleting: reset it to available and delete it once more")
        d.run(["cinder", "snapshot-reset-state", "--state", "available", x])
        d.run(["openstack", "volume", "snapshot", "delete", x])
    d.wait(gone, 900, 15)
    return left


def migrate_volume(d, a):
    vid = a["id"]
    v = d.volume(vid, show=True)
    if v is None:
        raise Done(OK, "the volume no longer exists: nothing to do")
    if v.get("unknown"):
        raise Done(ATTENTION, f"the volume could not be read ({v['unknown']}): nothing was changed")
    name = v["name"]
    d.say(f"{name}: {v['status']}, migration_status {v['migstat'] or '-'}, on {v['host']}")
    if v["host"].split("#")[-1] == a["to"].split("#")[-1]:
        raise Done(OK, f"{name} is already in {a['to']}: nothing to do")
    if v["status"] not in ("available", "in-use"):
        raise Done(FAILED, f"{name} is {v['status']}: only available or in-use volumes migrate; nothing was changed")
    if v["migstat"] in ("migrating", "starting", "completing") or v["migstat"].startswith("target:"):
        raise Done(FAILED, f"{name} has migration_status {v['migstat']}: a migration runs already; nothing was changed")
    if v["group"]:
        raise Done(FAILED, f"{name} belongs to a group ({v['group']}): volumes of a group cannot migrate; nothing was changed")
    if v["replication"] == "enabled":
        raise Done(FAILED, f"{name} is replicated: it cannot migrate; nothing was changed")
    if v["multiattach"] and len(v["attachments"]) > 1:
        raise Done(FAILED, f"{name} is attached to {len(v['attachments'])} instances: a multiattach volume migrates only "
                           "when attached to one at most; nothing was changed")
    snaps = d.snapshots_of(vid)
    extra = [s for s in snaps if s["id"] not in a["snapshots"]]
    if extra:
        raise Done(FAILED, f"{name} has snapshot(s) that were not approved in the check ({', '.join(s['name'] or s['id'] for s in extra[:5])}): "
                           "a volume with snapshots cannot migrate. Run the check again; nothing was changed")
    if snaps:
        d.say(f"{name} has {len(snaps)} approved snapshot(s): delete them first (a volume with snapshots cannot migrate)")
        left = delete_snapshots(d, [s["id"] for s in snaps], name)
        if left:
            raise Done(ATTENTION, f"snapshot(s) {', '.join(left)} of {name} could not be deleted: the volume was not migrated")
    targets = [a["to"]] + [p for p in a["try"] if p != a["to"]]
    if len(targets) == 1:   # no other pool: after a failure (temporary copy cleaned up) the same pool once more
        targets.append(a["to"])
    last = ""
    for n, target in enumerate(targets[:MAX_ATTEMPTS], 1):
        d.say(f"Attempt {n}: migrate {name} to {target}")
        started = d.clock()
        rc, out = d.run(["cinder", "migrate", vid, target])
        if rc != 0:
            last = last_error(out) or f"exit {rc}"
            if DESTINATION.search(out or "") and n < len(targets):
                d.say(f"Automatic fix: {target} refused it ({last}); the next pool is tried")
                continue
            raise Done(FAILED, f"cinder migrate was refused: {last}. Nothing changed: {name} stays in {v['host']}")
        state = {}

        def ended():
            v2 = d.volume(vid)
            state["v"] = v2
            if v2 is None or v2.get("unknown"):
                return v2 is None
            if v2["migstat"] in ("success", "error"):
                return True
            # Some clients clear migration_status at the end: the host tells.
            return v2["migstat"] in ("", "none") and d.clock() - started > 120
        if not d.wait(ended, a["timeout"], 30):
            raise Done(ATTENTION, f"{name} is still migrating after {minutes(a['timeout'])} (migration_status "
                                  f"{(state.get('v') or {}).get('migstat')}): a Cinder migration cannot be stopped safely. "
                                  "Leave it and follow it with Stuck instances and volumes")
        v2 = state["v"]
        if v2 is None:
            raise Done(OK, f"{name} was deleted during the migration")
        if v2["migstat"] == "success" or v2["host"].split("#")[-1] == target.split("#")[-1]:
            raise Done(OK, f"{name} is in {v2['host']} (migration took {minutes(d.clock() - started)})")
        last = f"migration_status {v2['migstat'] or 'cleared'}, still in {v2['host']}"
        d.say(f"The migration of {name} failed ({last})")
        cleanup_replica(d, vid)
        why = cinder_messages(d, vid)
        if why:
            last += f": {why}"
        if n < min(len(targets), MAX_ATTEMPTS):
            d.say("Automatic fix: the temporary copy was cleaned up; " + (
                "the same pool is tried once more" if targets[n] == target else f"{targets[n]} is tried next"))
    raise Done(FAILED, f"{name} could not be migrated: {last}. It stays in {v['host']}")


def cleanup_replica(d, vid):
    """The temporary copy a failed migration leaves (migration_status target:<volume>): reset and delete (WI Rollback
    Volume Type), only when it is not attached."""
    rc, out = d.run(["cinder", "list", "--all-tenants", "--fields", "id,name,status,os-vol-mig-status-attr:migstat"],
                    show=True, lines=0)
    rows = table(out)[0] if rc == 0 else []
    for r in rows:
        mig = str(r.get("os-vol-mig-status-attr:migstat") or r.get("migstat") or "").lower()
        rid = str(r.get("id") or "")
        if mig != f"target:{vid}" or not UUID_RE.match(rid):
            continue
        rep = d.volume(rid) or {}
        if rep.get("attachments"):
            d.say(f"The temporary copy {rid} is attached: not touched")
            continue
        d.say(f"Automatic fix: remove the temporary copy {rid} of the failed migration (WI Rollback Volume Type)")
        d.run(["cinder", "reset-state", "--state", "available", "--attach-status", "detached", "--reset-migration-status", rid])
        d.run(["cinder", "delete", rid])
        d.wait(lambda: d.volume(rid) is None, 600, 15)


def cinder_messages(d, vid):
    """The last user message Cinder kept for the volume (API 3.3), '' when none."""
    rc, out = d.run(["cinder", "--os-volume-api-version", "3.3", "message-list", "--resource_uuid", vid], show=True, lines=4)
    rows = table(out)[0] if rc == 0 else []
    texts = [str(r.get("user_message") or r.get("message") or "") for r in rows if r.get("user_message") or r.get("message")]
    return texts[-1][:300] if texts else ""


# ---------------------------------------------------------------- image housekeeping (Glance)
def delete_image(d, a):
    iid = a["id"]
    img, rc, out = d.read(["openstack", "image", "show", iid], show=True)
    if rc != 0 or not isinstance(img, dict):
        if re.search(r"no image|could not be found|not found", out or "", re.I):
            img = None
        else:
            raise Done(ATTENTION, f"the image could not be read ({first_line(out)}): nothing was changed")
    name = str((img or {}).get("name") or iid)
    if img is not None:
        if str(img.get("protected")).lower() == "true":
            raise Done(FAILED, f"{name} is protected: nothing was changed (unprotect it first if it really must go)")
        size = img.get("size")
        if a["expect"] == "size0" and nonempty(size) and str(size) != "0":
            raise Done(FAILED, f"{name} now has {size} bytes, not 0: nothing was changed")
        users, rc, out = d.read(["openstack", "server", "list", "--all-projects", "--image", iid], show=True)
        if rc != 0:
            raise Done(ATTENTION, f"the instances using {name} could not be listed ({first_line(out)}): nothing was changed")
        if users:
            raise Done(FAILED, f"{name} is used by {len(users)} instance(s) ({', '.join(str(u.get('Name')) for u in users[:5])}): "
                               "nothing was changed")
        rc, out = d.run(["openstack", "image", "delete", iid])
        if rc != 0:
            raise Done(FAILED, f"the image could not be deleted: {last_error(out)}")
        left, rc, out = d.read(["openstack", "image", "show", iid])
        if rc == 0 and isinstance(left, dict) and str(left.get("status")) not in ("deleted", "pending_delete"):
            raise Done(ATTENTION, f"{name} is still listed after the delete (status {left.get('status')})")
        d.say(f"Image {name} deleted")
    else:
        d.say("The image no longer exists")
    if not a["snapshots"]:
        raise Done(OK, f"image {name} deleted" if img is not None else "the image was already gone: nothing to do")
    gone = [x for x in a["snapshots"] if d.snapshot(x) is None]
    todo = [x for x in a["snapshots"] if x not in gone]
    bad = [x for x in todo if (d.snapshot(x) or {}).get("status") not in ("available", "error", "error_deleting")]
    todo = [x for x in todo if x not in bad]
    left = delete_snapshots(d, todo, f"image {name}") if todo else []
    note = (f"; {len(gone)} snapshot(s) were already gone" if gone else "") + \
           (f"; not deleted (busy): {', '.join(bad)}" if bad else "")
    if left:
        raise Done(ATTENTION, f"image {name} deleted, but volume snapshot(s) {', '.join(left)} could not be deleted{note}")
    raise Done(OK if not bad else FAILED, f"image {name} and {len(todo)} volume snapshot(s) deleted{note}")


OPS = {"live-migrate": live_migrate, "cold-migrate": cold_migrate, "migrate-volume": migrate_volume, "delete-image": delete_image}


def main(argv, director=None):
    d = director or Director()
    try:
        args = parse(argv)
    except ValueError as e:
        d.say(f"RESULT attention: refused: {e}")
        return ATTENTION
    try:
        OPS[args["verb"]](d, args)
        raise Done(ATTENTION, "the operation ended without a result")
    except Done as e:
        d.say(f"RESULT {LABEL[e.rc]}: {e.message}")
        return e.rc
    except Exception as e:   # an unexpected answer: stop the fix here, with what is known
        d.say(f"RESULT attention: unexpected error {e!r}")
        return ATTENTION


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

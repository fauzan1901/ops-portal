#!/usr/bin/env python3
"""Changes of Operation Automation that take more than one command: they run ON THE OPENSTACK DIRECTOR as admin (after
`source overcloudrc`), one item (instance, volume or image) per call, start the change, watch it until it ends and fix
what can be fixed safely on the way.

wi_analysis.os_action_script embeds this file in the fix script (`python3 -c`, standard library only: Python 3.6 on
RHOSP 16.2, 3.9 on 17.1); the fake cloud of the tests runs it with its own runner, clock and sleep. The command line
was validated by wi_analysis.OPENSTACK_FIX before it got here and is validated again by parse():

  live-migrate <server> from <host> to <host,..|auto> try <hosts|-> timeout <s> stall <abort|force> nodes <host=ip,..|-> user <user|->
               [under <percent> ram <MB>]
  cold-migrate <server> from <host> to <host,..|auto> try <hosts|-> timeout <s> [nodes <host=ip,..|-> user <user|-> under <percent> ram <MB>]
  migrate-volume <volume> to <host@backend#pool> try <pools|-> timeout <s> snapshots <snapshot ids|->
  retype-volume <volume> to <volume type> timeout <s> snapshots <snapshot ids|->
  delete-image <image> expect <size0|any> snapshots <snapshot ids|->
  delete-snapshots <volume> snapshots <snapshot ids>
  clear-fdb <fdb entry> dp <datapath key> mac <mac, 12 hex> port <port key> node <host=ip> user <user>
  port-security <port> project <project id> sg port-security-allow-all allow <addresses|-> dp <datapath key> pkey <port key>
               node <host=ip> user <user>
  getcert-resubmit <certmonger request id> node <host=ip> user <user>
  console-test <server> instance <instance-xxxxxxxx>
  rescan-luns <multipath WWID> addrs <H:C:T:L,..> keep <WWIDs> node <host=ip> user <user>
  move-leftover <server> node <host=ip> user <user>
  release-lv <LVM device-mapper UUID> node <host=ip> user <user>
  rescan-disk <server> wwid <multipath WWID> node <host=ip> user <user>
  flush-map <multipath WWID> node <host=ip> user <user>
  delete-path <sdX> addr <H:C:T:L> wwid <WWID|-> node <host=ip> user <user>

Exit code: 0 done (or nothing left to do); 5 not done, but the item is healthy where it was, so the next item may run;
6 a person must look at this item (it is not in a clean state): the fix stops there, unless the operator chose to skip
such items (migrations: "When an instance cannot be migrated: continue"); 7 skipped on purpose (no destination under
the usage limit): the item stays where it is and the next item always runs; 8 like 6, but the OpenStack control plane
itself fails (CONTROL_HINT): the run always stops, the next items would fail the same way.

Destination under a usage limit (under <percent> ram <MB>): right before the migration, the real CPU use (/proc/stat over
2 seconds) and memory use (MemTotal - MemAvailable, plus the RAM of this instance) of every enabled and up compute of
"nodes" are read on the computes themselves (ssh from the director, all at once); the instance goes to the least used
compute that stays under the limit for both, the next ones when it refuses. No such compute: the instance is not moved.
A live migration goes only to a compute with the CPU vendor of its source (vendor_id of /proc/cpuinfo, read with the use):
a running guest cannot move between an Intel and an AMD CPU; a named destination of another vendor is skipped too.
A compute that is reclaiming memory right now (direct reclaim during the 2 seconds) takes no instance. A large instance
(LARGE_RAM_MB or more) goes to no compute where another large guest started less than LARGE_SETTLE ago (one moved in, or
booted: large ones are spread in time), where a NUMA node has under NODE_FREE_MIN % free, or where the committed memory
(Committed_AS) with its RAM passes COMMIT_LIMIT % of the RAM; of the computes left, those with fewer large guests first.
While a large instance is copied, its destination is read with the progress (at once): direct reclaim there in
GUARD_STRIKES reads in a row aborts the copy (the instance stays on its source) and the next destination is tried.
Every OpenStack command it runs is printed ("$ ..."), and so is every automatic fix ("Automatic fix: ..."); the last
line is "RESULT ok|failed|attention: ...", after a migration the one before it the time of each phase ("Time: checks
before ..., migration ..., checks after ..."). The checks of a live migration read what they need ahead and at once
(threads; the same reads as one after the other), over one SSH connection per node for the whole item.

Sources of the rules: Red Hat OpenStack Platform 17.1 "Configuring the Compute service for instance creation", chapter
Migrating virtual machine instances between Compute nodes (constraints, `openstack server migrate --live-migration
[--host]`, `server migration list/show/abort/force complete`, cold migration and `server resize confirm`); upstream nova
"Live-migrate instances" (progress = memory remaining, abort, force-complete pauses the instance); Red Hat "Migrating a
volume between back ends" (available or in-use, no snapshots, not in a group, not replicated, a multiattach volume on
one instance at most) and the WI "Rollback Volume Type" (the temporary copy of a failed migration: reset-state, delete).

What is fixed automatically:
  live migration  the destination refuses it (no valid host, CPU not compatible, not enough resources, compute down,
                  pre-check error): the instance stays on its source, the next destination is tried (3 at most);
                  the copy does not converge for 2 minutes: the pause at switch-over allowed is raised to the one Nova is
                  configured to reach (live_migration_downtime, 500 ms by default; Nova starts at a tenth of it);
                  it runs 5 minutes and more: its guest is pinged every 5 minutes (no answer: noted, attention at the end);
                  the copy does not converge for 10 minutes (the guest changes its memory about as fast as it is copied;
                  Nova does not slow it down where post-copy is permitted): abort, or force-complete with stall force;
                  it does not finish within the timeout: abort (the instance stays on its source; reported as aborted only
                  when Nova recorded the action live_migration_cancel, a refused abort is shown and the migration followed
                  until it ends) or, with stall force, force-complete (the instance pauses until the copy ends);
                  one at a time per site: before each one, the portal waits while a live migration of another instance
                  is still running there (another fix, Horizon, the CLI), up to the timeout; still busy: not started;
                  a directory of the instance left on the destination (DestinationDiskExists), on local storage and with no
                  domain of it there: moved aside (renamed), then the migration starts; shared storage or a domain: skipped;
                  after a migration that ended back on its source: the destination's kernel log, multipath maps and running
                  domains are read; a disk of another instance that lost its paths in the rollback gets them back (scan of
                  only the removed SCSI addresses, a device kept only with the WWID of its map) and the item ends in attention;
                  a volume of the instance with more than one Cinder attachment (a leftover: "duplicate connectors" halfway):
                  the leftovers are deleted with the Cinder API first when every one of them is safe (not Nova's, which must
                  be attached to the instance's compute; error_attaching / reserved / error_detaching / detached, never
                  connected, not of that compute, unchanged for 30 min), else not started at all (nothing changed), as when
                  libvirt cannot take a job on its domain (state change lock);
                  guest LVs the source compute activated on its disks (host LVM without a filter): released first when
                  nothing opens them (only the host's mapping), else not started; LVM on a partition of a disk counts like
                  LVM on the whole disk (only a destination whose LVM filter keeps guest volumes off is used);
                  after a migration that ended on the destination: guest LVs that compute activated on its disks are
                  released; the domain running on such an LV, or a disk on one SCSI path, ends the item in attention;
                  the instance is left in ERROR, or in MIGRATING without a running migration: reset to ACTIVE only when
                  virsh shows its domain running on the compute Nova records and on no other compute that was involved;
                  a destination with iSCSI path devices in no map, a multipath map without a working path, or a disk of a
                  running VM without one, is skipped (a real case: the volume of dev-vm-01 came up there on dead
                  devices left by an earlier disconnect, the migration hung): the next destination is tried;
                  the incoming copy on the destination still "paused (starting up)" 5 minutes after the start (a normal
                  one starts in seconds) with a disk on a map without a working path: that copy is ended there (SIGKILL of
                  its QEMU, then fail_if_no_path on those maps; only when no running domain uses them and nothing else has
                  them open); Nova rolls back, the instance never stopped on its source, the next destination is tried
  cold migration  the destination refuses it: next destination; VERIFY_RESIZE is confirmed
  volume          attached to an instance Nova cannot swap it on (not ACTIVE / PAUSED / VERIFY_RESIZE, or a task runs:
                  Nova answers HTTP 409): skipped before anything is deleted, with the reason (migrate and retype);
                  snapshots: the ones approved in the check are deleted first (a volume with snapshots cannot migrate);
                  a new snapshot stops it; a snapshot left in error_deleting is reset to available and deleted once more;
                  migration error: the temporary copy (migration_status target:<volume>) is reset and deleted, then the
                  next pool is tried (no other pool: the same one once more)
  volume type     (retype, migration policy on-demand) the approved snapshots are deleted first (a volume with snapshots
                  cannot be retyped with a migration); a new snapshot stops it; a failed retype: its temporary copy is
                  reset and deleted (WI Rollback Volume Type), the volume keeps its type
  image           checked again (not protected, not used by an instance, still empty), deleted, then the volume
                  snapshots of a snapshot image (block_device_mapping) are deleted
  FDB entry       (OVN Southbound, WI "FDB Learning Issue") read again on the node: gone already = done; another MAC,
                  datapath or port than the check saw = nothing changed; else destroyed and read once more
  lost LUN        (check compute-disks: a disk of a running VM left without any path, e.g. by the rollback of a migration
                  that disconnected the source's LUN numbers there) its map read again (it has a path again = done); only
                  the SCSI addresses the kernel removed, and only where no device is now, are scanned; a new device is kept
                  (and given to multipathd) only when its WWID is one of keep, deleted again otherwise; the map read again:
                  a path again = 0, still none = 6 (by hand: lun-rescan)
  disk no path    (check host-lvm: a disk of a running VM whose multipath map has no path) the map read again (a path
                  again = done; not a disk of that instance = nothing changed); Nova's target and LUN of that disk read on
                  a controller; only that LUN on the sessions of that target is scanned, and only where no device is now;
                  a new device is kept only with the WWID of the map, deleted again otherwise; the map read again
  guest LV        (check host-lvm: an LV of a guest that a compute activated on a Cinder volume) read again on the compute:
                  gone = done; opened, held, the disk of a running domain, or on a device of the host itself = nothing
                  changed (5); else dmsetup remove (nothing is written to the volume), each freed path back to its map
  leftover map    (check host-lvm: a multipath map without a running path, e.g. under a released LV) read again: a path
                  runs, it is opened or held, or a running domain uses it = nothing changed (5); else multipath -f
  leftover dir    (check compute-disks: a directory of an instance on a compute with no domain of it, which makes a
                  live migration of that instance back to it fail with DestinationDiskExists) Nova read again (the
                  instance on this very compute, or a task or migration of it: nothing moved), the directory read again
                  (gone = done; a domain defined, shared or unknown storage: nothing moved = 5), renamed
                  <dir>.leftover-<UTC> (never deleted)
  port security   (WI "FDB Learning Issue", stage 9) the port read again (another project = nothing changed); the security
                  group port-security-allow-all of the project found or made, with its rules (all traffic in and out:
                  the traffic of the application stays as it was, only MAC / IP anti-spoofing starts); port security on
                  with that group and the allowed addresses (VIPs) in one call; read again; the address "unknown" of
                  its OVN port binding gone; the FDB entries recorded on the port cleared (OVN no longer learns there)
  certificate     (certmonger, TLS everywhere) the request read again on the node (no longer tracked = nothing changed);
                  resubmitted to its CA (IdM), then read every few seconds until it is MONITORING with a new expiry; still
                  CA_UNREACHABLE / CA_REJECTED / stuck, or no new certificate in time = not done (the certificate it has
                  stays in place, the next item runs). The post-save command of the request reloads the service that
                  uses it (Red Hat: TLS everywhere, getcert resubmit)
  console test    (after a migration, from the screenshots of the item; the operator looked at the console first) only
                  for an instance ACTIVE and running, still the one of the screenshot: the console before, ONE Enter key
                  (virsh send-key KEY_ENTER, nothing typed), the console 3 s after; answers = the screen changed clearly
                  more than it changes by itself (a blinking cursor), else a person looks
"""
import base64
import ipaddress
import json
import os
import re
import shlex
import struct
import subprocess
import sys
import time
import zlib

OK, FAILED, ATTENTION, SKIPPED, CONTROL_FAILED = 0, 5, 6, 7, 8
LABEL = {OK: "ok", FAILED: "failed", ATTENTION: "attention", SKIPPED: "skipped", CONTROL_FAILED: "attention"}
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
POOL_RE = re.compile(r"^[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+#[A-Za-z0-9_.-]+$")
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
REQUEST_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")   # a certmonger request ID (a timestamp, or a nickname)
NOVA_COMPUTE_LOG = "/var/log/containers/nova/nova-compute.log"
# "<date> <time> <pid> ERROR <logger> [req-... ] [instance: ...] ": the prefix oslo.log puts before each line
LOG_PREFIX = re.compile(r"^\S+ \S+ \d+ (?:ERROR|CRITICAL) \S+ (?:\[[^\]]*\] ?)*")
# libvirt cannot get the job of the domain: its QEMU does not answer (held by monitor=init-<instance>: the reconnect of
# virtqemud to it never ended). Every destination fails the same way.
STUCK_LOCK = re.compile(r"cannot acquire state change lock", re.I)
# Cinder refuses the attachment of a migration while another attachment of the same (not multiattach) volume is still
# connected: a leftover of an earlier failed migration (a real case: the cold migration ended in ERROR)
DUPLICATE = re.compile(r"duplicate connectors detected", re.I)
UUID_ANY = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
# the instances path on these filesystems is shared between the computes: a directory there is never a leftover to move
SHARED_FS = ("nfs", "nfs4", "ceph", "fuse.ceph", "glusterfs", "fuse.glusterfs", "cifs", "smb3", "gpfs", "lustre")
WWID_RE = re.compile(r"^3[0-9a-f]{32}$")
IQN_RE = re.compile(r"^iqn\.[0-9a-z.:-]+$")
# A client warning, not the reason of a failure (python-openstackclient with --os-compute-api-version above 2.24 prints it on
# every live migration; it can hide the real reason of a refusal)
CLIENT_WARNING = re.compile(r"will be an error in a future release|is deprecated|DeprecationWarning", re.I)
# An LVM global_filter that rejects every device it does not name: guest LVs on Cinder volumes stay off the host
LVM_REJECT_ALL = re.compile(r"r\|\^?\.\*\$?\|")
# The device-mapper UUID of an LVM LV: LVM- then the UUID of its VG and of the LV (32 characters each, no dash)
LV_UUID_RE = re.compile(r"^LVM-[A-Za-z0-9]{64}$")
SD_RE = re.compile(r"^sd[a-z]{1,4}$")
SCSI_ADDR_RE = re.compile(r"^\d{1,4}:\d{1,4}:\d{1,4}:\d{1,5}$")
INSTANCE_RE = re.compile(r"^instance-[0-9a-f]{8}$")
USERS = ("heat-admin", "tripleo-admin")
SSH = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=no",
       "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR"]


class SshPool:
    """One SSH connection per overcloud node for the whole run of wi_ops.py (OpenSSH ControlMaster in a private folder of
    this run): a live migration reads its source and destination a dozen times, and each new session pays its key exchange
    and login again. The connection is opened apart, with its input and output on /dev/null (so the background master never
    holds the output pipe of a command), lives at most PERSIST seconds without use, and is closed when wi_ops.py ends. A
    command uses it only while it answers (ssh -O check); otherwise the command runs as a plain new session, as before."""
    PERSIST = 300

    def __init__(self):
        import threading
        self.lock = threading.Lock()
        self.folder = None
        self.paths = {}       # target -> socket path
        self.locks = {}       # target -> lock (the first connection to one node is opened once, other nodes in parallel)
        self.failed = set()   # targets whose connection could not be opened: plain sessions for the rest of the run

    def _folder(self):
        if self.folder is None:
            import atexit
            import tempfile
            try:
                self.folder = tempfile.mkdtemp(prefix="wi-ssh.", dir="/tmp")
                atexit.register(self.close)
            except OSError:
                self.folder = ""
        return self.folder

    @staticmethod
    def _quiet(argv, timeout):
        try:
            return subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  timeout=timeout).returncode
        except (OSError, subprocess.SubprocessError):
            return 255

    def wrap(self, argv):
        """argv of `ssh <options> user@host <command>` over the node's connection when it answers; any other argv as it is."""
        argv = list(argv)
        if len(argv) < 3 or argv[0] != "ssh" or "@" not in argv[-2] or any(x in ("-S", "-O", "-M") for x in argv):
            return argv
        target, options = argv[-2], argv[1:-2]
        with self.lock:
            folder = self._folder()
            if not folder or target in self.failed:
                return argv
            path = self.paths.setdefault(target, os.path.join(folder, re.sub(r"[^A-Za-z0-9_.-]", "_", target)[:60]))
            lock = self.locks.setdefault(target, threading_lock())
        with lock:
            if self._quiet(["ssh", "-S", path, "-O", "check", target], 10) != 0:
                try:
                    os.unlink(path)   # a socket left by a connection that ended: ssh would not open a new one there
                except OSError:
                    pass
                self._quiet(["ssh"] + options + ["-o", "ControlMaster=yes", "-o", f"ControlPath={path}",
                                                 "-o", f"ControlPersist={self.PERSIST}", target, "true"], 40)
                if self._quiet(["ssh", "-S", path, "-O", "check", target], 10) != 0:
                    self.failed.add(target)   # unreachable or refused: not tried again (each try costs ConnectTimeout)
                    return argv
        return ["ssh"] + options + ["-o", "ControlMaster=no", "-o", f"ControlPath={path}", target, argv[-1]]

    def close(self):
        for target, path in list(self.paths.items()):
            if os.path.exists(path):
                self._quiet(["ssh", "-S", path, "-O", "exit", target], 10)
        if self.folder:
            import shutil
            shutil.rmtree(self.folder, ignore_errors=True)


def threading_lock():
    import threading
    return threading.Lock()


SSH_POOL = SshPool()
NOVA_LIVE = "2.30"   # live migration to a host the scheduler checks; server migration show / abort / force complete
NOVA_COLD = "2.56"   # cold migration to a given host
NOVA_ABORT = "2.65"  # abort also a live migration still queued or preparing (2.24 to 2.64: only a running one)
NOVA_LIST = "2.59"   # server migration list --changes-since (the live migrations of the whole site)
LIVE_BUSY = ("accepted", "queued", "preparing", "running", "post-migrating")   # a live migration not ended yet
CANCEL_ACTION = "live_migration_cancel"   # the instance action Nova records when it accepts an abort
MAX_ATTEMPTS = 3
INCOMING_STUCK = 300   # s: an incoming copy still starting up after this cannot open its disks (a normal one: seconds)
# A live migration that takes long is not a stuck one (a real case: two VMs of 512 GiB RAM took 23 and 28 minutes, an
# alarm called them stuck after 15): its progress is read from libvirt on the source every 2 minutes, its reason is
# written once it runs LONG_MIGRATION, and only one that copies nothing for NO_PROGRESS is stuck (aborted at once).
LONG_MIGRATION = 900
NO_PROGRESS = 360
# s: a copy that does not converge this long ends (stall abort: aborted, stall force: force-completed), not at the time
# limit: the guest changes its memory as fast as it is copied, and Nova does not slow it down where it permits post-copy
# (auto-converge is then not used; a 16 GiB VM: 30 min, iteration 576, 70-98% copied again and again)
NOT_CONVERGING = 600
# s: a copy that does not converge this long gets at once the pause at switch-over Nova is configured to reach
# (live_migration_downtime of the compute, 500 ms by default): Nova starts at a tenth of it and raises it only every 75 s
# per GiB of RAM (10 h 40 min for 512 GiB), so a busy guest never switches over (a real case: 0.2-0.7
# GiB left at 1 GiB/s for 9 minutes, 50 ms allowed). A parameter of that migration job only (virsh migrate-setmaxdowntime)
DOWNTIME_AFTER = 120
DOWNTIME_DEFAULT_MS = 500
NOVA_CONF = "/var/lib/config-data/puppet-generated/nova_libvirt/etc/nova/nova.conf"
# s: a live migration running this long: its guest is pinged (then every PING_EVERY) from the OVN metadata namespace of
# its network on the compute it runs on, to show whether it still answers (a request of a user)
PING_AFTER = 300
PING_EVERY = 300
SLOW_LINK = 50 * 2 ** 20   # bytes/s: a copy slower than this points at the migration network
JOB_EVERY = 30   # s: how often the progress of the copy is read from libvirt (one short read on the source) and shown
# Large instances are not stacked on one compute in a short time (a real case: three VMs of 512 GiB RAM and 64 vCPU
# went to iha-0 within an hour while it was the least used compute; filling hundreds of GiB, then one NUMA node full
# (1 GiB free of 503), made its host kernel reclaim and compact memory, and the guest already there froze for 22 s to
# 5 minutes (soft lockups, Kubernetes node NotReady) until 05:11). For an instance of LARGE_RAM_MB or more, a destination
# where another large guest started less than LARGE_SETTLE ago (its QEMU: a migration in, or a boot), where a NUMA node
# has under NODE_FREE_MIN % free, or where Committed_AS plus its RAM passes COMMIT_LIMIT % of MemTotal (the guests there
# can all grow to their full RAM) is skipped; any instance skips a compute that is in direct reclaim right now.
LARGE_RAM_MB = 64 * 1024
LARGE_SETTLE = 3600   # s from the start of the QEMU of a large guest: a 512 GiB migration in takes about 25 minutes
NODE_FREE_MIN = 5   # % of a NUMA node
COMMIT_LIMIT = 100   # % of MemTotal
# While a large instance is copied, its destination is read with the progress (at once, every JOB_EVERY): direct reclaim
# there in GUARD_STRIKES reads in a row (about a minute) aborts the copy, so the guests already there stop waiting for
# memory; the instance stays on its source and the next destination is tried. One read with reclaim is only noted.
GUARD_STRIKES = 2
# ML2/OVN: a port is ACTIVE once ovn-controller on the destination claims it, which can lag the end of the migration
# (a real case: vm-master-03 and vm-tunnel read DOWN right after it, the run stopped): a port not
# ACTIVE right after is read again for up to PORT_SETTLE seconds before it counts as a problem
PORT_SETTLE = 90
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
# A start of a migration that failed on Nova's control plane: an HTTP 5xx answer (nova-conductor lost its database or
# RabbitMQ: a real case, "WSREP has not yet prepared node", HTTP 500 after 328 s) or no answer at all. Every other
# instance would fail the same way, and Nova may have kept the instance in task migrating: the run stops there.
CONTROL = re.compile(
    r"unexpected api error|\(HTTP 50\d\)|remoteerror|dbconnectionerror|wsrep|mysql server has gone away"
    r"|lost connection to mysql|amqp|service unavailable|gateway time-?out|bad gateway|no answer after", re.I)
CONTROL_HINT = ("The next items of this run do not start: check nova-conductor, the database (galera) and RabbitMQ on the "
                "controllers (pcs status), then start the run again.")
START_SETTLE = 120        # a failed start that left a task: how long Nova may take to start the migration or clear the task
START_SETTLE_SLOW = 300   # the same after no answer (a timeout): Nova may still be working on the request
IN_PROGRESS = ("accepted", "queued", "preparing", "running", "post-migrating")
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


POWER = {"0": "nostate", "1": "running", "3": "paused", "4": "shutdown", "6": "crashed", "7": "suspended"}
# The TripleO Ansible inventory of the deployment: only the lines of its groups, hosts, addresses and SSH users are read
# (the file also holds passwords; those lines are never read)
INVENTORY_GREP = ("grep -shE '^[A-Za-z0-9_]+:$|^  hosts:$|^    [A-Za-z0-9_.-]+:$|^      (ansible_host|ctlplane_ip): "
                  "|^ +ansible_ssh_user: ' ~/overcloud-deploy/*/tripleo-ansible-inventory.yaml "
                  "~/config-download/*/tripleo-ansible-inventory.yaml ~/tripleo-ansible-inventory.yaml")
# What a guest prints on its console when it is not well (after its disk was swapped or it was moved)
CONSOLE_ERRORS = re.compile(r"I/O error|blk_update_request|Buffer I/O|EXT4-fs error|XFS \(\S+\): .*(error|corrupt|shutdown)|"
                            r"Remounting filesystem read-only|blocked for more than \d+ seconds|soft lockup|hung_task|"
                            r"Kernel panic|Call Trace|Out of memory|emergency mode|Give root password for maintenance|"
                            r"rescue mode|dracut-initqueue.*timeout", re.I)


# an application's own memory limit inside the guest (a container or a systemd slice): its processes are killed again and
# again whatever the platform does (web-crawler in production: chromium every few seconds, before and after the move)
CGROUP_OOM = re.compile(r"Memory cgroup out of memory", re.I)
SYSTEM_OOM = re.compile(r"Out of memory", re.I)

SHOT_MARK = "@@WI@@shot"   # one line: the marker, the instance, before|after, the server, the console (PNG, base64)
SHOT_MAX = 400000          # bytes of PNG at most (a bigger screen is halved first: a run may have 300 items)


def to_png(data):
    """The screenshot libvirt gives (PNG, or PPM P6 from QEMU's screendump) as PNG of SHOT_MAX bytes at most (halved
    until it fits), or None. Pure Python (stdlib zlib)."""
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        if len(data) <= SHOT_MAX:
            return data
        p = png_pixels(data)   # a big screen (a desktop with a photo): as RGB, then halved below
        if not p:
            return None
        w, h, bpp, rows = p
        pix = b"".join(bytes(b for x in range(0, w * bpp, bpp) for b in (r[x:x + 3] if bpp >= 3 else r[x:x + 1] * 3))
                       for r in rows)
    else:
        m = re.match(rb"P6\s+(?:#[^\n]*\n\s*)*(\d+)\s+(\d+)\s+(\d+)\s", data[:100])
        if not m:
            return None
        w, h, depth = (int(x) for x in m.groups())
        pix = data[m.end():m.end() + w * h * 3]
        if depth != 255 or not w or not h or len(pix) < w * h * 3:
            return None

    def encode(pix, w, h):
        raw = b"".join(b"\x00" + pix[y * w * 3:(y + 1) * w * 3] for y in range(h))

        def chunk(kind, body):
            return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body) & 0xffffffff)
        return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
                + chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b""))
    png = encode(pix, w, h)
    while len(png) > SHOT_MAX and w > 200:   # half the size: every second pixel of every second row
        rows = [pix[y * w * 3:(y + 1) * w * 3] for y in range(0, h, 2)]
        w2 = (w + 1) // 2
        pix = b"".join(bytes(b for x in range(0, w, 2) for b in r[x * 3:x * 3 + 3]) for r in rows)
        w, h = w2, len(rows)
        png = encode(pix, w, h)
    return png if len(png) <= SHOT_MAX else None


def png_pixels(data):
    """(width, height, bytes per pixel, [rows of pixel bytes]) of an 8-bit PNG without interlace (gray, RGB, gray + alpha,
    RGBA: what libvirt gives), None otherwise. Pure Python: the filter of each row is undone (PNG specification 9.2)."""
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    pos, idat, head = 8, [], None
    while pos + 8 <= len(data):
        n, kind = struct.unpack(">I4s", data[pos:pos + 8])
        if kind == b"IHDR":
            head = struct.unpack(">IIBBBBB", data[pos + 8:pos + 21])
        elif kind == b"IDAT":
            idat.append(data[pos + 8:pos + 8 + n])
        elif kind == b"IEND":
            break
        pos += 12 + n
    if not head:
        return None
    w, h, depth, color, _, _, interlace = head
    bpp = {0: 1, 2: 3, 4: 2, 6: 4}.get(color)
    if depth != 8 or not bpp or interlace or not w or not h or w * h > 16000000:
        return None
    try:
        raw = zlib.decompress(b"".join(idat))
    except zlib.error:
        return None
    stride = w * bpp
    if len(raw) < h * (stride + 1):
        return None
    rows, prev = [], bytearray(stride)
    for y in range(h):
        kind, line = raw[y * (stride + 1)], bytearray(raw[y * (stride + 1) + 1:(y + 1) * (stride + 1)])
        if kind == 1:     # Sub
            for i in range(bpp, stride):
                line[i] = (line[i] + line[i - bpp]) & 255
        elif kind == 2:   # Up
            line = bytearray((a + b) & 255 for a, b in zip(line, prev))
        elif kind == 3:   # Average
            for i in range(stride):
                line[i] = (line[i] + (((line[i - bpp] if i >= bpp else 0) + prev[i]) >> 1)) & 255
        elif kind == 4:   # Paeth
            for i in range(stride):
                a, b, c = (line[i - bpp], prev[i], prev[i - bpp]) if i >= bpp else (0, prev[i], 0)
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                line[i] = (line[i] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 255
        elif kind:
            return None
        rows.append(bytes(line))
        prev = line
    return w, h, bpp, rows


def changed_pixels(a, b):
    """How many pixels differ between two screenshots (PNG): all of them when the size changed, None when one cannot be
    read."""
    pa, pb = png_pixels(a or b""), png_pixels(b or b"")
    if not pa or not pb:
        return None
    if pa[:3] != pb[:3]:
        return max(pa[0] * pa[1], pb[0] * pb[1])
    bpp, n = pa[2], 0
    for x, y in zip(pa[3], pb[3]):
        if x != y:
            n += sum(1 for i in range(0, len(x), bpp) if x[i:i + bpp] != y[i:i + bpp])
    return n


def power_name(value):
    text = str(value or "").strip().lower()
    return POWER.get(text, text)


def parse_inventory(text):
    """{short host: {"ip", "user"}} from the grep of the TripleO Ansible inventory (YAML, 2-space indent)."""
    hosts, host = {}, ""
    for line in str(text or "").splitlines():
        m = re.match(r"^    ([A-Za-z0-9_.-]+):$", line)
        if m:
            host = short(m.group(1))
            hosts.setdefault(host, {"ip": "", "user": ""})
            continue
        m = re.match(r"^      (ansible_host|ctlplane_ip): +['\"]?([0-9.]+)['\"]?\s*$", line)
        if m and host:
            if m.group(1) == "ctlplane_ip" or not hosts[host]["ip"]:
                hosts[host]["ip"] = m.group(2)
            continue
        m = re.match(r"^      ansible_ssh_user: +['\"]?([a-z-]+)['\"]?\s*$", line)
        if m and host:
            hosts[host]["user"] = m.group(1)
        elif re.match(r"^[A-Za-z0-9_]+:$", line):
            host = ""
    return hosts


def new_lines(before, after):
    """The console lines printed since `before` was read (the lines after its last line in `after`; all of `after`
    when that line is not there any more, e.g. a new console log on the destination compute)."""
    last = next((x for x in reversed(before or []) if x.strip()), None)
    if last is not None:
        for i in range(len(after) - 1, -1, -1):
            if after[i] == last:
                return after[i + 1:]
    return list(after)


def before_change(d, sid, nodes=None, user="", ports=False):
    """What the instance shows before a change: {"log": its console log lines, "shot": a PNG of its console or None,
    "ports": {port id: status} when ports}, so the check after it judges only what is new, and the operator sees the
    console before and after (a guest that was already at an emergency prompt before, or a port already DOWN, is not the
    change's doing)."""
    state = {"log": d.console_log(sid), "shot": None, "ports": d.port_states(sid) if ports else None}
    down = [f"{p} {st or '?'}" for p, st in (state["ports"] or {}).items() if st != "ACTIVE"]
    if down:
        d.say(f"Note: before the change these ports are already not ACTIVE: {', '.join(down)}")
    s = d.server(sid)
    if s and not s.get("unknown") and s["host"] and INSTANCE_RE.match(s["instance"]):
        ip, user = d.node(s["host"], nodes, user)
        if ip:
            state["shot"] = d.screenshot(ip, user, s["instance"])
            if state["shot"]:
                d.say(f"{SHOT_MARK} {s['instance']} before {sid} {base64.b64encode(state['shot']).decode()}")
    old = [x.strip() for x in state["log"] or [] if CONSOLE_ERRORS.search(x)]
    if old:
        d.say(f"Note: before the change its console log already shows: {' | '.join(x[:160] for x in old[-3:])}")
    return state


def check_after(d, sid, done, host=None, nodes=None, user="", before=None, volume=None, ports=False, ports_before=None,
                rc_ok=OK, usable=False):
    """After a live migration or the swap of an attached volume (migrate / retype): is the instance well? Read-only:
    Nova (ACTIVE, running, no task, no fault, on the right compute), its ports (bound to that compute; ACTIVE unless they
    are administratively down or were already not ACTIVE before the change: ports_before {id: status}), the volume (still
    attached on the same device), the domain on the compute (running, no disk error, no block job left) and its console
    log (no I/O, filesystem or kernel error since the change). usable (after a cancel or a rollback, the instance stays
    on its source): also what its page and console in Horizon need (each volume found in Cinder by its ID, one Cinder
    attachment each, the console URL Nova gives; vm-c3, 2026-11-02: a volume missing by its ID breaks the instance
    page and with it the console tab). Ends the item: Done(rc_ok, done + what was checked), or Done(ATTENTION) with what
    is not normal (a person looks before the next item runs)."""
    problems, notes, ok = [], [], []
    s = d.server(sid)
    if s is None:
        raise Done(OK, f"{done}; the instance was deleted meanwhile")
    if s.get("unknown"):
        raise Done(OK, f"{done}; the instance could not be read to check it ({s['unknown']}): look at its console")
    name = s["name"]
    d.say(f"Check after the change: {name} is {s['status']}, power {s['power'] or '?'}, task {s['task'] or '-'}, on {s['host'] or '-'}")
    if s["status"] != "ACTIVE":
        problems.append(f"{name} is {s['status']}")
    if s["power"] and s["power"] != "running":
        problems.append(f"power state {s['power']}")
    if s["task"]:
        problems.append(f"task {s['task']} is still running")
    if s["fault"]:
        problems.append(f"fault: {s['fault'][:200]}")
    if host and short(s["host"]) != short(host):
        problems.append(f"Nova has it on {s['host']}, not on {host}")
    if not problems:
        ok.append("ACTIVE and running")
    if usable:
        opened = usable_checks(d, sid, s, problems, notes)
        if opened:
            ok.append(opened)
    if ports:
        bound = d.ports_of(sid)
        if bound is None:
            notes.append("its ports could not be read")
        else:
            # a port bound to another compute is always a problem; one that is not ACTIVE only when the change did it: not
            # when it is administratively down, nor when it was already so before (fw-vm-a in production)
            was = ports_before or {}

            def judge(bound):   # noqa: E306
                wrong = [p for p in bound if p["host"] and short(p["host"]) != short(s["host"])]
                down = [p for p in bound if p["status"] != "ACTIVE" and p not in wrong]
                same = [p for p in down if not p.get("admin", True) or was.get(p["id"], "ACTIVE") != "ACTIVE"]
                return wrong, down, same
            wrong, down, same = judge(bound)
            late, late_after = wrong + [p for p in down if p not in same], ""
            if late:   # OVN may not have reported them up yet: Neutron read again before they count as a problem
                d.say(f"  {len(late)} port(s) not ACTIVE on {short(s['host'])} right after the migration "
                      f"({', '.join(p['id'] + ' ' + (p['status'] or '?') for p in late)}): read again every 10 s for up to "
                      f"{PORT_SETTLE} s (ML2/OVN sets a port ACTIVE once the destination claims it)")
                waited, seen = d.clock(), {"bound": bound}

                def settled():
                    again = d.ports_of(sid)
                    if again is None:
                        return False
                    seen["bound"] = again
                    w, dn, sm = judge(again)
                    return not (w + [p for p in dn if p not in sm])
                if d.wait(settled, PORT_SETTLE, every=10):
                    late_after = f" ({len(late)} of them {minutes(d.clock() - waited)} after the migration ended)"
                    d.say(f"  every port ACTIVE on {short(s['host'])}{late_after}")
                bound = seen["bound"]
                wrong, down, same = judge(bound)
            for p in wrong + [p for p in down if p not in same]:
                problems.append(f"port {p['id']} is {p['status'] or '?'} bound to {p['host'] or 'no host'}"
                                + (" (it was ACTIVE before the change)" if was.get(p["id"]) == "ACTIVE" else ""))
            up = len(bound) - len(wrong) - len(down)
            if up:
                ok.append(f"{up} port(s) ACTIVE on {short(s['host'])}{late_after}")
            ok += [f"port {p['id']} {p['status'] or '?'} " + ("(administratively down)" if not p.get("admin", True)
                                                             else "as before the change") for p in same]
    disks = []
    if volume:
        vid, device = volume
        v = d.volume(vid)
        att = [x for x in (v or {}).get("attachments") or [] if isinstance(x, dict) and str(x.get("server_id")) == sid]
        if v is None or v.get("unknown"):
            notes.append("the volume could not be read again")
        elif v["status"] != "in-use" or not att:
            problems.append(f"the volume is {v['status']} and {'attached' if att else 'not attached'} to {name}")
        elif device and str(att[0].get("device") or "") != device:
            problems.append(f"the volume is now {att[0].get('device')} of {name}, it was {device}")
        else:
            ok.append(f"volume attached as {device or att[0].get('device')}")
        disk = re.sub(r"^/dev/", "", device or "")
        disks = [disk] if re.match(r"^[sv]d[a-z]{1,2}$", disk) else []
    ip, user = d.node(s["host"], nodes, user) if s["host"] else (None, None)
    if ip and INSTANCE_RE.match(s["instance"]):
        dom = d.domain_check(ip, user, s["instance"], disks)
        if dom.get("unknown"):
            notes.append(f"the domain on {short(s['host'])} could not be read ({dom['unknown']})")
        else:
            if not dom["state"].startswith("running"):
                problems.append(f"the domain is {dom['state']} on {short(s['host'])}")
            problems += [f"disk error: {x}" for x in dom["errors"]]
            problems += [f"block job still on {k}: {v}" for k, v in dom["jobs"].items()]
            if dom["state"].startswith("running") and not dom["errors"] and not dom["jobs"]:
                ok.append("domain running without disk errors")
        png = d.screenshot(ip, user, s["instance"])
        if png:
            d.say(f"{SHOT_MARK} {s['instance']} after {sid} {base64.b64encode(png).decode()}")
            ok.append("console screenshot taken (shown with this item)")
        else:
            notes.append("the console screenshot could not be taken: look at the console in Horizon")
    else:
        notes.append(f"the domain on {short(s['host']) or 'its compute'} was not checked (no ctlplane address)")
    log = d.console_log(sid)
    if log is None:
        notes.append("its console log could not be read: look at the console in Horizon")
    else:
        fresh = new_lines(before, log) if before is not None else log[-80:]
        bad = [x.strip() for x in fresh if CONSOLE_ERRORS.search(x)]
        # not the change's doing: an application hitting its own memory limit (Memory cgroup out of memory), or the guest
        # running out of memory as it already did before the change. Storage, filesystem and boot errors always count.
        app = [x for x in bad if CGROUP_OOM.search(x)]
        oom_before = any(SYSTEM_OOM.search(x) for x in before or [])
        known = [x for x in bad if x not in app and oom_before and SYSTEM_OOM.search(x)
                 and not CONSOLE_ERRORS.search(SYSTEM_OOM.sub("", x))]
        bad = [x for x in bad if x not in app and x not in known]
        if app:
            ok.append(f"console: {len(app)} line(s) of an application's own memory limit in the guest (Memory cgroup out of "
                      "memory), not the change's doing")
        if known:
            ok.append(f"console: {len(known)} out-of-memory line(s), as the guest already printed before the change")
        if bad:
            problems.append("console: " + " | ".join(x[:160] for x in bad[-3:]))
        elif not any(x.strip() for x in log):
            notes.append("the console log is empty (a guest that writes nothing there, e.g. Windows): look at the console in Horizon")
        else:
            ok.append(f"console log without errors ({len(fresh)} new line(s))")
    if problems:
        raise Done(ATTENTION, f"{done}, but after it: {'; '.join(problems)}. Look at {name} (console in Horizon, openstack "
                              f"console log show {sid}) before the next item runs" + (f"; not checked: {'; '.join(notes)}" if notes else ""))
    raise Done(rc_ok, f"{done}; checked: {', '.join(ok) or 'nothing'}" + (f"; not checked: {'; '.join(notes)}" if notes else ""))


def usable_checks(d, sid, s, problems, notes):
    """What Horizon needs to open an instance after a cancel or a rollback: every volume found in Cinder by its ID (its
    page lists them; one missing fails the whole page and its console tab), each with one Cinder attachment (a leftover
    of the migration keeps the LUN mapped to the destination), and the console URL Nova gives. Adds to problems / notes;
    returns what was fine as one text ('' when nothing)."""
    fine, vols, missing = [], s.get("volumes") or [], []
    for vid in vols:
        v = d.volume(vid)
        if v is None or v.get("missing"):
            missing.append(vid)
            problems.append(f"volume {vid} is not in Cinder by its ID ({v['missing'] if v else 'Cinder answers 404'}): Horizon "
                            "cannot open the instance page nor its console tab")
            continue
        if v.get("unknown"):
            notes.append(f"volume {vid} could not be read ({v['unknown']})")
            continue
        atts = d.attachments(vid)
        if atts is None:
            notes.append(f"the Cinder attachments of volume {vid} could not be read")
        elif not v.get("multiattach") and (len(atts) != 1 or atts[0]["status"] != "attached"):
            problems.append(f"volume {vid} has {len(atts)} Cinder attachment(s) ("
                            + (", ".join(f"{x['id']} {x['status']}" for x in atts[:4]) or "none")
                            + "): a leftover of the migration; run the check \"Volume connections of an instance\"")
    if vols and not missing:
        fine.append(f"{len(vols)} volume(s) found in Cinder by ID")
    con = d.console_url(sid)
    if con.get("url"):
        fine.append("the console opens (Nova gives its URL)")
    elif con.get("unavailable"):
        notes.append(f"the console URL ({con['unavailable']})")
    else:
        problems.append(f"the console does not open: Nova gives no console URL ({con.get('error')})")
    return ", ".join(fine)


def short(host):
    return str(host or "").split(".")[0].lower()


def skip(d, target, why):
    """A destination left out before a migration (nothing was started there): said, and kept for the result."""
    d.say(f"Skip {target}: {why}")
    d.skipped.append((short(target), why))


def none_left(d, last):
    """Why no destination took an instance: the last refusal, and the destinations left out with the reason of each
    (a real case: "no enabled and up compute in the list" while compute-2 was left out for another reason)."""
    seen = []
    for host, why in d.skipped:
        first = why.split(". ")[0][:220]
        if (host, first) not in seen:
            seen.append((host, first))
    out = "; ".join(f"{h} left out: {w}" for h, w in seen[:6])
    if last:
        return last + (f" ({out})" if out else "")
    return out or "no enabled and up compute in the list"


def same_host(a, b):
    return bool(short(a)) and short(a) == short(b)


def first_line(text, limit=300):
    for line in str(text or "").splitlines():
        line = line.strip()
        if line and not line.startswith("$ "):
            return line[:limit]
    return ""


def last_error(text):
    """The most useful line of a traceback or an error text: the last line naming an exception or an error. The code
    line under each File "...", line N of a Python traceback is not an error: Nova keeps only the frames of an event's
    traceback, without the exception, and its last code line LOG.error('Create attachment failed for volume ' was shown
    as the reason (a real case). A traceback of frames only gives ''."""
    lines, frame = [], False
    for raw in str(text or "").splitlines():
        l = raw.strip()
        if not l or re.fullmatch(r"[\^~]+", l):
            continue
        if frame and not l.startswith(('File "', "Traceback")):
            frame = False
            continue
        frame = l.startswith('File "')
        lines.append(l)
    real = [l for l in lines if not CLIENT_WARNING.search(l)] or lines
    for line in reversed(real):
        if re.search(r"(Error|Exception|error|refused|failed|Failed)", line) and not line.startswith(("File ", "Traceback")):
            return line[:400]
    rest = [l for l in real if not l.startswith(("File ", "Traceback"))]
    return (rest[-1] if rest else "")[:400]


def last_frame(text):
    """Where a traceback ended in Nova's own code: 'attachment_create (nova/volume/cinder.py)', '' when it has no frame."""
    frames = re.findall(r'File "[^"]*/(nova/[^"]+)", line \d+, in (\w+)', str(text or ""))
    return f"{frames[-1][1]} ({frames[-1][0]})" if frames else ""


def gone(out, kind):
    """The client says this object does not exist; not when the API itself is missing or failing ("public endpoint for
    volumev3 ... not found", a timeout), which must never read as "already deleted"."""
    text = str(out or "")
    if re.search(r"endpoint|service catalog|unable to establish|timed out|connection|HTTP 5\d\d", text, re.I):
        return False
    return bool(re.search(r"No %s with a name or ID|No %s found|could not be found|\(HTTP 404\)|NotFound" % (kind, kind), text, re.I))


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


SIZE_UNITS = {"b": 1, "bytes": 1, "kib": 2 ** 10, "mib": 2 ** 20, "gib": 2 ** 30, "tib": 2 ** 40}


def parse_jobinfo(text):
    """virsh domjobinfo of a migrating domain -> {"op", "processed", "remaining", "total" (bytes of memory), "bandwidth",
    "dirty" (bytes/s: the copy speed and how fast the guest changes its memory), "iteration"}; {} without a job."""
    vals = {}
    for line in str(text or "").splitlines():
        key, sep, value = line.partition(":")
        if sep:
            vals[key.strip().lower()] = value.strip()
    if str(vals.get("job type", "")).lower() in ("", "none"):
        return {}

    def size(key):
        m = re.match(r"^([\d.]+)\s*([KMGT]iB|B|bytes)?", vals.get(key, ""), re.I)
        return int(float(m.group(1)) * SIZE_UNITS.get((m.group(2) or "b").lower(), 1)) if m else None

    pages = re.match(r"^(\d+)", vals.get("dirty rate", ""))
    page = re.match(r"^(\d+)", vals.get("page size", ""))
    it = re.match(r"^(\d+)", vals.get("iteration", ""))
    return {"op": vals.get("operation", ""),
            "processed": size("memory processed") if size("memory processed") is not None else size("data processed"),
            "remaining": size("memory remaining") if size("memory remaining") is not None else size("data remaining"),
            "total": size("memory total") or size("data total"), "bandwidth": size("memory bandwidth"),
            "dirty": int(pages.group(1)) * (int(page.group(1)) if page else 4096) if pages else None,
            "iteration": int(it.group(1)) if it else None}


def gib(n):
    return f"{(n or 0) / 2 ** 30:.1f} GiB"


def mib_s(n):
    return f"{(n or 0) / 2 ** 20:.0f} MiB/s"


def progress_line(elapsed, mig, job, prev, now):
    """One progress line of a running live migration, from libvirt: how much is copied, the speed measured since the read
    before (and the one libvirt gives now), how fast the guest changes its memory, the iteration and the time left."""
    total, left = job.get("total") or 0, job.get("remaining")
    done = total - left if total and left is not None else None
    speed = None
    if prev and prev[1].get("processed") is not None and job.get("processed") is not None and now > prev[0]:
        speed = max(0, job["processed"] - prev[1]["processed"]) / (now - prev[0])
    dirty = job.get("dirty") or 0
    eta = f"; about {minutes(left / (speed - dirty))} left" if speed and speed > dirty and left else ""
    return (f"  {minutes(elapsed)}: migration {mig['id']} {mig['status']}: "
            + (f"{100 * done / total:.0f}% copied ({gib(done)} of {gib(total)}), {gib(left)} left; " if done is not None else "")
            + (f"speed {mib_s(speed)} (libvirt now {mib_s(job.get('bandwidth'))})" if speed is not None
               else f"speed {mib_s(job.get('bandwidth'))} (libvirt)")
            + (f"; guest changes {mib_s(dirty)}" if dirty else "")
            + (f"; iteration {job['iteration']}" if job.get("iteration") else "") + eta)


def copy_rate(history):
    """(speed of the copy in bytes/s over the last 100 s, else libvirt's; the rate the guest changes its memory at; whether
    the memory left shrinks) at the newest libvirt read of history [(time, job)]."""
    t, job = history[-1]
    prev = [(tt, jj) for tt, jj in history if tt <= t - 100]
    speed = job.get("bandwidth")
    if prev and job.get("processed") is not None and prev[-1][1].get("processed") is not None and t > prev[-1][0]:
        speed = max(0, job["processed"] - prev[-1][1]["processed"]) / (t - prev[-1][0])
    shrinking = not prev or prev[-1][1].get("remaining") is None or job.get("remaining") is None \
        or job["remaining"] < prev[-1][1]["remaining"]
    return speed, job.get("dirty") or 0, shrinking


def diverging(history):
    """Does the copy not converge at the newest read: past its first pass, the memory left does not shrink or the guest
    changes its memory at 80% of the copy speed or more (it never gets small enough to switch over)."""
    if not history:
        return False
    speed, dirty, shrinking = copy_rate(history)
    return (history[-1][1].get("iteration") or 0) > 1 and (not shrinking or bool(speed and dirty >= 0.8 * speed))


def job_verdict(history, now, timeout, stall):
    """Why a live migration takes long, from the libvirt reads of its source [(time, job)], newest last: ("stuck", why)
    when nothing was copied for NO_PROGRESS; ("long", why) with how much is left, at what speed, and whether the copy
    converges (the guest changes its memory slower than it is copied); ("", "") when too little is known."""
    if not history:
        return "", ""
    t, job = history[-1]
    old = [(tt, jj) for tt, jj in history if tt <= now - NO_PROGRESS]
    if old and job.get("processed") is not None and old[-1][1].get("processed") is not None \
            and job["processed"] <= old[-1][1]["processed"]:
        return "stuck", (f"nothing copied for {minutes(now - old[-1][0])} (libvirt on the source: {gib(job['processed'])} of "
                         f"{gib(job['total'])} copied, {gib(job['remaining'])} left, iteration {job.get('iteration') or '?'})")
    speed, dirty, _shrinking = copy_rate(history)
    done = job["total"] - job["remaining"] if job.get("total") and job.get("remaining") is not None else job.get("processed")
    copied = f"{gib(done)} of {gib(job['total'])} of RAM copied, {gib(job['remaining'])} left"   # as the progress lines
    at = f"at {mib_s(speed)}" if speed else "at an unknown speed"
    end = ("aborted (the instance stays on its source)" if stall != "force" else "force-completed (the instance pauses "
           "until the copy ends)")
    if speed and speed < SLOW_LINK:
        return "long", (f"{copied} {at}: the copy is slow, check the migration network between the two computes; not "
                        f"stuck, data keeps moving; at the time limit ({minutes(timeout)}) it is {end}")
    if diverging(history):
        return "long", (f"{copied} {at}, iteration {job['iteration']}: the guest changes its memory at {mib_s(dirty)}, about as "
                        "fast as it is copied, so the copy does not converge (Nova does not slow the guest down where it "
                        f"permits post-copy); not stuck, data keeps moving; after {minutes(NOT_CONVERGING)} of this, or at the "
                        f"time limit ({minutes(timeout)}), it is {end}")
    eta = f", about {minutes(job['remaining'] / max(speed - dirty, 1))} more" if speed and speed > dirty and job.get("remaining") else ""
    return "long", f"{copied} {at}{eta}: a large memory to copy, it is moving, not stuck"


IPV4_RE = re.compile(r"^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$")


def parse_ping(text):
    """The output of Director.ping_guest -> {address: {"sent", "received", "avg" (ms or None), "why"}}."""
    out, addr = {}, None
    for line in str(text or "").splitlines():
        m = re.match(r"^@@ping (\S+)$", line.strip())
        if m:
            addr = m.group(1)
            out[addr] = {"sent": 0, "received": 0, "avg": None, "why": ""}
            continue
        if not addr:
            continue
        m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", line)
        if m:
            out[addr].update(sent=int(m.group(1)), received=int(m.group(2)))
        m = re.search(r"= [\d.]+/([\d.]+)/", line)
        if m:
            out[addr]["avg"] = float(m.group(1))
        if re.search(r"Cannot open network namespace|No such file", line):
            out[addr]["why"] = "no OVN metadata namespace of its network there"
    return out


def lower_keys(d):
    return {re.sub(r"[\s-]+", "_", str(k).lower()): v for k, v in (d or {}).items()} if isinstance(d, dict) else {}


def parse_disk_paths(text):
    """The output of Director.disk_paths -> {"removed": [(h, c, t, l)], "io": {dm}, "maps": {dm: {"wwid", "paths",
    "vendor"}}, "users": {dm: [(domain, uuid)]}}."""
    out, section, current, dom = {"removed": [], "io": set(), "maps": {}, "users": {}}, "", None, None
    for line in str(text or "").splitlines():
        if line.strip() in ("@@kernel", "@@maps", "@@domains"):
            section = line.strip()[2:]
            continue
        if section == "kernel":
            m = re.search(r"(?:scsi|sd) (\d+):(\d+):(\d+):(\d+): (?:alua: Detached|\[sd[a-z]+\] Synchronizing SCSI cache)", line)
            if m and tuple(int(x) for x in m.groups()) not in out["removed"]:
                out["removed"].append(tuple(int(x) for x in m.groups()))
            m = re.search(r"I/O error, dev (dm-\d+)", line)
            if m:
                out["io"].add(m.group(1))
        elif section == "maps":
            m = re.match(r"^(\S+)(?: \((3[0-9a-f]{32})\))? (dm-\d+) ?(.*)$", line)
            if m and not line.startswith(("size=", "|", "`", " ")):
                current = m.group(3)
                out["maps"][current] = {"wwid": m.group(2) or m.group(1), "paths": 0, "vendor": m.group(4).strip()}
            elif current and re.search(r"\d+:\d+:\d+:\d+\s+sd[a-z]+\s", line):
                out["maps"][current]["paths"] += 1
        elif section == "domains":
            m = re.match(r"^@@dom (\S+) ?(\S*)$", line)
            if m:
                dom = (m.group(1), m.group(2))
                continue
            m = re.match(r"^@@disk /dev/(dm-\d+)$", line.strip())
            if m and dom:
                out["users"].setdefault(m.group(1), []).append(dom)
    return out


# ---------------------------------------------------------------- guest LVs a compute activated (host LVM)
# A real case: on a compute whose LVM accepts every device (no global_filter, or a|.*|), the host activates the LVs
# of a guest on the first iSCSI path of a volume before multipathd claims it. os-brick then takes that LV for the volume's
# multipath device and gives it to the domain (the guest sees its own inner LV as its disk, shifted), or, with LVM on a
# partition, multipath cannot build the map and the domain runs on one SCSI path. An LV left on the map of a disk makes
# Nova's flush of that map fail when the disk is disconnected (migration, detach, hard reboot).
# Read as root on a compute, read-only: the LVM filter, every LVM LV (device, name, UUID, open count, holders, what is
# under it: path:<dev>:<disk>:<wwid> an iSCSI path or its partition, map:<dev>:<map>:<wwid> a multipath map,
# gone:<dev>:<disk> a removed device, local / other: a device of the host itself), every multipath map (open count,
# holders, running / all paths, path devices) and the disks of the running domains.
# Every running domain of a compute and its disks ("@@dom <name> <uuid>", then "@@disk <source>" lines), in ONE podman exec
# of the libvirt container: one exec per domain took 25-50 s on a compute with 159 instances (a real case)
DOMAIN_DISKS = r"""podman exec "$c" sh -c 'for x in $(virsh -c qemu:///system list --name); do echo "@@dom $x $(virsh -c qemu:///system domuuid $x)"; virsh -c qemu:///system domblklist $x | awk "\$2 ~ /^\/dev\// {print \"@@disk \" \$2}"; done'"""
HOST_LVS = r"""c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$')
echo "@@filter $(lvmconfig --type full devices/global_filter 2>/dev/null | cut -d= -f2-)"
echo "@@devicesfile $(lvmconfig --type full devices/use_devicesfile 2>/dev/null | cut -d= -f2) $([ -s /etc/lvm/devices/system.devices ] && echo present || echo absent)"
ww() { sed -E 's/^naa\./3/' /sys/block/$1/device/wwid 2>/dev/null; }
for x in /sys/block/dm-*; do
  [ -e "$x/dm/uuid" ] || continue
  u=$(cat $x/dm/uuid); d=${x##*/}; n=$(cat $x/dm/name)
  o=$(dmsetup info -c --noheadings -o open "$n" 2>/dev/null | tr -d ' ')
  h=$(ls $x/holders 2>/dev/null | paste -sd, -)
  case "$u" in
    mpath-*) r=0; t=0
      for v in $(ls $x/slaves 2>/dev/null); do t=$((t+1)); [ "$(cat /sys/block/$v/device/state 2>/dev/null)" = running ] && r=$((r+1)); done
      a=$(dmsetup status "$n" 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i ~ /^[0-9]+:[0-9]+$/ && $(i+1) == "A") k++} END {if (NR) print k + 0}')
      echo "@@map $d ${u#mpath-} ${o:-?} ${h:--} $r $t $(ls $x/slaves 2>/dev/null | paste -sd, - | grep . || echo -) ${a:-?}";;
    LVM-*) s=""
      for v in $(ls $x/slaves 2>/dev/null); do p=$v
        [ -e /sys/class/block/$v/partition ] && p=$(basename "$(dirname "$(readlink -f /sys/class/block/$v)")")
        case "$p" in
          sd*) if [ ! -e /sys/block/$p/device ]; then s="$s,gone:$v:$p"
               else a=$(basename "$(readlink -f /sys/block/$p/device)")
                 if [ -e /sys/class/iscsi_host/host${a%%:*} ]; then s="$s,path:$v:$p:$(ww $p)"; else s="$s,local:$v:$p"; fi; fi;;
          dm-*) k=$(cat /sys/block/$p/dm/uuid 2>/dev/null)
                case "$k" in
                  mpath-*) s="$s,map:$v:$p:${k#mpath-}";;
                  part*-mpath-*) s="$s,map:$v:$(ls /sys/block/$p/slaves 2>/dev/null | head -1):${k#*-mpath-}";;
                  *) s="$s,other:$v:$p";;
                esac;;
          *) s="$s,other:$v:$p";;
        esac
      done
      [ -n "$s" ] || s=",none"
      echo "@@lv $d $n $u ${o:-?} ${h:--} ${s#,}";;
  esac
done
T=$(mktemp -d /tmp/wi-hl.XXXXXXXX)
for x in /sys/block/sd*; do v=${x##*/}
  [ -e $x/device ] || continue
  a=$(basename "$(readlink -f $x/device)")
  [ -e /sys/class/iscsi_host/host${a%%:*} ] || continue
  [ -z "$(for y in $x/holders/* $x/$v*/holders/*; do [ -e "$y" ] && echo "$y"; done)" ] || continue
  echo "$v $a $(cat $x/device/state 2>/dev/null || echo ?) $(ww $v | tr ' ' '_' | grep . || echo -)" >> $T/list
  (timeout -s KILL 5 dd if=/dev/$v of=/dev/null bs=4096 count=1 iflag=direct; echo $? > $T/$v) >/dev/null 2>&1 &
done
if [ -s $T/list ]; then
  for i in 1 2 3 4 5 6; do n=0; while read -r v r; do [ -s $T/$v ] || n=1; done < $T/list; [ $n = 0 ] && break; sleep 1; done
  while read -r v r; do q=$(cat $T/$v 2>/dev/null); echo "@@sd $v $r ${q:-none}"; done < $T/list
fi
rm -rf $T
echo @@domains
[ -n "$c" ] || exit 0
podman exec "$c" sh -c 'for x in $(virsh -c qemu:///system list --name); do echo "@@dom $x $(virsh -c qemu:///system domuuid $x)"; virsh -c qemu:///system domblklist $x | awk "\$2 ~ /^\/dev\// {print \"@@src\", \$1, \$2}"; done' |
  while read -r k t s; do if [ "$k" = "@@src" ]; then echo "@@disk $t $(basename "$(readlink -f "$s")")"; else echo "$k $t $s"; fi; done"""


def parse_host_lvs(text):
    """The output of HOST_LVS -> {"filter", "devicesfile": (value, system.devices), "lvs": [{"dm", "name", "uuid", "open",
    "holders", "on": [(kind, device, disk, wwid)]}], "maps": {dm: {"wwid", "open", "holders", "running", "total",
    "paths": [sd]}}, "domains": {name: uuid}, "disks": {device: [(domain, target)]}, "loose": {sd: {"addr", "state",
    "wwid"}}}. running: the paths whose device runs AND multipath counts active (a device can run while every read of
    it fails: a real case, sdez / sdfa); loose: iSCSI path devices in no map, no LV, no partition in use, with
    the read of their first block ("read": ok / failed / none = no answer in 5 s / "" = not read)."""
    out = {"filter": "", "devicesfile": ("", ""), "lvs": [], "maps": {}, "domains": {}, "disks": {}, "loose": {}}
    dom = None
    for line in str(text or "").splitlines():
        p = line.strip().split(" ")
        if p[0] == "@@filter":
            out["filter"] = line.strip()[9:].strip()
        elif p[0] == "@@devicesfile" and len(p) >= 3:
            out["devicesfile"] = (p[1], p[2])
        elif p[0] == "@@map" and len(p) >= 8 and re.match(r"^dm-\d+$", p[1]):
            out["maps"][p[1]] = {"wwid": p[2], "open": p[3], "holders": [] if p[4] == "-" else p[4].split(","),
                                 "running": int(p[5]) if p[5].isdigit() else 0, "total": int(p[6]) if p[6].isdigit() else 0,
                                 "paths": [] if p[7] == "-" else p[7].split(",")}
            if len(p) >= 9 and p[8].isdigit():   # older reads: the device states only
                out["maps"][p[1]]["running"] = min(out["maps"][p[1]]["running"], int(p[8]))
        elif p[0] == "@@sd" and len(p) >= 5 and SD_RE.match(p[1]) and SCSI_ADDR_RE.match(p[2]):
            rd = p[5] if len(p) >= 6 else ""
            out["loose"][p[1]] = {"addr": p[2], "state": p[3], "wwid": p[4] if WWID_RE.match(p[4]) else "",
                                  "read": "ok" if rd == "0" else "none" if rd == "none" else "failed" if rd else ""}
        elif p[0] == "@@lv" and len(p) >= 7 and re.match(r"^dm-\d+$", p[1]):
            on = []
            for part in p[6].split(","):
                f = part.split(":")
                if f[0] in ("path", "map", "gone", "local", "other"):
                    on.append((f[0], f[1] if len(f) > 1 else "", f[2] if len(f) > 2 else "", f[3] if len(f) > 3 else ""))
            out["lvs"].append({"dm": p[1], "name": p[2], "uuid": p[3], "open": p[4],
                               "holders": [] if p[5] == "-" else p[5].split(","), "on": on})
        elif p[0] == "@@dom" and len(p) >= 2:
            dom = p[1]
            out["domains"][dom] = p[2] if len(p) > 2 else ""
        elif p[0] == "@@disk" and len(p) >= 3 and dom:
            out["disks"].setdefault(p[2], []).append((dom, p[1]))
    return out


def guest_lvs(seen):
    """The guest LVs of HOST_LVS (an LV with anything of the host itself under it is the host's own, left out), each
    {"dm", "name", "uuid", "open", "holders", "on", "kind", "users": [(domain, target)], "wwid", "map", "why"}. kind:
      runs-on  a running domain uses the LV itself as its disk (its guest sees the inner LV, shifted): stop it first;
      busy     opened or held on the host: left alone;
      disk     on the map of a disk of a running domain, on a path of it, or on a partition of a disk the domain runs
               on with one SCSI device (users): releasable while it runs (only the host's mapping goes);
      leftover on nothing a running domain uses (a map or path of a volume no longer used here, a removed device)."""
    disks, maps = seen["disks"], seen["maps"]
    by_wwid = {m["wwid"]: dm for dm, m in maps.items()}
    out = []
    for lv in seen["lvs"]:
        if not lv["on"] or any(k in ("local", "other") for k, _d, _p, _w in lv["on"]):
            continue
        users, wwid, mapdm = [], "", ""
        for kind, dev, disk, w in lv["on"]:
            if kind == "map":
                mapdm, wwid = disk, w
                users += disks.get(disk, [])
            elif kind == "path":
                wwid = w
                mapdm = by_wwid.get(w, "")
                users += disks.get(mapdm, []) if mapdm else []
                users += disks.get(disk, []) + (disks.get(dev, []) if dev != disk else [])
        x = dict(lv, users=list(dict.fromkeys(users)), wwid=wwid, map=mapdm)
        if lv["dm"] in disks:
            x["kind"], x["users"] = "runs-on", disks[lv["dm"]]
            x["why"] = "a running domain uses this LV itself as its disk"
        elif lv["open"] != "0" or lv["holders"]:
            x["kind"] = "busy"
            x["why"] = f"opened {lv['open']} time(s) on the host" + (f", held by {','.join(lv['holders'])}" if lv["holders"] else "")
        elif x["users"]:
            x["kind"], x["why"] = "disk", ""
        else:
            x["kind"], x["why"] = "leftover", ""
        out.append(x)
    return out


def dead_maps(seen):
    """Multipath maps without a running path, not opened, not held and not the disk of a running domain (a leftover, e.g.
    under a guest LV that was released): [(dm, wwid)]."""
    return [(dm, m["wwid"]) for dm, m in sorted(seen["maps"].items(), key=lambda x: int(x[0][3:]))
            if m["running"] == 0 and m["open"] == "0" and not m["holders"] and dm not in seen["disks"] and WWID_RE.match(m["wwid"])]


def loose_paths(seen):
    """iSCSI path devices of a compute in no multipath map, under no LV and no disk of a running domain: left by a volume
    disconnect that did not finish (os-brick deletes them). A later connection of a LUN at the same address takes such a
    device instead of a new one (a real case: the volume of dev-vm-01 on dead sdez / sdfa, its live migration hung).
    [(sd, addr, wwid, state, read)]: read ok = a LUN still mapped to this compute that nothing uses (DCA iha-0 sdhh / sdhi,
    LUN 58), not a dead path."""
    under = {d for lv in seen["lvs"] for _k, dev, disk, _w in lv["on"] for d in (dev, disk)}
    return [(sd, x["addr"], x["wwid"], x["state"], x.get("read", "")) for sd, x in
            sorted(seen["loose"].items(), key=lambda i: (len(i[0]), i[0])) if sd not in seen["disks"] and sd not in under]


# Release one guest LV on a compute (as root, $U its device-mapper UUID): read again, refused unless it is opened 0 times,
# held by nothing, no disk of a running domain and only on iSCSI paths / their partitions / multipath maps / removed
# devices; then dmsetup remove (only the host's mapping: nothing is written to the volume) and each freed whole path is
# given back to the map of its WWID (multipathd add path) when that map exists.
RELEASE_LV = r"""c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$')
m=$(podman ps --format '{{.Names}}' | grep -m1 -x multipathd)
d=""; for x in /sys/block/dm-*; do [ "$(cat $x/dm/uuid 2>/dev/null)" = "$U" ] && d=${x##*/}; done
[ -n "$d" ] || { echo "@@gone"; exit 0; }
n=$(cat /sys/block/$d/dm/name); o=$(dmsetup info -c --noheadings -o open "$n" 2>/dev/null | tr -d ' ')
h=$(ls /sys/block/$d/holders 2>/dev/null | paste -sd, -)
used=""; if [ -n "$c" ]; then used=$(podman exec "$c" sh -c 'for y in $(virsh -c qemu:///system list --name); do virsh -c qemu:///system domblklist $y | awk -v y=$y "\$2 ~ /^\/dev\// {print y, \$2}"; done' |
  while read -r y s; do [ "$(basename "$(readlink -f "$s")")" = "$d" ] && printf ' %s' "$y"; done); fi
echo "@@lv $d $n ${o:-?} ${h:--}"
[ -n "$c" ] || { echo "@@refused no libvirt container: the disks of the running domains cannot be checked"; exit 0; }
[ "$o" = 0 ] || { echo "@@refused opened ${o:-?} time(s) on the host"; exit 0; }
[ -z "$h" ] || { echo "@@refused held by $h"; exit 0; }
[ -z "$used" ] || { echo "@@refused the disk of running domain(s)$used"; exit 0; }
plan=""
for v in $(ls /sys/block/$d/slaves 2>/dev/null); do p=$v
  [ -e /sys/class/block/$v/partition ] && p=$(basename "$(dirname "$(readlink -f /sys/class/block/$v)")")
  case "$p" in
    sd*) if [ -e /sys/block/$p/device ]; then a=$(basename "$(readlink -f /sys/block/$p/device)")
           [ -e /sys/class/iscsi_host/host${a%%:*} ] || { echo "@@refused $v is not an iSCSI device (a disk of the host?)"; exit 0; }
           [ "$v" = "$p" ] && plan="$plan $p:$(sed -E 's/^naa\./3/' /sys/block/$p/device/wwid)"; fi;;
    dm-*) case "$(cat /sys/block/$p/dm/uuid 2>/dev/null)" in mpath-*|part*-mpath-*) ;; *) echo "@@refused $v is not a multipath map"; exit 0;; esac;;
    *) echo "@@refused $v is not an iSCSI device"; exit 0;;
  esac
done
dmsetup remove "$n" || { echo "@@failed dmsetup remove $n"; exit 0; }
echo "@@removed $d $n"
for x in $plan; do p=${x%%:*}; w=${x#*:}; t=""
  for y in /sys/block/dm-*; do [ "$(cat $y/dm/uuid 2>/dev/null)" = "mpath-$w" ] && t=${y##*/}; done
  [ -n "$t" ] || { echo "@@left $p $w"; continue; }
  if [ -n "$m" ]; then podman exec "$m" multipathd add path $p >/dev/null 2>&1; else multipathd add path $p >/dev/null 2>&1; fi
  sleep 2; echo "@@added $p $t $(ls /sys/block/$t/slaves 2>/dev/null | wc -l)"
done"""

# Flush one leftover multipath map on a compute (as root, $W its WWID): read again, refused unless no path of it runs, it
# is opened 0 times, held by nothing and no disk of a running domain; then multipath -f with its device-mapper name; when
# multipath no longer takes it for a multipath device (a real case: "is not a multipath device") and it still has no
# path device, is opened 0 times and held by nothing, dmsetup remove of that name (what multipath -f does underneath).
FLUSH_MAP = r"""c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$')
m=$(podman ps --format '{{.Names}}' | grep -m1 -x multipathd)
d=""; for x in /sys/block/dm-*; do [ "$(cat $x/dm/uuid 2>/dev/null)" = "mpath-$W" ] && d=${x##*/}; done
[ -n "$d" ] || { echo "@@gone"; exit 0; }
o=$(dmsetup info -c --noheadings -o open "$W" 2>/dev/null | tr -d ' '); h=$(ls /sys/block/$d/holders 2>/dev/null | paste -sd, -)
r=0; for v in $(ls /sys/block/$d/slaves 2>/dev/null); do [ "$(cat /sys/block/$v/device/state 2>/dev/null)" = running ] && r=$((r+1)); done
a=$(dmsetup status "$(cat /sys/block/$d/dm/name)" 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i ~ /^[0-9]+:[0-9]+$/ && $(i+1) == "A") k++} END {if (NR) print k + 0}')
[ -n "$a" ] && [ "$a" -lt "$r" ] && r=$a
used=""; if [ -n "$c" ]; then used=$(podman exec "$c" sh -c 'for y in $(virsh -c qemu:///system list --name); do virsh -c qemu:///system domblklist $y | awk -v y=$y "\$2 ~ /^\/dev\// {print y, \$2}"; done' |
  while read -r y s; do [ "$(basename "$(readlink -f "$s")")" = "$d" ] && printf ' %s' "$y"; done); fi
echo "@@map $d ${o:-?} ${h:--} $r"
[ -n "$c" ] || { echo "@@refused no libvirt container: the disks of the running domains cannot be checked"; exit 0; }
[ "$r" = 0 ] || { echo "@@refused $r path(s) of it still run"; exit 0; }
[ "$o" = 0 ] || { echo "@@refused opened ${o:-?} time(s) on the host"; exit 0; }
[ -z "$h" ] || { echo "@@refused held by $h"; exit 0; }
[ -z "$used" ] || { echo "@@refused the disk of running domain(s)$used"; exit 0; }
n=$(cat /sys/block/$d/dm/name); k=$(dmsetup table "$n" 2>/dev/null | awk 'NR == 1 {print $3}')
if [ -n "$m" ]; then f=$(podman exec "$m" multipath -f "$n" 2>&1); else f=$(multipath -f "$n" 2>&1); fi
gone() { ! { [ -e /sys/block/$d/dm ] && [ "$(cat /sys/block/$d/dm/uuid 2>/dev/null)" = "mpath-$W" ]; }; }
gone && { echo "@@flushed $d multipath -f $n"; exit 0; }
[ "$(dmsetup info -c --noheadings -o open "$n" 2>/dev/null | tr -d ' ')" = 0 ] && [ -z "$(ls /sys/block/$d/holders 2>/dev/null)" ] &&
  [ -z "$(ls /sys/block/$d/slaves 2>/dev/null)" ] && dmsetup remove "$n" >/dev/null 2>&1
gone && { echo "@@flushed $d dmsetup remove $n (multipath -f: $(echo "$f" | head -1 | cut -c1-120); table ${k:-none})"; exit 0; }
echo "@@failed $(echo "$f" | head -1) (name $n, table ${k:-none})"
"""

# Delete one iSCSI path device a compute keeps in no map (as root, $D its name, $A its SCSI address H:C:T:L, $W its WWID or
# -): read again, refused unless it is still that address, an iSCSI device, the same WWID, held by nothing (no map, no LV,
# no partition in use), open by no process (multipathd's checkers aside), not mounted and no disk of a domain (also a
# paused one: an incoming migration); all read again 20 s later (a connection being made builds its map within seconds;
# a name can be taken by a new device); refused when it answers a read of its first block (a working device: multipath
# may still add it). Then multipathd del path and echo 1 > device/delete (what os-brick does on a disconnect): the iSCSI
# session stays, nothing is written to the LUN.
DELETE_PATH = r"""c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$')
m=$(podman ps --format '{{.Names}}' | grep -m1 -x multipathd)
MP="|$(pgrep -x multipathd | paste -sd'|' -)|"
x=/sys/block/$D
[ -e $x/device ] || { echo "@@gone"; exit 0; }
a=$(basename "$(readlink -f $x/device)")
[ "$a" = "$A" ] || { echo "@@gone $D is now $a"; exit 0; }
[ -e /sys/class/iscsi_host/host${a%%:*} ] || { echo "@@refused $D is not an iSCSI device (a disk of the host?)"; exit 0; }
w=$(sed -E 's/^naa\./3/' $x/device/wwid 2>/dev/null)
[ "$W" = - ] || [ "$w" = "$W" ] || { echo "@@refused its WWID is now ${w:-unknown}, not $W"; exit 0; }
[ -n "$c" ] || { echo "@@refused no libvirt container: the disks of the domains cannot be checked"; exit 0; }
busy() {
  h=$(for y in $x/holders/* $x/$D*/holders/*; do [ -e "$y" ] && basename "$y"; done | paste -sd, -)
  [ -z "$h" ] || { echo "held by $h"; return; }
  o=$(find /proc/[0-9]*/fd -maxdepth 1 \( -lname "/dev/$D" -o -lname "/dev/$D[0-9]*" \) 2>/dev/null | cut -d/ -f3 | sort -u |
    while read -r q; do case "$MP" in (*"|$q|"*) ;; (*) echo "$q";; esac; done | paste -sd, -)
  [ -z "$o" ] || { echo "open by process(es) $o"; return; }
  grep -qE "^/dev/$D[0-9]* " /proc/mounts && { echo "mounted"; return; }
  u=$(podman exec "$c" sh -c 'for y in $(virsh -c qemu:///system list --name); do virsh -c qemu:///system domblklist $y | awk -v y=$y "\$2 ~ /^\/dev\// {print y, \$2}"; done' |
    while read -r y s; do case "$(basename "$(readlink -f "$s")")" in ("$D"|"$D"[0-9]*) printf ' %s' "$y";; esac; done)
  [ -z "$u" ] || echo "the disk of domain(s)$u"
}
why=$(busy); [ -z "$why" ] || { echo "@@refused $why"; exit 0; }
echo "@@path $D $a $(cat $x/device/state 2>/dev/null) ${w:--}"
sleep 20
[ -e $x/device ] || { echo "@@gone"; exit 0; }
a=$(basename "$(readlink -f $x/device)")
[ "$a" = "$A" ] || { echo "@@gone $D is now $a"; exit 0; }
w=$(sed -E 's/^naa\./3/' $x/device/wwid 2>/dev/null)
[ "$W" = - ] || [ "$w" = "$W" ] || { echo "@@refused its WWID is now ${w:-unknown}, not $W (20 s later)"; exit 0; }
why=$(busy); [ -z "$why" ] || { echo "@@refused $why (20 s later: a connection being made?)"; exit 0; }
f=$(mktemp); (dd if=/dev/$D of=/dev/null bs=4096 count=1 iflag=direct 2>/dev/null; echo $? > $f) &
for i in $(seq 1 20); do [ -s $f ] && break; sleep 1; done
r=$(cat $f 2>/dev/null); rm -f $f
[ "$r" = 0 ] && { echo "@@refused it answers a read of its first block: a working device, not a dead path"; exit 0; }
if [ -n "$r" ]; then echo "@@read exit $r"; else echo "@@read no answer in 20 s"; fi
[ -n "$m" ] && podman exec "$m" multipathd del path /dev/$D >/dev/null 2>&1
echo 1 > $x/device/delete
for i in 1 2 3 4 5; do [ -e /sys/block/$D ] || break; sleep 1; done
[ -e /sys/block/$D ] && echo "@@failed still there after echo 1 > device/delete" || echo "@@deleted $D $a"
"""

# End the incoming copy of a live migration on its destination when it hangs because it cannot open a disk (as root, $I the
# domain): refused unless the domain there is "paused (starting up)" (an incoming one that never started: never a running
# domain), it has exactly one QEMU process, at least one of its disks is a multipath map without a working path, and every
# disk of it is used by no running domain and open by no other process. Then SIGKILL to that QEMU first (it can never go
# on), and fail_if_no_path on those maps, so that the I/O it waits for returns and it ends; libvirt and Nova roll the
# migration back (a real case, dev-vm-01: the abort of Nova had no effect for an hour). Only multipath maps are
# judged (an LV or another device-mapper target never counts as a dead disk); multipathd's checkers holding a device are
# no user of it; the state and the process are read again right before the SIGKILL.
END_INCOMING = r"""c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$')
m=$(podman ps --format '{{.Names}}' | grep -m1 -x multipathd)
[ -n "$c" ] || { echo "@@refused no libvirt container here"; exit 0; }
st=$(timeout 30 podman exec "$c" virsh -c qemu:///system domstate --reason "$I" 2>&1 | head -1)
case "$st" in "paused (starting up)") ;; *) echo "@@not-stuck ${st:-no answer within 30 s}"; exit 0;; esac
P=""; for p in $(pgrep -f "guest=$I,"); do case "$(readlink /proc/$p/exe 2>/dev/null)" in *qemu*) P="$P $p";; esac; done
P=$(echo $P)
[ -n "$P" ] || { echo "@@refused no QEMU process of $I here"; exit 0; }
[ "$(echo $P | wc -w)" = 1 ] || { echo "@@refused $(echo $P | wc -w) QEMU processes of $I"; exit 0; }
echo "@@qemu $P $(ps -o stat= -p $P | tr -d ' ') $(ps -L -o stat= -p $P | grep -c '^D')"
MP=" $(pgrep -x multipathd | paste -sd' ' -) "
DISKS=$(timeout 30 podman exec "$c" cat "/run/libvirt/qemu/$I.xml" 2>/dev/null | grep -oE "<source dev='/dev/[^']+'" | cut -d"'" -f2 | sort -u)
[ -n "$DISKS" ] || DISKS=$(timeout 10 cat /proc/$P/cmdline | tr '\0' '\n' | grep -oE '/dev/[A-Za-z0-9/_.:-]+' | sort -u)
RUNNING=$(timeout 90 podman exec "$c" sh -c 'for y in $(virsh -c qemu:///system list --state-running --name); do virsh -c qemu:///system domblklist $y | awk -v y=$y "\$2 ~ /^\/dev\// {print y, \$2}"; done' |
  while read -r y s; do echo "$y $(basename "$(readlink -f "$s")")"; done)
FAIL=""; OTHER=""
for s in $DISKS; do
  k=$(basename "$(readlink -f "$s")")
  case "$k" in dm-*) ;; *) OTHER="$OTHER $k"; continue;; esac
  case "$(cat /sys/block/$k/dm/uuid 2>/dev/null)" in mpath-*) ;; *) OTHER="$OTHER $k"; continue;; esac
  n=$(cat /sys/block/$k/dm/name 2>/dev/null)
  act=$(dmsetup status "$n" 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i ~ /^[0-9]+:[0-9]+$/ && $(i+1) == "A") a++} END {if (NR) print a + 0}')
  used=$(echo "$RUNNING" | awk -v k="$k" '$2 == k {print $1}' | paste -sd, -)
  o=$(find /proc/[0-9]*/fd -maxdepth 1 -lname "/dev/$k" 2>/dev/null | cut -d/ -f3 | sort -u | paste -sd, -)
  h=$(ls /sys/block/$k/holders 2>/dev/null | paste -sd, -)
  echo "@@disk $k $n $act $(ls /sys/block/$k/slaves 2>/dev/null | paste -sd, - | grep . || echo -)"
  [ -z "$used" ] || { echo "@@refused $k is a disk of running domain(s) $used here"; exit 0; }
  [ -z "$h" ] || { echo "@@refused $k is held by $h"; exit 0; }
  for x in $(echo "$o" | tr , ' '); do
    case "$MP" in *" $x "*) continue;; esac
    [ "$x" = "$P" ] || { echo "@@refused $k is also open by process $x"; exit 0; }
  done
  [ "$act" = 0 ] && FAIL="$FAIL $n"
done
[ -n "$FAIL" ] || { echo "@@refused no multipath disk of it is without a working path${OTHER:+ (not multipath, not judged:$OTHER)}: it hangs for another reason"; exit 0; }
st=$(timeout 30 podman exec "$c" virsh -c qemu:///system domstate --reason "$I" 2>&1 | head -1)
[ "$st" = "paused (starting up)" ] || { echo "@@not-stuck ${st:-no answer within 30 s} (read again right before the end)"; exit 0; }
timeout 5 cat /proc/$P/cmdline 2>/dev/null | tr '\0' ' ' | grep -q "guest=$I," || { echo "@@refused process $P is no longer the QEMU of $I"; exit 0; }
kill -9 "$P" || { echo "@@failed kill -9 $P did not work: nothing else was done"; exit 0; }
echo "@@killed $P"
for n in $FAIL; do
  [ -n "$m" ] && podman exec "$m" multipathd disablequeueing map "$n" >/dev/null 2>&1
  dmsetup message "$n" 0 fail_if_no_path && echo "@@noqueue $n"
done
for i in $(seq 1 30); do [ -d /proc/$P ] || break; sleep 2; done
[ -d /proc/$P ] && echo "@@still $P" || echo "@@ended $P"
"""

# Before a live migration, on its destination, read-only and light (one dmsetup status for every map, sysfs, one find of
# the open devices; host-lvm reads far more, e.g. 263 maps and 136 domains on DCA iha-0): the multipath maps without a
# working path (with how often each is open) and the iSCSI path devices in no map, under nothing, that no process has open
# (multipathd's checkers aside) and that do not answer a read of their first block within 5 s (all read at once): a
# working device in no map (a volume of a shut-off instance on one path, a LUN being connected right now) is no reason
# to leave the compute out.
# Only lines of multipath tables count: a compute without any map answers "No devices found" (a real case, emptied: taken for a map "No" in use without a path, and the compute was left out).
DEST_PATHS = r"""Z=$(dmsetup status --target multipath 2>/dev/null | awk '$4 == "multipath" {n = $1; sub(/:$/, "", n); a = 0; t = 0
  for (i = 2; i < NF; i++) if ($i ~ /^[0-9]+:[0-9]+$/) {t++; if ($(i+1) == "A") a++}
  if (a == 0) print n, t}')
if [ -n "$Z" ]; then I=$(dmsetup info -c --noheadings -o name,minor,open --separator ' ' 2>/dev/null)
  echo "$Z" | while read -r n t; do set -- $(echo "$I" | awk -v n="$n" '$1 == n {print $2, $3}'); echo "@@dead dm-${1:-?} $n ${2:-?} $t"; done
fi
MP=$(pgrep -x multipathd | paste -sd'|' -)
O=$(find /proc/[0-9]*/fd -maxdepth 1 -lname '/dev/sd*' -printf '%h %l\n' 2>/dev/null |
  awk -v mp="$MP" 'BEGIN {n = split(mp, p, "|"); for (i = 1; i <= n; i++) skip["/proc/" p[i] "/fd"] = 1} !($1 in skip) {print $2}' |
  sed -E 's|^/dev/||; s/[0-9]+$//' | sort -u)
T=$(mktemp -d /tmp/wi-dp.XXXXXXXX)
for x in /sys/block/sd*; do v=${x##*/}
  [ -e $x/device ] || continue
  set -- $x/holders/*; [ -e "$1" ] && continue
  set -- $x/$v*/holders/*; [ -e "$1" ] && continue
  a=$(basename "$(readlink -f $x/device)")
  [ -e /sys/class/iscsi_host/host${a%%:*} ] || continue
  echo "$O" | grep -qx "$v" && continue
  echo "$v $a $(cat $x/device/state 2>/dev/null || echo ?) $(sed -E 's/^naa\./3/' $x/device/wwid 2>/dev/null | tr ' ' '_' | grep . || echo -)" >> $T/list
  (timeout -s KILL 5 dd if=/dev/$v of=/dev/null bs=4096 count=1 iflag=direct; echo $? > $T/$v) >/dev/null 2>&1 &
done
if [ -s $T/list ]; then
  for i in 1 2 3 4 5; do n=0; while read -r v r; do [ -s $T/$v ] || n=1; done < $T/list; [ $n = 0 ] && break; sleep 1; done
  while read -r v r; do q=$(cat $T/$v 2>/dev/null); [ "$q" = 0 ] && continue; echo "@@sd $v $r ${q:-none}"; done < $T/list
fi
rm -rf $T
echo @@end"""


def parse_dest_paths(text):
    """The output of DEST_PATHS -> {"dead": [(dm, name, open, path devices)], "loose": [(sd, addr, state, wwid)]}, None
    when it did not end (not read)."""
    text = str(text or "")
    if not re.search(r"^@@end$", text, re.M):
        return None
    dead = [(dm, n, o, int(t)) for dm, n, o, t in re.findall(r"^@@dead (dm-\d+) (\S+) (\d+) (\d+)$", text, re.M)]
    loose = [(sd, a, st + ("" if not rd else ", no answer to a read" if rd == "none" else ", read failed"), w if WWID_RE.match(w) else "")
             for sd, a, st, w, rd in re.findall(r"^@@sd (sd[a-z]+) (\S+) (\S+) (\S+)(?: (\S+))?$", text, re.M) if SCSI_ADDR_RE.match(a)]
    return {"dead": dead, "loose": loose}


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
    """auto, or one compute, or several (comma separated, 16 at most: the least used of them that fits is chosen)."""
    if value == "auto":
        return value
    items = str(value).split(",")
    if len(items) > 16 or not all(HOST_RE.match(h) for h in items):
        raise ValueError(f"invalid destination {value!r}")
    return value


def to_hosts(a):
    """The destinations named in the command line ([] for auto)."""
    return [] if a["to"] == "auto" else a["to"].split(",")


def _pool(value):
    if not POOL_RE.match(value):
        raise ValueError(f"invalid pool {value!r}")
    return value


def _int(value):
    if not re.match(r"^\d{1,9}$", str(value)):
        raise ValueError(f"invalid number {value!r}")
    return int(value)


def _mac(value):
    if not re.match(r"^[0-9a-f]{12}$", str(value)):
        raise ValueError(f"invalid MAC {value!r}")
    return ":".join(str(value)[i:i + 2] for i in range(0, 12, 2))


def _node(value):
    host, _, ip = str(value).partition("=")
    if not HOST_RE.match(host) or not IP_RE.match(ip):
        raise ValueError(f"invalid node {value!r}")
    return {"host": host, "ip": ip}


def _user(value):
    if value != "-" and value not in USERS:
        raise ValueError(f"invalid overcloud user {value!r}")
    return "" if value == "-" else value


def _group(value):
    if not UUID_RE.match(value):
        raise ValueError(f"invalid server group {value!r}")
    return value


def _instance(value):
    if not INSTANCE_RE.match(value):
        raise ValueError(f"invalid instance name {value!r}")
    return value


def _volume_type(value):
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$", str(value)):
        raise ValueError(f"invalid volume type {value!r}")
    return str(value)


def _project(value):
    if not re.match(r"^[0-9a-f]{32}$", str(value)):
        raise ValueError(f"invalid project ID {value!r}")
    return str(value)


def _addresses(value):
    """Allowed address pairs: IPv4 / IPv6 addresses or networks, comma separated (16 at most), or -."""
    if value == "-":
        return []
    out = []
    for x in str(value).split(","):
        try:
            ipaddress.ip_network(x, strict=False)
        except ValueError:
            raise ValueError(f"invalid address {x!r}") from None
        out.append(x)
    if not out or len(out) > 16:
        raise ValueError(f"invalid addresses {value!r}")
    return out


def _addrs(value):
    """SCSI addresses H:C:T:L, comma separated (32 at most): [(h, c, t, l)]."""
    out = []
    for x in str(value).split(","):
        if not re.match(r"^\d{1,4}:\d{1,4}:\d{1,4}:\d{1,5}$", x):
            raise ValueError(f"invalid SCSI address {x!r}")
        out.append(tuple(int(v) for v in x.split(":")))
    if not out or len(out) > 32:
        raise ValueError(f"invalid SCSI addresses {value!r}")
    return out


def _wwid(value):
    if not WWID_RE.match(str(value)):
        raise ValueError(f"invalid WWID {value!r}")
    return str(value)


def _addr(value):
    if not SCSI_ADDR_RE.match(str(value)):
        raise ValueError(f"invalid SCSI address {value!r}")
    return str(value)


def _wwid_or_none(value):
    return "-" if value == "-" else _wwid(value)


def _wwids(value):
    out = str(value).split(",")
    if not out or len(out) > 16 or not all(WWID_RE.match(w) for w in out):
        raise ValueError(f"invalid WWIDs {value!r}")
    return out


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
OPTIONAL = {"nodes": {}, "user": "", "under": 0, "ram": 0, "group": ""}
GRAMMAR = {
    "live-migrate": [("from", _host), ("to", _host_or_auto), ("try", _hosts), ("timeout", _seconds),
                     ("stall", _one_of("abort", "force")), ("nodes", _nodes), ("user", _user), ("under", _percent), ("ram", _mb),
                     ("group", _group)],
    "cold-migrate": [("from", _host), ("to", _host_or_auto), ("try", _hosts), ("timeout", _seconds), ("nodes", _nodes),
                     ("user", _user), ("under", _percent), ("ram", _mb), ("group", _group)],
    "migrate-volume": [("to", _pool), ("try", _pools), ("timeout", _seconds), ("snapshots", _ids)],
    "retype-volume": [("to", _volume_type), ("timeout", _seconds), ("snapshots", _ids)],
    "delete-image": [("expect", _one_of("size0", "any")), ("snapshots", _ids)],
    "delete-snapshots": [("snapshots", _ids)],
    "clear-fdb": [("dp", _int), ("mac", _mac), ("port", _int), ("node", _node), ("user", _user)],
    "port-security": [("project", _project), ("sg", _one_of("port-security-allow-all")), ("allow", _addresses), ("dp", _int),
                      ("pkey", _int), ("node", _node), ("user", _user)],
    "getcert-resubmit": [("node", _node), ("user", _user)],
    "console-test": [("instance", _instance)],
    "rescan-luns": [("addrs", _addrs), ("keep", _wwids), ("node", _node), ("user", _user)],
    "move-leftover": [("node", _node), ("user", _user)],
    "release-lv": [("node", _node), ("user", _user)],
    "rescan-disk": [("wwid", _wwid), ("node", _node), ("user", _user)],
    "flush-map": [("node", _node), ("user", _user)],
    "delete-path": [("addr", _addr), ("wwid", _wwid_or_none), ("node", _node), ("user", _user)],
}
# what the item is when it is not an OpenStack UUID
ID_OF = {"getcert-resubmit": REQUEST_RE, "rescan-luns": WWID_RE, "release-lv": LV_UUID_RE, "flush-map": WWID_RE,
         "delete-path": SD_RE}


def parse(argv):
    """{"verb", "id", <keyword>: value} of a command line; ValueError when anything is not exactly as GRAMMAR says."""
    argv = list(argv)
    if len(argv) < 2 or argv[0] not in GRAMMAR:
        raise ValueError("unknown operation " + " ".join(argv[:1]))
    if not ID_OF.get(argv[0], UUID_RE).match(argv[1]):
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
def prefetchable(method):
    """A read-only method of Director whose result Director.prefetch can read ahead: the next call with the same positional
    arguments gets that result (once; the call after it reads again). Keyword arguments (show) only change the log."""
    import functools

    @functools.wraps(method)
    def read(self, *args, **kwargs):
        ahead = self._ahead.pop((method.__name__, repr(args)), None) if getattr(self, "_ahead", None) else None
        if ahead is not None:
            return ahead.result()
        return method(self, *args, **kwargs)
    return read


class Ahead:
    """The result of a read already made (prefetch without threads)."""

    def __init__(self, fn, args):
        self.value, self.error = None, None
        try:
            self.value = fn(*args)
        except Exception as e:   # noqa: BLE001  raised where the result is used, as without prefetch
            self.error = e

    def result(self):
        if self.error is not None:
            raise self.error
        return self.value


class Director:
    """Runs the OpenStack clients (and ssh to the overcloud nodes) on the director. runner(argv, timeout) -> (rc, output);
    clock() -> seconds; sleep(seconds); write(line)."""

    def __init__(self, runner=None, clock=None, sleep=None, write=None, until=None, parallel=None, cancelled=None):
        self.runner = runner or self._subprocess
        # was the run cancelled on the portal: the flag file "cancel" the playbook puts in the folder of this script
        # (WI_LIVE_DIR, wi_analysis.live_poll); a test gives its own function
        self._cancelled = cancelled
        # reads made ahead (prefetch) run in threads with the real commands only; a test's runner gets them one after the
        # other, in the order given, when prefetch is called
        self.parallel = runner is None if parallel is None else parallel
        self._ahead = {}
        self._incoming_seen = set()   # (node, instance) whose incoming copy was already checked (end_incoming)
        self.skipped = []   # destinations left out before a migration: (compute, why), for the result when none is left
        self._threads = None
        self.clock = clock or time.time
        self.sleep = sleep or time.sleep
        self.write = write or self._print
        self._modern = None
        self._inventory = None
        self.names = {}
        self.started = self.clock()
        self.marks = []   # (phase, clock) where a phase of a migration began: the item's last line before RESULT gives the times
        # the end of the time of this item (epoch seconds, from the fix script: WI_ITEM_UNTIL): no wait runs past it and no
        # new change starts after it, so the portal always gets the result before it gives up on the item
        if until is None:
            until = os.environ.get("WI_ITEM_UNTIL", "")
        self.until = int(until) if str(until).isdigit() else 0

    def time_left(self):
        return max(0, self.until - self.clock()) if self.until else None

    def prefetch(self, *calls):
        """Read ahead, at once: calls are (method name, positional arguments...) of @prefetchable methods, whose next call
        with the same arguments gets the result. Only reads: a check reads what it needs a little earlier and all together
        instead of one after the other (a real case: about 3 minutes of checks per instance, 25-80 s of
        migration). A read whose result is not used is simply dropped."""
        for name, *args in calls:
            key = (name, repr(tuple(args)))
            if key in self._ahead:
                continue
            raw = getattr(type(self), name).__wrapped__   # the read itself, not its look-up of what was read ahead

            def fn(*args, raw=raw):
                return raw(self, *args)
            if self.parallel:
                if self._threads is None:
                    from concurrent.futures import ThreadPoolExecutor
                    self._threads = ThreadPoolExecutor(max_workers=12)
                self._ahead[key] = self._threads.submit(fn, *args)
            else:
                self._ahead[key] = Ahead(fn, args)

    def forget(self, name):
        """Drop the reads of one method made ahead: their results are stale now (after a wait), they are read again."""
        for key in [k for k in self._ahead if k[0] == name]:
            self._ahead.pop(key, None)

    def mark(self, phase):
        """The phase that begins now (a migration: "migration", then "checks after"); the phase before it is "checks before"."""
        if not self.marks or self.marks[-1][0] != phase:   # a second attempt goes on in the same phase
            self.marks.append((phase, self.clock()))

    def timing(self):
        """'Time: checks before 95 s, migration 41 s, checks after 63 s (in all 3 min 19 s)', or '' without marks."""
        if not self.marks:
            return ""
        end = self.clock()
        bounds = [("checks before", self.started)] + self.marks
        parts = [f"{name} {minutes(max(0, (bounds[i + 1][1] if i + 1 < len(bounds) else end) - at))}"
                 for i, (name, at) in enumerate(bounds)]
        return f"Time: {', '.join(parts)} (in all {minutes(max(0, end - self.started))})"

    @staticmethod
    def _print(line):
        sys.stdout.write(line + "\n")
        sys.stdout.flush()

    @staticmethod
    def _subprocess(argv, timeout):
        argv = SSH_POOL.wrap(argv)
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
        """One line of the log: names read from OpenStack (volumes, images) may hold line breaks or control characters,
        which must never make a line of their own (a forged RESULT or end marker)."""
        self.write(re.sub(r"[\x00-\x1f\x7f]", " ", str(text)))

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

    def cancel_asked(self):
        """Was the run of this item cancelled on the portal (its live migration is then aborted)?"""
        if self._cancelled is not None:
            return bool(self._cancelled())
        folder = os.environ.get("WI_LIVE_DIR", "")
        return bool(re.match(r"^/tmp/wi-live\.[A-Za-z0-9]+$", folder)) and os.path.exists(os.path.join(folder, "cancel"))

    # ---- client generation: python-openstackclient 5.5 (RHOSP 17.1) has server migration list / show / abort / force
    # complete and server migrate --live-migration --host; older clients (4.0 on RHOSP 16.2) use the nova client.
    @prefetchable
    def modern(self):
        if self._modern is None:
            rc, out = self.run(["openstack", "--version"], show=False)
            m = re.search(r"(\d+)\.(\d+)", out or "")
            self._modern = bool(m) and (int(m.group(1)), int(m.group(2))) >= (5, 5)
        return self._modern

    # ---- compute
    @prefetchable
    def server(self, sid, show=False):
        """The instance as Nova sees it now, None when it does not exist, {"unknown": reason} when the API failed."""
        value, rc, out = self.read(["openstack", "server", "show", sid], show=show)
        if rc != 0 or not isinstance(value, dict):
            if gone(out, "server"):
                return None
            return {"unknown": first_line(out) or f"exit {rc}"}
        fault = value.get("fault")
        return {"name": str(value.get("name") or sid), "status": str(value.get("status") or "").upper(),
                "task": str(field(value, "OS-EXT-STS:task_state", "task_state")).lower(),
                "host": str(field(value, "OS-EXT-SRV-ATTR:host", "compute_host", "host")),
                "instance": str(field(value, "OS-EXT-SRV-ATTR:instance_name", "instance_name")),
                "power": power_name(field(value, "OS-EXT-STS:power_state", "power_state")),
                "fault": str((fault or {}).get("message") if isinstance(fault, dict) else fault or ""),
                "volumes": list(dict.fromkeys(UUID_ANY.findall(str(value.get("volumes_attached") or ""))))}

    @prefetchable
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

    @prefetchable
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
            return self.run(["openstack", "--os-compute-api-version", NOVA_ABORT, "server", "migration", "abort", sid, str(mid)])
        return self.run(["nova", "--os-compute-api-version", NOVA_ABORT, "live-migration-abort", sid, str(mid)])

    def action_request(self, sid, action, since):
        """Request ID of the newest instance action `action` that started at or after `since` (epoch seconds), '' when
        there is none: the proof that Nova accepted a request (an abort is the action live_migration_cancel)."""
        events, rc, _ = self.read(["openstack", "server", "event", "list", sid])
        start = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(since))
        found = [e for e in events or [] if isinstance(e, dict) and str(e.get("Action") or e.get("action") or "") == action
                 and str(e.get("Start Time") or e.get("start_time") or "") >= start]
        latest = max(found, key=lambda e: str(e.get("Start Time") or e.get("start_time") or ""), default=None)
        return str(latest.get("Request ID") or latest.get("request_id") or "") if latest else ""

    def live_migrations_running(self, exclude="", show=False):
        """Live migrations of other instances than `exclude` not ended yet on the site, changed in the last 6 hours (a record
        a dead compute left "running" long ago does not count): [{"id", "server", "status", "source", "dest"}], None when
        the list could not be read."""
        since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.clock() - 6 * 3600))
        if self.modern():
            value, rc, _ = self.read(["openstack", "--os-compute-api-version", NOVA_LIST, "server", "migration", "list",
                                      "--changes-since", since], show=show)
            rows = [lower_keys(x) for x in value if isinstance(x, dict)] if rc == 0 and isinstance(value, list) else None
        else:
            rc, out = self.run(["nova", "--os-compute-api-version", NOVA_LIST, "migration-list", "--changes-since", since],
                               show=show)
            rows = table(out)[0] if rc == 0 else None
        if rows is None:
            return None
        busy = []
        for r in rows:
            server = str(r.get("server_uuid") or r.get("instance_uuid") or "")
            kind, status = str(r.get("migration_type") or r.get("type") or "").lower(), str(r.get("status") or "").lower()
            if server and server != exclude and kind == "live-migration" and status in LIVE_BUSY:
                busy.append({"id": str(r.get("id") or ""), "server": server, "status": status,
                             "source": str(r.get("source_compute") or ""), "dest": str(r.get("dest_compute") or "")})
        return busy

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
                # a traceback of frames only: the exception class Nova kept (details) and where it was raised
                tb, where = e.get("traceback") or "", last_frame(e.get("traceback"))
                why = last_error(tb) or " ".join(x for x in (str(e.get("details") or ""), f"in {where}" if where else "") if x)
                texts.append(f"{e.get('event') or ''}: {why}".strip(": "))
        return "\n".join(texts)

    def rollback_state(self, sid, actions):
        """Nova's rollback on the destination of the last of these instance actions: "ended" (its event has a finish
        time), "running", or "" (no such event, or the events could not be read)."""
        events, rc, _ = self.read(["openstack", "server", "event", "list", sid], show=False)
        wanted = [e for e in events if isinstance(e, dict) and str(e.get("Action") or e.get("action") or "") in actions] \
            if isinstance(events, list) else []
        if not wanted:
            return ""
        latest = max(wanted, key=lambda e: str(e.get("Start Time") or e.get("start_time") or ""))
        req = str(latest.get("Request ID") or latest.get("request_id") or "")
        detail, rc, _ = self.read(["openstack", "server", "event", "show", sid, req], show=False) if req else (None, 1, "")
        for e in (detail or {}).get("events") or [] if isinstance(detail, dict) else []:
            if isinstance(e, dict) and "rollback_live_migration_at_destination" in str(e.get("event") or ""):
                return "ended" if e.get("finish_time") else "running"
        return ""

    def node(self, host, nodes=None, user=""):
        """(ctlplane address, SSH user) of an overcloud node, (None, None) when unknown: from the node list of the check,
        else from the TripleO Ansible inventory on this director (only its group / host / address / user lines)."""
        h = short(host)
        if nodes and nodes.get(h):
            return nodes[h], user if user in USERS else self.node_user()
        if self._inventory is None:
            rc, out = self.run(["sh", "-c", INVENTORY_GREP], show=False)
            self._inventory = parse_inventory(out)
        x = self._inventory.get(h) or {}
        try:
            private = ipaddress.ip_address(x.get("ip") or "").is_private
        except ValueError:
            private = False
        if not private:
            return None, None
        return x["ip"], x.get("user") if x.get("user") in USERS else self.node_user()

    def node_user(self):
        rc, out = self.run(["cat", "/etc/rhosp-release"], show=False)
        return "tripleo-admin" if re.search(r"release 1[7-9]", out or "") else "heat-admin"

    @prefetchable
    def instance_dir(self, ip, user, sid):
        """On a compute, read-only: is the directory of the instance there (/var/lib/nova/instances/<uuid>), the filesystem
        type of the instances path, is a domain of the instance defined there: {"exists", "changed", "fstype", "domain"
        (yes / no / unknown)} or {"unknown": why}."""
        inner = (f"d=/var/lib/nova/instances/{sid}; if [ -e \"$d\" ]; then echo \"@@exists yes $(stat -c %y \"$d\" | cut -c1-19)\"; "
                 "else echo '@@exists no'; fi; echo \"@@fstype $(findmnt -n -T /var/lib/nova/instances -o FSTYPE)\"; "
                 "c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$'); "
                 "if [ -z \"$c\" ]; then echo '@@domain unknown'; "
                 f"elif podman exec \"$c\" virsh -c qemu:///system dominfo {sid} >/dev/null 2>&1; then echo '@@domain yes'; "
                 "else echo '@@domain no'; fi")
        self.say(f"$ ssh {user}@{ip} sudo ls -ld /var/lib/nova/instances/{sid}; findmnt -T /var/lib/nova/instances; virsh "
                 f"dominfo {sid} (is a directory of the instance left there?)")
        rc, out = self.run(SSH + [f"{user}@{ip}", "sudo -n sh -c " + shlex.quote(inner)], show=False, timeout=90)
        found = dict(re.findall(r"^@@(exists|fstype|domain) ?(.*)$", str(out or ""), re.M))
        if rc != 0 or "exists" not in found:
            return {"unknown": first_line(out) or f"exit {rc}"}
        return {"exists": found["exists"].startswith("yes"), "changed": found["exists"][4:].strip(),
                "fstype": found.get("fstype", "").strip().lower(), "domain": (found.get("domain") or "unknown").strip()}

    def move_aside(self, ip, user, sid, stamp):
        """Move a leftover directory of the instance on a compute aside (renamed, never deleted): (rc, output)."""
        path = f"/var/lib/nova/instances/{sid}"
        inner = f"[ -d {path} ] && [ ! -e {path}.leftover-{stamp} ] && mv {path} {path}.leftover-{stamp} && ls -ld {path}.leftover-{stamp}"
        self.say(f"$ ssh {user}@{ip} sudo mv {path} {path}.leftover-{stamp}")
        return self.run(SSH + [f"{user}@{ip}", "sudo -n sh -c " + shlex.quote(inner)], show=False, timeout=60)

    @prefetchable
    def disk_paths(self, ip, user, since, show=True):
        """On a compute, read-only: the kernel lines since `since` (epoch seconds) about removed SCSI devices and dm I/O
        errors, the multipath maps with their number of paths, and the disks of every running domain: {"removed": [(host,
        channel, target, lun)], "io": {dm}, "maps": {dm: {"wwid", "paths", "vendor"}}, "users": {dm: [(domain, uuid)]}}
        or {"unknown": why}."""
        inner = (f"echo @@kernel; journalctl -k --since @{max(0, int(since))} --no-pager 2>/dev/null | "
                 "grep -E 'alua: Detached|Synchronizing SCSI cache|I/O error, dev dm-[0-9]+' | tail -n 300; "
                 "echo @@maps; m=$(podman ps --format '{{.Names}}' | grep -m1 -x multipathd); "
                 "if [ -n \"$m\" ]; then podman exec \"$m\" multipath -ll 2>/dev/null; else multipath -ll 2>/dev/null; fi; "
                 "echo @@domains; c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$'); "
                 + DOMAIN_DISKS)
        if show:
            self.say(f"$ ssh {user}@{ip} sudo journalctl -k --since @{max(0, int(since))}; multipath -ll; virsh domblklist "
                     "(did a disk of another instance lose its paths?)")
        rc, out = self.run(SSH + [f"{user}@{ip}", "sudo -n sh -c " + shlex.quote(inner)], show=False, timeout=180)
        if rc != 0 or "@@domains" not in str(out or ""):
            return {"unknown": first_line(out) or f"exit {rc}"}
        return parse_disk_paths(out)

    def rescan_luns(self, ip, user, addrs, wwids):
        """Scan only these SCSI addresses (host, channel, target, lun) on a compute, each only when no device is at that
        address now (a device there is never touched); a new device is kept (and given to multipathd) only when its WWID is
        one of `wwids`, deleted again otherwise: [(address, sd, wwid, kept)]."""
        addrs = [x for x in addrs if len(x) == 4 and all(isinstance(v, int) for v in x)]
        wwids = [w for w in wwids if WWID_RE.match(w)]
        if not addrs or not wwids:
            return []
        keep = " ".join(wwids)
        chunks = []
        for h, c, t, l in addrs:
            a = f"{h}:{c}:{t}:{l}"
            chunks.append(
                f"if ls -d /sys/class/scsi_host/host{h}/device/session*/target*/{a} >/dev/null 2>&1; then echo '@@present {a}'; "
                f"else echo '{c} {t} {l}' > /sys/class/scsi_host/host{h}/scan; sleep 3; "
                f"for b in /sys/class/scsi_host/host{h}/device/session*/target*/{a}/block/*; do [ -e \"$b\" ] || continue; "
                "sd=$(basename \"$b\"); w=3$(sed -E 's/^naa\\.//' /sys/block/$sd/device/wwid); "
                f"case \" {keep} \" in *\" $w \"*) "
                "if [ -n \"$m\" ]; then podman exec \"$m\" multipathd add path $sd >/dev/null 2>&1; "
                "else multipathd add path $sd >/dev/null 2>&1; fi; "
                f"echo \"@@kept {a} $sd $w\";; *) echo 1 > /sys/block/$sd/device/delete; echo \"@@deleted {a} $sd $w\";; esac; done; fi")
        inner = "m=$(podman ps --format '{{.Names}}' | grep -m1 -x multipathd); " + "; ".join(chunks)
        self.say(f"$ ssh {user}@{ip} sudo: scan only SCSI address(es) {', '.join(f'{h}:{c}:{t}:{l}' for h, c, t, l in addrs)} "
                 f"(none where a device is now); keep a new device only with the WWID of a map that lost its paths ({keep})")
        rc, out = self.run(SSH + [f"{user}@{ip}", "sudo -n sh -c " + shlex.quote(inner)], show=False, timeout=180)
        return [(a, sd, w, kind == "kept") for kind, a, sd, w in re.findall(r"^@@(kept|deleted) (\S+) (\S+) (\S+)$", str(out or ""), re.M)]

    @prefetchable
    def job_blocked(self, ip, user, instance):
        """'' when libvirt can take a job on the domain on its compute now (virsh domjobinfo answers), else why: a reconnect
        of virtqemud that never ended holds its job lock (cannot acquire state change lock), and every job fails."""
        inner = ("c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$'); [ -n \"$c\" ] || exit 7; "
                 f"timeout 45 podman exec \"$c\" virsh -c qemu:///system domjobinfo {instance} 2>&1")
        self.say(f"$ ssh {user}@{ip} sudo podman exec <nova_virtqemud|nova_libvirt> virsh domjobinfo {instance} (can libvirt "
                 "take a job on it?)")
        rc, out = self.run(SSH + [f"{user}@{ip}", "sudo -n sh -c " + shlex.quote(inner)], show=False, timeout=90)
        if STUCK_LOCK.search(str(out or "")):
            return last_error(out) or first_line(out)
        return "virsh domjobinfo did not answer within 45 s" if rc == 124 else ""

    @prefetchable
    def job_progress(self, ip, user, instance):
        """The migration job of a domain on its source, from libvirt (virsh domjobinfo, read-only; libvirt answers it while
        the migration runs, as Nova itself reads it): parse_jobinfo(), or {"unknown": why}. Nova's own migration record
        has no memory figures on RHOSP 16.2 (a real case: "migration 46307 running" for 23 minutes, nothing more)."""
        inner = ("c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$'); [ -n \"$c\" ] || exit 7; "
                 f"timeout 30 podman exec \"$c\" virsh -c qemu:///system domjobinfo {instance} 2>&1")
        rc, out = self.run(SSH + [f"{user}@{ip}", "sudo -n sh -c " + shlex.quote(inner)], show=False, timeout=60)
        job = parse_jobinfo(out) if rc == 0 else {}
        return job if job.get("total") else {"unknown": first_line(out) or f"exit {rc}"}

    def switch_pause(self, ip, user, instance):
        """Give the live migration of a domain the pause at switch-over Nova is configured to reach (live_migration_downtime
        of nova.conf on its source, else DOWNTIME_DEFAULT_MS) when libvirt allows less now: virsh migrate-getmaxdowntime,
        then migrate-setmaxdowntime (a parameter of this migration job only, as Nova sets it). {"before", "limit", "now"}
        in ms, or {"unknown": why}."""
        if not INSTANCE_RE.match(str(instance)):
            return {"unknown": "invalid domain name"}
        virsh = f"timeout 30 podman exec \"$c\" virsh -c qemu:///system"
        inner = ("c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$'); [ -n \"$c\" ] || exit 7; "
                 f"lim=$(sed -n 's/^live_migration_downtime[[:space:]]*=[[:space:]]*\\([0-9][0-9]*\\).*/\\1/p' {NOVA_CONF} 2>/dev/null "
                 f"| tail -n 1); lim=${{lim:-{DOWNTIME_DEFAULT_MS}}}; cur=$({virsh} migrate-getmaxdowntime {instance} 2>&1); "
                 "echo \"@@before $cur\"; echo \"@@limit $lim\"; case \"$cur\" in ''|*[!0-9]*) exit 8;; esac; "
                 f"[ \"$cur\" -lt \"$lim\" ] && {virsh} migrate-setmaxdowntime {instance} \"$lim\" > /dev/null 2>&1; "
                 f"echo \"@@now $({virsh} migrate-getmaxdowntime {instance} 2>&1)\"")
        self.say(f"$ ssh {user}@{ip} sudo: virsh migrate-getmaxdowntime {instance}; nova.conf live_migration_downtime "
                 f"(else {DOWNTIME_DEFAULT_MS} ms); virsh migrate-setmaxdowntime {instance} <that> when less is allowed now")
        rc, out = self.run(SSH + [f"{user}@{ip}", "sudo -n sh -c " + shlex.quote(inner)], show=False, timeout=120)
        vals = dict(re.findall(r"^@@(before|limit|now) (\d+)$", str(out or ""), re.M))
        if rc != 0 or not {"before", "limit", "now"} <= set(vals):
            return {"unknown": first_line(re.sub(r"^@@\w+ ", "", str(out or ""), flags=re.M)) or f"exit {rc}"}
        return {k: int(v) for k, v in vals.items()}

    @prefetchable
    def ping_targets(self, sid):
        """[(network id, IPv4 address)] of the ports of an instance (port list, then port show of each; 4 addresses at
        most), None when not readable."""
        ports, rc, _ = self.read(["openstack", "port", "list", "--server", sid, "-c", "ID"])
        if rc != 0 or not isinstance(ports, list):
            return None
        out = []
        for p in ports[:4]:
            value, rc, _ = self.read(["openstack", "port", "show", str(field(p, "ID", "id")), "-c", "network_id", "-c", "fixed_ips"])
            net = str((value or {}).get("network_id") or "") if isinstance(value, dict) else ""
            if rc != 0 or not UUID_RE.match(net):
                continue
            for addr in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", str(value.get("fixed_ips") or "")):
                if IPV4_RE.match(addr) and (net, addr) not in out:
                    out.append((net, addr))
        return out[:4]

    def ping_guest(self, ip, user, targets):
        """Ping each address of an instance from the OVN metadata namespace of its network on a compute (ip netns exec
        ovnmeta-<network> ping, 3 packets, read-only): parse_ping()."""
        parts = [f"echo '@@ping {addr}'; ip netns exec ovnmeta-{net} ping -n -c 3 -i 0.5 -W 1 {addr} 2>&1 | tail -n 3"
                 for net, addr in targets if UUID_RE.match(str(net)) and IPV4_RE.match(str(addr))]
        if not parts:
            return {}
        rc, out = self.run(SSH + [f"{user}@{ip}", "sudo -n sh -c " + shlex.quote("; ".join(parts))], show=False, timeout=60)
        return parse_ping(out)

    @prefetchable
    def dest_pressure(self, ip, user):
        """The direct reclaim and compaction stalls so far on a compute and its available memory (/proc/vmstat and
        /proc/meminfo, read-only, no sudo): parse_pressure(), or {"unknown": why}."""
        rc, out = self.run(SSH + [f"{user}@{ip}", PRESSURE_COMMAND], show=False, timeout=30)
        p = parse_pressure(out) if rc == 0 else {}
        return p or {"unknown": first_line(out) or f"exit {rc}"}

    def controller(self):
        """(ctlplane address, SSH user) of the first controller of the TripleO inventory on this director, (None, None)."""
        if self._inventory is None:
            rc, out = self.run(["sh", "-c", INVENTORY_GREP], show=False)
            self._inventory = parse_inventory(out)
        name = next((h for h in sorted(self._inventory) if "controller" in h), None)
        return self.node(name) if name else (None, None)

    @prefetchable
    def bdm_rows(self, sid):
        """Nova's connection of each volume of the instance, from its database on a controller (target and LUN only, no
        secret): [(device, volume, iqn, lun)], or None when it cannot be read."""
        ip, user = self.controller()
        if not ip or not UUID_RE.match(sid):
            return None
        sql = ("SELECT device_name, volume_id, IFNULL(JSON_VALUE(connection_info, '$.data.target_iqn'), '-'), "
               "IFNULL(JSON_VALUE(connection_info, '$.data.target_lun'), '-') FROM nova.block_device_mapping "
               f"WHERE instance_uuid = '{sid}' AND deleted = 0 AND destination_type = 'volume'")
        inner = ("g=$(podman ps -q -f name=galera-bundle | head -1); [ -n \"$g\" ] || exit 7; "
                 f"podman exec \"$g\" mysql -N -B -e {shlex.quote(sql)} | sed 's/^/@@bdm /'")
        self.say(f"$ ssh {user}@{ip} sudo podman exec <galera> mysql: Nova's connection (target, LUN) of each volume of the "
                 "instance (no secret)")
        rc, out = self.run(SSH + [f"{user}@{ip}", "sudo -n sh -c " + shlex.quote(inner)], show=False, timeout=90)
        if rc != 0:
            return None
        rows = [tuple(x.strip() for x in line[6:].split("\t")) for line in str(out or "").splitlines() if line.startswith("@@bdm ")]
        return [r for r in rows if len(r) == 4]

    def attachment_rows(self, sid):
        """Read-only, from the databases on a controller (SELECT, never connection_info itself: it holds the CHAP secret):
        for each volume of the instance, the attachment Nova uses (block device mapping) and every Cinder attachment of it
        {volume: {"nova": id, "atts": {id: {"status", "host", "connector", "connected", "server", "minutes"}}}} (minutes:
        since its last change), None when they cannot be read."""
        ip, user = self.controller()
        if not ip or not UUID_RE.match(sid):
            return None
        mine = (f"SELECT volume_id FROM nova.block_device_mapping WHERE instance_uuid = '{sid}' AND deleted = 0 "
                "AND destination_type = 'volume'")
        sql = (f"SELECT 'bdm', volume_id, IFNULL(attachment_id, '') FROM nova.block_device_mapping WHERE instance_uuid = '{sid}' "
               "AND deleted = 0 AND destination_type = 'volume'; "
               "SELECT 'att', volume_id, id, IFNULL(attach_status, ''), IFNULL(attached_host, ''), "
               "IFNULL(JSON_VALUE(connector, '$.host'), ''), IF(connection_info IS NULL, 0, 1), IFNULL(instance_uuid, ''), "
               "TIMESTAMPDIFF(MINUTE, IFNULL(updated_at, created_at), UTC_TIMESTAMP()) FROM cinder.volume_attachment "
               f"WHERE deleted = 0 AND volume_id IN ({mine})")
        inner = ("g=$(podman ps -q -f name=galera-bundle | head -1); [ -n \"$g\" ] || exit 7; "
                 f"podman exec \"$g\" mysql -N -B -e {shlex.quote(sql)} | sed 's/^/@@vatt /'")
        self.say(f"$ ssh {user}@{ip} sudo podman exec <galera> mysql: the attachment Nova uses and every Cinder attachment of "
                 "each volume of the instance (status, host, connector host, connected or not; no secret)")
        rc, out = self.run(SSH + [f"{user}@{ip}", "sudo -n sh -c " + shlex.quote(inner)], show=False, timeout=90)
        if rc != 0:
            return None
        facts = {}
        for line in str(out or "").splitlines():
            f = [x.strip() for x in line[7:].split("\t")] if line.startswith("@@vatt ") else []
            if len(f) == 3 and f[0] == "bdm" and UUID_RE.match(f[1]):
                facts.setdefault(f[1], {"nova": "", "atts": {}})["nova"] = f[2]
            elif len(f) == 9 and f[0] == "att" and UUID_RE.match(f[1]) and UUID_RE.match(f[2]):
                facts.setdefault(f[1], {"nova": "", "atts": {}})["atts"][f[2]] = {
                    "status": f[3].lower(), "host": f[4], "connector": f[5], "connected": f[6] == "1", "server": f[7],
                    "minutes": int(f[8]) if f[8].lstrip("-").isdigit() else None}
        return facts

    def disk_facts(self, ip, user, instance, luns):
        """On the compute of the instance, read-only: each disk of its domain {target: {"dm", "kind" (mpath, LVM = an LV
        the host activated, sd = one SCSI device), "wwid", "paths", "pv" (offset of an LVM label in the first 4 KiB of the
        whole disk, "no", or "-" not read)}}, and for Nova's (iqn, lun) pairs the devices at that LUN on the sessions of
        that target {(iqn, lun): [(device, wwid, [domains])]}: {"disks", "luns"} or {"unknown": why}."""
        luns = [(q, str(n)) for q, n in luns if IQN_RE.match(q or "") and str(n).isdigit()]
        script = r"""c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$'); [ -n "$c" ] || exit 7
V="podman exec $c virsh -c qemu:///system"
m=$(podman ps --format '{{.Names}}' | grep -m1 -x multipathd)
if [ -n "$m" ]; then L=$(podman exec "$m" multipath -ll 2>/dev/null); else L=$(multipath -ll 2>/dev/null); fi
ww() { sed -E 's/^naa\./3/' /sys/block/$1/device/wwid 2>/dev/null; }
U=$(podman exec "$c" sh -c 'for x in $(virsh -c qemu:///system list --name); do virsh -c qemu:///system domblklist $x 2>/dev/null | awk -v x=$x "\$2 ~ /^\/dev\// {print \$2, x}"; done' | while read -r s x; do echo "$(basename "$(readlink -f "$s")") $x"; done)
echo @@disks
$V domblklist @I@ 2>/dev/null | awk '$2 ~ /^\/dev\// {print $1, $2}' | while read -r t s; do
  d=$(basename "$(readlink -f "$s")")
  if [ -e /sys/block/$d/dm ]; then k=$(cut -d- -f1 /sys/block/$d/dm/uuid 2>/dev/null); w=$(cat /sys/block/$d/dm/name)
    n=$(printf '%s\n' "$L" | awk -v d=$d '/^[^ |`]/ {if ($0 ~ / dm-[0-9]+ /) on = ($2 == d || $3 == d); next} on && / sd[a-z]+ / && /active ready/ {n++} END {print n+0}')
  else k=sd; w=$(ww $d); n=0; [ "$(cat /sys/block/$d/device/state 2>/dev/null)" = running ] && n=1; fi
  pv=-
  if [ "$n" -gt 0 ] && [ "$k" != LVM ]; then pv=$(timeout 10 dd if=/dev/$d bs=4096 count=1 iflag=direct 2>/dev/null | grep -abo LABELONE | head -1 | cut -d: -f1); pv=${pv:-no}; fi
  echo "@@disk $t $d ${k:-dm} ${w:-none} $n $pv"
done
echo @@luns
printf '%s\n' "@Q@" | while read -r q l; do
  [ -n "$q" ] || continue
  for ss in /sys/class/iscsi_session/session*; do
    [ "$(cat $ss/targetname 2>/dev/null)" = "$q" ] || continue
    h=$(ls -d $ss/device/target* 2>/dev/null | head -1 | sed -E 's/.*target([0-9]+):.*/\1/')
    for a in /sys/class/scsi_device/$h:*:*:$l /sys/class/scsi_device/$h:*:*:$((l + 16384)); do
      [ -e "$a" ] || continue
      sd=$(ls $a/device/block 2>/dev/null | head -1); [ -n "$sd" ] || continue
      hd=$(ls /sys/block/$sd/holders 2>/dev/null | head -1); dv=${hd:-$sd}
      echo "@@lun $q $l $dv $(ww $sd) $(printf '%s\n' "$U" | awk -v d=$dv '$1 == d {print $2}' | paste -sd, -)"
    done
  done
done"""
        inner = script.replace("@I@", instance).replace("@Q@", "\n".join(f"{q} {n}" for q, n in luns))
        self.say(f"$ ssh {user}@{ip} sudo: the disks of {instance} (multipath map or not, paths, an LVM label on the whole "
                 "disk) and the devices at Nova's LUN numbers there")
        rc, out = self.run(SSH + [f"{user}@{ip}", "sudo -n sh -c " + shlex.quote(inner)], show=False, timeout=180)
        if rc != 0 or "@@luns" not in str(out or ""):
            return {"unknown": first_line(out) or f"exit {rc}"}
        disks, found = {}, {}
        for line in str(out).splitlines():
            p = line.split(" ")
            if p[0] == "@@disk" and len(p) >= 7:
                disks[p[1]] = {"dm": p[2], "kind": p[3], "wwid": p[4], "paths": int(p[5]) if p[5].isdigit() else 0, "pv": p[6]}
            elif p[0] == "@@lun" and len(p) >= 5:
                found.setdefault((p[1], p[2]), []).append((p[3], p[4], [x for x in (p[5] if len(p) > 5 else "").split(",") if x]))
        return {"disks": disks, "luns": found}

    @prefetchable
    def lvm_filter(self, ip, user):
        """Does the LVM of a compute leave the LVs inside guest volumes alone: {"safe": bool, "filter": text} or {"unknown":
        why}. Safe when its global_filter rejects every device it does not name (r|.*|), or it uses an LVM devices file."""
        inner = ("echo \"@@filter $(lvmconfig --type full devices/global_filter 2>/dev/null | cut -d= -f2-)\"; "
                 "echo \"@@devicesfile $(lvmconfig --type full devices/use_devicesfile 2>/dev/null | cut -d= -f2) "
                 "$([ -s /etc/lvm/devices/system.devices ] && echo present || echo absent)\"")
        self.say(f"$ ssh {user}@{ip} sudo lvmconfig devices/global_filter devices/use_devicesfile (does its LVM leave guest "
                 "volumes alone?)")
        rc, out = self.run(SSH + [f"{user}@{ip}", "sudo -n sh -c " + shlex.quote(inner)], show=False, timeout=60)
        f = re.search(r"^@@filter (.*)$", str(out or ""), re.M)
        df = re.search(r"^@@devicesfile (\S*) (\S+)$", str(out or ""), re.M)
        if rc != 0 or not f:
            return {"unknown": first_line(out) or f"exit {rc}"}
        safe = bool(LVM_REJECT_ALL.search(f.group(1))) or bool(df and df.group(1) == "1" and df.group(2) == "present")
        return {"safe": safe, "filter": f.group(1).strip() or "not set (accepts every device)"}

    @prefetchable
    def dead_disks(self, ip, user):
        """On a compute, read-only, now: the disks of running domains whose multipath map has no path {dm: wwid} (a base
        line before a migration, so that only what it removes is reported after), or None."""
        inner = ("m=$(podman ps --format '{{.Names}}' | grep -m1 -x multipathd); echo @@maps; "
                 "if [ -n \"$m\" ]; then podman exec \"$m\" multipath -ll 2>/dev/null; else multipath -ll 2>/dev/null; fi; "
                 "echo @@domains; c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$'); "
                 + DOMAIN_DISKS)
        rc, out = self.run(SSH + [f"{user}@{ip}", "sudo -n sh -c " + shlex.quote(inner)], show=False, timeout=120)
        if rc != 0 or "@@domains" not in str(out or ""):
            return None
        seen = parse_disk_paths(out)
        return {dm: x["wwid"] for dm, x in seen["maps"].items() if dm in seen["users"] and (x["paths"] == 0 or "##" in x["vendor"])}

    @prefetchable
    def dest_paths(self, ip, user):
        """On a compute, read-only and light: multipath maps without a working path, iSCSI path devices in no map that no
        process has open (DEST_PATHS, parse_dest_paths), or {"unknown": why}."""
        self.say(f"$ ssh {user}@{ip} sudo: dmsetup status --target multipath; iSCSI path devices in no map and not open (sysfs)")
        rc, out = self.run(SSH + [f"{user}@{ip}", "sudo -n sh -c " + shlex.quote(DEST_PATHS)], show=False, timeout=120)
        seen = parse_dest_paths(out) if rc == 0 else None
        return seen if seen is not None else {"unknown": first_line(out) or f"exit {rc}"}

    @prefetchable
    def host_lvs(self, ip, user, why=""):
        """On a compute, read-only: its LVM filter, the LVM LVs and multipath maps of the host and the disks of its
        running domains (HOST_LVS, parse_host_lvs), or {"unknown": why}."""
        self.say(f"$ ssh {user}@{ip} sudo: lvmconfig devices/global_filter; the LVM LVs and multipath maps of the host; "
                 f"virsh domblklist of the running domains{' (' + why + ')' if why else ''}")
        rc, out = self.run(SSH + [f"{user}@{ip}", "sudo -n sh -c " + shlex.quote(HOST_LVS)], show=False, timeout=180)
        if rc != 0 or "@@domains" not in str(out or ""):
            return {"unknown": first_line(out) or f"exit {rc}"}
        return parse_host_lvs(out)

    def release_lv(self, ip, user, uuid):
        """Release one guest LV on a compute (RELEASE_LV, read again and checked there first): {"state": gone | refused |
        failed | removed, "why", "lv": "<dm> <name>", "added": [(path, map, paths)], "left": [(path, wwid)]}."""
        if not LV_UUID_RE.match(str(uuid)):
            return {"state": "refused", "why": "not the UUID of an LVM LV"}
        self.say(f"$ ssh {user}@{ip} sudo: the LV {uuid} read again (opened 0 times, held by nothing, no disk of a running "
                 "domain, only on iSCSI devices), then dmsetup remove; each freed path back to the map of its WWID")
        rc, out = self.run(SSH + [f"{user}@{ip}", "sudo -n sh -c " + shlex.quote(f"U={uuid}\n" + RELEASE_LV)], show=False, timeout=180)
        text = str(out or "")
        lv = re.search(r"^@@lv (\S+) (\S+)", text, re.M)
        res = {"lv": f"{lv.group(1)} {lv.group(2)}" if lv else uuid, "added": [], "left": [], "why": ""}
        if re.search(r"^@@gone$", text, re.M):
            return dict(res, state="gone")
        for kind in ("refused", "failed"):
            m = re.search(rf"^@@{kind} (.*)$", text, re.M)
            if m:
                return dict(res, state=kind, why=m.group(1).strip())
        if rc != 0 or not re.search(r"^@@removed ", text, re.M):
            return dict(res, state="failed", why=first_line(out) or f"exit {rc}")
        res["added"] = [(p, t, int(n)) for p, t, n in re.findall(r"^@@added (\S+) (\S+) (\d+)$", text, re.M)]
        res["left"] = re.findall(r"^@@left (\S+) (\S+)$", text, re.M)
        return dict(res, state="removed")

    def session_hosts(self, ip, user, iqn):
        """The SCSI host numbers of the iSCSI sessions of a compute to one target ([int]), [] when none or unknown."""
        if not IQN_RE.match(str(iqn or "")):
            return []
        inner = (f"for s in /sys/class/iscsi_session/session*; do [ \"$(cat $s/targetname 2>/dev/null)\" = {shlex.quote(iqn)} ] || continue; "
                 "h=$(ls -d $s/device/target* 2>/dev/null | head -1 | sed -E 's/.*target([0-9]+):.*/\\1/'); "
                 "[ -n \"$h\" ] && echo \"@@host $h\"; done")
        self.say(f"$ ssh {user}@{ip} sudo: the iSCSI sessions of target {iqn}")
        rc, out = self.run(SSH + [f"{user}@{ip}", "sudo -n sh -c " + shlex.quote(inner)], show=False, timeout=60)
        return sorted({int(h) for h in re.findall(r"^@@host (\d+)$", str(out or ""), re.M)}) if rc == 0 else []

    def flush_map(self, ip, user, wwid):
        """Flush one leftover multipath map on a compute (FLUSH_MAP, read again and checked there first): {"state": gone |
        refused | failed | flushed, "why", "map"}."""
        if not WWID_RE.match(str(wwid)):
            return {"state": "refused", "why": "not a multipath WWID", "map": wwid}
        self.say(f"$ ssh {user}@{ip} sudo: the map {wwid} read again (no running path, opened 0 times, held by nothing, no "
                 "disk of a running domain), then multipath -f")
        rc, out = self.run(SSH + [f"{user}@{ip}", "sudo -n sh -c " + shlex.quote(f"W={wwid}\n" + FLUSH_MAP)], show=False, timeout=120)
        text = str(out or "")
        mp = re.search(r"^@@map (\S+)", text, re.M)
        res = {"map": mp.group(1) if mp else wwid, "why": ""}
        if re.search(r"^@@gone$", text, re.M):
            return dict(res, state="gone")
        for kind in ("refused", "failed"):
            m = re.search(rf"^@@{kind} ?(.*)$", text, re.M)
            if m:
                return dict(res, state=kind, why=m.group(1).strip())
        done = re.search(r"^@@flushed \S+ ?(.*)$", text, re.M)
        if rc != 0 or not done:
            return dict(res, state="failed", why=first_line(out) or f"exit {rc}")
        return dict(res, state="flushed", how=done.group(1).strip())

    def delete_path(self, ip, user, dev, addr, wwid):
        """Delete one iSCSI path device a compute keeps in no map (DELETE_PATH, read again and checked there first):
        {"state": gone | refused | failed | deleted, "why", "read"}."""
        if not SD_RE.match(str(dev)) or not SCSI_ADDR_RE.match(str(addr)) or not (wwid == "-" or WWID_RE.match(str(wwid))):
            return {"state": "refused", "why": "not a path device, a SCSI address or a WWID", "read": ""}
        self.say(f"$ ssh {user}@{ip} sudo: {dev} ({addr}) read again (still that address and WWID, in no map, open by no "
                 "process, no disk of a domain; again 20 s later; it does not answer a read), then echo 1 > device/delete")
        rc, out = self.run(SSH + [f"{user}@{ip}", "sudo -n sh -c " + shlex.quote(f"D={dev}; A={addr}; W={wwid}\n" + DELETE_PATH)],
                           show=False, timeout=180)
        text = str(out or "")
        rd = re.search(r"^@@read (.*)$", text, re.M)
        res = {"why": "", "read": rd.group(1).strip() if rd else ""}
        m = re.search(r"^@@gone ?(.*)$", text, re.M)
        if m:
            return dict(res, state="gone", why=m.group(1).strip())
        for kind in ("refused", "failed"):
            m = re.search(rf"^@@{kind} ?(.*)$", text, re.M)
            if m:
                return dict(res, state=kind, why=m.group(1).strip())
        if rc != 0 or not re.search(r"^@@deleted ", text, re.M):
            return dict(res, state="failed", why=first_line(out) or f"exit {rc}")
        return dict(res, state="deleted")

    def end_incoming(self, ip, user, instance):
        """On the destination of a live migration: end its incoming copy when it hangs on a disk without a working path
        (END_INCOMING, checked there first). {"state": not-stuck | refused | ended | still | failed, "why", "maps": [names
        given fail_if_no_path], "disks": [(dm, name, working paths, path devices)]}."""
        if not INSTANCE_RE.match(str(instance)):
            return {"state": "refused", "why": "not a libvirt domain name", "maps": [], "disks": []}
        first = (ip, instance) not in self._incoming_seen
        self._incoming_seen.add((ip, instance))
        if first:   # every 2 minutes after the first: said once (a real case, read as if a copy had been killed)
            self.say(f"$ ssh {user}@{ip} sudo: is the incoming copy of {instance} stuck? (virsh domstate --reason; only a copy "
                     "still starting up with a disk on a map without a working path, used by nothing else, would be ended "
                     "there: SIGKILL of its QEMU, then fail_if_no_path on that map) — read again every 2 minutes")
        rc, out = self.run(SSH + [f"{user}@{ip}", "sudo -n sh -c " + shlex.quote(f"I={instance}\n" + END_INCOMING)],
                           show=False, timeout=300)
        text = str(out or "")
        res = {"why": "", "maps": re.findall(r"^@@noqueue (\S+)$", text, re.M),
               "disks": re.findall(r"^@@disk (\S+) (\S+) (\d+) (\S+)$", text, re.M)}
        for kind in ("not-stuck", "refused"):
            m = re.search(rf"^@@{kind} ?(.*)$", text, re.M)
            if m:
                return dict(res, state=kind, why=m.group(1).strip())
        if re.search(r"^@@killed ", text, re.M):
            return dict(res, state="ended" if re.search(r"^@@ended ", text, re.M) else "still")
        m = re.search(r"^@@failed ?(.*)$", text, re.M)
        return dict(res, state="failed", why=(m.group(1).strip() if m else "") or first_line(out) or f"exit {rc}")

    @prefetchable
    def domain_check(self, ip, user, instance, disks=()):
        """On the node, read-only: virsh domstate (with its reason), domblkerror, and the block jobs of these disks.
        {"state", "errors": [...], "jobs": {disk: text}} or {"unknown": why}."""
        virsh = "podman exec \"$c\" virsh -c qemu:///system"
        inner = ("c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$'); "
                 "[ -n \"$c\" ] || { echo 'no libvirt container'; exit 7; }; "
                 f"echo @@state; {virsh} domstate {instance} --reason; echo @@errors; {virsh} domblkerror {instance}; "
                 + "".join(f"echo @@job {dsk}; {virsh} blockjob {instance} {dsk} --info; " for dsk in disks))
        self.say(f"$ ssh {user}@{ip} sudo podman exec <nova_virtqemud|nova_libvirt> virsh domstate / domblkerror"
                 f"{' / blockjob ' + ' '.join(disks) if disks else ''} {instance}")
        rc, out = self.run(SSH + [f"{user}@{ip}", "sudo -n sh -c " + shlex.quote(inner)], show=False, timeout=120)
        parts, key = {}, None
        for line in str(out or "").splitlines():
            line = line.strip()
            if line.startswith("@@"):
                key = line[2:]
                parts[key] = []
            elif key and line:
                parts[key].append(line)
        if "state" not in parts:
            return {"unknown": first_line(out) or f"exit {rc}"}
        state = (parts["state"][-1] if parts["state"] else "unknown").lower()
        errors = [x for x in parts.get("errors", []) if not re.search(r"no errors found", x, re.I)]
        jobs = {k[4:]: " ".join(v) for k, v in parts.items() if k.startswith("job ") and v
                and not re.search(r"no current block job", " ".join(v), re.I)}
        self.say(f"  domain {state}; disk errors: {'; '.join(errors) or 'none'}"
                 + (f"; block jobs: {'; '.join(f'{k} {v}' for k, v in jobs.items()) or 'none'}" if disks else ""))
        return {"state": state, "errors": errors, "jobs": jobs}

    @prefetchable
    def screenshot(self, ip, user, instance):
        """PNG of what the console of an instance shows now (virsh screenshot on its compute, as the VNC console in
        Horizon shows it; nothing changes in the guest), None when it cannot be taken."""
        f = f"/tmp/wi-shot-{instance}"
        inner = ("c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$'); [ -n \"$c\" ] || exit 7; "
                 f"podman exec \"$c\" virsh -c qemu:///system screenshot {instance} {f} >/dev/null 2>&1 && "
                 f"podman exec \"$c\" cat {f} | base64 -w0; podman exec \"$c\" rm -f {f}")
        self.say(f"$ ssh {user}@{ip} sudo podman exec <nova_virtqemud|nova_libvirt> virsh screenshot {instance} (the console now)")
        rc, out = self.run(SSH + [f"{user}@{ip}", "sudo -n sh -c " + shlex.quote(inner)], show=False, timeout=180)
        try:
            data = base64.b64decode(str(out or "").strip(), validate=True)
        except ValueError:
            return None
        return to_png(data)

    def send_enter(self, ip, user, instance):
        """ONE Enter key on the console of an instance (virsh send-key KEY_ENTER on its compute, as a key pressed in the
        VNC console of Horizon; nothing else is typed): (done, output)."""
        inner = ("c=$(podman ps --format '{{.Names}}' | grep -m1 -E '^(nova_virtqemud|nova_libvirt)$'); "
                 "[ -n \"$c\" ] || { echo 'no libvirt container'; exit 7; }; "
                 f"podman exec \"$c\" virsh -c qemu:///system send-key {instance} KEY_ENTER")
        self.say(f"$ ssh {user}@{ip} sudo podman exec <nova_virtqemud|nova_libvirt> virsh send-key {instance} KEY_ENTER (one Enter key)")
        rc, out = self.run(SSH + [f"{user}@{ip}", "sudo -n sh -c " + shlex.quote(inner)], show=False, timeout=60)
        return rc == 0, out

    def console_url(self, sid):
        """The console Horizon opens for an instance (openstack console url show: Nova makes a token, nothing else):
        {"url"} when Nova gives one, {"unavailable": why} when that console type is not set up here, {"error": why}."""
        value, rc, out = self.read(["openstack", "console", "url", "show", sid], show=False)
        if rc == 0 and isinstance(value, dict) and value.get("url"):
            return {"url": str(value["url"])}
        why = last_error(out) or first_line(out) or f"exit {rc}"
        return {"unavailable": why} if re.search(r"unavailable console type|not supported|console type .* disabled", why, re.I) \
            else {"error": why}

    @prefetchable
    def console_log(self, sid, lines=400):
        """The last lines of the serial console of an instance (what the guest printed), None when it cannot be read."""
        rc, out = self.run(["openstack", "console", "log", "show", sid, "--lines", str(lines)], show=False)
        return None if rc != 0 else str(out or "").splitlines()

    @prefetchable
    def ports_of(self, sid):
        """[{id, status, host, admin}] of the ports of an instance (binding host and admin state from port show), None when
        not readable. admin: False when the port is administratively down (its status is DOWN on purpose)."""
        ports, rc, _ = self.read(["openstack", "port", "list", "--server", sid, "-c", "ID"])
        if rc != 0 or not isinstance(ports, list):
            return None
        out = []
        for p in ports[:8]:
            pid = str(field(p, "ID", "id"))
            value, rc, _ = self.read(["openstack", "port", "show", pid, "-c", "status", "-c", "binding_host_id", "-c", "admin_state_up"])
            if rc == 0 and isinstance(value, dict):
                admin = str(value.get("admin_state_up", True)).strip().lower() not in ("false", "down", "0")   # client 4.x: bool, 5.x: UP / DOWN
                out.append({"id": pid, "status": str(value.get("status") or "").upper(), "host": str(value.get("binding_host_id") or ""),
                            "admin": admin})
        return out

    @prefetchable
    def port_states(self, sid):
        """{port id: status} of the ports of an instance (one port list), None when not readable."""
        ports, rc, _ = self.read(["openstack", "port", "list", "--server", sid, "-c", "ID", "-c", "Status"])
        if rc != 0 or not isinstance(ports, list):
            return None
        return {str(field(p, "ID", "id")): str(field(p, "Status", "status")).upper() for p in ports if isinstance(p, dict)}

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

    def nova_errors(self, ip, user, sid, seconds):
        """ERROR lines nova-compute logged on a node for an instance in the last seconds (its current log, read-only).
        By time: the lines of a failed live migration carry no request ID ([-]), they come from its own thread."""
        inner = (f"c=$(date -d '-{int(seconds)} seconds' '+%Y-%m-%d %H:%M:%S'); "
                 f"grep -hE ' (ERROR|CRITICAL) .*{sid}' {NOVA_COMPUTE_LOG} | awk -v c=\"$c\" '($1 \" \" $2) >= c' | tail -n 150")
        self.say(f"$ ssh {user}@{ip} sudo grep ' ERROR .*{sid}' {NOVA_COMPUTE_LOG} (its lines of the last {minutes(seconds)})")
        rc, out = self.run(SSH + [f"{user}@{ip}", "sudo -n sh -c " + shlex.quote(inner)], show=False, timeout=120)
        return [line for line in str(out or "").splitlines() if line.strip()] if rc == 0 else []

    def reset_active(self, sid):
        return self.run(["openstack", "server", "set", "--state", "active", sid])

    # ---- block storage and images
    def volume(self, vid, show=False):
        value, rc, out = self.read(["openstack", "volume", "show", vid], show=show)
        if rc != 0 or not isinstance(value, dict):
            if gone(out, "volume"):
                return None
            return {"unknown": first_line(out) or f"exit {rc}"}
        # openstack volume show falls back to a NAME when no volume has that ID: the target of a Cinder volume migration
        # that never completed is named after the volume it replaces (vm-c3, 2026-11-02: volume 7a3c9e01 of Nova
        # gone, 8b4d0f12 named "7a3c9e01-..." with migration_status target:7a3c9e01)
        got = str(value.get("id") or "")
        if UUID_RE.match(str(vid)) and got and got != vid:
            why = (f"no volume with ID {vid} in Cinder; a volume NAMED so exists: {got} ({str(value.get('status') or '?').lower()}, "
                   f"migration {field(value, 'migration_status', 'os-vol-mig-status-attr:migstat') or 'none'})")
            return {"unknown": why, "missing": why}
        return {"name": str(value.get("name") or vid), "status": str(value.get("status") or "").lower(), "size": value.get("size") or "?",
                "migstat": str(field(value, "migration_status", "os-vol-mig-status-attr:migstat")).lower(),
                "host": str(field(value, "os-vol-host-attr:host", "host")),
                "attachments": value.get("attachments") or [],
                "multiattach": str(value.get("multiattach")).lower() == "true",
                "bootable": str(value.get("bootable")).lower() == "true",
                "group": str(field(value, "group_id", "consistencygroup_id")),
                "type": str(field(value, "volume_type", "type")),
                "replication": str(field(value, "replication_status")).lower()}

    @prefetchable
    def vendor(self, ip, user):
        """The CPU vendor of a compute (vendor_id of /proc/cpuinfo: GenuineIntel / AuthenticAMD), "" when unknown."""
        rc, out = self.runner(SSH + [f"{user}@{ip}", VENDOR_COMMAND], 60) if ip else (1, "")
        m = VENDOR_RE.search(str(out or "")) if rc == 0 else None
        return m.group(1) if m else ""

    @prefetchable
    def attachments(self, vid):
        """Every Cinder attachment record of a volume, whatever its status (attached, reserved, attaching...): [{"id",
        "status", "server"}], None when they could not be read (cinder attachment-list, volume API 3.27)."""
        rc, out = self.run(["cinder", "--os-volume-api-version", "3.27", "attachment-list", "--all-tenants", "--volume-id", vid],
                           show=False)
        if rc != 0:
            return None
        return [{"id": str(r.get("id") or ""), "status": str(r.get("status") or "").lower(), "server": str(r.get("server_id") or "")}
                for r in table(out)[0] if r.get("id")]

    def snapshots_of(self, vid):
        value, rc, _ = self.read(["openstack", "volume", "snapshot", "list", "--all-projects", "--volume", vid], show=True)
        if rc != 0:
            raise Done(ATTENTION, "the snapshots of the volume could not be listed: nothing was changed")
        return [{"id": str(s.get("ID") or s.get("id")), "status": str(s.get("Status") or s.get("status") or "").lower(),
                 "name": str(s.get("Name") or s.get("name") or "")}
                for s in value or [] if isinstance(s, dict) and str(s.get("Volume") or s.get("volume_id") or vid) == vid]

    def snapshot(self, sid):
        """{"status", "name", "group", "volume"} of a volume snapshot, None when it does not exist. group: its group
        snapshot (or the cgsnapshot of a consistency group), when the API shows it (newer volume API microversions only)."""
        value, rc, out = self.read(["openstack", "volume", "snapshot", "show", sid])
        if rc != 0 or not isinstance(value, dict):
            return None if gone(out, "snapshot") else {"status": "unknown", "name": "", "group": "", "volume": ""}
        return {"status": str(value.get("status") or "").lower(), "name": str(value.get("name") or ""),
                "group": str(value.get("group_snapshot_id") or value.get("cgsnapshot_id") or ""),
                "volume": str(value.get("volume_id") or "")}

    def wait(self, check, timeout, every=15):
        """Poll check() (True: done) every `every` seconds up to timeout (and not past the end of the item); True when done."""
        left = self.time_left()
        end = self.clock() + (min(timeout, left) if left is not None else timeout)
        while True:
            if check():
                return True
            if self.clock() >= end:
                return False
            self.sleep(every)


# ---------------------------------------------------------------- live migration
# also: Committed_AS, the free memory of each NUMA node, the direct reclaim / compaction stalls before and after the 2
# seconds (@a / @b), and every QEMU with its age in seconds, guest name and RAM (@q: the large guests that started lately)
STALLS = "grep -E '^(allocstall_[a-z0-9]+|compact_stall) ' /proc/vmstat"
PRESSURE_COMMAND = f"{STALLS}; grep -E '^(MemTotal|MemAvailable):' /proc/meminfo"
USAGE_COMMAND = ("head -n 1 /proc/stat; grep -E '^(MemTotal|MemAvailable|Committed_AS):' /proc/meminfo; "
                 "grep -hE '^Node [0-9]+ (MemTotal|MemFree):' /sys/devices/system/node/node*/meminfo 2>/dev/null; "
                 f"{STALLS} | sed 's/^/@a /'; sleep 2; head -n 1 /proc/stat; {STALLS} | sed 's/^/@b /'; "
                 "ps -ww -eo etimes=,args= | awk '/qemu-kvm/ && !/awk/ {g = \"\"; m = \"\"; for (i = 2; i < NF; i++) "
                 "{if ($i == \"-name\") g = $(i + 1); if ($i == \"-m\") m = $(i + 1)} if (g != \"\") print \"@q\", $1, g, m}'; "
                 "grep -m1 '^vendor_id' /proc/cpuinfo")
VENDOR_COMMAND = "grep -m1 '^vendor_id' /proc/cpuinfo"
VENDOR_RE = re.compile(r"^vendor_id\s*:\s*(\S+)", re.M)


def parse_usage(text):
    """The output of USAGE_COMMAND -> {"cpu": % busy over the 2 seconds, "used_kb", "total_kb"}, or None."""
    cpu = [list(map(int, l.split()[1:])) for l in str(text or "").splitlines() if re.match(r"^cpu\s+\d", l)]
    mem = dict(re.findall(r"^(MemTotal|MemAvailable):\s+(\d+)", str(text or ""), re.M))
    if len(cpu) < 2 or "MemTotal" not in mem or "MemAvailable" not in mem or int(mem["MemTotal"]) <= 0:
        return None
    # the first 8 fields only: guest and guest_nice (the vCPUs of the instances) are already counted in user and nice, so
    # summing them too counts the instances twice and makes a compute look busier than it is
    a, b = cpu[0][:8], cpu[-1][:8]
    idle = lambda v: v[3] + (v[4] if len(v) > 4 else 0)   # noqa: E731  idle + iowait
    total = sum(b) - sum(a)
    busy = total - (idle(b) - idle(a))
    total_kb, avail_kb = int(mem["MemTotal"]), int(mem["MemAvailable"])
    out = {"cpu": round(100.0 * busy / total, 1) if total > 0 else 0.0, "used_kb": total_kb - avail_kb, "total_kb": total_kb}
    vendor = VENDOR_RE.search(str(text or ""))
    if vendor:
        out["vendor"] = vendor.group(1)   # GenuineIntel / AuthenticAMD
    text = str(text or "")
    commit = re.search(r"^Committed_AS:\s+(\d+)", text, re.M)
    if commit:
        out["commit_kb"] = int(commit.group(1))
    nodes = {}
    for n, key, kb in re.findall(r"^Node (\d+) (MemTotal|MemFree):\s+(\d+)", text, re.M):
        nodes.setdefault(int(n), {})[key] = int(kb)
    nodes = {n: (v["MemTotal"], v["MemFree"]) for n, v in sorted(nodes.items())
             if v.get("MemTotal", 0) > 0 and "MemFree" in v}
    if nodes:
        out["nodes"] = nodes   # {node: (total_kb, free_kb)}
    before, after = (dict(re.findall(rf"^@{t} (\S+) (\d+)", text, re.M)) for t in ("a", "b"))
    if before and after:
        delta = lambda key: sum(int(after.get(k, 0)) - int(v) for k, v in before.items() if k.startswith(key))   # noqa: E731
        out["reclaim"], out["compaction"] = max(0, delta("allocstall")), max(0, delta("compact_stall"))
    guests = [(int(age), name.split(",")[0].split("=")[-1], qemu_ram_kb(ram))
              for age, name, ram in re.findall(r"^@q (\d+) (\S+) ?(\S*)", text, re.M)]
    if guests:
        out["guests"] = guests   # [(seconds since its QEMU started, guest name, RAM in KiB or 0)]
    return out


def parse_pressure(text):
    """The output of PRESSURE_COMMAND -> {"reclaim": direct reclaim stalls so far, "compaction": compaction stalls so far,
    "avail_kb", "total_kb"}, or {} when the counters are missing."""
    counters = dict(re.findall(r"^(allocstall_\S+|compact_stall) (\d+)", str(text or ""), re.M))
    mem = dict(re.findall(r"^(MemTotal|MemAvailable):\s+(\d+)", str(text or ""), re.M))
    if not counters:
        return {}
    return {"reclaim": sum(int(v) for k, v in counters.items() if k.startswith("allocstall")),
            "compaction": int(counters.get("compact_stall", 0)),
            "avail_kb": int(mem.get("MemAvailable", 0)), "total_kb": int(mem.get("MemTotal", 0))}


def qemu_ram_kb(value):
    """The RAM of a guest from QEMU's -m (size=536870912k / 524288 / 512G[,slots=..]) in KiB; 0 when unknown. Without a
    suffix QEMU means MiB."""
    m = re.match(r"(?:size=)?(\d+)([kKmMgGtT]?)", str(value or ""))
    if not m:
        return 0
    return int(m.group(1)) * {"k": 1, "m": 1024, "g": 1024 ** 2, "t": 1024 ** 3}.get(m.group(2).lower(), 1024)


def large_refusal(u, ram_kb, now_large=True):
    """Why a compute with this use (parse_usage) takes no large instance of ram_kb, or "" when it can: a large guest started
    there less than LARGE_SETTLE ago, a NUMA node under NODE_FREE_MIN % free, or Committed_AS with the instance over
    COMMIT_LIMIT % of MemTotal. Only for a large instance (now_large)."""
    if not now_large:
        return ""
    recent = sorted((age, name, kb) for age, name, kb in u.get("guests") or [] if kb >= LARGE_RAM_MB * 1024 and age < LARGE_SETTLE)
    if recent:
        age, name, kb = recent[0]
        return (f"large guest {name} ({kb // 1024 ** 2} GiB) started there {minutes(age)} ago (moved in or booted): no "
                f"other large one within {LARGE_SETTLE // 60} min")
    full = [(n, free, total) for n, (total, free) in (u.get("nodes") or {}).items() if 100.0 * free / total < NODE_FREE_MIN]
    if full:
        n, free, total = min(full, key=lambda x: x[1] / x[2])
        return (f"NUMA node {n} has {free / 1024 ** 2:.0f} GiB free of {total / 1024 ** 2:.0f} GiB (under {NODE_FREE_MIN}%): "
                "its kernel reclaims and compacts memory there, the guests stall")
    if "commit_kb" in u and u["total_kb"] > 0:
        pct = round(100.0 * (u["commit_kb"] + ram_kb) / u["total_kb"], 1)
        if pct > COMMIT_LIMIT:
            return f"committed memory {pct:g}% of its RAM with it (over {COMMIT_LIMIT}%: the guests there can grow to their full RAM)"
    return ""


def large_guests(u):
    """How many large guests (LARGE_RAM_MB or more) run on a compute, from parse_usage."""
    return sum(1 for _age, _name, kb in u.get("guests") or [] if kb >= LARGE_RAM_MB * 1024)


def source_vendor(d, a, src):
    """The CPU vendor of the source compute (vendor_id of /proc/cpuinfo), read once per item; "" when unknown."""
    if "source_vendor" not in a:
        a["source_vendor"] = d.vendor((a.get("nodes") or {}).get(short(src)), a.get("user") or "heat-admin")
    return a["source_vendor"]


# A hard server group decides where Nova's scheduler lets an instance go (ServerGroupAffinityFilter /
# ServerGroupAntiAffinityFilter): affinity only to a compute where another member runs, anti-affinity never there. A real case: test-vm-21, the only member of an affinity group, was refused on iha-6, iha-11 and iha-0
# ("No valid host was found", ServerGroupAffinityFilter returned 0 hosts) and the drain of iha-7 stopped there.
GROUP_READS = 20   # members whose compute is read
POLICY_RE = re.compile(r"\b(soft-anti-affinity|anti-affinity|soft-affinity|affinity)\b")


def group_rule(d, a, sid, name, src):
    """The server group of the instance (a["group"], found by the check) read now, members move: {"name", "policy",
    "only": the computes affinity allows (None: no such limit), "avoid": {compute: why} anti-affinity refuses}. Done
    SKIPPED when affinity allows no compute but the source (nothing is started: the scheduler would refuse every one)."""
    gid = a.get("group")
    if not gid:
        return {"name": "", "policy": "", "only": None, "avoid": {}}
    g, rc, out = d.read(["openstack", "server", "group", "show", gid], show=True)
    if rc != 0 or not isinstance(g, dict):
        d.say(f"Server group {gid}: " + ("it no longer exists, no group rule" if gone(out, "server group") else
                                         f"not read ({first_line(out) or f'exit {rc}'}), the scheduler decides"))
        return {"name": "", "policy": "", "only": None, "avoid": {}}
    m = POLICY_RE.search(str(g.get("policy") or g.get("policies") or ""))
    policy, gname = (m.group(1) if m else ""), str(g.get("name") or gid)
    members = [x for x in dict.fromkeys(UUID_ANY.findall(str(g.get("members") or ""))) if x != sid]
    where, unknown = {}, max(0, len(members) - GROUP_READS)
    for x in members[:GROUP_READS]:
        s = d.server(x)
        if s is None:
            continue
        if s.get("unknown") or not s.get("host"):
            unknown += 1
            continue
        where.setdefault(short(s["host"]), []).append(s["name"])
    shown = "; ".join(f"{h}: {', '.join(n[:3])}{' ...' if len(n) > 3 else ''}" for h, n in sorted(where.items()))
    d.say(f"Server group {gname} ({policy or 'policy not read'}): {len(members)} other member(s)"
          + (f" on {shown}" if shown else "") + (f", {unknown} not read" if unknown else ""))
    rule = {"name": gname, "policy": policy, "only": None, "avoid": {}}
    if policy == "affinity":
        rule["only"] = set(where) - {src}
        if not rule["only"]:
            if unknown:   # a member not read may run elsewhere: the scheduler decides
                rule["only"] = None
                return rule
            raise Done(SKIPPED, f"not moved: {name} is in server group {gname} with the policy affinity, and "
                       + (f"its other member(s) run on {a['from']} too" if members else "it is the only member")
                       + f": Nova (ServerGroupAffinityFilter) accepts no compute but {a['from']} for it, so every "
                       f"destination answers No valid host. Nothing was started: {name} keeps running on {a['from']}. To "
                       "move it, its owner decides: delete the server group (openstack server group delete "
                       f"{gid}; its instances keep running, only the affinity rule goes), then migrate it again")
    elif policy == "anti-affinity":
        rule["avoid"] = {h: f"its anti-affinity server group {gname} has {', '.join(n[:3])} there" for h, n in where.items()}
    return rule


def group_bar(rule, target):
    """Why the group of the instance keeps it off this destination ("" when it does not)."""
    if not target:
        return ""
    if rule["only"] is not None and short(target) not in rule["only"]:
        return (f"its affinity server group {rule['name']} runs on {', '.join(sorted(rule['only']))}: Nova accepts only "
                "a compute where another member runs")
    return rule["avoid"].get(short(target), "")


def group_reachable(rule, targets, name, a):
    """Done SKIPPED when affinity allows only computes that are not among the destinations (over the limit, down...)."""
    if rule["only"] is not None and not any(t is None or short(t) in rule["only"] for t in targets):
        raise Done(SKIPPED, f"not moved: {name} is in server group {rule['name']} with the policy affinity, so Nova accepts "
                            f"only {', '.join(sorted(rule['only']))} (where its other members run), and "
                            + ("that compute is not" if len(rule["only"]) == 1 else "none of them is")
                            + f" a destination now (over the usage limit, not enabled and up, or not named). {name} keeps "
                            f"running on {a['from']}")


def same_vendor(d, a, src, host, vendor=None):
    """Live migration: '' when the destination has the CPU vendor of the source (or either is unknown), else why it is
    skipped: QEMU cannot move a running guest between an Intel and an AMD CPU (a real case: the scheduler refused the
    AMD computes for an instance of an Intel compute, and the three attempts were spent on them)."""
    sv = source_vendor(d, a, src)
    if vendor is None:
        vendor = d.vendor((a.get("nodes") or {}).get(short(host)), a.get("user") or "heat-admin")
    if not sv or not vendor or vendor == sv:
        return ""
    return f"its CPU is {vendor}, the source's is {sv}: a running instance cannot move between them"


def candidates(a, src, services, every=False):
    """{short host: ip} of the possible destinations whose usage is read: the named ones, or every enabled and up compute
    of the node list but the source (every: also those without an address)."""
    if a["to"] != "auto":
        pool = {short(h): a["nodes"].get(short(h)) for h in to_hosts(a) if short(h) != src}
    else:
        pool = {h: ip for h, ip in a["nodes"].items() if h != src and services.get(h) == ("enabled", "up")}
    return pool if every else {h: ip for h, ip in pool.items() if ip}


def destinations(d, a, name, src, services):
    """The computes under the usage limit for this instance, the least used first; for a large instance (LARGE_RAM_MB or
    more) without the computes where a large guest started lately, a NUMA node is (nearly) full or the committed memory
    would pass COMMIT_LIMIT, those with fewer large guests first. Any instance skips a compute in direct reclaim now.
    Done SKIPPED when none is left."""
    limit, ram_kb = a["under"], a["ram"] * 1024
    large = a["ram"] >= LARGE_RAM_MB
    unmeasured = [h for h, ip in candidates(a, src, services, every=True).items() if not ip]
    pool = candidates(a, src, services)
    d.say(f"Usage of {len(pool)} compute(s) now (real use, read on each compute; RAM with the {a['ram'] // 1024} GiB of {name}), "
          f"limit {limit}% for CPU and RAM"
          + (f"; {name} is large: not to a compute where a large guest started in the last {LARGE_SETTLE // 60} min, with a "
             f"NUMA node under {NODE_FREE_MIN}% free, or with committed memory over {COMMIT_LIMIT}% with it; fewer large "
             "guests first" if large else "") + ":")
    found = d.usage(pool, a["user"] or "heat-admin") if pool else {}
    ok, why = [], []
    for h in sorted(found):
        u = found[h]
        if "error" in u:
            d.say(f"  {h}: not measured ({u['error']})")
            why.append(f"{h} not measured")
            continue
        ram = round(100.0 * (u["used_kb"] + ram_kb) / u["total_kb"], 1)
        a.setdefault("vendors", {})[h] = u.get("vendor") or None   # read with the use: not read again for the attempt
        other = same_vendor(d, a, src, h, u["vendor"]) if a.get("verb") == "live-migrate" and u.get("vendor") else ""
        refusal = other or (f"in direct reclaim now ({u['reclaim']} stall(s) in 2 s): the guests there already wait for "
                            "memory" if u.get("reclaim") else "") or large_refusal(u, ram_kb, large)
        fits = u["cpu"] < limit and ram < limit and not refusal
        bigs = f", {large_guests(u)} large guest(s)" if large and ("guests" in u or "commit_kb" in u) else ""   # read
        d.say(f"  {h}: CPU {u['cpu']:g}%, RAM {ram:g}%{bigs} -> "
              + (f"skipped, {refusal}" if refusal else 'can take it' if fits else 'over the limit'))
        if fits:
            ok.append(((large_guests(u) if large else 0, max(u["cpu"], ram)), h))
        else:
            why.append(f"{h} {refusal}" if refusal else f"{h} CPU {u['cpu']:g}% RAM {ram:g}%")
    for h in unmeasured:
        why.append(f"{h} has no ctlplane address")
    if not ok:
        cpu = " with the CPU of the source" if any("cannot move between them" in w for w in why) else ""
        ready = (" free for a large instance now" if any(x in w for w in why for x in ("large guest", "NUMA node",
                                                                                   "committed memory")) else "")
        raise Done(SKIPPED, f"not moved: no compute{cpu}{ready} stays under {limit}% CPU and RAM with {name} "
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
    read_ahead_before(d, a, s)
    services = d.computes()
    if a.get("under") and candidates(a, src, services):   # the usage of the possible destinations, with the checks below
        d.prefetch(("usage", candidates(a, src, services), a["user"] or "heat-admin"))
    blockers = migration_blockers(d, a, s, live=True)
    if blockers:
        raise Done(FAILED, f"not started: {'; '.join(blockers)}. Nothing was changed: {name} keeps running on {a['from']}")
    group = group_rule(d, a, sid, name, src)
    release_source_lvs(d, a, s)
    state = before_change(d, sid, a["nodes"], a["user"], ports=True)
    before = state["log"]   # only lines printed after the move are judged
    if a.get("under"):
        targets = destinations(d, a, name, src, services)
    else:
        named = to_hosts(a)
        targets = (named or [None]) + [h for h in a["try"] if short(h) not in {short(x) for x in named} | {src}]
    group_reachable(group, targets, name, a)
    last, tried = "", 0
    for target in targets:
        if tried >= MAX_ATTEMPTS:
            break
        if group_bar(group, target):
            skip(d, target, group_bar(group, target))
            continue
        if target and services.get(short(target)) != ("enabled", "up"):
            skip(d, target, f"nova-compute is {'/'.join(services.get(short(target)) or ('not listed',))}")
            continue
        if target and a.get("nodes"):
            read_ahead_target(d, a, sid, target)
        other = same_vendor(d, a, src, target, (a.get("vendors") or {}).get(short(target))) if target and a.get("nodes") else ""
        if other:
            skip(d, target, other)
            continue
        if target and not prepare_destination(d, a, sid, target):
            continue
        if not target and a.get("lvm_disks"):
            skip(d, "a compute chosen by the scheduler", f"LVM on the whole disk of {', '.join(a['lvm_disks'])} needs a "
                 "destination whose LVM leaves guest volumes alone; name one")
            continue
        tried += 1
        wait_site_free(d, a, sid, name)
        d.say(f"Attempt {tried}: live migration of {name} to {target or 'a compute chosen by the scheduler'}")
        if a.get("nodes"):   # the baselines: read ahead with the checks (again here only after a wait), both at once
            d.prefetch(*[("dead_disks",) + d.node(h, a.get("nodes"), a.get("user") or "") for h in (a["from"], target)
                         if h and d.node(h, a.get("nodes"), a.get("user") or "")[0]])
        base = {h: base_line(d, a, h) for h in (a["from"], target) if h}
        a.pop("abort_reason", None)
        a.pop("dest_pressure", None)
        a.pop("diverged", None)
        a.pop("cancelled", None)
        a.pop("ping_lost", None)
        a.pop("pause_ms", None)
        a.pop("last_job", None)
        if d.cancel_asked():   # cancelled on the portal while this item waited or tried another destination
            raise Done(FAILED, f"the run was cancelled on the portal before attempt {tried} started: nothing changed, {name} "
                               f"keeps running on {a['from']}")
        started = d.clock()
        d.mark("migration")
        rc, out = d.live_start(sid, target)
        if rc != 0:
            last = last_error(out) or f"exit {rc}"
            if not start_failed(d, a, sid, name, rc, out, last, started):   # Nova kept nothing of it
                if CONTROL.search(out or ""):
                    raise Done(ATTENTION, f"the live migration was not started: the OpenStack control plane failed ({last}). "
                                          f"Nothing changed: {name} keeps running on {a['from']}. {CONTROL_HINT}")
                if DESTINATION.search(out or ""):
                    d.say(f"Automatic fix: the destination refused it ({last}); {name} did not move, the next destination is tried")
                    continue
                raise Done(FAILED, f"the live migration was refused: {last}. Nothing changed: {name} is still on {a['from']}")
        outcome, info = watch_live(d, a, sid, src, started)
        d.mark("checks after")
        if outcome == "done":   # Nova disconnected the volumes on the source: did it touch another instance's disk there?
            read_ahead_after(d, a, s, info, started)
            hurt = check_victims(d, a, a["from"], started, base.get(a["from"]), "after the migration")
            lvs = check_dest_lvs(d, a, s, info)   # did the destination activate the guest's LVs on its disks?
            try:
                took, job = d.clock() - started, a.get("last_job") or {}
                why = (f": {gib(job['total'])} of RAM at about {mib_s(job['total'] / took)} on average"
                       if took >= LONG_MIGRATION and job.get("total") else "") \
                    + (f"; the pause at switch-over allowed was raised to {a['pause_ms']} ms" if a.get("pause_ms") else "")
                check_after(d, sid, f"{name} is on {info} (live migration took {minutes(took)}{why})", host=info,
                            nodes=a["nodes"], user=a["user"], before=before, ports=True, ports_before=state["ports"])
            except Done as e:
                but = ([f"the disconnect of the volumes on {short(a['from'])} {hurt}"] if hurt else []) \
                    + ([f"on {short(info)}: {lvs}"] if lvs else []) \
                    + ([f"the guest did not answer ping during the migration at {', '.join(a['ping_lost'])} (it may also "
                        "drop ping by its own firewall): look at it"] if a.get("ping_lost") else [])
                if but:
                    raise Done(ATTENTION if e.rc in (OK, ATTENTION) else e.rc, f"{e.message}. But {'; and '.join(but)}")
                raise
        if outcome == "gone":
            raise Done(OK, f"{name} was deleted during the migration: nothing left to do")
        if outcome == "back":   # the rollback ran on the destination: did it touch another instance's disk there?
            back_to = target or next((m["dest"] for m in d.migrations(sid)[:1] if m["dest"]), "")
            if back_to and a.get("nodes"):
                wait_rollback(d, sid, back_to)
            check_rollback(d, a, name, back_to, started, base.get(target))
            # the event says where it failed, often without the message (a traceback of frames only, the exception class);
            # the nova-compute log has the message: of the destination first when its pre_live_migration failed
            event, dests = d.diagnose(sid, LIVE_ACTIONS), [m["dest"] for m in d.migrations(sid)[:1]]
            pre = "pre_live_migration" in event
            logged = compute_reason(d, a, sid, dests + [a["from"]] if pre else [a["from"]] + dests, d.clock() - started,
                                    first=pre)
            why = "\n".join(x for x in (event, logged) if x) or info
            last = "; ".join(x for x in (last_error(event), logged) if x) or info
            try:
                if info.startswith("incoming: "):
                    last = info[len("incoming: "):]
                    d.say(f"Automatic fix: {name} is back on {a['from']} ({last}); the next destination is tried")
                    continue
                if info.startswith("aborted"):
                    if a.get("cancelled"):   # the operator cancelled the run: no other destination
                        raise Done(FAILED, f"{info}; {name} keeps running on {a['from']}, unchanged; it can be migrated later from "
                                           "a new check")
                    if a.get("dest_pressure"):   # the guard: the destination was reclaiming memory, try the next one
                        last = info
                        d.say(f"Automatic fix: {name} is back on {a['from']} ({info}); the next destination is tried")
                        continue
                    if a.get("diverged"):   # the guest's own pace: another destination copies it no faster
                        raise Done(FAILED, f"{info}; {name} keeps running on {a['from']}. Its guest changes its memory about as fast "
                                           "as it can be copied, so a live migration of it does not end: move it when the guest is "
                                           "quiet (ask its owner what runs in it), with stall force (the instance pauses until the "
                                           "copy ends, or runs on in post-copy where Nova permits it), or cold-migrate it in a window")
                    if a.get("abort_reason"):   # stuck: copying nothing, not slow
                        raise Done(FAILED, f"{info}; {name} keeps running on {a['from']}. Check the migration network and "
                                           f"libvirt / QEMU on {a['from']} and {short(target or '') or 'the destination'} before "
                                           "another attempt")
                    raise Done(FAILED, f"{info}; {name} keeps running on {a['from']}. Try again outside busy hours, or with "
                                       "stall force (pauses the instance until the copy ends)")
                if DESTINATION.search(why or "") and not PLATFORM.search(why or ""):
                    d.say(f"Automatic fix: the destination refused it ({last}); {name} is back on {a['from']}, the next destination is tried")
                    continue
                hint = lock_hint(why, a["from"]) or leftover_hint(why) or (" The compute nodes cannot reach each other for the migration (SSH on port "
                                                     "2022, libvirt, storage or network binding): check nova_migration_target and "
                                                     "the nova-compute log of both computes." if PLATFORM.search(why or "") else "")
                raise Done(FAILED, f"the live migration failed and was rolled back: {last}. {name} keeps running on {a['from']}.{hint}")
            except Done as e:   # it stays on its source: is it well there, and can Horizon open it (page, console)?
                if e.rc != FAILED:
                    raise
                check_after(d, sid, e.message.rstrip("."), host=a["from"], nodes=a["nodes"], user=a["user"], before=before,
                            ports=True, ports_before=state["ports"], rc_ok=FAILED, usable=True)
        recover(d, a, sid, info, d.clock() - started)   # error / stuck: ends with Done
    raise Done(FAILED, f"no destination accepted {name}: {none_left(d, last)}. It keeps running "
                       f"on {a['from']}")


def start_failed(d, a, sid, name, rc, out, last, started):
    """The start of a live migration failed (the client exited non-zero). On an error of Nova's control plane the API can
    keep part of it (a real case, metrics-vm: nova-conductor lost its database, HTTP 500 after 328 s): the
    instance stays in task migrating without any migration, so it cannot be aborted and its console is refused until
    someone resets it; after a timeout Nova may even still start the migration. True: a migration of the instance is
    under way (it is followed like any other); False: Nova kept nothing (the instance is as before). Else the item ends
    through recover(): a reset to ACTIVE only when virsh shows the domain running on the source alone; after an error of
    the control plane the run then stops (ATTENTION), so no other instance is sent into it."""
    control = bool(CONTROL.search(out or ""))
    s = d.server(sid, show=True)
    if s is None:
        raise Done(OK, f"{name} was deleted: nothing left to do")
    if not s.get("unknown") and s.get("status") in ("ACTIVE", "PAUSED") and not s.get("task"):
        return False
    wait = START_SETTLE_SLOW if rc == 124 or re.search(r"timed out|timeout|no answer", out or "", re.I) else START_SETTLE
    state = (f"{s['status']}{' (' + s['task'] + ')' if s.get('task') else ''}" if not s.get("unknown")
             else f"unknown ({s['unknown']})")
    d.say(f"{name} is {state} after the failed start: waiting up to {minutes(wait)} for Nova to start the migration or "
          "clear the task (nothing is changed meanwhile)")
    seen = {"s": s, "busy": []}

    def settled():
        now = d.server(sid)
        seen["s"] = now
        if now is None:
            return True
        if now.get("unknown"):
            return False
        busy = [m for m in d.migrations(sid) if m["status"] in IN_PROGRESS] if now.get("task") else []
        seen["busy"] = busy
        return bool(busy) or not now.get("task")
    d.wait(settled, wait, every=15)
    s, busy = seen["s"], seen["busy"]
    if s is None:
        raise Done(OK, f"{name} was deleted: nothing left to do")
    if busy:
        d.say(f"Nova started it after all: migration {busy[0]['id']} {busy[0]['status']}; it is followed")
        return True
    if s.get("unknown"):
        raise Done(ATTENTION, f"the start of the live migration failed ({last}) and the OpenStack API does not answer now "
                              f"({s['unknown']}): {name} may be left in task migrating. {CONTROL_HINT} Once the API answers: "
                              f"if openstack server show {sid} still shows a task and openstack server migration list --server "
                              f"{sid} no migration under way, check virsh domstate on {a['from']} and only then reset it "
                              f"(openstack server set --state active {sid}).")
    if s.get("status") in ("ACTIVE", "PAUSED") and not s.get("task"):
        return False
    why = (f"the start failed ({last}) and Nova left it {s['status']}{' (' + s['task'] + ')' if s.get('task') else ''} "
           "without a migration")
    try:
        recover(d, a, sid, why, d.clock() - started)
    except Done as e:
        if control and e.rc in (FAILED, ATTENTION) and CONTROL_HINT not in e.message:
            raise Done(ATTENTION, f"{e.message} {CONTROL_HINT}")
        raise
    raise Done(ATTENTION, f"{name}: {why}")   # recover always ends with Done


def read_ahead_before(d, a, s):
    """The reads of the checks before a live migration, all at once (Director.prefetch): the Cinder attachments, the
    libvirt job, Nova's connections, the guest LVs of the source, the computes, the console, ports and screenshot before
    the change, the CPU of the source. Each check then gets the read it makes, with the same arguments, as before."""
    sid, inst = a["id"], s.get("instance") or ""
    calls = [("attachments", v) for v in s.get("volumes") or []]
    calls += [("computes",), ("console_log", sid), ("port_states", sid), ("server", sid), ("modern",)]
    if a.get("nodes") and INSTANCE_RE.match(inst):
        ip, user = d.node(s["host"], a["nodes"], a.get("user") or "")
        if ip:
            calls += [("host_lvs", ip, user, f"guest LVs on the disks of {inst}?"), ("dead_disks", ip, user),
                      ("job_blocked", ip, user, inst), ("bdm_rows", sid)]
        ip, user = d.node(s["host"], a["nodes"], a["user"])
        if ip:
            calls.append(("screenshot", ip, user, inst))
        calls.append(("vendor", a["nodes"].get(short(a["from"])), a.get("user") or "heat-admin"))
    d.prefetch(*calls)


def read_ahead_target(d, a, sid, target):
    """Before an attempt to a named destination, at once: its CPU (unless the usage read gave it), whether a directory of
    the instance is left there, and its LVM filter when a disk has LVM on the whole disk."""
    calls = []
    if (a.get("vendors") or {}).get(short(target)) is None:
        calls.append(("vendor", a["nodes"].get(short(target)), a.get("user") or "heat-admin"))
    ip, user = d.node(target, a["nodes"], a.get("user") or "")
    if ip:
        calls.append(("dead_disks", ip, user))
        calls.append(("instance_dir", ip, user, sid))
        calls.append(("dest_paths", ip, user))
        if a.get("lvm_disks"):
            calls.append(("lvm_filter", ip, user))
    d.prefetch(*calls)


def read_ahead_after(d, a, s, host, started):
    """After a live migration that ended on its destination, at once: the disks of the source since the start, the guest
    LVs of the destination, and what check_after reads (Nova, ports, the domain, its console and screenshot)."""
    sid, inst = a["id"], s.get("instance") or ""
    calls = [("server", sid), ("ports_of", sid), ("console_log", sid)]
    if a.get("nodes"):
        ip, user = d.node(a["from"], a["nodes"], a.get("user") or "")
        if ip:
            calls.append(("disk_paths", ip, user, started - 60))
        ip, user = d.node(host, a["nodes"], a.get("user") or "")
        if ip:
            calls.append(("host_lvs", ip, user, f"did {short(host)} activate guest LVs on the disks of {inst}?"))
    ip, user = d.node(host, a.get("nodes"), a.get("user")) if host else (None, None)
    if ip and INSTANCE_RE.match(inst):
        calls += [("domain_check", ip, user, inst, []), ("screenshot", ip, user, inst)]
    d.prefetch(*calls)


def prepare_destination(d, a, sid, target):
    """Before a live migration to a named destination: Nova refuses it (DestinationDiskExists) when the directory of the
    instance is still on that compute, and the rollback of that refusal disconnects volumes there with the LUN numbers of
    the source (a real case: the data disk of another instance lost all its paths). A leftover directory on local
    storage, with no domain of the instance defined there, is moved aside (renamed, never deleted); on shared storage, with
    a domain, or when it cannot be moved, it is left alone and that destination is skipped (False)."""
    ip, user = d.node(target, a["nodes"], a.get("user") or "") if a.get("nodes") else (None, None)
    if a.get("lvm_disks"):
        lvm = d.lvm_filter(ip, user) if ip else {"unknown": "not in the node list"}
        if not lvm.get("safe"):
            skip(d, target, f"LVM on the whole disk of {', '.join(a['lvm_disks'])}, and the LVM of {target} "
                 + (f"could not be read ({lvm['unknown']})" if lvm.get("unknown") else f"accepts guest volumes (global_filter "
                    f"{lvm['filter']})") + ": it could activate the guest's LVs on a path, and the instance would run on the "
                 "inner LV there (a real case)")
            return False
    if not ip:
        return True
    if not clean_paths(d, target, ip, user):
        return False
    found = d.instance_dir(ip, user, sid)
    if found.get("unknown"):
        d.say(f"Note: the instance directory on {target} could not be read ({found['unknown']}): not checked")
        return True
    if not found["exists"]:
        return True
    path = f"/var/lib/nova/instances/{sid}"
    if not found["fstype"] or found["fstype"] in SHARED_FS or found["domain"] != "no":
        why = (f"a domain of the instance is defined there ({found['domain']})" if found["domain"] != "no"
               else f"the instances path is {found['fstype'] or 'of an unknown filesystem'}, shared between the computes")
        skip(d, target, f"{path} is there (changed {found['changed']}) and {why}: it is left alone; Nova would refuse "
              "the migration (DestinationDiskExists)")
        return False
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(d.clock()))
    rc, out = d.move_aside(ip, user, sid, stamp)
    if rc != 0:
        skip(d, target, f"the leftover {path} could not be moved aside ({first_line(out) or f'exit {rc}'})")
        return False
    d.say(f"Automatic fix: {path} was still on {target} (changed {found['changed']}; local {found['fstype']}, no domain of the "
          f"instance there): moved aside to {path}.leftover-{stamp} (not deleted), so Nova does not refuse the migration "
          "(DestinationDiskExists) and run a rollback there")
    return True


def clean_paths(d, target, ip, user):
    """Before a live migration to a destination (DEST_PATHS, light): iSCSI path devices left there in no map, multipath
    maps without a working path, or a disk in use without one. A volume connected at the address of such a device runs on it, dead, and
    the migration hangs: the incoming copy cannot open the disk, Nova's abort does not end it (a real case,
    dev-vm-01). Such a destination is skipped (False); one whose devices cannot be read is used (noted)."""
    seen = d.dest_paths(ip, user)
    if seen.get("unknown"):
        d.say(f"Note: the path devices of {target} could not be read ({seen['unknown']}): not checked")
        return True
    loose = [f"{sd} ({addr}, {st})" for sd, addr, st, _w in seen["loose"]]
    dead = [dm for dm, _n, o, _t in seen["dead"] if o == "0"]
    lost = [dm for dm, _n, o, _t in seen["dead"] if o != "0"]
    if not loose and not dead and not lost:
        return True
    parts = ([f"{len(loose)} iSCSI path device(s) in no map: {', '.join(loose[:6])}"] if loose else []) \
        + ([f"{len(dead)} multipath map(s) without a working path: {', '.join(dead[:6])}"] if dead else []) \
        + ([f"{len(lost)} disk(s) in use without a working path: {', '.join(lost[:6])}"] if lost else [])
    skip(d, target, f"{'; '.join(parts)}. A volume connected there could come up on a dead device and the migration "
          "hang (a real case): clean it with the check host-lvm (Flush the leftover maps, Delete the dead path "
          "devices) before migrating to it")
    return False


ROLLBACK_WAIT = 600     # how long the end of Nova's rollback on the destination is awaited before its disks are read
ROLLBACK_APPEAR = 120   # no rollback event on the destination by then: none is coming


def wait_rollback(d, sid, dest):
    """Nova's rollback on the destination runs on after the migration shows failed: it disconnects the volumes there,
    and a disconnect that cannot flush a map retries for minutes before it deletes the path devices (a real case: the paths of another instance's disk on iha-11 were deleted at 14:51:34, 2 minutes after the failure; the
    item had read that compute before and ended at 14:52:15, the disk stayed without path for 2 hours). Waits for the
    end of its event (compute_rollback_live_migration_at_destination), at most ROLLBACK_WAIT."""
    t0 = d.clock()
    while True:
        st = d.rollback_state(sid, LIVE_ACTIONS)
        waited = d.clock() - t0
        if st == "ended":
            if waited:
                d.say(f"Nova's rollback on {short(dest)} ended after {minutes(waited)}: its disks are checked now")
            return
        if (not st and waited >= ROLLBACK_APPEAR) or waited >= ROLLBACK_WAIT:
            d.say(f"Note: Nova's rollback on {short(dest)} " + ("is still running" if st else "was not recorded")
                  + f" after {minutes(waited)}: its disks are checked now")
            return
        d.sleep(10)


def check_rollback(d, a, name, dest, started, base=None):
    """After a live migration that ended back on its source: Nova's rollback disconnects the volumes on the destination,
    and with the source's LUN numbers it can remove the paths of another instance's disk there (a real case: a 100 GB
    data disk had no path for hours, its XFS shut down). Reads the destination's kernel log since the start, its multipath
    maps and the disks of its running domains. A disk of a running instance that lost its paths gets them back with a
    scan of only the removed SCSI addresses (a new device is kept only with the WWID of that disk's map, deleted again
    otherwise); then the item ends in ATTENTION naming those instances (the run stops). Nothing found: one line."""
    if not dest or not a.get("nodes"):
        return
    hurt = check_victims(d, a, dest, started, base, "after the rollback")
    if hurt:
        raise Done(ATTENTION, f"the rollback of the migration of {name} on {short(dest)} {hurt}. {name} keeps running on "
                              f"{a['from']}")


def base_line(d, a, host):
    """The disks of running instances on a compute that already have no path before a migration ({dm: wwid}), so that
    only what the migration removes is reported after it; {} when it cannot be read (then every dead disk is reported)."""
    ip, user = d.node(host, a.get("nodes"), a.get("user") or "") if a.get("nodes") else (None, None)
    return (d.dead_disks(ip, user) or {}) if ip else {}


def check_victims(d, a, host, started, base, moment):
    """After a migration (its source: Nova disconnected the volumes there) or a rollback (its destination: Nova disconnected
    them with the source's LUN numbers, a real case): reads the compute's kernel log since the start, its multipath maps
    and the disks of its running domains. A disk of another running instance that lost its paths in that time (not one
    already without path before: base) gets them back with a scan of only the removed SCSI addresses (a new device is kept
    only with the WWID of that disk's map, deleted again otherwise). Returns what it found as text for an ATTENTION, or
    "" (one line said)."""
    ip, user = d.node(host, a["nodes"], a.get("user") or "") if a.get("nodes") else (None, None)
    if not ip:
        d.say(f"Note: {host} is not in the node list: its disks were not checked {moment}")
        return ""
    since = started - 60
    seen = d.disk_paths(ip, user, since)
    if seen.get("unknown"):
        d.say(f"Note: the disks of {short(host)} could not be read {moment} ({seen['unknown']})")
        return ""
    dead = lambda x: x["paths"] == 0 or "##" in x["vendor"]   # noqa: E731  a map left without any path
    base = base or {}
    victims = sorted(dm for dm in seen["users"]
                     if (dm in seen["io"] or (dm in seen["maps"] and dead(seen["maps"][dm])))
                     and not (dm in base and base[dm] == (seen["maps"].get(dm) or {}).get("wwid")))
    if not victims:
        d.say(f"Checked {short(host)} {moment}: no disk of another instance lost a path"
              + (f" ({len(seen['removed'])} SCSI device(s) removed there)" if seen["removed"] else "")
              + (f"; {len(base)} disk(s) there were already without path before" if base else ""))
        return ""
    lost = [dm for dm in victims if dm in seen["maps"] and dead(seen["maps"][dm])]
    if lost and seen["removed"]:
        for addr, sd, wwid, kept in d.rescan_luns(ip, user, seen["removed"], [seen["maps"][dm]["wwid"] for dm in lost]):
            d.say(f"Automatic fix: {addr} came back as {sd} (WWID {wwid}): "
                  + ("kept, it is the disk of a running instance that lost its paths" if kept else "not such a disk, deleted again"))
        again = d.disk_paths(ip, user, since, show=False)
        if not again.get("unknown"):
            seen["maps"] = again["maps"]
    parts = []
    for dm in victims:
        mp = seen["maps"].get(dm) or {"wwid": "?", "paths": 0, "vendor": ""}
        who = ", ".join(f"{n} ({u or '?'})" for n, u in seen["users"][dm])
        state = (f"{mp['paths']} path(s) now" if not dead(mp) else "still no path")
        parts.append(f"{who}: disk {dm} ({mp['wwid']}) " + ("had I/O errors" if dm in seen["io"] else "lost its paths") + f", {state}")
    return (f"touched the disks of other instances there: {'; '.join(parts)}. Their guests may have I/O errors or "
            "a read-only / shut-down filesystem and need their owner; reboot one only after the check \"Volume connections "
            "of an instance\" is clean for it")


def migration_blockers(d, a, s, live):
    """Read-only, before a migration starts (nothing is changed yet): the states known to make it fail halfway and leave
    leftovers behind (a real case), as [why] (empty: none):
      - a volume of the instance that Cinder does not have by its ID (only a volume NAMED so, the target of a volume
        migration that never completed, or none): Nova cannot make its attachment for the destination (HTTP 404), and its
        rollback then disconnects the source's LUN number on the destination, the disk of another instance there (a real case: vm-c3 failed this way, instance 9c5e1a23 on iha-11 had no disk for 2 hours). Done SKIPPED
        at once (nothing else is read or changed; the next item of a run still runs);
      - a volume of the instance with more than one Cinder attachment (not multiattach): Cinder refuses the attachment of
        the migration ("duplicate connectors") after the instance was stopped (cold) or the volume mapped (live);
      - live: libvirt cannot take a job on the domain on its source compute (cannot acquire state change lock): the live
        migration fails after the destination was prepared and Nova leaves the instance in ERROR without a rollback."""
    why, facts = [], None
    for vid in s.get("volumes") or []:
        v = d.volume(vid)
        if v is None or v.get("missing"):
            why.append(f"volume {vid} of the instance (Nova's block device mapping) is not in Cinder by its ID: "
                       + (v["missing"] if v else "Cinder answers 404")
                       + ". Nova could not make its attachment for the destination, and the rollback would disconnect the "
                         "source's LUN number on the destination, the disk of another instance there (a real case). The "
                         "volume record needs a repair first (a Cinder volume migration that never completed): the check "
                         "\"Volume connections of an instance\" names the volume it runs on and the steps")
    if why:
        raise Done(SKIPPED, f"not moved, nothing was changed: {'; '.join(why)}. {s.get('name') or a['id']} stays on {a['from']}")
    for vid in s.get("volumes") or []:
        atts = d.attachments(vid)
        if atts is None:
            d.say(f"Note: the Cinder attachments of volume {vid} could not be read")
            continue
        if len(atts) > 1 and not (d.volume(vid) or {}).get("multiattach"):
            if facts is None:
                facts = d.attachment_rows(a["id"]) or {}
            kept = drop_leftover_attachments(d, a, s, vid, facts)
            if not kept:
                continue
            why.append(f"volume {vid} has {len(atts)} Cinder attachments ("
                       + ", ".join(f"{x['id']} {x['status']}" for x in atts[:4])
                       + "): a leftover of an earlier failed migration; the migration would be refused with \"duplicate "
                         f"connectors\" halfway ({kept}). Run the check \"Volume connections of an instance\" to see which "
                         "one is stale")
    if live and a.get("nodes") and s.get("instance") and INSTANCE_RE.match(s["instance"]):
        ip, user = d.node(s["host"], a["nodes"], a.get("user") or "")
        blocked = d.job_blocked(ip, user, s["instance"]) if ip else ""
        if blocked:
            why.append(f"libvirt on {s['host']} cannot take a job on {s['instance']} ({blocked}): the live migration would "
                       "fail after the destination is prepared and leave the instance in ERROR. Check virtqemud and the QEMU "
                       "process of the instance on that compute first")
    if live and s.get("volumes") and s.get("instance") and INSTANCE_RE.match(s["instance"]):
        why += disk_blockers(d, a, s)
    return why


STALE_ATTACHMENT = ("error_attaching", "reserved", "error_detaching", "detached")
STALE_MINUTES = 30


def leftover_attachments(facts, vid, sid, host):
    """The other Cinder attachments of a volume, when every one of them is safe to delete before a migration: ([ids], "")
    or ([], why not). Safe: the attachment Nova uses is attached to the compute the instance runs on, and each other one is
    of this instance, error_attaching / reserved / error_detaching / detached, has no connection (no host was given the
    LUN to connect), is not of that compute and has not changed for STALE_MINUTES (nothing is attaching it now). Its
    delete then removes the record and, with its connector, the LUN mapping of THAT host's initiator only (NetApp: per
    host igroup), never the one the instance runs on. Any other attachment: nothing is deleted."""
    f = (facts or {}).get(vid) or {}
    if not f.get("atts"):
        return [], "its attachments could not be read in the database of a controller"
    nova = f.get("nova") or ""
    mine = f["atts"].get(nova)
    if not mine:
        return [], "the attachment Nova uses for it is not among them"
    if mine["status"] != "attached" or not same_host(mine["host"] or mine["connector"], host):
        return [], (f"the attachment Nova uses ({nova}) is {mine['status']} on {short(mine['host'] or mine['connector']) or 'no host'}, "
                    f"not attached to {short(host)}")
    ids = []
    for aid, x in f["atts"].items():
        if aid == nova:
            continue
        problem = ("it belongs to another instance" if x["server"] and x["server"] != sid else
                   f"it is {x['status'] or 'without status'}" if x["status"] not in STALE_ATTACHMENT else
                   "it has a connection (a host may have connected the LUN)" if x["connected"] else
                   f"it is of {short(host)}, where the instance runs" if same_host(x["host"], host) or same_host(x["connector"], host) else
                   f"it changed {x['minutes']} min ago" if x["minutes"] is None or x["minutes"] < STALE_MINUTES else "")
        if problem:
            return [], f"attachment {aid}: {problem}"
        ids.append(aid)
    return ids, ""


def drop_leftover_attachments(d, a, s, vid, facts):
    """Automatic fix before a migration (a real case: error_attaching attachments left by live
    migrations that failed on 17 Oct stopped every later one): the leftover attachments of a volume are deleted with the
    Cinder API (attachment-delete, volume API 3.27) when every one of them is safe (leftover_attachments), then read
    again. "" when only the attachment Nova uses is left, else why the volume still blocks the migration."""
    ids, why = leftover_attachments(facts, vid, a["id"], s["host"])
    if why:
        return f"not deleted automatically: {why}"
    nova = facts[vid]["nova"]
    for aid in ids:
        x = facts[vid]["atts"][aid]
        d.say(f"Automatic fix: delete the leftover Cinder attachment {aid} of volume {vid} ({x['status']}, connector "
              f"{short(x['connector']) or 'none'}, never connected, unchanged for {x['minutes']} min); Nova uses {nova}, "
              f"attached to {short(s['host'])}, which is not touched")
        rc, out = d.run(["cinder", "--os-volume-api-version", "3.27", "attachment-delete", aid])
        if rc != 0:
            return f"the delete of the leftover {aid} failed: {last_error(out) or 'exit ' + str(rc)}"
    left = d.attachments(vid)
    if left is None or [x["id"] for x in left] != [nova] or left[0]["status"] != "attached":
        return ("after the delete Cinder lists " + (", ".join(f"{x['id']} {x['status']}" for x in left or []) or "nothing readable")
                + f" for it, not only {nova} attached")
    vol = d.volume(vid) or {}
    if vol.get("status") != "in-use":
        raise Done(ATTENTION, f"the leftover attachment(s) {', '.join(ids)} of volume {vid} were deleted, but Cinder now shows "
                              f"the volume {vol.get('status') or vol.get('unknown') or 'unreadable'}, not in-use, while {s['name']} "
                              f"still runs on it on {s['host']}: not migrated. Set it back before anything else (cinder "
                              f"reset-state --state in-use --attach-status attached {vid})")
    d.say(f"  volume {vid}: only {nova} (attached) is left, the volume is in-use")
    return ""


def disk_blockers(d, a, s):
    """Live, read-only, before the migration: the disks of the instance on its compute against Nova's connection of each
    volume. Blocks (as [why]):
      - a disk the domain runs on that is an LVM LV the host activated (uuid LVM-), not the volume's multipath map (a real case, storage-vm / app-staging): the guest sees that inner LV as its whole disk; at the destination it would
        get the whole disk and its data would move under it while it runs;
      - stale connection info: Nova's LUN of a volume is, on the source, a device that is not the instance's disk (DCA
        vm-c3): after the migration Nova disconnects that LUN there, which removes another instance's disk;
      - a LUN number that presents another LUN: Nova's LUN is the instance's own map, but its paths there report another
        WWID (a real case, tenant-staging-3): the storage changed what that number gives the compute, the guest
        may run on that LUN, and a migration would switch it back to its volume under its running file system.
    Also notes the disks with an LVM label on the whole disk (a["lvm_disks"]): their destination must be a compute whose
    LVM leaves guest volumes alone (prepare_destination)."""
    why = []
    ip, user = d.node(s["host"], a.get("nodes"), a.get("user") or "")
    if not ip:
        d.say(f"Note: {s['host']} is not in the node list: the disks of {s['instance']} were not compared with Nova's connections")
        return why
    rows = d.bdm_rows(a["id"])
    if rows is None:
        d.say("Note: Nova's connection of the volumes could not be read on a controller: stale connection info not checked")
        rows = []
    facts = d.disk_facts(ip, user, s["instance"], [(r[2], r[3]) for r in rows])
    if facts.get("unknown"):
        d.say(f"Note: the disks of {s['instance']} on {short(s['host'])} could not be read ({facts['unknown']}): not checked")
        return why
    disks = facts["disks"]
    for tgt, x in sorted(disks.items()):
        if x["kind"] == "LVM":
            why.append(f"{tgt} runs on {x['dm']} ({x['wwid']}), an LVM LV of the guest that {short(s['host'])} activated, not the "
                       "multipath map of the volume: the guest sees that LV as its whole disk, and the migration would give it "
                       "the whole disk while it runs. Stop the instance, release the LV on the compute (host-lv-release), "
                       "start it, then migrate")
    for dev, vol, iqn, lun in rows:
        tgt = dev.rsplit("/", 1)[-1]
        mine = disks.get(tgt)
        if not mine or mine["kind"] == "LVM" or not IQN_RE.match(iqn) or not lun.isdigit():
            continue
        others = [(dv, w, users) for dv, w, users in facts["luns"].get((iqn, lun), []) if w != mine["wwid"]]
        foreign = [x for x in others if x[0] != mine["dm"]]
        if foreign:
            dv, w, users = foreign[0]
            who = [u for u in users if u != s["instance"]]
            why.append(f"{dev} (volume {vol}): Nova's connection names LUN {lun}, which on {short(s['host'])} is {dv} ({w})"
                       + (f", a disk of {', '.join(who)}" if who else "") + f", not the disk of the instance ({mine['dm']}, "
                       f"{mine['wwid']}): stale connection info. After the migration Nova would disconnect LUN {lun} there "
                       "and remove that disk. Repair the connection first (check \"Volume connections of an instance\")")
        elif others:
            # A real case, tenant-staging-3: Nova's LUN is the instance's own map, but its paths there came to
            # report another LUN (the kernel keeps the WWID of their last scan; the map keeps the one it was made with)
            w = others[0][1]
            why.append(f"{dev} (volume {vol}): Nova's LUN {lun} is the instance's own disk {mine['dm']} ({mine['wwid']}), "
                       f"but {len(others)} path(s) of it at that LUN report another LUN ({w}, read at their last scan): the "
                       f"storage presents another LUN at number {lun} to {short(s['host'])}, a change on the storage side, not "
                       "in OpenStack. The guest may be reading and writing that LUN instead of its volume, and a migration "
                       "would put it back on its volume under its running file system. First the storage team checks "
                       f"which LUN number {lun} gives this compute and since when (lun mapping show -lun-id {lun}), and the "
                       "owner of the instance decides what comes next")
    a["lvm_disks"] = sorted(t for t, x in disks.items() if str(x["pv"]).isdigit())
    if a["lvm_disks"]:
        d.say(f"Note: LVM on the whole disk of {', '.join(a['lvm_disks'])}: only a destination whose LVM leaves guest volumes "
              "alone is used")
    return why


def lvs_of(seen, instance):
    """The guest LVs of HOST_LVS on the disks of one domain, each with the disk targets of that domain it sits on."""
    out = []
    for x in guest_lvs(seen):
        targets = [t for dom, t in x["users"] if dom == instance]
        if targets:
            out.append(dict(x, targets=targets))
    return out


def release_source_lvs(d, a, s):
    """Live, before the migration (after the read-only checks): the guest LVs its source compute activated on the disks of
    the instance (on a map, a path of it, or a partition of a disk it runs on with one SCSI device; a real case:
    nfs-vm-1, BIGIP). When the migration ends Nova flushes each map there, and an LV on it makes that flush fail
    (map in use): the disk stays connected on the source. Each such LV opened by nothing is released first (dmsetup remove,
    only the host's mapping; the instance keeps running on its map); one in use, or that cannot be released, stops the
    migration before it starts. A disk with LVM on a partition is noted like LVM on the whole disk: only a destination whose
    LVM leaves guest volumes alone is used (prepare_destination)."""
    if not a.get("nodes") or not s.get("volumes") or not INSTANCE_RE.match(s.get("instance") or ""):
        return
    ip, user = d.node(s["host"], a["nodes"], a.get("user") or "")
    if not ip:
        return
    seen = d.host_lvs(ip, user, f"guest LVs on the disks of {s['instance']}?")
    if seen.get("unknown"):
        d.say(f"Note: the LVM LVs of {short(s['host'])} could not be read ({seen['unknown']}): guest LVs on the disks of "
              f"{s['instance']} not checked")
        return
    mine = lvs_of(seen, s["instance"])
    if not mine:
        d.say(f"Checked {short(s['host'])}: no guest LV of {s['instance']} is active on the host")
        return
    stop, part = [], []
    for x in mine:
        where = f"{x['dm']} {x['name']} on {', '.join(x['targets'])}"
        if x["kind"] in ("runs-on", "busy"):
            stop.append(f"the guest LV {where} is {x['why']}")
            continue
        if any(k == "path" and dev != disk for k, dev, disk, _w in x["on"]) or \
                any(k == "map" and dev != disk for k, dev, disk, _w in x["on"]):
            part += x["targets"]
        res = d.release_lv(ip, user, x["uuid"])
        if res["state"] in ("removed", "gone"):
            d.say(f"Automatic fix: the guest LV {where}, activated by {short(s['host'])}, released there (only the host's "
                  "mapping; the instance keeps running, the volume is not written), so that Nova can flush the disk's map "
                  "after the migration" + "".join(f"; path {p} back to {t} ({n} path(s))" for p, t, n in res.get("added") or []))
        else:
            stop.append(f"the guest LV {where} could not be released ({res['state']}: {res['why']})")
    if stop:
        raise Done(FAILED, f"not started: {'; '.join(stop)}: Nova could not flush the disk's map on {short(s['host'])} after "
                           f"the migration. Run the check \"Guest LVs active on computes\" for {short(s['host'])}. "
                           f"{s['name']} keeps running there")
    if part:
        a["lvm_disks"] = sorted(set(a.get("lvm_disks") or []) | set(part))
        d.say(f"Note: LVM on a partition of {', '.join(sorted(set(part)))}: only a destination whose LVM leaves guest volumes "
              "alone is used (elsewhere the disk could end on one SCSI path)")


def check_dest_lvs(d, a, s, host):
    """After a live migration that ended on `host`: did that compute activate the guest's LVs on the disks of the instance
    (a real case: dcbvm-mdt01 and app-staging ran on their inner LVs from then on, their filesystems broke)? An LV
    the domain runs on, or a disk on one SCSI device without a multipath map, is returned as text for an ATTENTION (the
    run stops: a person stops the instance and releases the LV, or moves it to a compute with an LVM filter). An LV only
    sitting on its map or a path is released at once. Nothing found: one line, "" returned."""
    if not a.get("nodes") or not s.get("volumes") or not INSTANCE_RE.match(s.get("instance") or "") or not host:
        return ""
    ip, user = d.node(host, a["nodes"], a.get("user") or "")
    if not ip:
        d.say(f"Note: {host} is not in the node list: guest LVs on the disks of {s['instance']} there not checked")
        return ""
    seen = d.host_lvs(ip, user, f"did {short(host)} activate guest LVs on the disks of {s['instance']}?")
    if seen.get("unknown"):
        d.say(f"Note: the LVM LVs of {short(host)} could not be read ({seen['unknown']}): not checked after the migration")
        return ""
    bad = []
    for x in lvs_of(seen, s["instance"]):
        where = f"{', '.join(x['targets'])} ({x['dm']} {x['name']})"
        if x["kind"] == "runs-on":
            bad.append(f"{where}: the domain runs on an LV of the guest that the compute activated, not on the volume's "
                       "multipath map; the guest sees its own inner LV as that disk, shifted. Stop the instance now, release "
                       "the LV (check \"Guest LVs active on computes\"), then start it")
        elif x["kind"] == "busy":
            bad.append(f"{where}: an LV of the guest the compute activated on that disk is {x['why']}")
        else:
            res = d.release_lv(ip, user, x["uuid"])
            if res["state"] in ("removed", "gone"):
                d.say(f"Automatic fix: the guest LV {x['dm']} {x['name']} that {short(host)} activated on {', '.join(x['targets'])} "
                      "released there (only the host's mapping; the instance runs on its disk as before)")
            else:
                bad.append(f"{where}: an LV of the guest the compute activated on that disk could not be released ({res['why']})")
    raw = sorted((t, dev) for dev, users in seen["disks"].items() if re.match(r"^sd[a-z]+$", dev)
                 for dom, t in users if dom == s["instance"])
    for t, dev in raw:
        bad.append(f"{t} runs on {dev}, one SCSI path without a multipath map (LVM of the compute on a partition of it, or no "
                   "second path): one more path failure and the guest gets I/O errors; move it to a compute whose LVM filter "
                   "keeps guest volumes off")
    if not bad:
        mine = [t for users in seen["disks"].values() for dom, t in users if dom == s["instance"]]
        d.say(f"Checked {short(host)} after the migration: every disk of {s['instance']} is on its multipath map, no guest LV "
              "of it on the host" if mine else f"Note: no disk of {s['instance']} was found on {short(host)} after the "
                                               "migration: guest LVs there not checked")
    return "; ".join(bad)


def wait_site_free(d, a, sid, name):
    """Live migrations run one at a time per site: the portal starts no second one in a fix, and before each one it also
    waits while a live migration of another instance is still running there (another fix left it running, or someone
    started it in Horizon or with the CLI), up to the timeout of a migration. Still busy then: not started (Done)."""
    busy = d.live_migrations_running(sid, show=True)
    if busy is None:
        d.say("Note: the live migrations of the site could not be read; this one is started (the portal itself runs one at a time)")
        return
    if not busy:
        return
    seen = lambda b: ", ".join(  # noqa: E731
        f"migration {m['id']} of {m['server']} ({m['source']} -> {m['dest']}, {m['status']})" for m in b[:3])
    d.say(f"Waiting: a live migration is already running on this site: {seen(busy)}; live migrations run one at a time")
    if d.wait(lambda: not d.live_migrations_running(sid), a["timeout"], every=30):
        d.say("The other live migration has ended: this one starts now")
        d.forget("dead_disks")   # the disks without a path are read again right before the start
        return
    busy = d.live_migrations_running(sid) or busy
    raise Done(ATTENTION, f"not started: another live migration is still running on this site after {minutes(a['timeout'])} "
                          f"({seen(busy)}); {name} keeps running on {a['from']}. Live migrations run one at a time per site")


def switch_pause(d, a, history, diverge, now, ip, user, inst):
    """A copy that has not converged for DOWNTIME_AFTER: the pause at switch-over libvirt allows is raised to the one Nova
    is configured to reach (Director.switch_pause), said with what the last copies needed."""
    speed, dirty, _shrinking = copy_rate(history)
    left = [j["remaining"] for t, j in history if t >= diverge and j.get("remaining") is not None]
    least = round(min(left) / speed * 1000) if left and speed else None   # ms the smallest rest needs to switch over
    need = ("" if least is None else
            f"; the last {gib(min(left))} left needs about {least} ms of pause to switch over at {mib_s(speed)}" if min(left) == max(left)
            else f"; the last {gib(min(left))} to {gib(max(left))} left need about {least} to {round(max(left) / speed * 1000)} ms "
                 f"of pause to switch over at {mib_s(speed)}")
    p = d.switch_pause(ip, user, inst)
    why = (f"the copy has not converged for {minutes(now - diverge)} (the guest changes its memory at {mib_s(dirty)} while "
           f"it is copied at {mib_s(speed)}{need})")
    if "unknown" in p:
        d.say(f"  Note: {why}; the pause at switch-over could not be read or raised on {short(a['from'])} ({p['unknown']})")
    elif p["now"] > p["before"]:
        a["pause_ms"] = p["now"]
        d.say(f"Automatic fix: {why}: the pause at switch-over allowed is raised from {p['before']} ms to {p['now']} ms, the "
              f"one Nova is configured to reach (live_migration_downtime; Nova raises it only every 75 s per GiB of RAM)"
              + (f"; the guest needs more than that now, the copy may still not converge" if least and least > p["now"] else ""))
    else:
        d.say(f"  Note: {why}; the pause at switch-over allowed is already {p['before']} ms (Nova's limit {p['limit']} ms)")


def ping_during(d, a, sid, ip, user, elapsed, pinged):
    """Ping the guest of a live migration that runs long, from the OVN metadata namespace of each of its networks on the
    compute it runs on; a guest that answers on none of its addresses is noted for the result (a_ping_lost)."""
    if pinged["targets"] is None:
        pinged["targets"] = d.ping_targets(sid) or []
    if not pinged["targets"]:
        if not pinged["said"]:
            pinged["said"] = True
            d.say(f"  Ping at {minutes(elapsed)}: no IPv4 address of the instance could be read; not pinged")
        return
    res = d.ping_guest(ip, user, pinged["targets"])
    shown, tried, answered = [], 0, False
    for _net, addr in pinged["targets"]:
        r = res.get(addr)
        if not r or r["why"] or not r["sent"]:
            shown.append(f"{addr} not pinged ({(r or {}).get('why') or 'no answer from ' + short(a['from'])})")
            continue
        tried += 1
        answered = answered or r["received"] > 0
        shown.append(f"{addr} {r['received']}/{r['sent']} replies" + (f", avg {r['avg']:g} ms" if r["avg"] is not None else ""))
    d.say(f"  Ping at {minutes(elapsed)} (the guest runs on {short(a['from'])} while it is copied): " + "; ".join(shown))
    if tried and not answered:
        a.setdefault("ping_lost", []).append(minutes(elapsed))
        d.say(f"  Note: the guest did not answer ping at {minutes(elapsed)} (it may also drop ping by its own firewall)")


def aborted_why(d, a, sid, latest, started):
    """What the abort the portal sent did, as Nova recorded it: the status of the migration and the live_migration_cancel
    action (no action: Nova did not take the abort, the migration ended by itself)."""
    req = d.action_request(sid, CANCEL_ACTION, started)
    where = f"migration {latest['id']} {latest['status']}" if latest else "no migration record"
    return (f"aborted {a.get('abort_reason') or 'after ' + minutes(a['timeout']) + ' (timeout)'}: {where}, "
            + (f"Nova recorded the action {CANCEL_ACTION} ({req})" if req else f"but Nova recorded no {CANCEL_ACTION} action"))


def guard_destination(d, a, sid, mig, ip, user, guard):
    """One read of the destination of a large instance while it is copied (guard: what the reads before saw). Direct
    reclaim there in GUARD_STRIKES reads in a row: the copy is aborted, the guests already there come first (a real case, TenantVM3 froze while two others of 512 GiB were copied in), and "abort" or "abort refused" is
    returned; else "". A destination whose memory cannot be read is noted once and the copy goes on."""
    dest = short(mig["dest"])
    if not guard["said"]:
        guard["said"] = True
        d.say(f"  Guard: the memory of {dest} is read with the progress; direct reclaim there for about a minute aborts the "
              "copy (the instance stays on its source, the guests there come first)")
    now = d.clock()
    p = d.dest_pressure(ip, user)
    guard["at"] = now
    if "unknown" in p:
        if not guard.get("unread"):
            guard["unread"] = True
            d.say(f"  Note: the memory of {dest} cannot be read ({p['unknown']}): the copy goes on without the guard")
        return ""
    last, guard["last"] = guard["last"], (now, p)
    if last is None:
        return ""
    grew = p["reclaim"] - last[1]["reclaim"]
    if grew <= 0:
        guard.update(strikes=0, stalls=0, since=None)
        return ""
    guard["strikes"] += 1
    guard["stalls"] += grew
    guard["since"] = guard["since"] or last[0]
    free = f", {100.0 * p['avail_kb'] / p['total_kb']:.0f}% of its RAM available" if p.get("total_kb") else ""
    if guard["strikes"] < GUARD_STRIKES:
        d.say(f"  {dest}: {grew} direct reclaim stall(s) in the last {minutes(now - last[0])}{free}: its guests wait for "
              "memory; watched, the copy is aborted if it goes on")
        return ""
    why = (f"{dest} kept reclaiming memory for {minutes(now - guard['since'])} while it received the copy "
           f"({guard['stalls']} direct reclaim stall(s){free}): its guests were waiting for memory")
    a["dest_pressure"] = why
    a["abort_reason"] = f"because {why}"
    d.say(f"Automatic fix: {why}; abort migration {mig['id']} (the instance stays on its source)")
    rc, out = d.abort(sid, mig["id"])
    if rc != 0:
        a.pop("dest_pressure", None)
        d.say(f"  Nova refused it ({last_error(out) or f'exit {rc}'}): the migration goes on and is followed until it ends")
        return "abort refused"
    return "abort"


def watch_live(d, a, sid, src, started):
    """Follow a live migration: ("done", host), ("back", why), ("error", fault), ("stuck", why) or ("gone", "")."""
    acted, unknown, reported, last_left, mig = "", 0, started, None, None
    looked, noted, incoming = None, "", ""
    history, said_long, said_job = [], False, False   # the libvirt job of the source [(time, job)]
    diverge = None   # since when the copy does not converge (every read since), None while it does
    paused = False   # the switch-over pause of Nova's configuration given (once)
    pinged = {"next": started + PING_AFTER, "targets": None, "said": False}   # the guest pinged while it is copied
    job_at, job_ok = started, None   # the last read of libvirt, and whether it answered
    sip, suser = d.node(a["from"], a.get("nodes"), a.get("user")) if a.get("nodes") and a.get("user") else (None, None)
    large = a.get("ram", 0) >= LARGE_RAM_MB and bool(a.get("nodes")) and bool(a.get("user"))
    guard = {"at": started, "last": None, "strikes": 0, "stalls": 0, "since": None, "said": False}   # the destination
    d.forget("dest_pressure")   # a read made ahead for an attempt before (left when that one was aborted) is stale
    d.forget("job_progress")
    while True:
        elapsed = d.clock() - started
        # most live migrations end within a minute (a real case: 25-80 s): read often at first
        d.sleep(3 if elapsed < 60 else 5 if elapsed < 120 else 10 if elapsed < 300 else 20 if elapsed < 1800 else 30)
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
            refused = " (the abort was refused)" if acted == "abort refused" else ""
            if acted == "incoming":
                return "back", f"incoming: {incoming}" + (f"; migration {latest['id']} {latest['status']}" if latest else "")
            if latest and latest["status"] in ("error", "failed", "cancelled", "aborted"):
                return "back", (aborted_why(d, a, sid, latest, started) if acted == "abort"
                                else f"migration {latest['id']} ended {latest['status']}{refused}")
            if elapsed >= 180:
                return "back", (aborted_why(d, a, sid, latest, started) if acted == "abort" else
                                f"no migration started or it ended {latest['status'] if latest else 'without a record'}{refused}")
            continue   # accepted, not yet started
        if s["status"] == "ERROR":
            return "error", s["fault"] or "status ERROR"
        if s["status"] != "MIGRATING" and s["task"] not in ("migrating",):
            if elapsed > a["timeout"] + 900:
                return "stuck", f"status {s['status']} task {s['task'] or '-'}"
            continue
        if mig is None or d.clock() - reported >= 120:
            migs = [m for m in d.migrations(sid) if m["type"] in ("", "live-migration")]
            running = [m for m in migs if m["status"] in LIVE_BUSY]
            mig = running[0] if running else None
            if not running and migs and migs[0]["status"] in ("error", "failed") and elapsed > 300:
                return "stuck", f"MIGRATING while migration {migs[0]['id']} is {migs[0]['status']}"
            if mig and d.clock() - reported >= 120:
                if job_ok is False:   # libvirt did not answer: Nova's figures (none on RHOSP 16.2 while it runs)
                    left = d.memory_left(sid, mig["id"])
                    trend = "" if left is None or last_left is None else " (not decreasing)" if left >= last_left else ""
                    d.say(f"  {minutes(elapsed)}: migration {mig['id']} {mig['status']}"
                          + (f", {left / 2 ** 30:.2f} GiB memory left{trend}" if left is not None else ""))
                    last_left = left
                reported = d.clock()
        # cancelled on the portal (the flag the playbook relays with its next read of the output): the copy is aborted
        # now, the instance stays on its source (a refused abort, in post-copy: the migration is followed to its end)
        if mig and acted in ("", "none") and d.cancel_asked():
            a["cancelled"] = True
            a["abort_reason"] = "because the run was cancelled on the portal"
            d.say(f"Automatic fix: the run was cancelled on the portal: abort migration {mig['id']} (the instance stays on "
                  "its source)")
            rc, out = d.abort(sid, mig["id"])
            acted = "abort" if rc == 0 else "abort refused"
            if rc != 0:
                d.say(f"  Nova refused it ({last_error(out) or f'exit {rc}'}): the migration goes on and is followed "
                      "until it ends")
        # a large instance: its destination is read with the progress, both at once (no time added to the watch)
        dip = duser = None
        if large and mig and acted in ("", "none") and mig.get("dest") and short(mig["dest"]) != src \
                and d.clock() - guard["at"] >= JOB_EVERY:
            dip, duser = d.node(mig["dest"], a["nodes"], a["user"])
            inst = s.get("instance") or ""
            if dip and sip and job_ok is not False and d.clock() - job_at >= JOB_EVERY and INSTANCE_RE.match(inst):
                d.prefetch(("job_progress", sip, suser, inst), ("dest_pressure", dip, duser))
        # the progress of the copy, every JOB_EVERY seconds from libvirt on the source (shown live on the run page)
        if mig and job_ok is not False and d.clock() - job_at >= JOB_EVERY:
            job_at = d.clock()
            inst = s.get("instance") or ""
            job = d.job_progress(sip, suser, inst) if sip and INSTANCE_RE.match(inst) else {"unknown": "no node address"}
            if job.get("unknown"):
                job_ok = False
                if sip and not said_job:
                    said_job = True
                    d.say(f"  Note: the progress of the copy cannot be read from libvirt on {src} ({job['unknown']}): "
                          "Nova's figures only, every 2 minutes")
            else:
                job_ok = True
                prev = history[-1] if history else None
                history.append((job_at, job))
                a["last_job"] = job
                d.say(progress_line(elapsed, mig, job, prev, job_at))
                kind, why = job_verdict(history, job_at, a["timeout"], a["stall"])
                diverge = (job_at if diverge is None else diverge) if kind == "long" and diverging(history) else None
                if kind == "stuck" and acted in ("", "none"):   # not only at the time limit: a stuck copy ends now
                    a["abort_reason"] = f"because {why}"
                    d.say(f"Automatic fix: {why}: the migration is stuck; abort migration {mig['id']} (the instance "
                          "stays on its source)")
                    rc, out = d.abort(sid, mig["id"])
                    acted = "abort" if rc == 0 else "abort refused"
                    if rc != 0:
                        d.say(f"  Nova refused it ({last_error(out) or f'exit {rc}'}): the migration goes on and is "
                              "followed until it ends")
                elif (diverge is not None and job_at - diverge >= DOWNTIME_AFTER and not paused and acted in ("", "none")
                      and sip and INSTANCE_RE.match(inst)):
                    paused = True
                    switch_pause(d, a, history, diverge, job_at, sip, suser, inst)
                elif diverge is not None and job_at - diverge >= NOT_CONVERGING and acted in ("", "none"):
                    speed, dirty, _shrinking = copy_rate(history)
                    a["diverged"] = (f"the copy did not converge for {minutes(job_at - diverge)} (iteration "
                                     f"{job.get('iteration')}): the guest changes its memory at {mib_s(dirty)} while it is copied "
                                     f"at {mib_s(speed)}")
                    if a["stall"] == "force":
                        d.say(f"Automatic fix: {a['diverged']}: force-complete migration {mig['id']} (the instance pauses "
                              "until the copy ends, or Nova switches it to post-copy where it permits that)")
                        rc, out = d.force_complete(sid, mig["id"])
                        acted = "force" if rc == 0 else "force refused"
                    else:
                        a["abort_reason"] = f"because {a['diverged']}"
                        d.say(f"Automatic fix: {a['diverged']}; abort migration {mig['id']} (the instance stays on its source)")
                        rc, out = d.abort(sid, mig["id"])
                        acted = "abort" if rc == 0 else "abort refused"
                    if rc != 0:
                        d.say(f"  Nova refused it ({last_error(out) or f'exit {rc}'}): the migration goes on and is "
                              "followed until it ends")
                elif kind == "long" and elapsed >= LONG_MIGRATION and not said_long:
                    said_long = True
                    d.say(f"Why it takes long ({minutes(elapsed)}): {why}")
        if dip and acted in ("", "none"):
            acted = guard_destination(d, a, sid, mig, dip, duser, guard) or acted
        # running for 5 minutes and more: does the guest still answer? (every 5 minutes, from the compute it runs on)
        if mig and sip and acted in ("", "none") and d.clock() >= pinged["next"]:
            pinged["next"] = d.clock() + PING_EVERY
            ping_during(d, a, sid, sip, suser, elapsed, pinged)
        # also after an abort was sent at a short timeout: an abort does not end a copy that hangs on its disks
        if (mig and acted in ("", "abort", "abort refused", "none") and elapsed >= INCOMING_STUCK
                and (looked is None or d.clock() - looked >= 120)
                and a.get("nodes") and a.get("user") and INSTANCE_RE.match(s.get("instance") or "")):
            looked = d.clock()
            dest = mig.get("dest") or ""
            ip, user = d.node(dest, a["nodes"], a["user"]) if dest and short(dest) != src else (None, None)
            if ip:
                res = d.end_incoming(ip, user, s["instance"])
                if res["state"] in ("ended", "still"):
                    acted = "incoming"
                    dead = ", ".join(f"{dm} ({paths})" for dm, _n, act, paths in res["disks"] if act == "0") or "?"
                    incoming = (f"the incoming copy on {short(dest)} was still starting up after {minutes(elapsed)}: it could "
                                f"not open its disk(s) on {dead} without a working path")
                    d.say(f"Automatic fix: {incoming}. Ended there (SIGKILL of its QEMU, then fail_if_no_path on "
                          f"{', '.join(res['maps'])}); the instance keeps running on {src}, Nova rolls the migration back"
                          + ("" if res["state"] == "ended" else " (its QEMU has not exited yet)"))
                elif res["state"] != "not-stuck" and res["why"] != noted:
                    noted = res["why"]
                    d.say(f"  The incoming copy on {short(dest)} was not ended: {res['why'] or res['state']}")
        if elapsed > a["timeout"] and not acted:
            running = [m for m in d.migrations(sid) if m["type"] in ("", "live-migration") and m["status"] in LIVE_BUSY]
            mig = running[0] if running else mig   # its status now: an abort needs one not ended yet
            if mig:
                if a["stall"] == "force":
                    d.say(f"Automatic fix: not finished after {minutes(a['timeout'])}: force-complete (the instance pauses "
                          "until the memory copy ends)")
                    rc, out = d.force_complete(sid, mig["id"])
                    acted = "force" if rc == 0 else "force refused"
                else:
                    d.say(f"Automatic fix: not finished after {minutes(a['timeout'])}: abort migration {mig['id']} "
                          f"({mig['status']}; the instance stays on its source)")
                    rc, out = d.abort(sid, mig["id"])
                    acted = "abort" if rc == 0 else "abort refused"
                if rc != 0:   # never reported as done: the migration goes on, and no other one starts before it ends
                    d.say(f"  Nova refused it ({last_error(out) or f'exit {rc}'}): the migration goes on and is followed "
                          "until it ends")
            else:
                acted = "none"
        if elapsed > a["timeout"] + 900:
            return "stuck", f"still MIGRATING {minutes(elapsed)} after the start" + (f" ({acted}{' sent' if acted in ('abort', 'force') else ''})" if acted else "")


def first_error(lines):
    """The first error line of nova-compute log lines (prefix removed; traceback frames, their code lines, indented after
    the prefix, are left out): the cause, where the later ones are what the rollback ran into."""
    for line in lines:
        rest = LOG_PREFIX.sub("", line)
        if not rest.strip() or rest[:1].isspace() or rest.startswith("Traceback"):
            continue
        if re.search(r"(Error|Exception|error|refused|failed|Failed|could not be found)", rest):
            return rest.strip()[:400]
    return ""


def compute_reason(d, a, sid, hosts, seconds, first=False):
    """The error nova-compute logged for an instance since the migration started (seconds ago, plus 5 minutes), on the
    first of these computes that has one ('' when none is found). Nova records no fault when the libvirt migration itself
    fails: the instance is left in ERROR and only this log says why. first: its first error line, not its last (a failed
    pre_live_migration: the cause, then the errors of the rollback, a real case)."""
    if not a.get("nodes") or not a.get("user"):
        return ""
    seen = []
    for h in hosts:
        ip = a["nodes"].get(short(h)) if h and h != "auto" else None
        if not ip or short(h) in seen:
            continue
        seen.append(short(h))
        lines = d.nova_errors(ip, a["user"], sid, seconds + 300)
        found = first_error(lines) if first else last_error("\n".join(LOG_PREFIX.sub("", line) for line in lines))
        if found:
            return f"nova-compute on {h}: {found}"
    return ""


def leftover_hint(why):
    """What to do when a migration failed on a leftover attachment ("duplicate connectors"): never a hard reboot first."""
    return (" A volume of the instance still has an attachment of an earlier failed migration. Do not hard reboot, start or "
            "delete the instance before the check \"Volume connections of an instance\" shows its volume connections are "
            "clean: with a stale connection info, the disconnect of a reboot can hit another instance's disk on that compute."
            ) if DUPLICATE.search(why or "") else ""


def lock_hint(why, host):
    return (f" libvirt on {host} cannot get the lock of the instance: its QEMU does not answer libvirt (held by "
            "monitor=init-...: the reconnect of virtqemud to it never ended), so any destination fails the same way. Check "
            f"the QEMU process of the instance and virtqemud on {host} before another attempt.") if STUCK_LOCK.search(why or "") else ""


def recover(d, a, sid, why, seconds):
    """An instance left in ERROR, or MIGRATING without a running migration: reset it to ACTIVE only when its domain runs
    on the compute Nova records and on no other compute involved (virsh through the director). Why it failed is read
    first (the fault, the events, else the nova-compute log), as a reset clears the fault. Ends with Done."""
    s = d.server(sid, show=True) or {}
    if s.get("status") in ("ACTIVE", "PAUSED") and not s.get("task"):
        if short(s.get("host")) != short(a["from"]):
            raise Done(OK, f"{s.get('name')} is on {s.get('host')}")
        raise Done(FAILED, f"{s.get('name')} is back on {a['from']} after: {why}")
    name, host, instance = s.get("name") or sid, s.get("host") or "", s.get("instance") or ""
    state = f"{s.get('status')}{' (' + s['task'] + ')' if s.get('task') else ''}"
    involved = []
    dests = [m["dest"] for m in d.migrations(sid)[:1] if m["dest"]]   # where the scheduler sent it (destination "auto")
    for h in [host, a["from"]] + dests + ([] if dests else to_hosts(a)):
        if h and h != "auto" and short(h) not in [short(x) for x in involved]:
            involved.append(h)
    if s.get("fault") and s["fault"] not in why:
        why = s["fault"]
    elif why == "status ERROR":
        why = d.diagnose(sid, LIVE_ACTIONS) or compute_reason(d, a, sid, involved, seconds) or \
            "status ERROR without a fault: Nova recorded no reason (see the nova-compute log of the computes)"
    d.say(f"{name} is {state} on {host or '-'} after: {why}")
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
        raise Done(FAILED, f"{name} reset to ACTIVE on {a['from']}, where it keeps running; it was not migrated: {last_error(why).rstrip('.')}."
                               + (lock_hint(why, a["from"]) or leftover_hint(why)))
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
    blockers = migration_blockers(d, a, s, live=False)
    if blockers:
        raise Done(FAILED, f"not started: {'; '.join(blockers)}. Nothing was changed: {name} stays on {a['from']}")
    group = group_rule(d, a, sid, name, src)
    services = d.computes()
    if a.get("under"):
        targets = destinations(d, a, name, src, services)
    else:
        named = to_hosts(a)
        targets = (named or [None]) + [h for h in a["try"] if short(h) not in {short(x) for x in named} | {src}]
    group_reachable(group, targets, name, a)
    last, tried = "", 0
    for target in targets:
        if tried >= MAX_ATTEMPTS:
            break
        if group_bar(group, target):
            skip(d, target, group_bar(group, target))
            continue
        if target and services.get(short(target)) != ("enabled", "up"):
            skip(d, target, f"nova-compute is {'/'.join(services.get(short(target)) or ('not listed',))}")
            continue
        tried += 1
        d.say(f"Attempt {tried}: cold migration of {name} to {target or 'a compute chosen by the scheduler'}")
        started = d.clock()
        d.mark("migration")
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
            fault = s2["fault"] or d.diagnose(sid, COLD_ACTIONS) or "no fault message"
            raise Done(ATTENTION, f"{name} is in ERROR after the cold migration: {last_error(fault)}. It was shut off: check its "
                                  "disks on both computes before resetting its state" + leftover_hint(fault))
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
    raise Done(FAILED, f"no destination accepted {name}: {none_left(d, last)}")


# ---------------------------------------------------------------- volume migration (Cinder)
HEARTBEAT = 300   # while a migration or a retype runs: a line every 5 min, so the live output shows it is followed


def heartbeat(d, state, started, text):
    """A line of the live output every HEARTBEAT seconds while a long change is followed (nothing is said otherwise)."""
    if d.clock() - state.get("said", started) >= HEARTBEAT:
        state["said"] = d.clock()
        d.say(text)


SNAP_DELETABLE = ("available", "error")
SNAP_BUSY = ("creating", "backing-up", "restoring", "unmanaging")
SNAP_BUSY_WAIT = 900   # how long a busy snapshot (creating, backing up...) is waited for before it counts as stuck


def in_group(sid, group):
    where = (f"belongs to group snapshot {group}" if group else
             "was refused by Cinder although it is available, so it is part of a group snapshot (or of a consistency group "
             "snapshot; the API does not show which)")
    return (f"snapshot {sid} {where}: Cinder deletes it only together with its whole group snapshot, which also holds "
            "snapshots of the other volumes of the group, so the portal does not; a person decides (cinder "
            "group-snapshot-delete, after checking those volumes)")


def delete_snapshots(d, ids, label):
    """Delete the approved snapshots of a volume (or of an image) and wait until they are gone. Cinder deletes a snapshot
    only when it is available or error and not part of a group snapshot ("Snapshot status must be available or error and
    must not be part of a group"), so each one is read first, and none is deleted while one of them cannot be:
      deleting                   being deleted already: waited for
      error_deleting             an earlier delete failed on the backend: reset to available, then deleted (automatic fix)
      creating, backing-up, restoring, unmanaging   busy: waited for (up to 15 min), then deleted
      in a group snapshot, still busy, unreadable  nothing is deleted: the reason is returned
    A delete Cinder refuses all the same stops the deletion there (no wait for it). Returns {"deleted": n, "refused":
    [reason]: the rest was not deleted, the volume is as it was; "stuck": [reason]: a delete was accepted but the snapshot
    is still there (not a clean state)}."""
    state = {sid: d.snapshot(sid) for sid in ids}
    busy = [sid for sid, x in state.items() if x and x["status"] in SNAP_BUSY]
    if busy:
        d.say(f"{len(busy)} snapshot(s) of {label} are busy ({', '.join(sid + ' ' + state[sid]['status'] for sid in busy[:5])}): "
              f"Cinder deletes only available or error snapshots; waiting up to {minutes(SNAP_BUSY_WAIT)} for them to finish")

        def settled():
            for sid in busy:
                state[sid] = d.snapshot(sid)
            return all(not state[sid] or state[sid]["status"] not in SNAP_BUSY for sid in busy)
        d.wait(settled, SNAP_BUSY_WAIT, 30)
    refused = []
    for sid, x in state.items():
        if x is None:
            continue
        if x["status"] == "unknown":
            refused.append(f"snapshot {sid} could not be read")
        elif x["group"]:
            refused.append(in_group(sid, x["group"]))
        elif x["status"] in SNAP_BUSY:
            refused.append(f"snapshot {sid} is still {x['status']} after {minutes(SNAP_BUSY_WAIT)}: it may be stuck (check "
                           "Stuck instances and volumes)")
        elif x["status"] not in SNAP_DELETABLE + ("deleting", "error_deleting"):
            refused.append(f"snapshot {sid} is {x['status'] or 'without a status'}: Cinder deletes only available or error snapshots")
    if refused:
        for why in refused:
            d.say(f"Not deleted: {why}")
        return {"deleted": 0, "refused": refused, "stuck": []}
    accepted = []
    for sid, x in state.items():
        if x is None:
            continue
        if x["status"] != "deleting":
            if x["status"] == "error_deleting":
                d.say(f"Automatic fix: snapshot {sid} is error_deleting (an earlier delete failed): reset it to available and "
                      "delete it again")
                d.run(["cinder", "snapshot-reset-state", "--state", "available", sid])
            rc, out = d.run(["openstack", "volume", "snapshot", "delete", sid])
            if rc != 0:
                now = d.snapshot(sid)
                if now is None:
                    continue   # gone meanwhile
                if now["status"] != "deleting":
                    why = (in_group(sid, now["group"]) if now["group"] or now["status"] in SNAP_DELETABLE
                           else f"snapshot {sid} is {now['status']} now: Cinder deletes only available or error snapshots")
                    error = next((line.strip() for line in out.splitlines() if re.search(r"HTTP \d{3}|Invalid", line)), last_error(out))
                    d.say(f"Cinder refused to delete snapshot {sid} ({now['status']}): {error[:300]}")
                    d.say(f"Not deleted: {why}; the other snapshots are left as they are")
                    refused.append(why)
                    break
        accepted.append(sid)
    left = list(accepted)

    def gone_all():
        left[:] = [sid for sid in left if d.snapshot(sid) is not None]
        return not left
    if left and not d.wait(gone_all, 1800, 15):
        retry = [sid for sid in left if (d.snapshot(sid) or {}).get("status") == "error_deleting"]
        for sid in retry:
            d.say(f"Automatic fix: snapshot {sid} is error_deleting: reset it to available and delete it once more")
            d.run(["cinder", "snapshot-reset-state", "--state", "available", sid])
            d.run(["openstack", "volume", "snapshot", "delete", sid])
        d.wait(gone_all, 900, 15)
    stuck = [f"snapshot {sid} is still there after its delete ({(d.snapshot(sid) or {}).get('status') or 'gone'})" for sid in left]
    deleted = len(accepted) - len(left)
    if deleted:
        d.say(f"{deleted} snapshot(s) of {label} deleted")
    return {"deleted": deleted, "refused": refused, "stuck": stuck}


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
    blocked = swap_blocked(d, v)
    if blocked:
        raise Done(SKIPPED, f"{name} was not migrated, nothing was changed: {blocked}")
    snaps = d.snapshots_of(vid)
    extra = [s for s in snaps if s["id"] not in a["snapshots"]]
    if extra:
        raise Done(FAILED, f"{name} has snapshot(s) that were not approved in the check ({', '.join(s['name'] or s['id'] for s in extra[:5])}): "
                           "a volume with snapshots cannot migrate. Run the check again; nothing was changed")
    if snaps:
        d.say(f"{name} has {len(snaps)} approved snapshot(s): delete them first (a volume with snapshots cannot migrate)")
        res = delete_snapshots(d, [s["id"] for s in snaps], name)
        done = f" {res['deleted']} of its {len(snaps)} approved snapshot(s) were deleted." if res["deleted"] else " None of its snapshots was deleted."
        if res["stuck"]:
            raise Done(ATTENTION, f"{name} was not migrated: {'; '.join(res['stuck'])}.{done}")
        if res["refused"]:
            raise Done(FAILED, f"{name} was not migrated, it stays in {v['host']}: {'; '.join(res['refused'])}.{done}")
    gone = f" Its {len(snaps)} approved snapshot(s) were deleted." if snaps else ""
    server, device = attached_to(v)
    before = before_change(d, server)["log"] if server else None   # only console lines printed after the swap are judged
    targets = [a["to"]] + [p for p in a["try"] if p != a["to"]]
    if len(targets) == 1:   # no other pool: after a failure (temporary copy cleaned up) the same pool once more
        targets.append(a["to"])
    last = ""
    for n, target in enumerate(targets[:MAX_ATTEMPTS], 1):
        if n > 1 and d.time_left() is not None and d.time_left() < 900:   # never a new migration the portal cannot follow
            raise Done(FAILED, f"{name} could not be migrated: {last}; no time left in this fix for attempt {n}. It stays in "
                               f"{v['host']}." + gone)
        d.say(f"Attempt {n}: migrate {name} to {target}")
        started = d.clock()
        rc, out = d.run(["cinder", "migrate", vid, target])
        if rc != 0:
            last = last_error(out) or f"exit {rc}"
            now = d.volume(vid)   # the API may have taken it all the same (a proxy timeout)
            if now is None or now.get("unknown"):
                raise Done(ATTENTION, f"cinder migrate failed ({last}) and {name} could not be read again: look at it "
                                      "before running the fix again." + gone)
            if now["migstat"] not in ("migrating", "starting", "completing"):
                if DESTINATION.search(out or "") and n < len(targets):
                    d.say(f"Automatic fix: {target} refused it ({last}); the next pool is tried")
                    continue
                raise Done(FAILED, f"cinder migrate was refused: {last}. {name} stays in {v['host']}." + gone)
            d.say(f"cinder migrate gave an error ({last}), but {name} is migrating: it is followed")
        state = {}
        copy = (" For an attached volume the data may be copied by the compute of its instance (Nova swap volume): "
                "virsh blockjob <instance> <disk> --info there shows how far it is.") if v["status"] == "in-use" else ""
        d.say(f"Waiting for the migration of {name} ({v['size']} GiB): checked every 30 s, a line every "
              f"{minutes(HEARTBEAT)}, for up to {minutes(a['timeout'])}. A Cinder migration cannot be stopped safely.{copy}")

        def ended():
            v2 = d.volume(vid)
            state["v"] = v2
            if v2 is None or v2.get("unknown"):
                return v2 is None
            if v2["migstat"] in ("success", "error"):
                return True
            # Some clients clear migration_status at the end: the host tells.
            if v2["migstat"] in ("", "none") and d.clock() - started > 120:
                return True
            heartbeat(d, state, started, f"{name}: still migrating to {target} after {minutes(d.clock() - started)} "
                                         f"(migration_status {v2['migstat'] or '-'}, status {v2['status']}, on {v2['host']})")
            return False
        if not d.wait(ended, a["timeout"], 30):
            raise Done(ATTENTION, f"{name} is still migrating after {minutes(d.clock() - started)} (migration_status "
                                  f"{(state.get('v') or {}).get('migstat')}): a Cinder migration cannot be stopped safely. "
                                  "Leave it and follow it with Stuck instances and volumes." + gone)
        v2 = state["v"]
        if v2 is None:
            raise Done(OK, f"{name} was deleted during the migration")
        if v2["migstat"] == "success" or v2["host"].split("#")[-1] == target.split("#")[-1]:
            done = f"{name} is in {v2['host']} (migration took {minutes(d.clock() - started)})"
            if server:
                check_after(d, server, done, before=before, volume=(vid, device))
            raise Done(OK, done)
        last = f"migration_status {v2['migstat'] or 'cleared'}, still in {v2['host']}"
        d.say(f"The migration of {name} failed ({last})")
        copies = cleanup_replica(d, vid)
        if copies:   # a copy that could not be removed: no other attempt over it
            raise Done(ATTENTION, f"the migration of {name} failed ({last}) and a temporary copy is left: "
                                  f"{', '.join(copies)}. Follow it with Stuck instances and volumes." + gone)
        blocked = swap_blocked(d, v) if server else ""
        if blocked:   # another pool would fail the same way
            raise Done(FAILED, f"the migration of {name} failed: {blocked}. It stays in {v['host']}." + gone)
        why = cinder_messages(d, vid)
        if why:
            last += f": {why}"
        if n < min(len(targets), MAX_ATTEMPTS):
            d.say("Automatic fix: the temporary copy was cleaned up; " + (
                "the same pool is tried once more" if targets[n] == target else f"{targets[n]} is tried next"))
    raise Done(FAILED, f"{name} could not be migrated: {last}. It stays in {v['host']}." + gone)


def retype_volume(d, a):
    """The volume type of one volume (WIs "Volume Snapshot Error on the Backend", "VM Fails to Resize Root Disk", "Backup
    Scheduler Tidak Menjalankan Snapshot"), migration policy on-demand: checked again, its approved snapshots deleted
    first, cinder retype, followed until it is back to its status with the new type."""
    vid = a["id"]
    v = d.volume(vid, show=True)
    if v is None:
        raise Done(OK, "the volume no longer exists: nothing to do")
    if v.get("unknown"):
        raise Done(ATTENTION, f"the volume could not be read ({v['unknown']}): nothing was changed")
    name = v["name"]
    d.say(f"{name}: {v['status']}, type {v['type'] or '-'}, migration_status {v['migstat'] or '-'}")
    if v["type"] == a["to"]:
        raise Done(OK, f"{name} has the type {a['to']} already: nothing to do")
    if v["status"] not in ("available", "in-use"):
        raise Done(FAILED, f"{name} is {v['status']}: only available or in-use volumes are retyped; nothing was changed")
    if v["migstat"] in ("migrating", "starting", "completing") or v["migstat"].startswith("target:"):
        raise Done(FAILED, f"{name} has migration_status {v['migstat']}: a migration runs already; nothing was changed")
    if v["multiattach"] and len(v["attachments"]) > 1:
        raise Done(FAILED, f"{name} is attached to {len(v['attachments'])} instances: nothing was changed")
    blocked = swap_blocked(d, v)   # the retype moves it to the pools of the new type: Nova swaps it
    if blocked:
        raise Done(SKIPPED, f"the type of {name} was not changed, nothing was changed: {blocked}")
    if v["group"]:   # refused by Cinder: checked before any snapshot is deleted
        raise Done(FAILED, f"{name} belongs to a group ({v['group']}): it cannot be retyped with a migration; nothing was changed")
    if v["replication"] == "enabled":
        raise Done(FAILED, f"{name} is replicated: it cannot be retyped with a migration; nothing was changed")
    snaps = d.snapshots_of(vid)
    extra = [s for s in snaps if s["id"] not in a["snapshots"]]
    if extra:
        raise Done(FAILED, f"{name} has snapshot(s) that were not approved in the check ({', '.join(s['name'] or s['id'] for s in extra[:5])}): "
                           "a volume with snapshots cannot be retyped. Run the check again; nothing was changed")
    gone = ""   # said in every result after the snapshots were deleted: they are not "nothing changed"
    if snaps:
        if d.time_left() is not None and d.time_left() < 600:
            raise Done(FAILED, f"not enough time left for {name} in this fix: nothing was changed")
        d.say(f"{name} has {len(snaps)} approved snapshot(s): delete them first (a volume with snapshots cannot be retyped)")
        res = delete_snapshots(d, [s["id"] for s in snaps], name)
        done = f" {res['deleted']} of its {len(snaps)} approved snapshot(s) were deleted." if res["deleted"] else " None of its snapshots was deleted."
        if res["stuck"]:
            raise Done(ATTENTION, f"the type of {name} was not changed: {'; '.join(res['stuck'])}.{done}")
        if res["refused"]:
            raise Done(FAILED, f"the type of {name} was not changed: {'; '.join(res['refused'])}.{done}")
        gone = f" Its {len(snaps)} approved snapshot(s) were deleted."
    server, device = attached_to(v)
    before = before_change(d, server)["log"] if server else None
    started = d.clock()
    rc, out = d.run(["cinder", "retype", "--migration-policy", "on-demand", vid, a["to"]])
    if rc != 0:   # the API may have taken it all the same (a proxy timeout): the volume tells
        now = d.volume(vid)
        if now is None or now.get("unknown"):
            raise Done(ATTENTION, f"cinder retype failed ({last_error(out) or f'exit {rc}'}) and {name} could not be read "
                                  "again: look at it before running the fix again." + gone)
        if now["status"] != "retyping" and now["migstat"] not in ("migrating", "starting", "completing") and now["type"] != a["to"]:
            raise Done(FAILED, f"cinder retype was refused: {last_error(out) or f'exit {rc}'}. {name} keeps the type "
                               f"{v['type']}." + gone)
        d.say(f"cinder retype gave an error ({last_error(out)}), but {name} is being retyped: it is followed")
    state = {}
    d.say(f"Waiting for the retype of {name}: checked every 30 s, a line every {minutes(HEARTBEAT)}, for up to "
          f"{minutes(a['timeout'])}. A running retype cannot be stopped safely.")

    def ended():
        v2 = d.volume(vid)
        state["v"] = v2
        if v2 is None or v2.get("unknown"):
            return v2 is None
        if v2["status"] == "retyping" or v2["migstat"] in ("migrating", "starting", "completing"):
            heartbeat(d, state, started, f"{name}: still being retyped to {a['to']} after {minutes(d.clock() - started)} "
                                         f"(status {v2['status']}, migration_status {v2['migstat'] or '-'})")
            return False
        return v2["type"] == a["to"] or d.clock() - started > 60
    if not d.wait(ended, a["timeout"], 30):
        raise Done(ATTENTION, f"{name} is still being retyped after {minutes(d.clock() - started)} (status "
                              f"{(state.get('v') or {}).get('status')}, migration_status {(state.get('v') or {}).get('migstat')}): "
                              "a running retype cannot be stopped safely. Follow it with Stuck instances and volumes." + gone)
    v2 = state["v"]
    if v2 is None:
        raise Done(OK, f"{name} was deleted during the retype")
    if v2["type"] == a["to"] and v2["status"] in ("available", "in-use"):
        done = f"{name} has the type {a['to']} (took {minutes(d.clock() - started)})"
        if server:
            check_after(d, server, done, before=before, volume=(vid, device))
        raise Done(OK, done)
    d.say(f"The retype of {name} failed (status {v2['status']}, migration_status {v2['migstat'] or '-'}, type {v2['type']})")
    left = cleanup_replica(d, vid)
    why = cinder_messages(d, vid)
    copies = f" Temporary copy left (not removed): {', '.join(left)}." if left else ""
    if v2["status"] not in ("available", "in-use") or left:
        raise Done(ATTENTION, f"the retype of {name} failed and the volume is {v2['status']}" + (f": {why}" if why else "")
                              + ". Follow it with Stuck instances and volumes (WI Rollback Volume Type)." + copies + gone)
    raise Done(FAILED, f"the retype of {name} failed" + (f": {why}" if why else "") + f"; it keeps the type "
                       f"{v2['type'] or v['type']}." + gone)


SWAPPABLE = ("ACTIVE", "PAUSED", "VERIFY_RESIZE")   # Nova swaps an attached volume only then, without a task (else HTTP 409)


def swap_blocked(d, v):
    """Why Nova would refuse to swap this attached volume to its new pool (a migration, or a retype that moves it), ''
    when it would not, or when the volume is not attached or its instance cannot be read (the change itself then tells).
    Checked before any snapshot is deleted. Seen 2026-10-27 on DCA: the boot volume of a SHUTOFF instance, three pools
    tried, each time Cinder made a copy and Nova answered "Cannot 'swap_volume' instance ... in vm_state stopped" (409)."""
    sid, device = attached_to(v)
    if not sid:
        return ""
    s = d.server(sid)
    if s is None:
        return (f"it is attached to the instance {sid}, which Nova does not know (a stale attachment): Nova cannot swap "
                "it. Clear the attachment first (Stuck instances and volumes)")
    if s.get("unknown"):
        d.say(f"Its instance {sid} could not be read ({s['unknown']}): the change is tried, Cinder tells")
        return ""
    if s["status"] in SWAPPABLE and not s["task"]:
        return ""
    state = s["status"] + (f" with the task {s['task']}" if s["task"] else "")
    if s["status"] == "SHUTOFF" and not s["task"]:
        how = (f"with the customer's agreement start {s['name']}, run the fix again for this volume, then stop it again"
               + ("" if v.get("bootable") else "; or, while it is off, detach the volume, migrate it while available and "
                  "attach it again (check its device name after)"))
    else:
        how = f"run the fix again when {s['name']} is ACTIVE without a task"
    return (f"it is attached as {device or '?'} to {s['name']} ({sid}), which is {state}. Nova swaps an attached volume to "
            f"its new pool only while the instance is ACTIVE, PAUSED or VERIFY_RESIZE without a task; otherwise it refuses "
            f"(HTTP 409) and the migration fails. To move it: {how}")


def attached_to(v):
    """(server ID, device) of the instance a volume is attached to, ("", "") when it is not attached."""
    for x in v.get("attachments") or []:
        if isinstance(x, dict) and x.get("server_id"):
            return str(x["server_id"]), str(x.get("device") or "")
    return "", ""


def cleanup_replica(d, vid):
    """The temporary copy a failed migration leaves (migration_status target:<volume>): reset and delete (WI Rollback
    Volume Type), only when it is not attached."""
    rc, out = d.run(["cinder", "list", "--all-tenants", "--fields", "id,name,status,os-vol-mig-status-attr:migstat"],
                    show=True, lines=0)
    rows = table(out)[0] if rc == 0 else []
    left = []   # copies found but not removed: the caller says so
    for r in rows:
        mig = str(r.get("os-vol-mig-status-attr:migstat") or r.get("migstat") or "").lower()
        rid = str(r.get("id") or "")
        if mig != f"target:{vid}" or not UUID_RE.match(rid):
            continue
        rep = d.volume(rid)
        if rep is None:
            continue
        # only a copy that was read, is attached nowhere and is not being worked on by Cinder itself
        if rep.get("unknown") or rep.get("attachments") or rep.get("status") not in ("available", "error", "error_deleting"):
            d.say(f"The temporary copy {rid} is " + ("not readable" if rep.get("unknown") else "attached" if rep.get("attachments")
                                                    else str(rep.get("status"))) + ": not touched")
            left.append(rid)
            continue
        d.say(f"Automatic fix: remove the temporary copy {rid} of the failed migration (WI Rollback Volume Type)")
        d.run(["cinder", "reset-state", "--state", "available", "--attach-status", "detached", "--reset-migration-status", rid])
        d.run(["cinder", "delete", rid])
        if not d.wait(lambda: d.volume(rid) is None, 600, 15):
            left.append(rid)
    return left


def cinder_messages(d, vid):
    """The last user message Cinder kept for the volume (API 3.3), '' when none. The API filters by resource only from a
    later microversion (seen 2026-10-27: --resource_uuid at 3.3 also lists the messages of other volumes), so the rows
    are filtered here by their Resource UUID."""
    rc, out = d.run(["cinder", "--os-volume-api-version", "3.3", "message-list", "--resource_uuid", vid], show=True, lines=4)
    rows = table(out)[0] if rc == 0 else []
    rows = [r for r in rows if r.get("resource_uuid", vid) == vid]
    texts = [str(r.get("user_message") or r.get("message") or "") for r in rows if r.get("user_message") or r.get("message")]
    return texts[-1][:300] if texts else ""


# ---------------------------------------------------------------- image housekeeping (Glance)
def delete_volume_snapshots(d, a):
    """The snapshots of one volume its PIC approved, deleted (check "Cinder volume over 80%", Delete these snapshots): each
    one read first and deleted only when Cinder can (delete_snapshots: one being deleted already is waited for, one in
    error_deleting reset, a busy one waited for, one of a group snapshot never), then waited for until gone. A real case: a plain "openstack volume snapshot delete" of a snapshot still deleting from an earlier fix failed with
    "Snapshot status must be available or error and must not be part of a group". A snapshot of another volume is refused;
    one already gone counts as done."""
    vid, ids = a["id"], a["snapshots"]
    if not ids:
        raise Done(OK, "no snapshot to delete")
    other = []
    for sid in ids:
        x = d.snapshot(sid)
        if x and x.get("volume") and x["volume"] != vid:
            other.append(f"{sid} (of volume {x['volume']})")
    if other:
        raise Done(FAILED, f"snapshot(s) {', '.join(other)} are not of volume {vid}: nothing was deleted")
    res = delete_snapshots(d, ids, f"volume {vid}")
    deleted, refused, stuck = res["deleted"], res["refused"], res["stuck"]
    if stuck:
        raise Done(ATTENTION, f"{deleted} snapshot(s) deleted, but " + "; ".join(stuck))
    if refused:
        raise Done(ATTENTION if deleted else FAILED,
                   (f"{deleted} snapshot(s) deleted, the others not: " if deleted else "nothing was deleted: ") + "; ".join(refused))
    raise Done(OK, f"the {len(ids)} snapshot(s) of volume {vid} are gone ({deleted} deleted or waited for now"
                   + (f", {len(ids) - deleted} gone already" if len(ids) > deleted else "") + ")")


def delete_image(d, a):
    iid = a["id"]
    img, rc, out = d.read(["openstack", "image", "show", iid], show=True)
    if rc != 0 or not isinstance(img, dict):
        if gone(out, "image"):
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
    res = delete_snapshots(d, todo, f"image {name}") if todo else {"deleted": 0, "refused": [], "stuck": []}
    note = (f"; {len(gone)} snapshot(s) were already gone" if gone else "") + \
           (f"; not deleted (busy): {', '.join(bad)}" if bad else "") + \
           (f"; not deleted: {'; '.join(res['refused'])}" if res["refused"] else "")
    if res["stuck"]:
        raise Done(ATTENTION, f"image {name} deleted, but {'; '.join(res['stuck'])}{note}")
    raise Done(OK if not bad and not res["refused"] else FAILED, f"image {name} and {res['deleted']} volume snapshot(s) deleted{note}")


def clear_fdb(d, a):
    """One OVN FDB entry (WI "FDB Learning Issue", stage 8), on the node through the director: read again, destroyed only
    when it is still the entry the check saw, read once more."""
    uid, node, user = a["id"], a["node"], a["user"]
    if user not in USERS:
        raise Done(ATTENTION, "no overcloud user (heat-admin / tripleo-admin): nothing was changed")
    sb = OVN_SB

    def read():
        rc, out = d.run(SSH + [f"{user}@{node['ip']}", f"{sb} --no-leader-only --format=json --columns=mac,dp_key,port_key list fdb {uid}"],
                        show=False, timeout=60)
        if rc != 0:
            if re.search(r"no row|not found|does not exist", out or "", re.I):
                return None
            raise Done(ATTENTION, f"the FDB entry could not be read on {node['host']} ({first_line(out)}): nothing was changed")
        try:
            doc = json.loads(out)
            row = dict(zip(doc.get("headings") or [], (doc.get("data") or [[]])[0]))
        except (ValueError, IndexError, TypeError):
            raise Done(ATTENTION, f"unexpected answer of ovn-sbctl ({first_line(out)}): nothing was changed")
        return row or None

    d.say(f"$ ssh {user}@{node['ip']} {sb} --no-leader-only list fdb {uid}")
    row = read()
    if row is None:
        raise Done(OK, f"the FDB entry {a['mac']} is already gone (relearned or cleared): nothing to do")
    now = (str(row.get("mac") or "").lower(), str(row.get("dp_key")), str(row.get("port_key")))
    if now != (a["mac"], str(a["dp"]), str(a["port"])):
        raise Done(FAILED, f"the entry is now MAC {now[0]} on datapath {now[1]} port {now[2]}, not what the check saw: nothing was changed")
    d.say(f"$ ssh {user}@{node['ip']} {sb} destroy fdb {uid}")
    rc, out = d.run(SSH + [f"{user}@{node['ip']}", f"{sb} destroy fdb {uid}"], show=False, timeout=60)
    if rc != 0:
        raise Done(FAILED, f"ovn-sbctl destroy failed: {last_error(out)}")
    if read() is not None:
        raise Done(ATTENTION, f"the FDB entry {a['mac']} is still there after the destroy")
    raise Done(OK, f"FDB entry {a['mac']} (port key {a['port']}) removed from datapath {a['dp']}")


ALLOW_ALL = "port-security-allow-all"
OVN_SB = "sudo -n podman exec ovn_controller ovn-sbctl"   # as the checks read it (overcloud.py)
ALLOW_ALL_RULES = [(direction, eth, prefix) for direction in ("ingress", "egress")
                   for eth, prefix in (("IPv4", "0.0.0.0/0"), ("IPv6", "::/0"))]


def _group_ids(value):
    """A list of IDs as the clients print it: a JSON list, or "a, b" / "['a', 'b']" text."""
    if isinstance(value, list):
        return [str(x.get("id") if isinstance(x, dict) else x) for x in value]
    return re.findall(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", str(value or ""))


def _pairs(value):
    """The IP addresses of allowed_address_pairs (a list of {"ip_address", "mac_address"}, or text)."""
    if isinstance(value, list):
        return [str(x.get("ip_address")) for x in value if isinstance(x, dict) and x.get("ip_address")]
    return re.findall(r"ip_address='([^']+)'", str(value or ""))


def _same_address(a, b):
    try:
        return ipaddress.ip_network(a, strict=False) == ipaddress.ip_network(b, strict=False)
    except ValueError:
        return a == b


def binding_macs(text):
    """The mac column of `ovn-sbctl --format=json --columns=mac find port_binding ...` (one row): a list of strings,
    None when there is no row or the answer is not JSON."""
    try:
        rows = json.loads(text or "").get("data") or []
    except (ValueError, AttributeError):
        return None
    if not rows or not isinstance(rows[0], list) or not rows[0]:
        return None
    cell = rows[0][0]
    if isinstance(cell, list) and len(cell) == 2 and cell[0] == "set":
        return [str(x) for x in cell[1]]
    return [str(cell)] if cell not in (None, "") else []


def allow_all_group(d, project):
    """The ID of the security group port-security-allow-all of the project, made when missing, with its four rules (all
    protocols in and out, IPv4 and IPv6; a rule that exists already is fine)."""
    groups, rc, out = d.read(["openstack", "security", "group", "list", "--project", project], show=True)
    if rc != 0 or not isinstance(groups, list):
        raise Done(ATTENTION, f"the security groups of the project could not be read ({first_line(out)}): nothing was changed")
    found = [g for g in groups if isinstance(g, dict) and str(field(g, "Name", "name")) == ALLOW_ALL]
    if found:
        sg = str(field(found[0], "ID", "id"))
        d.say(f"Security group {ALLOW_ALL} exists already ({sg}).")
    else:
        made, rc, out = d.read(["openstack", "security", "group", "create", ALLOW_ALL, "--project", project, "--description",
                                "All traffic in and out: port security on (MAC/IP anti-spoofing) without filtering. "
                                "Operation Automation, WI FDB Learning Issue"], show=True)
        if rc != 0 or not isinstance(made, dict):
            raise Done(ATTENTION, f"the security group could not be made ({last_error(out)}): nothing was changed")
        sg = str(field(made, "id", "ID"))
    if not UUID_RE.match(sg):
        raise Done(ATTENTION, f"unexpected security group ID {sg!r}: nothing was changed")
    for direction, eth, prefix in ALLOW_ALL_RULES:
        cmd = ["openstack", "security", "group", "rule", "create", f"--{direction}", "--ethertype", eth, "--protocol", "any",
               "--remote-ip", prefix, sg]
        rc, out = d.run(cmd, show=False)
        # only a duplicate is fine; a 409 for the quota ("Quota exceeded") is not: the group would block all traffic in
        exists = rc != 0 and re.search(r"already exists|SecurityGroupRuleExists", out or "", re.I)
        d.say("$ " + " ".join(cmd) + ("   (exists already)" if exists else ""))
        if rc != 0 and not exists:
            raise Done(ATTENTION, f"the rule {direction} {eth} of {ALLOW_ALL} could not be made ({last_error(out)}): "
                                  "the port was not changed")
    return sg


def port_security(d, a):
    """Port security on for one port of an instance (WI "FDB Learning Issue", stage 9), with the security group
    port-security-allow-all and the allowed addresses (VIPs) given in the check; checked again before and after, then the
    address "unknown" of its OVN port binding is gone and the FDB entries recorded on it are cleared."""
    pid = a["id"]
    port, rc, out = d.read(["openstack", "port", "show", pid], show=True)
    if rc != 0 or not isinstance(port, dict):
        if gone(out, "port"):
            raise Done(FAILED, "the port does not exist any more: nothing was changed")
        raise Done(ATTENTION, f"the port could not be read ({first_line(out)}): nothing was changed")
    project = str(field(port, "project_id", "tenant_id"))
    if project != a["project"]:
        raise Done(FAILED, f"the port belongs to project {project or '-'} now, not {a['project']}: nothing was changed")
    enabled = str(field(port, "port_security_enabled")).lower() in ("true", "1")
    have = _pairs(field(port, "allowed_address_pairs"))
    missing = [x for x in a["allow"] if not any(_same_address(x, h) for h in have)]
    node, user = a["node"], a["user"]
    if user not in USERS:
        raise Done(ATTENTION, "no overcloud user (heat-admin / tripleo-admin) to check OVN: nothing was changed")
    ssh = SSH + [f"{user}@{node['ip']}"]

    def binding():
        rc, out = d.run(ssh + [f"{OVN_SB} --no-leader-only --format=json --columns=mac find port_binding logical_port={pid}"],
                        show=False, timeout=60)
        return rc, out, (binding_macs(out) if rc == 0 else None)
    # OVN must answer before anything changes: without it the port could not be checked nor its FDB cleared afterwards
    d.say(f"$ ssh {user}@{node['ip']} {OVN_SB} --no-leader-only find port_binding logical_port={pid}")
    rc, out, macs = binding()
    if rc != 0:
        raise Done(ATTENTION, f"the OVN port binding cannot be read on {node['host']} ({last_error(out)}): nothing was changed")
    if macs is None:
        raise Done(ATTENTION, f"no OVN port binding of the port on {node['host']}: nothing was changed")
    d.say(f"  mac: {', '.join(macs) or '-'}")
    sg = allow_all_group(d, a["project"])
    if enabled and not missing:
        d.say("Port security is on already, with every allowed address.")
    else:
        cmd = ["openstack", "port", "set"] + ([] if enabled else ["--enable-port-security", "--security-group", sg])
        for x in missing:
            cmd += ["--allowed-address", f"ip-address={x}"]
        rc, out = d.run(cmd + [pid])
        if rc != 0:   # the API may have done it all the same (a proxy timeout): the port tells
            now, rc2, _o = d.read(["openstack", "port", "show", pid], show=True)
            if rc2 != 0 or not isinstance(now, dict):
                raise Done(ATTENTION, f"openstack port set failed ({last_error(out)}) and the port could not be read again: "
                                      "look at it before running the fix again")
            if (str(field(now, "port_security_enabled")).lower() in ("true", "1")) == enabled:
                raise Done(FAILED, f"openstack port set failed ({last_error(out)}): the port is as it was")
            d.say(f"openstack port set gave an error ({last_error(out)}), but port security changed: the result is checked")
    port, rc, out = d.read(["openstack", "port", "show", pid], show=True)
    if rc != 0 or not isinstance(port, dict):
        raise Done(ATTENTION, f"the port could not be read after the change ({first_line(out)})")
    on = str(field(port, "port_security_enabled")).lower() in ("true", "1")
    groups = _group_ids(field(port, "security_group_ids", "security_groups"))
    pairs = _pairs(field(port, "allowed_address_pairs"))
    lost = [x for x in a["allow"] if not any(_same_address(x, h) for h in pairs)]
    if not on or (not enabled and sg not in groups) or lost:
        raise Done(ATTENTION, "the port is not as expected after the change: port security "
                              f"{'on' if on else 'off'}, security groups {', '.join(groups) or '-'}, allowed addresses "
                              f"{', '.join(pairs) or '-'}" + (f" (missing {', '.join(lost)})" if lost else ""))
    d.say(f"Port security on, security group{'s' if len(groups) != 1 else ''} {', '.join(groups)}, allowed addresses "
          f"{', '.join(pairs) or '-'}.")
    macs, rc, out = None, 1, ""
    for _ in range(10):   # ovn-northd writes the new addresses of the port binding within seconds
        rc, out, macs = binding()
        if macs is not None and "unknown" not in macs:
            break
        d.sleep(3)
    d.say(f"$ ssh {user}@{node['ip']} {OVN_SB} --no-leader-only find port_binding logical_port={pid}")
    if rc != 0:
        raise Done(ATTENTION, f"port security is on; the OVN port binding could not be read on {node['host']} "
                              f"({last_error(out)}): run the fix again for this port to check OVN and clear its FDB")
    if macs is None:
        raise Done(ATTENTION, f"port security is on; no OVN port binding of the port on {node['host']} "
                              f"({first_line(out) or 'no row'})")
    d.say(f"  mac: {', '.join(macs) or '-'}")
    if "unknown" in macs:
        raise Done(ATTENTION, "port security is on, but the OVN port binding still has the address \"unknown\" after 30 s "
                              f"(mac: {', '.join(macs)}): Neutron did not update OVN; compare the Logical_Switch_Port in the "
                              f"OVN NB (ovn-nbctl lsp-get-addresses {pid}, on a controller) before clearing the FDB")
    d.say("  the address \"unknown\" is gone: OVN no longer learns MAC addresses on this port")
    cleared = 0
    if a["dp"] and a["pkey"]:
        rc, out = d.run(ssh + [f"{OVN_SB} --no-leader-only --bare --columns=_uuid find fdb dp_key={a['dp']} port_key={a['pkey']}"],
                        show=False, timeout=60)
        d.say(f"$ ssh {user}@{node['ip']} {OVN_SB} --no-leader-only find fdb dp_key={a['dp']} port_key={a['pkey']}")
        if rc != 0:
            raise Done(ATTENTION, f"port security is on; the FDB of the port could not be read ({last_error(out)}): run the "
                                  "fix again for this port to clear it")
        for uid in [x for x in (out or "").split() if UUID_RE.match(x)]:
            rc2, out2 = d.run(ssh + [f"{OVN_SB} destroy fdb {uid}"], show=False, timeout=60)
            if rc2 != 0:
                raise Done(ATTENTION, f"port security is on; the FDB entry {uid} could not be cleared ({last_error(out2)})")
            cleared += 1
        d.say(f"  {cleared} FDB entr{'y' if cleared == 1 else 'ies'} recorded on the port cleared")
    raise Done(OK, f"port security on (security group {ALLOW_ALL}"
                   + (f", allowed addresses {', '.join(a['allow'])}" if a["allow"] else "")
                   + f"); the address \"unknown\" is gone; {cleared} FDB entr{'y' if cleared == 1 else 'ies'} cleared")


# ---------------------------------------------------------------- certmonger (TLS everywhere)
GETCERT_WAIT, GETCERT_POLL = 300, 10   # seconds for certmonger to get the new certificate from IdM, and between reads
GETCERT_BAD = ("CA_UNREACHABLE", "CA_REJECTED", "NEED_GUIDANCE", "CA_UNCONFIGURED", "NEED_CA")


def getcert_request(text, rid):
    """The fields of request rid in `getcert list -i <rid>`: {"status", "stuck", "expires", "ca-error", "certificate", "CA"}
    ({} when the output does not list it)."""
    out, inside = {}, False
    for line in str(text or "").splitlines():
        m = re.match(r"^Request ID '([^']*)':", line)
        if m:
            inside = m.group(1) == rid
            continue
        m = re.match(r"^\s+(status|stuck|ca-error|issued|expires|certificate|CA):\s?(.*)$", line)
        if inside and m:
            out[m.group(1)] = m.group(2).strip()
    return out


def getcert_resubmit(d, a):
    """One certmonger request on an overcloud node (through the director): read again, resubmitted to its CA, followed
    until certmonger monitors a new certificate."""
    rid, node, user = a["id"], a["node"], a["user"]
    if user not in USERS:
        raise Done(ATTENTION, "no overcloud user (heat-admin / tripleo-admin): nothing was changed")
    login = f"{user}@{node['ip']}"

    def read(changed=True):
        rc, out = d.run(SSH + [login, f"sudo -n getcert list -i {rid}"], show=False, timeout=60)
        if rc != 0 and not re.search(r"no request", out or "", re.I):
            # before the resubmit nothing was changed (the next item may run); after it, a person must look
            raise Done(ATTENTION if changed else FAILED, f"certmonger could not be read on {node['host']} ({first_line(out)})"
                       + ("" if changed else ": nothing was changed"))
        return getcert_request(out, rid) if rc == 0 else {}

    d.say(f"$ ssh {login} sudo getcert list -i {rid}")
    before = read(changed=False)
    if not before:
        raise Done(FAILED, f"certmonger on {node['host']} no longer tracks request {rid}: nothing was changed")
    where = re.search(r"location='([^']*)'", before.get("certificate", ""))
    d.say(f"  certificate {where.group(1) if where else before.get('certificate') or '?'}")
    d.say(f"  status {before.get('status') or '?'}, expires {before.get('expires') or '?'}"
          + (f", ca-error: {before['ca-error'][:200]}" if before.get("ca-error") else ""))
    d.say(f"$ ssh {login} sudo getcert resubmit -i {rid}")
    rc, out = d.run(SSH + [login, f"sudo -n getcert resubmit -i {rid}"], show=False, timeout=120)
    if out:
        d.say("  " + first_line(out))
    if rc in (124, 255):   # no answer: the resubmit may have reached certmonger all the same
        raise Done(ATTENTION, f"getcert resubmit did not answer on {node['host']} ({first_line(out)}): read the request "
                              f"there before running it again (sudo getcert list -i {rid})")
    if rc != 0:
        raise Done(FAILED, f"getcert resubmit failed on {node['host']}: {last_error(out)} (nothing was changed)")
    end, seen = d.clock() + GETCERT_WAIT, before.get("status")
    while True:
        d.sleep(GETCERT_POLL)
        now = read()
        if not now:
            raise Done(ATTENTION, f"request {rid} is no longer listed on {node['host']} after the resubmit")
        status = str(now.get("status") or "").upper()
        if status != seen:
            d.say(f"  status {status}")
            seen = status
        # a new certificate: a new expiry, or a new issue date (a CA that caps the expiry at its own gives the same one)
        if status == "MONITORING" and (now.get("expires") != before.get("expires") or now.get("issued") != before.get("issued")):
            raise Done(OK, f"request {rid} on {node['host']} renewed: expires {now.get('expires')} (was {before.get('expires')}); "
                           "the post-save command of the request reloads the service that uses it")
        if status in GETCERT_BAD or now.get("stuck") == "yes":
            raise Done(FAILED, f"certmonger could not renew request {rid} on {node['host']}: {status}"
                               + (" (stuck)" if now.get("stuck") == "yes" else "")
                               + (f", {now['ca-error'][:200]}" if now.get("ca-error") else "")
                               + ". The certificate it has stays in place: check that the node reaches IdM and its host keytab "
                                 "(kinit -k), then run it again")
        if d.clock() >= end:
            raise Done(FAILED, f"no new certificate for request {rid} on {node['host']} after {minutes(GETCERT_WAIT)} "
                               f"(status {status}, expires {now.get('expires')}): certmonger keeps trying, read it again later")


def rescan_lost(d, a):
    """rescan-luns: the paths of one disk of a running VM that lost all of them (check compute-disks). Its map is read
    again; only the SCSI addresses the kernel removed (and only where no device is now) are scanned; a new device is
    kept only with a WWID of keep (this map's, or another map of the compute that lost its paths), deleted otherwise."""
    wwid, node, user = a["id"], a["node"], a["user"]
    if user not in USERS:
        raise Done(ATTENTION, "no overcloud user (heat-admin / tripleo-admin): nothing was changed")
    ip, host = node["ip"], node["host"]
    seen = d.disk_paths(ip, user, d.clock())
    if seen.get("unknown"):
        raise Done(FAILED, f"the multipath maps of {host} could not be read ({seen['unknown']}): nothing was changed")
    dm = next((x for x, m in seen["maps"].items() if m["wwid"] == wwid), None)
    if not dm:
        raise Done(FAILED, f"{host} has no multipath map {wwid} (any more): nothing was changed")
    users = ", ".join(f"{n} ({u or '?'})" for n, u in seen["users"].get(dm, [])) or "no running domain"
    m = seen["maps"][dm]
    if m["paths"] > 0 and "##" not in m["vendor"]:
        raise Done(OK, f"{dm} ({wwid}) on {host} has {m['paths']} path(s) already (used by {users}): nothing to do")
    d.say(f"{dm} ({wwid}) on {host} has no path; used by {users}")
    for addr, sd, w, kept in d.rescan_luns(ip, user, a["addrs"], list(dict.fromkeys([wwid] + a["keep"]))):
        d.say(f"Automatic fix: {addr} came back as {sd} (WWID {w}): "
              + ("kept" + (", the disk of this map" if w == wwid else ", the disk of another map that lost its paths")
                 if kept else "not a disk that lost its paths, deleted again"))
    again = d.disk_paths(ip, user, d.clock(), show=False)
    m2 = next((x for x in (again.get("maps") or {}).values() if x["wwid"] == wwid), None)
    if m2 and m2["paths"] > 0 and "##" not in m2["vendor"]:
        raise Done(OK, f"{dm} ({wwid}) on {host} has {m2['paths']} path(s) again. The guest of {users} may still have I/O "
                       "errors or a read-only / shut-down filesystem: its owner checks it; reboot it only after the check "
                       "\"Volume connections of an instance\" is clean for it")
    raise Done(ATTENTION, f"{dm} ({wwid}) on {host} still has no path after the scan of "
                          f"{', '.join(':'.join(str(v) for v in x) for x in a['addrs'])}: its LUN is at another SCSI address, or "
                          "no longer mapped to this compute. Rescan it by hand (lun-rescan with its target and LUN from the "
                          "volume's connection info) and check the LUN mapping in ONTAP")


def move_leftover(d, a):
    """move-leftover: a directory of an instance on a compute with no domain of it (check compute-disks), renamed aside
    (never deleted) after Nova and the directory are read again."""
    sid, node, user = a["id"], a["node"], a["user"]
    if user not in USERS:
        raise Done(ATTENTION, "no overcloud user (heat-admin / tripleo-admin): nothing was moved")
    ip, host = node["ip"], node["host"]
    s = d.server(sid, show=True)
    if s is not None and s.get("unknown"):
        raise Done(FAILED, f"the instance could not be read ({s['unknown']}): nothing was moved")
    name = (s or {}).get("name") or sid
    if s is not None and short(s["host"]) == short(host):
        raise Done(ATTENTION, f"Nova has {name} on {host} itself ({s['status']}), without a domain there: nothing was "
                              "moved; check that instance (Volume connections of an instance) before anything else")
    if s is not None and (s["task"] or s["status"] in ("MIGRATING", "RESIZE", "VERIFY_RESIZE")):
        raise Done(FAILED, f"{name} is {s['status']}" + (f" (task {s['task']})" if s["task"] else "")
                   + ": a migration of it may use this directory now; nothing was moved")
    found = d.instance_dir(ip, user, sid)
    path = f"/var/lib/nova/instances/{sid}"
    if found.get("unknown"):
        raise Done(FAILED, f"{path} on {host} could not be read ({found['unknown']}): nothing was moved")
    if not found["exists"]:
        raise Done(OK, f"{path} is no longer on {host}: nothing to do")
    if found["domain"] != "no":
        raise Done(FAILED, f"a domain of {name} is defined on {host} ({found['domain']}): {path} is in use; nothing was moved")
    if not found["fstype"] or found["fstype"] in SHARED_FS:
        raise Done(FAILED, f"the instances path of {host} is {found['fstype'] or 'of an unknown filesystem'} (shared between "
                           f"the computes: the directory may be the live one of {name}); nothing was moved")
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(d.clock()))
    rc, out = d.move_aside(ip, user, sid, stamp)
    if rc != 0:
        raise Done(FAILED, f"{path} on {host} could not be renamed ({first_line(out) or f'exit {rc}'}): nothing was moved")
    raise Done(OK, f"{path} on {host} (changed {found['changed']}; {'deleted instance' if s is None else name + ' is on ' + (s['host'] or '-')}) "
                   f"renamed to {path}.leftover-{stamp} (not deleted): a live migration of it to {host} is no longer refused "
                   "(DestinationDiskExists)")


def release_lv(d, a):
    """release-lv: one LV of a guest that a compute activated on a Cinder volume (check host-lvm). Read again and checked
    on the compute (opened 0 times, held by nothing, no disk of a running domain, only on iSCSI paths / their partitions /
    multipath maps / removed devices), removed from the host (dmsetup remove: nothing is written to the volume), each
    freed path given back to the map of its WWID."""
    uuid, node, user = a["id"], a["node"], a["user"]
    if user not in USERS:
        raise Done(ATTENTION, "no overcloud user (heat-admin / tripleo-admin): nothing was changed")
    ip, host = node["ip"], node["host"]
    res = d.release_lv(ip, user, uuid)
    if res["state"] == "gone":
        raise Done(OK, f"the LV {uuid} is no longer active on {host}: nothing to do")
    if res["state"] == "refused":
        raise Done(FAILED, f"{res['lv']} on {host} was not released: {res['why']}. Nothing was changed")
    if res["state"] == "failed":
        raise Done(ATTENTION, f"{res['lv']} on {host} could not be released ({res['why']}): check it on the compute")
    for p, t, n in res["added"]:
        d.say(f"Automatic fix: path {p} given back to its map {t} ({n} path(s) now)")
    raise Done(OK, f"{res['lv']} released on {host} (only the host's mapping, the volume is not written)"
                   + (f"; {', '.join(p for p, _w in res['left'])} has no multipath map here: a disk on one SCSI path stays so "
                      "until its instance moves to a compute whose LVM filter keeps guest volumes off" if res["left"] else ""))


def rescan_disk(d, a):
    """rescan-disk: a disk of a running instance whose multipath map has no path (check host-lvm), the removal of its
    devices may be older than the kernel log. The map read again; Nova's target and LUN of that disk read on a controller;
    only that LUN on the sessions of that target is scanned, and only where no device is now (a device there is never
    touched: Nova's LUN may be stale); a new device is kept only with the WWID of the map, deleted again otherwise."""
    sid, wwid, node, user = a["id"], a["wwid"], a["node"], a["user"]
    if user not in USERS:
        raise Done(ATTENTION, "no overcloud user (heat-admin / tripleo-admin): nothing was changed")
    ip, host = node["ip"], node["host"]
    seen = d.host_lvs(ip, user, f"the map {wwid} and the disks of {sid}")
    if seen.get("unknown"):
        raise Done(FAILED, f"the maps and domains of {host} could not be read ({seen['unknown']}): nothing was changed")
    dm = next((x for x, m in seen["maps"].items() if m["wwid"] == wwid), None)
    if not dm:
        raise Done(FAILED, f"{host} has no multipath map {wwid} (any more): nothing was changed")
    doms = [dom for dom, uuid in seen["domains"].items() if uuid == sid]
    targets = [t for dom, t in seen["disks"].get(dm, []) if dom in doms]
    if not targets:
        raise Done(FAILED, f"{dm} ({wwid}) on {host} is not a disk of the running instance {sid}: nothing was changed")
    m = seen["maps"][dm]
    if m["running"]:
        raise Done(OK, f"{dm} ({wwid}) on {host} has {m['running']} path(s) already ({targets[0]} of {doms[0]}): nothing to do")
    if m["total"]:
        raise Done(ATTENTION, f"{dm} ({wwid}) on {host} has {m['total']} path device(s), none running: a session or storage "
                              "problem, not removed devices; nothing was scanned. Check the iSCSI sessions and the LUN in ONTAP")
    rows = d.bdm_rows(sid)
    if rows is None:
        raise Done(FAILED, f"Nova's connection of the volumes of {sid} could not be read on a controller: nothing was changed")
    row = next((r for r in rows if r[0].rsplit("/", 1)[-1] == targets[0]), None)
    if not row or not IQN_RE.match(row[2]) or not row[3].isdigit():
        raise Done(FAILED, f"Nova has no iSCSI target and LUN for {targets[0]} of {sid}: nothing was changed. Check \"Volume "
                           "connections of an instance\"")
    _dev, vol, iqn, lun = row
    hosts = d.session_hosts(ip, user, iqn)
    if not hosts:
        raise Done(FAILED, f"{host} has no iSCSI session to {iqn}: nothing was changed")
    d.say(f"{dm} ({wwid}) on {host} has no path: {targets[0]} of {doms[0]}, volume {vol}, Nova's LUN {lun} of {iqn}")
    for addr, sd, w, kept in d.rescan_luns(ip, user, [(h, 0, 0, int(lun)) for h in hosts], [wwid]):
        d.say(f"Automatic fix: {addr} came back as {sd} (WWID {w}): "
              + ("kept, the disk of this map" if kept else "not this disk, deleted again"))
    again = d.host_lvs(ip, user, "the map again")
    m2 = next((x for x in (again.get("maps") or {}).values() if x["wwid"] == wwid), None)
    if m2 and m2["running"]:
        raise Done(OK, f"{dm} ({wwid}) on {host} has {m2['running']} path(s) again ({targets[0]} of {doms[0]}). The guest may "
                       "still have I/O errors or a read-only / shut-down filesystem: its owner checks it")
    raise Done(ATTENTION, f"{dm} ({wwid}) on {host} still has no path after the scan of LUN {lun} on {len(hosts)} session(s) of "
                          f"{iqn}: Nova's LUN may be stale, or the LUN is no longer mapped to this compute. Check \"Volume "
                          f"connections of an instance\" for {sid} and the LUN mapping in ONTAP")


def flush_map(d, a):
    """flush-map: one multipath map of a compute left without any running path, opened by nothing and no disk of a
    running domain (check host-lvm: e.g. under a guest LV that was released): read again and checked, then multipath -f."""
    wwid, node, user = a["id"], a["node"], a["user"]
    if user not in USERS:
        raise Done(ATTENTION, "no overcloud user (heat-admin / tripleo-admin): nothing was changed")
    ip, host = node["ip"], node["host"]
    res = d.flush_map(ip, user, wwid)
    if res["state"] == "gone":
        raise Done(OK, f"{host} has no map {wwid} (any more): nothing to do")
    if res["state"] == "refused":
        raise Done(FAILED, f"the map {res['map']} ({wwid}) on {host} was not flushed: {res['why']}. Nothing was changed")
    if res["state"] == "failed":
        raise Done(ATTENTION, f"the map {res['map']} ({wwid}) on {host} could not be flushed ({res['why'] or 'still there'})")
    raise Done(OK, f"the leftover map {res['map']} ({wwid}) flushed on {host}" + (f" ({res['how']})" if res.get("how") else ""))


def delete_path(d, a):
    """delete-path: one iSCSI path device a compute keeps in no multipath map, no LV and no disk of a domain (check
    host-lvm: left by a disconnect that did not finish; a later connection at its address takes it instead of a new
    device). Read again and checked, deleted only when it does not answer a read."""
    dev, node, user = a["id"], a["node"], a["user"]
    if user not in USERS:
        raise Done(ATTENTION, "no overcloud user (heat-admin / tripleo-admin): nothing was changed")
    ip, host = node["ip"], node["host"]
    res = d.delete_path(ip, user, dev, a["addr"], a["wwid"])
    if res["state"] == "gone":
        raise Done(OK, f"{host} has no {dev} at {a['addr']} (any more{': ' + res['why'] if res['why'] else ''}): nothing to do")
    if res["state"] == "refused":
        raise Done(FAILED, f"{dev} ({a['addr']}) on {host} was not deleted: {res['why']}. Nothing was changed")
    if res["state"] == "failed":
        raise Done(ATTENTION, f"{dev} ({a['addr']}) on {host} could not be deleted ({res['why'] or 'still there'})")
    raise Done(OK, f"the dead path device {dev} ({a['addr']}, read: {res['read'] or '?'}) deleted on {host}")


CONSOLE_SETTLE = 3      # seconds between a screenshot and the next one (the guest draws its answer)
CONSOLE_ANSWERS = 400   # pixels: a new line of text at least (a blinking cursor is 16 to 144 pixels)


def console_test(d, a):
    """Does the console of an instance take a key? Pressed from the screenshots of an item (the operator looked at the
    console first): two screenshots 3 s apart (what changes by itself: a blinking cursor, a clock), ONE Enter key, a
    screenshot 3 s after. A login prompt shows itself again, a maintenance prompt says "Login incorrect": the screen
    changes clearly more than by itself. Nothing is pressed unless the instance is ACTIVE, running, without a task, and
    still the domain of the screenshot."""
    sid, inst = a["id"], a["instance"]
    s = d.server(sid, show=True)
    if s is None:
        raise Done(FAILED, "the instance no longer exists: nothing was pressed")
    if s.get("unknown"):
        raise Done(FAILED, f"the instance could not be read ({s['unknown']}): nothing was pressed")
    name = s["name"]
    if s["instance"] != inst:
        raise Done(FAILED, f"{name} is now the domain {s['instance'] or '?'}, not {inst} of the screenshot: nothing was pressed")
    if s["status"] != "ACTIVE" or (s["power"] and s["power"] != "running") or s["task"]:
        raise Done(FAILED, f"{name} is {s['status']}, power {s['power'] or '?'}" + (f", task {s['task']}" if s["task"] else "")
                   + ": the console is tested only on an ACTIVE, running instance without a task; nothing was pressed")
    ip, user = d.node(s["host"]) if s["host"] else (None, None)
    if not ip:
        raise Done(FAILED, f"the address of {s['host'] or 'its compute'} is not in the TripleO inventory: nothing was pressed")
    first = d.screenshot(ip, user, inst)
    d.sleep(CONSOLE_SETTLE)
    before = d.screenshot(ip, user, inst)
    if not first or not before:
        raise Done(FAILED, f"the console of {name} could not be read (virsh screenshot on {short(s['host'])}): nothing was pressed")
    d.say(f"{SHOT_MARK} {inst} before {sid} {base64.b64encode(before).decode()}")
    alone = changed_pixels(first, before)
    pressed, out = d.send_enter(ip, user, inst)
    if not pressed:
        raise Done(FAILED, f"virsh send-key failed on {short(s['host'])}: {first_line(out) or 'no answer'}; nothing was pressed")
    d.say(f"One Enter key pressed on the console of {name}; the screen is read again in {CONSOLE_SETTLE} s")
    d.sleep(CONSOLE_SETTLE)
    after = d.screenshot(ip, user, inst)
    if not after:
        raise Done(ATTENTION, f"Enter was pressed on {name}, but its console could not be read after it: look at it in Horizon")
    d.say(f"{SHOT_MARK} {inst} after {sid} {base64.b64encode(after).decode()}")
    moved = changed_pixels(before, after)
    if moved is None or alone is None:   # not a PNG this code reads: only "the same or not"
        if after != before:
            raise Done(OK, f"the console of {name} answers: the screen changed after one Enter key (not measured)")
        raise Done(ATTENTION, f"the screen of {name} did not change after one Enter key: the guest may not read its keyboard "
                              "(frozen, or a screen that ignores Enter). Look at the console in Horizon")
    measured = f"{moved} pixel(s) changed after Enter, {alone} by themselves in the {CONSOLE_SETTLE} s before (cursor, clock)"
    if moved >= max(CONSOLE_ANSWERS, 2 * alone + 100):
        raise Done(OK, f"the console of {name} answers: {measured}")
    raise Done(ATTENTION, f"the screen of {name} did not change after one Enter key ({measured}): the guest may not read its "
                          "keyboard (frozen, or a screen that ignores Enter). Look at the console in Horizon")


OPS = {"live-migrate": live_migrate, "cold-migrate": cold_migrate, "migrate-volume": migrate_volume, "retype-volume": retype_volume,
       "delete-image": delete_image, "delete-snapshots": delete_volume_snapshots,
       "clear-fdb": clear_fdb, "port-security": port_security, "getcert-resubmit": getcert_resubmit, "console-test": console_test,
       "rescan-luns": rescan_lost, "move-leftover": move_leftover, "release-lv": release_lv, "flush-map": flush_map,
       "rescan-disk": rescan_disk, "delete-path": delete_path}


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
        if d.timing():
            d.say(d.timing())
        d.say(f"RESULT {LABEL[e.rc]}: {e.message}")
        if e.rc == ATTENTION and CONTROL_HINT in e.message:   # the platform, not this item: the run must stop
            return CONTROL_FAILED
        return e.rc
    except Exception as e:   # an unexpected answer: stop the fix here, with what is known
        d.say(f"RESULT attention: unexpected error {e!r}")
        return ATTENTION


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

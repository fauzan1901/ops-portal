"""Sync of the findings from Tenable: one at a time, in a background thread of the portal.

A sync asks Tenable for a vulnerability export of the findings that changed: the first one those of the last
FIRST_DAYS days, the next ones since the start of the last successful sync minus one hour (an export misses nothing that
changed while the one before ran). Severities VULNS_SEVERITIES (default low, medium, high, critical: info is noise for
remediation), states OPEN, REOPENED and FIXED. It polls the status of the export every POLL_SECONDS, reads every chunk as
soon as Tenable has it, saves the findings (findings.upsert) and, when done, the trend point of every site.
Started by "Sync now" or by itself when a page of the module opens and the last sync is older than VULNS_SYNC_HOURS
(0 = never by itself); after a failed sync it waits AUTO_RETRY_MINUTES before it tries by itself again.
"""
import datetime
import logging
import os
import threading
import time

from . import findings, scope, tenable

log = logging.getLogger("portal.nessus")

FIRST_DAYS = 90
OVERLAP = 3600   # s before the start of the last successful sync
POLL_SECONDS = float(os.environ.get("VULNS_EXPORT_POLL_SECONDS", "5"))
MAX_WAIT = int(os.environ.get("VULNS_EXPORT_MAX_MINUTES", "30")) * 60
SYNC_HOURS = float(os.environ.get("VULNS_SYNC_HOURS", "6"))
AUTO_RETRY_MINUTES = 15
NUM_ASSETS = 500
SEVERITIES = [s for s in (x.strip().lower() for x in os.environ.get("VULNS_SEVERITIES", "low,medium,high,critical").split(","))
              if s in findings.RANK] or ["low", "medium", "high", "critical"]

_lock = threading.Lock()
_state = {"thread": None, "id": None, "username": "", "started": "", "reason": "", "phase": ""}


class Busy(ValueError):
    pass


def running():
    """The sync running now ({"id", "username", "started", "reason", "phase"}) or None."""
    with _lock:
        t = _state["thread"]
        if not t or not t.is_alive():
            return None
        return {k: _state[k] for k in ("id", "username", "started", "reason", "phase")}


def _phase(text):
    with _lock:
        _state["phase"] = text


def _epoch(iso):
    return int(datetime.datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp())


def since_epoch():
    """Findings changed since: the last successful sync's start minus an hour, or FIRST_DAYS days ago (also once after the
    table got new columns: the findings kept before get them too)."""
    last = findings.last_sync("ok")
    if last and last.get("started") and not findings.full_sync_needed():
        try:
            return _epoch(last["started"]) - OVERLAP
        except ValueError:
            pass
    return int(time.time()) - FIRST_DAYS * 86400


def start(username, client_factory, event, reason="manual", client_ip="", before=None):
    """Start a sync in the background; Busy when one is running. client_factory() -> tenable.Client (the stored keys);
    event(actor, action, target, detail, client_ip) writes the activity log; before(): read the scans of Tenable first
    (which scanner ran which scan: the site of a finding no network places)."""
    with _lock:
        t = _state["thread"]
        if t and t.is_alive():
            raise Busy(f"A sync is already running (started by {_state['username']}): wait until it ends.")
        since = since_epoch()
        sync_id = findings.sync_start(username, reason, findings.utc(since), client_ip)
        _state.update(id=sync_id, username=username, started=findings.now_iso(), reason=reason, phase="Starting")
        thread = threading.Thread(target=_run, args=(sync_id, since, username, client_factory, event, reason, client_ip, before),
                                  name=f"nessus-sync-{sync_id}", daemon=True)
        _state["thread"] = thread
        thread.start()
    return sync_id


def due():
    """Should a page that opens start a sync by itself now? (none running, the last one too old, no recent failure)"""
    if SYNC_HOURS <= 0 or running():
        return False
    last = findings.last_sync()
    if not last:
        return True
    try:
        age = time.time() - _epoch(last["started"])
    except (TypeError, ValueError):
        return True
    if last["status"] == "error":
        return age > AUTO_RETRY_MINUTES * 60 and _ok_age() > SYNC_HOURS * 3600
    return last["status"] != "running" and _ok_age() > SYNC_HOURS * 3600


def _ok_age():
    ok = findings.last_sync("ok")
    try:
        return time.time() - _epoch(ok["started"]) if ok else float("inf")
    except (TypeError, ValueError):
        return float("inf")


def wait(timeout=60):
    """Tests and shutdown: wait for the running sync to end."""
    with _lock:
        t = _state["thread"]
    if t:
        t.join(timeout)
    return not (t and t.is_alive())


def _run(sync_id, since, username, client_factory, event, reason, client_ip, before=None):
    counts = {"received": 0, "new": 0, "updated": 0, "fixed": 0, "reopened": 0}
    began = time.monotonic()
    try:
        client = client_factory()
        cfg = scope.config()
        if before:
            _phase("Reading the scans of Tenable (which scanner found what)")
            try:
                before()
            except Exception as e:   # without it the findings are placed by their network only, until the next sync
                log.warning("Nessus sync #%s: the scans of Tenable could not be read: %s", sync_id, e)
        findings.remap_sites(cfg)
        _phase("Asking Tenable for an export")
        uuid = client.export_vulns({"severity": SEVERITIES, "state": ["OPEN", "REOPENED", "FIXED"], "since": int(since)},
                                   NUM_ASSETS)
        done, deadline = set(), time.monotonic() + MAX_WAIT
        while True:
            st = client.export_status(uuid)
            status = str(st.get("status") or "").upper()
            chunks = sorted(int(n) for n in st.get("chunks_available") or [] if str(n).isdigit() or isinstance(n, int))
            for n in chunks:
                if n in done:
                    continue
                _phase(f"Reading chunk {n} of the export ({status.lower() or 'processing'})")
                for key, value in findings.upsert(client.export_chunk(uuid, n), cfg).items():
                    counts[key] += value
                done.add(n)
            if status == "FINISHED":
                break
            if status in ("CANCELLED", "ERROR"):
                raise tenable.TenableError(f"Tenable ended the export with status {status}")
            if time.monotonic() > deadline:
                raise tenable.TenableError(f"The export was not ready after {MAX_WAIT // 60} minutes (status {status or 'unknown'})")
            _phase(f"Tenable prepares the export ({status.lower() or 'queued'}, {len(done)} chunks read)")
            time.sleep(POLL_SECONDS)
        findings.remap_sites(cfg, force=True)   # every finding of an address in one site, by network or by scanner
        findings.sync_finish(sync_id, "ok", counts)
        findings.full_sync_done()
        findings.trend_snapshot(sync_id)
        seconds = int(time.monotonic() - began)
        event(username, "nessus.sync", "Tenable", f"Sync #{sync_id}{' (automatic)' if reason == 'auto' else ''}: "
              f"{findings.counts_text(counts)}, since {findings.utc(since)} ({seconds} s)", client_ip)
    except Exception as e:   # the reason is shown on the pages and in the activity log (never the keys: tenable.py)
        message = str(e) or e.__class__.__name__
        if not isinstance(e, (tenable.TenableError, ValueError)):
            log.exception("Nessus sync #%s failed", sync_id)
        findings.sync_finish(sync_id, "error", counts, message)
        event(username, "nessus.sync_failed", "Tenable", f"Sync #{sync_id}: {message}", client_ip)
    finally:
        with _lock:
            _state["phase"] = ""

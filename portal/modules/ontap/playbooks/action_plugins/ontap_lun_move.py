"""Action plugin: lun move the restored LUN to the target tier FlexVol (same SVM) through the native ONTAP REST API,
then wait for it to finish.

Start: PATCH /api/storage/luns/{uuid} {"name": "<destination path>"} (as the REST NetApp Cinder driver does).
Watch: GET /api/storage/luns?name=*<LUN name>&fields=name,uuid,movement  -> movement.progress.state / percent_complete /
       failure.message. States: preparing (allocation) -> replicating (data copy) -> complete.

Observed on ONTAP DCB 9.13.1: a lun move started 2-3 minutes after restore-file (used at 99%) was stopped by ONTAP
without creating the destination LUN (EMS only LUN.move.started, no LUN.move.dstPresent) and the LUN stayed in the
source FlexVol; the same lun move 14 minutes after the restore succeeded. The PATCH for a large LUN can also take long
to return. Therefore:
  - before the first attempt, wait until the -restore LUN used space is unchanged for settle_seconds
    (at most settle_max_seconds);
  - the PATCH is limited to patch_timeout_seconds; when it does not return, the move status is still checked
    (it may already be running);
  - a LUN that did not move is retried after retry_delay_seconds, at most `attempts` times.
Fails on state failed/paused_error, when attempts run out, or when timeout_seconds is exceeded (ONTAP keeps running
a lun move that is in progress).

ONTAP credentials come from the environment (ONTAP_USER/ONTAP_PASSWORD). Live progress:
"PROGRESS move pct=<0-100> status=<state>" for the Web UI progress bar.
"""
import base64
import json
import os
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from ansible.plugins.action import ActionBase
from ansible.utils.display import Display

display = Display()
FAILED = ("failed", "paused_error")
GIB = 1024 ** 3


class OntapError(Exception):
    pass


class OntapTimeout(OntapError):
    pass


class ActionModule(ActionBase):
    TRANSFERS_FILES = False
    _VALID_ARGS = frozenset(("host", "source_path", "destination_path", "poll_seconds", "timeout_seconds", "attempts",
                             "retry_delay_seconds", "settle_seconds", "settle_max_seconds", "patch_timeout_seconds",
                             "validate_certs"))

    def run(self, tmp=None, task_vars=None):
        result = super().run(tmp, task_vars)
        args = self._task.args
        self.host = str(args["host"])
        src, dst = str(args["source_path"]), str(args["destination_path"])
        poll = max(1, int(args.get("poll_seconds", 10)))
        timeout = max(poll, int(args.get("timeout_seconds", 7200)))
        attempts = max(1, int(args.get("attempts", 5)))
        retry_delay = max(0, int(args.get("retry_delay_seconds", 120)))
        settle = max(0, int(args.get("settle_seconds", 60)))
        settle_max = max(settle, int(args.get("settle_max_seconds", 900)))
        patch_timeout = max(1, int(args.get("patch_timeout_seconds", 300)))
        ctx = ssl.create_default_context() if str(args.get("validate_certs", False)).lower() == "true" else ssl._create_unverified_context()
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
        self.token = base64.b64encode(f"{os.environ.get('ONTAP_USER', '')}:{os.environ.get('ONTAP_PASSWORD', '')}".encode()).decode()
        base = dst.rsplit("/", 1)[-1]
        start = time.time()
        display.display(f"lun move {src} -> {dst} (native REST, polling every {poll}s, limit {timeout}s, up to {attempts} attempts)")
        try:
            self._settle(src, poll, settle, settle_max)
            for attempt in range(1, attempts + 1):
                lun = self._find_retry(base, dst, poll)
                if not lun:
                    return self._fail(result, f"LUN {base} was not found in ONTAP (expected at {src}). cinder manage has not been run.")
                if lun["name"] == dst and not lun.get("movement"):
                    display.display(f"PROGRESS move pct=100 status=complete | LUN is already at {dst}")
                    return self._done(result, start, attempt)
                if lun["name"] == src and not lun.get("movement"):
                    display.display(f"Attempt {attempt}/{attempts}: starting lun move (PATCH LUN name to the destination path)")
                    try:
                        self._call("PATCH", f"/api/storage/luns/{lun['uuid']}", {"name": dst}, timeout=patch_timeout)
                    except OntapTimeout as e:   # ONTAP may already have accepted it: check the move status
                        display.display(f"   {e}; checking whether the lun move is already running")
                outcome = self._watch(base, src, dst, poll, start, timeout)
                if outcome == "complete":
                    return self._done(result, start, attempt)
                if outcome.startswith("failed:"):
                    return self._fail(result, f"lun move {src} -> {dst} failed: {outcome[7:]}. cinder manage has not been run; "
                                              "check the LUN in ONTAP (lun move show).")
                if outcome == "timeout":
                    return self._fail(result, f"lun move {src} -> {dst} has not finished after {int(time.time() - start)}s. "
                                              "ONTAP keeps running it; once it completes, run cinder manage manually for the destination LUN.")
                # outcome == "stopped": ONTAP stopped the lun move without creating the destination LUN; the LUN is still at the source path.
                if attempt < attempts:
                    display.display(f"   ONTAP stopped the lun move without moving the LUN (still at {src}); "
                                    f"retrying in {retry_delay}s ({attempt + 1}/{attempts})")
                    time.sleep(retry_delay)
            return self._fail(result, f"ONTAP stopped lun move {src} -> {dst} {attempts} times without moving the LUN "
                                      f"(LUN still at {src}). cinder manage has not been run; check EMS LUN.move.* in ONTAP.")
        except OntapError as e:
            return self._fail(result, f"lun move {src} -> {dst}: {e}. cinder manage has not been run.")

    # ---------------- REST ----------------
    def _call(self, method, path, body=None, timeout=60):
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(f"https://{self.host}{path}", data=data, method=method,
                                         headers={"Authorization": f"Basic {self.token}", "Accept": "application/json",
                                                  "Content-Type": "application/json"})
        where = f"ONTAP {method} {path.split('?')[0]}"
        try:
            with self.opener.open(request, timeout=timeout) as resp:
                return json.loads(resp.read().decode() or "{}")
        except urllib.error.HTTPError as e:
            try:
                message = json.loads(e.read().decode() or "{}").get("error", {}).get("message") or str(e)
            except Exception:
                message = str(e)
            raise OntapError(f"{where} failed (HTTP {e.code}): {message}")
        except (TimeoutError, socket.timeout) as e:
            raise OntapTimeout(f"{where} did not respond within {timeout}s")
        except urllib.error.URLError as e:
            if isinstance(e.reason, (TimeoutError, socket.timeout)):
                raise OntapTimeout(f"{where} did not respond within {timeout}s")
            raise OntapError(f"{where} could not connect: {e.reason}")
        except (OSError, ValueError) as e:
            raise OntapError(f"{where} failed: {e}")

    def _find(self, base, dst=""):
        """LUN named base; when there are briefly two (source and destination), prefer the moving one, then the destination."""
        records = self._call("GET", f"/api/storage/luns?name=*{urllib.parse.quote(base, safe='')}&fields=name,uuid,movement").get("records") or []
        records.sort(key=lambda r: (not r.get("movement"), r.get("name") != dst))
        return records[0] if records else None

    def _settle(self, src, poll, settle, limit):
        """Wait until the -restore LUN used space is unchanged for `settle` seconds: background restore-file has finished."""
        if settle <= 0:
            return
        display.display(f"Waiting for LUN {src} used space to be stable for {settle}s before lun move (restore-file still finishing in the background)")
        start = last_change = time.time()
        last_used = None
        while True:
            try:
                records = self._call("GET", f"/api/storage/luns?name={urllib.parse.quote(src, safe='/')}&fields=space.used").get("records") or []
            except OntapError as e:   # transient error: retry on the next poll
                display.display(f"   {e}; retrying in {poll}s")
                time.sleep(poll)
                continue
            if not records:   # LUN no longer at the source path: the lun move attempt will check it
                return
            used = int((records[0].get("space") or {}).get("used") or 0)
            now = time.time()
            if used != last_used:
                last_used, last_change = used, now
            if now - last_change >= settle:
                display.display(f"   used space stable at {used / GIB:.1f} GiB for {settle}s")
                return
            if now - start >= limit:
                display.display(f"   used space still changing after {limit}s ({used / GIB:.1f} GiB); trying lun move anyway")
                return
            time.sleep(poll)

    def _find_retry(self, base, dst, poll, tries=5):
        for i in range(tries):
            try:
                return self._find(base, dst)
            except OntapError as e:   # transient error while reading the LUN status
                if i == tries - 1:
                    raise
                display.display(f"   {e}; retrying in {poll}s")
                time.sleep(poll)

    def _watch(self, base, src, dst, poll, start, timeout):
        """complete | stopped | timeout | failed:<message>"""
        idle, errors, last = 0, 0, None
        while True:
            time.sleep(poll)
            try:
                lun = self._find(base, dst) or {}
                errors = 0
            except OntapError as e:   # transient error: retry on the next poll
                errors += 1
                display.display(f"   {e}; retrying in {poll}s")
                if errors >= 5:
                    return f"failed:status could not be read ({e})"
                continue
            progress = (lun.get("movement") or {}).get("progress") or {}
            state = str(progress.get("state") or "")
            if progress:
                idle = 0
                pct = int(progress.get("percent_complete") or 0)
                line = f"PROGRESS move pct={pct} status={state or '-'} | lun move {state or '-'} {pct}%"
                if line != last:
                    display.display(line)
                    last = line
                if state == "complete":
                    return "complete"
                if state in FAILED:
                    return f"failed:{state}: {(progress.get('failure') or {}).get('message') or 'no reason given by ONTAP'}"
            elif lun.get("name") == dst:
                display.display("PROGRESS move pct=100 status=complete | lun move complete 100%")
                return "complete"
            else:
                idle += 1
                if idle >= 3:   # no movement and the LUN is still at the source path: stopped by ONTAP
                    return "stopped"
            if time.time() - start >= timeout:
                return "timeout"

    def _done(self, result, start, attempt):
        waited = int(time.time() - start)
        result.update(changed=True, waited=waited, attempts=attempt, msg=f"lun move finished in {waited}s ({attempt} attempt{'s' if attempt != 1 else ''})")
        return result

    @staticmethod
    def _fail(result, msg):
        result.update(failed=True, msg=msg)
        return result

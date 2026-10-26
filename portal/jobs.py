"""Runs Ansible playbooks as background jobs and keeps their output for the browser (shared by the portal modules).

Non-secret parameters go to the playbook in a JSON vars file (mode 600, deleted afterwards). Passwords of service
accounts go in the process environment only: never on the command line (visible in `ps`) and never on disk.
The playbook writes its result as JSON to `result_file` ({"ok": true|false, "error": ..., ...}).
"""
import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid

import settings

log = logging.getLogger("portal.jobs")
MAX_LINES = 5000
KEEP_JOBS = 200
# Only these variables reach Ansible (FAKE_* = test mode with a fake director, fake hosts and mock APIs).
PASSTHROUGH_ENV = ("PATH", "HOME", "LANG", "LC_ALL", "TZ",
                   "FAKE_DIRECTOR_STATE", "FAKE_ONTAP_URL", "FAKE_DIRECTOR_FAIL", "FAKE_POOL_PREFIX", "FAKE_DIRECTOR_RC",
                   "FAKE_PORT_FAIL", "FAKE_SERVER_ERROR", "FAKE_HOSTS_STATE")
NOISE = ("included: ", "Check result: ", "Check ONTAP response", "Save ", "Record ", "Periksa ", "Simpan ", "Catat ")


def ansible_playbook():
    beside_python = os.path.join(os.path.dirname(sys.executable), "ansible-playbook")
    return (os.environ.get("ANSIBLE_PLAYBOOK_BIN") or (beside_python if os.path.exists(beside_python) else None)
            or shutil.which("ansible-playbook") or "ansible-playbook")


class Jobs:
    """Jobs of one module. playbook_dir: the module's playbooks (with ansible.cfg); timeouts: {kind: seconds}."""

    def __init__(self, playbook_dir, timeouts, busy_message="A job for this item is already running. Wait until it finishes.",
                 timeout_message="The {timeout}-second time limit was reached; the job was stopped."):
        self.playbook_dir = playbook_dir
        self.timeouts = timeouts
        self.busy_message = busy_message
        self.timeout_message = timeout_message
        self._lock = threading.Lock()
        self._jobs = {}
        self._busy = set()

    def start(self, kind, params, secrets=None, key=None, on_finish=None, owner="", timeout=None, playbook=None, user=""):
        """Start playbook `playbook` (default <kind>.yml) with params. secrets: environment variables for the
        playbook (service account passwords). key: one job per key at a time. owner: tag of the portal session that
        started the job. timeout: seconds (default timeouts[kind])."""
        with self._lock:
            if key and key in self._busy:
                raise ValueError(self.busy_message)
            if key:
                self._busy.add(key)
            job = {"id": uuid.uuid4().hex[:12], "kind": kind, "user": user, "owner": owner, "params": dict(params),
                   "status": "running", "lines": [], "task": "", "result": None, "error": "", "started": time.time(),
                   "finished": None, "key": key, "timeout": int(timeout or self.timeouts[kind]),
                   "playbook": playbook or f"{kind}.yml"}
            self._jobs[job["id"]] = job
            for old in sorted(self._jobs.values(), key=lambda j: j["started"])[:-KEEP_JOBS]:
                if old["status"] != "running":
                    del self._jobs[old["id"]]
        threading.Thread(target=self._run, args=(job, dict(secrets or {}), on_finish), daemon=True).start()
        return job

    def get(self, job_id):
        with self._lock:
            return self._jobs.get(job_id)

    def latest(self, kind, owner, **params):
        """The newest successful job of this kind started by this owner whose params match (None if there is none),
        for example to show a result again without running the playbook again."""
        with self._lock:
            found = [j for j in self._jobs.values() if j["kind"] == kind and j["owner"] == owner and j["status"] == "success"
                     and all(j["params"].get(k) == v for k, v in params.items())]
        return max(found, key=lambda j: j["started"], default=None)

    def busy(self, key):
        with self._lock:
            return key in self._busy

    def running(self):
        """Jobs that are still running (the updater refuses to restart the portal while there are any)."""
        with self._lock:
            return [j for j in self._jobs.values() if j["status"] == "running"]

    def _line(self, job, line):
        if len(job["lines"]) < MAX_LINES:
            job["lines"].append(line)
        if line.startswith("TASK [") and line.rstrip("* ").endswith("]"):
            name = line[6:line.rstrip("* ").rfind("]")]
            if not name.startswith(NOISE):
                job["task"] = name

    def _run(self, job, secrets, on_finish):
        os.makedirs(os.path.join(settings.DATA_DIR, "jobs"), mode=0o700, exist_ok=True)
        workdir = tempfile.mkdtemp(prefix=f"{job['kind']}-{job['id']}-", dir=os.path.join(settings.DATA_DIR, "jobs"))
        result_file = os.path.join(workdir, "result.json")
        vars_file = os.path.join(workdir, "vars.json")
        with os.fdopen(os.open(vars_file, os.O_WRONLY | os.O_CREAT, 0o600), "w") as f:
            json.dump(dict(job["params"], result_file=result_file), f)
        env = {k: os.environ[k] for k in PASSTHROUGH_ENV if k in os.environ}
        env.update(ANSIBLE_CONFIG=os.path.join(self.playbook_dir, "ansible.cfg"), ANSIBLE_NOCOLOR="1", ANSIBLE_FORCE_COLOR="0",
                   PYTHONUNBUFFERED="1", **secrets)
        cmd = [ansible_playbook(), job["playbook"], "-e", f"@{settings.SITES_FILE}", "-e", f"@{vars_file}"]
        timer = None
        try:
            proc = subprocess.Popen(cmd, cwd=self.playbook_dir, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    stdin=subprocess.DEVNULL, text=True, bufsize=1, start_new_session=True)
            timer = threading.Timer(job["timeout"], self._kill, args=(proc, job))
            timer.start()
            with proc.stdout:
                for line in proc.stdout:
                    self._line(job, line.rstrip("\n"))
            rc = proc.wait()
            result = None
            if os.path.exists(result_file):
                with open(result_file, encoding="utf-8") as f:
                    result = json.load(f)
            ok = rc == 0 and bool(result and result.get("ok"))
            job["result"] = result
            job["error"] = "" if ok else ((result or {}).get("error") or job["error"] or f"ansible-playbook stopped (rc={rc})")
            job["status"] = "success" if ok else "failed"
        except Exception as e:
            log.exception("Job %s could not be run", job["id"])
            job["error"], job["status"] = f"Could not run Ansible: {e}", "failed"
        finally:
            if timer:
                timer.cancel()
            job["finished"] = time.time()
            shutil.rmtree(workdir, ignore_errors=True)
            with self._lock:
                self._busy.discard(job["key"])
            if on_finish:
                try:
                    on_finish(job)
                except Exception:
                    log.exception("Failed to record the result of job %s", job["id"])

    def _kill(self, proc, job):
        job["error"] = self.timeout_message.format(timeout=job["timeout"])
        try:
            os.killpg(proc.pid, signal.SIGTERM)
            time.sleep(10)
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

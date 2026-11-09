"""Action plugin: wait until the used capacity of the restored LUN in ONTAP matches the used capacity of the
existing LUN (WI step).

Done when:
  - "match":  used >= target * (1 - tolerance_pct/100), or
  - "stable": used has not grown for stable_seconds (0 = disabled). This happens when the volume data changed
              after the snapshot was taken, so the restored used capacity never exactly matches the existing one.
Fails when timeout_seconds is exceeded.

ONTAP credentials come from the environment (ONTAP_USER/ONTAP_PASSWORD), like the playbook, never from task
arguments. Progress is printed live with the prefix "PROGRESS used=<bytes> target=<bytes>" for the Web UI progress bar.
"""
import base64
import json
import os
import ssl
import time
import urllib.request

from ansible.plugins.action import ActionBase
from ansible.utils.display import Display

display = Display()
GIB = 1024 ** 3


class ActionModule(ActionBase):
    TRANSFERS_FILES = False
    _VALID_ARGS = frozenset(("host", "lun_path", "target", "tolerance_pct", "poll_seconds", "stable_seconds",
                             "timeout_seconds", "validate_certs"))

    def run(self, tmp=None, task_vars=None):
        result = super().run(tmp, task_vars)
        args = self._task.args
        host, lun_path = str(args["host"]), str(args["lun_path"])
        target = int(args["target"])
        tolerance = float(args.get("tolerance_pct", 1))
        poll = max(1, int(args.get("poll_seconds", 10)))
        stable = max(0, int(args.get("stable_seconds", 300)))
        timeout = max(poll, int(args.get("timeout_seconds", 7200)))
        ctx = ssl.create_default_context() if str(args.get("validate_certs", False)).lower() == "true" else ssl._create_unverified_context()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
        token = base64.b64encode(f"{os.environ.get('ONTAP_USER', '')}:{os.environ.get('ONTAP_PASSWORD', '')}".encode()).decode()
        request = urllib.request.Request(f"https://{host}/api/storage/luns?name={lun_path}&fields=name,space.used,space.size",
                                         headers={"Authorization": f"Basic {token}", "Accept": "application/json"})
        need = target * (1 - tolerance / 100)
        display.display(f"Waiting for used space of LUN {lun_path} to match the existing LUN ({target / GIB:.1f} GiB, "
                        f"tolerance {tolerance:g}%, polling every {poll}s)")
        start = time.time()
        last_used, last_change, used, reason = None, start, 0, ""
        while True:
            try:
                with opener.open(request, timeout=30) as resp:
                    records = json.loads(resp.read().decode() or "{}").get("records") or []
                used = int(((records[0].get("space") or {}).get("used")) or 0) if records else 0
            except Exception as e:   # transient error: retry on the next poll
                display.display(f"   ONTAP did not respond ({e}); retrying in {poll}s")
            now = time.time()
            if used != last_used:
                last_used, last_change = used, now
            pct = 100 if target <= 0 else min(100, int(used * 100 / target))
            display.display(f"PROGRESS used={used} target={target} | restored LUN used {used / GIB:.1f} GiB of {target / GIB:.1f} GiB ({pct}%)")
            if used >= need:
                reason = "match"
                break
            if stable and used > 0 and now - last_change >= stable:
                reason = "stable"
                break
            if now - start >= timeout:
                result.update(failed=True, used=used, target=target, msg=(
                    f"LUN {lun_path} used space is only {used / GIB:.1f} GiB of {target / GIB:.1f} GiB after {int(now - start)}s. "
                    "The -restore LUN remains in ONTAP; check it manually before cinder manage."))
                return result
            time.sleep(poll)
        result.update(changed=False, used=used, target=target, reason=reason, waited=int(time.time() - start),
                      msg=("used space matches the existing LUN" if reason == "match" else
                           f"used space stopped growing at {used / GIB:.1f} GiB (existing {target / GIB:.1f} GiB) for {stable}s"))
        return result

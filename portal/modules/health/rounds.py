"""Status rounds: every INTERVAL_HOURS the read-only checks of every product (products.py) run on every site where they
are configured, by themselves, as the account "health" (an operator of Runbook Automation without any fix right: a
round never changes anything). An operator can start the round of a site now (Run now).

A round runs its checks one after the other (one site does not load its director, ONTAP or vCenter with several at
once; the sites run side by side), each through Runbook Automation (start_run: the same check as Checks → Run, in Runs
as user "health"). A check of the same site and parameters that is already running (an operator's) is waited for up to
three minutes, then noted "already running". A check waits at most CHECK_WAIT for its result. The scheduler looks every
minute, START_DELAY after the portal started (an install is not followed by a burst of checks); a round of a site
starts when its last one started INTERVAL_HOURS ago or more. Rounds and their items are kept KEEP_DAYS days; the runs
stay in Runs as any run.

Tables (database of the portal): health_rounds (site, trigger auto/manual, by, started, finished) and health_items (one
per check of a round: product, check, run id, status waiting/running/ok/warn/fail/error/unknown/not-configured/stopped,
note).
"""
import contextlib
import datetime
import logging
import os
import sqlite3
import threading
import time

import settings
import sites

from . import products

log = logging.getLogger("portal.health")

INTERVAL_HOURS = float(os.environ.get("STATUS_INTERVAL_HOURS", "4"))   # 0: no round by itself (Run now only)
START_DELAY = int(float(os.environ.get("STATUS_START_DELAY_MINUTES", "5")) * 60)
CHECK_WAIT = int(float(os.environ.get("STATUS_CHECK_WAIT_MINUTES", "30")) * 60)
BUSY_RETRIES, BUSY_WAIT = 3, 60   # a check already running (an operator's): tried again 3 times, a minute apart
KEEP_DAYS = 30
ROBOT = {"username": "health", "display_name": "Status check", "role": "operator", "source": "health", "modules": ["wi"]}
FINAL = ("ok", "warn", "fail", "error", "unknown", "skip", "not-configured", "stopped")

# What this module needs from Runbook Automation (set by modules/health/__init__.py; fakes in the tests).
HOOKS = {"start": None,    # (user, site, check, raw params, after(run_id, status), note) -> run id
         "access": None,   # (check id, site) -> {"runnable": bool, "missing": [str]}
         "get_run": None,  # (run id) -> stored run with its result
         "targets": None}  # (site, kind) -> [names]: the targets a "per" product checks one by one (kind bmc: the BMCs)
_lock = threading.Lock()
_threads = {}             # site -> thread of its round
_scheduler = {"thread": None}


@contextlib.contextmanager
def _db():
    os.makedirs(os.path.dirname(os.path.abspath(settings.DB_PATH)), exist_ok=True)
    conn = sqlite3.connect(settings.DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def _now():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def _age(iso):
    try:
        return (datetime.datetime.now().astimezone() - datetime.datetime.fromisoformat(iso)).total_seconds()
    except (TypeError, ValueError):
        return None


def init():
    with _db() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS health_rounds (id INTEGER PRIMARY KEY AUTOINCREMENT, site TEXT NOT NULL,
                      trigger TEXT NOT NULL, username TEXT NOT NULL, started TEXT NOT NULL, finished TEXT)""")
        db.execute("""CREATE TABLE IF NOT EXISTS health_items (id INTEGER PRIMARY KEY AUTOINCREMENT, round_id INTEGER NOT NULL,
                      product TEXT NOT NULL, check_id TEXT NOT NULL, run_id INTEGER, status TEXT NOT NULL, note TEXT NOT NULL DEFAULT '',
                      started TEXT, finished TEXT)""")
        cols = {r["name"] for r in db.execute("PRAGMA table_info(health_items)")}
        if "target" not in cols:   # the target of a check of a "per" product (a BMC), "" for the others
            db.execute("ALTER TABLE health_items ADD COLUMN target TEXT NOT NULL DEFAULT ''")
        db.execute("CREATE INDEX IF NOT EXISTS health_rounds_site ON health_rounds (site, id)")
        db.execute("CREATE INDEX IF NOT EXISTS health_items_round ON health_items (round_id)")
        # a round the portal stopped in the middle (restart, install): what had not ended is "stopped"
        db.execute("UPDATE health_items SET status = 'stopped', note = 'The portal stopped during the round.', finished = ? "
                   "WHERE status IN ('waiting', 'running')", (_now(),))
        db.execute("UPDATE health_rounds SET finished = ? WHERE finished IS NULL", (_now(),))
        cutoff = (datetime.datetime.now().astimezone() - datetime.timedelta(days=KEEP_DAYS)).isoformat(timespec="seconds")
        db.execute("DELETE FROM health_items WHERE round_id IN (SELECT id FROM health_rounds WHERE started < ?)", (cutoff,))
        db.execute("DELETE FROM health_rounds WHERE started < ?", (cutoff,))


def running(site):
    with _lock:
        t = _threads.get(site)
        return bool(t and t.is_alive())


def running_sites():
    with _lock:
        return sorted(s for s, t in _threads.items() if t.is_alive())


def last_round(site, finished=False):
    with _db() as db:
        r = db.execute("SELECT * FROM health_rounds WHERE site = ?" + (" AND finished IS NOT NULL" if finished else "")
                       + " ORDER BY id DESC LIMIT 1", (site,)).fetchone()
    return dict(r) if r else None


def items(round_id):
    with _db() as db:
        return [dict(r) for r in db.execute("SELECT * FROM health_items WHERE round_id = ? ORDER BY id", (round_id,))]


def _set(item_id, **values):
    cols = ", ".join(f"{k} = ?" for k in values)
    with _db() as db:
        db.execute(f"UPDATE health_items SET {cols} WHERE id = ?", [*values.values(), item_id])


def targets(site, product):
    """The targets a product checks one by one on a site ([""]: a product checked once)."""
    if not product.get("per"):
        return [""]
    try:
        return list(HOOKS["targets"](site, product["per"]) or [])
    except Exception:
        log.exception("Status: the %s targets of %s could not be read", product["per"], site)
        return []


def configured(site):
    """The products of a site with at least one check it can run (the others are not configured there)."""
    out = []
    for p in products.PRODUCTS:
        if any(HOOKS["access"](c["check"], site)["runnable"] for c in p["checks"]) and (not p.get("per") or targets(site, p)):
            out.append(p["id"])
    return out


def start(site, user, trigger="manual"):
    """Start the round of a site (Run now, or the scheduler). Returns the round id. ValueError while one runs."""
    if site not in sites.sites():
        raise ValueError(f"Unknown site {site}")
    with _lock:
        t = _threads.get(site)
        if t and t.is_alive():
            raise ValueError(f"The health round of {site} is running: it shows its results as each check ends.")
        with _db() as db:
            rid = db.execute("INSERT INTO health_rounds (site, trigger, username, started) VALUES (?,?,?,?)",
                             (site, trigger, user["username"], _now())).lastrowid
            for p in products.PRODUCTS:
                for c in p["checks"]:
                    for target in targets(site, p) or [""]:   # a "per" product without a target: not configured there
                        db.execute("INSERT INTO health_items (round_id, product, check_id, target, status) VALUES (?,?,?,?,'waiting')",
                                   (rid, p["id"], c["check"], target))
        t = threading.Thread(target=_round, args=(rid, site), name=f"health-{site}", daemon=True)
        _threads[site] = t
        t.start()
    return rid


def _run_item(rid, site, item, params):
    """One check of a round: started as "health", its result waited for."""
    access = HOOKS["access"](item["check_id"], site)
    if not access["runnable"]:
        _set(item["id"], status="not-configured", note="; ".join(access["missing"])[:500], finished=_now())
        return
    done, result = threading.Event(), {}

    def after(run_id, status):
        result["status"] = status
        done.set()

    run_id = None
    for attempt in range(BUSY_RETRIES + 1):
        try:
            run_id = HOOKS["start"](ROBOT, site, item["check_id"], params, after, f"health round #{rid}")
            break
        except ValueError as e:
            if "already running" in str(e) and attempt < BUSY_RETRIES:
                time.sleep(BUSY_WAIT)
                continue
            _set(item["id"], status="error", note=str(e)[:500], finished=_now())
            return
    _set(item["id"], status="running", run_id=run_id, started=_now())
    done.wait(CHECK_WAIT)
    status = result.get("status") or (HOOKS["get_run"](run_id) or {}).get("status") or "unknown"
    note = "" if result else f"No result after {CHECK_WAIT // 60} minutes: see the run in Runs."
    _set(item["id"], status=status if status in FINAL else "unknown", note=note, finished=_now())


def _params(item):
    """The parameters of the check of an item: those of products.py, and its target for a "per" product."""
    entry = next((c for p in products.PRODUCTS if p["id"] == item["product"] for c in p["checks"] if c["check"] == item["check_id"]), {})
    params = dict(entry.get("params") or {})
    if item.get("target") and entry.get("param"):
        params[entry["param"]] = item["target"]
    return params


def _round(rid, site):
    try:
        for item in items(rid):
            try:
                _run_item(rid, site, item, _params(item))
            except Exception as e:   # one check that cannot start does not stop the round
                log.exception("Status round #%s of %s: %s", rid, site, item["check_id"])
                _set(item["id"], status="error", note=str(e)[:500], finished=_now())
    finally:
        with _db() as db:
            db.execute("UPDATE health_rounds SET finished = ? WHERE id = ?", (_now(), rid))
        log.info("Status round #%s of %s ended", rid, site)


def due(site):
    """The scheduler starts the round of a site when its last one started INTERVAL_HOURS ago or more (or never ran)."""
    if INTERVAL_HOURS <= 0 or running(site):
        return False
    last = last_round(site)
    age = _age(last["started"]) if last else None
    return age is None or age >= INTERVAL_HOURS * 3600


def next_round(site):
    """When the scheduler starts the next round of a site (ISO), or "" without a schedule."""
    if INTERVAL_HOURS <= 0:
        return ""
    last = last_round(site)
    if not last:
        return _now()
    try:
        at = datetime.datetime.fromisoformat(last["started"]) + datetime.timedelta(hours=INTERVAL_HOURS)
    except ValueError:
        return _now()
    return at.isoformat(timespec="seconds")


def tick():
    """One look of the scheduler: the rounds that are due start (sites with nothing configured are left out)."""
    started = []
    for site in sites.sites():
        try:
            if due(site) and configured(site):
                start(site, ROBOT, "auto")
                started.append(site)
        except ValueError:
            pass   # started meanwhile
        except Exception:
            log.exception("Status round of %s could not start", site)
    return started


def _loop():
    time.sleep(START_DELAY)
    while True:
        tick()
        time.sleep(60)


def start_scheduler():
    if INTERVAL_HOURS <= 0:
        log.info("Status rounds: no schedule (STATUS_INTERVAL_HOURS=0), Run now only")
        return
    with _lock:
        if _scheduler["thread"] and _scheduler["thread"].is_alive():
            return
        _scheduler["thread"] = threading.Thread(target=_loop, name="health-scheduler", daemon=True)
        _scheduler["thread"].start()
    log.info("Status rounds every %s hours (first look %s s after start)", INTERVAL_HOURS, START_DELAY)


def jobs():
    """For the home page and the updater: the rounds running now."""
    return [{"id": f"health-{s}", "title": f"Status: round of {s}", "user": ROBOT["username"]} for s in running_sites()]

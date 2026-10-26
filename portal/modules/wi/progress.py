"""How far a running job is, for the progress bar of the run page: a percentage, what runs now (the Ansible task, in
words) and the last tasks done with their outcome. Read from the live Ansible output of the job (jobs.py keeps it), so
it needs nothing from the playbooks.

A check (run_check.yml): its input and plan (5%), the connections (10%), then its phases (wi_analysis.plan: 10% to 90%,
each phase an equal share, filled as its tasks run), rating what was read (92%) and saving the result (96%).
A fix (run_action.yml): with ticked items, the items done of the ticked ones (the progress file of the fix); else the
connection (15%), the fix itself (30%: one command line that runs until it ends) and its result (90%).
"""
import re

TASK_RE = re.compile(r"^TASK \[(.*)\]\s*\**\s*$")
OUTCOME_RE = re.compile(r"^(ok|changed|skipping|failed|fatal|unreachable|included): ")
OUTCOME = {"ok": "ok", "changed": "ok", "included": "ok", "skipping": "skipped", "failed": "failed", "fatal": "failed",
           "unreachable": "failed"}
HIDDEN = ("included: ", "Record", "Check result: ", "Where the output is", "New lines", "Follow: ", "Live output for the run page",
          "Progress of the items", "Record the result of the item", "Record whether the next item may start", "Time of the item",
          "The director did not answer", "Next pages of the lists")
SHOWN = 8   # the last tasks listed under the bar


def tasks(lines):
    """[[task name, outcome]] in order: ok, failed, skipped, or running for a task without an outcome yet."""
    out = []
    for line in lines or []:
        m = TASK_RE.match(line)
        if m:
            out.append([m.group(1), "running"])
            continue
        m = OUTCOME_RE.match(line)
        if m and out and out[-1][1] == "running":
            out[-1][1] = OUTCOME[m.group(1)]
    return out


def words(name, phases):
    """A task as the operator reads it."""
    m = re.match(r"^Phase (\d+): what to read$", name)
    if m:
        return f"Planning the reads of step {m.group(1)} of {phases}"
    m = re.match(r"^Phase (\d+): (.+)$", name)
    if m:
        return f"Reading {m.group(2)} (step {m.group(1)} of {phases})"
    return {"Validate input": "Checking the input", "Plan of the check": "Planning the check",
            "Rate what was read": "Rating what was read", "Keep what was read (raw output of the run, masked by the portal)":
            "Keeping the raw output", "Write job result": "Saving the result", "Summary": "Saving the result"}.get(name, name)


INTERNAL = re.compile(r"^(Start|Output while it runs|Result|Output of|Wait for the end|The end, when the wait saw it): "
                      r"|(: running|: next read| ended)$")


def _shown(items, phases):
    visible = [x for x in items if not x[0].startswith(HIDDEN) and not INTERNAL.search(x[0]) and x[1] != "skipped"]
    return [{"name": words(n, phases), "status": st} for n, st in visible[-SHOWN:]]


def of_check(lines, phases, done=False):
    phases = max(1, int(phases or 1))
    items = tasks(lines)
    percent, phase, inside = 2.0, 0, 0
    for name, _st in items:
        m = re.match(r"^Phase (\d+): what to read$", name)
        if m:
            phase, inside = int(m.group(1)), 0
            continue
        if name in ("Validate input", "Plan of the check"):
            percent = max(percent, 5)
        elif "connection" in name.lower() or name.startswith(("Register ", "Prepare ", "Validate the host")):
            percent = max(percent, 10)
        elif name == "Rate what was read":
            percent = max(percent, 92)
        elif name.startswith(("Keep what was read", "Write job result", "Summary", "Save result")):
            percent = max(percent, 96)
        elif phase:
            inside += 1
        if phase and percent < 90:   # inside a phase: its share fills as its tasks run (never quite full)
            share = 80.0 / phases
            percent = max(percent, 10 + (phase - 1) * share + share * min(0.9, 0.15 + 0.15 * inside))
    current = next((words(n, phases) for n, st in reversed(items) if not n.startswith(HIDDEN)), "Starting")
    return {"percent": 100 if done else min(99, round(percent)), "current": "Done" if done else current,
            "steps": _shown(items, phases)}


def of_fix(lines, progress=None, done=False):
    items = tasks(lines)
    percent = 2.0
    if progress and progress.get("of"):
        total = int(progress["of"])
        finished = len(progress.get("done") or [])
        percent = 5 + 90.0 * (finished + (0.5 if progress.get("current") else 0)) / total
        cur = progress.get("current")
        current = f"Item {cur['n']} of {total}: {cur['label']}" if cur else f"{finished} of {total} items done"
    else:
        for name, _st in items:
            if name == "Validate input":
                percent = max(percent, 5)
            elif "connection" in name.lower() or name.startswith(("Register ", "Prepare ", "Validate the host")):
                percent = max(percent, 15)
            elif name.startswith(("Fix on ", "Start: ", "VyOS upgrade", "ONTAP fix")):
                percent = max(percent, 30)
            elif name.startswith(("Result of the", "Result: ")):
                percent = max(percent, 90)
        current = next((n for n, st in reversed(items) if not n.startswith(HIDDEN) and not INTERNAL.search(n)), "Starting")
    return {"percent": 100 if done else min(99, round(percent)), "current": "Done" if done else current,
            "steps": _shown(items, 1)}

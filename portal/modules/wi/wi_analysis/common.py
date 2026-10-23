"""Building blocks of an Operation Automation result: steps with a status, tables, evidence, recommendations, and parsers for the
command output the playbooks collect.

Result (what the playbook writes and the browser shows):
    {"ok": true, "status": "ok|warn|fail|skip", "summary": "...",
     "steps": [{"key", "title", "status", "detail", "table": {"columns": [...], "rows": [[...]]}, "evidence": "..."}],
     "recommendations": [{"text", "commands": [...], "warning", "where"}],
     "screens": [...]}   (added by wi_analysis.analyze: "Where to look", see wi_analysis/screens.py)
"ok" only says the check ran; problems found are in "status".
"""
import json
import re

ORDER = {"fail": 3, "warn": 2, "ok": 1, "info": 0, "skip": 0}
MAX_ROWS = 200
MAX_PICK_ROWS = 2000   # the items of a fix the operator ticks are all shown (each row is one item to tick)
MAX_EVIDENCE = 6000


class Result:
    def __init__(self, check_id):
        self.check_id = check_id
        self.steps = []
        self.recommendations = []
        self.facts = {}

    def step(self, key, title, status, detail="", table=None, evidence=None, marks=None):
        """marks: text that shows this step's finding in the command output (the lines marked on the terminal of
        "Where to look"); without it the lines are found from the values in the detail."""
        if status not in ORDER:
            raise ValueError(f"unknown step status {status}")
        item = {"key": key, "title": title, "status": status, "detail": str(detail or "")}
        if marks:
            item["marks"] = [str(m) for m in marks if m][:5]
        if table and table.get("rows"):
            rows = table["rows"]
            item["table"] = {"columns": list(table["columns"]), "rows": [[cell(v) for v in r] for r in rows[:MAX_ROWS]],
                             "more": max(0, len(rows) - MAX_ROWS)}
        if evidence:
            text = evidence if isinstance(evidence, str) else "\n".join(str(x) for x in evidence)
            item["evidence"] = text if len(text) <= MAX_EVIDENCE else text[:MAX_EVIDENCE] + "\n… (truncated)"
        self.steps.append(item)
        return item

    def skip(self, key, title, reason):
        return self.step(key, title, "skip", reason)

    def recommend(self, text, commands=None, warning="", where="", action=None, items=None, refs=None):
        """A fix for a finding: what to do, the commands with the values found (never placeholders when the value is
        known), where to run them, and what to watch out for. The first sentence of text is its title (shown bold);
        keep names, IDs and lists out of the text: items ({"columns", "rows"}) is a table shown under it, and a
        command's trailing "   # comment" is shown beside the command.
        action: what the portal may run for this fix (button "Run this fix", see modules/wi/fixes.py):
          {"commands": [...], "shell": "sh"|"vyos", "risk": "high"|"normal" (default: from the commands)} on the host of
          the check, or {"kind": "ontap", ...}. Only exact commands that can run unattended; checks of other places,
          tests from another machine and interactive steps stay out of it.
        refs: keys of wi_analysis.references (the vendor documentation of this problem: Red Hat, Broadcom, Lenovo...),
          or {"vendor", "title", "url"} items; unknown keys are ignored."""
        item = {"text": text, "commands": [c for c in (commands or []) if c], "warning": warning, "where": where}
        if refs:
            from .references import resolve
            found = resolve(refs)
            if found:
                item["references"] = found
        if items and items.get("rows"):
            rows = items["rows"]
            cap = MAX_PICK_ROWS if (action or {}).get("select") else MAX_ROWS
            item["items"] = {"columns": list(items["columns"]), "rows": [[cell(v) for v in r] for r in rows[:cap]],
                             "more": max(0, len(rows) - cap)}
        if action:
            item["action"] = dict(action, commands=[c for c in (action.get("commands") or []) if c])
        self.recommendations.append(item)

    def status(self):
        rated = [s["status"] for s in self.steps if s["status"] in ("ok", "warn", "fail")]
        if not rated:
            return "skip"
        return max(rated, key=lambda s: ORDER[s])

    def done(self, summary=""):
        status = self.status()
        if not summary:
            problems = [s["title"] for s in self.steps if s["status"] in ("fail", "warn")]
            summary = ({"ok": "No problem found.", "skip": "Nothing could be checked (see the skipped steps)."}.get(status)
                       or f"{len(problems)} finding{'s' if len(problems) != 1 else ''}: " + "; ".join(problems))
        return {"ok": True, "check": self.check_id, "status": status, "summary": summary, "steps": self.steps,
                "recommendations": self.recommendations, "facts": self.facts}


def cell(value):
    if value is None:
        return ""
    if isinstance(value, float):
        return f"{value:.1f}"
    return value if isinstance(value, (int, str)) else str(value)


def worst(*statuses):
    return max(statuses, key=lambda s: ORDER.get(s, 0)) if statuses else "ok"


def level(value, warn, fail):
    """'fail' when value >= fail, 'warn' when >= warn, else 'ok' (None = 'skip')."""
    if value is None:
        return "skip"
    return "fail" if value >= fail else "warn" if value >= warn else "ok"


# ---------------- raw data collected by the playbooks ----------------
def source(data, key):
    """One collected item: {"rc", "out"} (command), {"status", "json"} (REST), or {"skipped": reason}. Missing = skipped."""
    item = (data or {}).get(key)
    return item if isinstance(item, dict) else {"skipped": f"{key} was not collected"}


def unavailable(item):
    """Reason why an item cannot be used ('' when it can)."""
    if item.get("skipped"):
        return str(item["skipped"])
    if "rc" in item and item.get("rc") not in (0, "0"):
        lines = [l.strip() for l in str(item.get("out") or "").splitlines() if l.strip()]
        if lines and lines[0].startswith("Traceback"):   # a Python error: its last line names the exception
            return f"command failed (exit {item.get('rc')}): {lines[-1][:300]}"
        return f"command failed (exit {item.get('rc')}): {first_line(item.get('out'))}"
    if "status" in item and item.get("status") not in (200, "200"):
        return f"HTTP {item.get('status') or 'no answer'}: {item.get('msg') or first_line(item.get('body'))}"
    return ""


def first_line(text, limit=300):
    for line in str(text or "").splitlines():
        if line.strip():
            return line.strip()[:limit]
    return ""


def text_of(item):
    return str(item.get("out") or "")


def extract_json(text):
    """The first JSON value in text (CLI output can carry warnings before or after it). None when there is none."""
    text = str(text or "")
    decoder = json.JSONDecoder()
    for match in re.finditer(r"[\[{]", text):
        try:
            value, _ = decoder.raw_decode(text[match.start():])
            return value
        except ValueError:
            continue
    return None


def json_of(item):
    if "json" in item:
        return item["json"]
    return extract_json(text_of(item))


# ---------------- parsers ----------------
def parse_df(text):
    """`df -P` / `df -Pk` lines -> [{"fs", "size_kb", "used_kb", "avail_kb", "pct", "mount"}]."""
    rows = []
    for line in str(text or "").splitlines():
        parts = line.split()
        if len(parts) >= 6 and parts[4].endswith("%") and parts[1].isdigit():
            rows.append({"fs": parts[0], "size_kb": int(parts[1]), "used_kb": int(parts[2]), "avail_kb": int(parts[3]),
                         "pct": int(parts[4].rstrip("%")), "mount": " ".join(parts[5:])})
    return rows


def kib(n):
    """Human size from KiB."""
    return human(int(n or 0) * 1024)


def human(n):
    n = float(n or 0)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if abs(n) < 1024 or unit == "PiB":
            return f"{n:.0f} {unit}" if unit in ("B", "KiB") else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PiB"


def parse_size(text):
    """'141G', '961M', '44G', '1.2T', '512K', '700' (KiB) -> bytes."""
    m = re.match(r"^\s*([0-9.]+)\s*([KMGTP]?)i?B?\s*$", str(text or ""), re.I)
    if not m:
        return None
    factor = {"": 1024, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4, "P": 1024 ** 5}[m.group(2).upper()]
    return int(float(m.group(1)) * factor)


def property_tables(text):
    """`cinder get-pools --detail` style output: several "| Property | Value |" tables -> list of dicts."""
    tables, current = [], None
    for line in str(text or "").splitlines():
        line = line.strip()
        if not line.startswith("|"):
            if line.startswith("+") and current is not None and current.get("_closed_header"):
                pass
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 2:
            continue
        key, value = cells[0], "|".join(cells[1:]).strip()
        if key == "Property" and value == "Value":
            current = {}
            tables.append(current)
            continue
        if current is not None and key:
            current[key] = value
    return tables


def to_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def pct(part, whole):
    part, whole = to_float(part), to_float(whole)
    if part is None or not whole:
        return None
    return round(part * 100.0 / whole, 1)


def lines(text):
    return [l.rstrip() for l in str(text or "").splitlines() if l.strip()]


def director(ctx):
    return f"OpenStack director of {ctx.get('site') or 'the site'}, as stack after: source ~/overcloudrc"


def on_host(ctx):
    name, address = ctx.get("host_name"), ctx.get("host_address")
    return f"{name} ({address})" if name and address and name != address else (name or address or "the host")

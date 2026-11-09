"""Where to look: the screens an engineer opens to see what a check saw, drawn with the values of this run.

  - terminal  the commands the check ran on the host, the network device or the director, with their output
  - horizon   the OpenStack dashboard of RHOSP (Red Hat theme, PatternFly 3)
  - vcd       vCloud Director (tenant portal of the organization, or the provider portal), NSX-T backed edges
  - vsphere   vSphere Client (inventory tree, object tabs)
  - nsx       NSX Manager
  - ontap     ONTAP System Manager

Numbered marks point at what the check found; the notes under a screen say what each mark means and what to do there.
Everything comes from the data the check read (nothing is invented); passwords, keys and secrets in command output are
masked. Drawn by static/wi.js (Screens).

A screen: {"key", "label", "app", "status", "chrome": {...}, "blocks": [...], "notes": [{"n", "tone", "text"}], "after"?}
  after: the same screen as it looks once How to fix it is done (values from the fix: the new IP, the new rule, the new
  quota, the LIF on its home port...), so the reader learns what changes and what "fixed" looks like.
  blocks: {"type": "terminal", "command", "lines": [{"t", "n"?, "tone"?} | {"gap": count}], "rc"?, "skipped"?}
          {"type": "grid", "title"?, "columns", "rows", "marks": {row: {"n", "tone"}}, "toolbar"?, "footer"?}
          {"type": "props", "title"?, "items": [{"label", "value", "mark"?}]}
          {"type": "meters", "title"?, "items": [{"label", "text", "pct", "mark"?}]}
  A mark: {"n", "tone"} with tone danger | warning | success | info.
"""
import copy
import json
import re
import shlex

from .common import json_of, source, text_of, unavailable

MAX_SCREENS = 9
MAX_ROWS = 40
MAX_LINE = 180
TONE = {"fail": "danger", "warn": "warning", "ok": "success", "info": "info", "skip": "info"}
ORDER = {"danger": 3, "warning": 2, "success": 1, "info": 0}


def clip(value, limit=MAX_LINE):
    text = str(value if value is not None else "")
    return text if len(text) <= limit else text[:limit - 1] + "…"


# ------------------------------------------------------------------------------------------------- building blocks
class Screen:
    def __init__(self, key, label, app, **chrome):
        self.key, self.label, self.app = key, label, app
        self.chrome = {k: v for k, v in chrome.items() if v not in (None, "", [], {})}
        self.blocks, self.notes = [], []
        self.after = None

    def twin(self):
        """The "after the fix" view of this screen: same place, blocks and notes of its own."""
        self.after = Screen(self.key, self.label, self.app, **copy.deepcopy(self.chrome))
        return self.after

    def mark(self, tone, text):
        """A numbered mark and its note (the same note keeps its number); None when there is nothing to say."""
        if not tone or not text:
            return None
        text = clip(text, 420)
        for n in self.notes:
            if n["text"] == text and n["tone"] == tone:
                return {"n": n["n"], "tone": tone}
        self.notes.append({"n": len(self.notes) + 1, "tone": tone, "text": text})
        return {"n": len(self.notes), "tone": tone}

    def grid(self, columns, rows, marks=None, title="", toolbar=None, footer="", empty="No items to display.", select="",
             count="", link_col=0, row_action="", filter=False, per_page=False, row_action_danger=False, menu=None):
        """A table of the console. select: "radio" | "checkbox" column; count: the footer noun ("rules", "NIC(s)");
        link_col: the column shown as a link (-1: none); row_action: the button of the Actions column (Horizon)."""
        marks = {i: m for i, m in (marks or {}).items() if m}
        rows = [list(r) for r in rows]
        keep = list(range(len(rows)))
        if len(rows) > MAX_ROWS:   # every marked row stays; the others fill up to MAX_ROWS in their order
            room = MAX_ROWS - len(marks)
            keep = sorted(set(marks) | set([i for i in range(len(rows)) if i not in marks][:max(room, 0)]))
        out_rows, out_marks = [], {}
        for new, old in enumerate(keep):
            out_rows.append([clip(c, 120) if c is not None else "" for c in rows[old]])
            if old in marks:
                out_marks[str(new)] = marks[old]
        self.blocks.append({"type": "grid", "title": title, "columns": [str(c) for c in columns], "rows": out_rows,
                            "marks": out_marks, "toolbar": [t for t in toolbar or [] if t],
                            "footer": footer or (f"{len(rows)} item{'s' if len(rows) != 1 else ''}" if rows else ""),
                            "empty": empty, "hidden": len(rows) - len(keep), "select": select, "count": count,
                            "link_col": link_col, "row_action": row_action, "filter": filter, "per_page": per_page, "total": len(rows),
                            "row_action_danger": row_action_danger, "menu": menu})

    def props(self, items, title="", edit=False):
        self.blocks.append({"type": "props", "title": title, "edit": edit,
                            "items": [{"label": i[0], "value": clip(i[1], 200), "mark": i[2] if len(i) > 2 else None}
                                      for i in items if i and i[1] not in (None, "")]})

    def cards(self, cards, count=""):
        """Cards of a list (vCloud: Virtual Machines)."""
        self.blocks.append({"type": "cards", "cards": cards, "count": count})

    def stack(self, blocks, toolbar=None):
        """A stack view: sections with a header and label / value rows (vCloud: Allocation)."""
        self.blocks.append({"type": "stack", "blocks": blocks, "toolbar": [t for t in toolbar or [] if t]})

    def meters(self, items, title=""):
        self.blocks.append({"type": "meters", "title": title, "items": [i for i in items if i]})

    def dict(self):
        tones = [n["tone"] for n in self.notes]
        status = max(tones, key=lambda t: ORDER.get(t, 0)) if tones else "info"
        out = {"key": self.key, "label": self.label, "app": self.app, "status": status, "chrome": self.chrome,
               "blocks": self.blocks, "notes": self.notes}
        if self.after is not None and self.after.blocks:
            out["after"] = self.after.dict()
        return out


def button(label, mark=None, primary=False, style="", disabled=False, icon=""):
    return {"label": label, "mark": mark, "primary": primary, "style": style or ("primary" if primary else ""), "disabled": disabled,
            "icon": icon}


def meter(label, used, total, unit="", mark=None, text=""):
    try:
        p = round(float(used) * 100 / float(total), 1) if float(total) > 0 else None
    except (TypeError, ValueError):
        p = None
    return {"label": label, "pct": p, "text": text or f"Used {used}{unit} of {total}{unit}", "mark": mark}


class View:
    """What a builder needs: the data read, the parameters, the site context and the result (steps by key, fixes)."""

    def __init__(self, data, params, ctx, result):
        self.data, self.params, self.ctx, self.result = data or {}, params or {}, ctx or {}, result or {}
        self.steps = {}
        for s in self.result.get("steps") or []:
            self.steps.setdefault(s.get("key"), s)
        self.recs = self.result.get("recommendations") or []

    def step(self, key):
        return self.steps.get(key) or {}

    def tone(self, key):
        return TONE.get(self.step(key).get("status"), "")

    def problem(self, key):
        return self.step(key).get("status") in ("fail", "warn")

    def said(self, key):
        """'<title>: <detail>' of a step, for a note."""
        s = self.step(key)
        return f"{s.get('title')}: {s.get('detail')}" if s else ""

    def json(self, key):
        return json_of(source(self.data, key))

    def rec(self, *words):
        """The first fix whose text, place and commands contain every word."""
        for r in self.recs:
            blob = " ".join([str(r.get("text")), str(r.get("where")), " ".join(map(str, r.get("commands") or []))])
            if all(w in blob for w in words):
                return r
        return None

    def rec_text(self, *words, prefix="How to fix it: "):
        r = self.rec(*words)
        return prefix + str(r.get("text")) if r else ""


def table(step):
    """(columns, rows) of a step's table."""
    t = (step or {}).get("table") or {}
    return t.get("columns") or [], t.get("rows") or []


def col(columns, name):
    return columns.index(name) if name in columns else None


# ------------------------------------------------------------------------------------------------- secrets
SECRET_WORD = re.compile(r"^['\"]?(encrypted-password|plaintext-password|pre-shared-secret|pre-shared-key|shared-secret|secret|"
                         r"password|passphrase|psk|community|authentication-key|md5-key|key-string|private-key|auth-key|"
                         r"cipher|irreversible-cipher)['\"]?$", re.I)
MODIFIER = {"cipher", "irreversible-cipher", "simple", "plain", "encrypted", "hash", "sha256", "md5", "read", "write", "0", "7", "5",
            "8", "9", "id"}
LOG_LINE = re.compile(r"\b(failed|accepted|invalid user|authentication failure|for user|session opened|session closed)\b", re.I)
KEY_VALUE = re.compile(r"((?:password|passwd|secret|token|api[_-]?key|private[_-]?key)\s*[=:]\s*)('[^']*'|\"[^\"]*\"|[^\s,;]+)", re.I)
SSH_KEY = re.compile(r"((?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-\S+)\s+|key\s+'?)(AAAA[0-9A-Za-z+/=]{16,})")
PEM = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)
HASH = re.compile(r"\$(?:1|5|6|y|1c|2[aby])\$[^\s'\":]{8,}|%\^%#[^\s]*%\^%#|%\$%\$[^\s]*%\$%\$")
URL_CREDENTIAL = re.compile(r"(\b[a-z][a-z0-9+.-]*://[^:/\s@]+:)[^@\s/]+@", re.I)   # rabbit://user:password@host


def mask_line(line):
    """A configuration line with its secret values masked: after a secret keyword (password, secret, pre-shared-key,
    community, cipher, ...) the next value that is not a modifier (cipher, simple, read, id <n>, ...) becomes ********."""
    parts = re.split(r"(\s+)", line)
    i, n = 0, len(parts)
    while i < n:
        if SECRET_WORD.match(parts[i] or ""):
            j = i + 1
            while j < n:
                tok = parts[j]
                if not tok or tok.isspace():
                    j += 1
                    continue
                bare = tok.strip("'\"").lower()
                if bare in MODIFIER or SECRET_WORD.match(tok):
                    j += 1
                    continue
                q = tok[0] if tok[0] in "'\"" else ""
                parts[j] = f"{q}********{q}"
                break
            i = j
        i += 1
    return "".join(parts)


def redact(text):
    """Command output without secrets: configuration lines keep their keywords, secret values become ********; PEM private
    keys, password hashes, Huawei cipher strings and SSH key material are masked everywhere (log lines stay readable)."""
    text = PEM.sub("-----BEGIN PRIVATE KEY----- ******** -----END PRIVATE KEY-----", str(text or ""))
    out = []
    for line in text.splitlines():
        if not LOG_LINE.search(line):
            line = mask_line(line)
        line = KEY_VALUE.sub(lambda m: m.group(1) + "********", line)
        line = SSH_KEY.sub(lambda m: m.group(1) + "AAAA…(key)", line)
        line = HASH.sub("********", line)
        line = URL_CREDENTIAL.sub(lambda m: m.group(1) + "********@", line)
        out.append(line)
    return "\n".join(out)


# ------------------------------------------------------------------------------------------------- terminal
TOKEN_RES = (
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"), 4),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b"), 3),
    (re.compile(r"(?<![\w./-])/(?:[\w.@*-]+/?)+"), 3),
    (re.compile(r"\b\d+(?:\.\d+)?\s?%"), 3),
    (re.compile(r"\b(?=[\w.:-]*\d)(?=[\w.:-]*[A-Za-z])[A-Za-z0-9][\w.:/-]*[A-Za-z0-9]\b"), 2),
)
WORD = re.compile(r"\b[A-Za-z][A-Za-z_-]{3,}\b")
STOP = set("""
about above after again also always another anything because been before being below between both cannot could does
doing down during each either else enough every from further have having here into itself just more most must need
none nothing only other over present same should since some such than that their them then there these they this
those through under until very were what when where which while with within without would your yours none found
absent missing used uses free full more less ok fail warn error none yes check checks step steps value values read
host hosts rule rules port ports service services line lines file files command commands output instance instances
volume volumes project projects network networks running number total last first given level after before every
""".split())


def tokens(text, ignore=()):
    found = {}
    for rx, weight in TOKEN_RES:
        for m in rx.finditer(text):
            t = m.group(0).strip(".,;:()[]'\"").rstrip("/")
            if len(t) >= 2 and t not in ignore:
                found[t] = max(found.get(t, 0), weight)
    for m in WORD.finditer(text):
        w = m.group(0)
        if w.lower() not in STOP and w not in ignore and w not in found:
            found[w] = 1
    return {t: (w, re.compile((r"(?<![\w.])" if w > 1 else r"(?<![\w])") + re.escape(t) + r"(?![\w])", 0 if w > 1 else re.I))
            for t, w in list(found.items())[:40]}


def score(line, toks):
    return sum(w for w, rx in toks.values() if rx.search(line))


def shown(source_name, cmd, root=False):
    """The command as an engineer types it: a VyOS op-mode command without the vbash wrapper; SUDO becomes sudo (or
    nothing when the account is root)."""
    cmd = str(cmd)
    if cmd.startswith("/opt/vyatta/bin/vyatta-op-cmd-wrapper "):
        cmd = cmd[len("/opt/vyatta/bin/vyatta-op-cmd-wrapper "):]
    if cmd.startswith("/bin/vbash -c "):
        try:
            inner = shlex.split(cmd)[2]
            cmd = inner.split("; run ", 1)[1] if "; run " in inner else inner
        except (IndexError, ValueError):
            pass
    return cmd.replace("SUDO ", "" if root else "sudo ")


def prompt_of(source_name, ctx):
    host = ctx.get("host_name") or "host"
    user = ctx.get("host_user") or "user"
    group = ctx.get("host_group") or ""
    if source_name == "openstack":
        director = ctx.get("director") or "director"
        return f"[stack@{director.split('.')[0]} ~]$", f"stack@{director} — director"
    if source_name == "device":
        return f"<{host}>", f"{user}@{host} — SSH"
    if source_name == "tcp":
        return "portal $", "Ops Portal server — TCP test"
    if group == "esxi":
        return f"[{user}@{host}:~]", f"{user}@{host} — ESXi Shell"
    if group == "vyos":
        return f"{user}@{host}:~$", f"{user}@{host} — VyOS"
    return f"{user}@{host}:~{'#' if user == 'root' else '$'}", f"{user}@{host} — SSH"


def cli_table(text, limit=48):
    """`openstack ... -f json` output as the default table of the openstack client (same data, the format an engineer
    sees when typing the command without -f json); other text unchanged. None when it is not JSON."""
    raw = str(text or "").strip()
    if not raw.startswith(("[", "{")):
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    if isinstance(data, dict):
        columns, rows = ["Field", "Value"], [[k, json.dumps(v) if isinstance(v, (dict, list)) else v] for k, v in data.items()]
    elif isinstance(data, list) and all(isinstance(x, dict) for x in data):
        columns = list(dict.fromkeys(k for x in data for k in x))[:8]
        rows = [[x.get(c, "") for c in columns] for x in data]
    else:
        return None
    rows = [["" if v is None else clip(v if isinstance(v, str) else json.dumps(v), limit) for v in r] for r in rows]
    widths = [max([len(str(c))] + [len(r[i]) for r in rows]) for i, c in enumerate(columns)]
    line = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    fmt = lambda cells: "| " + " | ".join(str(c).ljust(w) for c, w in zip(cells, widths)) + " |"
    return "\n".join([line, fmt(columns), line] + [fmt(r) for r in rows] + [line])


def step_tokens(st, ignore):
    """Values that show a step's finding: from its title, its detail and the first cells of its table rows."""
    text = f"{st.get('title') or ''} {st.get('detail') or ''}"
    toks = tokens(text, ignore)
    columns, rows = table(st)
    for r in rows[:5]:
        for cell in r[:2]:
            c = str(cell or "").strip()
            if len(c) >= 3 and c not in ignore and c not in toks and c not in ("-", "None", "none"):
                toks[c] = (3, re.compile(r"(?<![\w.])" + re.escape(c) + r"(?![\w])"))
    return toks


def terminal_recs(view, source_name):
    """The fixes that are typed on this terminal."""
    host = view.ctx.get("host_name") or ""
    out = []
    for r in view.recs:
        where = str(r.get("where") or "")
        if not r.get("commands"):
            continue
        if source_name == "openstack" and where.startswith("OpenStack director"):
            out.append(r)
        elif source_name in ("host", "device") and (r.get("action") or (host and host in where)) and "PowerCLI" not in where:
            out.append(r)
    return out


def terminals(view, commands):
    """One terminal per place the check ran commands: the commands with their (masked) output; the lines that show
    each step's finding carry the step's mark. Its "after" view: the commands of How to fix it, then what the check
    expects when it runs again."""
    ctx, data = view.ctx, view.data
    out = []
    labels = {"openstack": "Director (CLI)", "host": "Terminal", "device": "Device CLI", "tcp": "TCP test"}
    for source_name in ("openstack", "host", "device", "tcp"):
        items = [(k, c) for k, c in (commands.get(source_name) or {}).items() if k in data]
        if not items:
            continue
        prompt, title = prompt_of(source_name, ctx)
        s = Screen(f"term-{source_name}", labels[source_name] if source_name != "host" else f"Terminal {ctx.get('host_name') or ''}".strip(),
                   "terminal", title=title, prompt=prompt)
        blocks = []
        if source_name == "openstack":
            blocks.append({"command": "source ~/overcloudrc", "lines": []})
        for key, cmd in items:
            item = data.get(key) or {}
            if source_name == "tcp":
                target = str(cmd)
                hostport = target.rsplit(":", 1)
                command = f"nc -vz -w 5 {hostport[0]} {hostport[1] if len(hostport) > 1 else ''}".strip()
                if item.get("skipped"):
                    lines = [f"# not tested: {item['skipped']}"]
                elif item.get("ok"):
                    lines = [f"# {target} answered (TCP connect from the portal in {item.get('elapsed', '?')} s)"]
                else:
                    lines = [f"# {target} did not answer: {clip(item.get('msg') or 'timeout', 160)}"]
                blocks.append({"command": command, "lines": lines})
                continue
            command = shown(source_name, cmd, ctx.get("host_user") == "root")
            if item.get("skipped"):
                blocks.append({"command": command, "lines": [], "skipped": str(item["skipped"])[:200]})
                continue
            text = item.get("out") or ""
            as_table = cli_table(text) if source_name == "openstack" else None
            if as_table is not None:
                text, command = as_table, re.sub(r"\s+-f json\b", "", command)
            blocks.append({"command": command, "lines": redact(text).splitlines()[:4000], "rc": item.get("rc")})
        # marks: for every rated step, the lines of the outputs that show its finding
        ignore = {ctx.get("host_name") or "", ctx.get("host_address") or "", ctx.get("director") or "", ""}
        marked = {}
        rated = [st for st in view.result.get("steps") or [] if st.get("status") in ("fail", "warn", "ok")]
        rated.sort(key=lambda st: {"fail": 0, "warn": 1, "ok": 2}[st["status"]])
        for st in rated[:8]:
            toks = step_tokens(st, ignore)
            explicit = [m for m in st.get("marks") or [] if m]
            found = []
            for bi, b in enumerate(blocks):
                for li, line in enumerate(b["lines"]):
                    if (bi, li) in marked:
                        continue
                    sc = 99 if any(m in line for m in explicit) else score(line, toks) if toks else 0
                    if sc >= 3:
                        found.append((sc, bi, li))
            top = max((f[0] for f in found), default=0)
            if found and (st["status"] != "ok" or top >= 4):   # an OK step only marks a clear match
                best = [f for f in found if f[0] == top]
                m = s.mark(TONE[st["status"]], f"{st.get('title')}: {st.get('detail')}")
                for _, bi, li in sorted(best, key=lambda f: (-f[0], f[1], f[2]))[:3]:
                    marked[(bi, li)] = m
        for bi, b in enumerate(blocks):
            s.blocks.append(window(b, {li: m for (bj, li), m in marked.items() if bj == bi}))
        # after the fix: the commands of How to fix it, then the check again
        recs = terminal_recs(view, source_name)
        failed = [st for st in view.result.get("steps") or [] if st.get("status") in ("fail", "warn")]
        if recs and failed:
            t = s.twin()
            for r in recs:
                n = t.mark("info", f"{clip(r.get('text'), 300)}")
                for i, cmd in enumerate(r.get("commands") or []):
                    t.blocks.append({"type": "terminal", "command": str(cmd), "lines": [], "mark": n if i == 0 else None})
            done = t.mark("success", "Then run this check again from the portal: these steps must be OK — "
                          + "; ".join(st.get("title") for st in failed[:6]) + ".")
            t.blocks.append({"type": "terminal", "command": "# Operation Automation → Run again",
                             "lines": [dict({"t": f"OK  {st.get('title')}"}, **done) for st in failed[:6]]})
        out.append(s)
    return out


def window(b, marks):
    """A terminal block with the lines that matter: all of a short output; of a long one the first lines and the
    marked lines with two lines around them (gaps counted)."""
    lines = b["lines"]
    if len(lines) <= 28:
        keep = set(range(len(lines)))
    else:
        keep = set(range(4)) | {i for li in marks for i in range(li - 2, li + 3) if 0 <= i < len(lines)}
        if not marks:
            keep |= set(range(min(12, len(lines))))
    shown_lines, last = [], -1
    for li in sorted(keep):
        if li - last > 1:
            shown_lines.append({"gap": li - last - 1})
        entry = {"t": clip(lines[li])}
        if li in marks and marks[li]:
            entry.update(marks[li])
        shown_lines.append(entry)
        last = li
    if lines and last < len(lines) - 1:
        shown_lines.append({"gap": len(lines) - 1 - last})
    block = {"type": "terminal", "command": b["command"], "lines": shown_lines}
    if b.get("skipped"):
        block["skipped"] = b["skipped"]
    if b.get("rc") not in (None, 0):
        block["rc"] = b["rc"]
    return block


# ------------------------------------------------------------------------------------------------- OpenStack: Horizon (RHOSP)
# Horizon of RHOSP (RCUE theme): dashboards in the utility bar, panel groups in the dark bar, panels in the light bar.
# Menus, columns, buttons and detail sections as read on the RHOSP dashboard of the site.
HZ_GROUPS = {"Project": ["Project", "Compute", "Volumes", "Network", "Orchestration", "Share"],
             "Admin": ["Overview", "Compute", "Volume", "Network", "System"],
             "Identity": ["Identity"]}
HZ_PANELS = {("Project", "Compute"): ["Overview", "Instances", "Images", "Key Pairs", "Server Groups"],
             ("Project", "Volumes"): ["Volumes", "Snapshots", "Groups", "Group Snapshots"],
             ("Project", "Network"): ["Network Topology", "Networks", "Routers", "Security Groups", "Load Balancers", "Floating IPs", "Trunks"],
             ("Admin", "Compute"): ["Hypervisors", "Host Aggregates", "Instances", "Flavors", "Images"],
             ("Admin", "Volume"): ["Volumes", "Snapshots", "Volume Types", "Groups", "Group Snapshots", "Group Types"],
             ("Admin", "Network"): ["Networks", "Routers", "Floating IPs", "RBAC Policies"],
             ("Admin", "System"): ["Defaults", "Metadata Definitions", "System Information"],
             ("Identity", "Identity"): ["Projects", "Users", "Groups", "Roles", "Application Credentials"]}
HZ_URL = {("Project", "Compute", "Overview"): "/dashboard/project/", ("Project", "Compute", "Instances"): "/dashboard/project/instances/",
          ("Project", "Network", "Security Groups"): "/dashboard/project/security_groups/",
          ("Admin", "Compute", "Instances"): "/dashboard/admin/instances/", ("Admin", "Volume", "Volumes"): "/dashboard/admin/volumes/",
          ("Admin", "Volume", "Volume Types"): "/dashboard/admin/volume_types/", ("Identity", "Identity", "Projects"): "/dashboard/identity/"}
PORT_NAMES = {"20": "FTP-DATA", "21": "FTP", "22": "SSH", "25": "SMTP", "53": "DNS", "80": "HTTP", "110": "POP3", "143": "IMAP",
              "389": "LDAP", "443": "HTTPS", "445": "SMB", "465": "SMTPS", "587": "SMTP", "993": "IMAPS", "995": "POP3S",
              "1433": "MS SQL", "3306": "MYSQL", "3389": "RDP", "5432": "POSTGRESQL"}


def horizon(key, label, view, path, title, crumbs=None, tabs=None, tab="", detail=False, detail_action="", detail_mark=None, url=""):
    dashboard, group, panel = (list(path) + ["", "", ""])[:3]
    return Screen(key, label, "horizon", host=view.ctx.get("horizon_host") or "", url=url or HZ_URL.get(tuple(path), "/dashboard/"),
                  user="admin", dashboard=dashboard, groups=HZ_GROUPS.get(dashboard, []), group=group,
                  panels=HZ_PANELS.get((dashboard, group), []), panel=panel,
                  crumbs=crumbs or [x for x in ([dashboard] + ([group] if group != dashboard else []) + [panel]) if x],
                  title=title, tabs=tabs, tab=tab, detail=detail, detail_action=detail_action, detail_mark=detail_mark)


def hz_port(spec):
    """Port range as Horizon shows it: 'Any', '443 (HTTPS)', '1 - 65535'."""
    spec = str(spec or "").strip()
    if spec.lower() in ("", "any", "none", "-"):
        return "Any"
    lo, _, hi = spec.replace(":", "-").partition("-")
    lo, hi = lo.strip(), hi.strip()
    if not hi or hi == lo:
        return f"{lo} ({PORT_NAMES[lo]})" if lo in PORT_NAMES else lo
    return f"{lo} - {hi}"


def hz_age(text):
    """'95 min' -> '1 hour, 35 minutes' (Horizon's Age)."""
    m = re.match(r"^(\d+)", str(text or ""))
    if not m:
        return "-"
    mins = int(m.group(1))
    days, rest = divmod(mins, 1440)
    hours, minutes = divmod(rest, 60)
    parts = [f"{v} {u}{'s' if v != 1 else ''}" for v, u in ((days, "day"), (hours, "hour"), (minutes, "minute")) if v][:2]
    return ", ".join(parts) or "0 minutes"


def hz_status(text):
    s = str(text or "").replace("_", " ")
    return {"in-use": "In-use", "error": "Error", "available": "Available"}.get(s.lower(), s[:1].upper() + s[1:].lower())


def hz_volume_rows(view, ids):
    from .openstack import cinder_volumes
    vols = {v["id"]: v for v in cinder_volumes(source(view.data, "volumes"))}
    return [vols[i] for i in ids if i in vols]


def project_name(view, pid):
    """Horizon shows the project name; the commands give the ID (openstack project list when it was read)."""
    names = {str(x.get("ID") or x.get("id")): x.get("Name") or x.get("name") for x in (view.json("projects") or []) if isinstance(x, dict)} \
        if isinstance(view.json("projects"), list) else {}
    return names.get(str(pid), pid)


def rec_commands(view):
    return [str(c) for r in view.recs for c in r.get("commands") or []]


ADMIN_VOL_COLS = ["Project", "Host", "Name", "Size", "Status", "Group", "Type", "Attached To", "Bootable", "Encrypted"]
ADMIN_VOL = dict(select="checkbox", row_action="Update Volume Status", filter="Volume Name =", link_col=2,
                 toolbar=[{"label": "Manage Volume"}, {"label": "Delete Volumes", "style": "danger", "icon": "trash", "disabled": True}])


def admin_vol_row(project, host, name, size, status, vtype, attached="-", bootable="-"):
    size = f"{int(float(size))}GiB" if str(size).replace(".", "", 1).isdigit() else (size or "-")
    return [project or "-", host or "-", name or "-", size, hz_status(status), "-", vtype or "-", attached or "-", bootable, "No"]


def admin_vol(view, project, *rest):
    return admin_vol_row(project_name(view, project), *rest)


def os_cinder_pool_usage(view):
    out = []
    columns, rows = table(view.step("volumes"))
    if rows:   # Pool, Volume, ID, Size, Status, Project
        vols = {v["id"]: v for v in hz_volume_rows(view, [r[2] for r in rows])}
        moves = {}
        for c in rec_commands(view):
            m = re.search(r"cinder migrate (\S+) '?([^'\s]+)'?", c)
            if m:
                moves[m.group(1)] = m.group(2)
        s = horizon("hz-volumes", "Horizon: Volumes", view, ("Admin", "Volume", "Volumes"), "Volumes")
        a = s.twin() if moves else None
        marks, grid, arows, amarks = {}, [], [], {}
        for i, r in enumerate(rows):
            v = vols.get(r[2]) or {}
            row = admin_vol(view, r[5], v.get("host") or f"…#{r[0]}", r[1], v.get("size") or r[3], v.get("status") or r[4], v.get("type"))
            grid.append(row)
            if r[2] in moves:
                marks[i] = s.mark("warning", f"{r[1]}: Actions ▾ → Migrate Volume → Destination Host {moves[r[2]]} (How to fix it), so its pool "
                                             "goes below 80%.")
                arows.append(row[:1] + [moves[r[2]]] + row[2:])
                amarks[i] = a.mark("success", f"{r[1]} is now on {moves[r[2]].split('#')[-1]} (Host column).")
            else:
                arows.append(row)
        s.grid(ADMIN_VOL_COLS, grid, marks, **ADMIN_VOL)
        if a:
            a.grid(ADMIN_VOL_COLS, arows, amarks, **ADMIN_VOL)
            a.mark("success", "Run the check again: the pool of the alert is below 80% (cinder get-pools / System Manager).")
        out.append(s)
    body = view.json("flexvols")
    flexvols = [v for v in (body.get("records") or []) if isinstance(v, dict)] if isinstance(body, dict) else []
    pcols, prows = table(view.step("pools"))
    if flexvols and prows:
        bad = {r[0]: r[-1] for r in prows if str(r[-1]).upper() in ("FAIL", "WARN")}
        s = ontap_screen("sm-volumes", "System Manager: Volumes", view, "Storage/Volumes", "Volumes")
        marks, grid = {}, []
        for i, v in enumerate(sorted(flexvols, key=lambda x: str(x.get("name")))):
            sp = v.get("space") or {}
            used, size = sp.get("used") or 0, sp.get("size") or 0
            p = round(used * 100 / size, 1) if size else None
            grid.append([v.get("name"), (v.get("svm") or {}).get("name", ""), str(v.get("state", "")).capitalize(), human_b(size),
                         f"{p}%" if p is not None else "-"])
            pool = next((name for name in bad if name and (name == v.get("name") or name.endswith(str(v.get("name"))))), None)
            if pool:
                marks[i] = s.mark("danger" if str(bad[pool]).upper() == "FAIL" else "warning",
                                  f"{v.get('name')}: {p}% used — the Cinder pool {pool} of the alert.")
        s.grid(["Name", "Storage VM", "Status", "Capacity", "Used %"], grid, marks, toolbar=[button("+ Add", primary=True)])
        out.append(s)
    return out


def os_volume_type_legacy(view):
    out = []
    columns, rows = table(view.step("volumes"))
    if rows:   # Volume, ID, Type, Change to, Size, Status, Project
        vols = {v["id"]: v for v in hz_volume_rows(view, [r[1] for r in rows])}
        s = horizon("hz-volumes", "Horizon: Volumes", view, ("Admin", "Volume", "Volumes"), "Volumes")
        a = s.twin()
        marks, grid, amarks, agrid = {}, [], {}, []
        for i, r in enumerate(rows):
            v = vols.get(r[1]) or {}
            grid.append(admin_vol(view, r[6], v.get("host"), r[0], r[4], r[5], r[2]))
            agrid.append(admin_vol(view, r[6], v.get("host"), r[0], r[4], r[5], r[3]))
            marks[i] = s.mark("warning", f"Type {r[2]} is an old type: Project → Volumes → {r[0]} → Actions ▾ → Change Volume Type → {r[3]}, "
                                         "Migration Policy On Demand.")
            amarks[i] = a.mark("success", f"Type {r[3]}: the retype is done (status back to {hz_status(r[5])}).")
        s.grid(ADMIN_VOL_COLS, grid, marks, **ADMIN_VOL)
        a.grid(ADMIN_VOL_COLS, agrid, amarks, **ADMIN_VOL)
        out.append(s)
    types = view.json("types")
    if isinstance(types, list) and types:
        from .openstack import DEFAULT_LEGACY_TYPES
        legacy = view.ctx.get("legacy_volume_types") or DEFAULT_LEGACY_TYPES
        s = horizon("hz-types", "Horizon: Volume Types", view, ("Admin", "Volume", "Volume Types"), "Volume Types")
        marks, grid = {}, []
        for i, t in enumerate(x for x in types if isinstance(x, dict)):
            name = t.get("Name") or t.get("name")
            grid.append([name, t.get("Description") or "-", "-", "No", "True" if t.get("Is Public", True) else "False"])
            if name in legacy:
                marks[i] = s.mark("warning", f"{name}: old type, change its volumes to {legacy[name]}.")
            elif name in legacy.values():
                marks[i] = s.mark("success", f"{name}: the type to change to.")
        s.grid(["Name", "Description", "Associated QoS Spec", "Encryption", "Public"], grid, marks, select="checkbox",
               row_action="Create Encryption",
               toolbar=[{"label": "Create Volume Type", "icon": "plus"}, {"label": "Delete Volume Types", "style": "danger", "icon": "trash", "disabled": True}])
        out.append(s)
    return out


def number(text):
    m = re.search(r"-?\d+(?:\.\d+)?", str(text or ""))
    return float(m.group(0)) if m else None


QUOTA_GROUP = {"Compute": ["Instances", "vCPU", "RAM"], "Volume": ["Volumes", "Snapshots", "Volume storage"],
               "Network": ["Floating IPs", "Security Groups", "Security Group Rules", "Networks", "Ports", "Routers"]}
QUOTA_LABEL = {"vCPU": "VCPUs", "Volume storage": "Volume Storage", "Snapshots": "Volume Snapshots"}


def os_project_quota(view):
    body = view.json("project")
    project = body if isinstance(body, dict) else {}
    pname = project.get("name") or view.params.get("project") or "the project"
    raised = {}
    for c in rec_commands(view):
        m = re.search(r"#\s*([^:]+):\s*(.+?)\s*→\s*(.+)$", c)
        if m and "quota set" in c:
            raised[m.group(1).strip()] = m.group(3).strip()
    rows = {}
    for key in list(view.steps):
        columns, trows = table(view.step(key))
        if columns[:3] == ["Resource", "In use", "Quota"]:
            rows.update({r[0]: r for r in trows})
    if not rows:
        return []
    out = []
    s = horizon("hz-overview", "Horizon: Overview", view, ("Project", "Compute", "Overview"), "Overview")
    s.mark("info", f"Project ▾ (top right) → {pname}: the Overview shows the quota of the selected project.")
    a = s.twin() if raised else None
    gb = lambda x: str(x).replace(" GiB", "GB")
    for group, labels in QUOTA_GROUP.items():
        items, after = [], []
        for label in labels:
            r = rows.get(label)
            if not r or r[2] in ("-", "unlimited"):
                continue
            status = str(r[4]).lower()
            name = QUOTA_LABEL.get(label, label)
            verb = "Allocated" if label == "Floating IPs" else "Used"
            m = s.mark(TONE.get(status, ""), f"{name}: {r[1]} of {r[2]} — an administrator raises it: Identity → Projects → {pname} → "
                       "Manage Members ▾ → Modify Quotas.") if status in ("fail", "warn") else None
            items.append({"label": name, "pct": number(r[3]), "text": f"{verb} {gb(r[1])} of {gb(r[2])}", "mark": m})
            if a is not None:
                if label in raised:
                    used, new = number(r[1]), number(raised[label])
                    p = round(used * 100 / new, 1) if used is not None and new else None
                    after.append({"label": name, "pct": p, "text": f"{verb} {gb(r[1])} of {gb(raised[label])}",
                                  "mark": a.mark("success", f"{name}: quota {r[2]} → {raised[label]}.")})
                else:
                    after.append({"label": name, "pct": number(r[3]), "text": f"{verb} {gb(r[1])} of {gb(r[2])}", "mark": None})
        if items:
            s.meters(items, title=group)
            if a is not None:
                a.meters(after, title=group)
    out.append(s)
    if raised or any(str(r[4]).lower() in ("fail", "warn") for r in rows.values()):
        p = horizon("hz-projects", "Horizon: Modify Quotas", view, ("Identity", "Identity", "Projects"), "Projects")
        m = p.mark("info", f"Where the quota is raised: Identity → Projects → {pname} → Manage Members ▾ → Modify Quotas (administrator), "
                           "with the values of How to fix it.")
        p.grid(["Name", "Description", "Project ID", "Domain Name", "Enabled"],
               [[pname, project.get("description") or "-", project.get("id") or "-", project.get("domain_id") or "Default", "Yes"]],
               {0: m}, select="checkbox", row_action="Manage Members", filter="Project Name =",
               toolbar=[{"label": "Create Project", "icon": "plus"}, {"label": "Delete Projects", "style": "danger", "icon": "trash", "disabled": True}],
               menu={"row": 0, "items": ["Manage Members", "Modify Groups", "Edit Project", "View Usage", "Modify Quotas", "Delete Project"],
                     "active": "Modify Quotas", "mark": m})
        out.append(p)
    return out


def os_stuck_resources(view):
    out = []
    srows = []
    for key in ("build", "error"):
        columns, rows = table(view.step(key))
        srows += [(key, r) for r in rows]   # Instance, ID, Compute, Age, Project, Fault
    cols = ["Project", "Host", "Name", "Image Name", "IP Address", "Flavor", "Status", "Task", "Power State", "Age"]
    kw = dict(select="checkbox", row_action="Edit Instance", filter="Project Name =", link_col=2,
              toolbar=[{"label": "Delete Instances", "style": "danger", "icon": "trash", "disabled": True}])
    if srows:
        s = horizon("hz-instances", "Horizon: Instances", view, ("Admin", "Compute", "Instances"), "Instances")
        marks, grid = {}, []
        for i, (key, r) in enumerate(srows):
            grid.append([project_name(view, r[4]), r[2] if r[2] not in ("-", "", None) else "-", r[0], "-", "-", "-", "Build" if key == "build" else "Error",
                         "Spawning" if key == "build" else "None", "No State", hz_age(r[3])])
            marks[i] = s.mark(view.tone(key), f"{r[0]}: " + ("in BUILD for " + hz_age(r[3]) if key == "build" else "ERROR")
                              + (f" — {r[5]}" if r[5] else ""))
        s.grid(cols, grid, marks, **kw)
        a = s.twin()
        a.grid(cols, [], {}, empty="No items to display.", **kw)
        a.mark("success", "After How to fix it, none of these instances stays in BUILD or ERROR: each one is Active again or "
                          "deleted and created again, as agreed with the customer.")
        out.append(s)
    vrows = []
    for key in ("volumes", "volume_errors", "migration"):
        columns, rows = table(view.step(key))
        vrows += [(key, r) for r in rows]   # Volume, ID, Status, Migration, Since update, Project
    if vrows:
        states = {}
        for c in rec_commands(view):
            m = re.search(r"reset-state --state (\S+).*?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", c)
            if m:
                states.setdefault(m.group(2), m.group(1))
        s = horizon("hz-volumes", "Horizon: Volumes", view, ("Admin", "Volume", "Volumes"), "Volumes")
        a = s.twin() if states else None
        vols = {v["id"]: v for v in hz_volume_rows(view, [r[1] for _, r in vrows])}
        marks, grid, amarks, agrid = {}, [], {}, []
        for i, (key, r) in enumerate(vrows):
            v = vols.get(r[1]) or {}
            row = admin_vol(view, r[5], v.get("host"), r[0], v.get("size"), r[2], v.get("type"))
            grid.append(row)
            marks[i] = s.mark(view.tone(key), f"{r[0]}: {r[2]}" + (f", migration {r[3]}" if r[3] not in ("-", "") else "")
                              + f", unchanged for {hz_age(r[4])} — Actions ▾ Update Volume Status only after checking the real state.")
            if a is not None:
                if r[1] in states:
                    agrid.append(row[:4] + [hz_status(states[r[1]])] + row[5:])
                    amarks[len(agrid) - 1] = a.mark("success", f"{r[0]}: {hz_status(states[r[1]])} again (cinder reset-state of How to fix it).")
                else:
                    agrid.append(row)
        s.grid(ADMIN_VOL_COLS, grid, marks, **ADMIN_VOL)
        if a is not None:
            a.grid(ADMIN_VOL_COLS, agrid, amarks, **ADMIN_VOL)
        out.append(s)
    return out


def os_volume_attach(view):
    vol = view.json("volume") or {}
    if not isinstance(vol, dict) or not vol:
        return []
    name = vol.get("name") or vol.get("id")
    s = horizon("hz-volume", "Horizon: Volume details", view, ("Admin", "Volume", "Volumes"), name,
                crumbs=["Admin", "Volume", "Volumes", name], tabs=["Overview", "Snapshots", "Messages"], tab="Overview",
                detail=True, detail_action="Update Volume Status", url=f"/dashboard/admin/volumes/{vol.get('id')}/")
    status_mark = s.mark(view.tone("volume"), view.said("volume")) if view.problem("volume") else None
    columns, rows = table(view.step("attachments"))
    att_mark = s.mark(view.tone("attachments"), view.said("attachments")) if view.problem("attachments") else None
    if view.problem("target"):
        s.mark(view.tone("target"), view.said("target"))

    def detail(scr, status, sm, attached, am):
        scr.props([("Name", name), ("ID", vol.get("id")), ("Project ID", vol.get("os-vol-tenant-attr:tenant_id") or vol.get("project_id")),
                   ("Status", status, sm), ("Group", "-")], title="Overview")
        scr.props([("Size", f"{vol.get('size')} GiB"), ("Type", vol.get("type") or vol.get("volume_type")),
                   ("Bootable", "Yes" if str(vol.get("bootable")).lower() == "true" else "No"), ("Encrypted", "No"),
                   ("Created", vol.get("created_at") or "-")], title="Specs")
        scr.props([("Attached To", "\n".join(attached) if attached else "Not attached", am)], title="Attachments")
    detail(s, hz_status(vol.get("status")), status_mark, [f"{r[0]} on {r[2] or '-'}" for r in rows], att_mark)
    cmds = rec_commands(view)
    attach = next((re.search(r"openstack server add volume (\S+) (\S+)", c) for c in cmds if "server add volume" in c), None)
    reset = any("reset-state --state available" in c for c in cmds)
    if attach or reset:
        a = s.twin()
        st = "In-use" if attach else "Available"
        detail(a, st, a.mark("success", f"Status {st} after How to fix it."),
               [f"{attach.group(1)} on /dev/vd…"] if attach else [],
               a.mark("success", f"Attached to {attach.group(1)} (Service Portal → Storage → Attach, or the command)." if attach
                      else "Free: attach it again from the Service Portal."))
    return [s]


def port_in(spec, port):
    """port inside a Horizon port range ('any', '443', '443:443', '1-65535')."""
    spec = str(spec or "").strip().lower()
    if spec in ("", "any", "none", "-"):
        return True
    m = re.match(r"^(\d+)(?:\s*[:-]\s*(\d+))?$", spec)
    return bool(m) and int(m.group(1)) <= int(port) <= int(m.group(2) or m.group(1))


def hz_rule_line(direction, proto, rng, remote):
    """A rule as the instance Overview lists it: 'ALLOW IPv4 443/tcp from 0.0.0.0/0'."""
    proto = str(proto or "any").lower()
    port = "" if str(rng).lower() in ("", "any", "none", "-") else str(rng).replace(":", "-")
    what = f"{port}/{proto}" if port and proto not in ("any", "none") else proto if proto not in ("any", "none") else ""
    way = "from" if str(direction).lower() == "ingress" else "to"
    return " ".join(x for x in ("ALLOW IPv4", what, way, remote or "0.0.0.0/0") if x)


def os_instance_network(view):
    out = []
    server = view.json("server") or view.json("server2") or {}
    server = server if isinstance(server, dict) else {}
    sname = server.get("name") or view.params.get("instance") or ""
    columns, prow = table(view.step("ports"))   # Port, IP address, Subnet, Status, Floating IP
    sg_cols, sg_rows = table(view.step("security_groups"))
    fip = view.rec("floating ip create")
    nofip = bool(fip) and bool(prow) and all(r[4] in ("", "-", "none", None) for r in prow)
    addresses = server.get("addresses")

    fips = [r[4] for r in prow if r[4] not in ("", "-", "none", None)]

    def ip_cell(extra=""):
        if isinstance(addresses, dict) and addresses:
            parts = []
            for i, (net, ips) in enumerate(addresses.items()):
                ips = [str(x) for x in (ips if isinstance(ips, list) else [ips])]
                more = [f for f in fips if f not in ips] if i == 0 else []
                parts.append(f"**{net}**\n{', '.join(ips + more + ([extra] if extra and i == 0 else []))}")
            return "\n".join(parts)
        return "\n".join(f"{r[1]}" + (f", {r[4]}" if r[4] not in ("", "-", "none", None) else "") for r in prow) + (f", {extra}" if extra else "")

    if server or prow:
        s = horizon("hz-instances", "Horizon: Instances", view, ("Project", "Compute", "Instances"), "Instances")
        st_mark = s.mark(view.tone("instance"), view.said("instance")) if view.problem("instance") else None
        mark = st_mark or (s.mark("danger", "No floating IP: " + clip(fip["text"], 300)) if nofip else None)
        status = hz_status(server.get("status"))
        flavor = server.get("flavor")
        flavor = flavor.split(" (")[0] if isinstance(flavor, str) else (flavor or {}).get("original_name", "-") if isinstance(flavor, dict) else "-"
        image = server.get("image")
        image = image.split(" (")[0] if isinstance(image, str) and image else "-"
        row = [sname, image, ip_cell(), flavor, server.get("key_name") or "-", status, server.get("OS-EXT-AZ:availability_zone") or "nova",
               "None", "Running" if status == "Active" else "Shutdown", "-"]
        cols = ["Instance Name", "Image Name", "IP Address", "Flavor", "Key Pair", "Status", "Availability Zone", "Task", "Power State", "Age"]
        kw = dict(select="checkbox", row_action="Create Snapshot", filter="Instance ID =", link_col=0,
                  toolbar=[{"label": "Launch Instance", "icon": "cloud"}, {"label": "Delete Instances", "style": "danger", "icon": "trash", "disabled": True},
                           {"label": "More Actions", "caret": True}])
        s.grid(cols, [row], {0: mark} if mark else {}, **kw)
        if nofip:
            a = s.twin()
            arow = list(row)
            arow[2] = ip_cell("(new floating IP)")
            a.grid(cols, [arow], {0: a.mark("success", "Actions ▾ → Associate Floating IP (or the commands of How to fix it): the floating "
                                                   "IP shows in the IP Address column and the instance answers on it.")}, **kw)
        out.append(s)
        # The instance's Overview: status, IP addresses and the rules of its security groups
        if server:
            d = horizon("hz-instance", "Horizon: Instance details", view, ("Project", "Compute", "Instances"), sname,
                        crumbs=["Project", "Compute", "Instances", sname], tabs=["Overview", "Interfaces", "Log", "Console", "Action Log"],
                        tab="Overview", detail=True, detail_action="Create Snapshot", url=f"/dashboard/project/instances/{server.get('id')}/")
            groups = []
            for r in sg_rows:
                if r[0] not in groups:
                    groups.append(r[0])
            fix = view.rec("security group rule create", "tcp")
            new_rule = next((c for c in rec_commands(view) if "security group rule create" in c and "--protocol tcp" in c), "")
            rule = re.search(r"--protocol (\S+) --dst-port (\S+) --remote-ip (\S+)", new_rule) if new_rule else None
            sg_mark = d.mark(view.tone("security_groups"), view.said("security_groups")) if view.problem("security_groups") else None

            def detail(scr, smark, extra_rule=None, emark=None):
                scr.props([("Name", sname), ("ID", server.get("id")), ("Description", server.get("description") or "-"), ("Project ID", server.get("project_id") or "-"),
                           ("Status", status, smark), ("Locked", "False"), ("Availability Zone", server.get("OS-EXT-AZ:availability_zone") or "nova"),
                           ("Created", server.get("created") or "-"), ("Host", server.get("OS-EXT-SRV-ATTR:host") or "-")], title="Overview")
                if isinstance(addresses, dict) and addresses:
                    scr.props([(net, ", ".join(ips if isinstance(ips, list) else [str(ips)])) for net, ips in addresses.items()], title="IP Addresses")
                items = []
                for g in groups or [x.get("name") if isinstance(x, dict) else str(x) for x in server.get("security_groups") or []]:
                    lines = [hz_rule_line(r[1], r[2], r[3], r[4]) for r in sg_rows if r[0] == g]
                    if extra_rule and g == extra_rule[0]:
                        lines.append(extra_rule[1])
                    items.append((g, "\n".join(lines) or "-", (emark if extra_rule and g == extra_rule[0] else smark if smark and False else None)))
                if items:
                    scr.props(items, title="Security Groups")
            detail(d, st_mark)
            if sg_mark and d.blocks and d.blocks[-1].get("title") == "Security Groups":
                for it in d.blocks[-1]["items"]:
                    it["mark"] = sg_mark
            if sg_mark and rule and groups:
                target = next((g for g in groups if fix and re.search(rf"(?<![\w-]){re.escape(g)}(?![\w-])", fix["text"])), groups[0])
                a = d.twin()
                detail(a, None, (target, hz_rule_line("ingress", rule.group(1), rule.group(2), rule.group(3))),
                       a.mark("success", f"{target} now lists ALLOW IPv4 {rule.group(2)}/{rule.group(1)} from {rule.group(3)}."))
            out.append(d)
    if view.step("security_groups"):
        groups = []
        for r in sg_rows:
            if r[0] not in groups:
                groups.append(r[0])
        ids = {}
        for k, v in view.data.items():
            if k.startswith("sgname_") and isinstance(v, dict):
                n = (json_of(v) or {}).get("name") if isinstance(json_of(v), dict) else None
                if n:
                    ids[n] = k[7:]
        port = str(view.params.get("port") or "")
        new_rule = next((c for c in rec_commands(view) if "security group rule create" in c and "--protocol tcp" in c), "")
        rule = re.search(r"--protocol (\S+) --dst-port (\S+) --remote-ip (\S+)", new_rule) if new_rule else None
        fix = view.rec("security group rule create", "tcp")
        target_group = next((g for g in groups if fix and re.search(rf"(?<![\w-]){re.escape(g)}(?![\w-])", fix["text"])), groups[0] if groups else "")
        cols = ["Direction", "Ether Type", "IP Protocol", "Port Range", "Remote IP Prefix", "Remote Security Group", "Description"]
        tb = lambda m: [{"label": "Add Rule", "icon": "plus", "mark": m}, {"label": "Delete Rules", "style": "danger", "icon": "trash", "disabled": True}]
        for g in (groups or [""])[:2]:
            title = f"Manage Security Group Rules: {g} ({ids.get(g, '…')})"
            s = horizon(f"hz-sg-{len(out)}", f"Horizon: Rules of {g}".strip(), view, ("Project", "Network", "Security Groups"), title,
                        crumbs=["Project", "Network", "Security Groups", title])
            marks, grid = {}, []
            raw = view.json(f"sg_{ids[g]}") if g in ids else None
            listed = [x for x in raw if isinstance(x, dict)] if isinstance(raw, list) else []
            rules = [(x.get("Direction"), x.get("Ethertype") or "IPv4", x.get("IP Protocol"), x.get("Port Range"),
                      x.get("IP Range") or x.get("Remote IP Prefix"), x.get("Remote Security Group"), x.get("Description"))
                     for x in sorted(listed, key=lambda x: (str(x.get("Direction")) != "egress", str(x.get("IP Protocol"))))] or \
                [(r[1], "IPv4", r[2], r[3], r[4] if re.match(r"^[\d.:/a-f]+$", str(r[4] or "")) else "", r[4], "") for r in sg_rows if r[0] == g]
            for direction, ether, proto, rng, remote_ip, remote_sg, desc in rules:
                grid.append([str(direction or "").capitalize(), ether, str(proto).upper() if proto not in ("any", None, "") else "Any", hz_port(rng),
                             remote_ip or "-", (remote_sg or "-") if not remote_ip else "-", desc or "-"])
                if port and str(direction).lower() == "ingress" and port_in(rng, port) and str(proto).lower() in ("tcp", "any", "none"):
                    marks[len(grid) - 1] = s.mark("success", f"This rule allows TCP {port}.")
            add = s.mark("danger", "No rule allows the port: " + clip(fix["text"], 300)) if fix and view.problem("security_groups") and g == target_group else None
            kw = dict(select="checkbox", row_action="Delete Rule", row_action_danger=True, link_col=-1)
            s.grid(cols, grid, marks, toolbar=tb(add), **kw)
            if add and rule:
                a = s.twin()
                agrid = grid + [["Ingress", "IPv4", rule.group(1).upper(), hz_port(rule.group(2)), rule.group(3), "-", "-"]]
                a.grid(cols, agrid, {len(agrid) - 1: a.mark("success", f"New rule: Ingress TCP {rule.group(2)} from {rule.group(3)} "
                                                                      "(Add Rule → Custom TCP Rule → Port → CIDR).")}, toolbar=tb(None), **kw)
            out.append(s)
    return out


# ------------------------------------------------------------------------------------------------- vCloud Director (NSX-T)
# Menus, columns and buttons as in the tenant portal of vCloud Director 10.5+ ("IAAS ACME CLOUD", NSX-T backed edges).
VCD_NAV1 = ["Data Centers", "Applications", "Networking", "Content Hub", "Libraries", "|", "Administration", "Monitor"]
VCD_VDC_NAV = [{"group": "Compute", "icon": "applications", "items": ["vApps", "Virtual Machines", "Affinity Rules"]},
               {"group": "Networking", "icon": "network-globe", "items": ["Networks", "Edges", "Network Pool", "Edge Clusters",
                                                                          "Segment Profile Templates", "Network Policies"]},
               {"group": "Storage", "icon": "storage", "items": ["Named Disks"]},
               {"group": "Policies", "icon": "shield", "items": ["Storage Policies", "VM Placement Policies", "VM Sizing Policies"]},
               {"group": "Settings", "icon": "cog", "items": ["General", "Metadata", "Sharing", "Allocation"]}]
VCD_EDGE_NAV = [{"group": "Configuration", "items": ["General", "Edge Cluster", "Rate Limiting", "External Networks"]},
                {"group": "Services", "items": ["Firewall", "NAT", "IPSec VPN", "L2 VPN"]},
                {"group": "Load Balancer", "items": ["General Settings"]},
                {"group": "Routing", "items": ["Static Routes"]},
                {"group": "Security", "items": ["Static Groups", "IP Sets", "MAC Sets", "Application Port Profiles", "Network Context Profiles"]},
                {"group": "IP Management", "items": ["IP Allocations", "DNS", "DHCPv6", "DHCP Forwarding"]}]
VCD_VM_NAV = [{"group": "", "items": ["General"]},
              {"group": "Hardware", "items": ["Removable Media", "Hard Disks", "Compute", "Advanced", "NICs"]},
              {"group": "", "items": ["Guest OS Customization", "Guest Properties", "Snapshots", "Sharing", "Metadata"]},
              {"group": "Monitor", "items": ["Tasks", "Events"]},
              {"group": "", "items": ["Security Tags"]}]
VCD_NET_NAV = [{"group": "", "items": ["General"]},
               {"group": "IP Management", "items": ["Static IP Pools", "IP Allocations", "DHCP", "Manual IP Reservation"]}]
VCD_VM_ACTIONS = ["POWER ON", "POWER OFF", "LAUNCH WEB CONSOLE", "LAUNCH REMOTE CONSOLE", "ALL ACTIONS"]


def vcd(key, label, view, org="", vdc="", nav2_active="", crumbs=(), entity=None, h2="", sidenav=None, side_active="",
        section="", tabs=None, tab="", recent=None):
    """A page of the tenant portal: header, main menu, the VDC menu, then an entity page (name, actions, its own menu)
    or a list page (big title)."""
    return Screen(key, label, "vcd", host=view.ctx.get("vcd_host") or "", brand=view.ctx.get("vcd_brand") or "IAAS ACME CLOUD",
                  url=(f"/tenant/{org}/vdcs" if org else "/tenant"), org=org, vdc=vdc, nav1="Data Centers", nav2=VCD_VDC_NAV,
                  nav2_active=nav2_active, crumbs=list(crumbs), entity=entity, h2=h2, sidenav=sidenav, side_active=side_active,
                  side_marks={}, section=section, tabs=tabs, tab=tab, recent=recent or [])


def field(text, name, stop=","):
    """'<name> <value>' out of a fix text ('external IP 11.4.20.31, internal IP ...')."""
    m = re.search(rf"{re.escape(name)} ([^{stop}]+?)(?:{stop}|\.$|$)", str(text or ""))
    return m.group(1).strip().strip("'") if m else ""


def vcd_edge(view):
    from .vcloud import VcdEdge, values
    edge = VcdEdge._edge(view.data)
    if not edge:
        return []
    name = edge.get("name")
    org = (edge.get("orgRef") or {}).get("name") or ""
    vdc = (edge.get("orgVdc") or {}).get("name") or (edge.get("ownerRef") or {}).get("name") or ""
    entity = {"name": name, "icon": "router", "actions": ["INCREASE SCOPE", "DELETE"]}
    crumbs = ["All Org VDC Edge Gateways", name]

    def page(key, label, section, tabs=None):
        return vcd(key, label, view, org, vdc, "Edges", crumbs, entity, sidenav=VCD_EDGE_NAV, side_active=section,
                   section=section, tabs=tabs, tab=(tabs or [""])[0])
    out = []
    # General
    s = page("vcd-edge-general", "vCloud: Edge gateway", "General")
    backing = (edge.get("gatewayBacking") or {}).get("gatewayType") or "NSXT_BACKED"
    bmark = s.mark("warning", "NSX-V backed edge: NSX-V is no longer used; move it to an NSX-T backed edge.") if backing == "NSXV_BACKED" else None
    s.props([("Name", name), ("Status", "Normal" if str(edge.get("status") or "REALIZED").upper() in ("REALIZED", "NORMAL") else edge.get("status")),
             ("Description", edge.get("description") or "-"), ("Gateway backing", "NSX-T" if backing != "NSXV_BACKED" else "NSX-V", bmark)],
            title="General", edit=True)
    uplinks = edge.get("edgeGatewayUplinks") or []
    s.props([("Organization Virtual Data Center", vdc or "-"), ("Organization", org or "-")]
            + [("External network", f"{u.get('uplinkName') or '-'}: " + ", ".join(sb.get("primaryIp") for sb in ((u.get("subnets") or {}).get("values") or [])
                                                                                      if sb.get("primaryIp"))) for u in uplinks], title="Scope")
    s.mark("info", "Firewall, NAT and IPSec VPN of this edge are under Services in its menu; the next tabs show each one with the "
                   "values of this run.")
    out.append(s)
    # IPSec VPN
    tunnels = values(source(view.data, "ipsec"))
    if tunnels or "ipsec" in view.data:
        s = page("vcd-edge-ipsec", "vCloud: IPSec VPN", "IPSec VPN")
        a = s.twin()
        rows, marks, arows, amarks, down = [], {}, [], {}, None
        for i, t in enumerate(tunnels):
            st = json_of(source(view.data, f"tunnel_{t.get('id')}")) or {}
            ts = str(st.get("tunnelStatus") or "?").upper()
            ike = st.get("ikeStatus") or {}
            on = t.get("active", t.get("enabled", True))
            row = [t.get("name"), "Enabled" if on else "Disabled", "Policy Based" if t.get("policyBased", True) else "Route Based",
                   "Up" if ts == "UP" else "Down" if ts == "DOWN" else ts.title(), (t.get("securityType") or "Default").title(),
                   "Pre-Shared Key" if str(t.get("authenticationMode") or "PSK").upper() == "PSK" else t.get("authenticationMode"),
                   (t.get("localEndpoint") or {}).get("localAddress"), (t.get("remoteEndpoint") or {}).get("remoteAddress"),
                   "Enabled" if t.get("logging") else "Disabled"]
            rows.append(row)
            if on and ts != "UP":
                reason = ike.get("failReason") or st.get("failReason") or ""
                marks[i] = s.mark("danger", f"{t.get('name')}: Connectivity Status {row[3]}" + (f" ({reason})" if reason else "")
                                  + f", IKE {ike.get('ikeServiceStatus') or '?'}. Select it → EDIT → State off → SAVE, then EDIT → State on "
                                  "→ SAVE; wait 1-2 minutes and REFRESH STATUS.")
                down = down or marks[i]
                arows.append(row[:3] + ["Up"] + row[4:])
                amarks[i] = a.mark("success", f"{t.get('name')}: Connectivity Status Up after the disable/enable (or once the customer's "
                                              f"side {row[7]} answers again).")
            else:
                arows.append(row)
        cols = ["Name", "State", "Type", "Connectivity Status", "Security Profile", "Authentication Mode", "Local IP", "Remote IP", "Logging"]
        tb = lambda m: [button("NEW"), button("REFRESH STATUS", m)]
        s.grid(cols, rows, marks, toolbar=tb(down), select="radio", count="IPSec tunnel(s)", empty="No IPSec VPN tunnels.")
        if amarks:
            a.grid(cols, arows, amarks, toolbar=tb(None), select="radio", count="IPSec tunnel(s)")
        out.append(s)
    # NAT
    nat = values(source(view.data, "nat"))
    if nat or "nat" in view.data:
        s = page("vcd-edge-nat", "vCloud: NAT", "NAT", ["Rules", "Logs"])
        a = s.twin()
        detail = str(view.step("nat").get("detail") or "")
        rows, marks, arows, amarks = [], {}, [], {}
        for i, x in enumerate(nat):
            on = x.get("enabled", True)
            row = [x.get("name"), "User defined", "Active" if on else "Disabled", x.get("type") or x.get("ruleType"), x.get("externalAddresses"),
                   x.get("internalAddresses"), x.get("dnatExternalPort") or "-", x.get("priority", 0),
                   {"MATCH_INTERNAL_ADDRESS": "Match Internal Address", "MATCH_EXTERNAL_ADDRESS": "Match External Address",
                    "BYPASS": "Bypass"}.get(x.get("firewallMatch"), x.get("firewallMatch") or "-")]
            rows.append(row)
            fix = view.rec(f"NAT → {x.get('name')} → Edit")
            if fix:
                marks[i] = s.mark("danger", f"How to fix it: {fix['text']}")
                arows.append(row[:2] + ["Active"] + row[3:])
                amarks[i] = a.mark("success", f"{x.get('name')}: State Active (select → EDIT → State on → SAVE).")
            else:
                if x.get("name") and re.search(rf"(?<![\w-]){re.escape(str(x.get('name')))}(?![\w-])", detail):
                    marks[i] = s.mark("success", f"{x.get('name')} covers the VM.")
                arows.append(row)
        new = None
        for r in view.recs:
            if str(r.get("where", "")).endswith("→ NAT → New"):
                new = s.mark("danger", f"How to fix it: {r['text']}")
                text = r["text"]
                kind = "DNAT" if "DNAT" in text.split(":")[0] else "SNAT"
                arows.append([field(text, "name"), "User defined", "Active", kind, field(text, "external IP"),
                              field(text, "internal IP").split(" (")[0], field(text, "application TCP") if kind == "DNAT" else "-", 0,
                              "Match Internal Address" if kind == "DNAT" else "-"])
                amarks[len(arows) - 1] = a.mark("success", f"New {kind} rule {field(text, 'name')} (NEW → the values of How to fix it → SAVE).")
        cols = ["Name", "Category", "State", "NAT Action", "External IP", "Internal IP", "External Port", "Priority", "Firewall Match"]
        s.grid(cols, rows, marks, toolbar=[button("NEW", new)], select="radio", count="rules", empty="No NAT rules.")
        if amarks:
            a.grid(cols, arows, amarks, toolbar=[button("NEW")], select="radio", count="rules")
        out.append(s)
    # Firewall
    fw = json_of(source(view.data, "fw")) or {}
    user_rules = (fw.get("userDefinedRules") or []) if isinstance(fw, dict) else []
    rules = user_rules + ((fw.get("defaultRules") or []) if isinstance(fw, dict) else [])
    if rules:
        fstep = view.step("firewall")
        decided = re.search(r"by rule (.+?)(?: \(|\.$)", str(fstep.get("detail") or ""))
        fix = view.rec("Edge Gateways", "Firewall")
        s = page("vcd-edge-fw", "vCloud: Firewall", "Firewall", ["Rules", "Logs"])
        rows, marks, at = [], {}, None
        for i, x in enumerate(rules):
            rows.append([i + 1, x.get("name"), "User Defined" if x in user_rules else "Default", "Active" if x.get("enabled", True) else "Disabled",
                         ", ".join(p.get("name", "") for p in x.get("applicationPortProfiles") or []) or "Any",
                         ", ".join(g.get("name", "") for g in x.get("sourceFirewallGroups") or []) or "Any",
                         ", ".join(g.get("name", "") for g in x.get("destinationFirewallGroups") or []) or "Any",
                         str(x.get("actionValue") or x.get("action") or "").title()])
            if decided and x.get("name") == decided.group(1):
                marks[i] = s.mark(view.tone("firewall"), f"{fstep.get('title')}: {fstep.get('detail')}")
                at = i
        edit = s.mark("danger", f"How to fix it: {fix['text']}") if fix else None
        for item in ("Application Port Profiles", "IP Sets"):
            if fix and item in fix["text"]:
                s.chrome.setdefault("side_marks", {})[item] = edit
        cols = ["#", "Name", "Category", "State", "Applications", "Source", "Destination", "Action"]   # Context hidden (Manage Columns)
        tb = lambda m: [button("NEW"), button("EDIT RULES", m), button("EDIT", disabled=True), button("DELETE", disabled=True),
                        button("MOVE TO", disabled=True), button("REARRANGE")]
        s.grid(cols, rows, marks, toolbar=tb(edit), select="radio", count="rule(s)", per_page=True, link_col=1)
        if fix:
            a = s.twin()
            text = fix["text"].split("New ABOVE", 1)[-1]
            new = ["", field(text, "name"), "User Defined", "Active", field(text, "applications"), field(text, "source"),
                   field(text, "destination IP set"), "Allow"]
            pos = at if at is not None else len(rows)
            arows = [list(r) for r in rows[:pos]] + [new] + [list(r) for r in rows[pos:]]
            for i, r in enumerate(arows):
                r[0] = i + 1
            a.chrome["side_marks"] = {}
            for item, what in (("Application Port Profiles", f"profile {field(text, 'applications')}"), ("IP Sets", f"IP set {field(text, 'destination IP set')}")):
                if item in s.chrome.get("side_marks", {}):
                    a.chrome["side_marks"][item] = a.mark("success", f"Security → {item}: {what} created first.")
            a.grid(cols, arows, {pos: a.mark("success", f"New rule {new[1]} ABOVE {rows[at][1] if at is not None else 'the default rule'}: "
                                                         "it is evaluated first, the port is allowed.")},
                   toolbar=tb(None), select="radio", count="rule(s)", per_page=True, link_col=1)
        out.append(s)
    return out


def vcd_vm_power(view):
    from .vcloud import VcdVmPower, records, values, IP_RE
    vm = VcdVmPower._vm(view.data, view.params)
    if not vm:
        return []
    out = []
    org, vname = vm.get("orgName") or "", vm.get("name")
    vdc_name = vm.get("vdcName") or ""
    status = str(vm.get("status") or "")
    pretty = lambda x: str(x or "").replace("_", " ").capitalize()
    problems = [k for k in ("quota", "conflict", "state", "pool", "stuck") if view.problem(k)]
    tasks = records(source(view.data, "tasks"))
    recent = [[t.get("operationFull") or t.get("name"), str(t.get("status") or "").capitalize().replace("Success", "Succeeded"),
               "vm", t.get("ownerName"), t.get("startDate"), t.get("endDate") or ""] for t in tasks[:4]]
    entity = lambda st: {"name": vname, "icon": "vm", "status": pretty(st), "off": st != "POWERED_ON", "actions": VCD_VM_ACTIONS}
    # Virtual machines of the VDC (cards)
    s = vcd("vcd-vms", "vCloud: Virtual machines", view, org, vdc_name, "Virtual Machines", h2="Virtual Machines", recent=recent)
    found = records(source(view.data, "vm"))

    def card(x, st, mark=None):
        return {"name": x.get("name"), "status": pretty(st), "on": st == "POWERED_ON", "mark": mark,
                "rows": [["Runtime lease", "Never Suspends"], ["Owner", x.get("ownerName") or "-"], ["vApp", x.get("containerName") or "-"],
                         ["Guest OS", x.get("guestOs") or "-"], ["Network", f"{x.get('networkName') or '-'} ({x.get('ipAddress') or '-'})"]],
                "res": [["CPUs", x.get("numberOfCpus")], ["Storage", "-"], ["Memory", f"{int(x.get('memoryMB') or 0) // 1024} GB"],
                        ["Networks", "1"]]}
    m0 = s.mark(view.tone("vm") if view.problem("vm") else "info", view.said("vm"))
    s.cards([card(x, str(x.get("status") or ""), m0 if i == 0 else None) for i, x in enumerate(found)], count=f"{len(found)} Virtual Machines")
    if problems and status != "POWERED_ON":
        a = s.twin()
        am = a.mark("success", f"After How to fix it: {vname} → POWER ON from vCloud (never from vCenter); the task ends Succeeded.")
        a.cards([card(x, "POWERED_ON" if i == 0 else str(x.get("status") or ""), am if i == 0 else None) for i, x in enumerate(found)],
                count=f"{len(found)} Virtual Machines")
    out.append(s)
    # NICs
    task = next((t for t in tasks if str(t.get("status")).lower() == "error"), None)
    bad_ips = set(IP_RE.findall(str((task or {}).get("details") or ""))) if view.step("conflict") else set()
    fix_ip = view.rec("Give", "free IP")
    new_ip = (re.search(r"with IP (\d+\.\d+\.\d+\.\d+)", fix_ip["text"]) or [None, ""])[1] if fix_ip else ""
    nics_body = view.json("nics")
    nics = nics_body.get("networkConnection") if isinstance(nics_body, dict) else None
    s = vcd("vcd-nics", "vCloud: VM NICs", view, org, vdc_name, "Virtual Machines", ["All Virtual Machines", vname], entity(status),
            sidenav=VCD_VM_NAV, side_active="NICs", recent=recent)
    rows, marks = [], {}
    mode = {"MANUAL": "Static - Manual", "POOL": "Static - IP Pool", "DHCP": "DHCP", "NONE": "None"}
    if isinstance(nics, list) and nics:
        primary = nics_body.get("primaryNetworkConnectionIndex")
        for n in sorted(nics, key=lambda n: n.get("networkConnectionIndex") or 0):
            rows.append(["Yes" if n.get("networkConnectionIndex") == primary else "No", n.get("networkConnectionIndex"),
                         "Yes" if n.get("isConnected") else "No", n.get("networkAdapterType") or "-", n.get("network") or "-",
                         mode.get(n.get("ipAddressAllocationMode"), n.get("ipAddressAllocationMode") or "-"), n.get("ipAddress") or "-",
                         n.get("externalIpAddress") or "-", n.get("macAddress") or "-"])
    else:
        rows.append(["Yes", 0, "Yes", "-", vm.get("networkName") or "-", "-", vm.get("ipAddress") or "-", "-", "-"])
    for i, r in enumerate(rows):
        if r[6] in bad_ips:
            marks[i] = s.mark("danger", f"IP {r[6]} is already used by another running VM: " + clip(fix_ip["text"] if fix_ip else view.said("conflict"), 300))
    cols = ["Primary NIC", "NIC", "Connected", "Network Adapter Type", "Network", "IP Mode", "IP Address", "External IP Address", "MAC Address"]
    s.grid(cols, rows, marks, toolbar=[button("EDIT", next(iter(marks.values()), None))], count="NIC(s)", link_col=-1)
    if marks and new_ip:
        a = s.twin()
        arows, amarks = [list(r) for r in rows], {}
        for i in marks:
            arows[i][6], arows[i][5], arows[i][8] = new_ip, "Static - Manual", "(new MAC)"
            amarks[i] = a.mark("success", f"NIC removed and added again with IP {new_ip} (free in the static pool); then POWER ON works.")
        a.grid(cols, arows, amarks, toolbar=[button("EDIT")], count="NIC(s)", link_col=-1)
    out.append(s)
    # IP allocations of the network (IP conflict)
    used = values(source(view.data, "ips"))
    if view.step("conflict") and used:
        net = vm.get("networkName") or "network"
        s = vcd("vcd-ipalloc", "vCloud: IP allocations", view, org, vdc_name, "Networks", ["Networks", net],
                {"name": net, "icon": "network-globe", "actions": ["DELETE"]}, sidenav=VCD_NET_NAV, side_active="IP Allocations",
                tabs=["IPv4 Allocations", "IPv6 Allocations"], tab="IPv4 Allocations", recent=recent)
        marks = {}
        rows = [[u.get("ipAddress"), "Yes" if u.get("deployed") else "No", u.get("entityName") or "-", "-", org or "-"] for u in used]
        for i, u in enumerate(used):
            if u.get("ipAddress") in bad_ips and u.get("entityName") != vname:
                marks[i] = s.mark("danger", f"{u.get('ipAddress')} is already used by {u.get('entityName')} (deployed).")
        cols = ["IP Address", "Deployed", "Usage", "vApp", "Organization"]
        s.grid(cols, rows, marks, toolbar=[button("DELETE", disabled=True)], select="checkbox", count="IP allocation(s)", link_col=-1)
        if new_ip:
            a = s.twin()
            arows = [r for r in rows if not (r[2] == vname and r[0] in bad_ips)] + [[new_ip, "Yes", vname, "-", org or "-"]]
            a.grid(cols, arows, {len(arows) - 1: a.mark("success", f"{vname} uses {new_ip}; {', '.join(sorted(bad_ips))} stays with the other VM only.")},
                   toolbar=[button("DELETE", disabled=True)], select="checkbox", count="IP allocation(s)", link_col=-1)
        out.append(s)
    # Allocation of the Org VDC (VDC → Settings → Allocation)
    vdc = view.json("vdc") or {}
    if isinstance(vdc, dict) and vdc.get("computeCapacity"):
        s = vcd("vcd-alloc", "vCloud: Allocation", view, org, vdc.get("name") or vdc_name, "Allocation", h2="Allocation", recent=recent)
        cap = vdc.get("computeCapacity") or {}
        mem, cpu = cap.get("memory") or {}, cap.get("cpu") or {}
        raise_fix = view.rec("Allocation", "raise")
        qm = s.mark(view.tone("quota"), ("How to fix it: " + raise_fix["text"]) if raise_fix else view.said("quota")) if view.problem("quota") else None
        ghz = lambda v: f"{round((v or 0) / 1000)} GHz" if (cpu.get("units") or "MHz") == "MHz" else f"{v} {cpu.get('units')}"
        gb = lambda v: f"{round((v or 0) / 1024)} GB" if (mem.get("units") or "MB") == "MB" else f"{v} {mem.get('units')}"
        model = {"AllocationPool": "Allocation Pool", "AllocationVApp": "Pay-As-You-Go", "ReservationPool": "Reservation Pool"}.get(vdc.get("allocationModel"), vdc.get("allocationModel"))
        blocks = lambda mlimit, m: [{"head": "Allocation Model", "rows": [["Allocation Model", model]]},
                                    {"head": "CPU", "rows": [["CPU allocation used", ghz(cpu.get("used"))], ["CPU allocation", ghz(cpu.get("limit")) if cpu.get("limit") else "Unlimited"]]},
                                    {"head": "Memory", "rows": [["Memory allocation used", gb(mem.get("used")), m],
                                                                ["Memory allocation", gb(mlimit) if mlimit else "Unlimited", m]]}]
        s.stack(blocks(mem.get("limit"), qm), toolbar=[button("EDIT", qm)])
        new_limit = (re.search(r"to at least (\d+) MB", raise_fix["text"]) or [None, ""])[1] if raise_fix else ""
        if qm and new_limit:
            a = s.twin()
            am = a.mark("success", f"Memory allocation {gb(mem.get('limit'))} → {gb(int(new_limit))} (EDIT → Memory allocation → SAVE), after "
                                   "the customer approved the extra quota; then POWER ON has room.")
            a.stack(blocks(int(new_limit), am), toolbar=[button("EDIT")])
        out.append(s)
    # Tasks of the VM (VM → Monitor → Tasks)
    running = [t for t in records(source(view.data, "running")) if t.get("objectName") == vname]
    if tasks or running:
        s = vcd("vcd-tasks", "vCloud: Tasks", view, org, vdc_name, "Virtual Machines", ["All Virtual Machines", vname], entity(status),
                sidenav=VCD_VM_NAV, side_active="Tasks", recent=recent)
        rows, marks = [], {}
        for t in (tasks + [x for x in running if x not in tasks])[:30]:
            rows.append([t.get("operationFull") or t.get("name"), str(t.get("status") or "").capitalize().replace("Success", "Succeeded"),
                         "vm", t.get("ownerName"), t.get("startDate"), t.get("endDate") or ""])
            i = len(rows) - 1
            if t is task:
                marks[i] = s.mark("danger", f"Failed: {clip(t.get('details') or 'no message', 300)}")
            elif str(t.get("status")).lower() == "running" and view.problem("stuck"):
                marks[i] = s.mark(view.tone("stuck"), view.rec_text("cell-management-tool") or view.said("stuck"))
        cols = ["Task", "Status", "Type", "Initiator", "Start Time", "Completion Time"]
        s.grid(cols, rows, marks, count="task(s)", link_col=0)
        if marks and problems:
            a = s.twin()
            arows = [[f"Starting Virtual Machine {vname}", "Succeeded", "vm", "administrator", "after the fix", ""]] + \
                    [r if r[1] != "Running" else r[:1] + ["Succeeded"] + r[2:] for r in rows]
            a.chrome["entity"] = entity("POWERED_ON")
            a.grid(cols, arows, {0: a.mark("success", f"POWER ON of {vname} from vCloud ends Succeeded; stuck tasks are finished.")},
                   count="task(s)", link_col=0)
        out.append(s)
    # vCenter: power state and resource pool of the VM
    vc = VcdVmPower._vcenter_vm(view.data)
    if vc:
        pools = view.json("pool") or []
        pool_name = pools[0].get("name") if isinstance(pools, list) and pools and isinstance(pools[0], dict) else ""
        vc_name = vc.get("name")
        tree = [{"label": view.ctx.get("vcenter_host") or "vCenter", "icon": "vcenter", "level": 0}]
        if pool_name:
            tree.append({"label": pool_name, "icon": "pool", "level": 1})
        tree.append({"label": vc_name, "icon": "vm", "level": 2 if pool_name else 1, "active": True})
        s = vsphere_screen("vs-vm", "vSphere: VM", view, "hosts", tree, vc_name, "vm", VS_TABS["vm"], "Summary")
        state_mark = s.mark(view.tone("state"), view.said("state")) if view.problem("state") else None
        pool_mark = s.mark(view.tone("pool"), view.said("pool")) if view.problem("pool") else None
        s.chrome["tree"][-1]["mark"] = state_mark or pool_mark
        vc_state = str(vc.get("power_state") or "").replace("_", " ").title()
        props = lambda st, vst, pool, sm, pm: [("Power state (vCenter)", st, sm), ("Status in vCloud Director", vst),
                                               ("Resource pool", pool or "-", pm), ("CPUs", vc.get("cpu_count")),
                                               ("Memory", f"{vc.get('memory_size_MiB')} MB" if vc.get("memory_size_MiB") else None)]
        s.props(props(vc_state, pretty(status), pool_name, state_mark, pool_mark), title="VM Details")
        if state_mark or pool_mark:
            a = s.twin()
            a.chrome["tree"][-1]["mark"] = None
            sm = a.mark("success", "vCenter and vCloud agree: the VM was shut down in vCenter, then powered on from vCloud.") if state_mark else None
            pm = a.mark("success", f"The VM is back in the resource pool of its Org VDC ({pool_name}).") if pool_mark else None
            a.props(props("Powered On", "Powered on", pool_name, sm, pm), title="VM Details")
        out.append(s)
    return out


# ------------------------------------------------------------------------------------------------- vSphere Client
VS_TABS = {"vcenter": ["Summary", "Monitor", "Configure", "Permissions", "Datacenters", "Hosts & Clusters", "VMs", "Datastores", "Networks"],
           "datacenter": ["Summary", "Monitor", "Configure", "Permissions", "Hosts & Clusters", "VMs", "Datastores", "Networks", "Updates"],
           "cluster": ["Summary", "Monitor", "Configure", "Permissions", "Hosts", "VMs", "Datastores", "Networks", "Updates"],
           "host": ["Summary", "Monitor", "Configure", "Permissions", "VMs", "Datastores", "Networks", "Updates"],
           "datastore": ["Summary", "Monitor", "Configure", "Permissions", "Files", "Hosts", "VMs"],
           "pool": ["Summary", "Monitor", "Configure", "Permissions", "VMs"],
           "vm": ["Summary", "Monitor", "Configure", "Permissions", "Datastores", "Networks", "Snapshots", "Updates"]}


def vsphere_screen(key, label, view, inventory, tree, title, icon, tabs, tab, side=None, side_active="", meter_=None):
    return Screen(key, label, "vsphere", host=view.ctx.get("vcenter_host") or "vcenter", inventory=inventory, tree=tree,
                  title=title, icon=icon, tabs=tabs, tab=tab, side=side, side_active=side_active, meter=meter_)


def human_b(n):
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "-"
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if abs(n) < 1024 or unit == "PB":
            return f"{n:.2f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return str(n)


def vs_datastore(view):
    body = view.json("datastores")
    stores = [d for d in body if isinstance(d, dict)] if isinstance(body, list) else []
    if not stores:
        return []
    free_min = int(view.params.get("min_free") or 20)
    goal = free_min + 10
    dcs_body = view.json("datacenters")
    dcs = [d.get("name") for d in dcs_body if isinstance(d, dict)] if isinstance(dcs_body, list) else []
    root = view.ctx.get("vcenter_host") or "vCenter"
    one_dc = len(dcs) == 1
    tree = [{"label": root, "icon": "vcenter", "level": 0}]
    if one_dc:
        tree.append({"label": dcs[0], "icon": "datacenter", "level": 1, "active": True})
    level = 2 if one_dc else 1
    s = vsphere_screen("vs-datastores", "vSphere: Datastores", view, "storage", tree, dcs[0] if one_dc else root,
                       "datacenter" if one_dc else "vcenter", VS_TABS["datacenter" if one_dc else "vcenter"], "Datastores")
    # what each fix leaves: "<ds> then has <goal>% free", target "about <x>% free after"
    after_pct = {}
    for r in view.recs:
        m = re.match(r"^(\S+): ", str(r.get("text")))
        if m and ("then has" in r["text"] or "deleting old snapshots" in r["text"]):
            after_pct[m.group(1)] = float(goal)
            t = re.search(r"to (\S+) \([^)]*about ([\d.]+)% free after\)", r["text"])
            if t:
                after_pct[t.group(1)] = float(t.group(2))
    rows, marks, low, arows, amarks = [], {}, [], [], {}
    a = s.twin() if after_pct else None
    for i, d in enumerate(sorted(stores, key=lambda d: str(d.get("name")))):
        cap, free = d.get("capacity") or 0, d.get("free_space") or 0
        pf = round(free * 100 / cap, 1) if cap else None
        st = "Alert" if pf is not None and pf < free_min else "Warning" if pf is not None and pf < goal else "Normal"
        row = [d.get("name"), st, d.get("type"), human_b(cap), human_b(free), f"{pf}%" if pf is not None else "-"]
        rows.append(row)
        node = {"label": d.get("name"), "icon": "datastore", "level": level}
        if st != "Normal":
            marks[i] = s.mark("danger" if st == "Alert" else "warning", f"{d.get('name')}: {pf}% free "
                              f"({'below' if st == 'Alert' else 'close to'} the {free_min}% threshold).")
            node["mark"] = marks[i]
            low.append(d)
        if len(tree) < 30 or st != "Normal":
            tree.append(node)
        if a is not None:
            if d.get("name") in after_pct and cap:
                p2 = after_pct[d.get("name")]
                arows.append([d.get("name"), "Normal" if p2 >= goal else "Warning", d.get("type"), human_b(cap), f"≈ {human_b(cap * p2 / 100)}", f"≈ {p2}%"])
                amarks[i] = a.mark("success", f"{d.get('name')}: about {p2}% free after How to fix it "
                                              f"({'VMs moved away' if st != 'Normal' else 'VMs moved in, still enough room'}).")
            else:
                arows.append(row)
    cols = ["Name", "Status", "Type", "Capacity", "Free", "Free %"]
    s.grid(cols, rows, marks, footer=f"{len(rows)} items")
    if a is not None:
        a.chrome["tree"] = [dict(n, mark=None) for n in tree]
        a.grid(cols, arows, amarks, footer=f"{len(arows)} items")
    out = [s]
    for d in sorted(low, key=lambda d: (d.get("free_space") or 0) / (d.get("capacity") or 1))[:2]:
        vms = view.json(f"vms_{d.get('datastore')}")
        vms = [v for v in vms if isinstance(v, dict)] if isinstance(vms, list) else []
        cap, free = d.get("capacity") or 0, d.get("free_space") or 0
        dtree = [dict(t, active=(t["label"] == d.get("name")) if t["icon"] == "datastore" else False) for t in tree]
        ds = vsphere_screen(f"vs-ds-{d.get('datastore')}", f"vSphere: {d.get('name')}", view, "storage", dtree, d.get("name"),
                            "datastore", VS_TABS["datastore"], "VMs")
        fix = next((r for r in view.recs if str(r.get("text")).startswith(f"{d.get('name')}:")), None)
        mk = ds.mark("danger" if cap and free * 100 / cap < free_min else "warning", f"{d.get('name')}: {human_b(free)} free of {human_b(cap)}. "
                     + (f"How to fix it: {clip(fix['text'], 300)}" if fix else ""))
        ds.chrome["meter"] = {"label": "Storage", "used": human_b(cap - free), "free": human_b(free), "capacity": human_b(cap),
                              "pct": round((cap - free) * 100 / cap, 1) if cap else None, "mark": mk}
        cols = ["Name", "State", "Status", "vCPU", "Memory"]
        grid = [[v.get("name"), str(v.get("power_state") or "").replace("_", " ").title(), "Normal", v.get("cpu_count"),
                 f"{v.get('memory_size_MiB')} MB" if v.get("memory_size_MiB") else "-"] for v in vms]
        toolbar = [button("Virtual Machines", primary=True), button("VM Templates")]
        ds.grid(cols, grid, toolbar=toolbar, footer=f"{len(vms)} items")
        ds.mark("info", "Many VMs: right-click a VM → Migrate… → Change storage only → the target datastore (Storage vMotion). "
                        "Few VMs: VM → Snapshots → Manage Snapshots → delete the old ones.")
        if d.get("name") in after_pct and cap:
            a = ds.twin()
            p2 = after_pct[d.get("name")]
            am = a.mark("success", f"{d.get('name')}: about {p2}% free after How to fix it; the alert clears.")
            a.chrome["meter"] = {"label": "Storage", "used": f"≈ {human_b(cap * (100 - p2) / 100)}", "free": f"≈ {human_b(cap * p2 / 100)}",
                                 "capacity": human_b(cap), "pct": round(100 - p2, 1), "mark": am}
            a.grid(cols, grid, toolbar=toolbar, footer="The VMs that were moved are listed on the target datastore now.")
        out.append(ds)
    return out


def vs_host_usage(view):
    inv = view.json("inventory") or {}
    inv = inv if isinstance(inv, dict) else {}
    hosts, vms = [dict(h) for h in inv.get("hosts") or []], inv.get("vms") or []
    clusters = {c["name"]: c for c in inv.get("clusters") or [] if c.get("name")}
    if not hosts:
        return []
    cpu_t, mem_t = int(view.params.get("cpu") or 85), int(view.params.get("memory") or 90)
    from .vmware import pct
    for h in hosts:
        h["_cpu"], h["_mem"] = pct(h.get("cpu_used_mhz") or 0, h.get("cpu_total_mhz") or 0), pct(h.get("mem_used_mb") or 0, h.get("mem_total_mb") or 0)
        up = h.get("connection") == "connected" and not h.get("maintenance")
        h["_state"] = ("danger" if up and ((h["_cpu"] or 0) >= cpu_t or (h["_mem"] or 0) >= mem_t) else
                       "warning" if up and ((h["_cpu"] or 0) >= cpu_t - 10 or (h["_mem"] or 0) >= mem_t - 10) else "")
    wanted = str(view.params.get("host") or "").strip()
    focus = [h for h in hosts if wanted and (h["name"] == wanted or wanted in h["name"])] or \
        sorted(hosts, key=lambda h: -max(h["_cpu"] or 0, h["_mem"] or 0))
    cluster = focus[0].get("cluster") or ""
    root = view.ctx.get("vcenter_host") or "vCenter"

    def tree_for(active_host=None, active_cluster=False, marked=True):
        t = [{"label": root, "icon": "vcenter", "level": 0}]
        for cname in sorted({h.get("cluster") or "" for h in hosts}):
            t.append({"label": cname or "(standalone)", "icon": "cluster", "level": 1, "active": active_cluster and cname == cluster})
            for h in sorted([h for h in hosts if (h.get("cluster") or "") == cname], key=lambda h: h["name"]):
                node = {"label": h["name"], "icon": "host", "level": 2, "active": h["name"] == active_host}
                if h["_state"] and marked:
                    node["mark"] = {"tone": h["_state"]}
                t.append(node)
        return t[:40]
    plan = view.rec("vMotion")
    moves, after_load = {}, {}
    if plan:
        body = plan["text"].split(":", 1)[1].split(". ")[0] if ":" in plan["text"] else ""
        moves = {k.strip(" ,"): v for k, v in re.findall(r"([\w.() :-]+?) → ([\w.-]+)", body)}
        m = re.search(r"(\S+) then runs at about CPU ([\d.]+)% / memory ([\d.]+)%", plan["text"])
        if m:
            after_load[m.group(1)] = (m.group(2), m.group(3))
    out = []
    s = vsphere_screen("vs-hosts", "vSphere: Hosts", view, "hosts", tree_for(active_cluster=True), cluster or root, "cluster",
                       VS_TABS["cluster"], "Hosts")
    rows, marks, arows, amarks = [], {}, [], {}
    a = s.twin() if after_load else None
    in_cluster = sorted([h for h in hosts if (h.get("cluster") or "") == cluster], key=lambda h: -max(h["_cpu"] or 0, h["_mem"] or 0))
    for i, h in enumerate(in_cluster):
        row = [h["name"], "Maintenance Mode" if h.get("maintenance") else str(h.get("connection") or "").title(),
               f"{h['_cpu']}%", f"{h['_mem']}%", sum(1 for v in vms if v.get("host") == h["name"] and v.get("power") == "poweredOn")]
        rows.append(row)
        if h["_state"]:
            marks[i] = s.mark(h["_state"], f"{h['name']}: CPU {h['_cpu']}%, memory {h['_mem']}% (alert at CPU {cpu_t}% / memory {mem_t}%).")
        if a is not None:
            moved_in = sum(1 for t in moves.values() if t == h["name"])
            moved_out = sum(1 for v in vms if v.get("host") == h["name"] and v.get("name") in moves)
            if h["name"] in after_load:
                c, m = after_load[h["name"]]
                arows.append([row[0], row[1], f"≈ {c}%", f"≈ {m}%", row[4] - moved_out])
                amarks[i] = a.mark("success", f"{h['name']}: about CPU {c}% / memory {m}% after the vMotion of How to fix it.")
            elif moved_in:
                arows.append(row[:4] + [row[4] + moved_in])
                amarks[i] = a.mark("info", f"{h['name']}: takes {moved_in} VM(s), still below the threshold.")
            else:
                arows.append(row)
    cols = ["Name", "State", "Consumed CPU %", "Consumed Memory %", "Running VMs"]
    s.grid(cols, rows, marks)
    if a is not None:
        a.chrome["tree"] = tree_for(active_cluster=True, marked=False)
        a.grid(cols, arows, amarks)
    out.append(s)
    for h in [x for x in focus if x["_state"] == "danger"][:2]:
        hs = vsphere_screen(f"vs-host-{h['name']}", f"vSphere: {h['name']}", view, "hosts", tree_for(active_host=h["name"]), h["name"],
                            "host", VS_TABS["host"], "VMs")
        on = sorted([v for v in vms if v.get("host") == h["name"] and v.get("power") == "poweredOn"],
                    key=lambda v: -(v.get("cpu_used_mhz") or 0))[:15]
        rows, marks = [], {}
        for i, v in enumerate(on):
            rows.append([v["name"], "Powered On", f"{v.get('cpu_used_mhz')} MHz", human_b((v.get("mem_host_mb") or 0) * 1024 ** 2),
                         f"{v.get('vcpu')} / {human_b((v.get('mem_mb') or 0) * 1024 ** 2)}", v.get("pool")])
            if v["name"] in moves:
                marks[i] = hs.mark("warning", f"{v['name']}: right-click → Migrate… → Change compute resource only → {moves[v['name']]}.")
            elif i == 0:
                marks[i] = hs.mark("info", f"{v['name']} uses the most: look inside the VM (How to fix it).")
        cols = ["Name", "State", "Host CPU", "Host Mem", "vCPU / Memory", "Resource Pool"]
        toolbar = [button("Virtual Machines", primary=True), button("VM Templates")]
        hs.grid(cols, rows, marks, toolbar=toolbar)
        if any(r[0] in moves for r in rows):
            a = hs.twin()
            a.chrome["tree"] = tree_for(active_host=h["name"], marked=False)
            a.grid(cols, [r for r in rows if r[0] not in moves], toolbar=toolbar)
            a.mark("success", "Moved away: " + ", ".join(f"{k} → {v}" for k, v in moves.items()) + ". They now show on the VMs tab of "
                              "their new host.")
        out.append(hs)
        cl = clusters.get(h.get("cluster")) or {}
        if cl:
            ds = vsphere_screen(f"vs-drs-{cl['name']}", f"vSphere: DRS {cl['name']}", view, "hosts", tree_for(active_cluster=True), cl["name"],
                                "cluster", VS_TABS["cluster"], "Configure",
                                side=[{"group": "Services", "items": ["vSphere DRS", "vSphere Availability"]},
                                      {"group": "Configuration", "items": ["Quickstart", "General", "VMware EVC", "VM/Host Groups",
                                                                           "VM/Host Rules", "VM Overrides", "Host Options"]}],
                                side_active="vSphere DRS")
            drs_key = f"drs_{h['name']}"
            m = ds.mark(view.tone(drs_key), (view.rec_text("Get-DrsRecommendation") or view.said(drs_key))) if view.problem(drs_key) else None
            behavior = {"fullyAutomated": "Fully Automated", "partiallyAutomated": "Partially Automated", "manual": "Manual"}
            ds.props([("vSphere DRS", "Turned ON" if cl.get("drs") else "Turned OFF", m if not cl.get("drs") else None),
                      ("Automation Level", behavior.get(cl.get("drs_behavior"), cl.get("drs_behavior") or "-"), m if cl.get("drs") else None)],
                     title="vSphere DRS")
            if m and cl.get("drs"):
                a = ds.twin()
                a.props([("vSphere DRS", "Turned ON"), ("Automation Level", behavior.get(cl.get("drs_behavior"), "-")),
                         ("Recommendations", "None pending", a.mark("success", "Monitor → vSphere DRS → Recommendations: the list is "
                                                                    "empty after APPLY RECOMMENDATIONS."))], title="vSphere DRS")
            out.append(ds)
    columns, rows = table(view.step("pools"))
    if view.problem("pools") and rows:
        vm_name, cl_name, now_pool, must = rows[0][:4]
        base = [{"label": root, "icon": "vcenter", "level": 0}, {"label": cl_name, "icon": "cluster", "level": 1}]
        ps = vsphere_screen("vs-pool", "vSphere: Resource pool", view, "hosts", None, vm_name, "vm", VS_TABS["vm"], "Summary")
        wrong = ps.mark("danger", f"{vm_name} is in {now_pool}: drag it into {must}, or right-click → Migrate… → Change compute "
                                  f"resource only → {must}.")
        right = ps.mark("info", f"{must}: the resource pool of its Org VDC.")
        ps.chrome["tree"] = base + [{"label": str(now_pool).split("/")[-1], "icon": "pool", "level": 2},
                                    {"label": vm_name, "icon": "vm", "level": 3, "active": True, "mark": wrong},
                                    {"label": must, "icon": "pool", "level": 2, "mark": right}]
        ps.props([("Resource pool", now_pool, wrong), ("Must be in", must, right), ("Cluster", cl_name)], title="Related Objects")
        a = ps.twin()
        ok = a.mark("success", f"{vm_name} is in {must}: power on and changes from vCloud work again.")
        a.chrome["tree"] = base + [{"label": str(now_pool).split("/")[-1], "icon": "pool", "level": 2},
                                   {"label": must, "icon": "pool", "level": 2},
                                   {"label": vm_name, "icon": "vm", "level": 3, "active": True, "mark": ok}]
        a.props([("Resource pool", must, ok), ("Cluster", cl_name)], title="Related Objects")
        out.append(ps)
    return out


# ------------------------------------------------------------------------------------------------- NSX Manager
NSX_NAV = [{"group": "Connectivity", "items": ["Tier-0 Gateways", "Tier-1 Gateways", "Segments"]},
           {"group": "Network Services", "items": ["VPN", "NAT", "Load Balancing", "Forwarding Policies"]},
           {"group": "IP Management", "items": ["DNS", "DHCP", "IP Address Pools"]},
           {"group": "Settings", "items": ["Global Networking Config"]}]


def nsx_snat_priority(view):
    data = view.json("rules") or {}
    rules = [x for x in (data.get("results") or []) if isinstance(x, dict)] if isinstance(data, dict) else []
    if not rules and not view.step("rules"):
        return []
    t1 = view.params.get("tier1") or ""
    s = Screen("nsx-nat", "NSX Manager: NAT", "nsx", host=view.ctx.get("nsxt_host") or "nsx-manager",
               top=["Home", "Networking", "Security", "Inventory", "Plan & Troubleshoot", "System"], top_active="Networking",
               side=NSX_NAV, side_active="NAT", title="NAT", filters=[["Gateway", t1], ["View", "NAT"]])
    fix = view.rec("sequence_number")
    changes = dict(re.findall(r"(\S+) \d+ → (\d+)", fix["text"])) if fix else {}
    cols = ["Name", "Action", "Match Source", "Match Destination", "Translated IP", "Priority", "Status"]
    row = lambda x, prio: [x.get("display_name") or x.get("id"), x.get("action"), x.get("source_network") or "Any",
                           x.get("destination_network") or "Any", x.get("translated_network"), prio,
                           "Enabled" if x.get("enabled", True) else "Disabled"]
    ordered = sorted(rules, key=lambda x: (x.get("sequence_number") or 0))
    rows, marks = [], {}
    for i, x in enumerate(ordered):
        name = x.get("display_name") or x.get("id")
        rows.append(row(x, x.get("sequence_number")))
        if name in changes:
            marks[i] = s.mark("danger", f"{name}: Priority {x.get('sequence_number')} → {changes[name]} (⋮ → Edit → Priority → SAVE).")
    if not changes and view.step("order").get("status") == "ok" and rows:
        s.mark("success", view.said("order"))
    s.grid(cols, rows, marks, toolbar=[button("ADD NAT RULE", primary=True)])
    if changes:
        a = s.twin()
        prio = lambda x: int(changes.get(x.get("display_name") or x.get("id"), x.get("sequence_number") or 0))
        after = sorted(rules, key=prio)
        a.grid(cols, [row(x, prio(x)) for x in after],
               {i: a.mark("success", f"{x.get('display_name')}: Priority {prio(x)} — " + ("the specific (Colo/MPLS) rule is evaluated first."
                                                                                       if x.get("destination_network") else "the catch-all comes last."))
                for i, x in enumerate(after) if (x.get("display_name") or x.get("id")) in changes},
               toolbar=[button("ADD NAT RULE", primary=True)])
        a.mark("info", "Test with a NEW session from the source: existing sessions keep their NAT state.")
    return [s]


# ------------------------------------------------------------------------------------------------- ONTAP System Manager
ONTAP_NAV = [{"group": "", "items": ["Dashboard", "Insights"]},
             {"group": "Storage", "items": ["Overview", "Volumes", "LUNs", "Consistency groups", "Shares", "Qtrees", "Quotas",
                                            "Storage VMs", "Tiers"]},
             {"group": "Network", "items": ["Overview", "Ethernet ports", "FC ports"]},
             {"group": "Events & jobs", "items": ["Events", "System alerts", "Jobs"]},
             {"group": "Protection", "items": ["Overview", "Relationships"]},
             {"group": "Hosts", "items": ["SAN initiator groups", "NFS clients"]},
             {"group": "Cluster", "items": ["Overview", "Settings", "Disks", "Support"]}]


def ontap_screen(key, label, view, side_active, title):
    body = view.json("cluster")
    cluster = body.get("name") if isinstance(body, dict) else ""
    return Screen(key, label, "ontap", host=view.ctx.get("ontap_host") or "ontap", cluster=cluster or view.ctx.get("site") or "",
                  side=ONTAP_NAV, side_active=side_active, title=title)


def ontap_health(view):
    from .ontap import records
    out = []
    lifs = records(source(view.data, "lifs"))
    if lifs:
        s = ontap_screen("sm-lifs", "System Manager: Network", view, "Network/Overview", "Network")
        ordered = sorted(lifs, key=lambda l: (l.get("name") != "cluster_mgmt", str(l.get("name"))))
        rows, marks, arows, amarks = [], {}, [], {}
        a = s.twin() if view.problem("cluster_mgmt") else None
        for i, l in enumerate(ordered):
            loc = l.get("location") or {}
            home_node, home_port = (loc.get("home_node") or {}).get("name"), (loc.get("home_port") or {}).get("name")
            row = [l.get("name"), "Up" if l.get("state") == "up" else "Down", (l.get("svm") or {}).get("name", ""),
                   (l.get("ip") or {}).get("address", ""), (loc.get("node") or {}).get("name"), (loc.get("port") or {}).get("name"),
                   home_node, home_port, "Yes" if loc.get("is_home") is not False else "No"]
            rows.append(row)
            if l.get("name") == "cluster_mgmt":
                if view.problem("cluster_mgmt"):
                    fixable = any(r.get("action") for r in view.recs)
                    marks[i] = s.mark("danger", view.said("cluster_mgmt") + (" Run this fix in the portal, or select it → ⋮ → Send to home."
                                                                             if fixable else " Select it → ⋮ → Send to home."))
                    arows.append([row[0], "Up", row[2], row[3], home_node, home_port, home_node, home_port, "Yes"])
                    amarks[i] = a.mark("success", f"cluster_mgmt is up on its home port {home_node} {home_port} (Is home: Yes); "
                                                  "System Manager and SSH answer on the cluster address again.")
                else:
                    marks[i] = s.mark("success", view.said("cluster_mgmt"))
                    arows.append(row)
            else:
                if l.get("state") != "up" or loc.get("is_home") is False:
                    marks[i] = s.mark("warning", f"{l.get('name')}: {'down' if l.get('state') != 'up' else 'not on its home port'} — check it "
                                                 "separately (do not revert data LIFs in bulk).")
                arows.append(row)
        cols = ["Name", "Status", "Storage VM", "IP address", "Current node", "Current port", "Home node", "Home port", "Is home"]
        s.grid(cols, rows, marks, title="Network interfaces", toolbar=[button("+ Add", primary=True)])
        if a is not None:
            a.grid(cols, arows, amarks, title="Network interfaces", toolbar=[button("+ Add", primary=True)])
        out.append(s)
    columns, rows = table(view.step("nodes"))
    if rows:
        s = ontap_screen("sm-nodes", "System Manager: Nodes", view, "Cluster/Overview", "Cluster")
        marks = {}
        for i, r in enumerate(rows):   # Node, State, Membership, Health, Eligibility, SP/BMC, SP address
            if r[1] != "up" or r[3] == "false" or r[4] == "false":
                marks[i] = s.mark("danger", f"{r[0]}: state {r[1]}, health {r[3]}, eligibility {r[4]} — stop and escalate to the storage team.")
            elif r[5] not in ("online", "-"):
                marks[i] = s.mark("warning", f"{r[0]}: service processor {r[5]} (no emergency path).")
        s.grid(["Node", "State", "Membership", "Health", "Eligibility", "Service processor", "SP address"], rows, marks, title="Nodes")
        out.append(s)
    ports = records(source(view.data, "ports"))
    if ports:
        s = ontap_screen("sm-ports", "System Manager: Ethernet ports", view, "Network/Ethernet ports", "Ethernet ports")
        marks = {i: s.mark("danger", f"{(p.get('node') or {}).get('name')} e0M is down: check the cable / switch port.")
                 for i, p in enumerate(ports) if p.get("state") != "up"}
        s.grid(["Node", "Port", "Status", "Enabled"], [[(p.get("node") or {}).get("name"), p.get("name"), str(p.get("state")).title(),
                                                       "Yes" if p.get("enabled", True) else "No"] for p in ports], marks)
        out.append(s)
    columns, rows = table(view.step("events"))
    if rows:
        s = ontap_screen("sm-events", "System Manager: Events", view, "Events & jobs/Events", "Events")
        s.grid(["Time", "Node", "Severity", "Event", "Message"], rows, {0: s.mark("warning", view.said("events"))})
        out.append(s)
    return out


BUILDERS = {
    "cinder-pool-usage": os_cinder_pool_usage,
    "volume-type-legacy": os_volume_type_legacy,
    "project-quota": os_project_quota,
    "stuck-resources": os_stuck_resources,
    "volume-attach": os_volume_attach,
    "instance-network": os_instance_network,
    "custom-port-tcp": os_instance_network,
    "ontap-cluster-health": ontap_health,
    "vcenter-datastore": vs_datastore,
    "vmware-host-usage": vs_host_usage,
    "vcd-vm-power": vcd_vm_power,
    "vcd-edge": vcd_edge,
    "nsxt-snat-priority": nsx_snat_priority,
}


def build(check_id, data, params, ctx, result, commands):
    """Every screen of a run: the consoles first (Horizon, vCloud, vSphere, NSX, System Manager), then the terminals."""
    if not isinstance(result, dict) or result.get("status") == "error":
        return []
    view = View(data, params, ctx, result)
    screens = list(BUILDERS[check_id](view)) if check_id in BUILDERS else []
    screens += terminals(view, commands or {})
    return [s.dict() for s in screens[:MAX_SCREENS]]

"""Templates made on the portal (modules/wi/templates.py): what a step does, and the check that runs a template.

A step is "read" when every command of it is a known read command (READ) used with read options, without writing a file
(no "> file", tee, sed -i, curl -o ...), without command substitution and without a background job; anything else is
"change". The portal rates every step again here, when the run is planned: a change step never runs with the check, it
only becomes the fix of the result (risk high: the operator types the host name), whatever was stored.
"""
import re
import shlex

from .common import Result, on_host, source, text_of

VYOS_OP = "/opt/vyatta/bin/vyatta-op-cmd-wrapper"


def _verbs(allowed, at=0):
    """The word at position `at` among the arguments that are not options must be one of `allowed` (none = allowed)."""
    def rule(args):
        words = [a for a in args if not a.startswith("-")]
        return len(words) <= at or words[at] in allowed
    return rule


def _letters(arg):
    """The letters of a short option cluster: -sSo -> {s, S, o}, -o/tmp/x -> {o, /, t, ...} (a value may be attached, so
    every character counts: a letter of a bad option anywhere in it makes it bad; on the safe side). Not an option: {}."""
    return set(arg[1:]) if len(arg) > 1 and arg[0] == "-" and arg[1] != "-" and not arg[1].isdigit() else set()


def _no_options(*bad):
    """None of these options: a long one (--x, also --x=value; "--x=" = any value), a single-dash word option (-delete,
    -pm: exact or with a value attached), and a short one (-o) also inside a cluster or with its value attached (-sSo,
    -o/tmp/x)."""
    def hit(a, b):
        if b.startswith("--"):
            return a == b or a.startswith(b if b.endswith("=") else b + "=")
        if len(b) == 2:
            return b[1] in _letters(a)
        return a == b or a.startswith(b)
    return lambda args: not any(hit(a, b) for a in args for b in bad)


def _only_options(*good):
    """Only these options and no other word (hostname -f, crontab -l)."""
    return lambda args: all(a in good for a in args)


def _ip(args):
    if any(a in ("-b", "-batch", "--batch", "-force", "-n", "-netns") or a.startswith("-batch") for a in args):
        return False   # -batch runs the ip commands of a file; -netns runs in another namespace
    words = [a for a in args if not a.startswith("-")]
    return len(words) < 2 or words[1] in ("show", "list", "ls", "lst", "sh", "get")


def _awk(args):
    """No program file, no extension (gawk -i inplace rewrites the files it reads), nothing that writes or runs."""
    return not any(a in ("-f", "--file", "-E", "--exec", "-i", "--include", "-l", "--load")
                   or a.startswith(("--file=", "--exec=", "--include=", "--load=")) for a in args) \
        and not any(x in a for a in args for x in ("system", ">", "|", "getline", "inplace"))


def _sed(args):
    """No -i, no script file, and no command that writes (w, W) or runs (e) or reads another file (r, R). The script is
    the value of each -e, else the first argument that is not an option; the other arguments are the files read."""
    if any(a.startswith(("-i", "--in-place", "-f", "--file")) for a in args):
        return False
    scripts = [args[i + 1] for i, a in enumerate(args[:-1]) if a in ("-e", "--expression")] \
        + [a.split("=", 1)[1] for a in args if a.startswith("--expression=")]
    if not scripts:
        scripts = [a for a in args if not a.startswith("-")][:1]
    return not any(re.search(r"[/|,#][gipIM0-9]*[ew]", x) or re.search(r"(^|[;{}\d$/])\s*[ewWrR](\s|$)", x) for x in scripts)


def _curl(args):
    """GET / HEAD only, nothing sent and no file written: no data, form, upload, output file, header / cookie / trace file,
    config file, also inside a cluster of short options (-sSo)."""
    for i, a in enumerate(args):
        if a in ("-X", "--request") and (i + 1 >= len(args) or args[i + 1].upper() not in ("GET", "HEAD")):
            return False
        if a.startswith("-X") and len(a) > 2 and a[2:].upper() not in ("GET", "HEAD"):
            return False
        if re.match(r"^--(data|form|upload-file|output|remote-name|config|json|dump-header|cookie-jar|trace|libcurl|stderr"
                    r"|remote-header-name|create-dirs)", a):
            return False
        if _letters(a) & set("dFToOKDcJ"):
            return False
    return True


def _container(args):
    words = [a for a in args if not a.startswith("-")]
    if not words:
        return True
    if words[0] in ("ps", "images", "logs", "inspect", "stats", "info", "version", "top", "port", "diff", "history"):
        return True
    return words[0] in ("network", "volume", "container", "image", "system", "compose", "pod") and len(words) > 1 \
        and words[1] in ("ls", "list", "inspect", "logs", "ps", "df", "info", "config", "top")


def _pcs(args):
    words = [a for a in args if not a.startswith("-")]
    return not words or words[0] == "status" or (
        words[0] in ("resource", "cluster", "stonith", "property", "constraint", "node", "config")
        and (len(words) == 1 or words[1] in ("status", "config", "show", "list")))


def _esxcli(args):
    """The command is the namespace words up to the first option: its last word (the verb) must be list or get."""
    words = []
    for a in args:
        if a.startswith("-"):
            break
        words.append(a)
    return bool(words) and words[-1] in ("list", "get")


def _vim_cmd(args):
    return bool(args) and (args[0].split("/")[-1].startswith("get") or args[0] in ("hostsvc/hostsummary", "hostsvc/hosthardware"))


def _date(args):
    return not any(a == "--set" or a.startswith("--set=") or "s" in _letters(a) or re.match(r"^\d{4,}", a) for a in args)


def _vtysh(args):
    commands = [args[i + 1] for i, a in enumerate(args[:-1]) if a == "-c"]
    return bool(commands) and all(c.strip().startswith("show") for c in commands)


def _ipmitool(args):
    words = [a for a in args if not a.startswith("-")]
    text = " ".join(words)
    return bool(re.search(r"\b(sdr|sensor|fru|sel (list|elist|info)|chassis status|lan print|mc info|power status)\b", text)) \
        and not re.search(r"\b(set|clear|reset|raw|power (on|off|cycle|reset|soft)|delete)\b", text)


def _smartctl(args):
    return not any(_letters(a) & set("stXoS") or a.startswith(("--set", "--test", "--abort", "--offlineauto",
                                                                  "--saveauto", "--smart=")) for a in args)


def _sysctl(args):
    return not any(a in ("--write", "--load", "--system") or a.startswith("--load=") or _letters(a) & set("wpf") or "=" in a
                   for a in args)


def _nft(args):
    words = [a for a in args if not a.startswith("-")]
    return bool(words) and words[0] == "list"


def _iptables(args):
    lists = any(a in ("-L", "--list", "-S", "--list-rules") or re.match(r"^-[nvxt]*[LS][nvx]*$", a) for a in args)
    changes = any(re.match(r"^-[A-Za-z]*[ADIRFZNXPE]", a) and not re.match(r"^-[nvxt]*[LS][nvx]*$", a) for a in args) \
        or any(a.startswith(("--append", "--delete", "--insert", "--replace", "--flush", "--zero", "--new-chain",
                             "--delete-chain", "--policy", "--rename-chain")) for a in args)
    return lists and not changes


READ = {   # command -> True (any arguments) or a rule on its arguments
    **{c: True for c in (
        "cat", "head", "tail", "grep", "egrep", "fgrep", "zgrep", "zcat", "bzcat", "xzcat", "cut", "tr", "column", "jq",
        "df", "du", "free", "uptime", "uname", "nproc", "lscpu", "lsmem", "lspci", "lsusb", "lsblk", "blkid", "findmnt",
        "lsof", "ps", "pgrep", "pidof", "id", "whoami", "who", "w", "last", "lastlog", "getent", "ls", "stat", "file",
        "readlink", "realpath", "md5sum", "sha1sum", "sha256sum", "wc", "test", "[", "true", "false", "echo", "printf",
        "sleep", "ss", "netstat", "ping", "ping6", "traceroute", "traceroute6", "tracepath", "dig", "nslookup", "host",
        "vmstat", "iostat", "mpstat", "sar", "pidstat", "dmidecode", "lshw", "sensors", "pvs", "vgs", "lvs", "pvdisplay",
        "vgdisplay", "lvdisplay", "getenforce", "sestatus", "aa-status", "ntpq", "ntpstat", "named-checkconf",
        "varnishstat", "ibstat", "ibv_devinfo", "basename", "dirname", "printenv", "show", "display", "iptables-save",
        "ip6tables-save", "lsmod", "modinfo", "hostid", "arch", "tty", "locale")},
    "nc": lambda args: any(a == "-z" or re.match(r"^-[a-zA-Z]*z", a) for a in args) and not any("l" in a for a in args if a.startswith("-")),
    "numactl": _only_options("--hardware", "-H", "--show", "-s"), "multipath": _only_options("-ll", "-l", "-v1", "-v2"),
    "conntrack": lambda args: any(a in ("-L", "--dump", "-S", "--stats", "-C", "--count") for a in args)
    and _no_options("-D", "--delete", "-F", "--flush", "-U", "--update", "-I", "--create", "-E", "--event")(args),
    "top": lambda args: any(a.startswith("-b") for a in args), "sensors": _no_options("-s", "--set"),
    "named-checkzone": _no_options("-o"), "ss": _no_options("-K", "--kill"), "sar": _no_options("-o"),
    "lastlog": _no_options("-C", "--clear", "-S", "--set"),
    "sed": _sed, "awk": _awk, "gawk": _awk, "mawk": _awk, "curl": _curl, "ip": _ip,
    "find": _no_options("-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls"),
    "sort": _no_options("-o", "--output"),
    "uniq": lambda args: len([a for a in args if not a.startswith("-")]) <= 1,
    "systemctl": _verbs(("status", "is-active", "is-enabled", "is-failed", "list-units", "list-unit-files", "list-timers",
                         "list-sockets", "list-dependencies", "show", "cat", "get-default")),
    "journalctl": _no_options("--vacuum-size=", "--vacuum-time=", "--vacuum-files=", "--rotate", "--flush", "--sync",
                              "--relinquish-var", "--setup-keys", "--update-catalog"),
    "docker": _container, "podman": _container, "crictl": _verbs(("ps", "pods", "images", "logs", "inspect", "info", "stats", "version")),
    "virsh": _verbs(("list", "dominfo", "domstate", "domiflist", "domblklist", "domifaddr", "dumpxml", "nodeinfo", "net-list",
                     "pool-list", "vol-list", "capabilities", "version", "domstats", "domblkinfo", "net-dumpxml")),
    "pcs": _pcs, "crm_mon": lambda args: "-1" in args or "--one-shot" in args,
    "ovs-vsctl": _verbs(("show", "list", "get", "list-br", "list-ports", "list-ifaces", "find", "br-exists", "port-to-br",
                         "iface-to-br", "get-controller", "get-manager")),
    "ovs-ofctl": _verbs(("show", "dump-flows", "dump-ports", "dump-ports-desc", "dump-tables", "dump-groups", "dump-meters",
                         "queue-stats")),
    "ovn-nbctl": _verbs(("show", "list", "find", "get", "ls-list", "lr-list", "lsp-list", "lrp-list", "lr-route-list",
                         "lr-nat-list", "lb-list", "acl-list", "lsp-get-addresses", "lsp-get-port-security", "lsp-get-type",
                         "lsp-get-up")),
    "ovn-sbctl": _verbs(("show", "list", "find", "get", "lflow-list", "dump-flows", "chassis-list")),
    "esxcli": _esxcli, "vim-cmd": _vim_cmd,
    "nvidia-smi": _no_options("-r", "--gpu-reset", "-pm", "--persistence-mode", "-pl", "--power-limit", "-e", "--ecc-config",
                              "-c", "--compute-mode", "-ac", "--applications-clocks", "-rac", "-mig", "--multi-instance-gpu",
                              "-lgc", "--lock-gpu-clocks", "-rgc", "-lmc", "-rmc", "-cc", "-am", "-dm", "-caa"),
    "ethtool": _no_options("-s", "--change", "-K", "--features", "--offload", "-G", "--set-ring", "-A", "--pause", "-C",
                           "--coalesce", "-L", "--set-channels", "-E", "--change-eeprom", "-r", "--negotiate", "-p",
                           "--identify", "-f", "--flash", "-W", "--set-dump", "-U", "-N", "--config-nfc", "--reset",
                           "--set-priv-flags", "--set-eee", "--set-fec", "-X", "--set-rxfh-indir"),
    "dmesg": _no_options("-c", "-C", "--clear", "--read-clear", "-D", "--console-off", "-E", "--console-on", "-n",
                         "--console-level"),
    "hostnamectl": _verbs(("status",)), "timedatectl": _verbs(("status", "show", "list-timezones", "timesync-status")),
    "localectl": _verbs(("status", "list-locales", "list-keymaps")),
    "hostname": _only_options("-f", "-i", "-I", "-s", "-d", "-A", "--fqdn", "--short", "--domain", "--ip-address",
                              "--all-ip-addresses", "--all-fqdns"),
    "date": _date, "mount": lambda args: not args or args in (["-l"],) or (len(args) == 2 and args[0] == "-t"),
    "crontab": _only_options("-l"), "arp": _no_options("-d", "--delete", "-s", "--set", "-f", "--file"),
    "route": lambda args: not any(a in ("add", "del", "delete", "flush", "change") for a in args)
    and _no_options("-f", "--flush", "-F", "-C", "--cache")(args),
    "chronyc": _verbs(("tracking", "sources", "sourcestats", "activity", "ntpdata", "serverstats", "clients")),
    "unbound-control": _verbs(("status", "stats_noreset", "list_forwards", "list_stubs", "list_local_zones", "list_local_data",
                               "get_option", "dump_requestlist", "list_auth_zones")),
    "rndc": _verbs(("status",)), "nginx": _only_options("-t", "-T", "-v", "-V", "-q"),
    "haproxy": lambda args: "-c" in args and not any(a in ("-D", "-sf", "-st", "-x") for a in args),
    "varnishadm": _verbs(("status", "ping", "backend.list", "vcl.list", "param.show", "storage.list", "panic.show", "banner")),
    "vtysh": _vtysh, "ipmitool": _ipmitool, "smartctl": _smartctl, "sysctl": _sysctl, "nft": _nft,
    "iptables": _iptables, "ip6tables": _iptables,
    "openssl": lambda args: bool(args) and args[0] in ("x509", "s_client", "verify", "crl", "version", "ciphers")
    and not any(a.split("=")[0] in ("-out", "-sess_out", "-keylogfile", "-msgfile", "-trace") for a in args),
    "dmidecode": _no_options("--dump-bin", "--from-dump"), "lshw": _no_options("-dump"),
    "blkid": _no_options("-c", "-g", "--garbage-collect"), "file": _no_options("-C", "--compile"),
    "iptables-save": _no_options("-f", "--file"), "ip6tables-save": _no_options("-f", "--file"),
    "ntpq": lambda args: not any("config" in a or "keyid" in a or "passwd" in a for a in args),
    "tcpdump": _no_options("-w", "-z", "-Z"),
    "mtr": lambda args: "--report" in args or "-r" in args or "-rw" in args,
}
SAFE_REDIRECT = re.compile(r"(?<![\w>&])(?:[12]?>{1,2}\s*/dev/null|2>&1|1>&2|>&2)(?![\w/])")
SEPARATORS = ("|", "||", "&&", ";", "|&")
SUDO_OPTIONS = ("-n", "--non-interactive", "-E", "-H")
WRAPPERS = ("timeout", "nice", "ionice", "stdbuf")


def classify(command, group=""):
    """("read", "") when the command only reads, else ("change", why). Huawei: only "display ..." reads."""
    cmd = str(command or "").strip()
    if not cmd:
        return "change", "empty command"
    if group == "huawei":
        return ("read", "") if re.match(r"^display\s+\S", cmd) and not re.search(r"[|;&<>`$]", cmd) \
            else ("change", "only display commands run on Huawei routers")
    if "\n" in cmd:
        return "change", "a command of several lines"
    if any(x in cmd for x in ("`", "$(", "<(", ">(")):
        return "change", "command substitution ($(...) or `...`)"
    text = SAFE_REDIRECT.sub(" ", cmd)
    try:
        lex = shlex.shlex(text, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        lex.commenters = ""   # "file#>x" is a redirection for bash: never drop what follows a "#"
        tokens = list(lex)
    except ValueError as e:
        return "change", f"cannot read the command: {e}"
    segment, segments = [], []
    for tok in tokens:
        if tok in SEPARATORS:
            segments.append(segment)
            segment = []
        elif tok and set(tok) <= set("()<>&|;"):
            if tok in ("<", "<<", "<<<"):   # input from a file or text only
                segment.append(tok)
                continue
            if ">" in tok:
                return "change", "writes the output to a file (>)"
            return "change", f"shell syntax {tok!r} (subshell or background job)"
        else:
            segment.append(tok)
    segments.append(segment)
    for words in segments:
        words = [w for w in words if w not in ("<", "<<", "<<<")]
        if not words:
            continue
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[0]):
            return "change", "sets a variable before the command"
        while words and words[0] in ("sudo", "SUDO"):
            words = words[1:]
            while words and words[0] in SUDO_OPTIONS:
                words = words[1:]
        while words and words[0] in WRAPPERS:   # timeout 10 cmd / nice cmd: rate the command it runs
            words = words[1:]
            while words and (words[0].startswith("-") or re.match(r"^\d+[smhd]?$", words[0])):
                words = words[1:]
        if not words:
            continue
        name = words[0].rsplit("/", 1)[-1]
        if name == "run" and group == "vyos" and len(words) > 1 and words[1] == "show":
            continue
        if name in ("tee", "xargs", "watch", "bash", "sh", "vbash", "python", "python3", "perl"):
            return "change", f"{name} can write files or run other commands"
        rule = READ.get(name)
        if rule is None:
            return "change", f"{name} is not a known read command"
        if name in ("show", "display") and group not in ("vyos", "huawei"):
            return "change", f"{name} is a command of network devices"
        if rule is not True and not rule(words[1:]):
            return "change", f"{name} with these arguments can change the system"
    return "read", ""




# ---------------- the check of a template ----------------
SUDO_WORD = re.compile(r"(^|[|;&]\s*)sudo\s+(?:-n\s+)?")
RATE_CHARS = 200_000   # the end of a step's output its patterns are matched on
MAX_WAIT = 1800        # seconds a step may wait before the next one
MAX_WAITS = 3600       # seconds all the waits of a template add up to


def wait_of(step):
    """The seconds to wait after a step (0: none), within MAX_WAIT."""
    try:
        return max(0, min(MAX_WAIT, int(step.get("wait") or 0)))
    except (TypeError, ValueError):
        return 0


def wait_text(seconds):
    m, s = divmod(int(seconds), 60)
    return " ".join(x for x in (f"{m} minute{'s' if m != 1 else ''}" if m else "",
                                f"{s} second{'s' if s != 1 else ''}" if s else "") if x) or "0 seconds"


def waits(steps, group):
    """Where the waits of a template happen: {"read": {i: seconds}, "change": {i: seconds}} (i from 1). The read steps run
    with the check, so a read step waits only when a read step follows it; the change steps run as the fix, and the wait
    of the last one holds the check that runs again after the fix (time for a service to start). Huawei: no waits (each
    display command is its own connection)."""
    out = {"read": {}, "change": {}}
    if group == "huawei":
        return out
    modes = [classify(s.get("command"), group)[0] for s in steps]
    for i, (s, mode) in enumerate(zip(steps, modes), 1):
        seconds = wait_of(s)
        if seconds and (mode == "change" or "read" in modes[i:]):
            out[mode][i] = seconds
    return out


def host_command(command, group):
    """The command as it runs on the host: sudo -> SUDO (sudo -n, or nothing when the account is root); VyOS show
    commands through the operational-mode wrapper."""
    cmd = SUDO_WORD.sub(r"\1SUDO ", str(command).strip())
    if group == "vyos":
        cmd = re.sub(r"^(?:run\s+)?show\s", f"{VYOS_OP} show ", cmd)
    return cmd


def _line(text, match):
    start = text.rfind("\n", 0, match.start()) + 1
    end = text.find("\n", match.end())
    return text[start:end if end >= 0 else len(text)].strip()[:200]


class Template:
    """A template made on the portal: its steps come with the run (ctx["template"], from the portal database)."""
    sources = ("host", "device")
    phases = 1

    @staticmethod
    def reads(phase, data, params, ctx):
        t = ctx.get("template") or {}
        group = str(t.get("group") or "")
        src = "device" if group == "huawei" else "host"
        out = {src: {} if src == "device" else {"conn": "uname -n"}}
        pause = waits(t.get("steps") or [], group)["read"]
        for i, s in enumerate(t.get("steps") or [], 1):
            if classify(s.get("command"), group)[0] == "read":
                out[src][f"s{i}"] = s["command"] if src == "device" else host_command(s["command"], group)
                if i in pause:   # in the same script, between the two reads
                    out[src][f"w{i}"] = f"sleep {pause[i]}"
        return out

    @staticmethod
    def analyze(data, params, ctx):
        t = ctx.get("template") or {}
        group = str(t.get("group") or "")
        r = Result(str(t.get("id") or "template"))
        if group != "huawei":
            conn = source(data, "conn")
            why = str(conn.get("skipped") or "")   # connected, even when uname is missing
            r.step("conn", "Connection", "fail" if why else "ok",
                   f"{on_host(ctx)}: {why}" if why else f"Connected to {on_host(ctx)} ({text_of(conn).strip()[:80] or 'no name'}).")
        changes, commands, shown = [], [], []
        steps = t.get("steps") or []
        pause = waits(steps, group)
        for i, s in enumerate(steps, 1):
            key, title = f"s{i}", str(s.get("title") or f"Step {i}")
            if classify(s.get("command"), group)[0] != "read":
                changes.append(s)
                commands.append(s["command"])
                shown.append(f"{s['command']}   # {s.get('title', '')}")
                if i in pause["change"]:
                    after = "before the next step" if any(classify(x.get("command"), group)[0] != "read" for x in steps[i:]) \
                        else "then the check runs again"
                    commands.append(f"sleep {pause['change'][i]}")
                    shown.append(f"sleep {pause['change'][i]}   # wait {wait_text(pause['change'][i])}, {after}")
                continue
            item = source(data, key)
            why = str(item.get("skipped") or "") or ("" if "rc" in item else "not read")   # the exit code is rated below
            if why:
                r.skip(key, title, why)
                continue
            text, rc = text_of(item), item.get("rc", 0)
            status, notes, marks = "ok", [], []
            if s.get("fail_on_error", True) and rc not in (0, None):
                status = "fail"
                notes.append(f"the command ended with exit code {rc}")
            for rule, label in (("problem_if", "Problem"), ("expect", "Problem"), ("warning_if", "Warning")):
                pattern = str(s.get(rule) or "")
                if not pattern:
                    continue
                try:   # on the end of the output only (a long output and a heavy pattern must not hold the job)
                    found = re.search(pattern, text[-RATE_CHARS:], re.I | re.M)
                except re.error:
                    found = None
                if rule == "expect" and not found:
                    status = "fail"
                    notes.append(f"the output does not contain “{pattern}”")
                elif rule != "expect" and found and (rule == "problem_if" or status == "ok"):
                    status = "fail" if rule == "problem_if" else "warn"
                    line = _line(text, found)
                    marks.append(line)
                    notes.append(f"the output contains “{line}”")
            last = next((l.strip() for l in reversed(text.splitlines()) if l.strip()), "")
            note = "; ".join(notes)
            detail = (note[:1].upper() + note[1:] + ".") if notes else \
                (f"Exit code {rc}." + (f" {last[:200]}" if last else " No output."))
            r.step(key, title, status, detail, evidence=f"$ {s.get('command')}\n{text}" if text else f"$ {s.get('command')}",
                   marks=marks)
            if i in pause["read"]:
                waited, title = source(data, f"w{i}"), f"Wait {wait_text(pause['read'][i])}"
                if waited.get("rc") == 0:
                    r.step(f"w{i}", title, "info", f"Waited {wait_text(pause['read'][i])} before the next step.")
                else:
                    r.skip(f"w{i}", title, str(waited.get("skipped") or "") or (
                        f"The wait ended with exit code {waited['rc']}." if "rc" in waited else "The wait did not run."))
        if changes:
            n = len(changes)
            wait = sum(pause["change"].values())
            r.recommend(f"Run the {n} change step{'s' if n != 1 else ''} of this template on {on_host(ctx)}. They run in "
                        "this order as one script and stop at the first command that fails"
                        + (f", with the waits of the template ({wait_text(wait)} in all)." if wait else "."),
                        shown, where=on_host(ctx),
                        action={"commands": commands, "shell": str(t.get("shell") or "sh"), "risk": "high",
                                "operation": True, "wait": wait},
                        warning="These steps change the host. The template runs again by itself after the fix, to check the result.")
        return r.done()

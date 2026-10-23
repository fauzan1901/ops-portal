"""Operation Automation checks on Linux and ESXi hosts listed in sites.yml (hosts: groups), read over SSH with a read-only account.

The commands are fixed here (never typed by the operator); parameters are validated before they reach a command and
are quoted. "SUDO " at the start of a command part becomes "sudo -n " when the host group has sudo: true (a sudoers
rule that only allows these read commands), otherwise it is dropped. The fixes are the commands for THIS host, with the
values found (PIDs, files, sizes, rule handles); the portal never runs them.
"""
import datetime
import re
import shlex

from .common import Result, human, kib, level, lines, on_host, parse_df, parse_size, source, text_of, unavailable

q = shlex.quote


def df_pct(data, key, mount):
    rows = parse_df(text_of(source(data, key)))
    return next((x for x in rows if x["mount"] == mount), rows[0] if rows else None)


def numbers(text):
    return [int(x) for x in re.findall(r"\d+", str(text or ""))]


def disk_step(r, data, key, mount, title, warn=80, fail=90):
    row = df_pct(data, key, mount)
    if not row:
        r.step(key, title, "fail", f"df failed: {unavailable(source(data, key)) or 'no output'}")
        return None
    status = level(row["pct"], warn, fail)
    r.step(key, title, status, f"{mount} on {row['fs']}: {row['pct']}% used, {kib(row['avail_kb'])} free of {kib(row['size_kb'])}.",
           evidence=text_of(source(data, key)))
    return row


def service_states(text):
    """`systemctl is-active a b` (one state per line, in order) or "name state" lines."""
    return [l.split()[-1] for l in lines(text)]


# Process name -> systemd unit that holds deleted log files (restart releases the space).
UNIT_OF = {"rsyslogd": "rsyslog", "haproxy": "haproxy", "nginx": "nginx", "varnishd": "varnish", "journald": "systemd-journald",
           "systemd-journal": "systemd-journald", "dockerd": "docker", "java": "", "mongod": "mongod"}

LOGROTATE_HAPROXY = """sudo tee /etc/logrotate.d/haproxy >/dev/null <<'EOF'
/var/log/haproxy.log {
    daily
    rotate 7
    size 500M
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
}
EOF"""


# =========================================================================================== CDN
class CdnDiskRun:
    """WI "Disk Full Alert on /run" (disk_alert_cdn_*, tmpfs /run full of AIDE files)."""
    sources = ("host",)
    phases = 1

    @staticmethod
    def reads(phase, data, params, ctx):
        return {"host": {"df": "df -Pk /run", "aide_size": "SUDO du -sk /run/aide 2>/dev/null || echo 0",
                         "aide_files": "SUDO find /run/aide -type f 2>/dev/null | wc -l",
                         "aide_proc": "pgrep -a aide 2>/dev/null; true"}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("cdn-disk-run")
        row = disk_step(r, data, "df", "/run", "Usage of /run (tmpfs)", 85, 95)
        aide_kb = (numbers(text_of(source(data, "aide_size"))) or [0])[0]
        files = (numbers(text_of(source(data, "aide_files"))) or [0])[0]
        share = round(aide_kb * 100 / row["used_kb"], 1) if row and row["used_kb"] else 0
        running = [l for l in lines(text_of(source(data, "aide_proc"))) if "aide" in l]
        r.step("aide", "Temporary AIDE files in /run/aide", "warn" if share >= 50 and row and row["pct"] >= 85 else "ok",
               f"{files} file(s), {kib(aide_kb)} ({share}% of what /run uses)." + (f" AIDE is running now (PID {running[0].split()[0]})." if running else ""))
        if row and row["pct"] >= 85:
            after = row["pct"] - round(aide_kb * 100 / row["size_kb"]) if row["size_kb"] else None
            cmds = ([f"sudo kill {running[0].split()[0]}   # AIDE scan still writing to /run/aide; let it end first if it may"] if running else [])
            cmds += ["sudo rm -rf /run/aide/*", "df -h /run"]
            fix = {"commands": ([f"sudo kill {running[0].split()[0]}"] if running else []) + ["sudo rm -rf /run/aide/*", "df -h /run"]}
            r.recommend(f"Free {kib(aide_kb)} on /run by deleting the {files} temporary AIDE files (safe; never delete /run itself)"
                        + (f": /run should drop to about {after}%." if after is not None else ".") + " If /run stays full, reboot the VM "
                        "and check again after the boot.",
                        cmds + ["sudo reboot   # only if /run is still full", "df -h /run   # after the reboot"],
                        where=on_host(ctx), action=fix,
                        warning="If /run fills again after a reboot, AIDE (or another service) keeps writing there: investigate. "
                                "The portal fix does not reboot.")
        return r.done()


class CdnRootDisk:
    """WI "Alert Root Disk Troubleshooting" (disk_alert_cdn_*, / full; earlier cause: /var/log/haproxy.log ~141 GB)."""
    sources = ("host",)
    phases = 1

    @staticmethod
    def reads(phase, data, params, ctx):
        return {"host": {"df": "df -Pk /",
                         "top": "SUDO du -xsk /var/log/* /var/lib/docker /root /log 2>/dev/null | sort -rn | head -12",
                         "haproxy": "SUDO stat -c '%s' /var/log/haproxy.log 2>/dev/null || echo missing",
                         "logrotate": "cat /etc/logrotate.d/haproxy 2>/dev/null || echo MISSING",
                         "journal": "journalctl --disk-usage 2>/dev/null; true",
                         "deleted": "SUDO lsof -nP +L1 2>/dev/null | awk 'NR>1 {print $1, $2, $7}' | sort -k3 -rn | head -10",
                         "services": "systemctl is-active haproxy rsyslog 2>/dev/null; true"}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("cdn-root-disk")
        where = on_host(ctx)
        row = disk_step(r, data, "df", "/", "Usage of the root filesystem /", 80, 90)
        top = []
        for l in lines(text_of(source(data, "top"))):
            parts = l.split(None, 1)
            if len(parts) == 2 and parts[0].isdigit():
                top.append((parts[1], int(parts[0])))
        r.step("top", "Largest folders and files", "info", "Largest first (du -x, same filesystem).",
               {"columns": ["Path", "Size"], "rows": [[p, kib(k)] for p, k in top]})
        hx = text_of(source(data, "haproxy")).strip()
        size = int(hx) if hx.isdigit() else None
        r.step("haproxy_log", "Size of /var/log/haproxy.log", level(size / 1024 ** 3 if size is not None else None, 1, 10)
               if size is not None else "info", f"{human(size)}." if size is not None else "The file does not exist.")
        rotate = text_of(source(data, "logrotate"))
        has_rotate = "MISSING" not in rotate and "haproxy" in rotate
        r.step("logrotate", "Logrotate for HAProxy", "ok" if has_rotate else "warn",
               "Configured." if has_rotate else "/etc/logrotate.d/haproxy is missing: the log grows without limit.",
               evidence=rotate if has_rotate else None)
        journal = text_of(source(data, "journal"))
        m = re.search(r"take up ([0-9.]+[KMGT]?)", journal)
        jsize = parse_size(m.group(1)) if m else None
        r.step("journal", "systemd journal size", level(jsize / 1024 ** 3 if jsize else None, 1, 4) if jsize else "info",
               f"{human(jsize)}." if jsize else (journal.strip() or "Unknown."))
        holders = []
        for l in lines(text_of(source(data, "deleted"))):
            parts = l.split()
            if len(parts) == 3 and parts[1].isdigit() and parts[2].isdigit():
                holders.append((parts[0], parts[1], int(parts[2])))
        held = sum(h[2] for h in holders)
        r.step("deleted", "Deleted files still held open", "warn" if held > 256 * 1024 ** 2 else "ok",
               f"{len(holders)} file(s), {human(held)} still used on disk"
               + (f" (by {', '.join(sorted({h[0] for h in holders}))})." if holders else "."))
        states = service_states(text_of(source(data, "services")))
        bad = [f"{n} {s}" for n, s in zip(["haproxy", "rsyslog"], states) if s != "active"]
        r.step("services", "HAProxy and rsyslog are active", "fail" if bad else "ok", f"Not active: {', '.join(bad)}." if bad else "Both active.")
        freed = 0
        if size and size > 1024 ** 3:
            freed += size
            r.recommend(f"Empty /var/log/haproxy.log ({human(size)}) with truncate — the file stays, HAProxy keeps logging, "
                        "nothing else is deleted.",
                        ["sudo truncate -s 0 /var/log/haproxy.log", "df -h /", "sudo systemctl is-active haproxy rsyslog"],
                        where=where, action={"commands": ["sudo truncate -s 0 /var/log/haproxy.log", "df -h /",
                                                          "sudo systemctl is-active haproxy rsyslog"]},
                        warning="Never rm -rf /var, /var/lib, /etc, /usr, /etc/haproxy, /var/lib/docker or the "
                                             "/root/<site> folders without approval.")
        if not has_rotate:
            r.recommend("Create the HAProxy logrotate rule so the log cannot grow without limit again, test it (dry run, then once for real).",
                        [LOGROTATE_HAPROXY, "sudo logrotate -d /etc/logrotate.d/haproxy", "sudo logrotate -f /etc/logrotate.d/haproxy",
                         "ls -lh /var/log/haproxy.log*"], where=where,
                        action={"commands": [LOGROTATE_HAPROXY, "sudo logrotate -d /etc/logrotate.d/haproxy",
                                             "sudo logrotate -f /etc/logrotate.d/haproxy", "ls -lh /var/log/haproxy.log*"]})
        if jsize and jsize > 1024 ** 3:
            freed += jsize - 700 * 1024 ** 2
            r.recommend(f"Shrink the journal from {human(jsize)} to 700 MB.", ["sudo journalctl --vacuum-size=700M"], where=where,
                        action={"commands": ["sudo journalctl --vacuum-size=700M", "journalctl --disk-usage"]})
        if held > 256 * 1024 ** 2:
            units = sorted({UNIT_OF.get(h[0], h[0]) for h in holders if UNIT_OF.get(h[0], h[0])})
            r.recommend(f"{human(held)} of deleted files is still held open by {', '.join(sorted({h[0] for h in holders}))}: "
                        "restart them to release the space.",
                        [f"sudo systemctl restart {u}" for u in units] + ["sudo lsof -nP +L1 | head", "df -h /"], where=where,
                        action={"commands": [f"sudo systemctl restart {u}" for u in units] + ["df -h /"]})
        if row and row["pct"] >= 80 and not freed and not held:
            biggest = top[0] if top else None
            r.recommend("The largest consumer is not a known log: look at it before deleting anything.",
                        [f"sudo du -xh --max-depth=2 {q(biggest[0])} | sort -rh | head -20" if biggest else "sudo du -xh --max-depth=2 / | sort -rh | head -20"],
                        where=where)
        return r.done()


class CdnMemory:
    """WI "Memory Alert CDN DCA-DCB-DCC" (memory_alert_cdn_*, >90%: Varnish, Docker HAProxy 'lb', or a stuck logparser)."""
    sources = ("host",)
    phases = 1

    @staticmethod
    def reads(phase, data, params, ctx):
        return {"host": {"mem": "grep -E '^(MemTotal|MemAvailable):' /proc/meminfo",
                         "top": "ps -eo pid,user,comm,rss,pcpu --sort=-rss | head -12",
                         "varnish": "systemctl is-active varnish 2>/dev/null; true",
                         "docker": "SUDO docker ps -a 2>&1 | head -20",
                         "dstats": "SUDO docker stats --no-stream 2>&1 | head -20",
                         "logparser": "pgrep -a logparser 2>/dev/null | head -30; true"}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("cdn-memory")
        where = on_host(ctx)
        mem = dict(re.findall(r"^(\w+):\s+(\d+)", text_of(source(data, "mem")), re.M))
        total, avail = int(mem.get("MemTotal", 0)), int(mem.get("MemAvailable", 0))
        used_pct = round((total - avail) * 100 / total, 1) if total else None
        r.step("memory", "Memory usage", level(used_pct, 80, 90),
               f"{used_pct}% used ({kib(total - avail)} of {kib(total)}); the alert fires above 90%." if total else "Unknown.",
               marks=["MemAvailable"])
        procs = []
        for l in lines(text_of(source(data, "top")))[1:]:
            parts = l.split(None, 4)
            if len(parts) == 5 and parts[3].isdigit():
                procs.append({"pid": parts[0], "user": parts[1], "comm": parts[2], "rss": int(parts[3]), "cpu": parts[4]})
        r.step("top", "Processes using the most memory", "info", "Largest first.",
               {"columns": ["PID", "User", "Process", "Memory", "CPU %"],
                "rows": [[p["pid"], p["user"], p["comm"], kib(p["rss"]), p["cpu"]] for p in procs]})
        varnish_kb = sum(p["rss"] for p in procs if p["comm"].startswith(("varnishd", "cache-main")))
        lb_kb = sum(p["rss"] for p in procs if p["comm"].startswith("haproxy"))
        lb_line = next((l for l in lines(text_of(source(data, "dstats"))) if re.search(r"\blb\b", l)), "")
        parsers = [l for l in lines(text_of(source(data, "logparser"))) if "logparser" in l]
        parser_kb = sum(p["rss"] for p in procs if p["comm"].startswith("logparser"))
        culprits = []
        if total and varnish_kb > total * 0.4:
            culprits.append("varnish")
        if total and lb_kb > total * 0.25 or re.search(r"\b([5-9]\d|100)\.\d+%", lb_line):
            culprits.append("lb")
        if len(parsers) > 3:
            culprits.append("logparser")
        r.step("cause", "Which service takes the memory", "warn" if culprits and used_pct and used_pct >= 80 else "ok",
               ", ".join({"varnish": f"Varnish ({kib(varnish_kb)})", "lb": f"Docker HAProxy lb ({lb_line.strip() or kib(lb_kb)})",
                          "logparser": f"{len(parsers)} logparser processes ({kib(parser_kb)} in the top list, stuck, from crontab)"}[c]
                         for c in culprits) or "No single service stands out.",
               marks=[{"varnish": "varnish", "lb": " lb ", "logparser": " logparser "}[c] for c in culprits])
        if "logparser" in culprits:
            pids = [l.split()[0] for l in parsers[:30]]
            r.recommend(f"Stop the {len(pids)} stuck logparser processes (they do not read or write HAProxy logs: safe to kill; "
                        f"crontab starts it again later). About {kib(parser_kb)} comes back.",
                        [f"sudo kill -TERM {' '.join(pids)}", "sleep 5",
                         f"sudo kill -9 {' '.join(pids)} 2>/dev/null || true   # only those that did not stop", "free -m",
                         "pgrep -a logparser"], where=where,
                        action={"commands": [f"sudo kill -TERM {' '.join(pids)} 2>/dev/null || true", "sleep 5",
                                             f"sudo kill -9 {' '.join(pids)} 2>/dev/null || true", "free -m",
                                             "pgrep -a logparser || true"]})
        if "varnish" in culprits:
            r.recommend(f"Restart Varnish ({kib(varnish_kb)}): safe, it only empties the cache (more origin traffic for a while).",
                        ["sudo systemctl restart varnish", "systemctl is-active varnish", "free -m"], where=where,
                        action={"commands": ["sudo systemctl restart varnish", "systemctl is-active varnish", "free -m"]})
        if "lb" in culprits:
            r.recommend("Restart the Docker HAProxy container lb (Prometheus runs inside it: data comes back after 1-2 minutes). "
                        "Do it quickly to keep the interruption short.",
                        ["sudo docker restart lb", "sudo docker ps --filter name=lb", "free -m"], where=where,
                        action={"commands": ["sudo docker restart lb", "sudo docker ps --filter name=lb", "free -m"]})
        if used_pct and used_pct >= 90 and not culprits:
            top = procs[0] if procs else None
            r.recommend("Memory stays high without a known cause: look at the biggest process before restarting anything "
                        "(possible leak or loop).",
                        [f"sudo cat /proc/{top['pid']}/status | grep -E 'Name|VmRSS|Threads'" if top else "ps aux --sort=-rss | head",
                         f"sudo systemctl status $(ps -o unit= -p {top['pid']})" if top else ""], where=where)
        return r.done()


PROM_TARGET = re.compile(r"server\s+\S+\s+([0-9A-Za-z_.-]+:\d+)")


class CdnDatasource:
    """WI "Datasource Error site DCB&DCA&DCC" (Grafana DatasourceError: Prometheus runs inside the Docker HAProxy 'lb')."""
    sources = ("host",)
    phases = 2

    @staticmethod
    def reads(phase, data, params, ctx):
        if phase == 1:
            return {"host": {"docker": "SUDO docker ps -a 2>&1 | head -20",
                             "backend": "SUDO docker exec lb sh -c 'grep -iA3 prometheus /usr/local/etc/haproxy/haproxy.cfg' 2>&1 | head -20"}}
        target = PROM_TARGET.search(text_of(source(data, "backend")))
        address = target.group(1) if target else "127.0.0.1:9090"
        return {"host": {"ready": f"curl -s -o /dev/null -m 5 -w '%{{http_code}}' http://{address}/-/ready; echo; true"}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("cdn-datasource")
        rows = [l for l in lines(text_of(source(data, "docker")))]
        lb = next((l for l in rows[1:] if re.search(r"\s(lb|haproxy)\s*$", l)), "")
        up = " Up " in f" {lb} "
        exited = re.search(r"Exited \((\d+)\) (.+?) ago", lb)
        r.step("container", "Docker HAProxy container (lb) running", "ok" if up else "fail",
               (lb.strip() if lb else "No container named lb.") + ("" if up else " Prometheus stops with it."),
               evidence="\n".join(rows))
        backend = text_of(source(data, "backend"))
        target = PROM_TARGET.search(backend)
        r.step("backend", "Prometheus backend in haproxy.cfg", "ok" if target else "warn",
               f"Backend {target.group(1)}." if target else "Not readable while lb is stopped." if not up else "No Prometheus backend line found.",
               evidence=backend)
        code = (re.findall(r"\b(\d{3})\b", text_of(source(data, "ready"))) or ["000"])[0]
        r.step("ready", "Prometheus answers (/-/ready)", "ok" if code == "200" else "fail", f"HTTP {code}.")
        where = on_host(ctx)
        ready_url = f"http://{target.group(1) if target else '127.0.0.1:9090'}/-/ready"
        if not up:
            r.recommend("Start the stopped lb container" + (f" (exited with code {exited.group(1)} {exited.group(2)} ago)" if exited else "")
                        + "; Prometheus starts with it. Then check Grafana Test: no DatasourceError, no 503/timeout.",
                        ["sudo docker logs --tail 50 lb", "sudo docker start lb", "sudo docker ps --filter name=lb",
                         f"curl -s -o /dev/null -w '%{{http_code}}\\n' {ready_url}"],
                        where=where, action={"commands": ["sudo docker logs --tail 50 lb", "sudo docker start lb", "sleep 5",
                                                          "sudo docker ps --filter name=lb",
                                                          f"curl -s -o /dev/null -w '%{{http_code}}\\n' {ready_url} || true"]},
                        warning="Exit code 137 = killed (out of memory): run the check \"Alert: memory\" on this host too.")
        elif code != "200":
            r.recommend("lb runs but Prometheus does not answer: restart the container (Prometheus is inside it, not an OS service).",
                        ["sudo docker restart lb", f"curl -s -o /dev/null -w '%{{http_code}}\\n' {ready_url}"],
                        where=where, warning="Do not change haproxy.cfg without a backup.",
                        action={"commands": ["sudo docker restart lb", "sleep 5", f"curl -s -o /dev/null -w '%{{http_code}}\\n' {ready_url} || true"]})
        return r.done()


class CdnRepo:
    """WI "cdn user alert repo" (cdn_user_alert: repository website unreachable — nginx down or SSL expired)."""
    sources = ("host",)
    phases = 1

    @staticmethod
    def reads(phase, data, params, ctx):
        domain = params.get("domain") or "ubuntu-mirror.example.com"
        return {"host": {"nginx": "systemctl is-active nginx 2>/dev/null; true",
                         "nginx_t": "SUDO nginx -t 2>&1 | tail -3",
                         "cert": f"echo | openssl s_client -connect 127.0.0.1:443 -servername {q(domain)} 2>/dev/null | "
                                 "openssl x509 -noout -enddate -subject 2>/dev/null",
                         "http": f"curl -sk -o /dev/null -m 10 -w '%{{http_code}}' -H {q('Host: ' + domain)} https://127.0.0.1/; echo; true",
                         "now": "date -u +%s"}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("cdn-repo")
        where = on_host(ctx)
        domain = params.get("domain") or "ubuntu-mirror.example.com"
        state = (service_states(text_of(source(data, "nginx"))) or ["unknown"])[0]
        r.step("nginx", "Web service nginx", "ok" if state == "active" else "fail", f"nginx is {state}.")
        test = text_of(source(data, "nginx_t"))
        good = "test is successful" in test or "syntax is ok" in test
        r.step("config", "nginx configuration test", "ok" if good else "warn", "nginx -t passed." if good else "nginx -t did not pass.",
               evidence=test)
        cert = text_of(source(data, "cert"))
        m = re.search(r"notAfter=(.+)", cert)
        now = (lambda v: int(v[0]) if v else None)(numbers(text_of(source(data, "now"))))
        days = None
        if m and now:
            try:
                end = datetime.datetime.strptime(m.group(1).strip(), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
                days = int((end.timestamp() - now) // 86400)
            except ValueError:
                pass
        r.step("ssl", f"SSL certificate of {domain}", "fail" if days is not None and days < 0 else "warn"
               if days is None or days < 14 else "ok",
               (f"Expired {-days} day(s) ago ({m.group(1).strip()})." if days is not None and days < 0 else
                f"Valid until {m.group(1).strip()} ({days} days left)." if days is not None else "Certificate could not be read."))
        code = (re.findall(r"\b(\d{3})\b", text_of(source(data, "http"))) or ["000"])[0]
        r.step("http", f"https://{domain} answers", "ok" if code[0] in "23" else "fail", f"HTTP {code}.")
        if days is not None and days < 14:
            if domain == "repo-mirror.example.com":
                r.recommend(f"Renew the certificate of {domain} with certbot on this VM, then reload nginx.",
                            [f"sudo certbot renew --cert-name {domain} --force-renewal", "sudo nginx -t", "sudo systemctl reload nginx"],
                            where=where, action={"commands": [f"sudo certbot renew --cert-name {domain} --force-renewal",
                                                              "sudo nginx -t", "sudo systemctl reload nginx"]})
            else:
                r.recommend(f"Renew the certificate of {domain} in Acme SSL (Ops Portal → project acme-cloud project → Acme SSL → "
                            f"{domain} → Renew), install the new files on this VM, then reload nginx.",
                            ["sudo nginx -t", "sudo systemctl reload nginx",
                             f"echo | openssl s_client -connect 127.0.0.1:443 -servername {domain} 2>/dev/null | openssl x509 -noout -enddate"],
                            where=where)
        if state != "active":
            r.recommend("Start nginx" + (" (the configuration test passes)" if good else " after fixing the error that nginx -t shows")
                        + ", then check the website.",
                        ["sudo nginx -t", "sudo systemctl start nginx", "sudo systemctl status nginx --no-pager -n 20",
                         f"curl -sI https://{domain}/ | head -1"], where=where,
                        action={"commands": ["sudo nginx -t", "sudo systemctl start nginx", "systemctl is-active nginx",
                                             f"curl -skI --resolve {domain}:443:127.0.0.1 https://{domain}/ | head -1"]} if good else None)
        return r.done()


class CdnVarnishMse:
    """WI "Resize Varnish MSE Cache" — pre-check, and the resize commands with the sizes of this host (a change with
    approval: the portal does not run it)."""
    sources = ("host",)
    phases = 1

    @staticmethod
    def reads(phase, data, params, ctx):
        return {"host": {"version": "varnishd -V 2>&1 | head -1",
                         "conf": "SUDO grep -nE 'database_size|filename|size' /var/lib/mse/mse.conf 2>&1",
                         "df": "df -Pk /cache",
                         "stats": "SUDO varnishstat -1 2>/dev/null | grep -E 'MSE_STORE.store.g_objects|MSE_STORE.store.g_alloc_bytes|"
                                  "MSE_STORE.store.g_free_bytes|MSE.mse.c_fail|MSE.mse.n_lru_nuked|MAIN.backend_fail'",
                         "active": "systemctl is-active varnish 2>/dev/null; true",
                         "ping": "SUDO varnishadm ping 2>&1 | head -1",
                         "aide": "pgrep -a aide 2>/dev/null; true",
                         "store": "SUDO stat -c '%s %U:%G %a' /cache/mse/store.dat 2>&1"}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("cdn-varnish-mse")
        where = on_host(ctx)
        version = text_of(source(data, "version")).strip()
        r.step("version", "Varnish Cache Plus with MSE (not MSE4)", "ok" if "plus" in version.lower() else "warn", version or "Unknown.")
        conf = text_of(source(data, "conf"))
        size = re.search(r'\bsize\s*=\s*"([^"]+)"', conf)
        current = size.group(1) if size else ""
        r.step("conf", "Store size in /var/lib/mse/mse.conf", "info", f"size = {current}" if current else "Not found.", evidence=conf)
        row = disk_step(r, data, "df", "/cache", "Usage of /cache (df)", 90, 98)
        stats = dict((k, int(v)) for k, v in re.findall(r"^(\S+)\s+(\d+)", text_of(source(data, "stats")), re.M))
        alloc, free = stats.get("MSE_STORE.store.g_alloc_bytes"), stats.get("MSE_STORE.store.g_free_bytes")
        inner = round(alloc * 100 / (alloc + free), 1) if alloc is not None and free else None
        r.step("inner", "Cache use inside MSE", "info",
               (f"{inner}% of the store holds objects ({stats.get('MSE_STORE.store.g_objects', 0)} objects)."
                + (" df shows the preallocated store file, not the cache use." if row and row["pct"] >= 90 and inner is not None and inner < 50 else ""))
               if inner is not None else "varnishstat MSE counters not available.")
        fails = stats.get("MSE.mse.c_fail", 0)
        r.step("errors", "MSE failures", "warn" if fails else "ok", f"MSE.mse.c_fail = {fails}.")
        state = (service_states(text_of(source(data, "active"))) or ["unknown"])[0]
        pong = "PONG" in text_of(source(data, "ping"))
        r.step("service", "varnish.service active, varnishadm PONG", "ok" if state == "active" and pong else "fail",
               f"varnish {state}, varnishadm {'PONG' if pong else 'no answer'}.")
        aide = [l for l in lines(text_of(source(data, "aide"))) if "aide" in l]
        r.step("aide", "AIDE is not scanning the store", "warn" if aide else "ok",
               "AIDE is running: stop it according to the SOP before any resize." if aide else "AIDE is not running.")
        store_bytes = (numbers(text_of(source(data, "store"))) or [0])[0]
        if row and row["pct"] >= 90 and current and store_bytes:
            # Target = what brings /cache to ~50% (as the WI: 940G on a 1007G filesystem -> 470G), rounded down to 10G.
            fs_g = row["size_kb"] / 1024 ** 2
            other_g = max(row["used_kb"] / 1024 ** 2 - store_bytes / 1024 ** 3, 0)
            target_g = int(max(10, (fs_g * 0.5 - other_g) // 10 * 10))
            target_bytes = target_g * 1024 ** 3
            r.step("target", "Size for /cache at about 50%", "info",
                   f"{current} → {target_g}G (store file {target_bytes} bytes); /cache would be about "
                   f"{round((target_bytes / 1024 ** 3 + other_g) * 100 / fs_g)}%.")
            ts = "$(date +%Y%m%d-%H%M%S)"
            r.recommend(f"Resize the MSE store from {current} to {target_g}G, inside an approved change with the node drained from "
                        "the load balancer (the whole cache is emptied).",
                        ([f"sudo pkill -TERM -x aide   # AIDE {aide[0].split()[0]} is reading the store"] if aide else [])
                        + [f"sudo cp -a /var/lib/mse/mse.conf /var/lib/mse/mse.conf.before-{target_g}G-{ts}",
                           f"sudo sed -i 's/size = \"{current}\";/size = \"{target_g}G\";/' /var/lib/mse/mse.conf",
                           "sudo grep -nE 'database_size|filename|size' /var/lib/mse/mse.conf",
                           "sudo systemctl stop varnish.service",
                           "sudo lsof /cache/mse/store.dat   # must show nothing",
                           "sudo /usr/bin/mkfs.mse -c /var/lib/mse/mse.conf -f; echo \"mkfs.mse exit code: $?\"",
                           "sudo chown -R varnish:varnish /varnish-cache/mse",
                           "sudo chown varnish:varnish /cache/mse /cache/mse/store.dat",
                           "sudo chmod 0755 /varnish-cache/mse /varnish-cache/mse/book /cache/mse",
                           "sudo chmod 0644 /cache/mse/store.dat",
                           "sudo systemctl reset-failed varnish.service",
                           "sudo systemctl start varnish.service",
                           f"sudo stat -c '%s %U:%G %a %n' /cache/mse/store.dat   # expect {target_bytes} varnish:varnish 644",
                           "df -hT /cache", "sudo varnishadm ping"],
                        where=where,
                        action={"risk": "high", "commands": ([f"sudo pkill -TERM -x aide"] if aide else []) + [
                            f"sudo cp -a /var/lib/mse/mse.conf /var/lib/mse/mse.conf.before-{target_g}G-$(date +%Y%m%d-%H%M%S)",
                            f"sudo sed -i 's/size = \"{current}\";/size = \"{target_g}G\";/' /var/lib/mse/mse.conf",
                            f"sudo grep -q 'size = \"{target_g}G\";' /var/lib/mse/mse.conf",
                            "sudo systemctl stop varnish.service",
                            "! sudo lsof /cache/mse/store.dat",
                            "sudo /usr/bin/mkfs.mse -c /var/lib/mse/mse.conf -f",
                            "sudo chown -R varnish:varnish /varnish-cache/mse",
                            "sudo chown varnish:varnish /cache/mse /cache/mse/store.dat",
                            "sudo chmod 0755 /varnish-cache/mse /varnish-cache/mse/book /cache/mse",
                            "sudo chmod 0644 /cache/mse/store.dat",
                            "sudo systemctl reset-failed varnish.service",
                            "sudo systemctl start varnish.service",
                            f"test \"$(sudo stat -c '%s %U:%G %a' /cache/mse/store.dat)\" = '{target_bytes} varnish:varnish 644'",
                            "df -hT /cache", "sudo varnishadm ping"]},
                        warning=f"Rollback: copy the mse.conf.before-{target_g}G-* backup back, run mkfs.mse -f again and start "
                                "Varnish. Never create the store with rm, truncate, dd or fallocate.")
        return r.done()


# =========================================================================================== DNS
class DnsRecursorSyslog:
    """WI "Recursive DNS Disk Log Full Alert" (PowerDNS Recursor quiet=no fills /var/log/syslog)."""
    sources = ("host",)
    phases = 1

    @staticmethod
    def reads(phase, data, params, ctx):
        return {"host": {"df": "df -Pk /",
                         "logs": "SUDO du -sk /var/log/syslog* 2>/dev/null",
                         "conf": "SUDO grep -HsE '^[[:space:]]*(quiet|loglevel|structured-logging)[[:space:]]*=' "
                                 "/etc/powerdns/recursor.conf /etc/powerdns/recursor.d/*.conf",
                         "spam": "SUDO tail -n 2000 /var/log/syslog 2>/dev/null | grep -c 'Question answered from packet cache'; true",
                         "service": "systemctl is-active pdns-recursor 2>/dev/null; true",
                         "journal": "journalctl --disk-usage 2>/dev/null; true"}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("dns-recursor-syslog")
        where = on_host(ctx)
        row = disk_step(r, data, "df", "/", "Usage of the root filesystem /", 80, 90)
        logs = []
        for l in lines(text_of(source(data, "logs"))):
            parts = l.split(None, 1)
            if len(parts) == 2 and parts[0].isdigit():
                logs.append((parts[1], int(parts[0])))
        syslog_kb = next((s for p, s in logs if p == "/var/log/syslog"), 0)
        archives = [p for p, _ in logs if p != "/var/log/syslog"]
        r.step("syslog", "Size of /var/log/syslog", level(syslog_kb / 1024 ** 2, 1, 5),
               f"/var/log/syslog is {kib(syslog_kb)}; all syslog files {kib(sum(s for _, s in logs))}.",
               {"columns": ["File", "Size"], "rows": [[p, kib(s)] for p, s in logs]})
        settings, quiet_file = {}, ""
        for l in lines(text_of(source(data, "conf"))):
            path, sep, rest = l.partition(":")
            m = re.match(r"^\s*([\w-]+)\s*=\s*(\S+)", rest if sep else path)
            if m:
                settings[m.group(1)] = m.group(2)
                if m.group(1) == "quiet" and sep:
                    quiet_file = path
        quiet = settings.get("quiet", "")
        r.step("quiet", "Query logging of the recursor (quiet)", "fail" if quiet == "no" else "ok",
               (f"quiet=no in {quiet_file or 'the recursor config'}: every DNS query is written to syslog (root cause of the incident)."
                if quiet == "no" else f"quiet={quiet or '(default yes)'}, loglevel={settings.get('loglevel', '-')}."))
        spam = (numbers(text_of(source(data, "spam"))) or [0])[0]
        r.step("spam", "Query lines in the last 2000 syslog lines", "fail" if spam > 200 else "ok",
               f"{spam} × \"Question answered from packet cache\".")
        state = (service_states(text_of(source(data, "service"))) or ["unknown"])[0]
        r.step("service", "pdns-recursor active", "ok" if state == "active" else "fail", f"pdns-recursor is {state}.")
        conf_file = quiet_file or "/etc/powerdns/recursor.d/recursor-local.conf"
        if quiet == "no":
            r.recommend(f"Stop the query logging: back up {conf_file}, set quiet=yes, restart pdns-recursor, check that the query "
                        "lines stop.",
                        [f"sudo cp -a {conf_file} {conf_file}.bak-$(date +%F)",
                         f"sudo sed -i 's/^[[:space:]]*quiet[[:space:]]*=.*/quiet=yes/' {conf_file}",
                         f"grep -nE '^(quiet|loglevel|structured-logging)' {conf_file}",
                         "sudo systemctl restart pdns-recursor", "systemctl is-active pdns-recursor",
                         "sudo tail -n 200 /var/log/syslog | grep -c 'Question answered from packet cache'"],
                        where=where, warning=f"Rollback: sudo cp {conf_file}.bak-<date> {conf_file} && sudo systemctl restart pdns-recursor",
                        action={"commands": [f"sudo cp -a {conf_file} {conf_file}.bak-$(date +%F)",
                                             f"sudo sed -i 's/^[[:space:]]*quiet[[:space:]]*=.*/quiet=yes/' {conf_file}",
                                             f"grep -nE '^(quiet|loglevel|structured-logging)' {conf_file}",
                                             "sudo systemctl restart pdns-recursor", "systemctl is-active pdns-recursor"]})
        if syslog_kb > 1024 ** 2 or (row and row["pct"] >= 80):
            gz = [a for a in archives if a.endswith(".gz")]
            r.recommend(f"Free the disk: empty /var/log/syslog ({kib(syslog_kb)}, rsyslog keeps writing to it)"
                        + (f", delete the {len(gz)} old syslog archives" if gz else "") + ", and cap the journal at 500 MB.",
                        ["sudo truncate -s 0 /var/log/syslog"] + ([f"sudo rm -f {' '.join(gz)}"] if gz else [])
                        + ["sudo journalctl --vacuum-size=500M",
                           "sudo sed -i 's/^#\\?SystemMaxUse=.*/SystemMaxUse=500M/; s/^#\\?RuntimeMaxUse=.*/RuntimeMaxUse=100M/' /etc/systemd/journald.conf",
                           "sudo systemctl restart systemd-journald", "df -h /"],
                        where=where,
                        action={"commands": ["sudo truncate -s 0 /var/log/syslog"] + ([f"sudo rm -f {' '.join(gz)}"] if gz else [])
                                + ["sudo journalctl --vacuum-size=500M",
                                   "sudo sed -i 's/^#\\?SystemMaxUse=.*/SystemMaxUse=500M/; s/^#\\?RuntimeMaxUse=.*/RuntimeMaxUse=100M/' /etc/systemd/journald.conf",
                                   "sudo systemctl restart systemd-journald", "df -h /"]})
        return r.done()


# =========================================================================================== Linux service / firewall
def listeners(text, port):
    """`ss -H -lntup` lines listening on port -> [(address, process, pid)]."""
    found = []
    for l in lines(text):
        parts = l.split()
        if len(parts) < 5:
            continue
        local = parts[4]
        if local.rsplit(":", 1)[-1] == str(port):
            proc = re.search(r'users:\(\("([^"]+)",pid=(\d+)', l)
            found.append((local, proc.group(1) if proc else "?", proc.group(2) if proc else ""))
    return found


# Where common services set their listen address (the fix when a service only listens on localhost).
BIND_HINTS = {
    "mongod": ("/etc/mongod.conf", "sudo sed -i 's/^\\([[:space:]]*bindIp:\\).*/\\1 0.0.0.0/' /etc/mongod.conf", "mongod"),
    "redis-server": ("/etc/redis/redis.conf", "sudo sed -i 's/^bind .*/bind 0.0.0.0/' /etc/redis/redis.conf", "redis-server"),
    "mysqld": ("/etc/mysql/mysql.conf.d/mysqld.cnf", "sudo sed -i 's/^bind-address.*/bind-address = 0.0.0.0/' /etc/mysql/mysql.conf.d/mysqld.cnf", "mysql"),
    "postgres": ("/etc/postgresql/*/main/postgresql.conf", "sudo sed -i \"s/^#\\?listen_addresses.*/listen_addresses = '*'/\" /etc/postgresql/*/main/postgresql.conf", "postgresql"),
}


class LinuxServicePort:
    """WIs "Custom Port TCP <SITE> <PORT> is DOWN" (inside the VM) and "Nginx Port Conflict": what listens on the port,
    the service, local answer, and internet access of the VM."""
    sources = ("host",)
    phases = 1

    @staticmethod
    def reads(phase, data, params, ctx):
        port, service = int(params["port"]), params.get("service") or ""
        reads = {"listen": "SUDO ss -H -lntup 2>/dev/null",
                 "local": f"timeout 3 bash -c {q(f'exec 3<>/dev/tcp/127.0.0.1/{port}')} 2>/dev/null && echo TCP_OPEN || echo TCP_CLOSED",
                 "internet": "ping -c 2 -W 2 8.8.8.8 >/dev/null 2>&1 && echo OK || echo FAIL",
                 "route": "ip route show default"}
        if service:
            reads["service"] = f"systemctl is-active {q(service)} 2>/dev/null; systemctl status {q(service)} --no-pager -n 5 2>&1 | head -15"
        if port in (80, 443):
            reads["web"] = "for u in nginx apache2 httpd; do printf '%s %s\\n' $u $(systemctl is-active $u 2>/dev/null || true); done"
        return {"host": reads}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("linux-service-port")
        where = on_host(ctx)
        port, service = int(params["port"]), params.get("service") or ""
        found = listeners(text_of(source(data, "listen")), port)
        local_only = found and all(a.startswith(("127.", "[::1]")) for a, _, _ in found)
        r.step("listen", f"A process listens on port {port}", "fail" if not found else "warn" if local_only else "ok",
               ", ".join(f"{p} (PID {pid}) on {a}" for a, p, pid in found) if found else f"Nothing listens on port {port}: the service is not running.")
        base = service.split(".")[0]
        conflict = service and found and not any(base.startswith(p) or p.startswith(base) for _, p, _ in found)
        if service:
            text = text_of(source(data, "service"))
            state = (lines(text) or ["unknown"])[0].strip()
            r.step("service", f"Service {service}", "ok" if state == "active" else "fail", f"{service} is {state}.", evidence=text)
            if conflict:
                other = found[0][1]
                r.step("conflict", f"Port {port} is held by another program", "fail",
                       f"{other} (PID {found[0][2]}) holds port {port}, not {service}: {service} fails with "
                       "\"bind() … Address already in use\".")
                r.recommend(f"Stop and disable {other} so {service} can bind port {port} again (or move one of them to "
                            "another port if both are needed).",
                            [f"sudo systemctl stop {other}", f"sudo systemctl disable {other}",
                             "sudo nginx -t" if base == "nginx" else "", f"sudo systemctl start {service}",
                             f"sudo ss -lntp | grep ':{port} '", f"curl -sI http://127.0.0.1:{port}/ | head -1"],
                            where=where,
                            action={"commands": [f"sudo systemctl stop {other}", f"sudo systemctl disable {other}",
                                                 "sudo nginx -t" if base == "nginx" else "", f"sudo systemctl start {service}",
                                                 f"systemctl is-active {service}", f"sudo ss -lntp | grep ':{port} '"]}, warning=f"Emergency only (SEV-1): sudo fuser -k {port}/tcp kills everything on the port.")
            elif state != "active":
                r.recommend(f"Start {service} again and check that it listens on {port}.",
                            [f"sudo journalctl -u {service} -n 30 --no-pager", f"sudo systemctl restart {service}",
                             f"systemctl is-active {service}", f"sudo ss -lntp | grep ':{port} '",
                             f"curl -sv --max-time 5 http://127.0.0.1:{port}/ -o /dev/null"],
                            where=where,
                            action={"commands": [f"sudo journalctl -u {service} -n 30 --no-pager", f"sudo systemctl restart {service}",
                                                 "sleep 3", f"systemctl is-active {service}", f"sudo ss -lntp | grep ':{port} '"]})
        local = "TCP_OPEN" in text_of(source(data, "local"))
        r.step("local", f"Connect to 127.0.0.1:{port} inside the VM", "ok" if local else "fail" if not local_only and found else "warn",
               "Connection accepted." if local else "Connection refused.")
        net = "OK" in text_of(source(data, "internet"))
        gw = (re.search(r"default via (\S+)", text_of(source(data, "route"))) or [None, ""])[1]
        r.step("internet", "VM reaches the internet (8.8.8.8)", "ok" if net else "warn",
               "Ping OK." if net else f"No reply (default gateway {gw or 'missing'}): check the route, DHCP/cloud-init and the "
               "outbound rules of the security group.")
        if not net:
            r.recommend("The VM has no internet, so UptimeRobot cannot see it as UP: check the gateway and DNS.",
                        [f"ping -c 3 {gw}" if gw else "ip route   # no default route: fix the network config / DHCP",
                         "ip -br a", "cat /etc/resolv.conf"], where=where)
        if local_only:
            proc = found[0][1]
            hint = BIND_HINTS.get(proc)
            r.recommend(f"{proc} only listens on {found[0][0]}: make it listen on the VM address so clients can reach port {port}"
                        + (f" ({hint[0]})" if hint else "") + ", then restart it.",
                        ([hint[1], f"sudo systemctl restart {hint[2]}"] if hint else
                         [f"sudo grep -rnE 'listen|bind' /etc/{proc}* 2>/dev/null | head"]) + [f"sudo ss -lntp | grep ':{port} '"],
                        where=where,
                        action={"commands": [hint[1], f"sudo systemctl restart {hint[2]}", "sleep 3",
                                             f"sudo ss -lntp | grep ':{port} '"]} if hint else None, warning="Listening on 0.0.0.0 exposes the service: keep the security group / firewall limited to the clients that need it.")
        return r.done()


def nft_rules(text):
    """`nft -a list ruleset` -> [{"family", "table", "chain", "handle", "rule"}] for every rule line with a handle."""
    rules, family, table, chain = [], "", "", ""
    for raw in str(text or "").splitlines():
        l = raw.strip()
        m = re.match(r"^table (\S+) (\S+)", l)
        if m:
            family, table = m.group(1), m.group(2)
            continue
        m = re.match(r"^chain (\S+)", l)
        if m:
            chain = m.group(1)
            continue
        m = re.search(r"# handle (\d+)$", l)
        if m and chain and not l.startswith(("type ", "policy ")):
            rules.append({"family": family, "table": table, "chain": chain, "handle": m.group(1),
                          "rule": l[:m.start()].strip()})
    return rules


class LinuxFirewall:
    """WI "troubleshooting firewall nsxt & linux": local firewall / filter of the destination VM (nftables, iptables,
    ufw, firewalld, netfilter-persistent) when NSX-T Traceflow says Delivered but the port fails."""
    sources = ("host",)
    phases = 1

    @staticmethod
    def reads(phase, data, params, ctx):
        return {"host": {"listen": "SUDO ss -H -lntup 2>/dev/null",
                         "nft": "SUDO nft -a list ruleset 2>&1 | head -300",
                         "ipt": "SUDO iptables-save 2>&1 | head -300",
                         "iptv": "iptables -V 2>&1",
                         "ufw": "SUDO ufw status numbered 2>&1 | head -40",
                         "units": "for u in nftables firewalld ufw netfilter-persistent; do printf '%s %s\\n' $u $(systemctl is-active $u 2>/dev/null || true); done",
                         "routes": "ip route show table all 2>/dev/null | grep -E 'blackhole|unreachable|prohibit'; true",
                         "addr": "ip -br a"}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("linux-firewall")
        where = on_host(ctx)
        port = int(params.get("port") or 0)
        src = params.get("source") or ""
        if port:
            found = listeners(text_of(source(data, "listen")), port)
            r.step("listen", f"Service listens on port {port}", "ok" if found and not all(a.startswith("127.") for a, _, _ in found) else "fail",
                   ", ".join(f"{p} on {a}" for a, p, _ in found) if found else "Nothing listens: the problem is the service, not the firewall.")
        units = dict(l.split()[:2] for l in lines(text_of(source(data, "units"))) if len(l.split()) >= 2)
        active = [u for u, s in units.items() if s == "active"]
        r.step("services", "Firewall services active", "info" if active else "ok",
               f"Active: {', '.join(active)}." if active else "None of nftables, firewalld, ufw, netfilter-persistent is active.",
               {"columns": ["Service", "State"], "rows": [[u, s] for u, s in units.items()]})
        rules = nft_rules(text_of(source(data, "nft")))
        blocking = [x for x in rules if re.search(r"\b(reject|drop)\b", x["rule"])]

        def for_port(x):
            return port and re.search(rf"\bdport\s+(\{{[^}}]*\b)?{port}\b", x["rule"])

        def allowed_before(x):
            """An accept for the port (from the source, or from anywhere) earlier in the same chain wins over x."""
            for y in rules[:rules.index(x)]:
                if (y["family"], y["table"], y["chain"]) == (x["family"], x["table"], x["chain"]) and for_port(y) \
                        and re.search(r"\baccept\b", y["rule"]) and (not src or "saddr" not in y["rule"] or src in y["rule"]):
                    return y
            return None
        on_port = [x for x in blocking if for_port(x) and not allowed_before(x)]
        opened = [(x, allowed_before(x)) for x in blocking if for_port(x) and allowed_before(x)]
        r.step("nft", "nftables rules that reject or drop", "fail" if on_port else "warn" if blocking and not opened else "ok",
               (f"{len(blocking)} rule(s); {len(on_port)} block port {port}." if blocking else "No reject/drop rule.")
               + "".join(f" Rule {x['handle']} would reject {port}, but rule {y['handle']} accepts it first." for x, y in opened)
               + (" A reject answers with ICMP admin prohibited (traceroute !X)." if on_port else ""),
               {"columns": ["Table", "Chain", "Handle", "Rule"],
                "rows": [[f"{x['family']} {x['table']}", x["chain"], x["handle"], x["rule"]] for x in blocking]},
               marks=[f"# handle {x['handle']}" for x in on_port if x.get("handle")])
        ipt = text_of(source(data, "ipt"))
        ipt_rejects = [l for l in ipt.splitlines() if l.startswith("-A ") and re.search(r"-j (REJECT|DROP)", l)]
        ipt_port = [l for l in ipt_rejects if port and re.search(rf"--dport {port}\b", l)]
        r.step("iptables", f"iptables rules ({text_of(source(data, 'iptv')).strip() or 'version unknown'})",
               "fail" if ipt_port else "warn" if ipt_rejects else "ok",
               f"{len(ipt_rejects)} REJECT/DROP rule(s)." if ipt_rejects else "No REJECT/DROP rule.", evidence="\n".join(ipt_rejects[:40]) or None)
        ufw = text_of(source(data, "ufw"))
        ufw_active = "Status: active" in ufw
        r.step("ufw", "ufw", "warn" if ufw_active else "ok", (lines(ufw) or ["ufw not installed"])[0])
        routes = lines(text_of(source(data, "routes")))
        r.step("routes", "Blackhole / prohibit routes", "warn" if routes else "ok", "; ".join(routes) or "None.")
        match = f"ip saddr {src} " if src else ""
        save = "sudo cp -a /etc/nftables.conf /etc/nftables.conf.bak-$(date +%F) && sudo sh -c 'nft list ruleset > /etc/nftables.conf'"
        for x in on_port:
            r.recommend(f"nftables rule {x['handle']} in {x['family']} {x['table']} chain {x['chain']} rejects TCP {port}"
                        + (f": allow {src} in front of it" if src else ": allow the client in front of it (set 'Source IP' to limit it)")
                        + ", test from the source, then save the ruleset so it survives a reboot.",
                        [f"sudo nft insert rule {x['family']} {x['table']} {x['chain']} position {x['handle']} {match}tcp dport {port} accept",
                         f"sudo nft -a list chain {x['family']} {x['table']} {x['chain']}",
                         f"nc -zv {ctx.get('host_address') or 'this VM'} {port}   # from the source VM", save],
                        where=where,
                        action={"commands": [f"sudo nft insert rule {x['family']} {x['table']} {x['chain']} position {x['handle']} {match}tcp dport {port} accept",
                                             f"sudo nft -a list chain {x['family']} {x['table']} {x['chain']}", save]},
                        warning=f"Or remove the reject itself: sudo nft delete rule {x['family']} {x['table']} {x['chain']} handle {x['handle']} "
                                "(only if nothing else needs it). Never leave a production VM with an empty ruleset.")
        for l in ipt_port:
            r.recommend(f"iptables rejects TCP {port}: insert an accept in front of it, or delete the rule.",
                        [f"sudo iptables -I {l.split()[1]} 1 {'-s ' + src + ' ' if src else ''}-p tcp --dport {port} -j ACCEPT",
                         "sudo iptables " + l.replace("-A ", "-D ", 1) + "   # alternative: delete the reject",
                         "sudo sh -c 'iptables-save > /etc/iptables/rules.v4'   # when netfilter-persistent loads the rules"],
                        where=where,
                        action={"commands": [f"sudo iptables -I {l.split()[1]} 1 {'-s ' + src + ' ' if src else ''}-p tcp --dport {port} -j ACCEPT",
                                             f"sudo iptables -S {l.split()[1]} | head -5"]})
        if ufw_active and port:
            ufw = [f"sudo ufw allow {'from ' + src + ' to any ' if src else ''}port {port} proto tcp", "sudo ufw status numbered"]
            r.recommend(f"ufw is active: allow TCP {port}.", ufw, where=where, action={"commands": ufw})
        if (blocking or ipt_rejects or active) and not (on_port or ipt_port or opened):
            r.recommend("No rule names this port, but a firewall is active: confirm with tcpdump while the source connects. "
                        "'ICMP … admin prohibited filter' means the local firewall rejects it.",
                        [f"sudo tcpdump -nn -i any 'tcp port {port or 22} or icmp' -c 20", "sudo nft -a list ruleset | less"],
                        where=where)
        return r.done()


# =========================================================================================== SIEM
def collector(params, ctx, default_port):
    text = str(params.get("collector") or ctx.get("siem_collector") or "")
    host, _, port = text.partition(":")
    return host, int(port or default_port)


RSYSLOG_FORWARD = """sudo tee /etc/rsyslog.d/60-forward-to-syslog-collector.conf >/dev/null <<'EOF'
action(
    type="omfwd"
    target="{host}"
    port="{port}"
    protocol="tcp"
    queue.type="LinkedList"
    queue.filename="openstack_forward_queue"
    queue.saveOnShutdown="on"
    action.resumeRetryCount="-1"
)
EOF"""


class SiemForwarder:
    """WI "OpenStack RHEL Forward Log to 172.26.0.40 port 541": rsyslog forwarding, SELinux port, connection."""
    sources = ("host",)
    phases = 1

    @staticmethod
    def reads(phase, data, params, ctx):
        host, port = collector(params, ctx, 541)
        return {"host": {"pkg": "rpm -q rsyslog 2>&1",
                         "active": "systemctl is-active rsyslog 2>/dev/null; true",
                         "fwd": "SUDO grep -rhsE 'omfwd|target=|port=|protocol=' /etc/rsyslog.conf /etc/rsyslog.d/",
                         "selinux": "getenforce 2>&1",
                         "semanage": "SUDO semanage port -l 2>/dev/null | grep syslogd_port_t; true",
                         "tcp": f"timeout 5 bash -c {q(f'exec 3<>/dev/tcp/{host}/{port}')} 2>/dev/null && echo OPEN || echo CLOSED",
                         "journal": "SUDO journalctl -u rsyslog -n 300 --no-pager 2>/dev/null | grep -iE 'cannot connect|permission denied|suspended' | tail -5; true",
                         "check": "SUDO rsyslogd -N1 2>&1 | tail -2"}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("siem-forwarder")
        where = on_host(ctx)
        host, port = collector(params, ctx, 541)
        state = (service_states(text_of(source(data, "active"))) or ["unknown"])[0]
        installed = "not installed" not in text_of(source(data, "pkg"))
        r.step("rsyslog", "rsyslog installed and active", "ok" if state == "active" else "fail",
               f"{text_of(source(data, 'pkg')).strip()}; {state}.")
        fwd = text_of(source(data, "fwd"))
        targets = re.findall(r'target="([^"]+)"', fwd)
        ports = re.findall(r'port="(\d+)"', fwd)
        right = host in targets and str(port) in ports
        r.step("forward", f"Forwarding to {host}:{port} configured", "ok" if right else "fail",
               f"omfwd target(s) {', '.join(targets) or 'none'}, port(s) {', '.join(ports) or 'none'}.", evidence=fwd)
        enforcing = "Enforcing" in text_of(source(data, "selinux"))
        sel = text_of(source(data, "semanage"))
        allowed = bool(re.search(rf"\btcp\b.*\b{port}\b", sel))
        tcp_ports = ", ".join(re.findall(r"tcp\s+([0-9, ]+)", sel)).strip() or "none"
        r.step("selinux", f"SELinux allows rsyslog on TCP {port}", "ok" if not enforcing or allowed or port == 514 else "fail",
               ("SELinux is not enforcing." if not enforcing else f"syslogd_port_t TCP ports: {tcp_ports}"
                + ("" if allowed or port == 514 else f" — {port} is missing, rsyslog gets Permission denied.")))
        conn = "OPEN" in text_of(source(data, "tcp"))
        r.step("tcp", f"TCP connection to {host}:{port}", "ok" if conn else "fail", "Open." if conn else "Refused or timed out.")
        errors = lines(text_of(source(data, "journal")))
        r.step("errors", "rsyslog connection errors", "warn" if errors else "ok", "; ".join(errors[-3:]) or "None in the last 300 lines.")
        check = text_of(source(data, "check"))
        r.step("syntax", "rsyslog configuration check (rsyslogd -N1)", "ok" if "End of config validation" in check else "warn",
               lines(check)[-1] if lines(check) else "-")
        fixes, what = [], []
        if not installed or state != "active":
            fixes += ["sudo dnf install -y rsyslog", "sudo systemctl enable --now rsyslog"]
            what.append("install/start rsyslog")
        if enforcing and not allowed and port != 514:
            fixes += [f"sudo semanage port -a -t syslogd_port_t -p tcp {port} || sudo semanage port -m -t syslogd_port_t -p tcp {port}"]
            what.append(f"allow TCP {port} in SELinux")
        if not right:
            fixes += [RSYSLOG_FORWARD.format(host=host, port=port)]
            what.append("add the forwarding config")
        if fixes:
            r.recommend(f"Make rsyslog on this VM forward to {host}:{port}: {', '.join(what)}; then validate, restart and send a "
                        "test message.",
                        fixes + ["sudo rsyslogd -N1", "sudo systemctl restart rsyslog",
                                 f"logger -p user.notice -t OPENSTACK_TEST \"TEST_OPENSTACK_RHEL_TO_{host}_PORT_{port}\"",
                                 "sudo journalctl -u rsyslog -n 20 --no-pager"],
                        where=where,
                        action={"commands": fixes + ["sudo rsyslogd -N1", "sudo systemctl restart rsyslog",
                                                     f"logger -p user.notice -t OPENSTACK_TEST \"TEST_OPENSTACK_RHEL_TO_{host}_PORT_{port}\"",
                                                     "sudo journalctl -u rsyslog -n 20 --no-pager"]}, warning="Ask the collector administrator to confirm the test message arrived.")
        if not conn:
            r.recommend(f"{host}:{port} is not reachable from this VM: check the route and the ACLs between the segments, and that "
                        "the collector listens on the port.",
                        [f"ping -c 4 {host}", f"traceroute -T -p {port} {host}", "ip route"], where=where)
        return r.done()


class SiemCollector:
    """WIs "Forward Log ESXi To RHEL Collector" / "NXLog Windows AD and Veeam": the collector side (rsyslog, listener,
    firewall, fresh files per source type, disk)."""
    sources = ("host",)
    phases = 1

    @staticmethod
    def reads(phase, data, params, ctx):
        return {"host": {"active": "systemctl is-active rsyslog 2>/dev/null; true",
                         "listen": "SUDO ss -H -lntup 2>/dev/null | grep -E ':(514|541) '; true",
                         "fw": "SUDO firewall-cmd --list-ports 2>&1",
                         "recent": "for d in /data/collectorlogs/*/; do printf '%s %s\\n' $(basename $d) $(find $d -type f -mmin -10 2>/dev/null | wc -l); done",
                         "unknown": "ls -1t /data/collectorlogs/unknown 2>/dev/null | head -10",
                         "df": "df -Pk /data 2>/dev/null || df -Pk /"}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("siem-collector")
        where = on_host(ctx)
        state = (service_states(text_of(source(data, "active"))) or ["unknown"])[0]
        r.step("rsyslog", "rsyslog active", "ok" if state == "active" else "fail", f"rsyslog is {state}.")
        listen = lines(text_of(source(data, "listen")))
        r.step("listen", "Listening on 514 / 541", "ok" if listen else "fail", "; ".join(l.split()[4] for l in listen if len(l.split()) > 4) or "Not listening.")
        fw = text_of(source(data, "fw")).strip()
        r.step("firewall", "firewalld open ports", "ok" if "514/tcp" in fw or "not running" in fw else "warn", fw or "-")
        recent = [l.split() for l in lines(text_of(source(data, "recent"))) if len(l.split()) == 2]
        quiet = [d for d, n in recent if n == "0" and d != "unknown"]
        unknown = next((int(n) for d, n in recent if d == "unknown"), 0)
        senders = [s for s in lines(text_of(source(data, "unknown"))) if re.match(r"^[0-9a-fA-F.:]+$", s)]
        r.step("fresh", "New log files in the last 10 minutes per source type", "warn" if quiet or unknown else "ok",
               (f"No new files from: {', '.join(quiet)}." if quiet else "Every source type sends logs.")
               + (f" {unknown} new file(s) in unknown (from {', '.join(senders[:5]) or 'unknown senders'}): classification rules missing." if unknown else ""),
               {"columns": ["Source type", "Files changed (10 min)"], "rows": recent})
        disk_step(r, data, "df", "/data", "Disk of the collector", 80, 90)
        if state != "active" or not listen:
            r.recommend("rsyslog must run and listen on TCP/UDP 514 (and 541): restart it and look at its errors.",
                        ["sudo rsyslogd -N1", "sudo systemctl restart rsyslog", "sudo ss -lntup | grep -E ':(514|541) '",
                         "sudo journalctl -u rsyslog -n 50 --no-pager"], where=where,
                        action={"commands": ["sudo rsyslogd -N1", "sudo systemctl restart rsyslog", "sleep 2",
                                             "sudo ss -lntup | grep -E ':(514|541) '"]})
        if "514/tcp" not in fw and "not running" not in fw:
            fw_cmds = ["sudo firewall-cmd --permanent --add-port=514/tcp --add-port=514/udp --add-port=541/tcp",
                       "sudo firewall-cmd --reload", "sudo firewall-cmd --list-ports"]
            r.recommend("Open the syslog ports in firewalld.", fw_cmds, where=where, action={"commands": fw_cmds})
        for d in quiet:
            r.recommend(f"No new {d} logs for 10 minutes: find the newest file and which senders stopped, then check them "
                        "(for ESXi: the check \"ESXi host sends syslog\").",
                        [f"sudo ls -lt /data/collectorlogs/{d}/ | head", f"sudo find /data/collectorlogs/{d} -type f -mmin -60 | head",
                         "sudo tcpdump -nn -i any 'port 514 or port 541' -c 20"], where=where)
        if unknown and senders:
            r.recommend(f"Files from {', '.join(senders[:5])} land in unknown: add these senders to the classification rules "
                        "of the collector (the rule that chooses the source-type folder), then restart rsyslog.",
                        [f"sudo ls -l /data/collectorlogs/unknown/{senders[0]}/ | head",
                         "sudo grep -rn 'collectorlogs' /etc/rsyslog.d/ | head", "sudo rsyslogd -N1", "sudo systemctl restart rsyslog"],
                        where=where)
        return r.done()


class EsxiSyslog:
    """WI "Forward Log ESXi To RHEL Collector": syslog settings of one ESXi host."""
    sources = ("host",)
    phases = 1

    @staticmethod
    def reads(phase, data, params, ctx):
        host, port = collector(params, ctx, 514)
        return {"host": {"config": "esxcli system syslog config get",
                         "ruleset": "esxcli network firewall ruleset list | grep -i syslog",
                         "tcp": f"nc -z -w 5 {q(host)} {port} && echo OPEN || echo CLOSED",
                         "err": "tail -n 10 /var/log/.vmsyslogd.err 2>/dev/null; true"}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("esxi-syslog")
        host, port = collector(params, ctx, 514)
        cfg = text_of(source(data, "config"))
        remote = (re.search(r"Remote Host:\s*(.*)", cfg) or [None, ""])[1].strip()
        want = f"tcp://{host}:{port}"
        r.step("loghost", "Remote syslog host", "ok" if want in remote else "fail", f"Remote Host: {remote or '<none>'} (expected {want}).",
               evidence=cfg)
        rs = text_of(source(data, "ruleset"))
        rs_on = bool(re.search(r"syslog\s+true", rs))
        r.step("ruleset", "ESXi firewall ruleset syslog enabled", "ok" if rs_on else "fail", rs.strip() or "-")
        conn = "OPEN" in text_of(source(data, "tcp"))
        r.step("tcp", f"TCP {host}:{port} from the ESXi host", "ok" if conn else "fail", "Open." if conn else "Refused or timed out.")
        err = lines(text_of(source(data, "err")))
        r.step("errors", "vmsyslogd errors", "warn" if err else "ok", "; ".join(err[-3:]) or "None.")
        if want not in remote or not rs_on:
            r.recommend(f"Point {ctx.get('host_name') or 'this ESXi host'} at {want}, reload syslog, send a test message, then check on "
                        f"the collector that it arrived in /data/collectorlogs/vmware/{ctx.get('host_address') or '<IP of this host>'}/.",
                        ([] if rs_on else ["esxcli network firewall ruleset set --ruleset-id=syslog --enabled=true"])
                        + ([f"esxcli system syslog config set --loghost=\"{want}\""] if want not in remote else [])
                        + ["esxcli system syslog reload", "esxcli system syslog config get",
                           "esxcli system syslog mark --message=\"TEST_ESXI_TO_RHEL_COLLECTOR\""],
                        where=on_host(ctx), warning="Rollback: esxcli system syslog config set --loghost=\"\" && esxcli system syslog reload",
                        action={"commands": ([] if rs_on else ["esxcli network firewall ruleset set --ruleset-id=syslog --enabled=true"])
                                + ([f"esxcli system syslog config set --loghost=\"{want}\""] if want not in remote else [])
                                + ["esxcli system syslog reload", "esxcli system syslog config get",
                                   "esxcli system syslog mark --message=\"TEST_ESXI_TO_RHEL_COLLECTOR\""]})
        if not conn:
            r.recommend(f"{host}:{port} is not reachable from the ESXi host: check the management VMkernel, VLAN and routing.",
                        [f"vmkping {host}", "esxcli network ip interface ipv4 get", "esxcli network ip route ipv4 list"], where=on_host(ctx))
        return r.done()


# =========================================================================================== GB200
class Gb200NicLink:
    """SOP "CT Linkdown check": NIC devices (BlueField-3, ConnectX-7) of a GB200 compute tray, link state and errors."""
    sources = ("host",)
    phases = 1

    @staticmethod
    def reads(phase, data, params, ctx):
        return {"host": {"lspci": "lspci 2>/dev/null | grep -iE 'mellanox|connectx|bluefield'; true",
                         "links": "ip -br link",
                         "ethtool": "for i in $(ls /sys/class/net | grep -vE '^(lo|docker|veth|virbr|br-)'); do printf '%s ' $i; "
                                    "SUDO ethtool $i 2>/dev/null | grep -m1 'Link detected' || echo 'Link detected: unknown'; done",
                         "dmesg": "SUDO dmesg 2>/dev/null | grep -iE 'mlx5|bluefield' | grep -iE 'error|fail|down|reset' | tail -20; true"}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("gb200-nic-link")
        where = on_host(ctx)
        devices = lines(text_of(source(data, "lspci")))
        r.step("pci", "NIC devices on PCIe (CX7 / BF3)", "ok" if devices else "fail", f"{len(devices)} device function(s).",
               evidence="\n".join(devices) or None)
        detected = {}
        for l in lines(text_of(source(data, "ethtool"))):
            m = re.match(r"^(\S+)\s+Link detected:\s*(\S+)", l)
            if m:
                detected[m.group(1)] = m.group(2)
        states = {l.split()[0]: l.split()[1] for l in lines(text_of(source(data, "links"))) if len(l.split()) >= 2}
        down = [i for i, s in detected.items() if s == "no"]
        r.step("links", "Links detected (ethtool)", "fail" if down else "ok", f"No link: {', '.join(down)}." if down else f"{len(detected)} interface(s) with link.",
               {"columns": ["Interface", "State (ip)", "Link detected"], "rows": [[i, states.get(i, "-"), s] for i, s in sorted(detected.items())]})
        errs = lines(text_of(source(data, "dmesg")))
        r.step("dmesg", "Driver errors and resets (mlx5 / BlueField)", "warn" if errs else "ok", f"{len(errs)} line(s)." if errs else "None.",
               evidence="\n".join(errs) or None)
        for iface in down:
            r.recommend(f"{iface} has no link: collect its driver/firmware and counters, try one link bounce, then check the switch "
                        "port and do a DAC loopback test of the NIC (SOP). Attach the outputs to the escalation (Aivres / NVIDIA).",
                        [f"sudo ethtool -i {iface}", f"sudo ethtool {iface}", f"sudo ethtool -S {iface} | grep -iE 'err|drop|down' | head -20",
                         f"sudo dmesg | grep -i {iface} | tail -20",
                         f"sudo ip link set {iface} down && sudo ip link set {iface} up   # one bounce, in the maintenance window",
                         f"sudo ethtool {iface} | grep 'Link detected'"],
                        where=where, warning=f"On the switch: show interface <port cabled to {iface}> — the mapping is in the cabling sheet.",
                        action={"commands": [f"sudo ethtool -i {iface}", f"sudo ip link set {iface} down", "sleep 2",
                                             f"sudo ip link set {iface} up", "sleep 10", f"sudo ethtool {iface} | grep 'Link detected'"]})
        return r.done()

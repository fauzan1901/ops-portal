"""Controller reboot readiness: may the controllers be rebooted (kernel patch, maintenance), one after the other, without
taking the OpenStack API down? Read on every controller through the director, only reads:

  Pacemaker   quorum, every controller online (none standby / unclean), no resource stopped or failed
  Galera      every controller Synced in a Primary cluster of all controllers
  clustercheck  the Galera health check of HAProxy (port 9200) answers 200 on every controller
  Elastic     Elastic Endpoint / elastic-agent installed, running, started at boot: its rule "Socat
              Reverse Shell or Listener Activity" can kill the socat of clustercheck after a kernel patch; HAProxy then marks
              mysql down and the API goes down
  Kernel      the kernel running and the newest installed (the one a reboot starts), needs-restarting -r

The verdict is the worst step; the safe order (Red Hat: Rebooting Controller and composable nodes) is given with the
names of this site's controllers: one controller at a time, the next only once this check is green again.
"""
import re

from . import overcloud
from .common import Result, source, unavailable
from .control_plane import parse_wsrep
from .overcloud_checks import inventory, item_out, parse_pcs, resource_status

ELASTIC_UNITS = ("elastic-agent", "ElasticEndpoint")


def parse_elastic(text):
    """The read "elastic" -> {"package", "units": {unit: (enabled, active)}, "opt": bool}."""
    out = {"package": "", "units": {}, "opt": False}
    for line in str(text or "").splitlines():
        line = line.strip()
        if line.startswith("elastic-agent-") and "not installed" not in line:
            out["package"] = line
        m = re.match(r"^unit (\S+) (\S*) (\S*)$", line)
        if m:
            out["units"][m.group(1)] = (m.group(2) or "-", m.group(3) or "-")
        if line == "opt-elastic present":
            out["opt"] = True
    return out


def parse_clustercheck(text):
    """The read "clustercheck" -> {"containers": [(name, status)], "listen": "addr:9200" or "", "http": "200"/... or ""}."""
    out = {"containers": [], "listen": "", "http": ""}
    for line in str(text or "").splitlines():
        line = line.strip()
        if line.startswith("container "):
            name, _, status = line[10:].partition("|")
            out["containers"].append((name, status))
        elif line.startswith("listen "):
            out["listen"] = out["listen"] or line[7:]
        elif line.startswith("http "):
            out["http"] = line[5:].strip()
    return out


def parse_kernel(text):
    """The read "kernel" -> {"running", "newest", "reboot_needed": True/False/None, "since"}."""
    lines = [x.strip() for x in str(text or "").splitlines() if x.strip()]
    out = {"running": lines[0] if lines else "", "newest": "", "reboot_needed": None, "since": ""}
    for line in lines[1:]:
        m = re.match(r"^kernel-(\S+)\s", line + " ")
        if m and not out["newest"]:
            out["newest"] = m.group(1)
        m = re.match(r"^needs-restarting (\d+)$", line)
        if m:
            out["reboot_needed"] = {"0": False, "1": True}.get(m.group(1))
        m = re.match(r"^up since (.+)$", line)
        if m:
            out["since"] = m.group(1)
    return out


class ControllerRebootReadiness:
    """May the controllers be rebooted one by one now (Pacemaker, Galera, clustercheck, Elastic Endpoint, kernel)?"""
    sources = ("undercloud", "overcloud")
    phases = 2

    @staticmethod
    def reads(phase, data, params, ctx):
        if phase == 1:
            return {"undercloud": dict(overcloud.INVENTORY_READS)}
        _found, controllers, user, _v, problem = inventory(data, ctx)
        if problem:
            return {}
        out = {}
        for i, n in enumerate(controllers):
            for key, cmd in (("ker", "kernel"), ("pcs", "pcs_status"), ("gal", "galera_status"), ("cc", "clustercheck"),
                             ("ela", "elastic")):
                out[f"{key}_{i}"] = overcloud.read(n["name"], n["ip"], user, cmd)
        return {"overcloud": out}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("controller-reboot-readiness")
        _found, controllers, user, version, problem = inventory(data, ctx)
        if problem:
            r.step("nodes", "Controllers", "fail", problem)
            return r.done()
        where = f"each controller, as {user} with sudo: from the director, ssh {user}@<its ctlplane address>"
        up = [(i, n) for i, n in enumerate(controllers)
              if not unavailable(source(data, f"ker_{i}")) and parse_kernel(item_out(data, f"ker_{i}"))["running"]]
        down = [n for i, n in enumerate(controllers) if (i, n) not in up]
        r.step("nodes", "Controllers reached from the director", "fail" if down else "ok",
               f"{len(up)} of {len(controllers)} controller(s) answered as {user}" + (f" (RHOSP {version})" if version else "") + ".",
               {"columns": ["Controller", "ctlplane", "SSH from the director"],
                "rows": [[n["name"], n["ip"], "reached" if (i, n) in up else (unavailable(source(data, f"ker_{i}")) or "no answer")[:160]]
                         for i, n in enumerate(controllers)]}, marks=[n["name"] for n in down])
        if not up:
            return r.done("No controller answered: nothing can be said about a reboot.")

        # ---------------- Pacemaker ----------------
        views = [(i, n, parse_pcs(item_out(data, f"pcs_{i}"))) for i, n in up]
        main = next(((i, n, v) for i, n, v in views if v["resources"] or v["online"]), None)
        if not main:
            r.step("cluster", "Pacemaker cluster", "fail", "pcs status did not answer on any controller.")
        else:
            i, n, pcs = main
            names = [c["name"] for c in controllers]
            missing = [x for x in names if x not in pcs["online"]]
            bad_nodes = sorted(set(pcs["offline"] + pcs["unclean"] + missing))
            status = "fail" if pcs["quorum"] is False or bad_nodes else "warn" if pcs["standby"] else "ok"
            r.step("cluster", "Pacemaker quorum and nodes", status,
                   f"Quorum {'yes' if pcs['quorum'] else 'NO' if pcs['quorum'] is False else 'unknown'}; online: "
                   f"{', '.join(pcs['online']) or '-'}" + (f"; not online: {', '.join(bad_nodes)}" if bad_nodes else "")
                   + (f"; standby: {', '.join(pcs['standby'])}" if pcs["standby"] else "")
                   + (". Rebooting a controller now takes one more away from the cluster." if bad_nodes else "."),
                   marks=bad_nodes or pcs["standby"])
            stopped = [(res, *resource_status(res)) for res in pcs["resources"] if not res["agent"].lower().startswith("stonith:")]
            stopped = [(res, st, why) for res, st, why in stopped if st != "ok"]
            r.step("resources", "Pacemaker resources", "fail" if stopped or pcs["failed_actions"] else "ok",
                   (f"{len(stopped)} resource(s) not running as expected" if stopped else "Every resource runs")
                   + (f"; {len(pcs['failed_actions'])} failed action(s) recorded" if pcs["failed_actions"] else "") + ".",
                   {"columns": ["Resource", "State", "Why"], "rows": [[res["name"], res["state"], why] for res, _st, why in stopped][:40]}
                   if stopped else None, marks=[res["name"] for res, _s, _w in stopped])

        # ---------------- Galera ----------------
        rows, bad = [], []
        for i, n in up:
            item = source(data, f"gal_{i}")
            w = {} if unavailable(item) else parse_wsrep(item_out(data, f"gal_{i}"))
            size, state, status = w.get("wsrep_cluster_size", ""), w.get("wsrep_local_state_comment", ""), w.get("wsrep_cluster_status", "")
            ok = size == str(len(controllers)) and state == "Synced" and status == "Primary"
            if not ok:
                bad.append(n["name"])
            rows.append([n["name"], size or "-", status or "-", state or (unavailable(item) or "not read")[:80]])
        r.step("galera", "Galera replication", "fail" if bad else "ok",
               (f"Not Synced in a Primary cluster of {len(controllers)}: {', '.join(bad)}. A reboot now can leave the database "
                "without a quorum." if bad else f"Every controller is Synced in a Primary cluster of {len(controllers)}."),
               {"columns": ["Controller", "Cluster size", "Status", "State"], "rows": rows}, marks=bad)

        # ---------------- clustercheck ----------------
        rows, bad = [], []
        for i, n in up:
            cc = parse_clustercheck(item_out(data, f"cc_{i}"))
            running = [f"{name} ({status})" for name, status in cc["containers"]]
            ok = cc["http"] == "200"
            if not ok:
                bad.append(n["name"])
            rows.append([n["name"], ", ".join(running) or "no clustercheck container", cc["listen"] or "nothing listens on 9200",
                         cc["http"] or "-"])
        r.step("clustercheck", "clustercheck (Galera health check of HAProxy, port 9200)", "fail" if bad else "ok",
               (f"clustercheck does not answer 200 on {', '.join(bad)}: HAProxy takes mysql of that node out (on all of them: "
                "the API is down)." if bad else "clustercheck answers 200 (Galera synced) on every controller."),
               {"columns": ["Controller", "Container", "Listening", "HTTP"], "rows": rows}, marks=bad)

        # ---------------- Elastic Endpoint ----------------
        rows, risky = [], []
        for i, n in up:
            e = parse_elastic(item_out(data, f"ela_{i}"))
            units = e["units"]
            boot = [u for u in ELASTIC_UNITS if (units.get(u) or ("-", "-"))[0] in ("enabled", "static", "alias")]
            active = [u for u in ELASTIC_UNITS if (units.get(u) or ("-", "-"))[1] == "active"]
            if boot or active:
                risky.append(n["name"])
            rows.append([n["name"], e["package"] or "not installed",
                         ", ".join(f"{u}: {'/'.join(units[u])}" for u in ELASTIC_UNITS if u in units) or "-",
                         "present" if e["opt"] else "-"])
        r.step("elastic", "Elastic Endpoint (EDR)", "warn" if risky else "ok",
               (f"Elastic runs or starts at boot on {', '.join(risky)}. Its rule \"Socat Reverse Shell or "
                "Listener Activity\" can kill the socat of clustercheck after a reboot: HAProxy then marks mysql down and the API "
                "goes down. Get an exception for /usr/bin/clustercheck (socat) from the Elastic owner, or stop and disable it "
                "with approval, before the reboot." if risky else "Elastic Endpoint is not running and does not start at boot."),
               {"columns": ["Controller", "Package", "Units (enabled / active)", "/opt/Elastic"], "rows": rows}, marks=risky)

        # ---------------- kernel ----------------
        rows, change = [], []
        for i, n in up:
            k = parse_kernel(item_out(data, f"ker_{i}"))
            differs = bool(k["newest"]) and k["newest"] != k["running"]
            if differs or k["reboot_needed"]:
                change.append(n["name"])
            rows.append([n["name"], k["running"] or "-", k["newest"] or "-",
                         {True: "yes", False: "no", None: "-"}[k["reboot_needed"]], k["since"] or "-"])
        r.step("kernel", "Kernel after the reboot", "info",
               (f"A reboot starts a newer kernel on {', '.join(change)}: check the result after each controller (this check "
                "again) before the next." if change else "The controllers run their newest installed kernel."),
               {"columns": ["Controller", "Running", "Newest installed", "needs-restarting", "Up since"], "rows": rows})

        # ---------------- what to do ----------------
        blockers = [s["title"] for s in r.steps if s["status"] == "fail"]
        names = [n["name"] for _i, n in up]
        if blockers:
            r.recommend("Do not reboot a controller now: fix these first, then run this check again. "
                        "A reboot takes one controller out of the cluster; with a problem already there, the cluster can lose "
                        "its quorum or the API its database.",
                        ["sudo pcs status --full", "sudo pcs resource failcount show",
                         "sudo podman exec $(sudo podman ps -q -f name=galera-bundle) mysql -e \"SHOW STATUS LIKE 'wsrep_%'\" | "
                         "grep -E 'cluster_size|local_state_comment|cluster_status'",
                         "curl -s -o /dev/null -w '%{http_code}\\n' http://$(sudo ss -ltnH 'sport = :9200' | awk '{print $4}' | head -n 1)/"],
                        where=where, refs=["rhosp-galera", "rhosp-fencing"],
                        items={"columns": ["Not ready"], "rows": [[b] for b in blockers]})
        if risky:
            r.recommend("Elastic Endpoint must not stop clustercheck after the reboot: ask the Elastic owner for an exception "
                        "(process /usr/bin/clustercheck, socat listener on 9200), or, with the approval of the security owner, "
                        "stop and disable it on the controllers before the reboot.",
                        ["sudo systemctl is-enabled elastic-agent ElasticEndpoint; sudo systemctl is-active elastic-agent ElasticEndpoint",
                         "sudo systemctl disable --now elastic-agent ElasticEndpoint   # only with approval"],
                        where=where, warning="Changing a security agent needs the approval of its owner.")
        if not blockers:
            steps = []
            for name in names:
                steps += [f"# {name}: from the director, ssh {user}@<ctlplane of {name}>", "sudo pcs cluster stop", "sudo reboot",
                          f"# wait until {name} is back, then on it:", "sudo pcs status", "sudo podman ps --format '{{.Names}} {{.Status}}' | grep -vi ' up '",
                          "# run this check again: green before the next controller"]
            r.recommend("Ready: reboot the controllers one at a time, the next only once this check is green again "
                        "(Red Hat: Rebooting Controller and composable nodes).", steps, where=where,
                        refs=["rhosp-reboot-controllers"],
                        warning="Never two controllers at once: the cluster keeps its quorum with one controller away only.")
        return r.done("Ready to reboot the controllers one at a time." if not blockers and not risky else "")

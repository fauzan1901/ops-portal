"""NetApp ONTAP beyond capacity (RISET-KNOWN-ISSUES.md 2.5): volumes and LUNs that are not online (a LUN in space_error
because its FlexVol is full although the aggregate has room), FlexVols with LUNs that fill without autosize, inodes,
stopped SVMs, and the HA and redundancy of the cluster (takeover possible, spare disks, ports down, NTP and the time of
the nodes). REST GET only, with the ONTAP Restore account of the site; no fix runs from the portal (they need an ONTAP
role with write rights): the commands and the NetApp knowledge base articles are given.
"""
import datetime
import re

from .common import Result, json_of, source, unavailable

FULL_WARN = 85        # % used of a FlexVol that holds LUNs, with autosize off
INODE_WARN, INODE_FAIL = 80, 90
SKEW_WARN = 60        # seconds between a node and the portal
EVENT_HOURS = 72      # EMS events older than this are history, not a finding
KB = "https://kb.netapp.com/on-prem/ontap"


def records(item):
    data = json_of(item) or {}
    return data.get("records") or [] if isinstance(data, dict) else []


def gib(n):
    return f"{(n or 0) / 1073741824:,.0f} GiB"


def ref(title, path):
    return {"vendor": "NetApp", "title": title, "url": f"{KB}/{path}"}


EVENTS = ("scsiblade.lun.offline.system", "LUN.out.of.space", "wafl.vol.full", "wafl.vol.runningOutOfInodes",
          "wafl.vol.outOfInodes", "wafl.inconsistent.vol")


class OntapVolumeLunState:
    """Volumes and LUNs of the cluster: not online, LUN space_error, FlexVols with LUNs near full without autosize,
    inodes, stopped SVMs and the EMS events of these problems."""
    sources = ("ontap",)
    phases = 1

    @staticmethod
    def reads(phase, data, params, ctx):
        return {"ontap": {
            "volumes": "/api/storage/volumes?fields=name,svm.name,state,space.size,space.available,space.used,autosize.mode,"
                       "files.used,files.maximum&max_records=5000",
            "luns": "/api/storage/luns?fields=name,svm.name,location.volume.name,status.state,space.size,space.used&max_records=5000",
            "svms": "/api/svm/svms?fields=name,state,subtype&max_records=500",
            "events": "/api/support/ems/events?fields=time,node.name,message.name,log_message&message.name=" + "|".join(EVENTS)
                      + "&order_by=time%20desc&max_records=30"}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("ontap-volume-lun-state")
        vols_item, luns_item = source(data, "volumes"), source(data, "luns")
        if unavailable(vols_item):
            r.step("volumes", "FlexVols", "fail", f"The volumes could not be read: {unavailable(vols_item)}")
            return r.done()
        vols, luns = records(vols_item), records(luns_item)
        offline = [v for v in vols if str(v.get("state") or "online") != "online"]
        r.step("volumes", "FlexVols online", "fail" if offline else "ok",
               (f"{len(offline)} of {len(vols)} volume(s) not online: " + ", ".join(f"{v.get('name')} ({v.get('state')})" for v in offline[:10])
                + ". Their LUNs and shares cannot be reached.") if offline else f"All {len(vols)} volume(s) online.",
               {"columns": ["Volume", "SVM", "State"], "rows": [[v.get("name"), (v.get("svm") or {}).get("name"), v.get("state")] for v in offline]},
               marks=[v.get("name") for v in offline])
        if unavailable(luns_item):
            r.step("luns", "LUNs online", "skip", f"The LUNs could not be read: {unavailable(luns_item)}")
        else:
            bad = [l for l in luns if str((l.get("status") or {}).get("state") or "online") != "online"]
            space = [l for l in bad if (l.get("status") or {}).get("state") == "space_error"]
            r.step("luns", "LUNs online", "fail" if bad else "ok",
                   (f"{len(bad)} of {len(luns)} LUN(s) not online" + (f", {len(space)} in space_error: their FlexVol is full, "
                    "even when the aggregate has room" if space else "") + ". The Cinder volumes on them fail (I/O errors in the "
                    "instances).") if bad else f"All {len(luns)} LUN(s) online.",
                   {"columns": ["LUN", "Volume", "State", "Size", "Used"],
                    "rows": [[l.get("name"), ((l.get("location") or {}).get("volume") or {}).get("name"), (l.get("status") or {}).get("state"),
                              gib((l.get("space") or {}).get("size")), gib((l.get("space") or {}).get("used"))] for l in bad[:40]]},
                   marks=[l.get("name") for l in bad[:5]])
            if space:
                r.recommend("A LUN is offline in space_error because its FlexVol is full: grow the FlexVol (or turn autosize on) "
                            "while the aggregate has room, then bring the LUN online. Do not turn snapshot autodelete on without "
                            "the owner of the volume.",
                            [f"volume size -vserver {(l.get('svm') or {}).get('name')} -volume "
                             f"{((l.get('location') or {}).get('volume') or {}).get('name')} -new-size +500g   # if the aggregate has room"
                             for l in space[:3]]
                            + [f"lun online -vserver {(l.get('svm') or {}).get('name')} -path {l.get('name')}" for l in space[:3]],
                            where="ONTAP CLI (cluster management), an account allowed to change volumes",
                            refs=[ref("Lun goes offline with space-error due to volume full", "Ontap_OS/OS-KBs/Lun_goes_offline_with_space-error_due_to_volume_full"),
                                  ref("ONTAP LUN offline due to lack of space in the volume or aggregate",
                                      "da/SAN/SAN-KBs/ONTAP_LUN_offline_due_to_lack_of_space_in_the_volume_or_aggregate")])
        with_luns = {((l.get("location") or {}).get("volume") or {}).get("name") for l in luns}
        full, inodes = [], []
        for v in vols:
            sp = v.get("space") or {}
            if str(v.get("state") or "online") != "online" or (sp.get("used") is None and sp.get("available") is None):
                continue   # offline (above), or its space not given: not "full"
            size = sp.get("size") or 0
            used = sp["used"] if sp.get("used") is not None else size - sp["available"]
            pct = round(used * 100 / size) if size else 0
            mode = str((v.get("autosize") or {}).get("mode") or "")
            if v.get("name") in with_luns and pct >= FULL_WARN and mode == "off":   # not given: unknown, not off
                full.append((v, pct))
            files = v.get("files") or {}
            if files.get("maximum"):
                ipct = round((files.get("used") or 0) * 100 / files["maximum"])
                if ipct >= INODE_WARN:
                    inodes.append((v, ipct, files))
        r.step("autosize", "FlexVols with LUNs near full, without autosize", "warn" if full else "ok",
               (f"{len(full)} FlexVol(s) holding LUNs at {FULL_WARN}% or more with autosize off: a write that does not fit takes "
                "their LUNs offline (space_error).") if full else f"No FlexVol with LUNs at {FULL_WARN}% or more without autosize.",
               {"columns": ["Volume", "SVM", "Used", "Autosize"],
                "rows": [[v.get("name"), (v.get("svm") or {}).get("name"), f"{p}%", (v.get("autosize") or {}).get("mode") or "-"] for v, p in full]},
               marks=[v.get("name") for v, _p in full])
        r.step("inodes", "Inodes (files) of the FlexVols", "fail" if any(p >= INODE_FAIL for _v, p, _f in inodes) else "warn" if inodes else "ok",
               (f"{len(inodes)} FlexVol(s) at {INODE_WARN}% of their files or more: writes fail with \"No space left on device\" "
                "although space is left.") if inodes else f"Every FlexVol under {INODE_WARN}% of its files.",
               {"columns": ["Volume", "SVM", "Files used", "Maximum", "Used"],
                "rows": [[v.get("name"), (v.get("svm") or {}).get("name"), f"{f.get('used'):,}", f"{f.get('maximum'):,}", f"{p}%"] for v, p, f in inodes]},
               marks=[v.get("name") for v, _p, _f in inodes])
        if full or inodes:
            r.recommend("Give the FlexVols room before they stop their LUNs or files: turn autosize on (grow) for the volumes "
                        "that hold LUNs, and raise the maximum number of files where the inodes run out (after reading NetApp's "
                        "considerations).",
                        [f"volume autosize -vserver {(v.get('svm') or {}).get('name')} -volume {v.get('name')} -mode grow" for v, _p in full[:5]]
                        + [f"volume modify -vserver {(v.get('svm') or {}).get('name')} -volume {v.get('name')} -files <new maximum>"
                           for v, _p, _f in inodes[:5]],
                        where="ONTAP CLI (cluster management), an account allowed to change volumes",
                        refs=[ref("How to increase the maximum number of files for a flexble volume",
                                  "Ontap_OS/OS-KBs/How_to_increase_the_maximum_number_of_files_for_a_flexble_volume"),
                              ref("Considerations before increasing the file count in ONTAP",
                                  "Ontap_OS/OS-KBs/Considerations_before_increasing_the_file_count_in_ONTAP")])
        svms_item = source(data, "svms")
        if not unavailable(svms_item):
            stopped = [s for s in records(svms_item) if str(s.get("state")) != "running"
                       and not str(s.get("subtype") or "").startswith(("dp_destination", "sync_destination"))]
            r.step("svms", "SVMs running", "fail" if stopped else "ok",
                   (f"Stopped: {', '.join(s.get('name') for s in stopped)}: their data LIFs are down." if stopped else
                    f"All {len(records(svms_item))} SVM(s) running (DR destinations are stopped on purpose)."),
                   marks=[s.get("name") for s in stopped])
        start = (datetime.datetime.fromtimestamp(int(ctx["now"]), datetime.timezone.utc) - datetime.timedelta(hours=EVENT_HOURS)
                 if ctx.get("now") else None)
        events = [e for e in records(source(data, "events")) if (e.get("message") or {}).get("name") in EVENTS
                  and (start is None or ((parse_time(e.get("time")) or start) >= start))]
        if events:
            r.step("events", "EMS events of these problems", "warn",
                   f"{len(events)} event(s) in the last {EVENT_HOURS} hours: " + ", ".join(sorted({(e.get('message') or {}).get('name') for e in events})) + ".",
                   {"columns": ["Time", "Node", "Event", "Message"],
                    "rows": [[str(e.get("time") or "")[:19], (e.get("node") or {}).get("name"), (e.get("message") or {}).get("name"),
                              str(e.get("log_message") or "")[:160]] for e in events[:20]]})
        return r.done()


def parse_time(value):
    try:
        return datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


class OntapHaRedundancy:
    """HA and redundancy of the cluster: storage failover (takeover possible, giveback), spare disks per node, ports that
    are down while in use, NTP servers and the time of the nodes."""
    sources = ("ontap",)
    phases = 1

    @staticmethod
    def reads(phase, data, params, ctx):
        return {"ontap": {
            "nodes": "/api/cluster/nodes?fields=name,state,ha.enabled,ha.auto_giveback,ha.takeover.state,ha.giveback.state,ha.partners"
                     "&max_records=50",
            "failover": "/api/private/cli/storage/failover?fields=node,possible,partner_name,state_description",
            "spares": "/api/storage/disks?container_type=spare&fields=name,node.name,type,class&max_records=5000",
            # spare partitions (root-data partitioning, AFF): not in storage/disks?container_type=spare
            "sparepool": "/api/storage/aggregates?show_spares=true",
            # with the lag (members, active ports) and the vlan (base port), and the LIFs: a port is in use when a
            # LIF is on it (or on a VLAN of it); an interface group is checked by its active member ports
            "ports": "/api/network/ethernet/ports?fields=name,node.name,enabled,state,type,broadcast_domain.name,lag,vlan"
                     "&max_records=2000",
            "lifs": "/api/network/ip/interfaces?fields=name,location.home_node.name,location.home_port.name,location.node.name,"
                    "location.port.name&max_records=5000",
            "ntp": "/api/cluster/ntp/servers?fields=server&max_records=20",
            "dates": "/api/private/cli/cluster/date?fields=node,date"}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("ontap-ha-redundancy")
        nodes_item = source(data, "nodes")
        if unavailable(nodes_item):
            r.step("ha", "Storage failover (HA)", "fail", f"The nodes could not be read: {unavailable(nodes_item)}")
            return r.done()
        nodes = records(nodes_item)
        sfo = {str(x.get("node")): x for x in records(source(data, "failover"))}
        rows, bad = [], []
        for n in nodes:
            ha = n.get("ha") or {}
            f = sfo.get(str(n.get("name"))) or {}
            take = str((ha.get("takeover") or {}).get("state") or "")
            give = str((ha.get("giveback") or {}).get("state") or "")
            problem = (not ha.get("enabled", True)) or f.get("possible") is False \
                or take in ("not_possible", "in_progress", "in_takeover", "failed") or give in ("failed", "in_progress", "partial")
            if problem:
                bad.append(n.get("name"))
            rows.append([n.get("name"), ", ".join(p.get("name", "") for p in ha.get("partners") or []) or f.get("partner_name") or "-",
                         "yes" if ha.get("enabled", True) else "NO", take or "-", give or "-",
                         "yes" if f.get("possible") is True else "NO" if f.get("possible") is False else "not read",
                         str(f.get("state_description") or "-")[:120]])
        unread = "" if sfo else (f" Takeover possible was not read (storage failover show: "
                                 f"{unavailable(source(data, 'failover')) or 'no answer'}): only the HA state of the nodes was rated.")
        r.step("ha", "Storage failover (HA)", "fail" if bad else "ok",
               (f"Takeover not possible or failover not normal on: {', '.join(bad)}: a failure of the partner stops its data." if bad else
                f"Storage failover enabled on all {len(nodes)} node(s), takeover " + ("possible." if sfo else "not reported impossible."))
               + unread,
               {"columns": ["Node", "Partner", "HA", "Takeover", "Giveback", "Takeover possible", "State"], "rows": rows}, marks=bad)
        if bad:
            r.recommend("Storage failover is not ready on a node: until it is, the failure of its partner stops the data of "
                        "both. Read the reason (interconnect, partner not responding, giveback pending) and fix it with NetApp "
                        "Support; a giveback runs only when the partner is healthy.",
                        ["storage failover show -fields possible,state-description", "storage failover show-giveback",
                         "system ha interconnect status show"], where="ONTAP CLI (cluster management)",
                        refs=[ref("The System Manager reports Storage failover is disabled",
                                  "DM/System_Manager/SM-KBs/The_System_Manager_reports_Storage_failover_is_disabled")])
        spares_item = source(data, "spares")
        if not unavailable(spares_item):
            count = {str(n.get("name")): 0 for n in nodes}
            for d in records(spares_item):
                name = str((d.get("node") or {}).get("name") or "")
                count[name] = count.get(name, 0) + 1
            pool = json_of(source(data, "sparepool")) if not unavailable(source(data, "sparepool")) else None
            usable = {k: 0 for k in count}
            for x in (pool.get("spares") or []) if isinstance(pool, dict) else []:
                if isinstance(x, dict) and str(x.get("usable") or "0").isdigit():
                    name = str((x.get("node") or {}).get("name") or "")
                    usable[name] = usable.get(name, 0) + int(x["usable"])
            none = [k for k in count if count[k] == 0 and usable.get(k, 0) == 0]
            r.step("spares", "Spare disks per node", "warn" if none else "ok",
                   (f"No spare disk on: {', '.join(none)}: the next failed disk of that node leaves its RAID group degraded." if none else
                    "Every node has spare disks or spare partitions.")
                   + ("" if isinstance(pool, dict) else " Spare partitions (root-data partitioning) were not read: a node with "
                                                         "partitioned disks may have spares this does not show."),
                   {"columns": ["Node", "Spare disks", "Usable spares (partitions included)"],
                    "rows": [[k, str(v), str(usable.get(k, 0)) if isinstance(pool, dict) else "-"] for k, v in count.items()]},
                   marks=none)
            if none:
                r.recommend("A node has no spare disk: assign a spare to it, or replace the failed disks (RMA).",
                            ["storage aggregate show-spare-disks", "storage disk show -broken"], where="ONTAP CLI (cluster management)",
                            refs=[ref("SPARES LOW ERROR AutoSupport message", "OHW/OHW-KBs/SPARES_LOW_ERROR_AutoSupport_message")])
        ports_item, lifs_item = source(data, "ports"), source(data, "lifs")
        if not unavailable(ports_item):
            ports = records(ports_item)
            key = lambda node, port: (str(node or ""), str(port or ""))
            by_key = {key((p.get("node") or {}).get("name"), p.get("name")): p for p in ports}
            lifs_read = not unavailable(lifs_item)
            used = set()
            for lif in records(lifs_item) if lifs_read else []:
                loc = lif.get("location") or {}
                for nk, pk in (("home_node", "home_port"), ("node", "port")):
                    k = key((loc.get(nk) or {}).get("name"), (loc.get(pk) or {}).get("name"))
                    if k[1]:
                        used.add(k)
            for k in list(used):   # a LIF on a VLAN uses its base port (often an interface group)
                base = (((by_key.get(k) or {}).get("vlan") or {}).get("base_port") or {}).get("name")
                if base:
                    used.add(key(k[0], base))
            members_of_groups = {key((p.get("node") or {}).get("name"), m.get("name")) for p in ports
                                 for m in ((p.get("lag") or {}).get("member_ports") or []) if isinstance(m, dict)}
            down, idle = [], 0
            for p in ports:
                if p.get("enabled") is False:
                    continue
                node, name = (p.get("node") or {}).get("name"), p.get("name")
                bd = (p.get("broadcast_domain") or {}).get("name") or ""
                state = str(p.get("state") or "")
                # without the LIFs, a port of a broadcast domain counts as used (as before)
                in_use = key(node, name) in used or bd == "Cluster" or (not lifs_read and bool(bd))
                lag = p.get("lag") or {}
                members = [m.get("name") for m in lag.get("member_ports") or [] if isinstance(m, dict)]
                if str(p.get("type")) == "lag" and members and isinstance(lag.get("active_ports"), list):
                    active = [m.get("name") for m in lag["active_ports"] if isinstance(m, dict)]
                    if len(active) < len(members):
                        down.append([node, name, "interface group", bd or "-",
                                     f"{len(active)} of {len(members)} member port(s) active; not active: "
                                     + ", ".join(m for m in members if m not in active)])
                        continue
                if state in ("down", "degraded") and key(node, name) not in members_of_groups:   # members: by their group
                    if in_use:
                        down.append([node, name, p.get("type") or "-", bd or "-", state])
                    else:
                        idle += 1
            r.step("ports", "Ports down while in use", "warn" if down else "ok",
                   (f"{len(down)} port(s) in use are down or have lost a member: the LIFs on them lose a path or move."
                    if down else "No port in use is down, and every interface group has all its member ports active.")
                   + (f" {idle} unused port(s) are down (no LIF on them): not rated." if idle else "")
                   + ("" if lifs_read else " The LIFs were not read: a port of a broadcast domain counts as in use."),
                   {"columns": ["Node", "Port", "Type", "Broadcast domain", "State"], "rows": down},
                   marks=[x[1] for x in down])
        ntp_item, dates_item = source(data, "ntp"), source(data, "dates")
        if not unavailable(ntp_item):
            servers = [s.get("server") for s in records(ntp_item)]
            now = datetime.datetime.fromtimestamp(int(ctx.get("now") or 0), datetime.timezone.utc) if ctx.get("now") else None
            skews = []
            for d in records(dates_item) if not unavailable(dates_item) else []:
                t = parse_time(d.get("date"))
                if t and now and t.tzinfo:
                    skews.append((d.get("node"), round((t - now).total_seconds())))
            off = [(n, s) for n, s in skews if abs(s) > SKEW_WARN]
            r.step("ntp", "NTP servers and the time of the nodes", "warn" if len(servers) < 2 or off else "ok",
                   f"{len(servers)} NTP server(s): {', '.join(servers) or '-'}"
                   + (" (fewer than 2: no fallback)" if len(servers) < 2 else "") + ". "
                   + ("Ahead / behind the portal by more than a minute: " + ", ".join(f"{n} {s:+d} s" for n, s in off) + "."
                      if off else ("Every node within a minute of the portal." if skews else "The time of the nodes was not read.")),
                   marks=[n for n, _s in off])
            if len(servers) < 2 or off:
                r.recommend("Configure at least two NTP servers and bring the time of the nodes back: Kerberos and CIFS fail "
                            "beyond 5 minutes of skew, and ONTAP rejects an NTP server beyond 1000 seconds (no EMS warns of it).",
                            ["cluster time-service ntp server show", "cluster date show",
                             "cluster time-service ntp server create -server <second NTP server>"],
                            where="ONTAP CLI (cluster management)",
                            refs=[ref("NTP server is rejected due to excessive skew", "Ontap_OS/OS-KBs/NTP_server_is_rejected_due_to_excessive_skew")])
        return r.done()

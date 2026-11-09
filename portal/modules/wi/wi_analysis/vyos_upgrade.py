"""VyOS upgrade (WI "VyOS Upgrade + CVE Mitigation", KB 8398), from the portal: a VyOS behind its jump host (Hosts & SSH,
"Connect through"), the image on the jump host.

The check (vyos-upgrade) only reads: version, installed images, hw-id of every interface, room in /tmp and for the
images, dropbear keys, the baseline (interfaces with their MAC and addresses, default gateway, routes, NAT rules). The fix
"Upgrade VyOS" (high risk: the host name typed) runs playbooks/tasks/vyos_upgrade.yml, step by step, stopping at the
first problem before anything irreversible:

  1  read the VyOS again (still the version and baseline of the check)        nothing changed when it differs
  2  backup: save, then /config/config.boot copied TO THE JUMP HOST (scp from the jump host, as the ISO; default
     /home/vyos/config-backup/<VyOS>/config.boot.<time>.before-<target>, mode 600), its sha256 compared with the
     VyOS; no copy is kept on the VyOS
  3  hw-id set on every interface that has none (WI 2.2), commit, save, verified
  4  the ISO on the jump host: present, size, sha256
  5  room on the VyOS: the image store for the new image; the ISO goes to /tmp (RAM: half the memory of the VM) or,
     when /tmp is too small, to the disk (the home folder of the login user, on the partition of the image store).
     When the image store is too small and its partition is the last of the disk: the partition and its ext4 grow
     online to the end of the disk (sfdisk -N, partx -u, resize2fs; the partition table is printed before). A disk
     enlarged in OpenStack / vCenter whose new size the VyOS does not see yet: the VyOS is rebooted first (boot ID)
  6  scp of the ISO from the jump host to that folder of the VyOS (the portal's key of the VyOS forwarded for this command
     only: ssh -A to the jump host; no key is stored on the jump host)
  7  sha256 on the VyOS = sha256 on the jump host
  8  add system image <folder>/<iso> (wi_vyos.py: Yes to every yes/no question, the proposed value to the others; a
     question with neither stops it),
     then show system image: the new image is there and is the default boot
  9  CVE-2025-30095: dropbear keys removed and a new one generated (WI 2.4)
 10  the ISO removed from the VyOS; reboot
 11  down, then up again within the time limit (default 15 minutes; SSH tried every 15 seconds), else the fix fails
     with the console rollback steps
 12  post-check against the baseline: version, every interface with the same MAC and addresses, default gateway,
     routes, NAT rules, ping of the next-hops of the static routes and of the default gateway (pinged before the
     upgrade too: one that did not answer before is not a failure; no internet address, not every VyOS has internet),
     new image default, dropbear key present

The check run after the fix sees the new version and offers "Roll back to <previous image>" (default boot back to
the previous image, reboot, wait, check) for when the post-check is not right.
"""
import os
import re
import shlex

from .common import Result, on_host, source, text_of, unavailable

q = shlex.quote
MARK = "@@VU@@"
ISO_RE = re.compile(r"^/[A-Za-z0-9_./-]{1,200}\.iso$")
DEFAULT_ISO = "/home/vyos/vyos-2026.03-generic-amd64.iso"
BACKUP_RE = re.compile(r"^/[A-Za-z0-9_./-]{1,200}$")
DEFAULT_BACKUP = "/home/vyos/config-backup"
TMP_NEED_KB = 100 * 1024        # besides the ISO itself
STORE_NEED_KB = 1536 * 1024     # a new image (squashfs and its config copy)
TMP_NEED_KB = 700 * 1024        # the ISO (about 600 MB; the fix checks its real size + 100 MB)
MAX_PINGS = 10                  # next-hops pinged before and after the upgrade
DIR_RE = re.compile(r"^/(tmp|home/[A-Za-z0-9_.-]{1,32})$")   # where the ISO may go on the VyOS
HERE = os.path.dirname(os.path.abspath(__file__))
NODE_SCRIPT = os.path.join(HERE, "wi_vyos.py")


def vyos_op(command):
    """A VyOS op-mode command run non-interactively (the program behind `run`; see network.vyos)."""
    return f"/opt/vyatta/bin/vyatta-op-cmd-wrapper {command}"


SECTIONS = (
    ("version", vyos_op("show version")),
    ("images", vyos_op("show system image")),
    ("config", vyos_op("show configuration commands")),
    ("links", "ip -o link show"),
    ("addrs", "ip -o -4 addr show"),
    ("routes", "ip route show"),
    ("tmp", "df -Pk /tmp"),
    ("isos", "ls -ln /tmp/*.iso 2>/dev/null"),
    ("home", "echo ~; df -Pk ~"),   # replaced by home_command(login user) when it is known
    ("store", "df -Pk /usr/lib/live/mount/persistence /lib/live/mount/persistence 2>/dev/null"),
    ("disk", None),   # DISK_COMMAND
    ("dropbear", "ls -1 /etc/dropbear /etc/dropbear-initramfs /etc/dropbear_rsa_host_key 2>/dev/null"),
    ("python", "command -v python3"),
)


# the partition of the image store, its filesystem, its disk (size in 512-byte sectors), every partition of that disk
# (start, size) and the tools that grow it
DISK_COMMAND = (
    "PATH=$PATH:/sbin:/usr/sbin; set -- $(df -PT /usr/lib/live/mount/persistence /lib/live/mount/persistence 2>/dev/null "
    "| awk 'NR==2{print $1, $2}'); echo \"dev $1 $2\"; p=${1#/dev/}; "
    "k=$(basename \"$(readlink -f /sys/class/block/$p/..)\"); echo \"disk $k $(cat /sys/class/block/$k/size 2>/dev/null)\"; "
    "for q in /sys/class/block/$k/$k*; do [ -f \"$q/start\" ] && echo \"part $(basename \"$q\") $(cat \"$q/start\") $(cat \"$q/size\")\"; done; "
    "for t in sfdisk partx resize2fs; do command -v $t >/dev/null 2>&1 && echo \"tool $t\"; done; true")
GROW_DEV = re.compile(r"^/dev/((?:vd|sd|xvd)[a-z]{1,2})(\d{1,2})$")


def parse_disk(text):
    """The output of DISK_COMMAND -> {"dev", "fstype", "disk", "sectors", "parts": [[name, start, size]], "tools"}."""
    d = {"dev": "", "fstype": "", "disk": "", "sectors": 0, "parts": [], "tools": []}
    for line in str(text or "").splitlines():
        f = line.split()
        if len(f) >= 3 and f[0] == "dev":
            d["dev"], d["fstype"] = f[1], f[2]
        elif len(f) >= 3 and f[0] == "disk" and f[2].isdigit():
            d["disk"], d["sectors"] = f[1], int(f[2])
        elif len(f) >= 4 and f[0] == "part" and f[2].isdigit() and f[3].isdigit():
            d["parts"].append([f[1], int(f[2]), int(f[3])])
        elif len(f) >= 2 and f[0] == "tool":
            d["tools"].append(f[1])
    return d


def grow_plan(disk):
    """Whether the partition of the image store can grow to the end of its disk: {"can", "why", "disk", "num", "dev",
    "free_kb" (outside the partition), "disk_kb"}."""
    disk = disk or {}
    plan = {"can": False, "why": "", "disk": "", "num": 0, "dev": "", "free_kb": 0, "disk_kb": int(disk.get("sectors") or 0) // 2}
    m = GROW_DEV.match(str(disk.get("dev") or ""))
    name = os.path.basename(str(disk.get("dev") or ""))
    part = next((p for p in disk.get("parts") or [] if p[0] == name), None)
    last = max(disk.get("parts") or [["", -1, 0]], key=lambda p: p[1])
    missing = [t for t in ("sfdisk", "partx", "resize2fs") if t not in (disk.get("tools") or [])]
    if not m or m.group(1) != disk.get("disk") or not part or not disk.get("sectors"):
        plan["why"] = f"the image store is on {disk.get('dev') or 'a device that was not read'}: not a disk partition the portal can grow"
    elif last[0] != name:
        plan["why"] = f"{name} is not the last partition of {disk['disk']} ({last[0]} comes after it): grow it by hand"
    elif disk.get("fstype") not in ("ext4", "ext3", "ext2"):
        plan["why"] = f"the filesystem of {name} is {disk.get('fstype') or 'unknown'}, not ext4: grow it by hand"
    elif missing:
        plan["why"] = f"{', '.join(missing)} missing on the VyOS: grow the partition by hand"
    else:
        free = max(0, disk["sectors"] - (part[1] + part[2]) - 34)   # 34 sectors: a GPT backup header at the end
        plan.update(can=True, disk=m.group(1), num=int(m.group(2)), dev=disk["dev"], free_kb=free // 2)
    return plan


def grow_need(tmp_kb, store_kb, disk, iso_kb):
    """Is the image store big enough for the new image (and the ISO when /tmp is too small)? When not: can the partition
    grow, is the room outside it enough now, or must the VyOS reboot to see a disk enlarged in OpenStack / vCenter.
    -> {"needed", "can", "enough", "need_kb", "store_kb", "text", "summary", "disk", "num", "dev", "free_kb"}."""
    iso_need = int(iso_kb) + 100 * 1024
    tmp_fits = (tmp_kb or 0) >= iso_need
    need = STORE_NEED_KB + (0 if tmp_fits else iso_need)
    plan = grow_plan(disk)
    out = dict(plan, needed=False, enough=True, need_kb=need, store_kb=store_kb, text="", summary="")
    if store_kb is None or store_kb >= need:
        return out
    usable = int(plan["free_kb"] * 0.95)   # the filesystem keeps a few percent
    what = "the new image" + ("" if tmp_fits else " and the ISO (/tmp is too small)")
    head = f"Image store: {round(store_kb / 1024)} MB free, {round(need / 1024)} MB needed for {what}. "
    out.update(needed=True, enough=plan["can"] and store_kb + usable >= need)
    if not plan["can"]:
        out.update(text=head + f"It cannot grow from the portal: {plan['why']}. Or delete an old image (delete system image <name>).",
                   summary="too small, cannot grow")
    elif out["enough"]:
        out.update(text=head + f"The disk {plan['disk']} has {round(plan['free_kb'] / 1024)} MB outside {os.path.basename(plan['dev'])}: "
                              f"the upgrade grows {os.path.basename(plan['dev'])} and its filesystem to the whole disk first, online "
                              "(no reboot for this).",
                   summary=f"grow {os.path.basename(plan['dev'])} by {round(plan['free_kb'] / 1024)} MB")
    else:
        min_gb = -(-(plan["disk_kb"] + int((need - store_kb - usable) / 0.95)) // (1024 * 1024))
        out.update(text=head + f"The disk {plan['disk']} ({round(plan['disk_kb'] / 1048576, 1)} GB) has "
                              f"{round(plan['free_kb'] / 1024)} MB outside {os.path.basename(plan['dev'])}: enlarge the disk of the VM "
                              f"to at least {min_gb} GB first, on the VM side (OpenStack: resize to a flavor with a bigger disk or "
                              "extend the volume; vCenter: edit the disk), not inside VyOS. Then run this check again, or "
                              f"start \"Disk enlarged: reboot, grow, upgrade\": the VyOS reboots to read the new size, the portal "
                              f"grows {os.path.basename(plan['dev'])} and its filesystem inside VyOS, online, and the upgrade continues.",
                   summary=f"enlarge the disk of the VM to at least {min_gb} GB (the VyOS is rebooted to read it)", min_gb=min_gb)
    return out


def home_command(user):
    """The home folder of the login user and its room: the scp writes there as that user. Not "~": with a credential
    that uses sudo the commands run as root, and ~ is /root."""
    if not re.match(r"^[A-Za-z0-9_.-]{1,32}$", str(user or "")):
        return "echo ~; df -Pk ~"
    return (f"h=$(getent passwd {user} | cut -d: -f6); h=${{h:-/home/{user}}}; echo \"$h\"; df -Pk \"$h\"")


def state_script(user=""):
    """One line (fixed read commands only) that prints every section of the VyOS between markers; user: the login user
    (its home folder is where the ISO goes when /tmp is too small)."""
    return "; ".join(f"echo '{MARK}{name}'; {home_command(user) if name == 'home' and user else DISK_COMMAND if name == 'disk' else cmd} 2>&1"
                     for name, cmd in SECTIONS) + "; true"


def sections(text):
    out, cur = {}, None
    for line in str(text or "").splitlines():
        if line.startswith(MARK):
            cur = line[len(MARK):].strip()
            out[cur] = []
        elif cur:
            out[cur].append(line)
    return {k: "\n".join(v) for k, v in out.items()}


def iso_sizes(text):
    """ls -ln of ISO files -> {basename: KiB}."""
    out = {}
    for line in str(text or "").splitlines():
        f = line.split()
        if len(f) >= 9 and f[4].isdigit() and f[-1].endswith(".iso"):
            out[os.path.basename(f[-1])] = int(f[4]) // 1024
    return out


def home_dir(text):
    """The first line of "echo ~; df -Pk ~": the home folder of the login user, when it is a plain /home/<name>."""
    first = (str(text or "").strip().splitlines() or [""])[0].strip()
    return first if DIR_RE.match(first) and first != "/tmp" else ""


def iso_dir(folder):
    """The folder of the ISO on the VyOS: /tmp or /home/<user> (validated: it goes into commands)."""
    folder = str(folder or "/tmp").rstrip("/") or "/tmp"
    if not DIR_RE.match(folder):
        raise ValueError("invalid folder for the image")
    return folder


def place_iso(tmp_kb, home_kb, store_kb, iso_kb, home):
    """Where the ISO goes: /tmp when it fits (with 100 MB to spare), else the home folder on the disk when it holds the
    ISO and the new image, else nowhere. -> {"dir", "text"}."""
    need = int(iso_kb) + 100 * 1024
    if (tmp_kb or 0) >= need:
        return {"dir": "/tmp", "text": f"/tmp: {round((tmp_kb or 0) / 1024)} MB usable, {round(need / 1024)} MB needed."}
    if home and (home_kb or 0) >= need + STORE_NEED_KB:
        return {"dir": home, "text": f"/tmp: {round((tmp_kb or 0) / 1024)} MB usable (RAM: half the memory of the VM), "
                                     f"{round(need / 1024)} MB needed: the ISO goes to the disk instead, {home} "
                                     f"({round(home_kb / 1024)} MB free, {round((need + STORE_NEED_KB) / 1024)} MB needed for "
                                     "the ISO and the new image), and is removed after the install. No resize of the VM needed."}
    return {"dir": "", "text": f"/tmp: {round((tmp_kb or 0) / 1024)} MB usable and the disk"
                               + (f" ({home}): {round((home_kb or 0) / 1024)} MB free" if home else ": its home folder not read")
                               + f": too small for the ISO ({round(need / 1024)} MB) and the new image ({STORE_NEED_KB // 1024} MB). "
                               "Delete an old image (delete system image <name>) or enlarge the disk of the VM."}


def parse_room(text, iso):
    """The room step of the fix -> {"tmp", "store", "home", "home_dir"} in KiB; an earlier copy of this ISO counts as
    room (the scp replaces it)."""
    s = sections(text)
    name = os.path.basename(str(iso or ""))
    old = {"/tmp": 0, "home": 0}
    for line in s.get("isos", "").splitlines():
        f = line.split()
        if len(f) >= 9 and f[4].isdigit() and os.path.basename(f[-1]) == name:
            old["/tmp" if f[-1].startswith("/tmp/") else "home"] += int(f[4]) // 1024
    home = home_dir(s.get("home"))
    return {"tmp": (free_kb(s.get("tmp")) or 0) + old["/tmp"], "store": free_kb(s.get("store")),
            "home": (free_kb(s.get("home")) or 0) + old["home"], "home_dir": home}


def free_kb(text):
    best = None
    for line in str(text or "").splitlines():
        f = line.split()
        if len(f) >= 6 and f[3].isdigit():
            best = max(best or 0, int(f[3]))
    return best


def parse_images(text):
    """show system image -> (names, default boot). VyOS 1.3: "   1: <name> (default boot)"; 1.4 and later (2026.x): a
    table "Name  Default boot  Running", Yes in the column of the default boot."""
    lines = str(text or "").splitlines()
    head = next((i for i, l in enumerate(lines) if re.search(r"\bName\b", l) and re.search(r"default boot", l, re.I)), None)
    images, default = [], ""
    if head is not None:
        col = lines[head].lower().index("default boot")
        for line in lines[head + 1:]:
            if not line.strip() or set(line.strip()) <= set("-+| "):
                continue
            name = line.split()[0]
            if not re.match(r"^[A-Za-z0-9_.+-]{1,80}$", name):
                continue
            images.append(name)
            if line[col:col + 14].strip().lower().startswith("yes"):
                default = name
        return images, default
    for line in lines:
        m = re.match(r"^\s*\d+:\s+(\S+)(.*)$", line)
        if m:
            images.append(m.group(1))
            if "default boot" in m.group(2):
                default = m.group(1)
    return images, default


def parse_state(text):
    """The sections of state_script() -> version, images, hw-id / MAC / addresses per interface, gateway, routes, NAT
    rules, free space, dropbear key files, python3."""
    s = sections(text)
    cfg = [l.strip().replace("'", "") for l in s.get("config", "").splitlines() if l.strip().startswith("set ")]
    version = (re.search(r"Version:\s*(?:VyOS\s*)?(\S+)", s.get("version", "")) or [None, ""])[1]
    images, default = parse_images(s.get("images", ""))
    macs = {m.group(1): m.group(2).lower() for l in s.get("links", "").splitlines()
            for m in [re.search(r"\d+:\s+(eth\d+)[@:].*link/ether ([0-9a-fA-F:]{17})", l)] if m}
    hwid = {m.group(1): m.group(2).lower() for l in cfg for m in [re.match(r"^set interfaces ethernet (eth\d+) hw-id (\S+)", l)] if m}
    ifaces = sorted({m.group(1) for l in cfg for m in [re.match(r"^set interfaces ethernet (eth\d+)\b", l)] if m}, key=lambda x: int(x[3:]))
    addrs = {}
    for l in s.get("addrs", "").splitlines():
        m = re.search(r"\d+:\s+(eth\d+)\S*\s+inet\s+(\S+)", l)
        if m:
            addrs.setdefault(m.group(1), []).append(m.group(2))
    routes = [l for l in s.get("routes", "").splitlines() if l.strip()]
    gw = next((m.group(1) for l in routes for m in [re.match(r"^default via (\S+)", l)] if m), "")
    nat = {kind: sorted({m.group(1) for l in cfg for m in [re.match(rf"^set nat {kind} rule (\d+) ", l)] if m}, key=int)
           for kind in ("source", "destination")}
    # what the post-check pings: the default gateway and the next-hops of the static routes (IPv4), in order, once each
    hops = [m.group(1) for l in cfg for m in [re.match(r"^set protocols static route \S+ next-hop (\d{1,3}(?:\.\d{1,3}){3})\b", l)] if m]
    targets = list(dict.fromkeys(([gw] if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", gw) else []) + hops))[:MAX_PINGS]
    return {"version": version, "images": images, "default_image": default, "ifaces": ifaces, "macs": macs, "hwid": hwid,
            "addrs": {k: sorted(v) for k, v in addrs.items()}, "gateway": gw, "routes": len(routes), "nat": nat, "targets": targets,
            "tmp_free_kb": free_kb(s.get("tmp")), "tmp_isos": iso_sizes(s.get("isos")), "store_free_kb": free_kb(s.get("store")),
            "home_dir": home_dir(s.get("home")), "home_free_kb": free_kb(s.get("home")), "disk": parse_disk(s.get("disk")),
            "dropbear": [l.strip() for l in s.get("dropbear", "").splitlines() if "key" in l],
            "python": bool(s.get("python", "").strip()), "read": bool(s)}


def target_version(iso):
    """The version in the ISO name: vyos-2026.03-generic-amd64.iso -> 2026.03, vyos-1.5-rolling-... -> 1.5-rolling-..."""
    m = re.match(r"^vyos-(.+?)-(?:generic-)?amd64\.iso$", os.path.basename(str(iso or "")))
    return m.group(1) if m else ""


def same_version(running, wanted):
    return bool(running and wanted) and (wanted in running or running in wanted)


# ---------------------------------------------------------------- scripts of the fix (every step names itself first)
def step_script(step, **a):
    """The script of one step on the VyOS. Values come from the stored result and were validated by the check."""
    tag = f": wi-vu {step}; "
    iso = os.path.basename(str(a.get("iso") or ""))
    if iso and not re.match(r"^[A-Za-z0-9_.-]+\.iso$", iso):
        raise ValueError("invalid image name")
    d = iso_dir(a.get("dir"))
    if step == "state":
        return tag + state_script()
    if step == "backup":   # saved only: the copy goes to the jump host (jump_script "backup"), none is kept here
        return tag + ("/bin/vbash -c " + q("source /opt/vyatta/etc/functions/script-template\nconfigure\nsave\nexit")
                      + " && sha256sum /config/config.boot && ls -l /config/config.boot")   # read as the login user, as the scp does
    if step == "hwid":
        lines = []
        for eth, mac in a.get("hwid") or []:
            if not re.match(r"^eth\d+$", str(eth)) or not re.match(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", str(mac)):
                raise ValueError("invalid hw-id")
            lines.append(f"set interfaces ethernet {eth} hw-id '{mac}'")
        body = "\n".join(["source /opt/vyatta/etc/functions/script-template", "configure"] + lines + ["commit", "save", "exit"])
        return tag + "/bin/vbash -c " + q(body) + " && " + vyos_op("show configuration commands") + " | grep hw-id"
    if step == "room":   # /tmp, the image store, the home folder, an earlier copy of the image (the scp replaces it)
        return tag + (f"echo '{MARK}tmp'; df -Pk /tmp; echo '{MARK}store'; "
                      "df -Pk /usr/lib/live/mount/persistence /lib/live/mount/persistence 2>/dev/null; "
                      f"echo '{MARK}home'; {home_command(a.get('user'))}; echo '{MARK}disk'; {DISK_COMMAND}; echo '{MARK}isos'; "
                      + (f"ls -ln /tmp/{iso} \"${{h:-$HOME}}/{iso}\" 2>/dev/null; " if iso else "") + "true")
    if step == "grow":   # the partition of the image store to the end of its disk, then its ext4, online
        dev, disk, num = str(a.get("dev") or ""), str(a.get("disk") or ""), int(a.get("num") or 0)
        m = GROW_DEV.match(dev)
        if not m or m.group(1) != disk or int(m.group(2)) != num:
            raise ValueError("invalid partition")
        rescan = (f"echo 1 | sudo tee /sys/class/block/{disk}/device/rescan >/dev/null 2>&1; " if disk.startswith("sd") else "")
        return tag + (f"PATH=$PATH:/sbin:/usr/sbin; echo '# the partition table before:'; sudo sfdisk -d /dev/{disk} || exit 3; {rescan}"
                      f"echo ', +' | sudo sfdisk --no-reread -N {num} /dev/{disk} || exit 4; "
                      f"sudo partx -u -n {num} /dev/{disk} || sudo partx -u /dev/{disk} || exit 5; "
                      f"sudo resize2fs {dev} || exit 6; df -Pk /usr/lib/live/mount/persistence /lib/live/mount/persistence 2>/dev/null; true")
    if step == "checksum":
        return tag + f"sha256sum {d}/{iso}"
    if step == "install":
        import base64
        with open(NODE_SCRIPT, "rb") as f:
            code = base64.b64encode(f.read()).decode()
        return (tag + f"f=$(mktemp /tmp/wi_vyos.XXXXXX) || exit 98; echo {code} | base64 -d > \"$f\"; "
                f"python3 \"$f\" install {d}/{iso}; rc=$?; rm -f \"$f\"; " + vyos_op("show system image") + "; exit $rc")
    if step == "cve":   # WI 2.4, before the reboot
        return tag + ("sudo rm -f /etc/dropbear/*key* /etc/dropbear-initramfs/*key*; "
                      "if command -v dropbearkey >/dev/null 2>&1; then sudo dropbearkey -t rsa -s 4096 -f /etc/dropbear_rsa_host_key "
                      "| grep -iE 'fingerprint|public key' | head -n 2; else echo 'dropbearkey is not installed: no dropbear key to regenerate'; fi; "
                      "ls -l /etc/dropbear_rsa_host_key /etc/dropbear 2>/dev/null; true")
    if step == "cleanup":
        return tag + f"rm -f {d}/{iso}; ls -l {d}/*.iso 2>/dev/null; true"
    if step == "reboot":   # in the background: the SSH session ends cleanly before the VyOS goes down
        return tag + "nohup sh -c 'sleep 3; sudo /sbin/reboot' >/dev/null 2>&1 & echo 'reboot in 3 seconds'"
    if step == "alive":   # changes only with a reboot (the uptime changes on every read)
        return tag + "cat /proc/sys/kernel/random/boot_id"
    if step == "ping":
        targets = [str(t) for t in (a.get("targets") or []) if t]
        if not targets or any(not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", t) for t in targets):
            raise ValueError("invalid ping targets")
        return tag + "; ".join(f"echo '{MARK}ping {h}'; ping -c 3 -W 2 {h} >/dev/null 2>&1 && echo OK || echo FAIL"
                               for h in targets[:MAX_PINGS]) + "; true"
    if step == "default_boot":
        import base64
        name = str(a.get("image") or "")
        if not re.match(r"^[A-Za-z0-9_.+-]{1,80}$", name):
            raise ValueError("invalid image name")
        with open(NODE_SCRIPT, "rb") as f:
            code = base64.b64encode(f.read()).decode()
        return (tag + f"f=$(mktemp /tmp/wi_vyos.XXXXXX) || exit 98; echo {code} | base64 -d > \"$f\"; "
                f"python3 \"$f\" default-boot {q(name)}; rc=$?; rm -f \"$f\"; " + vyos_op("show system image") + "; exit $rc")
    raise ValueError(f"unknown step {step}")


def jump_command(target, remote, jump_key="", target_key="", agent=False, password_stdin=False):
    """The command run on the portal server for the jump host: test mode, its fake program; else ssh to the jump host
    (its own key or password), with -A and an agent that holds only the VyOS key when agent is set (the scp from the
    jump host authenticates with it; the agent ends with the command); password_stdin: the VyOS password (WI_SSH_SECRET
    of the job) goes to the jump host on stdin, for wi_vyos.py copy."""
    jump = (target or {}).get("jump") or {}
    if jump.get("command"):   # test mode
        return f"{jump['command']} {q(remote)}"
    from . import JUMP_ADDRESS, JUMP_USER, _via_proxy
    address, user, port = str(jump.get("address") or ""), str(jump.get("user") or ""), int(jump.get("port") or 22)
    if not JUMP_ADDRESS.match(address) or not JUMP_USER.match(user) or not 0 < port < 65536:
        raise ValueError("The jump host is not valid")
    opts = (f"-F /dev/null -p {port} -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 -o ServerAliveInterval=30 "
            "-o ServerAliveCountMax=10")
    if jump.get("proxy"):
        opts += " -o " + q("ProxyCommand=" + _via_proxy(jump["proxy"]))
    if jump.get("auth") == "password":
        ssh = f"sshpass -e ssh {opts} -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive"
    else:
        if not re.match(r"^/[A-Za-z0-9_./-]+$", str(jump_key)):
            raise ValueError("No key file for the jump host")
        ssh = f"ssh {opts} -i {jump_key} -o IdentitiesOnly=yes -o BatchMode=yes"
    line = f"{ssh}{' -A' if agent else ''} {q(user + '@' + address)} {q(remote)}"
    if password_stdin:   # printf is a shell builtin: the password is on no command line
        return f"set -o pipefail; printf '%s\\n' \"$WI_SSH_SECRET\" | {line}"
    if not agent:
        return line
    if not re.match(r"^/[A-Za-z0-9_./-]+$", str(target_key)):
        raise ValueError("No key file for the VyOS: the upgrade needs a key credential")
    return ("set -o pipefail; eval \"$(ssh-agent -s)\" >/dev/null || exit 97; trap 'ssh-agent -k >/dev/null 2>&1' EXIT; "
            f"ssh-add -q {target_key} || exit 96; {line}")


def backup_file(backup_dir, name, target_version):
    """Where the configuration of a VyOS is kept on the jump host: <dir>/<VyOS>/config.boot.<time>.before-<target>
    (<time> is filled in by the jump host: $(date))."""
    if not BACKUP_RE.match(str(backup_dir or "")) or ".." in str(backup_dir):
        raise ValueError("invalid backup folder")
    safe = lambda v: re.sub(r"[^A-Za-z0-9_.-]", "_", str(v or "")).strip("._") or "vyos"
    return f"{str(backup_dir).rstrip('/')}/{safe(name)}", f"config.boot.TIME.before-{safe(target_version)}"


def jump_script(step, target, **a):
    """The command for the jump host: "iso" (present, size, sha256), "copy" (scp to the folder dir of the VyOS, /tmp or
    its home folder) or "backup"
    (scp of /config/config.boot of the VyOS to the backup folder of the jump host, mode 600, then its sha256)."""
    iso = str(a.get("iso") or "")
    if not ISO_RE.match(iso):
        raise ValueError("invalid ISO path")
    tag = f": wi-vu {step}; "
    if step == "iso":
        return tag + f"test -r {q(iso)} || {{ echo 'not found: {iso}'; exit 2; }}; stat -c %s {q(iso)}; sha256sum {q(iso)}"
    if step not in ("copy", "backup"):
        raise ValueError(f"unknown jump step {step}")
    user, address, port = str(target.get("user") or ""), str(target.get("address") or ""), int(target.get("port") or 22)
    if not re.match(r"^[A-Za-z0-9_.-]{1,32}$", user) or not re.match(r"^[A-Za-z0-9_.:-]+$", address):
        raise ValueError("invalid VyOS address")
    password = target.get("auth") == "password"   # wi_vyos.py on the jump host types the password (stdin) into scp
    if password:
        import base64
        with open(NODE_SCRIPT, "rb") as f:
            code = base64.b64encode(f.read()).decode()
        node = f"f=$(mktemp /tmp/wi_vyos.XXXXXX) || exit 98; echo {code} | base64 -d > \"$f\"; "
    base = f"scp -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 -P {port}"
    if step == "copy":
        d = iso_dir(a.get("dir"))
        if password:
            return tag + node + f"python3 \"$f\" copy {q(iso)} {q(user + '@' + address)} {port} {d}; rc=$?; rm -f \"$f\"; exit $rc"
        dest = f"{user}@{address}:{d}/{os.path.basename(iso)}"
        return tag + f"{base} {q(iso)} {q(dest)} || {base} -O {q(iso)} {q(dest)}"   # -O: the old scp protocol, when SFTP fails
    folder, name = backup_file(a.get("backup_dir") or DEFAULT_BACKUP, a.get("name") or address, a.get("version") or "new")
    src = f"{user}@{address}:/config/config.boot"
    # umask 077: the configuration holds password hashes and keys; the file name gets the time of the jump host
    head = (tag + f"umask 077; mkdir -p {q(folder)} || exit 3; chmod 700 {q(folder)}; "
            f"b={q(folder)}/{q(name.split('TIME')[0])}$(date +%Y%m%d-%H%M%S){q(name.split('TIME')[1])}; ")
    if password:
        fetch = node + f"python3 \"$f\" fetch {q(user + '@' + address)} {port} \"$b\"; rc=$?; rm -f \"$f\"; "
    else:
        fetch = f"{{ {base} {q(src)} \"$b\" || {base} -O {q(src)} \"$b\"; }}; rc=$?; "
    return (head + fetch + f"[ $rc -eq 0 ] && [ -s \"$b\" ] || {{ rm -f \"$b\"; echo 'the configuration was not copied'; exit 4; }}; "
            f"chmod 600 \"$b\"; echo '{MARK}backup '\"$b\"; sha256sum \"$b\"; ls -l \"$b\"")


# ---------------------------------------------------------------- post-check
def post_check(before, after, pings, wanted, expect_image="", pings_before=None):
    """[{"check", "ok", "detail"}] comparing the VyOS after the reboot with the baseline (WI 2.6 / success criteria).
    pings_before: the same pings before the upgrade; a target that did not answer then is not a failure now."""
    before, after = before or {}, after or {}
    rows = []

    def add(name, ok, detail):
        rows.append({"check": name, "ok": bool(ok), "detail": detail})
    add("Version", same_version(after.get("version"), wanted), f"{after.get('version') or '?'} (expected {wanted})")
    if expect_image:
        add("Default boot image", after.get("default_image") == expect_image,
            f"{after.get('default_image') or '?'} (expected {expect_image})")
    for eth in before.get("ifaces") or []:
        mac_b, mac_a = (before.get("macs") or {}).get(eth), (after.get("macs") or {}).get(eth)
        if not mac_b:   # configured without a network card before the upgrade (hw-id skipped)
            add(f"Interface {eth}", not mac_a, "no network card, as before" if not mac_a else f"now has MAC {mac_a}: check it")
            continue
        add_b, add_a = (before.get("addrs") or {}).get(eth) or [], (after.get("addrs") or {}).get(eth) or []
        add(f"Interface {eth}", mac_b == mac_a and add_b == add_a,
            f"MAC {mac_a or '-'}" + ("" if mac_b == mac_a else f" (before {mac_b or '-'}: the interfaces swapped)")
            + f"; addresses {', '.join(add_a) or '-'}" + ("" if add_b == add_a else f" (before {', '.join(add_b) or '-'})"))
    for eth, mac_b in sorted((before.get("macs") or {}).items(), key=lambda x: int(x[0][3:])):
        if eth in (before.get("ifaces") or []):
            continue
        mac_a = (after.get("macs") or {}).get(eth)   # a network card not in the configuration: the same name after the reboot
        add(f"Interface {eth} (not configured)", mac_a == mac_b,
            f"MAC {mac_a or '-'}" + ("" if mac_a == mac_b else f" (before {mac_b}: the names of the network cards changed)"))
    add("Default gateway", after.get("gateway") == before.get("gateway"),
        f"{after.get('gateway') or 'none'}" + ("" if after.get("gateway") == before.get("gateway") else f" (before {before.get('gateway') or 'none'})"))
    rb, ra = int(before.get("routes") or 0), int(after.get("routes") or 0)
    add("Routes", ra >= rb, f"{ra} route(s) (before {rb})")
    for kind in ("source", "destination"):
        nb, na = (before.get("nat") or {}).get(kind) or [], (after.get("nat") or {}).get(kind) or []
        add(f"NAT {kind} rules", nb == na, f"{len(na)} rule(s)" + ("" if nb == na else f" (before {len(nb)}: {', '.join(sorted(set(nb) ^ set(na)))} differ)"))
    pings_before = pings_before or {}
    for host, ok in (pings or {}).items():
        was = pings_before.get(host)
        add(f"Ping {host}", ok or was is False,
            "answers" if ok else "no answer, as before the upgrade" if was is False else
            "no answer (it answered before the upgrade)" if was else "no answer")
    if not pings:
        add("Ping", True, "nothing to ping: no default gateway and no static route with a next-hop")
    add("Dropbear key (CVE-2025-30095)", True, ", ".join(after.get("dropbear") or []) or "no dropbear key file (dropbear not used)")
    return rows


def parse_pings(text):
    out, cur = {}, None
    for line in str(text or "").splitlines():
        if line.startswith(f"{MARK}ping "):
            cur = line[len(MARK) + 5:].strip()
        elif cur and line.strip() in ("OK", "FAIL"):
            out[cur] = line.strip() == "OK"
    return out


# ---------------------------------------------------------------- the check
class VyosUpgrade:
    """WI "VyOS Upgrade + CVE Mitigation": everything the upgrade needs, read on the VyOS; the upgrade itself is the fix."""
    sources = ("host",)
    phases = 1

    @staticmethod
    def reads(phase, data, params, ctx):
        return {"host": {"state": state_script(ctx.get("host_user") or "")}}

    @staticmethod
    def analyze(data, params, ctx):
        r = Result("vyos-upgrade")
        name = ctx.get("host_name") or "the VyOS"
        where = f"{on_host(ctx)}, VyOS CLI"
        iso = str(params.get("image") or DEFAULT_ISO)
        wanted = target_version(iso)
        backup_dir = str(params.get("backup_dir") or DEFAULT_BACKUP).rstrip("/") or DEFAULT_BACKUP
        if not BACKUP_RE.match(backup_dir) or ".." in backup_dir:
            r.step("backup", "Backup folder on the jump host", "fail", f"{backup_dir} is not a valid folder (e.g. {DEFAULT_BACKUP}).")
            return r.done()
        item = source(data, "state")
        if unavailable(item):
            r.step("reach", f"Read {name}", "fail", unavailable(item))
            return r.done()
        st = parse_state(text_of(item))
        problems = []
        jump = ctx.get("host_jump") or ""
        if not jump:
            problems.append("no jump host")
        r.step("jump", "Jump host and image", "ok" if jump and wanted else "fail",
               (f"{name} ({ctx.get('host_address')}) is reached through {jump} ({ctx.get('host_jump_address')}); the image "
                f"{iso} is copied from there with scp, and the configuration of {name} is backed up there, in "
                f"{backup_file(backup_dir, name, wanted)[0]}/ (nothing is kept on the VyOS)." if jump else
                f"{name} has no jump host: set 'Connect through' to the jump host that holds the image (Hosts & SSH).")
               + ("" if wanted else f" The name of {iso} does not show its version (vyos-<version>-generic-amd64.iso)."))
        if not wanted:
            problems.append("image name")
        r.step("auth", "Credential of the VyOS", "ok",
               ("Password: for the scp, the portal sends it to the jump host on its SSH connection (not on a command line, "
                "not in a file) and types it into the password prompt of scp, once." if ctx.get("host_auth") == "password" else
                "Key: forwarded to the jump host only for the scp (ssh -A, an agent with this key only); nothing is stored there.")
               + (f" SSH port {ctx.get('host_port')}." if ctx.get("host_port") and str(ctx.get("host_port")) != "22" else ""))
        done = same_version(st["version"], wanted)
        r.step("version", "Current version", "ok" if done else "info",
               f"VyOS {st['version'] or '?'}; image to install: {wanted or '?'}."
               + (" Already on this version: nothing to upgrade." if done else ""))
        # configured without a network card (no MAC): nothing to pin, skipped (its configuration stays as it is)
        absent = [i for i in st["ifaces"] if i not in st["hwid"] and i not in st["macs"]]
        set_hw = [[i, st["macs"][i]] for i in st["ifaces"] if i not in st["hwid"] and i in st["macs"]]
        wrong = [i for i in st["ifaces"] if i in st["hwid"] and st["macs"].get(i) and st["hwid"][i] != st["macs"][i]]
        cfg_lines = [l for l in sections(text_of(item)).get("config", "").splitlines() if l.strip().startswith("set ")]
        cfg_addrs = {i: [m.group(1) for l in cfg_lines for m in [re.match(rf"^\s*set interfaces ethernet {i} address '?([^' ]+)", l)] if m]
                     for i in absent}
        r.step("hwid", "hw-id on every ethernet interface (WI 2.2)", "fail" if wrong else "warn" if set_hw or absent else "ok",
               ("; ".join(x for x in (f"set by the upgrade (current MAC): {', '.join(f'{i} {m}' for i, m in set_hw)}" if set_hw else "",
                                     f"in the configuration but without a network card (no MAC): {', '.join(absent)}: skipped, "
                                     "their configuration stays as it is (see the recommendation to remove it)" if absent else "",
                                     f"hw-id differs from the MAC on {', '.join(wrong)}: check the cabling / config first" if wrong else "") if x)
                or "Set on every interface."),
               {"columns": ["Interface", "hw-id in config", "MAC now", "Addresses", "Upgrade"],
                "rows": [[i, st["hwid"].get(i, "-"), st["macs"].get(i, "-"),
                          ", ".join(st["addrs"].get(i) or []) or (f"{', '.join(cfg_addrs[i])} (configured only)" if cfg_addrs.get(i) else "-"),
                          "hw-id set" if i in dict(set_hw) else "skipped: no network card" if i in absent else
                          "check: hw-id ≠ MAC" if i in wrong else "kept"] for i in st["ifaces"]]
                        # network cards that are not in the configuration (nothing on them, admin down): left as they are,
                        # their name and MAC are compared after the reboot
                        + [[i, "-", m, ", ".join(st["addrs"].get(i) or []) or "-",
                            "not configured: left as it is, its name checked after the reboot"]
                           for i, m in sorted(st["macs"].items(), key=lambda x: int(x[0][3:])) if i not in st["ifaces"]]},
               marks=absent + wrong)
        if wrong:
            problems.append("hw-id")
        for eth in absent:   # how to remove a configuration without its network card (the engineer decides)
            uses = [l.strip() for l in cfg_lines if re.search(rf"\b{eth}\b", l)]
            others = [l for l in uses if not l.startswith(f"set interfaces ethernet {eth} ")]
            addrs = sorted(set(re.findall(r"(\d+\.\d+\.\d+\.\d+/\d+)", " ".join(uses))))
            r.recommend(f"Optional: remove {eth} (no network card) from the configuration before the upgrade. The upgrade works "
                        "without this: it skips the hw-id of the interface and keeps its configuration. When the card is gone for "
                        "good, removing it lets the new image boot with a clean configuration. Delete the whole interface: "
                        f"deleting only its address fails with \"Interface {eth} does not exist\", because VyOS checks the "
                        "interface that remains.",
                        [f"show configuration commands | match {eth}   # everything that names it",
                         "configure", f"delete interfaces ethernet {eth}", "commit", "save", "exit"],
                        where=where,
                        items={"columns": [f"Configuration that names {eth}"], "rows": [[l] for l in uses]},
                        warning=(f"Check first that {', '.join(addrs) or 'its addresses'} is not needed any more (it may have "
                                 "moved to another interface or gateway), or attach the network card again instead. "
                                 + (f"{len(others)} other line(s) name {eth} (NAT, firewall, routes: see the table): change "
                                    "them by hand; deleting only their interface may widen a rule. " if others else "")
                                 + "When the commit still fails, leave it: the upgrade works with the interface skipped."))
        # the same image already in /tmp (an earlier copy) is replaced by the scp: its room counts as free. /tmp is a RAM
        # disk (half the memory of the VM): when the ISO does not fit there, it goes to the disk (the home folder)
        old_iso = (st.get("tmp_isos") or {}).get(os.path.basename(iso), 0)
        tmp_usable = (st["tmp_free_kb"] or 0) + old_iso
        iso_kb = TMP_NEED_KB - 100 * 1024   # the ISO, about 600 MB (the fix checks its real size)
        grow = grow_need(tmp_usable, st["store_free_kb"], st.get("disk"), iso_kb)
        place = place_iso(tmp_usable, st.get("home_free_kb"), st["store_free_kb"], iso_kb, st.get("home_dir"))
        tmp_fits = tmp_usable >= iso_kb + 100 * 1024
        enlarge_vm = False   # the disk of the VM must be enlarged first (OpenStack / vCenter): notice, upgrade on confirmation
        if grow["needed"]:   # the image store grows first (the fix): the ISO goes to /tmp, or to the grown disk
            folder = "/tmp" if tmp_fits else st.get("home_dir") or ""
            detail = (f"/tmp: {round(tmp_usable / 1024)} MB usable (RAM: half the memory of the VM), "
                      + ("enough for the ISO. " if tmp_fits else f"too small for the ISO: it goes to the disk ({folder or 'home folder not read'}). ")
                      + grow["text"])
            ok = grow["can"] and grow["enough"] and bool(folder)
            enlarge_vm = grow["can"] and not grow["enough"] and bool(folder)
            status = "warn" if ok else "fail"
        else:
            folder = place["dir"]
            ok = bool(folder)
            detail = place["text"] + " Image store: " + (f"{round(st['store_free_kb'] / 1024)} MB free (about {STORE_NEED_KB // 1024} MB needed)."
                                                         if st["store_free_kb"] is not None else "not read.")
            status = "fail" if not ok else "ok" if folder == "/tmp" else "warn"
        r.step("room", "Room for the image", status,
               detail + (f" ({round((st['tmp_free_kb'] or 0) / 1024)} MB free in /tmp + {round(old_iso / 1024)} MB of an earlier "
                         f"copy of {os.path.basename(iso)}, replaced by the scp.)" if old_iso else ""),
               marks=[] if status == "ok" else ["/tmp"] if not tmp_fits else [str((st.get("disk") or {}).get("dev") or "/tmp")])
        if not ok:
            problems.append("room")
        iso_folder = folder or "/tmp"
        r.step("images", "Installed images", "info", ", ".join(f"{i}{' (default boot)' if i == st['default_image'] else ''}"
                                                             for i in st["images"]) or "-")
        r.step("cve", "CVE-2025-30095: dropbear keys (WI 2.4)", "info",
               (f"{len(st['dropbear'])} key file(s): removed and a new key generated before the reboot." if st["dropbear"]
                else "No dropbear key file: the step only checks it."))
        if not st["python"]:
            problems.append("python3")
            r.step("python", "python3 on the VyOS", "fail", "python3 is missing: the portal answers the prompts of add system image with it.")
        r.step("baseline", "Baseline for the post-check", "info",
               f"Default gateway {st['gateway'] or 'none'}, {st['routes']} route(s), {len(st['nat']['source'])} source NAT and "
               f"{len(st['nat']['destination'])} destination NAT rule(s), {len(st['ifaces'])} interface(s): compared after the reboot. "
               + (f"Pinged before the upgrade and after the reboot (default gateway and next-hops of the static routes): "
                  f"{', '.join(st['targets'])}." if st["targets"] else
                  "No default gateway and no static route with a next-hop: nothing to ping."))
        poll = int(ctx.get("vyos_poll_seconds") or 15)
        wait = int(params.get("wait_minutes") or 15)
        # the disk of the VM not enlarged yet (as the VyOS sees it): no "Upgrade VyOS"; "Disk enlarged: ..." once it is
        if not done and (not problems or (problems == ["room"] and enlarge_vm)):
            folder, fname = backup_file(backup_dir, name, wanted)
            steps = ["save   # running configuration to /config/config.boot, its sha256",
                     f"jump host {jump}: scp {name}:/config/config.boot {folder}/{fname.replace('TIME', '<time>')}   # mode 600; sha256 = the VyOS; no copy on the VyOS",
                     *(f"set interfaces ethernet {i} hw-id '{m}'   # commit, save" for i, m in set_hw),
                     *(f"skip the hw-id of {i}   # no network card; its configuration stays" for i in absent),
                     *([f"reboot, SSH again   # only when the VyOS does not see the enlarged disk yet"] if grow["needed"] and not grow["enough"] else []),
                     *([f"sfdisk -d /dev/{grow['disk']}; echo ', +' | sfdisk --no-reread -N {grow['num']} /dev/{grow['disk']}; "
                        f"partx -u /dev/{grow['disk']}; resize2fs {grow['dev']}   # {os.path.basename(grow['dev'])} to the whole disk, online"]
                       if grow["needed"] and grow["can"] else []),
                     f"jump host {jump}: sha256sum {iso}; scp {iso} → {name}:{iso_folder}/   # "
                     + ("/tmp, in RAM" if iso_folder == "/tmp" else "the disk: /tmp is too small") + "; checked again with its real size",
                     f"sha256sum {iso_folder}/{os.path.basename(iso)}   # the same as on the jump host",
                     f"add system image {iso_folder}/{os.path.basename(iso)}   # Yes to every yes/no question, the proposed value to the others; show system image: new default",
                     "rm -f /etc/dropbear/*key* /etc/dropbear-initramfs/*key*; dropbearkey -t rsa -s 4096 -f /etc/dropbear_rsa_host_key",
                     f"rm -f {iso_folder}/{os.path.basename(iso)}",
                     "reboot",
                     f"SSH every {poll} s until it answers (at most {wait} minutes)",
                     "show version; show interfaces; ip route; NAT rules; ping "
                     + (", ".join(st["targets"]) or "-") + "   # against the baseline (pinged before the upgrade too)"]
            r.recommend((f"After the disk of the VM is enlarged to at least {grow.get('min_gb')} GB (OpenStack / vCenter): upgrade {name} "
                         f"from {st['version'] or '?'} to {wanted}. The image store is too small now and the VyOS does not see a "
                         "bigger disk: the fix first reboots it to read the new size, grows the partition inside VyOS, then follows "
                         "the WI step by step. " if enlarge_vm else
                         f"Upgrade {name} from {st['version'] or '?'} to {wanted}, following the WI step by step. ")
                        + "Take a snapshot of the VM (vCenter / OpenStack) first. Each step is checked before the next; nothing "
                        f"irreversible happens before the image is installed and verified; after the reboot the portal waits up to {wait} "
                        "minutes for SSH, then compares everything with the baseline.",
                        steps, where=where, refs=[],
                        warning=(f"Only after the disk of the VM is enlarged: when the VyOS still sees a disk too small after the "
                                 "first reboot, the fix stops there, before anything is installed. " if enlarge_vm else "")
                                + f"The reboot interrupts the traffic through {name} for a few minutes: run it in a maintenance window. "
                                + ("It reboots twice: first to read the enlarged disk, then into the new image. " if enlarge_vm else "")
                                + f"Rollback: set system image default-boot '{st['default_image']}' then reboot (the check offers it after "
                                f"the upgrade), or WI 4 with the backup on {jump}: scp it to /tmp of {name}, then configure; "
                                "load /tmp/<backup>; commit; save.",
                        action={"kind": "vyos_upgrade", "risk": "high", "commands": steps,
                                "label": "Disk enlarged: reboot, grow, upgrade" if enlarge_vm else "Upgrade VyOS",
                                "upgrade": {"image": iso, "target": wanted, "hwid": set_hw, "absent": absent, "old_image": st["default_image"],
                                            "backup_dir": backup_dir, "home": st.get("home_dir") or "",
                                            "wait": wait * 60, "poll": poll,
                                            "baseline": {k: st[k] for k in ("version", "ifaces", "macs", "addrs", "gateway", "routes", "nat", "targets")}}})
        previous = next((i for i in st["images"] if i != st["default_image"]), "")
        if done and previous:
            r.recommend(f"Roll back {name} to the previous image {previous} when the new version does not work: the default boot "
                        "goes back to it, the VyOS reboots, and the portal waits for SSH and checks the version.",
                        [f"set system image default-boot '{previous}'", "reboot", "show version; show interfaces; ip route"],
                        where=where, warning="The reboot interrupts the traffic again for a few minutes.",
                        action={"kind": "vyos_rollback", "risk": "high", "label": f"Roll back to {previous}",
                                "commands": [f"set system image default-boot '{previous}'", "reboot", f"wait for SSH (at most {wait} minutes)",
                                             "check version, interfaces, routes"],
                                "upgrade": {"image": iso, "target": previous, "rollback_image": previous, "wait": wait * 60, "poll": poll,
                                            "baseline": {k: st[k] for k in ("version", "ifaces", "macs", "addrs", "gateway", "routes", "nat", "targets")}}})
        return r.done(("Already on " + wanted + "." if done else
                       f"Ready to upgrade {st['version']} → {wanted}." if not problems else
                       "Not ready: " + ", ".join(problems) + "."))

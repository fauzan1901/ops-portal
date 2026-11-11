"""How to fix it: one finding of Tenable as a fix plan for the operator. The Nessus module only SHOWS the plan; it never
runs a command (changes on hosts and devices stay with the operator, the network team or the admins, in a window).

plan(finding) -> {"title", "why", "kind", "platform": {"id", "label"}, "versions": [{"item", "installed", "fixed"}],
                  "steps": [{"platform", "where", "text", "commands": [...]}], "notes": [...], "links": [...],
                  "tenable": <Tenable's own solution>, "facts": {"has_patch", "patch_date", "exploit"},
                  "fixed_version": <short, for the CSV>, "fix": <short, for the CSV>}

The platform comes from the asset's operating system (Tenable asset.operating_system), else from the plugin family or
the SSH banner in the output. The rules are tried in order (local package checks, Windows updates, Cisco advisories, SSH
algorithms, SSL/TLS, cleartext services, "Installed version / Fixed version", then Tenable's solution). Commands only
carry values of the finding itself (its address, port, the packages, versions, algorithms, cipher suites and KB numbers
Tenable printed), each checked against a strict pattern first: a value with any other character is left out, so text
in a plugin output can never become a shell command. The device commands follow the runbooks of the Internal VA Q3 2026
(tools/va-2026q3 on branch deploy/va-2026q3), without their addresses and names.
"""
import ipaddress
import re

PLATFORMS = {"debian": "Ubuntu / Debian", "rhel": "RHEL / Rocky / Alma / CentOS", "linux": "Linux", "windows": "Windows",
             "ios": "Cisco IOS", "iosxe": "Cisco IOS XE", "nxos": "Cisco NX-OS", "iosxr": "Cisco IOS XR", "apic": "Cisco APIC",
             "esxi": "VMware ESXi", "other": "Other"}
LINUX = ("debian", "rhel", "linux")
CISCO = ("ios", "iosxe", "nxos", "iosxr")
NOTE_APPROVAL = ("A change that can affect customers needs the owner's approval and a window, and is run by an operator: "
                 "this portal only shows the commands.")
NOTE_VERIFY = "After the fix: Verify fix on the host page scans this host again; Sync now then shows the finding as Fixed."

SAFE_PKG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_~-]{0,120}$")        # a package name (deb or rpm)
SAFE_VER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+:_~()/,-]{0,80}$")    # a version as Tenable prints it
SAFE_ALGO = re.compile(r"^[a-z0-9][a-z0-9@._-]{1,80}$")
SAFE_SUITE = re.compile(r"^[A-Z0-9][A-Z0-9_-]{2,80}$")
SAFE_PATH = re.compile(r"^[A-Za-z0-9/\\._:() -]{2,200}$")
ARCH = re.compile(r"\.(x86_64|aarch64|noarch|i686|i386|ppc64le|s390x|amd64|arm64)$")
KERNEL = re.compile(r"^(linux-(image|modules|headers|generic|signed|hwe|virtual|lowlatency|kvm|aws|azure|gcp|oracle|ibm)(-.*)?"
                    r"|kernel(-(core|modules|modules-core|modules-extra|tools|headers|devel|rt|debug|uek)[a-z0-9-]*)?|kernel-uek.*)$")
ADVISORY = re.compile(r"\b(USN-\d+-\d+|DSA-\d+-\d+|DLA-\d+-\d+|RHSA-\d{4}:\d+|RLSA-\d{4}:\d+|ALSA-\d{4}:\d+|ELSA-\d{4}-\d+"
                      r"|CESA-\d{4}:\d+|cisco-sa-[A-Za-z0-9-]+|KB\d{6,7}|VMSA-\d{4}-\d+)\b")

# Strong SSH algorithms the plans set (as linux-va-fix.sh and the Cisco runbooks of the VA)
SSH_CIPHERS = "aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
SSH_MACS = "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"
SSH_KEX = ("curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
           "diffie-hellman-group16-sha512,diffie-hellman-group14-sha256")
WEAK_SSH = re.compile(r"^(?:(?:3des|aes\d{3}|blowfish|cast128|twofish\d*|serpent\d*|des)-cbc(?:@[a-z.]+)?|rijndael-cbc@lysator\.liu\.se"
                      r"|arcfour\d*|chacha20-poly1305@openssh\.com|hmac-(?:md5|sha1|ripemd160)(?:-96)?(?:-etm)?(?:@openssh\.com)?"
                      r"|umac-64(?:-etm)?@openssh\.com|diffie-hellman-group1-sha1|diffie-hellman-group14-sha1"
                      r"|diffie-hellman-group-exchange-sha1|gss-(?:gex|group1|group14)-sha1-\S+|rsa1024-sha1|ssh-dss)$")
SSH_IDS = {70658: "cbc", 71049: "mac", 90317: "weak", 153953: "kex", 187315: "terrapin", 10882: "sshv1"}
TLS_IDS = {104743: "tls10", 157288: "tls11", 20007: "ssl", 42873: "cipher", 65821: "cipher", 26928: "cipher", 31705: "cipher",
           69551: "cert", 57582: "cert", 51192: "cert", 15901: "cert", 35291: "cert", 83875: "dh", 83738: "dh"}
CLEARTEXT_IDS = {42263: "telnet", 10281: "telnet", 34850: "http", 26194: "http", 34324: "ftp", 10092: "ftp"}
WEAK_SUITE = re.compile(r"3DES|DES-CBC|DES_CBC|RC4|_DES_|NULL|EXPORT|EXP-|ADH|AECDH|MD5|IDEA|SEED")
APIC_SERVICE_PORTS = (8481, 9003, 9020, 49152, 49153)   # Cisco services on the APIC that the Management Access policy does not reach
SCHANNEL = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"


# ---------------------------------------------------------------- what the finding is
def _text(f, key):
    return str(f.get(key) or "")


def _ip(f):
    try:
        return str(ipaddress.ip_address(_text(f, "ipv4").strip()))
    except ValueError:
        return ""


def _port(f):
    try:
        port = int(f.get("port") or 0)
    except (TypeError, ValueError):
        return 0
    return port if 0 < port < 65536 else 0


def _unique(items):
    out = []
    for x in items:
        if x and x not in out:
            out.append(x)
    return out


def platform_of(f):
    """debian | rhel | linux | windows | ios | iosxe | nxos | iosxr | apic | esxi | other."""
    os_name = _text(f, "os").lower()
    family, name = _text(f, "plugin_family").lower(), _text(f, "plugin_name").lower()
    for text in (os_name, f"{family} {name}" if family in ("cisco", "vmware esx local security checks") or "cisco" in name else ""):
        if not text:
            continue
        if "apic" in text or "application policy infrastructure controller" in text:
            return "apic"
        if "esxi" in text or "vmware esx" in text:
            return "esxi"
        if re.search(r"ios[ -]?xr", text):
            return "iosxr"
        if re.search(r"nx-?os|nexus", text):
            return "nxos"
        if re.search(r"ios[ -]?xe", text):
            return "iosxe"
        if "cisco" in text and "ios" in text:
            return "ios"
    if "windows" in os_name:
        return "windows"
    if re.search(r"ubuntu|debian", os_name):
        return "debian"
    if re.search(r"red hat|rhel|centos|rocky|alma|oracle linux|fedora|scientific linux|amazon linux", os_name):
        return "rhel"
    if re.search(r"ubuntu|debian", family) and "local security checks" in family:
        return "debian"
    if re.search(r"red hat|centos|rocky|alma|oracle linux|fedora|scientific|amazon linux", family) and "local security checks" in family:
        return "rhel"
    if family.startswith("windows"):
        return "windows"
    if "linux" in os_name:
        return "linux"
    if re.search(r"SSH-[12]\.\d+-Cisco", _text(f, "output")):
        return "ios"
    return "other"


def _rhel_pm(f):
    """yum on release 7 and older, dnf after."""
    m = re.search(r"(?:red hat enterprise linux|rhel|centos(?: linux)?|oracle linux|scientific linux)\D{0,12}(\d+)",
                  _text(f, "os").lower()) or re.search(r"\b(?:RHEL|CentOS|OracleLinux|Oracle Linux)\s*(\d+)\b", _text(f, "plugin_name"))
    return "yum" if m and int(m.group(1)) <= 7 else "dnf"


def _step(pid, where, text, commands=()):
    return {"platform": PLATFORMS.get(pid, pid), "where": where, "text": text, "commands": [c for c in commands if c]}


def _on(pid, ip):
    host = ip or "the host"
    if pid in LINUX:
        return f"On {host} (SSH, an account with sudo)"
    if pid == "windows":
        return f"On {host} (PowerShell as administrator)"
    if pid in CISCO:
        return f"On the device {host} (network team)"
    if pid == "apic":
        return f"APIC GUI of the fabric of {host} (network team, admin)"
    return f"On {host}"


BASTION = "From the bastion"


# ---------------------------------------------------------------- 1. packages of a local security check
PKG_PAIRS = (re.compile(r"Remote package installed\s*:\s*(\S+)\s*\n\s*-?\s*Should be\s*:\s*(\S+)", re.I),
             re.compile(r"Installed package\s*:\s*(\S+)\s*\n\s*-?\s*Fixed package\s*:\s*(\S+)", re.I))


def split_package(token, deb):
    """("openssl", "1.1.1f-1ubuntu2.20") of a deb "name_version" or an rpm "name-version-release[.arch]"."""
    token = token.strip()
    if deb and "_" in token:
        name, version = token.split("_", 1)
        return name, ARCH.sub("", version)
    token = ARCH.sub("", token)
    parts = token.split("-")
    if len(parts) >= 3:
        return "-".join(parts[:-2]), "-".join(parts[-2:])
    return token, ""


def packages(f, deb):
    """[{"name", "installed_name", "installed", "fixed"}] of the output, safe names and versions only."""
    out = []
    for pattern in PKG_PAIRS:
        for inst, fixed in pattern.findall(_text(f, "output")):
            iname, iver = split_package(inst, deb)
            fname, fver = split_package(fixed, deb)
            if SAFE_PKG.match(iname) and SAFE_PKG.match(fname) and (not iver or SAFE_VER.match(iver)) and SAFE_VER.match(fver or "x"):
                if not any(p["name"] == fname for p in out):
                    out.append({"name": fname, "installed_name": iname, "installed": iver, "fixed": fver})
    return out


def _is_local_check(f):
    family = _text(f, "plugin_family")
    return bool(re.search(r"Local Security Checks", family, re.I)) and not family.lower().startswith(("windows", "vmware"))


def rule_packages(f, pid, ip):
    deb = pid == "debian" or bool(re.search(r"ubuntu|debian", _text(f, "plugin_family"), re.I))
    pid = pid if pid in LINUX else ("debian" if deb else "rhel")
    pkgs = packages(f, deb)
    kernel = [p for p in pkgs if KERNEL.match(p["name"]) or KERNEL.match(p["installed_name"])]
    m = ADVISORY.search(_text(f, "plugin_name"))
    advisory = m.group(1) if m else ""
    where = _on(pid, ip)
    names = [p["name"] for p in pkgs]
    steps, notes = [], []
    if not pkgs:
        steps.append(_step(pid, where, "Tenable listed no package versions: update the packages of the advisory, then check what is left.",
                           ["sudo apt-get update", "apt list --upgradable"] if deb else [f"sudo {_rhel_pm(f)} check-update"]))
    elif deb:
        same = [p["name"] for p in pkgs if p["name"] == p["installed_name"]]
        renamed = [p["name"] for p in pkgs if p["name"] != p["installed_name"]]
        steps.append(_step(pid, where, "Check what is installed now (read-only).",
                           [f"apt-cache policy {' '.join(_unique(p['installed_name'] for p in pkgs))}"]))
        text = f"Update {_count(len(pkgs), 'package')} to the fixed version or later; nothing else is removed or changed."
        if renamed:
            text += (" A new kernel comes as a package with a new name (its ABI): it is installed next to the running one, which "
                     "stays until the reboot.")
        steps.append(_step(pid, where, text, ["sudo apt-get update",
                                              f"sudo apt-get install --only-upgrade {' '.join(same)}" if same else "",
                                              f"sudo apt-get install {' '.join(renamed)}" if renamed else ""]))
    else:
        pm = _rhel_pm(f)
        steps.append(_step(pid, where, "Check what is installed now (read-only).",
                           [f"rpm -q {' '.join(_unique(p['installed_name'] for p in pkgs))}"]))
        steps.append(_step(pid, where, f"Update {_count(len(pkgs), 'package')} to the fixed version or later (the newest of the "
                                       "repository); a new kernel is installed next to the running one.",
                           [f"sudo {pm} update {' '.join(names)}"]))
    if kernel:
        steps.append(_step(pid, where, "Reboot for the new kernel, in the window and one node at a time: on a pair (keepalived, "
                                       "HAProxy) the node WITHOUT the virtual IP first, the other one only when the first is back "
                                       "and its services run. After the reboot the running kernel is the new one.",
                           ["cat /var/run/reboot-required /var/run/reboot-required.pkgs 2>/dev/null" if deb else "sudo needs-restarting -r",
                            "ip -brief address", "sudo reboot", "uname -r"]))
        notes.append("Kernel update: the finding stays open until the host runs the new kernel (reboot).")
    elif pkgs:
        steps.append(_step(pid, where, "Restart the services that still use the old libraries (no reboot needed for these packages).",
                           ["sudo needrestart -r l" if deb else "sudo needs-restarting -s"]))
    fixed_version = "; ".join(f"{p['name']} {p['fixed']}" for p in pkgs[:3]) + (" …" if len(pkgs) > 3 else "")
    fix = (f"Update {', '.join(names[:4])}{' …' if len(names) > 4 else ''}" if pkgs else "Update the packages of the advisory")
    return {"kind": "packages", "platform": pid,
            "title": (f"Update {_count(len(pkgs), 'package')}" if pkgs else "Update the packages of the advisory")
                     + (f" ({advisory})" if advisory else "") + (" and reboot" if kernel else ""),
            "versions": [{"item": p["name"], "installed": p["installed"], "fixed": p["fixed"]} for p in pkgs],
            "steps": steps, "notes": notes,
            "fixed_version": fixed_version, "fix": fix + ("; reboot" if kernel else "")}


def _count(n, word):
    return f"{n} {word}{'' if n == 1 else 's'}"


# ---------------------------------------------------------------- 2. Windows updates
def kbs_of(f):
    text = f"{_text(f, 'plugin_name')}\n{_text(f, 'output')}"
    found = re.findall(r"\bKB\s?(\d{6,7})\b", text)
    listed = re.search(r"following (?:rollup )?KBs?\s*:\s*\n((?:\s*-\s*(?:KB)?\d{6,7}\s*\n?)+)", text, re.I)
    if listed:
        found += re.findall(r"(\d{6,7})", listed.group(1))
    return _unique(f"KB{k}" for k in found)


def rule_windows(f, pid, ip):
    kbs = kbs_of(f)
    files = re.findall(r"(?:-\s*)?(\S[^\n]*?)\s+has not been patched\.\s*\n\s*Remote version\s*:\s*(\S+)\s*\n\s*Should be\s*:\s*(\S+)",
                       _text(f, "output"))
    versions = [{"item": path.strip(), "installed": inst, "fixed": fixed} for path, inst, fixed in files
                if SAFE_PATH.match(path.strip()) and SAFE_VER.match(inst) and SAFE_VER.match(fixed)]
    if not versions:
        versions = [{"item": kb, "installed": "missing", "fixed": "installed"} for kb in kbs]
    where = _on("windows", ip)
    ids = ", ".join(kbs)
    steps = [_step("windows", where, "Check the updates installed now (read-only).",
                   [f"Get-HotFix -Id {ids} -ErrorAction SilentlyContinue" if kbs else "",
                    "Get-CimInstance Win32_QuickFixEngineering | Sort-Object InstalledOn -Descending | Select-Object -First 5 HotFixID, InstalledOn"]),
             _step("windows", where, (f"Install {ids or 'the missing update'} with WSUS or Windows Update (Settings → Windows Update → "
                                      "Check for updates). A server without either: download the .msu of the KB from the Microsoft "
                                      "Update Catalog and install it with wusa.exe <file>.msu /quiet /norestart. A rollup KB "
                                      "replaces the older ones: the newest cumulative update is enough.")),
             _step("windows", where, "Reboot in the window (a DNS or domain controller: only while the other one is up), then check that "
                                     "the update is there.",
                   ["(New-Object -ComObject Microsoft.Update.SystemInfo).RebootRequired", "Restart-Computer",
                    f"Get-HotFix -Id {ids}" if kbs else ""])]
    return {"kind": "windows-update", "platform": "windows", "title": f"Install {ids or 'the missing Windows update'} and reboot",
            "versions": versions, "steps": steps, "notes": ["The finding closes after the reboot that completes the update."],
            "fixed_version": ids or (versions[0]["fixed"] if versions else ""), "fix": f"Install {ids or 'the Windows update'}; reboot"}


# ---------------------------------------------------------------- 3. Cisco advisories
WEBUI_CVES = {"CVE-2023-20198", "CVE-2023-20273"}


def _field(output, *labels):
    for lab in labels:
        m = re.search(rf"^\s*{lab}\s*:\s*(.+?)\s*$", output, re.I | re.M)
        if m:
            return m.group(1).strip()
    return ""


def rule_cisco(f, pid, ip):
    out = _text(f, "output")
    pid = pid if pid in CISCO + ("apic",) else ("iosxe" if "IOS XE" in _text(f, "plugin_name") else "ios")
    product = _field(out, "Product") or PLATFORMS[pid] + (" Software" if pid in CISCO else "")
    installed = _field(out, r"Installed release", r"Installed version", r"Cisco IOS XE Software release", r"Version")
    fixed = _field(out, r"Fixed release", r"Fixed version")
    installed = installed if SAFE_VER.match(installed or "") else ""
    fixed = fixed if SAFE_VER.match((fixed or "").replace(" ", "")) else ""
    bugs = _unique(re.findall(r"\bCSC[a-z]{2}\d{5}\b", f"{out}\n{_text(f, 'solution')}"))
    advisory = next((m for m in ADVISORY.findall(" ".join([_text(f, "plugin_name"), *(f.get("see_also") or [])]))
                     if m.startswith("cisco-sa-")), "")
    where = _on(pid, ip)
    check = {"iosxe": ["show version | include Cisco IOS XE Software|Version", "show install summary"],
             "ios": ["show version | include IOS|Version|System image"], "nxos": ["show version | include NXOS|system:"],
             "iosxr": ["show version | include Version"], "apic": ["show version"]}[pid]
    steps = [_step(pid, where, "Check the release that runs now (read-only).", check)]
    if pid == "apic":
        steps.append(_step(pid, "Network team with Cisco TAC", f"Upgrade the APIC cluster{f' to {fixed} or later' if fixed else ''}: "
                                                                "the APICs first, then the leaf and spine switches as TAC advises; window, owner approval."))
    else:
        steps.append(_step(pid, "Network team", f"Upgrade {product}{f' from {installed}' if installed else ''}"
                                                f"{f' to {fixed} or later' if fixed else ' to a fixed release of the advisory'} (the fixed "
                                                "release of this train in the Cisco advisory), with the image from Cisco Software Download: "
                                                "window, owner approval, the configuration saved first."))
    cves = set(str(c) for c in (f.get("cves") or []))
    if pid in ("ios", "iosxe") and (cves & WEBUI_CVES or re.search(r"Web UI|HTTP Server", _text(f, "plugin_name"), re.I)):
        steps.insert(1, _step(pid, where, "Now, before the upgrade (and it stays so after): turn the web server off, then look for "
                                          "accounts nobody made (e.g. cisco_tac_admin, cisco_support) and configuration changes by an "
                                          "unknown web user. Found: isolate the device, open a TAC case and a security incident.",
                              ["show running-config | include ^restconf|^ip http", "configure terminal", " no ip http server",
                               " no ip http secure-server", "end", "write memory", "show running-config | include ^username",
                               "show logging | include WEBUI|%SYS-5-CONFIG_P|%SEC_LOGIN-5-WEBLOGIN"]))
    steps.append(_step(pid, where, "After the upgrade: the new release runs.", [check[0]]))
    notes = [f"Cisco bug ID{'s' if len(bugs) > 1 else ''}: {', '.join(bugs)}."] if bugs else []
    return {"kind": "cisco-advisory", "platform": pid,
            "title": f"Upgrade {product}{f' to {fixed}' if fixed else ''}" + (f" ({advisory})" if advisory else ""),
            "versions": [{"item": product, "installed": installed, "fixed": fixed}] if installed or fixed else [],
            "steps": steps, "notes": notes, "fixed_version": fixed, "fix": f"Upgrade {product}{f' to {fixed}' if fixed else ''}"}


# ---------------------------------------------------------------- 4. SSH algorithms
def weak_ssh(output):
    """The weak algorithms Tenable names in its output, in its order."""
    return _unique(t for t in re.findall(r"[A-Za-z0-9][A-Za-z0-9@._-]*", output or "")
                   if WEAK_SSH.match(t) and SAFE_ALGO.match(t))


def _ssh_kind(f):
    name = _text(f, "plugin_name")
    return SSH_IDS.get(int(f.get("plugin_id") or 0)) or ("sshv1" if re.search(r"protocol version 1|SSHv1", name, re.I) else
                                                        "terrapin" if "Terrapin" in name else "weak")


def _ssh_check(algos, ip, port):
    """From the bastion: offer one removed algorithm of each kind; "no matching ... found" means it is gone."""
    if not ip:
        return []
    kinds = (("Ciphers", lambda a: re.search(r"cbc|arcfour|chacha20", a)), ("MACs", lambda a: a.startswith(("hmac-", "umac-"))),
             ("KexAlgorithms", lambda a: a.startswith(("diffie-hellman", "gss-", "rsa1024"))))
    out = []
    for option, test in kinds:
        algo = next((a for a in algos if test(a)), "")
        if algo:
            out.append(f"ssh -o {option}={algo} -p {port or 22} <account>@{ip}")
    return out


def rule_ssh(f, pid, ip):
    kind = _ssh_kind(f)
    algos = weak_ssh(_text(f, "output"))
    terrapin = kind == "terrapin" or "CVE-2023-48795" in (f.get("cves") or [])
    port = _port(f) or 22
    where = _on(pid, ip)
    named = f" Tenable found: {', '.join(algos)}." if algos else ""
    steps = []
    if pid in LINUX:
        deb = pid == "debian"
        steps.append(_step(pid, where, "Check what sshd offers now (read-only).",
                           ["sudo sshd -T | grep -E '^(ciphers|macs|kexalgorithms|hostkeyalgorithms) '",
                            "grep -E '^[[:space:]]*Include' /etc/ssh/sshd_config"]))
        if terrapin:
            steps.append(_step(pid, where, "Update OpenSSH: 9.6 and later (and the patched distribution packages) support strict key "
                                           "exchange, the Terrapin countermeasure"
                                           + ("." if pid != "linux" else ": update openssh-server with the package manager of the host."),
                               ["sudo apt-get update", "sudo apt-get install --only-upgrade openssh-server openssh-client"] if deb else
                               [f"sudo {_rhel_pm(f)} update openssh-server openssh-clients"] if pid == "rhel" else []))
        steps.append(_step(pid, where, "Offer only strong algorithms with a drop-in file, read before the main file (the first value "
                                       f"wins); host keys are not touched.{named} sshd -t tests it before the reload. If the second "
                                       "command above shows no Include of sshd_config.d, put the three lines at the top of "
                                       "/etc/ssh/sshd_config instead.",
                           ["sudo tee /etc/ssh/sshd_config.d/50-strong-algorithms.conf >/dev/null <<'EOF'", f"Ciphers {SSH_CIPHERS}",
                            f"MACs {SSH_MACS}", f"KexAlgorithms {SSH_KEX}", "EOF",
                            "sudo sshd -t && (sudo systemctl reload ssh 2>/dev/null || sudo systemctl reload sshd)"]))
        if pid == "rhel":
            steps[-1]["text"] += " RHEL 8/9: the system crypto policy (update-crypto-policies --show) also sets these lists."
    elif pid == "windows":
        steps.append(_step(pid, where, f"OpenSSH Server of Windows: set the lists in its configuration, then restart it.{named}",
                           [r"notepad C:\ProgramData\ssh\sshd_config", "# lines to add at the top:", f"# Ciphers {SSH_CIPHERS}",
                            f"# MACs {SSH_MACS}", f"# KexAlgorithms {SSH_KEX}", "Restart-Service sshd"]))
    elif pid in ("ios", "iosxe"):
        enc = "aes256-gcm aes128-gcm aes256-ctr aes192-ctr aes128-ctr" if pid == "iosxe" else "aes256-ctr aes192-ctr aes128-ctr"
        cmds = ["show ip ssh", "configure terminal"]
        if kind == "sshv1":
            cmds += [" crypto key generate rsa general-keys modulus 2048", " ip ssh version 2", " ip ssh dh min size 2048"]
        cmds += [f" ip ssh server algorithm encryption {enc}", " ip ssh server algorithm mac hmac-sha2-512 hmac-sha2-256",
                 " ip ssh server algorithm kex ecdh-sha2-nistp521 ecdh-sha2-nistp384 ecdh-sha2-nistp256 diffie-hellman-group16-sha512",
                 "end", "write memory"]
        steps.append(_step(pid, where, ("SSH version 2 only with a 2048-bit RSA key, and " if kind == "sshv1" else "")
                           + f"only strong SSH algorithms.{named} First check what the release accepts (configure terminal, then "
                             "ip ssh server algorithm ?) and list only names it shows; if the command does not exist the release is "
                             "too old and only an upgrade closes this (until then: a vty access-class limited to the management "
                             "networks). Keep this session open until a new SSH login works.", cmds))
    elif pid == "nxos":
        steps.append(_step(pid, where, f"Only strong SSH algorithms.{named} The commands differ per NX-OS release: check ssh ? first. "
                                       "A release that only knows all / cipher-mode weak: no ssh cipher-mode weak, no ssh kexalgos all, "
                                       "no ssh macs all; what is left needs an NX-OS upgrade (the release of Cisco's advisory).",
                           ["show ssh server", "configure terminal", " ssh ciphers aes256-gcm@openssh.com aes128-gcm@openssh.com aes256-ctr aes128-ctr",
                            " ssh macs hmac-sha2-512 hmac-sha2-256",
                            " ssh kexalgos curve25519-sha256 ecdh-sha2-nistp256 ecdh-sha2-nistp384 ecdh-sha2-nistp521 "
                            "diffie-hellman-group16-sha512 diffie-hellman-group14-sha256", "end", "copy running-config startup-config"]))
    elif pid == "iosxr":
        cmds = ["show ssh server", "configure", " ssh server v2",
                " ssh server algorithms key-exchange ecdh-sha2-nistp521 ecdh-sha2-nistp384 ecdh-sha2-nistp256",
                " ssh server algorithms cipher aes256-gcm@openssh.com aes128-gcm@openssh.com aes256-ctr aes192-ctr aes128-ctr",
                " commit", "end"]
        if "ssh-dss" in algos:
            cmds.append("crypto key zeroize dsa")
        steps.append(_step(pid, where, f"Only strong SSH algorithms.{named} Check first what the release offers (ssh server algorithms "
                                       "key-exchange ?); only SHA-1 names listed: the release is too old, upgrade. Add "
                                       "ssh server disable hmac hmac-sha1 only when show ssh server also lists hmac-sha2, else SSH stops.",
                           cmds))
    elif pid == "apic":
        steps.append(_step(pid, where, "Fabric > Fabric Policies > Policies > Pod > Management Access > the policy of the pod policy "
                                       f"group: SSH: untick {', '.join(algos) or 'the weak algorithms'}; keep ecdh-sha2-nistp256/384/521 "
                                       "(curve25519-sha256 if listed), hmac-sha2-256/512, aes128/192/256-ctr (aes-gcm if listed). "
                                       "Submit. The policy covers every APIC, leaf and spine of the fabric: window, then a new SSH "
                                       "login to one APIC and one leaf. An APIC release without the checkbox needs an upgrade (TAC)."))
    elif pid != "esxi":
        steps.append(_step(pid, where, f"Configure the SSH server (or its firmware) to offer only ciphers {SSH_CIPHERS}, MACs "
                                       f"{SSH_MACS} and key exchange {SSH_KEX}.{named} A device that cannot: upgrade its firmware."))
    steps.append(_step(pid, BASTION, "Check: a new SSH login works, and a removed algorithm is refused (no matching … found).",
                       _ssh_check(algos, ip, port)))
    title = {"sshv1": "SSH version 2 only", "terrapin": "Close Terrapin (CVE-2023-48795)"}.get(kind, "Remove weak SSH algorithms")
    return {"kind": "ssh", "platform": pid, "title": title, "versions": [], "steps": steps,
            "notes": ["Old clients that know only the removed algorithms can no longer log in: check the tools that use SSH "
                      "(monitoring, backups, Ansible, the portal) before the change."],
            "fixed_version": "", "fix": f"{title}: {', '.join(algos[:5])}{' …' if len(algos) > 5 else ''}" if algos else title}


# ---------------------------------------------------------------- 5. SSL / TLS
def _tls_kind(f):
    known = TLS_IDS.get(int(f.get("plugin_id") or 0))
    if known:
        return known
    name = _text(f, "plugin_name")
    if re.search(r"TLS Version 1\.0|TLSv1(\.0)?\b", name):
        return "tls10"
    if re.search(r"TLS Version 1\.1|TLSv1\.1", name):
        return "tls11"
    if re.search(r"SSL Version 2|SSL Version 3|SSLv[23]|Version 2 and 3", name):
        return "ssl"
    if re.search(r"Diffie-Hellman|Logjam", name, re.I):
        return "dh"
    if re.search(r"Cipher|SWEET32|RC4|3DES", name, re.I):
        return "cipher"
    return "cert"


def suites_of(output):
    return _unique(t for t in re.findall(r"\b[A-Z0-9]+(?:[-_][A-Z0-9]+){1,10}\b", output or "")
                   if WEAK_SUITE.search(t) and SAFE_SUITE.match(t) and not re.match(r"^(CVE|CSC|KB)", t)
                   and re.search(r"(SHA\d*|MD5)$|_WITH_", t))[:20]   # a suite name ends with its MAC (not 3DES-CBC of a table)


def rule_tls(f, pid, ip):
    kind = _tls_kind(f)
    port = _port(f) or 443
    out = _text(f, "output")
    where = _on(pid, ip)
    protocols = {"tls10": ["TLS 1.0"], "tls11": ["TLS 1.1"]}.get(kind) or (
        _unique(p for p, pat in (("SSL 2.0", r"SSLv2|SSL 2"), ("SSL 3.0", r"SSLv3|SSL 3")) if re.search(pat, out)) or ["SSL 2.0", "SSL 3.0"]
        if kind == "ssl" else [])
    flags = {"TLS 1.0": "-tls1", "TLS 1.1": "-tls1_1", "SSL 3.0": "-ssl3"}
    suites = suites_of(out) if kind == "cipher" else []
    key = re.search(r"(?:RSA )?Key Length\s*:\s*(\d{3,4})\s*bits", out, re.I)
    subject = re.search(r"Subject\s*:\s*([^\n]+)", out)
    versions = [{"item": p, "installed": "enabled", "fixed": "disabled (TLS 1.2 or later only)"} for p in protocols]
    if key and int(key.group(1)) < 2048:
        versions.append({"item": "Certificate RSA key", "installed": f"{key.group(1)} bits", "fixed": "2048 bits or more"})
    steps = []
    special = pid == "apic" and port in APIC_SERVICE_PORTS
    what = {"tls10": "Turn TLS 1.0 off", "tls11": "Turn TLS 1.1 off", "ssl": f"Turn {' and '.join(protocols)} off",
            "cipher": "Remove the weak cipher suites", "dh": "Use 2048-bit (or larger) Diffie-Hellman groups",
            "cert": "Replace the certificate"}[kind]
    named = f" Tenable found: {', '.join(suites)}." if suites else ""
    if special:
        steps.append(_step(pid, "Network team with Cisco TAC", f"Port {port} is a Cisco service of the APIC itself: the Management Access "
                                                               "policy does not reach it and there is no user setting. Open a TAC case "
                                                               "with this finding and ask for the APIC release that closes it. Until then "
                                                               "(window, owner approval: a wrong contract locks the fabric's management out): "
                                                               "an out-of-band contract on tenant mgmt > Node Management EPGs > Out-of-Band "
                                                               "EPG default that allows only 22/tcp and 443/tcp (and what monitoring needs) "
                                                               "from the management networks."))
    elif pid == "windows":
        if protocols:
            cmds = [f'reg export "HKLM\\{SCHANNEL}" C:\\Windows\\Temp\\schannel-before.reg /y']
            for p in protocols:
                cmds.append(f"$k = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey('{SCHANNEL}\\Protocols\\{p}\\Server'); "
                            "$k.SetValue('Enabled', 0, 'DWord'); $k.SetValue('DisabledByDefault', 1, 'DWord'); $k.Close()")
            steps.append(_step(pid, where, f"{what} in SCHANNEL (every Windows service: RDP, IIS, WinRM, LDAPS). Export the key first; "
                                           "make sure what connects (RDP clients, SQL Server, agents) speaks TLS 1.2.", cmds))
        elif kind == "cipher":
            steps.append(_step(pid, where, f"{what}: the cipher suites with 3DES / RC4 / DES, and the SCHANNEL ciphers.{named} "
                                           "(As windows-disable-3des.ps1 of the VA.)",
                               ["Get-TlsCipherSuite | Where-Object { $_.Name -match '3DES|RC4|_DES_' } | Select-Object Name",
                                f'reg export "HKLM\\{SCHANNEL}" C:\\Windows\\Temp\\schannel-before.reg /y',
                                "Get-TlsCipherSuite | Where-Object { $_.Name -match '3DES|RC4|_DES_' } | ForEach-Object { Disable-TlsCipherSuite -Name $_.Name }",
                                *(f"$k = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey('{SCHANNEL}\\Ciphers\\{c}'); "
                                  "$k.SetValue('Enabled', 0, 'DWord'); $k.Close()"
                                  for c in ("Triple DES 168", "RC4 128/128", "RC4 64/128", "RC4 56/128", "RC4 40/128"))]))
        else:
            steps.append(_step(pid, where, f"{what}: for RDP a certificate of the internal CA in the computer store (Remote Desktop "
                                           "certificate by group policy), for IIS the site binding; 2048-bit RSA or ECDSA, SHA-256, with "
                                           f"the host's name and {ip or 'address'} in subjectAltName."))
        if kind != "cert":
            steps.append(_step(pid, where, "Reboot in the window: SCHANNEL reads these keys at boot. Undo: reg import the exported file "
                                           "and reboot.", ["Restart-Computer"]))
    elif pid in ("ios", "iosxe"):
        if kind == "cert":
            steps.append(_step(pid, where, "The device's HTTPS server uses a self-signed or weak certificate. Nobody manages it by web: "
                                           "turn the web server off. Else a 2048-bit key and a certificate of the internal CA on the "
                                           "trustpoint of ip http secure-trustpoint.",
                               ["show running-config | include ^restconf|^ip http", "configure terminal", " no ip http server",
                                " no ip http secure-server", "end", "write memory"]))
        else:
            steps.append(_step(pid, where, f"{what} of the device's web server.{named} Nobody manages it by web (show running-config shows "
                                           "no restconf): turn it off. Else keep HTTPS with TLS 1.2 and strong suites only (needs a "
                                           "2048-bit key; IOS 12.x cannot: keep it off).",
                               ["show running-config | include ^restconf|^ip http", "configure terminal", " no ip http server",
                                " no ip http secure-server", "end", "write memory",
                                "! only if HTTPS is really needed, instead of no ip http secure-server:",
                                "!  ip http tls-version TLSv1.2", "!  ip http secure-ciphersuite ecdhe-rsa-aes-gcm-sha2 ecdhe-rsa-aes-cbc-sha2"]))
    elif pid == "nxos":
        steps.append(_step(pid, where, f"{what} of NX-API (the HTTPS server of NX-OS).{named} Not used: turn NX-API off; else TLS 1.2 "
                                       "only and no weak suites.",
                           ["show feature | include nxapi", "configure terminal", " no feature nxapi", "end",
                            "! only if NX-API is used, instead of no feature nxapi:", "!  nxapi ssl protocols TLSv1.2",
                            "!  no nxapi ssl ciphers weak", "copy running-config startup-config"]))
    elif pid == "apic":
        steps.append(_step(pid, where, f"{what}: Fabric > Fabric Policies > Policies > Pod > Management Access > the policy of the pod "
                                       "policy group: HTTPS: SSL Protocols TLSv1.2 (and TLSv1.3 if listed) only, DH Param 2048 or "
                                       "4096" + ("; a certificate of the internal CA as Admin KeyRing" if kind == "cert" else "")
                                       + ". The policy covers every APIC, leaf and spine: window, then the APIC GUI and the portal's "
                                         "ACI pages must still load."))
    elif pid in LINUX:
        steps.append(_step(pid, where, f"Find the service that answers on port {port}.",
                           [f"sudo ss -ltnp 'sport = :{port}'"]))
        if kind == "cert":
            name = _text(f, "hostname") if SAFE_PKG.match(_text(f, "hostname")) else (ip or "host")
            san = f"IP:{ip}" + (f",DNS:{name}" if name != ip and name != "host" else "")
            steps.append(_step(pid, where, f"{what}: a certificate of the internal CA (or a public one), 2048-bit RSA or ECDSA, SHA-256, "
                                           "with the address in subjectAltName; make a key and a request, have it signed, then point the "
                                           "service at the new files (nginx ssl_certificate, Apache SSLCertificateFile) and reload it.",
                               [f'openssl req -new -newkey rsa:2048 -nodes -keyout {name}.key -out {name}.csr -subj "/CN={name}" '
                                f'-addext "subjectAltName = {san}"']))
        else:
            protos = "TLSv1.2 TLSv1.3"
            steps.append(_step(pid, where, f"{what} in the service found above.{named} nginx (in its server or http block):",
                               [f"ssl_protocols {protos};", "ssl_ciphers HIGH:!aNULL:!MD5:!3DES:!RC4:!DES;", "ssl_prefer_server_ciphers on;",
                                "sudo nginx -t && sudo systemctl reload nginx"]))
            steps.append(_step(pid, where, "Apache httpd (ssl.conf or the virtual host):",
                               ["SSLProtocol -all +TLSv1.2 +TLSv1.3", "SSLCipherSuite HIGH:!aNULL:!MD5:!3DES:!RC4:!DES", "SSLHonorCipherOrder on",
                                f"sudo apachectl configtest && sudo systemctl reload {'apache2' if pid == 'debian' else 'httpd'}"]))
            steps.append(_step(pid, where, "Another service (a Java application, a BMC, an appliance): its own TLS settings, or a "
                                           "firmware / version that has TLS 1.2 only."))
    elif pid != "esxi":
        steps.append(_step(pid, where, f"{what} on port {port}.{named} The web interface of the device (or its firmware): TLS 1.2 or "
                                       "later only, strong suites, a 2048-bit certificate of the internal CA. A device that cannot: "
                                       "upgrade the firmware, or limit the port to the management networks."))
    check = []
    if ip and not special:
        if protocols:
            check = [f"openssl s_client -connect {ip}:{port} {flags[p]} </dev/null" for p in protocols if p in flags]
        elif kind == "cipher" and suites:
            check = [f"openssl s_client -connect {ip}:{port} -cipher '{suites[0]}:@SECLEVEL=0' </dev/null"]
        else:
            check = [f"openssl s_client -connect {ip}:{port} </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -enddate -text "
                     "| grep -E 'Subject:|Issuer:|Not After|Public-Key|Signature Algorithm' | sort -u"]
    steps.append(_step(pid, BASTION, "Check: the handshake with what was removed fails (or the new certificate is served)."
                       + (" OpenSSL of the bastion may lack the old protocol: then only Verify fix tells." if protocols else ""), check))
    return {"kind": "tls", "platform": pid, "title": what + (f" on port {port}" if port else ""), "versions": versions, "steps": steps,
            "notes": [f"Certificate: {subject.group(1).strip()[:120]}"] if subject and kind == "cert" else [],
            "fixed_version": "TLS 1.2 or later" if protocols else ("2048-bit certificate" if kind == "cert" else ""),
            "fix": what + (f": {', '.join(suites[:3])}" if suites else "")}


# ---------------------------------------------------------------- 6. cleartext services (Telnet, HTTP, FTP)
def _cleartext_kind(f):
    known = CLEARTEXT_IDS.get(int(f.get("plugin_id") or 0))
    if known:
        return known
    name, port, service = _text(f, "plugin_name"), _port(f), _text(f, "service").lower()
    if "telnet" in name.lower() or port == 23 or service == "telnet":
        return "telnet"
    if re.search(r"\bFTP\b", name) or port == 21 or service == "ftp":
        return "ftp"
    return "http"


def rule_cleartext(f, pid, ip):
    kind = _cleartext_kind(f)
    port = _port(f) or {"telnet": 23, "ftp": 21, "http": 80}[kind]
    where = _on(pid, ip)
    label = {"telnet": "Telnet", "ftp": "FTP", "http": "HTTP (web management)"}[kind]
    steps = []
    if pid in ("ios", "iosxe"):
        if kind == "telnet":
            steps.append(_step(pid, where, "SSH only on every vty line, and only AFTER a new SSH login from the bastion works (a device "
                                           "without SSH: enable SSH first, through this Telnet session). Set every vty range that "
                                           "show running-config lists.",
                               ["show ip ssh", "show running-config | section ^line vty", "configure terminal", " line vty 0 4",
                                "  transport input ssh", " line vty 5 15", "  transport input ssh", "end", "write memory"]))
        else:
            steps.append(_step(pid, where, "Turn the plain-text web server off (and HTTPS too when nobody manages the device by web; "
                                           "RESTCONF needs HTTPS).",
                               ["show running-config | include ^restconf|^ip http", "configure terminal", " no ip http server", "end",
                                "write memory"]))
    elif pid == "nxos":
        steps.append(_step(pid, where, f"Turn {label} off.",
                           ["configure terminal", " no feature telnet" if kind == "telnet" else " no nxapi http", "end",
                            "copy running-config startup-config"]))
    elif pid == "iosxr":
        steps.append(_step(pid, where, f"Turn {label} off: one line per vrf that show running-config lists.",
                           ["show running-config | include ^telnet|^http", "configure",
                            " no telnet vrf default ipv4 server" if kind == "telnet" else " no http client vrf default", " commit", "end"]))
    elif pid == "apic":
        steps.append(_step(pid, where, f"Fabric > Fabric Policies > Policies > Pod > Management Access > the policy of the pod policy group: "
                                       f"{'Telnet' if kind == 'telnet' else 'HTTP'}: Admin State Disabled. The policy covers every APIC, "
                                       "leaf and spine of the fabric: window."))
    elif pid in LINUX:
        if kind == "http":
            steps.append(_step(pid, where, f"Find the service on port {port}, then serve it over HTTPS only (a redirect, or turn the plain "
                                           "listener off) or stop it if nobody needs it.", [f"sudo ss -ltnp 'sport = :{port}'"]))
        else:
            unit = "telnet.socket" if kind == "telnet" else "<the ftp service the first command shows, e.g. vsftpd>"
            steps.append(_step(pid, where, f"Find what serves {label} on port {port} and turn it off (use SSH / SFTP instead).",
                               [f"sudo ss -ltnp 'sport = :{port}'", f"systemctl list-units --all | grep -Ei '{kind}'",
                                f"sudo systemctl disable --now {unit}"]))
    elif pid == "windows":
        service = {"telnet": "TlntSvr", "ftp": "ftpsvc", "http": ""}[kind]
        steps.append(_step(pid, where, f"Turn {label} off" + (" (IIS: remove the http binding of the site, keep https)" if kind == "http" else "")
                           + ".", [f"Stop-Service {service}", f"Set-Service {service} -StartupType Disabled"] if service
                           else [f"Get-NetTCPConnection -LocalPort {port} -State Listen | Select-Object OwningProcess"]))
    elif pid != "esxi":
        steps.append(_step(pid, where, f"Turn {label} off in the device's management settings (or its firmware); manage it over "
                                       f"{'SSH' if kind == 'telnet' else 'HTTPS' if kind == 'http' else 'SFTP'} only."))
    steps.append(_step(pid, BASTION, f"Check: port {port} no longer answers.",
                       [f"timeout 5 bash -c '</dev/tcp/{ip}/{port}' && echo still open || echo closed"] if ip else []))
    return {"kind": "cleartext", "platform": pid, "title": f"Turn {label} off", "versions": [], "steps": steps,
            "notes": ["Passwords sent over it can be read on the network: change the passwords used on it after the change."]
            if kind in ("telnet", "ftp") else [], "fixed_version": "", "fix": f"Turn {label} off (port {port})"}


# ---------------------------------------------------------------- 7. "Installed version / Fixed version"
def _product(name):
    m = re.match(r"^(.*?)\s+(?:<|<=|>=|=|\d[\w.]*\.x\b|\d+\.\d+)", name)
    product = (m.group(1) if m else name).strip(" :-")
    return product or name


def rule_version(f, pid, ip):
    out = _text(f, "output")
    installed = _field(out, r"Installed version")
    fixed = _field(out, r"Fixed version")
    installed = installed if SAFE_VER.match(installed.replace(" ", "")) else ""
    fixed = fixed if SAFE_VER.match(fixed.replace(" ", "")) else ""
    path = _field(out, r"Path", r"Installed path", r"URL")
    path = path if SAFE_PATH.match(path) else ""
    product = _product(_text(f, "plugin_name"))
    where = _on(pid, ip)
    steps = []
    if path and path.startswith("/") and pid in LINUX:
        steps.append(_step(pid, where, "Which package installed it (read-only).",
                           [f"dpkg -S '{path}'" if pid == "debian" else f"rpm -qf '{path}'" if pid == "rhel" else f"ls -l '{path}'"]))
    elif path and pid == "windows" and re.match(r"^[A-Za-z]:\\", path):
        steps.append(_step(pid, where, "The version installed there (read-only).",
                           [f"Get-Item '{path}' | Select-Object -ExpandProperty VersionInfo"]))
    steps.append(_step(pid, where, f"Upgrade {product}{f' from {installed}' if installed else ''}{f' to {fixed} or later' if fixed else ''}: "
                                   "with the package manager when it came from a package, else the vendor's release (an appliance "
                                   "or a BMC: its firmware)."))
    notes = []
    if pid in LINUX:
        notes.append("A distribution package may carry the fix with an older version number (backport): check the advisory of the "
                     "distribution before an upgrade outside it; Tenable reads the version the service shows.")
    return {"kind": "version", "platform": pid, "title": f"Upgrade {product}{f' to {fixed}' if fixed else ''}",
            "versions": [{"item": product + (f" ({path})" if path else ""), "installed": installed, "fixed": fixed}],
            "steps": steps, "notes": notes, "fixed_version": fixed, "fix": f"Upgrade {product}{f' to {fixed}' if fixed else ''}"}


# ---------------------------------------------------------------- 8. Tenable's own solution
def rule_fallback(f, pid, ip):
    solution = _text(f, "solution").strip()
    return {"kind": "generic", "platform": pid, "title": _first_sentence(solution) or "See the links of the plugin",
            "versions": [], "steps": [_step(pid, _on(pid, ip), solution or "Tenable gives no solution for this plugin: see its links.")],
            "notes": [], "fixed_version": "", "fix": _first_sentence(solution)[:160]}


def _first_sentence(text):
    text = " ".join(str(text or "").split())
    m = re.match(r"^(.{10,200}?[.!])(\s|$)", text)
    return (m.group(1) if m else text[:200]).strip()


# ---------------------------------------------------------------- the plan
def _ssh_match(f):
    name = _text(f, "plugin_name")
    return int(f.get("plugin_id") or 0) in SSH_IDS or (
        bool(re.search(r"\bSSH\b", name)) and bool(re.search(r"CBC|weak|MAC|key exchange|Terrapin|algorithm|protocol version 1|"
                                                             r"SHA-?1|Diffie-Hellman|cipher", name, re.I)))


def _tls_match(f):
    name = _text(f, "plugin_name")
    return int(f.get("plugin_id") or 0) in TLS_IDS or (bool(re.search(r"\b(SSL|TLS)\b", name)) and "SSH" not in name)


def _cleartext_match(f):
    name = _text(f, "plugin_name")
    return int(f.get("plugin_id") or 0) in CLEARTEXT_IDS or bool(
        re.search(r"Telnet|Unencrypted|Cleartext|Clear Text|Without HTTPS|Basic Authentication|\bFTP\b", name, re.I))


RULES = (
    (_is_local_check, rule_packages),
    (lambda f: _text(f, "plugin_family").lower().startswith("windows") and bool(kbs_of(f)), rule_windows),
    (lambda f: _text(f, "plugin_family").upper() == "CISCO", rule_cisco),
    (_ssh_match, rule_ssh),
    (_tls_match, rule_tls),
    (_cleartext_match, rule_cleartext),
    (lambda f: bool(re.search(r"Installed version\s*:", _text(f, "output"), re.I)) and bool(re.search(r"Fixed version\s*:", _text(f, "output"), re.I)),
     rule_version),
)


def _links(f):
    out = []
    for url in f.get("see_also") or []:
        url = str(url).strip()
        if re.match(r"^https?://[^\s<>\"']{4,300}$", url) and url not in out:
            out.append(url)
    plugin = int(f.get("plugin_id") or 0)
    if plugin:
        out.append(f"https://www.tenable.com/plugins/nessus/{plugin}")
    return out[:12]


def plan(f):
    """The fix plan of one finding (a row of findings.py with its full fields)."""
    f = dict(f or {})
    if isinstance(f.get("cves"), str):
        f["cves"] = [c for c in f["cves"].split(",") if c]
    pid = platform_of(f)
    ip = _ip(f)
    result = None
    for match, build in RULES:
        if match(f):
            result = build(f, pid, ip)
            break
    result = result or rule_fallback(f, pid, ip)
    pid = result.pop("platform")
    if pid == "esxi":   # VMware Cloud stays read-only: the VMware team patches it
        result["steps"] = [_step("esxi", "VMware team", "Not from this portal: ESXi (VMware Cloud) is patched by the VMware team with "
                                                        "vSphere Lifecycle Manager, in a window (host in maintenance mode, its VMs "
                                                        "moved away), following the VMware advisory in the links.")]
    exploit = f.get("exploit_available")
    why = " ".join(_text(f, "synopsis").split()) or _first_sentence(_text(f, "description"))
    if exploit:
        why += " An exploit is publicly available."
    result.update(platform={"id": pid, "label": PLATFORMS[pid]}, why=why, links=_links(f), tenable=_text(f, "solution").strip(),
                  facts={"has_patch": f.get("has_patch"), "patch_date": f.get("patch_date") or "", "exploit": exploit},
                  notes=list(result.get("notes") or []) + [NOTE_APPROVAL, NOTE_VERIFY])
    result["steps"] = [s for s in result["steps"] if s["text"] or s["commands"]]
    result["fixed_version"] = str(result.get("fixed_version") or "")[:200]
    result["fix"] = str(result.get("fix") or result["title"])[:200]
    return result

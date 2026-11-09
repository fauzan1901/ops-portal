"""What the Shell module can open, per site, and how the portal server reaches it (the ssh command line).

Targets (the browser only ever sends an id; addresses, accounts and secrets stay on the server):
    <site>:mgmt                 OpenStack management host (sites.yml mgmt: user, private_key file on this server)
    <site>:director             OpenStack director, reached FROM the management host with its own key (ssh -t, as the
                                checks do; overcloud nodes are reached from there with ssh tripleo-admin@<ctlplane>)
    <site>:ontap                ONTAP cluster management LIF, with the ONTAP Restore account of the site (ontap:<site>)
    <site>:apic                 APIC, with the APIC account of the site (apic:<site>)
    <site>:host:<id>            a host of Operation Automation -> Hosts & SSH, with its own credential, jump host or proxy
    <site>:group:<group>:<name> a member of a hosts group in sites.yml, with the group's read-only key
ESXi hosts (group esxi, VMware Cloud) are not listed and cannot be opened: VMware Cloud stays read-only from the portal.

A private key is written to a 0600 file in the session's own folder (removed when the session ends); a password goes
to sshpass through a pipe (sshpass -d), the password of a jump host through SSHPASS (sshpass -e in its ProxyCommand),
never on a command line. Test mode: sites.yml <site>.shell.test_command replaces ssh with a local program.
"""
import os
import re
import shlex

import sites
from core import PORTAL
from modules.wi import hosts as wi_hosts
from modules.wi import wi_analysis

SSH_OPTIONS = ["-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=30",
               "-o", "ServerAliveCountMax=4"]
PASSWORD_OPTIONS = ["-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password,keyboard-interactive",
                    "-o", "NumberOfPasswordPrompts=1"]
PASS_FD = "{pass_fd}"   # replaced by the session with the read end of the password pipe
CATEGORIES = {"openstack": "OpenStack", "ontap": "NetApp ONTAP", "apic": "Cisco ACI (APIC)"}
# Groups never opened from Shell: ESXi hosts belong to VMware Cloud, which stays read-only from the portal.
EXCLUDED_GROUPS = ("esxi",)
ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,40}:(mgmt|director|ontap|apic|host:\d{1,9}|group:[a-z0-9_-]{1,32}:[A-Za-z0-9_.-]{1,63})$")
SAFE = re.compile(r"^[A-Za-z0-9_.:@#\\-]+$")


def _host_port(value, default=22):
    """"172.26.8.190", "127.0.0.1:9451" (a REST port: SSH keeps 22) or "[fd00::1]" -> address."""
    text = str(value or "").strip()
    if text.startswith("["):
        return text[1:text.find("]")] if "]" in text else text, default
    return (text.rsplit(":", 1)[0] if text.count(":") == 1 else text), default


def category_label(category):
    return CATEGORIES.get(category) or wi_hosts.GROUPS.get(category, category)


def _public(site, kind, key, category, name, address, port=22, user="", auth="key", via="", source="sites.yml",
            privilege="none", become=False, problem=""):
    return {"id": f"{site}:{key}", "site": site, "kind": kind, "category": category, "category_label": category_label(category),
            "name": name, "address": address, "port": port, "user": user, "auth": auth, "via": via, "source": source,
            "privilege": privilege, "become": become, "problem": problem}


def site_targets(site):
    """Every target of a site, without any secret; "problem" says why one cannot be opened now."""
    cfg = sites.get(site)
    out = []
    mgmt, director = cfg.get("mgmt") or {}, cfg.get("director") or {}
    if mgmt.get("host"):
        out.append(_public(site, "mgmt", "mgmt", "openstack", "Management host", str(mgmt["host"]), int(mgmt.get("port") or 22),
                           str(mgmt.get("user") or ""), "key"))
        if director.get("host"):
            same = director["host"] == mgmt["host"]
            out.append(_public(site, "director", "director", "openstack", "Director", str(director["host"]),
                               int(director.get("port") or 22), str(director.get("user") or ""), "key",
                               via="" if same else f"Management host {mgmt['host']}"))
    for kind, key in (("ontap", "ontap"), ("apic", "apic")):
        host = (cfg.get(key) or {}).get("host")
        if not host:
            continue
        name = f"{kind}:{site}"
        account = ""
        problem = ""
        if PORTAL.credential_configured(name):
            try:
                account = PORTAL.credential(name)["username"]
            except Exception as e:   # unreadable: shown as the reason
                problem = str(e)
        else:
            problem = f"The {name} service account is not set (Administration → Credentials)."
        address, port = _host_port(host)
        out.append(_public(site, kind, kind, kind, "Cluster management" if kind == "ontap" else "APIC", address, port,
                           _apic_user(account) if kind == "apic" else account, "password", source="Credentials",
                           problem=problem))
    portal_rows = wi_hosts.hosts(site)
    portal_names = {(h["grp"], h["name"]) for h in portal_rows}
    for group, gcfg in (cfg.get("hosts") or {}).items():
        if group in EXCLUDED_GROUPS:
            continue
        gcfg = gcfg or {}
        members = gcfg.get("members") or {}
        if isinstance(members, list):
            members = {str(m.get("name")): str(m.get("host")) for m in members if isinstance(m, dict)}
        for name, address in sorted(members.items()):
            if (group, str(name)) in portal_names or not SAFE.match(str(address)) or not re.match(r"^[A-Za-z0-9_.-]{1,63}$", str(name)):
                continue
            problem = "" if gcfg.get("private_key") or _test_command(cfg) else "The group has no private_key in sites.yml."
            if gcfg.get("connection") == "local" and not _test_command(cfg):
                problem = "This group is read on the portal server itself (connection: local), not over SSH."
            out.append(_public(site, "group", f"group:{group}:{name}", group, str(name), str(address), int(gcfg.get("port") or 22),
                               str(gcfg.get("user") or ""), "key", via=_proxy_via(str(address)), problem=problem))
    for h in portal_rows:
        if h["grp"] in EXCLUDED_GROUPS:
            continue
        problem = "" if h["credential_id"] else "No SSH credential (Operation Automation → Hosts & SSH)."
        privilege = h["privilege"] or "none"
        become = privilege == "sudo" or (privilege == "sudo_password" and bool(h["fixes"]))
        via = f"Jump host {h['jump']}" if h["jump"] else "Web proxy" if h["proxy"] else ""
        out.append(_public(site, "host", f"host:{h['id']}", h["grp"], h["name"], h["address"], int(h["port"] or 22),
                           h["username"] or "", h["auth"] or "key", via=via, source="Hosts & SSH", privilege=privilege,
                           become=become, problem=problem))
    return out


def all_targets():
    out = []
    for site in sites.sites():
        try:
            out += site_targets(site)
        except ValueError:
            continue
    return out


def find(target_id):
    """The public target of an id (ValueError when the id is not valid or not known)."""
    target_id = str(target_id or "")
    if not ID_RE.match(target_id):
        raise ValueError("Unknown host")
    site = target_id.split(":", 1)[0]
    match = next((t for t in site_targets(site) if t["id"] == target_id), None)
    if not match:
        raise ValueError("Unknown host: it was removed or renamed. Reload the host list.")
    return match


def _apic_user(username):
    """APIC sign-in with a login domain: REST "apic:<domain>\\user", SSH "apic#<domain>\\user"."""
    return "apic#" + username[5:] if username.startswith("apic:") else username


def _proxy_via(address):
    return "Web proxy" if wi_hosts.ssh_proxy(address, resolve=False) else ""


def _test_command(cfg):
    return str((cfg.get("shell") or {}).get("test_command") or "")


def _route(address):
    """-o ProxyCommand through the web proxy for a public address (WI_SSH_PROXY), else nothing."""
    proxy = wi_hosts.ssh_proxy(address)
    return ["-o", "ProxyCommand=" + wi_analysis._via_proxy(proxy)] if proxy else []


def _write_key(folder, name, secret):
    path = os.path.join(folder, name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(secret.rstrip("\n") + "\n")   # OpenSSH refuses a key file without the last newline
    return path


def _login(user, address):
    if user and not SAFE.match(user):
        raise ValueError("The account name of this host is not valid for SSH")
    if not SAFE.match(address):
        raise ValueError("The address of this host is not valid")
    return f"{user}@{address}" if user else address


def connection(target, folder):
    """How to open the target: {"argv", "env", "password", "sudo_password", "sudo_user"}. folder: a private (0700)
    folder of the session for key files. "password" goes to sshpass through a pipe ({pass_fd} in argv); the sudo password
    answers only the prompt "[sudo] password for <sudo_user>:" after Become root."""
    site = target["site"]
    cfg = sites.get(site)
    if target["problem"]:
        raise ValueError(target["problem"])
    test = _test_command(cfg)
    if test:   # test mode: a local program instead of ssh (only the sudo password, for Become root)
        argv = shlex.split(test.replace("{name}", target["name"]).replace("{address}", target["address"])
                           .replace("{user}", target["user"] or "user").replace("{kind}", target["kind"]))
        out = {"argv": argv, "env": {}, "password": None, "sudo_password": None}
        if target["kind"] == "host" and target["privilege"] == "sudo_password" and target["become"]:
            out.update(sudo_password=_host_secret(target)["secret"], sudo_user=target["user"])
        return out
    kind, port = target["kind"], str(int(target["port"] or 22))
    if kind in ("mgmt", "director"):
        mgmt = cfg.get("mgmt") or {}
        if mgmt.get("connection") == "local":
            raise ValueError("The management host of this site is the portal server itself (connection: local)")
        argv = ["ssh", "-tt", "-p", str(int(mgmt.get("port") or 22)), *SSH_OPTIONS, *shlex.split(str(mgmt.get("ssh_args") or ""))]
        if mgmt.get("private_key"):
            argv += ["-i", str(mgmt["private_key"]), "-o", "IdentitiesOnly=yes"]
        argv += ["-o", "BatchMode=yes", *_route(str(mgmt["host"])), _login(str(mgmt.get("user") or ""), str(mgmt["host"]))]
        director = cfg.get("director") or {}
        if kind == "director" and director.get("host") != mgmt.get("host"):
            # The director trusts the key of the management host (the checks use the same hop).
            argv += ["--", "ssh", "-t", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=30",
                     "-p", str(int(director.get("port") or 22)), _login(str(director.get("user") or ""), str(director["host"]))]
        return {"argv": argv, "env": {}, "password": None, "sudo_password": None}
    if kind in ("ontap", "apic"):
        cred = PORTAL.credential(f"{kind}:{site}")
        user = _apic_user(cred["username"]) if kind == "apic" else cred["username"]
        # APIC only offers an ssh-rsa host key, which OpenSSH 8.8+ refuses by default ("no matching host key type found.
        # Their offer: ssh-rsa"): allowed for APIC only, after the stronger types.
        legacy = ["-o", "HostKeyAlgorithms=+ssh-rsa"] if kind == "apic" else []
        argv = ["sshpass", "-d", PASS_FD, "ssh", "-tt", "-p", port, *SSH_OPTIONS, *legacy, *PASSWORD_OPTIONS,
                *_route(target["address"]), _login(user, target["address"])]
        return {"argv": argv, "env": {}, "password": cred["password"], "sudo_password": None}
    if kind == "group":
        group = target["category"]
        gcfg = (cfg.get("hosts") or {}).get(group) or {}
        argv = ["ssh", "-tt", "-p", port, *SSH_OPTIONS, *shlex.split(str(gcfg.get("ssh_args") or "")),
                "-i", str(gcfg["private_key"]), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
                *_route(target["address"]), _login(target["user"], target["address"])]
        return {"argv": argv, "env": {}, "password": None, "sudo_password": None}
    # A host of Hosts & SSH: its own credential, its jump host or the web proxy.
    host_id = int(target["id"].rsplit(":", 1)[1])
    row = next((h for h in wi_hosts.hosts(site) if h["id"] == host_id), None)
    if not row:
        raise ValueError("Unknown host: it was removed. Reload the host list.")
    resolved = wi_hosts.target(site, [row["grp"]], row["name"]) or {}
    cred = _host_secret(target)
    env, password = {}, None
    argv = ["ssh", "-tt", "-p", port, *SSH_OPTIONS]
    if cred["auth"] == "password":
        argv = ["sshpass", "-d", PASS_FD, *argv, *PASSWORD_OPTIONS]
        password = cred["secret"]
    else:
        argv += ["-i", _write_key(folder, "id_host", cred["secret"]), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes"]
    jump = resolved.get("jump")
    if jump:
        if not jump.get("credential_id"):
            raise ValueError(f"The jump host {jump['name']} has no SSH credential: give it one on Hosts & SSH.")
        jcred = wi_hosts.secret_of(PORTAL.vault, jump["credential_id"])
        keyfile = ""
        if jcred["auth"] == "password":
            env["SSHPASS"] = jcred["secret"]
        else:
            keyfile = _write_key(folder, "id_jump", jcred["secret"])
        argv += shlex.split(wi_analysis.ssh_proxy_args(jump, keyfile))
    else:
        argv += _route(target["address"])
    argv.append(_login(cred["username"], target["address"]))
    sudo_password = cred["secret"] if cred["privilege"] == "sudo_password" and target["become"] else None
    return {"argv": argv, "env": env, "password": password, "sudo_password": sudo_password, "sudo_user": cred["username"]}


def _host_secret(target):
    host_id = int(target["id"].rsplit(":", 1)[1])
    row = next((h for h in wi_hosts.hosts(target["site"]) if h["id"] == host_id), None)
    if not row or not row["credential_id"]:
        raise ValueError(f"{target['name']} has no SSH credential: give it one on Hosts & SSH.")
    return wi_hosts.secret_of(PORTAL.vault, row["credential_id"])


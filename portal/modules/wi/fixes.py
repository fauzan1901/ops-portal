"""Fixes run from a check result (actions): may this fix run, for this user, on this host, now — and how.

A fix is the `action` of one recommendation of a stored run: the exact commands the analysis generated from what it
read (never text from the browser). It runs only:
  - for an administrator, or an operator with the permission "wi-fix" (SSH hosts, ONTAP) or "wi-fix-openstack"
    (OpenStack of Acme Flex) on the Users page;
  - on a host of the page Hosts & SSH whose SSH credential allows fixes (sites.yml hosts stay read-only), on ONTAP
    with the ONTAP Restore account of the site (ontap:<site>), or on OpenStack through the director of the site as
    admin (overcloudrc; only the changes of wi_analysis.OPENSTACK_FIX);
  - from a recent result (WI_FIX_MAX_AGE_MINUTES, default 120): values found long ago may no longer be true;
  - for a high-risk fix (deletes, kills, restarts, reboots, formats, network device commits), after the operator typed
    the host name, or for OpenStack the ID or name of what is deleted;
  - for a fix with selectable items (instances, volumes, images ticked in the result), only the ticked items, each with
    its own commands of the stored result; a selection that deletes needs the number and kind typed ("3 images").
Acme Prime (VMware) and Huawei checks have no actions: their fixes stay for a person to run.
"""
import datetime
import os
import re

from . import catalog
from .wi_analysis import OPENSTACK_DELETE

PERMISSION = "wi-fix"
VYOS_KINDS = ("vyos_upgrade", "vyos_rollback")   # wi_analysis.vyos_upgrade: a host fix with its own playbook
HOST_KINDS = ("host",) + VYOS_KINDS
OPENSTACK_PERMISSION = "wi-fix-openstack"
MAX_AGE_MINUTES = int(os.environ.get("WI_FIX_MAX_AGE_MINUTES", "120"))
HIGH_RE = re.compile(
    r"(^|[\s;|&(])(rm|truncate|kill|pkill|killall|reboot|shutdown|poweroff|halt|mkfs(\.\w+)?|wipefs|dd|fuser|chattr)\b"
    r"|systemctl\s+(restart|stop|disable|kill|reload-or-restart|try-restart)\b|docker\s+(restart|stop|rm|kill)\b"
    r"|journalctl\s+--vacuum|\bdelete\b|\bdel\b|ip\s+link\s+set\s+\S+\s+down|nft\s+(delete|flush)|iptables\s+-[DF]\b"
    r"|add\s+system\s+image|^commit$|\bsemanage\s+port\s+-d|\bvgremove|\blvremove|\bumount\b")


def can_fix(user, kind="host"):
    """May this account run fixes of this kind (host and ontap: wi-fix; openstack: wi-fix-openstack)."""
    permission = OPENSTACK_PERMISSION if kind == "openstack" else PERMISSION
    return bool(user) and (user.get("role") == "admin" or permission in (user.get("modules") or []))


def can_fix_any(user):
    return can_fix(user) or can_fix(user, "openstack")


def deletes(commands):
    return any(OPENSTACK_DELETE.match(str(c).strip()) for c in commands or [])


def risk_of(action):
    if action.get("kind") == "openstack":   # deleting on OpenStack: type the ID or name; every other change: confirm
        items = (action.get("select") or {}).get("items") or []
        return "high" if deletes(action.get("commands")) or any(deletes(i.get("commands")) for i in items) else "normal"
    if action.get("risk") in ("high", "normal"):
        return action["risk"]
    if action.get("kind") == "ontap":
        return "normal"
    return "high" if any(HIGH_RE.search(str(c).strip()) for c in action.get("commands") or []) else "normal"


def _age_minutes(record):
    try:
        finished = datetime.datetime.fromisoformat(record.get("finished") or "")
    except ValueError:
        return None
    return (datetime.datetime.now().astimezone() - finished).total_seconds() / 60


def target_of(record, check, site_cfg):
    """The host the run read (resolved again now: it may have been removed), or None."""
    host_param = next((p for p in check["params"] if p.get("type") == "host"), None)
    if not host_param or not record.get("host"):
        return None
    try:
        return catalog.resolve_host(record["site"], site_cfg, host_param.get("groups") or [], record["host"])
    except ValueError:
        return None


def state(record, index, rec, check, site_cfg, user, ontap_configured):
    """{"available", "reason", "risk", "target", "kind", "commands"} of the fix of one recommendation (None: no fix)."""
    action = rec.get("action") if isinstance(rec, dict) else None
    if not action:
        return None
    kind = action.get("kind") or "host"
    risk = risk_of(action)
    reason, target_name = "", ""
    if kind in HOST_KINDS:
        target = target_of(record, check, site_cfg)
        target_name = (target or {}).get("name") or record.get("host") or ""
        if not target:
            reason = f"{target_name or 'The host'} is no longer a host of {record['site']}."
        elif target.get("source") != "portal":
            reason = (f"{target_name} is a read-only host of sites.yml. Add it on Hosts & SSH with a credential that may run "
                      "fixes.")
        elif not target.get("credential_id"):
            reason = f"{target_name} has no SSH credential (Hosts & SSH)."
        elif not target.get("fixes"):
            reason = f"The SSH credential {target.get('credential')} of {target_name} may only read: allow fixes on Hosts & SSH."
        elif kind in VYOS_KINDS and not target.get("jump"):
            reason = f"{target_name} has no jump host (Hosts & SSH, Connect through): the image is copied from it."
        elif kind in VYOS_KINDS and target.get("auth") not in ("key", "password"):
            reason = f"{target_name} has no usable credential for the copy from the jump host."
    elif kind == "ontap":
        target_name = action.get("lif") or "cluster_mgmt"
        if not ontap_configured(f"ontap:{record['site']}"):
            reason = (f"No ONTAP account of {record['site']} that may change LIFs: set ontap:{record['site']} in "
                      "Administration → Credentials.")
    elif kind == "openstack":
        target_name = str(action.get("confirm") or action.get("target") or "")
        if not (site_cfg.get("mgmt") or {}).get("host") or not (site_cfg.get("director") or {}).get("host"):
            reason = f"OpenStack of {record['site']} is not in sites.yml (mgmt, director)."
    else:
        reason = "This fix cannot run from the portal."
    age = _age_minutes(record)
    select = action.get("select") if kind == "openstack" else None
    # a fix of a problem runs from a result that found one; an operation on items the operator ticks (migrations, clean-ups)
    # runs from any result
    if not reason and record.get("status") not in ("fail", "warn") and not select and kind not in VYOS_KINDS:
        reason = "The fix only runs from a result with a problem."
    if not reason and (age is None or age > MAX_AGE_MINUTES):
        reason = f"This result is older than {MAX_AGE_MINUTES} minutes: run the check again, then run the fix from the new result."
    if not reason and not can_fix(user, kind):
        reason = ("Your account cannot run OpenStack fixes. An administrator can allow it on the Users page "
                  "(Operation Automation: run OpenStack fixes)." if kind == "openstack" else
                  "Your account cannot run fixes. An administrator can allow it on the Users page (Operation Automation: run fixes).")
    out = {"available": not reason, "reason": reason, "risk": risk, "target": target_name, "kind": kind,
           "commands": list(action.get("commands") or []) if kind in HOST_KINDS + ("openstack",) else [action.get("summary") or ""],
           "label": action.get("label") or "Run this fix", "index": index, "where": action.get("where") or ""}
    if select:   # the browser shows the items to tick; the server takes their commands from the stored result
        out.update(selectable=True, noun=str(select.get("noun") or "items"), max=int(select.get("max") or 40),
                   stop_on_failure=5 in (select.get("stop") or []),
                   items=[{"label": i.get("label") or "", "commands": list(i.get("commands") or []), "default": bool(i.get("default")),
                           "disabled": i.get("disabled") or ("" if i.get("commands") else "cannot run"),
                           "delete": deletes(i.get("commands"))} for i in select.get("items") or []])
    return out


def selection(action, selected):
    """The ticked items of a fix with selectable items: (indexes, items, commands, deletes). ValueError unless every
    index is an item of the stored result that can run, within the maximum per run."""
    select = action.get("select") or {}
    items, noun = select.get("items") or [], select.get("noun") or "items"
    if not isinstance(selected, list) or not selected:
        raise ValueError(f"Tick at least one of the {noun}.")
    idx = []
    for x in selected:
        if isinstance(x, bool) or not isinstance(x, int) or not 0 <= x < len(items):
            raise ValueError("Unknown item in the selection.")
        if x not in idx:
            idx.append(x)
    idx.sort()
    chosen = [items[i] for i in idx]
    blocked = [i["label"] for i in chosen if not i.get("commands")]
    if blocked:
        raise ValueError(f"These {noun} cannot run: {', '.join(blocked[:5])}.")
    limit = int(select.get("max") or 40)
    if len(chosen) > limit:
        raise ValueError(f"At most {limit} {noun} per run: tick fewer, then run the check again for the rest.")
    commands = [c for i in chosen for c in i["commands"]]
    return idx, chosen, commands, deletes(commands)


def host_job(target, action, credential):
    """Variables and secrets of a fix on a host. The private key or password goes in the environment only; commands
    that start with "sudo " lose it when the whole script already runs as root (become)."""
    become = credential["privilege"] in ("sudo", "sudo_password") and target.get("connection") != "local"
    variables = {"action_kind": "host", "host_target": dict(target, become=become),
                 "action_commands": [str(c) for c in action.get("commands") or []],
                 "action_shell": "vyos" if action.get("shell") == "vyos" else "sh",
                 "action_strip_sudo": credential["privilege"] in ("root", "sudo", "sudo_password")}
    secrets = {"WI_SSH_SECRET": credential["secret"]}
    return variables, secrets

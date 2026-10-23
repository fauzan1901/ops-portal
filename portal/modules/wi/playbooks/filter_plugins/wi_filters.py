"""Filters of the Operation Automation playbook: what to read (wi_plan, wi_reads), how to run it (wi_os_script, wi_host_script),
how to keep it (wi_batch, wi_rest_results, wi_command_results, wi_tcp_results, wi_skip), and the rating (wi_analyze).
The logic lives in modules/wi/wi_analysis (also used by the portal tests)."""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import wi_analysis  # noqa: E402


def wi_plan(check_id):
    return wi_analysis.plan(check_id)


def wi_reads(check_id, phase, data, params, ctx):
    return wi_analysis.reads(check_id, phase, data, params, ctx)


def wi_os_script(commands, overcloudrc="~/overcloudrc"):
    return wi_analysis.os_script(dict(commands), overcloudrc)


def wi_uc_script(commands, stackrc="~/stackrc"):
    return wi_analysis.os_script(dict(commands), stackrc, undercloud=True)


def wi_oc_script(reads):
    return wi_analysis.oc_script(dict(reads))


def wi_os_action_script(commands, overcloudrc="~/overcloudrc"):
    return wi_analysis.os_action_script(list(commands), overcloudrc)


def wi_item_result(out, item, index, stop_rcs=(6,)):
    return wi_analysis.item_result(dict(out or {}), dict(item or {}), int(index), list(stop_rcs or [6]))


def wi_progress(results, items, current):
    """{"of", "current": {"n", "label"} or None, "done": [{"n", "status", "label", "summary"}]} for the run page."""
    items = list(items or [])
    cur = int(current)
    return {"of": len(items), "current": {"n": cur + 1, "label": str(items[cur].get("label") or "")} if 0 <= cur < len(items) else None,
            "done": [{"n": int(r["index"]) + 1, "status": r["status"], "label": r["label"], "summary": r["summary"]}
                     for r in list(results or [])]}


def wi_items_result(results, items):
    return wi_analysis.items_result(list(results or []), list(items or []))


def wi_host_script(commands, sudo=False):
    return wi_analysis.host_script(dict(commands), bool(sudo))


def wi_ssh_route(target, keyfile=""):
    return wi_analysis.ssh_route_args(dict(target or {}), str(keyfile or ""))


def wi_action_script(commands, shell="sh", strip_sudo=False):
    return wi_analysis.action_script(list(commands), str(shell), bool(strip_sudo))


def wi_action_result(out, commands, target=None):
    return wi_analysis.action_result(dict(out or {}), list(commands), dict(target or {}))


def wi_ssh_hint(message, target=None):
    return wi_analysis.ssh_hint(str(message or ""), dict(target or {}))


def wi_collect_command(spec, director_prefix, mgmt, bundle_dir):
    return wi_analysis.logs.transfer_command(str(spec), str(director_prefix), dict(mgmt or {}), str(bundle_dir))


def wi_collect_results(results):
    return wi_analysis.logs.collect_results(list(results or []))


def wi_vu_step(step, args=None):
    return wi_analysis.vyos_upgrade.step_script(str(step), **dict(args or {}))


def wi_vu_jump(step, target, vu, jump_key="", target_key="", agent=False):
    vu, target = dict(vu or {}), dict(target or {})
    remote = wi_analysis.vyos_upgrade.jump_script(str(step), target, iso=vu.get("image"), backup_dir=vu.get("backup_dir"),
                                                  name=target.get("name"), version=vu.get("target"), dir=vu.get("dir"))
    password = target.get("auth") == "password" and str(step) in ("copy", "backup")
    return wi_analysis.vyos_upgrade.jump_command(dict(target or {}), remote, str(jump_key or ""), str(target_key or ""),
                                                 bool(agent) and not password, password_stdin=password)


def wi_vu_backup(text):
    """The output of the backup on the jump host -> {"file", "sha256"}."""
    import re as _re
    text = str(text or "")
    m = _re.search(r"^@@VU@@backup (\S+)$", text, _re.M)
    s = _re.search(r"\b([0-9a-f]{64})\b", text)
    return {"file": m.group(1) if m else "", "sha256": s.group(1) if s else ""}


def wi_vu_state(text):
    return wi_analysis.vyos_upgrade.parse_state(text)


def wi_vu_iso(text):
    """`stat -c %s` and `sha256sum` of the image on the jump host -> {"size", "sha256"}."""
    import re as _re
    size = next((int(l.strip()) for l in str(text or "").splitlines() if l.strip().isdigit()), 0)
    m = _re.search(r"\b([0-9a-f]{64})\b", str(text or ""))
    return {"size": size, "sha256": m.group(1) if m else ""}


def wi_vu_grow(text, iso, iso_size):
    """The room step of the fix -> whether the image store must grow, can, and has enough room outside its partition."""
    vu = wi_analysis.vyos_upgrade
    room = vu.parse_room(text, iso)
    return vu.grow_need(room["tmp"], room["store"], vu.parse_disk(vu.sections(text).get("disk", "")), int(iso_size or 0) // 1024)


def wi_vu_place(text, iso, iso_size, home=""):
    """The room step of the fix, the ISO (path, size in bytes) -> where it goes: {"dir" (/tmp, the home folder, or ""
    when nowhere), "text", "store" (KiB free in the image store)}. An earlier copy of the ISO counts as room."""
    vu = wi_analysis.vyos_upgrade
    room = vu.parse_room(text, iso)
    home = room["home_dir"] or (str(home or "") if vu.DIR_RE.match(str(home or "")) else "")
    return dict(vu.place_iso(room["tmp"], room["home"], room["store"], int(iso_size or 0) // 1024, home), store=room["store"])


def wi_vu_post(baseline, after, ping_text, wanted, expect_image="", ping_before_text=""):
    rows = wi_analysis.vyos_upgrade.post_check(dict(baseline or {}), dict(after or {}),
                                              wi_analysis.vyos_upgrade.parse_pings(ping_text), str(wanted), str(expect_image or ""),
                                              wi_analysis.vyos_upgrade.parse_pings(ping_before_text))
    return [dict(r, line=f"{'OK  ' if r['ok'] else 'FAIL'} {r['check']}: {r['detail']}") for r in rows]


def wi_vu_text(steps):
    """The steps of the VyOS upgrade as the full output of the fix (raw output): each step, its exit code and output."""
    return "\n\n".join(f"$ {s.get('command')}\n(exit {s.get('rc')})\n{s.get('out') or ''}" for s in steps or [])


def wi_vu_out(result):
    """stdout, stderr and the message of a raw result, as one text."""
    result = dict(result or {})
    return "\n".join(str(result.get(k) or "").strip() for k in ("stdout", "stderr", "msg") if str(result.get(k) or "").strip())


def wi_vu_images(text):
    """The images listed in a command output (show system image) -> {"images", "default_image"}."""
    return wi_analysis.vyos_upgrade.parse_state("@@VU@@images\n" + str(text or ""))


def wi_vu_lines(items):
    return "\n".join(str(x) for x in items or [])


def wi_vu_clip(text, limit=6000):
    text = str(text or "")
    return text if len(text) <= limit else "… " + text[-limit:]


def wi_batch(stdout, keys):
    return wi_analysis.batch(stdout, list(keys))


def wi_skip(items, reason):
    return {key: {"skipped": str(reason)} for key in dict(items)}


def wi_rest_results(results):
    """uri loop results -> {key: {"status", "json"}} (or {"status", "msg", "body"} on an error)."""
    out = {}
    for res in results or []:
        key = (res.get("item") or {}).get("key")
        if not key:
            continue
        if res.get("skipped"):
            out[key] = {"skipped": "not read"}
            continue
        status = res.get("status") or 0
        item = {"status": status}
        if status == 200 and "json" in res:
            item["json"] = res["json"]
        else:
            item["msg"] = str(res.get("msg") or "")[:300]
            item["body"] = str(res.get("content") or "")[:300]
        out[key] = item
    return out


def wi_command_results(results):
    """raw loop results -> {key: {"rc", "out"}}."""
    out = {}
    for res in results or []:
        key = (res.get("item") or {}).get("key")
        if not key:
            continue
        if res.get("unreachable"):
            out[key] = {"skipped": f"device not reachable: {str(res.get('msg') or '')[:200]}"}
        else:
            out[key] = {"rc": res.get("rc", 1), "out": str(res.get("stdout") or "") + str(res.get("stderr") or "")}
    return out


def wi_tcp_results(results):
    """wait_for loop results -> {key: {"ok", "elapsed", "msg"}}."""
    out = {}
    for res in results or []:
        key = (res.get("item") or {}).get("key")
        if key:
            # wait_for only returns "state" when the port answered (failed_when: false hides the failure itself)
            out[key] = {"ok": "state" in res and not res.get("skipped"), "elapsed": res.get("elapsed"),
                        "msg": str(res.get("msg") or "")[:200]}
    return out


def wi_tls_results(stdout, reads):
    """tls_cert.py output -> {key: {"status": 200, "json": {...}}} per address read (skipped when there is no answer)."""
    import json
    try:
        found = json.loads(stdout or "{}")
    except ValueError:
        found = {}
    out = {}
    for key, address in dict(reads).items():
        item = found.get(address)
        out[key] = {"status": 200, "json": item} if isinstance(item, dict) else {"skipped": "the certificate reader gave no answer"}
    return out


def wi_analyze(check_id, data, params, ctx):
    return wi_analysis.analyze(check_id, data, params, ctx)


class FilterModule:
    def filters(self):
        return {"wi_plan": wi_plan, "wi_reads": wi_reads, "wi_os_script": wi_os_script, "wi_uc_script": wi_uc_script, "wi_oc_script": wi_oc_script, "wi_os_action_script": wi_os_action_script, "wi_host_script": wi_host_script,
                "wi_batch": wi_batch, "wi_skip": wi_skip, "wi_rest_results": wi_rest_results,
                "wi_command_results": wi_command_results, "wi_tcp_results": wi_tcp_results, "wi_tls_results": wi_tls_results, "wi_analyze": wi_analyze,
                "wi_action_script": wi_action_script, "wi_action_result": wi_action_result, "wi_ssh_route": wi_ssh_route, "wi_ssh_hint": wi_ssh_hint,
                "wi_item_result": wi_item_result, "wi_items_result": wi_items_result, "wi_progress": wi_progress,
                "wi_collect_command": wi_collect_command, "wi_collect_results": wi_collect_results,
                "wi_vu_step": wi_vu_step, "wi_vu_jump": wi_vu_jump, "wi_vu_backup": wi_vu_backup, "wi_vu_state": wi_vu_state, "wi_vu_iso": wi_vu_iso,
                "wi_vu_place": wi_vu_place, "wi_vu_grow": wi_vu_grow, "wi_vu_post": wi_vu_post, "wi_vu_clip": wi_vu_clip, "wi_vu_text": wi_vu_text,
                "wi_vu_out": wi_vu_out, "wi_vu_images": wi_vu_images, "wi_vu_lines": wi_vu_lines}

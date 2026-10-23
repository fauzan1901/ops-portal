"""The portal object shared by every module: sign-in, users, module access and service credentials (portal_auth),
plus the registry of modules.

A module (package under modules/) calls register(...) when it is imported and uses PORTAL in its views:
    PORTAL.require("<module id>")   signed in and allowed to use the module (Forbidden otherwise)
    PORTAL.admin()                  administrators only
    PORTAL.credential("<target>")   service account entered on Administration -> Credentials
"""
import logging

import portal_auth
import settings

log = logging.getLogger("portal")
_MODULES = []


def register(module_id, title, description, url, icon, targets=None, tester=None, on_credential_change=None,
             running_jobs=None, permissions=None):
    """Add a module. targets(): its service accounts [{"name", "label", "host", "kind", "site"}, ...];
    tester(target, username, password): connection test after an administrator saves one of them;
    running_jobs(): jobs still running (shown on the home page, and the updater waits for them);
    permissions: extra rights inside the module [{"id", "title"}], ticked one by one on the Users page and never
    given by "all modules" (administrators always have them)."""
    _MODULES.append({"id": module_id, "title": title, "description": description, "url": url, "icon": icon,
                     "targets": targets or (lambda: []), "tester": tester, "on_credential_change": on_credential_change,
                     "running_jobs": running_jobs or (lambda: []), "permissions": list(permissions or [])})


def modules():
    return list(_MODULES)


def module_list():
    """For portal_auth and the Users page: [{"id", "title"}], each module followed by its permissions
    ({"id", "title", "permission_of": <module id>, "explicit": True})."""
    items = []
    for m in _MODULES:
        items.append({"id": m["id"], "title": m["title"]})
        items += [{"id": p["id"], "title": p["title"], "permission_of": m["id"], "explicit": True} for p in m["permissions"]]
    return items


def credential_targets():
    """Service accounts of every module, in module order; each target names its module."""
    targets = []
    for m in _MODULES:
        for target in m["targets"]():
            targets.append(dict(target, module=m["id"], module_title=m["title"]))
    return targets


def test_credential(target, username, password):
    module = next((m for m in _MODULES if m["id"] == target.get("module")), None)
    if not module or not module["tester"]:
        raise ValueError("No connection test for this credential")
    return module["tester"](target, username, password)


def credential_changed(name):
    for m in _MODULES:
        if m["on_credential_change"]:
            m["on_credential_change"](name)


PORTAL = portal_auth.Portal(settings.TITLE, settings.AUTH_FILE, settings.DB_PATH, settings.CREDENTIALS_KEY,
                            settings.SESSION_COOKIE, targets=credential_targets, tester=test_credential,
                            on_credential_change=credential_changed, trusted_proxy=bool(settings.TRUSTED_PROXIES),
                            modules=module_list)

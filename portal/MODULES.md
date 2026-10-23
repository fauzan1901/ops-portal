# Portal modules: contract

Every tool of the Ops Portal is a **module**: a Python package under `portal/modules/<id>/` that the portal
loads as a Flask blueprint (see `app.py`, `core.py`, decision in `docs/ADR-003-one-portal.md`). The portal owns the
sign-in, users, module access, Administration (Users, Credentials, Activity) and the application launcher; a module
owns its own pages, API, playbooks and tables.

| Module | id | URL | Comes from |
|---|---|---|---|
| Operation Automation | `wi` | `/wi/` | new |
| ONTAP Restore | `ontap` | `/ontap/` | `ontap_restore/` |
| ACI | `aci` | `/aci/` | `aci_webui/` |

## Files that belong to the portal (a module never edits them)

`app.py`, `core.py`, `settings.py`, `sites.py`, `jobs.py`, `portal_auth.py`, `templates/shell.html`,
`templates/_sprite.html`, `static/portal.css`, `static/shell.js`, `static/switcher.css`, `static/switcher.js`,
`static/fonts/`. A module that needs a change there says so instead.

## Python side

```python
from flask import Blueprint
from core import PORTAL, register
import settings, sites

blueprint = Blueprint("<id>", __name__, url_prefix="/<id>", template_folder="templates",
                      static_folder="static", static_url_path="/static")
register("<id>", "<Title>", "<one-line description>", "/<id>/", "<icon: checklist|database|network>",
         targets=<fn -> [{"name", "label", "host", "kind", "site"}]>, tester=<fn(target, user, password) -> message>,
         on_credential_change=<fn(name)>, running_jobs=<fn -> list of running jobs>)
```

- **Access.** Every view of the module calls `PORTAL.require("<id>")` (signed in *and* allowed to use the module;
  raises `portal_auth.NotSignedIn` → 401 or `portal_auth.Forbidden` → 403). Administrator-only actions call
  `PORTAL.admin()`. A module never calls `PORTAL.install()` (the portal already serves `/api/login`, `/api/logout`,
  `/auth/...`, `/api/admin/...`, `/export/events.csv`).
- **Routes.** Everything of the module lives under its prefix: page `/<id>/`, API `/<id>/api/...`, files
  `/<id>/export/...`, static `/<id>/static/...`. `/<id>/api/session` returns the module's session payload:
  `{"ui_version", **PORTAL.payload(), "allowed": <bool>, ...module data such as sites}`; it never fails with 403, so the
  page can show "no access" itself.
- **Service accounts.** Target names keep their old form (`apic:DCB`, `ontap:DCB`); Operation Automation uses `ro-<kind>:<site>`.
  `PORTAL.credential(name)` returns `{"username", "password"}`.
- **Database.** One SQLite file for everything: `settings.DB_PATH`. Table names must not collide; the portal uses
  `portal_users`, `portal_local_users`, `portal_events`, `service_credentials`. Module tables: ONTAP `restores`,
  `restore_groups`, `deletions`; ACI `aci_*`; Operation Automation `wi_runs`.
- **Sites.** `sites.sites()` (re-read when sites.yml changes) and `sites.get(name)`. Keys per site: `apic` (ACI),
  `ontap`, `mgmt`, `director`, `openstack` (ONTAP Restore and Operation Automation), `vcenter`, `vcd`, `nsxt`, `hosts` (Operation Automation).
- **Ansible.** `jobs.Jobs(playbook_dir, timeouts)`; `start(kind, params, secrets={...env...}, key=..., owner=...)`.
  The playbook gets `-e @<sites.yml> -e @<vars.json>` and writes `{"ok": ..., "error": ...}` to `result_file`.
- **Activity.** `PORTAL.store.event(actor, action, target, detail, client)` with actions named `<area>.<what>`
  (e.g. `restore.start`, `static_port.applied`, `wi.ok`) — the Users page filters and colours them.

## Browser side

The UI of a module stays what it was (same HTML, CSS and JS, PatternFly v5 look like AWX, `docs/UI-SPEC.md`).
Only these changes:

1. Masthead: `<div id="portalLauncher" data-current="<id>"></div>` just before the user menu, plus
   `<link rel="stylesheet" href="/static/switcher.css">` and `<script src="/static/switcher.js"></script>`
   (PatternFly application launcher, as in the OpenShift console masthead).
2. No sign-in form in the module: without a session (no `user`, or a 401) the page calls `PortalLauncher.signIn()`,
   which opens the portal sign-in and comes back afterwards.
3. Signed in but `allowed` is false: a PatternFly empty state "No access to <Title>" with a link to the portal home.
4. No Users / Credentials pages in the module: for administrators the sidebar section "Administration" links to
   `/#/users` and `/#/credentials` on the portal.
5. Sign out: `POST /api/logout`, then `location.assign('/')`.
6. Every request of the module goes to `/<id>/...` (one `BASE` constant), fonts come from `/static/fonts/`.

## Tests

`portal/tests/test_<id>.py` (stdlib `unittest`), run from `portal/`:

```
.venv/bin/python -m unittest tests.test_<id> -v
```

Set `PORTAL_SITES`, `PORTAL_DATA`, `PORTAL_DB`, `PORTAL_AUTH`, `PORTAL_CREDENTIALS_KEY` (and `PORTAL_MODULES=<id>`
when only this module is needed) before `import app`. Fakes and mocks live in `portal/tests/` (`fake_ldap.py`,
`fake_duo.py`, `fake_sso.py` are shared).

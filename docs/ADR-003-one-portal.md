# ADR-003: One portal for all automation (ACI, ONTAP Restore, WI Check)

**Status:** Accepted
**Date:** 2026-10-09
**Deciders:** Acme Cloud team (owner of ACI Web UI and ONTAP Restore Web UI)

## Context

Today there are two separate apps, each with its own port, login, user list, credentials, and database:

| App | Port | Login | Database |
|---|---|---|---|
| ACI Web UI | 8080 | own | `audit.db` |
| ONTAP Restore Web UI | 8081 | own | `restore.db` |

A third app will be added, **WI Check**: automatic (read-only) checks based on the Work Instructions in the Acme Cloud
Knowledge Base (`kb.example.com`, collective "Knowledge Based"). If it is built with the same pattern, operators must
log in to three ports, and admins manage three user lists and three sets of credentials.

The request: **everything is accessed from one portal**. After login, the operator chooses the module to use. There must
no longer be one portal per tool.

ADR-002 already chose the same pattern for the three old ACI apps (one login, one port, one code base) and rejected a
reverse proxy in front of the old apps because the logins would still be separate.

## Decision

Build **one `portal/` app** (Flask + gunicorn, one process) with these modules:

1. **Portal page (`/`).**
   - Not logged in: login page (AD, Duo, Duo SSO, local account — the same as the current `portal_auth`).
   - Logged in: the list of modules this user may use (tiles), plus Administration for admins.
   - The masthead of every module has a **module switcher**, so users change module without logging in again.
2. **A module = a Flask Blueprint under its own path**, with its own pages, JS, CSS, and API:
   - `/aci/` — Static Port, Provisioning, Report, History (logic from `aci_webui/`, not rewritten);
   - `/ontap/` — ONTAP Restore, Jobs, Approvals (logic from `ontap_restore/`, not rewritten);
   - `/wi/` — WI Check (new).
3. **Central Administration (`/admin/`)**: only one Users, Credentials, and Activity.
   - Roles stay `admin` / `operator`.
   - **Access per module per user**: an operator only sees and uses the modules the admin ticked
     (example: L1 only WI Check). Admins can always use all modules.
   - Credentials are grouped per system: APIC, ONTAP (restore), and the **read-only** WI Check accounts.
4. **One `portal_auth.py`** (the successor of the shared copy in both old apps) with module access added.
5. **One `sites.yml`** for all modules. Per site: `apic`, `ontap`, `mgmt`, `director`, `openstack`, and for
   WI Check `vcenter`, `vcd`, `nsxt`, plus a list of SSH hosts (CDN, DNS, VyOS, ...).
6. **One SQLite database** (`/var/lib/ops-portal/portal.db`) and one Fernet key. Module tables stay separate
   (`aci_audit`, `restores`, `deletions`, `wi_runs`, ...).
7. **WI Check only reads.**
   - One WI = one catalog entry (`modules/wi/catalog.yml`) + one Ansible playbook `checks/<id>.yml`.
   - Result per WI step: OK / WARN / FAIL / SKIP, with evidence (command output) and a link to the WI page in the KB.
   - The account used is a **read-only** service account per system and per site (`ro-*` credentials), separate from the
     ONTAP Restore account that has write rights.
   - OpenStack commands use the same path as ONTAP Restore (management host → director → `overcloudrc`),
     but WI Check tasks reject commands other than `list` / `show` / `get-pools` / `quota show`.
   - Fixes are not run; the fix steps are only shown as suggested commands.

### Port

| Stage | Portal | Notes |
|---|---|---|
| Lab test / pilot | 8083 (gunicorn 127.0.0.1:18083, PROXY 28083) | The old 8080/8081 keep running; 8082 is still used by the old portproxy |
| After cutover | 8080 | 8081 is redirected to `/ontap/`; the old apps are stopped |

## Options Considered

### Option A: One app with modules (chosen)
| Dimension | Assessment |
|-----------|------------|
| Complexity | Medium-high: module logic is moved, the login/admin UI is merged, tests are moved |
| Cost | No extra infrastructure; one service, one nginx server block |
| Scalability | New module = new blueprint + an entry in the module registry |
| Team familiarity | Still Flask + vanilla JS + Ansible |

**Pros:** one login, one URL, one user list and one set of credentials, one backup, one deploy.
**Cons:** a portal restart interrupts all modules at once (an update is still refused while a job is running, like
`update_portals.sh` today); all modules must be tested again before cutover.

### Option B: Three processes, session shared through SQLite, nginx per path
**Pros:** the old app code barely changes; one module crashing does not stop the others.
**Cons:** three services and three deploys remain; the Users/Credentials pages stay in each app (same data, three UIs);
sessions must be moved to a shared database; the credential tester and targets are spread over three processes.

### Option C: A launcher page with links to the existing apps
**Pros:** fastest.
**Cons:** still one login per app. Does not meet the request.

## Consequences

- Easier: operators open one URL; admins manage users, module access, and credentials in one place; one audit
  (Activity) for all modules.
- Harder: a change in one module also restarts the portal; the old databases must be migrated (the migration script
  merges users, credentials — decrypted with the old key and then encrypted again — activity, ACI history, and
  restore history).
- `aci_webui/` and `ontap_restore/` are not changed during the transition; the portal is built in the `portal/` folder.
- ADR-001 and `ontap_restore/DESIGN.md` no longer match the code (per-site service accounts are already in use); this
  ADR follows the code.

## Action Items

1. [ ] `portal/` skeleton: app shell, `portal_auth` with module access, login page + launcher, Administration.
2. [ ] Move the ONTAP Restore module to `/ontap/` together with its tests.
3. [ ] Move the ACI module to `/aci/` together with its tests.
4. [ ] WI Check module: catalog of all WI categories, phase 1 playbooks (Flex/OpenStack + NetApp), skeleton for phases 2–4.
5. [ ] Portal `test_mode.sh` (mock APIC, mock ONTAP, fake director, fake AD/Duo/SSO) and UI verification in a browser.
6. [ ] Migration script from the old databases → `portal.db`.
7. [ ] Deploy: `deploy/install.sh`, `tools/build_zips.py`, `tools/update_portals.sh`, `bastion/portal-proxy`.
8. [ ] Lab test on 8083, then cutover to 8080.

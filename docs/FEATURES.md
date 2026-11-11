# Features and design

The details behind the [README](../README.md): what each module does, how the portal is built, and how it is configured, deployed and kept safe.

## Features

**Portal (shared by every module)**
- Sign-in with Active Directory (LDAPS or a Duo Authentication Proxy), Duo Universal Prompt, Duo SSO, or local
  accounts. Users have a role (administrator / operator) and a list of modules they may use.
- Service accounts (APIC, ONTAP, read-only vCenter / NSX-T / vCloud Director accounts) stored encrypted; each is
  tested when it is saved, and a password only goes to the address it was entered for.
- An activity log of every sign-in, change, restore, ACI change and check, with filters and CSV export.
- An application launcher in the masthead to switch modules without signing in again.

**Runbook Automation (`portal/modules/wi`, `/runbook/`)**
- A catalog of work instructions (`catalog.yml`): each entry is a check, planned, manual, or handled by another module.
- Checks are read-only: fixed commands, GET-only REST calls, validated parameters (no free text reaches a shell).
- Every result shows the steps (OK / warning / problem / not checked), the evidence, **how to fix it** with the real
  values of the run, and **where to look**: the console screens (terminal, Horizon, vSphere Client, NSX Manager, ONTAP
  System Manager) drawn with the values found.
- Fixes run from the portal for permitted users: the exact commands are shown first, high-risk fixes need the host
  name typed, the check runs again afterwards. Operations on ticked items (live migration of instances, volume
  migrations, image clean-up) run one item after the other, with progress that survives closing the page.
- Log collection: raw output of every run, log bundles from overcloud nodes, `sos report`, BMC / ONTAP EMS / vCenter
  event exports, kept for 7 days.
- A VyOS router upgrade that follows the work instruction step by step: configuration backup to the jump host, hw-id
  pinning, image copy and checksum, `add system image`, CVE mitigation, reboot with boot-ID detection, growing the disk
  partition when the image store is too small, and a post-check against a baseline (interfaces, addresses, routes,
  NAT, pings), with a roll back.
- Compute drains (live / cold migration) skip an instance that cannot be moved and go on with the next one; the run
  stops when the OpenStack control plane fails or several instances in a row need a person.
- A controller reboot readiness check: Pacemaker quorum and resources, Galera, clustercheck, endpoint security agents
  that can kill cluster helpers, and the kernel a reboot starts, with a safe reboot order per controller.
- Every manual fix is pre-checked (the same check runs again and must still offer the same fix), then reviewed by
  an engineer (never the requester), then run by the requester within a short window (15 minutes by default).
- **Alerts**: Grafana or Prometheus Alertmanager sends its alerts to a webhook. Matching rules run their checks at
  once. A rule can give a check an automatic action: measure, run one item (for example one live migration, smallest
  VM first), measure again, until the problem is gone or a maximum is reached. New actions start in an observe-only
  pilot mode; customer-impacting ones need the owner's approval with a ticket; databases, ESXi and read-only clouds
  never run by themselves. Counts for the monitoring team's Prometheus come from a metrics endpoint. See
  [portal/docs/GRAFANA-ALERTS.md](../portal/docs/GRAFANA-ALERTS.md).

**Snapshot Restore (`portal/modules/ontap`, `/restore/`)**
- Plans and runs restores of OpenStack volumes from ONTAP snapshots (FlexClone, LUN mapping, Cinder manage), with a
  history, groups, and an approval flow for deleting the original volume (and its instance when it is the boot disk).

**Fabric Manager (`portal/modules/aci`, `/fabric/`)**
- Static port bindings on EPGs from product templates, bulk input, APIC search, a report per site, IP usage per EPG
  with free address suggestions, and an audit history with before / after.

**Web Terminal (`portal/modules/shell`, `/terminal/`)**
- Terminals in the browser (xterm.js): a host tree per site and product (OpenStack management host and director,
  ONTAP, APIC, the SSH hosts of Runbook Automation). ESXi hosts are not listed.
- The portal server runs `ssh` with the stored account; the browser only sends a host id, the keys typed and the
  terminal size, and never sees a password or key.
- Tabs, up to four panes, favorites and recent hosts, snippets, copy on select, and a paste that never presses Enter
  for you. **Become root** types `sudo -i` and the portal answers the account's own sudo prompt.
- Operators open only the hosts an administrator gave them (a site, a product, or single hosts), permanently or
  until a time with a ticket; taking access away ends the open sessions.
- Every session is recorded (activity log and session history). Administrators can watch a live session, join it, or
  end it, and the user sees who is watching.
- Optional Duo SSO step-up before opening a terminal, joining a session or becoming root (off by default). Idle,
  detached and maximum-length timeouts, and limits per user.

**Vulnerability Scans (`portal/modules/nessus`, `/vulns/`)**
- Tenable Vulnerability Management through a proxy: scans and findings per site (by the scanner that ran them and the
  management networks of the site), how to fix each finding, launch and stop scans, and a verify scan of one address.
- A scan starts only when every target is inside the management networks configured for its site, also for
  administrators.

**Status (`portal/modules/health`, `/status/`)**
- Read-only checks of Runbook Automation for every product of every site (OpenStack, NetApp ONTAP, VMware Cloud and
  every server BMC), by themselves every 4 hours or with Run now; never a fix.
- One card per product: safe, needs attention, not safe, could not check; what each check found, its recommendations
  and the checks to run next. Metrics on the same endpoint as the alerts.

## How it works

```
browser ──HTTPS──> nginx ──> gunicorn / Flask (portal/app.py)
                                 │  sign-in, users, credentials, activity (portal_auth.py, SQLite)
                                 │  one Flask blueprint per module (portal/modules/<id>/)
                                 └─> jobs.py ── ansible-playbook ──> SSH / REST to the systems checked or changed
                                                (secrets only in the process environment)
```

- A module is a Python package that registers a Flask blueprint (contract: [portal/MODULES.md](../portal/MODULES.md)).
- Long work (checks, fixes, restores, ACI changes) runs as an Ansible job; the page follows its log and result.
- Runbook Automation checks are Python classes (`portal/modules/wi/wi_analysis/`): each says what to read per
  phase and how to rate what was read. The playbook `portal/modules/wi/playbooks/run_check.yml` is the same for
  every check.

## Repository layout

| Path | |
|---|---|
| `portal/app.py`, `portal/core.py` | Flask app, module registry, portal routes |
| `portal/portal_auth.py` | sign-in, users, module access, encrypted service accounts |
| `portal/settings.py`, `portal/sites.py`, `portal/jobs.py` | paths (`PORTAL_*` variables), the sites file, the Ansible job runner |
| `portal/modules/wi/` | Runbook Automation: catalog, checks (`wi_analysis/`), playbooks, UI |
| `portal/modules/ontap/` | Snapshot Restore: API client, playbooks, UI |
| `portal/modules/aci/` | Fabric Manager: APIC client, templates, reports, IP usage, UI |
| `portal/modules/shell/` | Web Terminal: SSH targets, sessions and recordings, access rules, terminal UI (xterm.js vendored, MIT) |
| `portal/modules/health/` | Status: products and their checks, the 4-hour rounds, the status page |
| `portal/templates/`, `portal/static/` | portal pages, PatternFly-style CSS, fonts, application launcher |
| `portal/deploy/` | systemd units, nginx configuration, install / backup scripts |
| `portal/tests/` | unit and flow tests with mocks and fakes (no real system is touched) |
| `portal/*.example.yml` | example configuration (sites, sign-in) |
| `portal/docs/` | coverage of the work instructions, access needed by the checks, Grafana alerts, demo data |
| `docs/` | architecture decisions (ADR) and the UI specification |
| `tools/` | build and deploy helpers, test scripts for an OpenStack lab, an ACI access-policy dump tool |
| `bastion/portal-proxy/` | a small Windows proxy used to reach the portal from a jump host |

## Configuration

| File | |
|---|---|
| `sites.yml` (from `portal/sites.example.yml`) | per site: APIC, ONTAP, OpenStack management host and director, vCenter, NSX-T, vCloud Director, SSH hosts |
| `auth.yml` (from `portal/auth.example.yml`) | sign-in: AD / LDAPS, Duo, SSO, local accounts, trusted proxies |
| `ops-portal.env` (`portal/deploy/`) | service settings: port, TLS, host name, data folders, timeouts |
| `credentials.key` | the key that encrypts service accounts (created at install, never in the repository) |

Service-account passwords are entered in the portal (Administration → Credentials), not in files.

## Deployment

`portal/deploy/install.sh` installs or updates the portal on a Linux server: a service user, the application in
`/opt/ops-portal`, a virtualenv from local wheels (offline install), the systemd service (gunicorn on
127.0.0.1) and nginx in front (TLS). Configuration lives in `/etc/ops-portal`, data in `/var/lib/ops-portal`
(SQLite) with a daily backup timer. `tools/build_zips.py` builds the package and `tools/deploy_portal.sh` copies it to
the server.

## Security model

- Checks are read-only: OpenStack commands are limited to list / show style commands, REST calls are GET only, host
  commands are fixed and their arguments validated.
- Fixes run only for users with the permission, show their commands first, need a typed confirmation when risky, and
  are recorded in the activity log with their full output.
- Passwords and keys reach Ansible only through the process environment; outputs are masked before they are stored.
- Read-only service accounts are used wherever the work allows it.
- Web Terminal: credentials stay on the server, access is given per host, every session is recorded, and ESXi hosts are
  never offered.
- Alerts: the webhook needs a token per source (only its hash is stored), can be limited to sender addresses, and
  fixes run by themselves only when every rule in GRAFANA-ALERTS.md allows it.

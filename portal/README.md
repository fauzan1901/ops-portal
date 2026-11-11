# Ops Portal

One sign-in for the Acme Cloud automation tools, run with **Ansible**. After signing in, an operator picks a module;
the **application launcher** (grid button in the masthead, as in the OpenShift console) switches modules without a new
sign-in. Decision and options: [docs/ADR-003-one-portal.md](../docs/ADR-003-one-portal.md). The look is the
PatternFly v5 / AWX look of the existing tools ([docs/UI-SPEC.md](../docs/UI-SPEC.md)).

| Module | URL | What it does |
|---|---|---|
| **Runbook Automation** | `/runbook/` | Read-only checks from the Knowledge Base work instructions (kb.example.com) |
| **Snapshot Restore** | `/restore/` | Restore OpenStack volumes from NetApp ONTAP snapshots (was `snapshot_restore/`, port 8481) |
| **ACI** | `/fabric/` | Static port, product templates, provisioning, report, IP usage and history on Cisco ACI (was `fabric_ui/`, port 8480) |
| **Shell** | `/terminal/` | SSH terminals in the browser to every host the portal knows (like Termius / MobaXterm) |
| **Nessus** | `/vulns/` | Vulnerabilities of the management networks from Tenable Vulnerability Management: findings, hosts, scans, remediation tracking |

The UI of Snapshot Restore and ACI is unchanged; only their sign-in, Users and Credentials pages moved to the portal.

**ACI product templates** (Fabric → Templates): the paths that OpenStack Cloud, VMware Cloud, RHOSO and products added by users
fill in on Static Port, per site. Administrators and accounts with the permission **Fabric Manager: edit product templates**
(Users page, under ACI; never part of "all modules") add and remove physical / port-channel and vPC paths with the same
tools as the binding table (Search APIC, Interface range, Bulk text, Blank row), add products, or reset a product to the
shipped template (`product_templates.json`, in production `/etc/ops-portal/product_templates.json`). Every path
added must exist in that site's fabric (`fabricPathEp`, read from APIC). A save changes only the portal database
(`aci_templates`, `aci_products`), never APIC, and is recorded in History (action *Product template*, before and after)
and in the activity log (`static_port.template_saved`, `static_port.product_added`, ...).

**ACI interfaces** (Fabric → Interfaces, per site): every port of every leaf (`l1PhysIf`, `ethpmPhysIf`) with what uses
it — a vPC or port-channel (`pcAggrIf`, `pcRsMbrIfs`, the vPC pairs of `fabricExplicitGEp`), an interface selector and its
access / PC / vPC policy group (`infraHPortS`, `infraPortBlk`, `infraRsAccBaseGrp`, the leaf profiles), the static paths
of EPGs and L3Outs on it, and what is connected (LLDP / CDP). Search finds a port on every leaf (for example `eth1/23`),
a server, a policy group, an EPG or a VLAN; **Static port** (or ticked ports) puts the right path in the Static Port table:
the port itself, its port-channel, or its vPC (once for both leaves). A port in no selector is *Free*: a binding on it
raises a fault on APIC until a policy group is set on it. **vPC pairs** lists the vPCs of each pair of leaves and the
ports free on both (for a new vPC). Read-only on APIC (GET); Export CSV.

**ACI Create vPC** (Fabric → Create vPC, per site; ADR-004 phase 2): a new vPC on a vPC pair of leaves, as in Fabric →
Access Policies on APIC: a vPC interface policy group (`infraAccBndlGrp lagT=node`, settings copied from a vPC of the
pair: AAEP, LACP, link level, CDP, LLDP, MCP) and its interface selector with the port blocks, in the interface profile of
the pair (the same ports on both leaves) or in the profile of each leaf. Review checks it on APIC again (pair, free ports,
unused name, policies, unused selector name), History records it before the single POST to `uni/infra`
(action `access-policy`), and the new path `protpaths-<a>-<b>/pathep-[<name>]` goes to Static Port with one button. The
portal only adds: it never changes or deletes a policy group, selector or port, and a vPC is not undone from History.
Creating needs the permission *Fabric Manager: create vPCs* (`aci-interfaces`, Users page) or an administrator; the APIC service
account of the site needs write rights on `uni/infra`. Entry points on Interfaces: *Create vPC* on a vPC pair, or on free
ports ticked on both leaves of a pair.

**Guides**: every page of the portal modules ends with a fold *Guide* that shows, with an animation on a copy of the page
as it is now (its own data and dialogs), how the page is used (`static/guide.js`, `modules/<id>/static/guides.js`).
Snapshot Restore has two: Volume, Snapshot and Target project (with the OpenStack volume, its instance and the other disks
of that instance), and, while the wizard is on Review, the Review step (Cinder pool, attach, a new instance with its
networks, commands, launch). They follow the volume in the wizard, else the newest check of the session
(`GET /restore/api/guide`, jobs that already ran); a guide never starts a job.

**ACI IP usage** (Fabric → IP Usage, per site): the endpoint IPs APIC learned on each EPG (Client Endpoints: `fvCEp`,
`fvIp`, `fvRsCEpToPathEp`), the gateways of its bridge domain / EPG subnets, the free addresses and up to 10 suggested
free IPs. An address is in use when it is a gateway or learned on any endpoint of the site's fabric; every learned IP is
kept in `aci_ip_seen`, and a free address seen in the last 30 days (`FABRIC_IP_RECENT_DAYS`) is never suggested.
Read-only on APIC; Export CSV.

**Shell** (`/terminal/`, module `shell`; it needs Runbook Automation for its hosts and SSH credentials): terminals in the
browser, laid out like Termius / MobaXterm. The host tree lists, per site and product, the OpenStack management host and
director (through the management host, as the checks reach it; overcloud nodes from there with `ssh tripleo-admin@…`),
the ONTAP cluster (account `ontap:<site>`), APIC (`apic:<site>`), the hosts groups of sites.yml (their read-only key)
and every host of Runbook Automation → Hosts & SSH (its own credential, jump host or web proxy), except ESXi hosts
(VMware Cloud stays read-only from the portal). The portal server runs
`ssh` on a pseudo-terminal with the stored account; the browser only sends a host id, the keys typed and the terminal
size (`modules/shell/targets.py`, `sessions.py`). Tabs, up to four panes (drag a tab onto a pane), favorites and recent
hosts, a status bar, copy on select, paste with `⌘V` / `Ctrl+Shift+V` / the right-click menu (several lines are shown
before they are pasted; a paste never ends with Enter, so nothing runs by itself; right-click pastes at once on
Windows and Linux like MobaXterm, Shift+right-click or a Mac opens the menu; terminal answers to old output drawn again after a reload are not sent to the host), snippets (own ones, or shared by an administrator), light or dark terminal. **Become root** types `sudo -i`;
with a credential "sudo with the login password" that may run fixes, the portal answers that account's own sudo prompt
(the password is never shown). Access: the module **Shell** on the Users page, never part of "all modules";
administrators always. Which hosts: an operator opens only the hosts an administrator gave the account on **Shell →
Access** (a whole site, a product of a site including hosts added to it later, or single hosts; `shell_access` table),
nothing by default; administrators open every host. A rule can be permanent or temporary (until a time, at most 90 days,
with a ticket or reason). Taking a host away, or a temporary rule running out, ends its open sessions within about 15
seconds; every change is in the activity log (`shell.access`). Optional Duo step-up, **off by default** (Duo SSO can
time out on a slow link): with `sso.step_up_minutes` set (for example 240), **opening a terminal, joining a session and
Become root** need a new Duo SSO sign-in in a popup (`max_age=0`, `prompt=login`; the ID token's `auth_time` must be
new), valid that many minutes in that portal session. Local accounts (break-glass) are exempt and the activity log says
so. Every session is in the activity log (`shell.open`, `shell.close`, `shell.failed`, `shell.root`,
`shell.terminate`, `shell.watch`, `shell.join`) and in **Session history** with its recorded output
(`TERMINAL_KEEP_DAYS`, default 30 days; text download): operators see their own sessions, administrators every session;
administrators can watch an open session of another user live (read-only), join it (type too; for help or a takeover)
or end it. The
user of the session sees who watches or joined (status bar, notice), and the recording gets a note of the portal. A session ends when ssh exits,
after `TERMINAL_IDLE_MINUTES` (30) without input or output, `TERMINAL_DETACHED_MINUTES` (10) after its last page closed,
`TERMINAL_MAX_HOURS` (12), and when the portal restarts (installing a package ends every open shell: the home page counts
them as running). Limits: `TERMINAL_MAX_PER_USER` (8), `TERMINAL_MAX_SESSIONS` (20). xterm.js 5.5.0 is vendored under
`modules/shell/static/vendor/xterm/` (MIT).

**Nessus** (`/vulns/`, module `nessus`; details in Indonesian: [docs/NESSUS.md](docs/NESSUS.md)): the findings of
Tenable Vulnerability Management (cloud.tenable.com, the Nessus scanner linked at every site) kept in the portal for
remediation tracking. A sync (one at a time, in the background) reads a vulnerability export of what changed — the first
one the last 90 days, then since the last successful sync minus an hour; severities `VULNS_SEVERITIES` (default low to
critical) — and keeps every finding with its state (open, reopened, fixed) in `nessus_findings`, every sync in
`nessus_syncs` and a trend point per site and severity in `nessus_trend`. *Sync now*, or by itself when a page opens and
the last sync is older than `VULNS_SYNC_HOURS` (6; 0 = never by itself). Pages: Overview (per site: open per severity,
reopened, fixed in 30 days, trend, scanner online or not), Findings (per plugin with its hosts, or every finding; filters,
CSV), Hosts and one host (output and solution of every finding), Scans and one scan (status, scope, last run, schedule,
hosts, history). Site of a scan: `tenable.scanner` of sites.yml; site of a finding: the `tenable.networks` that holds its
address (else *Other*). Administrators and operators with the permission **Vulnerability Scans: launch and stop scans**
(`nessus-scan`, never part of "all modules") launch and stop existing scans and run **Verify fix** (the scan of the
host's site with `alt_targets` = that one IPv4 address); the portal never creates or edits a scan. Hard rule: a scan is
launched only when every target is inside the management networks of its site (`tenable.networks`); an address, network
or range outside them, a host name, no target list, or a site without networks is refused, for administrators too
(`nessus.refused`); stopping is always allowed. Every launch, stop and verify needs the scan name (or the IP) typed and is
in the activity log (`nessus.launch`, `nessus.stop`, `nessus.verify`, `nessus.sync`, `nessus.sync_failed`). The API keys of
one Tenable user are the service account `tenable` on Administration → Credentials (access key = username, secret key =
password); the portal reaches cloud.tenable.com through `VULNS_PROXY` (the Squid of the bastion, `ops-portal.env`).
**How to fix it** (`modules/nessus/remedy.py`): every finding comes with a fix plan built from the finding itself — the
platform from the asset's operating system, the installed and fixed versions parsed from the plugin output, numbered
steps with where they run and their commands (apt / dnf with the packages of a USN or RHSA and the kernel reboot order,
Windows KBs, Cisco advisories, SSH algorithms on Linux / IOS / IOS XE / NX-OS / IOS XR / APIC, SSL/TLS on Windows SCHANNEL
/ nginx / Apache / Cisco, Telnet / HTTP / FTP, "Installed version / Fixed version", else Tenable's solution), the patch and
exploit facts, the vendor links and Tenable's own solution; ESXi is "not from this portal". Commands are shown only and
carry only values of the finding, each checked against a strict pattern; the device commands follow the Internal VA Q3
2026 runbooks. With the Web Terminal module, *Open a terminal* links to Shell when the account may open that host there. The CSV
has the columns *Fixed version* and *Fix*.

## Sign-in, users, module access

- Same sign-in as before (`portal_auth.py`): Active Directory (LDAPS or Duo Authentication Proxy), Duo Universal
  Prompt, Duo SSO, and local portal accounts. **One** user list and **one** set of service accounts for all modules.
- **Administration → Users**: role (administrator / operator) and, per operator, the **modules** it may use (e.g. an
  L1 operator: Runbook Automation only). Administrators use every module. A module the account may not use is shown greyed out
  on the home page and answers "No access" (HTTP 403 on its API).
- **Administration → Credentials**: service accounts grouped per module — APIC (`apic:<site>`), ONTAP (`ontap:<site>`,
  used for restores and, GET only, by Runbook Automation), and the **read-only** accounts of Runbook
  Automation (`ro-vcenter`, `ro-nsxt` per site, `vcd-reader` for every site) together with the **address** of each of these
  systems (IP or DNS name, optional port; set and changed here, it replaces the host in `sites.yml`). When an address
  changes, the password must be entered again (a stored password only goes to the address it was entered for). Each is
  tested when it is saved. What the read-only accounts need: [docs/WI-CHECK-ACCESS.md](docs/WI-CHECK-ACCESS.md).
- **Activity** (on the Users page): sign-ins, changes of users and credentials, every restore, every ACI change and
  every troubleshooting check, with filters and CSV export.

## Runbook Automation

The catalog ([modules/wi/catalog.yml](modules/wi/catalog.yml)) lists **every work instruction of the Knowledge Base**
and what the portal does for it:

| Status | Meaning |
|---|---|
| Ready | The check runs (read-only) |
| Planned | Designed; waits for access, a client or a lab validation (e.g. WinRM, NVOS commands) — the reason is shown |
| Manual (WI) | Nothing to read automatically (a change, a customer device, a VM that does not boot): the WI is the guide |
| Portal module | Done by another module (Snapshot Restore, ACI) |

How to use:
1. **Products**: pick the site in the masthead, then a product in the left menu (one expandable group per product with
   its problems: OpenStack Cloud, NetApp, VMware Cloud, CDN, DNS, network, SIEM, Linux VM, GB200, File Box). Each product has
   its own page; **All products** shows a card per product and a search across products by alert name or WI title.
   Each problem links the WI pages, what the check reads (OpenStack, ONTAP read-only, SSH to a host group, …) and
   whether it can run on this site; **Where it reads** draws the path from the portal to the system that is checked.
2. **Run**: fill in what the alert gives (IP and port, instance ID, project, host of the alert such as
   `172.31.138.67:9100` — only hosts listed in sites.yml can be chosen), then **Run check**.
3. **Where it was checked**: a diagram of the systems that were read (portal → management host → director →
   OpenStack, ONTAP, vCenter, vCloud Director, NSX-T, the host over SSH) and the object checked (volume, instance, VM,
   edge), each with its result; hover a system for the steps read there.
4. **Result per step**: one line per WI step — OK, warning, problem found, not checked (missing access) or info — with
   the evidence (tables, command output) under it. **How to fix it** gives the fix for what was found: the commands
   with the real values of this run (volume and instance IDs, target pool, PIDs, files, firewall rule numbers and
   handles, prefixes) and where to run them (director, host, VyOS/Huawei CLI, NSX Manager, PowerCLI). The portal never
   runs them. **Copy ticket note** gives a plain-text summary with the fixes for the operational ticket.
   **Output** is the full Ansible log, like an AWX job.
5. **Where to look**: the screens an engineer opens to check the same thing by hand, drawn with the values of the run —
   the terminal of the host or director (the commands the check ran and their output, secrets masked; OpenStack JSON
   shown as the client's table), Horizon of RHOSP, vCloud Director (tenant/provider portal, NSX-T edges), vSphere
   Client, NSX Manager and ONTAP System Manager. Numbered marks point at what was found, the notes say what to do there.
   **After the fix · expected** shows the same screen once How to fix it is done (new IP, new rule, new quota, LIF on
   its home port, VMs moved…) so the reader learns the fix, not only the button; after a fix run from the portal,
   **After fix #N · as it ran** shows its real output. Built by modules/wi/wi_analysis/screens.py; each console is an
   isolated iframe styled after the real console (VMware Clarity CSS, Horizon RCUE look; see modules/wi/static/consoles).
6. **Run this fix**: on a host of **Hosts & SSH** whose credential may run fixes (and on ONTAP for the cluster
   management LIF), the fix of a result runs from the portal for administrators and operators with the permission
   "run fixes": the exact commands are shown first; nothing runs before a pre-check (the check again, read-only) and an
   engineer's approval on **Fix reviews** (permission "review fixes", never one's own request); then the requester has
   **Run now** for 15 minutes, a high-risk fix needs the host name typed, the check runs again afterwards. The
   automatic actions of alert rules do not wait for a review (the owner approves them on the rule). OpenStack fixes need the permission "run OpenStack fixes"; VMware Cloud (VMware) stays read-only.
   Fixes with **ticked items** (checkbox table: instances to migrate off a compute, images to clean up, Cinder volumes to
   migrate) run the ticked items one after the other, never together (one migration or image clean-up job per site);
   each item is an operation of modules/wi/wi_analysis/wi_ops.py on the director that checks it again, changes it,
   follows it until it ends and fixes what is safe (next destination / pool, abort a stalled migration, reset to
   ACTIVE only after virsh, clean the temporary copy of a failed volume migration). Progress shows per item. See
   docs/WI-CHECK-ACCESS.md and docs/WI-COVERAGE.md.
7. **Runs** lists every check by every user (filters, CSV export).
8. **Platform health** (checks not from a KB page, label "Platform health"): OpenStack services and agents, bare metal
   nodes as ironic reads them through the BMC (director with stackrc), vCenter alarms / events / hardware, NSX-T alarms
   and transport nodes, and the hardware of a server from its BMC. Every finding links to the primary vendor's
   documentation (**Vendor reference**: Red Hat, Broadcom, Lenovo, Inspur; verified links in
   modules/wi/wi_analysis/references.py). See docs/WI-COVERAGE.md.
9. **Export** of a result: **CSV** (every table of the steps — CPU / memory / disk / pool values and their status — and
   the fixes) and a printable **PDF** report (light, A4: Print → Save as PDF).
10. **BMC** (administrators): the BMC of each server (management IP of its web page, vendor) and the BMC web accounts,
   one account for many BMCs, password encrypted. Checks read a BMC with Redfish over HTTPS (GET only, not SSH).
11. **Log collection** (permission *Runbook Automation: collect logs*, administrators always): **Raw output (.zip)** of
   every run (each command / REST path and its full output, the Ansible log, the full output of each fix, event logs as
   CSV); **Collect logs** (every log line of a time window on chosen overcloud nodes, rotated files included, secrets
   masked on the node, one .tar.gz per node in one bundle); **sos report** for Red Hat support (up to 4 nodes, one after
   the other); full exports of the **BMC event logs**, **ONTAP EMS** and **vCenter events**. Files are kept 7 days on the
   portal server (`RUNBOOK_FILES_KEEP_DAYS`), then deleted. See docs/WI-COVERAGE.md.
12. **Alerts** (Grafana, or Prometheus Alertmanager; `modules/wi/alerts.py`): Grafana sends its alerts to
   `POST /runbook/api/alerts/grafana` (contact point *Webhook*) with the token of a **source** (one per Grafana or team, shown
   once, stored as a hash; `Authorization: Bearer <token>`, optionally only from given addresses). A **rule**
   (administrators) matches the alert name and labels, takes the site (fixed or from a label) and runs its checks (one
   or more, each with parameters from the labels such as `{{labels.instance|host}}`, each its own run) at once, as the
   account `grafana`; the same check of a rule waits its cooldown. A check of a rule can have an **automatic action**:
   a fix its results offered runs by itself one item at a time (live migrations smallest first), measured after each
   by a check of the rule, until the problem of its target is gone, at most N items per alert, stopping at the first
   failure. A customer-impacting fix (OpenStack, ONTAP, VyOS, ticked items, deletes, restarts, firewall, network or
   package changes) runs only with the owner's approval recorded on the rule (approver, ticket); never on a site the
   administrators list as frozen (optional, none by default), on VMware Cloud / ESXi, or in a database. One action per
   target at a time, at most N an hour per rule, once per target every 6 hours. The portal only receives: the alerting stays in Grafana, and
   what each alert did is on the page Alerts and in Runs. See docs/GRAFANA-ALERTS.md.

Safety:
- OpenStack commands go through the same path as Snapshot Restore (management host → director → `overcloudrc`), but a
  command that is not `list` / `show` / `get-pools` / `quota show` / `limits show` is refused before it is sent.
- ONTAP, vCenter, NSX-T and vCloud Director are read with read-only accounts, GET only (vCenter and vCloud Director
  open and close a session). The vCenter inventory (host load, VMs, resource pools, DRS) is read with pyVmomi through
  the PropertyCollector only. Host commands are fixed read commands; the operator only chooses a host of sites.yml and
  validated parameters (no free text reaches a shell).
- Overcloud nodes are read from the director (ssh heat-admin / tripleo-admin to the ctlplane address): only the fixed
  read commands of modules/wi/wi_analysis/overcloud.py (pcs status, stonith history, cluster_status, chrony, log lines)
  with validated arguments; passwords in log lines are masked.
- The undercloud (stackrc) only answers `openstack baremetal node list / show`, `openstack server list`, `metalsmith list`
  and `/etc/rhosp-release`; BMC reads are Redfish GET under
  /redfish/v1 with the BMC web account, and stop after the first refused sign-in (no lock-out burst).
- Passwords reach Ansible only in the process environment; never in the vars file, arguments or log.
- Log collection (`wi_analysis/wi_collect.py`, run with sudo on the node through the director) only reads log files and
  the journal, or runs `sos report`; the archive is streamed node → director → management host → portal server, so
  nothing stays on the way. The arguments are validated (`wi_analysis/logs.py`); no text from the browser reaches a shell.

Adding a check: an entry in `catalog.yml` and a class in `modules/wi/wi_analysis/` (what to read per phase, how to rate
it); the playbook `modules/wi/playbooks/run_check.yml` is the same for every check.

## Demo on a laptop

```bash
python3.14 -m venv .venv && .venv/bin/pip install -r requirements.txt
./test_mode.sh
```

Opens http://localhost:8483 with mock APICs, mock ONTAP clusters, a mock vCenter / NSX-T / vCloud Director, a fake
vCenter inventory, a fake OpenStack director, a mock Tenable (Nessus),
fake SSH hosts and a fake Active Directory — nothing real is touched. The script prints the demo accounts and what to
try. `DEMO_DUO=1`, `DEMO_SSO=1` and `MOCK_REJECT=DCC` work as in the old demos.

## Tests

```bash
.venv/bin/python -m unittest tests.test_portal_auth tests.test_wi tests.test_aci -v
.venv/bin/python -m unittest tests.test_nessus -v      # Nessus against tests/mock_tenable.py (seconds)
.venv/bin/python -m unittest tests.test_ontap -v      # about 10 minutes: Ansible really runs
```

## Files

| Path | |
|---|---|
| `app.py`, `core.py` | Flask app, module registry, portal routes (`/`, `/api/session`, `/healthz`) |
| `portal_auth.py` | sign-in, users, module access, encrypted service accounts |
| `settings.py`, `sites.py`, `jobs.py` | paths (`PORTAL_*` environment variables), sites.yml, Ansible job runner |
| `templates/shell.html`, `static/shell.js`, `static/portal.css` | sign-in, home (card view), Users, Credentials |
| `static/switcher.js`, `static/switcher.css` | application launcher used by every module |
| `modules/<id>/` | one Flask blueprint per module — contract in [MODULES.md](MODULES.md) |
| `sites.example.yml`, `auth.example.yml` | configuration of every module, sign-in |
| `test_mode.sh`, `tests/` | demo and tests (mocks and fakes) |

Deployment on the bastion (one service, port 8483 during the pilot, 8480 after the cutover) comes after the demo is
approved; see ADR-003, action items.

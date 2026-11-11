# Nessus (Tenable Vulnerability Management) in the portal

The module **Nessus** (`/vulns/`) shows the vulnerabilities that Tenable Vulnerability Management (cloud,
`https://cloud.tenable.com`) finds with the Nessus scanner linked to each site (DCB, DCA, DCC). The portal keeps the
findings itself for **remediation tracking**: what is still open, what came back (reopened), what is fixed, and the
trend per site. Operators with the permission can also **launch and stop existing scans** and run **Verify fix** for
one host. The portal never creates, changes or deletes a scan: that stays in Tenable.

Code: `modules/nessus/` (`tenable.py` API client, `scope.py` site and network rules, `findings.py` tables, `sync.py`
synchronisation, `remedy.py` How to fix it). Tests: `tests/test_nessus.py` with `tests/mock_tenable.py`.

## What it does

| Page | Content |
|---|---|
| **Overview** | One card per site: open findings per severity (Critical, High, Medium, Low), Reopened, Fixed in the last 30 days, number of hosts, trend per sync, scanner state (online / offline). A severity tile opens Findings with that filter. A card **Other** for addresses outside the networks of every site. |
| **Findings** | One row per plugin with its number of hosts and state; a row opens to show its hosts. Or **Every finding** (one row per host and plugin). Filters: text (host, IP, plugin, CVE), minimum severity, state. **Export CSV** (every row of the filter, with synopsis and solution). |
| **Hosts** / one host | Hosts with findings, the worst first. The host page: its operating system, every finding with **How to fix it** (see below), the scanner output (at most 8 KB) and plugin details, and the buttons **Verify fix** and **Open a terminal** (Shell). |
| **Scans** / one scan | The Tenable scans of the site's scanner: state, scope (see the rule below), last run, schedule; the hosts of the last run and the history. **Launch** / **Stop** for those allowed. |

Every page has a **Guide** fold (an animation of how to use the page; it sends no change).

## How to fix it

Every finding has a remediation plan, **How to fix it**, that the portal builds from the data of that finding
(`modules/nessus/remedy.py`). It shows in three places:

- the host page, when a finding row is opened;
- Findings → a plugin row opened: the plan for its first host (each host page has the plan with its own versions);
- Findings → **Every finding**, when a row is opened.

The portal **only shows** the commands. An operator, the network team or a Windows administrator runs them. Changes
that may affect customers need the owner's approval and a window.

A plan has:
- **Title and reason**: what is fixed (for example "Update 3 packages (USN-6608-1) and reboot") and the synopsis.
  A public exploit is mentioned.
- **Patch facts**: platform (from the asset's OS in Tenable), "Patch since <date>" or "No patch: a configuration
  change", and "Exploit available" / "No known exploit".
- **Versions**: package / product, installed version and fixed version, read from the plugin output.
- **Numbered steps**: each step says where it runs ("On 10.248.0.11 (SSH, an account with sudo)", "On the device …
  (network team)", "PowerShell as administrator", "From the bastion"), then its commands in a code block with a copy
  button.
- **Notes, Tenable says, and links**: the notes always name approval / window and Verify fix. "Tenable says" is the
  plugin's own solution. The links are the vendor advisories (see_also) and the plugin page on tenable.com.
- **Open a terminal**: shown when the Web Terminal module is on, the account may use Shell, and the host address is a Shell
  host that account may open. Shell cannot open a host from a link yet, so the button opens `/terminal/` and names the
  host to pick (site · group · name).

The rules, checked in this order:

| Kind of finding | Plan |
|---|---|
| Local Security Checks Ubuntu/Debian, RHEL/CentOS/Rocky/Alma/Oracle (USN, RHSA, …) | Packages and versions from the output ("Installed package / Fixed package" or "Remote package installed / Should be"). Ubuntu: `apt-get install --only-upgrade <package>`; a new kernel ABI uses `apt-get install <new package>`. RHEL: `dnf update` (`yum` on release 7). Kernel: reboot one node at a time, a node that does **not** hold the VIP first (check `/var/run/reboot-required` / `needs-restarting -r`). Other packages: restart the services (`needrestart` / `needs-restarting -s`). |
| Windows : Microsoft Bulletins | KB number and the files not patched yet. Check with `Get-HotFix`, install through WSUS / Windows Update (or the .msu from the Microsoft Update Catalog), then reboot in a window. |
| CISCO (advisory) | Installed and fixed release and the bug IDs. Upgrade by the network team (window, approval). For the IOS XE Web UI (CVE-2023-20198/20273): turn the web server off and check the accounts and logs. |
| Weak SSH algorithms, CBC, MAC, KEX, Terrapin, SSHv1 | The algorithms Tenable found are named. Linux: a drop-in `/etc/ssh/sshd_config.d/50-strong-algorithms.conf`, then `sshd -t` and reload (Terrapin: update OpenSSH first). IOS/IOS XE: `ip ssh server algorithm …`. NX-OS: `ssh ciphers/macs/kexalgos …`. IOS XR: `ssh server algorithms …`. APIC: Management Access policy (GUI). Check from the bastion: `ssh -o Ciphers=<old algorithm> …` must be refused. |
| SSL/TLS: TLS 1.0/1.1, SSLv2/3, SWEET32/RC4, certificates | Windows: SCHANNEL (export the registry first, then reboot). Linux: nginx / Apache (`ssl_protocols`, `SSLProtocol`), find the service with `ss -ltnp`. Cisco: `no ip http secure-server` or TLS 1.2 only. NX-OS: NX-API. APIC: Management Access policy. Ports 49152/49153/9003/9020/8481 on an APIC cannot be set by the operator: a TAC case and an OOB contract. Certificates: a 2048-bit CSR with the address in the SAN. Check with `openssl s_client -connect <ip>:<port> -tls1`. |
| Telnet, management HTTP, FTP | IOS: `transport input ssh` (only after an SSH login works), `no ip http server`. NX-OS: `no feature telnet`. IOS XR: `no telnet vrf … server`. Linux: `systemctl disable --now`. Windows: `Stop-Service`. Check the port from the bastion. |
| Output "Installed version / Fixed version" | "Upgrade <product> from X to Y or later", with the package it came from (`dpkg -S` / `rpm -qf <path>`). With a note on distribution backports. |
| ESXi | Not from this portal (VMware Cloud is read-only): the VMware team uses vSphere Lifecycle Manager. |
| Other | The solution from Tenable and its links. |

Only values of the finding itself go into a command: address, port, package name, version, algorithm / cipher suite
name and KB number. Every value is checked against a strict pattern. No other text of the plugin output ever goes into
a command, so a strange output cannot become a shell command.

**Export CSV** has the columns **Fixed version** (the version or KB that fixes it) and **Fix** (a short plan, for
example "Update linux-image-5.15.0-94-generic, linux-libc-dev; reboot").

## Required rule: management networks only

The Nessus scanners are used for the management addresses of each site only. The portal enforces it, **also for
administrators**:

- **Launch** runs only when **every** target of the scan (read from Tenable at launch, `info.targets`) is shown to be
  inside the `tenable.networks` of the scan's site. Refused (HTTP 400, the message names the target) when:
  - an address, network (CIDR) or range (`a.b.c.d-a.b.c.e` / `a.b.c.d-e`) is outside these networks, also when only
    part of it is (a CIDR larger than the network, a range across its edge);
  - a target is a host name (it cannot be checked before the scanner resolves it);
  - the scan has no target list (target group, tag);
  - the scan's scanner belongs to no site, or the site has no `tenable.networks`.
- **Verify fix**: `alt_targets` is exactly one IPv4 address inside the management networks of the scan's site, and
  that address must be a host with findings of that site in the portal.
- **Stop** is always allowed for those with the permission (stopping a scan is safe).
- Every refusal is recorded in the activity log as `nessus.refused`.

On the page Scans, the column **Scope** shows *Management only* (allowed) or *Not launchable* with the reason (the
Launch button is off). The confirmation dialog writes "This scan only covers the management networks of <site>: …".

## Configuration

### 1. Tenable API keys (Administration → Credentials)

Create an API user in Tenable (best a user for the portal only), generate its API keys, and enter them in the portal
on **Administration → Credentials**, target **Tenable Vulnerability Management (access key / secret key)**:

| Field | Value |
|---|---|
| Username | **access key** |
| Password | **secret key** (stored encrypted, never shown or logged) |

After saving, the portal tests the connection at once (`GET /session` and `GET /scanners`), for example:
`Connected to Tenable as svc-portal@…: 3 scanners (3 online)`. The API user needs to see every scanner and the assets
of the sites (for the vulnerability export) and to run (Can Execute) the scans that will be launched from the portal;
no permission to change or delete scans is needed.

Note: the access key shows as the "username" on the Credentials page and in the activity log `credential.set` (as for
every credential). The access key alone cannot sign in; the secret key is never shown.

### 2. Proxy (`/etc/ops-portal/ops-portal.env`)

When the portal server reaches `cloud.tenable.com` only through a proxy:

```text
VULNS_URL=https://cloud.tenable.com
VULNS_PROXY=http://<proxy address>:3128
```

`install.sh` adds both lines (values from the package) to the server's env file when it has none; values already
there are not changed. They can also be set at install: `sudo VULNS_PROXY=http://<proxy address>:3128 bash
.../install.sh`. An empty `VULNS_PROXY` = a direct connection. The server's `http(s)_proxy` variables are not used.
The proxy must allow `CONNECT cloud.tenable.com:443`. When the proxy inspects TLS with its own CA, set
`VULNS_CA_FILE=<CA file>`.

### 3. sites.yml: scanner and management networks per site

The scanners linked in Tenable (Settings → Sensors → Linked Scanners), for example `tenable-scanner-dcb` (group
`SG-DCB`), `tenable-scanner-dca`, `tenable-scanner-dcc`. The networks below are examples: write the real management
networks of each site.

```yaml
sites:
  DCB:
    tenable: {scanner: "tenable-scanner-dcb", groups: ["SG-DCB"], networks: ["172.26.40.0/24", "172.26.102.0/24"]}
  DCA:
    tenable: {scanner: "tenable-scanner-dca", networks: ["..."]}
  DCC:
    tenable: {scanner: "tenable-scanner-dcc", networks: ["..."]}
```

- `scanner`: the name of the site's Nessus scanner exactly as in Tenable (case does not matter). A scan belongs to the
  site whose scanner runs it.
- `groups` (optional): the scanner groups that scanner is in (Sensors → Scanner Groups). A scan run through a group
  records the group name instead of the scanner name, so the group name must be listed on its site too.
- `networks`: **the management networks the scanner of this site may scan**. Only this list is used by the launch
  rule and Verify fix.
- An entry that is not a network is shown as a warning on the Overview (administrators).

**The site of a finding** is decided in this order:

1. **Network**: the site whose `networks` hold the host address (the longest prefix when they overlap). The host page
   writes for example "network 10.248.0.0/24".
2. With no matching network, **the scanner that found it**. The Tenable export gives every finding `scan.uuid` (the
   run) and `scan.schedule_uuid`. The portal matches them with the Tenable scan list and each scan's scanner
   (`info.scanner_name`, kept in the table `nessus_scanners`). The finding goes to the site whose `scanner` or `groups`
   names that scanner. The host page writes "found by scanner tenable-scanner-dcb".
3. When neither matches, the finding goes to **Other**, for example hosts found by a Tenable cloud scanner (APAC Cloud
   Scanners, US East Cloud Scanners and so on), because no site names that scanner. The card Other on the Overview
   shows which scanners found its hosts.

A host is always in one site. A host found by scanners of several sites goes to the site with the most findings.

The placement runs again by itself whenever `networks`, `scanner` or `groups` in sites.yml change, and after every
sync. After an upgrade that adds these columns, the next sync reads the last 90 days once more, so that older findings
get their scan data too.

So filling in `scanner` and `groups` first is enough, for example
`tenable: {scanner: "tenable-scanner-dcb", groups: ["SG-DCB"]}`. Findings go to their site even before `networks` is
filled in.

**Networks seen (administrators, site card on the Overview).** For each site, the portal shows the /24 networks of the
hosts its scanner found, with their number of hosts, while `networks` is empty or does not hold them all. When a site
names no scanner at all, the portal uses the scanners whose name contains the site name (for example
`tenable-scanner-dcb` and `SG-DCB` for DCB) and marks them as a guess.

The portal also prepares a line ready to copy into sites.yml, for example:

```yaml
tenable: {scanner: "tenable-scanner-dcb", groups: ["SG-DCB"], networks: ["172.26.40.0/24", "..."]}
```

This is **only a suggestion to check**. The networks seen here are **not** used for launch or Verify fix until an
administrator writes them into `/etc/ops-portal/sites.yml`. Check with the network team first: a host a scanner
found is not necessarily in a management network.

**Proposal from the scan targets (administrators, page Scans).** The Scans page also shows the private IPv4 targets of
the site's scans that `networks` does not cover yet, exactly as written in the scan, with their sites.yml line. Public
addresses are never proposed. A scan of a scanner that belongs to no site gets a site guessed from the scanner name.

**Writing the networks (operator, with sudo).** Run `tools/nessus-sites-networks.py`, copied to the bastion as
`~/nessus-sites-networks.py`:

```text
sudo python3 ~/nessus-sites-networks.py DCB 172.26.32.0/24,172.26.112.0/23,172.26.252.0/24            # shows the diff only
sudo python3 ~/nessus-sites-networks.py DCB 172.26.32.0/24,172.26.112.0/23,172.26.252.0/24 --apply    # writes
```

- Only the `tenable: {...}` line of the named site changes.
- `networks` is replaced with exactly the list given.
- Only private IPv4 networks are accepted.
- Before writing, the tool makes a backup `sites.yml.bak-<time>`. When the result is not valid YAML, the backup is
  restored.
- Several sites at once: `DCB <networks> DCA <networks> DCC <networks>`.
- The portal reads the file again by itself. After **Refresh**, scans with targets inside those networks can be
  launched, including new scans created later in Tenable.

### 4. Permissions (Administration → Users)

| Who | Can |
|---|---|
| Module **Nessus** | See every page, Sync now, Export CSV |
| Permission **Vulnerability Scans: launch and stop scans** (`nessus-scan`) | Launch, Stop, Verify fix. Never part of "all modules": it must be ticked |
| Administrator | Always everything, but still bound to the management-network rule |

Every Launch / Stop asks for the **scan name typed**, Verify fix for the **address typed**, and the dialog warns that a
scan can load or disturb the scanned devices (BMCs, switches, storage controllers, old devices).

### 5. Other variables (optional)

| Variable | Default | Meaning |
|---|---|---|
| `VULNS_SYNC_HOURS` | `6` | An opened page starts a sync by itself when the last sync is older than this; `0` = manual only |
| `VULNS_SEVERITIES` | `low,medium,high,critical` | The severities exported (not info) |
| `VULNS_EXPORT_POLL_SECONDS` | `5` | Pause between export status checks |
| `VULNS_EXPORT_MAX_MINUTES` | `30` | How long to wait for an export |
| `VULNS_CA_FILE` | (empty) | An extra CA for TLS (a proxy that inspects TLS) |

## How a sync works

1. One sync at a time, in a background thread of the portal (it goes on when the page is closed; the home page shows
   it as a running job, so the updater waits for it).
2. The first sync asks for the findings changed in the **last 90 days**; later syncs since the start of the last
   successful sync minus 1 hour. States: OPEN, REOPENED, FIXED.
3. The portal waits for the export (`QUEUED` → `PROCESSING` → `FINISHED`), reads each chunk as soon as it is ready and
   stores the findings (key: asset uuid + plugin id + port + protocol).
4. At the end: a trend point per site and severity (active, reopened, fixed in 30 days) and the activity
   `nessus.sync` with the counts (`… findings received: N new, N fixed, N reopened`). On failure:
   `nessus.sync_failed` with the reason; an automatic sync is tried again after 15 minutes.
5. Requests to Tenable: 30-second timeout, retried (at most 3 times) on 429 or 5xx, honouring `Retry-After`. A POST
   that gets a 500 is not repeated (it may have been processed).

## Database tables

`nessus_findings`, `nessus_syncs`, `nessus_trend`, `nessus_meta` and `nessus_scanners` (scan or run → scanner) in the
portal database. The plugin output is cut at 8 KB per finding. For How to fix it, `nessus_findings` also keeps
`see_also`, `has_patch`, `patch_date`, `exploit`, `description` (4 KB), `plugin_type`, `os` and `fqdn`. For the site
placement it keeps `scan_uuid`, `schedule_uuid`, `scan_started`, `scanner` and `site_via` (the network or scanner that
placed it). These columns are added to older tables (ALTER TABLE) at start; the next sync then reads the last 90 days
once more, so that older findings get this data too.

## Security

- The secret key is only in the `X-ApiKeys` header of requests to Tenable; never in an error message, log, activity
  log, API answer or module table (checked by `test_zz_secret_never_leaks`).
- The portal does not create or change scans and does not change the Tenable configuration.
- Launch, stop, verify and refusals are recorded in **Activity** (filter "Nessus" on the page Users).

## Demo and tests

- `./test_mode.sh`: a mock Tenable on `http://127.0.0.1:9481` with the scanners `nessus-dcb-01`, `nessus-dca-01`
  (online) and `nessus-dcc-01` (offline). The second sync shows remediation (fixed, new, reopened). The account
  `operator` has `nessus-scan`, `l1` can only look.
- `.venv/bin/python -m unittest tests.test_nessus -v` (a few seconds, no network other than 127.0.0.1).

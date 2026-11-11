# Runbook Automation: read-only account per system

Runbook Automation only **reads**. To make sure the target system guarantees this, and not only the portal, each system is
read with a service account that has no right to change anything. Operators still log in to the portal with their own AD
accounts; the history (Runs and Activity) records who ran each check.

| System | Account | Rights | Filled in at |
|---|---|---|---|
| ONTAP (per site) | existing Snapshot Restore account (`ontap:<site>`) | Runbook Automation only sends GET (and ONTAP fixes run by an authorized operator); there is no separate ONTAP account | Administration → Credentials → `ontap:<site>` |
| vCenter (per site) | e.g. `wi-readonly@vsphere.local` | built-in **Read-only** role, set at the vCenter root, *Propagate to children*. Used for the REST API and for the host / VM / resource pool / cluster inventory (pyVmomi, PropertyCollector only) | `ro-vcenter:<site>` (the vCenter address is entered in the same dialog) |
| vCloud Director (**one for all sites**: one vCloud serves DCB, DCA, DCC) | e.g. `wi-readonly@System` (provider account, written as `user@System`) | a new provider role that contains only **View** rights (VM, vApp, task, Org VDC, network, edge gateway, IPsec, NAT, firewall, cell, Certificate Library, Trusted Certificates). Do not use *System Administrator* | `vcd-reader` (the vCloud Director address is entered in the same dialog) |
| NSX-T Manager (per site) | e.g. `wi-readonly` | **Auditor** role | `ro-nsxt:<site>` (the NSX Manager address is entered in the same dialog) |
| OpenStack | same path as Snapshot Restore (management host → director → `overcloudrc`) | the portal only allows the commands `list` / `show` / `get-pools` / `quota show` / `limits show` (other commands are rejected before they are sent) | `sites.yml` (`mgmt`, `director`) |
| Linux hosts (CDN, DNS, repo, VM, collector, GB200) | `runbook-ro` with an SSH key | regular user + the limited sudoers below | `sites.yml` → `hosts.<group>` |
| VyOS | `runbook-ro` | VyOS 1.4/1.5 no longer has the *operator* user level: restrict it through `command=` in authorized_keys or use it only in a lab first | `hosts.vyos` |
| Huawei RCGW | `runbook-ro` | monitoring-level user (privilege level 1), `display` only | `hosts.huawei` |
| ESXi | `runbook-ro` | ReadOnly role on the host; SSH only if it is actually enabled | `hosts.esxi` |

vCenter, NSX-T and vCloud Director are read through their APIs (login to their portal/API, not SSH). Their address (IP or DNS name,
optionally with `:port`, always HTTPS) is entered by the administrator in **Administration → Credentials** together with the account, and can be
changed there at any time; the address on that page replaces `host` in `sites.yml`. When the address is changed, the password must
be typed again: a stored password is only sent to the address it was entered for.

A host that has no IP the portal can reach (e.g. a CDN node behind an LB) is added in **Hosts & SSH** with
**Connect through**: pick a jump host (another host on the same site that is reached directly, e.g. the LB). The portal logs in to the jump
host with that jump host's credential, then from there opens SSH to the target host with the target host's credential (`ssh -W`,
one hop). A jump host with a password uses `sshpass` on the portal server.

The portal server (bastion) has no direct route to the internet: its Windows default gateway is 172.26.32.1 (management path,
not changed). The public networks that checks target are sent to pfSense (172.26.32.242) with one route per network on the
Windows bastion; pfSense passes and NATs the bastion traffic (172.26.32.100 → 11.9.218.251):

| Site | Public networks (route to 172.26.32.242) |
|---|---|
| DCA | 11.12.198.0/24, 11.11.254.0/23, 11.13.246.0/23, 11.14.143.0/24, 11.12.199.0/24 |
| DCB | 11.7.252.0/23, 11.9.229.0/24, 11.15.194.0/24, 11.8.246.0/23 |
| DCC | 11.14.145.0/24 |

New network: add its route on the bastion (PowerShell as Administrator):
`New-NetRoute -InterfaceAlias Ethernet0 -DestinationPrefix <network/prefix> -NextHop 172.26.32.242`.

Alternative without routes (not used at present): SSH to the **public address** through the pfSense Squid proxy (`RUNBOOK_SSH_PROXY=172.26.32.242:3128` in
`/etc/ops-portal/ops-portal.env`, HTTP CONNECT with `nc -X connect`); private addresses still go direct, and
hosts behind a jump host are reached by their jump host. Squid must allow CONNECT to the SSH port: in pfSense
**Services → Squid Proxy Server → ACLs → Squid Allowed Ports**: add `22` to **ACL SafePorts** and **ACL SSLPorts**
(other SSH ports too, if any). Without this, the Test button shows "The web proxy … refused the SSH connection (HTTP 403)".

The vCenter check "Host high CPU / memory, VM resource pool" needs the `pyvmomi` package in the portal venv
(`requirements.txt`). Without it the step fails with a clear message; other checks are not affected.

The OpenStack Cloud check "OVN FDB learning" reads the OVN Southbound DB through the `ovn_controller` container of the compute
the instances run on, or of the next node when that compute does not answer SSH from the director (the compute of another
instance, then a controller; the node used and the ones that did not answer are in the step "OVN Southbound DB") (from the director, user `heat-admin` / `tripleo-admin`, passwordless sudo: the same access as the
overcloud checks): only `ovn-sbctl --no-leader-only find/list` (datapaths, port bindings, FDB) and, when asked, a few
seconds of `tcpdump` on the tap of the instances (the `tcpdump` package must be on the compute; without it the capture step
says so). The fix "Clear the ticked FDB entries" writes to the Southbound DB (`ovn-sbctl destroy fdb <uuid>`, without
`--no-leader-only`) and needs the permission **run OpenStack fixes**. The fix "Turn port security on for the ticked ports" (the
same permission, type the number of ports) uses the overcloudrc admin account on the director: it makes the security group
`port-security-allow-all` in the project of the port when it is missing (every protocol in and out), runs
`openstack port set --enable-port-security` with the VIPs of the form as allowed address pairs, then on that node reads
the port binding (`unknown` must be gone) and clears the FDB entries recorded on that port. The port binding is also read
before the change: when the node does not answer, the port is not changed at all.

The check "Internal certificates" uses the read-only accounts that exist already. The vCenter certificate API
(`certificate-management/vcenter/...`) needs only `System.Read` (the Read-only role), and the ESXi host certificates are
read from vCenter (no SSH to the hosts). NSX uses the Auditor role, ONTAP the `ontap:<site>` account, and vCloud Director
the provider account with the right to view the Certificate Library and the Trusted Certificates. Without that right the
step is skipped with HTTP 403. A system without an account is skipped; the check still runs. The Solution User
certificates of vCenter are not in the API (only `vecs-cli` through root SSH on the VCSA, which the portal does not use);
the recommendation gives that command to an engineer. The check "certmonger certificates" runs `sudo -n getcert list` as
`stack` on the director and `getcert list` on the overcloud nodes (sudo without a password, the same access as the
overcloud checks). The fix "Resubmit the ticked certificates" (permission **run OpenStack fixes**, a plain confirmation
since it deletes nothing) runs, for each ticked request and one at a time: `getcert list -i <id>` (the request read
again; a node that does not answer or a request that is gone = nothing changed), `getcert resubmit -i <id>`, then
`getcert list -i <id>` every 10 seconds until it is MONITORING with a new expiry (5 minutes at most). A request that stays
CA_UNREACHABLE / CA_REJECTED / stuck counts as failed, its old certificate stays in place, and the next item still runs.
Requests with a CA problem are not ticked by default (fix the reach to IdM first). The director's own requests stay
commands for an engineer.

ONTAP example:

```
security login create -user-or-group-name wi-readonly -application http -authentication-method password -role readonly
```

## Sudoers for `runbook-ro` (Linux hosts)

The catalog uses only read commands. Save it as `/etc/sudoers.d/runbook-ro` and check it with `visudo -cf`.
Do not add `runbook-ro` to the `docker` group (equivalent to root); allow only the docker commands below.

```
Cmnd_Alias RUNBOOK_DISK   = /usr/bin/du -sk /run/aide, /usr/bin/find /run/aide -type f, /usr/bin/du -xsk *, \
                       /usr/bin/stat -c %s /var/log/haproxy.log, /usr/bin/lsof -nP +L1, /usr/bin/du -sk /var/log/syslog*
Cmnd_Alias RUNBOOK_CDN    = /usr/bin/docker ps -a, /usr/bin/docker stats --no-stream, \
                       /usr/bin/docker exec lb sh -c grep -iA3 prometheus /usr/local/etc/haproxy/haproxy.cfg, \
                       /usr/sbin/nginx -t, /usr/bin/grep -nE database_size|filename|size /var/lib/mse/mse.conf, \
                       /usr/bin/varnishstat -1, /usr/bin/varnishadm ping, /usr/bin/stat -c %s %U\:%G %a /cache/mse/store.dat
Cmnd_Alias RUNBOOK_LOGS   = /usr/bin/grep -HsE *, /usr/bin/grep -rhsE *, /usr/bin/tail -n 2000 /var/log/syslog, \
                       /usr/bin/journalctl -u rsyslog -n 300 --no-pager, /usr/sbin/rsyslogd -N1
Cmnd_Alias RUNBOOK_NET    = /usr/bin/ss -H -lntup, /usr/sbin/nft -a list ruleset, /usr/sbin/iptables-save, /usr/sbin/ufw status numbered, \
                       /usr/bin/firewall-cmd --list-ports, /usr/sbin/semanage port -l, /usr/sbin/ethtool *, /usr/bin/dmesg
runbook-ro ALL=(root) NOPASSWD: RUNBOOK_DISK, RUNBOOK_CDN, RUNBOOK_LOGS, RUNBOOK_NET
```

Binary paths differ between distros (`/usr/sbin` vs `/usr/bin`): adjust them with `command -v <command>` on the host.
A host without sudoers can still be used with `sudo: false`; steps that need root then show as failed
with a permission message, instead of being skipped silently.

## What is logged

- Runs: every check is recorded before it runs (AD user, site, host, parameters), together with the result per step
  and the Ansible output. CSV export on the Runs page.
- Activity (Administration → Users): `wi.run`, `wi.ok`, `wi.warn`, `wi.fail`, `wi.error`.
- Service account passwords never enter logs, vars files, or process arguments (only the environment of the Ansible process).

## Direct fixes from check results (SSH and ONTAP)

Besides reading, the portal can run a **fix** from a check result (the *Run this fix* button under *How to fix it*).
Only the commands that the analysis generates for that result are run, with the values that were found; text from the browser is
never run. Every manual fix first goes through a **pre-check and an engineer's review** (see below).

| Requirement | Details |
|---|---|
| Who | Administrator, or an operator with **Runbook Automation: run fixes** checked on the Users page. "All modules" does not include this permission |
| Host | Hosts on the **Hosts & SSH** page whose SSH credential has *May run fixes* checked. Hosts from `sites.yml` stay read-only |
| SSH credential | Private key (no passphrase) or password, stored encrypted (portal vault), never shown again. Root: root login, sudo NOPASSWD, or sudo with the login password |
| Result age | Fixes only from results younger than 120 minutes (`RUNBOOK_FIX_MAX_AGE_MINUTES`): old values may have changed |
| High risk | Delete files/logs, kill/restart/stop a service, reboot, mkfs, VyOS commit, bounce a link: the operator must type the host name |
| Review | A fix does not run at once: pre-check, then an engineer's review, then **Run now** by the requester within 15 minutes. See "Pre-check and engineer review" |
| After the fix | The same check is run again automatically; its result is linked under the fix. Everything is recorded in Runs and Activity (`wi.fix`, `wi.fix_ok`, `wi.fix_failed`) |
| OpenStack | Separate permission **Runbook Automation: run OpenStack fixes**. Only changes from the allowlist `wi_analysis.OPENSTACK_FIX`, run on the director as admin (`overcloudrc`); the condition is re-checked right before changing. Deleting: type the ID/name |
| Checked items | Fixes with a checkbox table (live/cold migration of instances from one compute node, delete images, migrate Cinder volumes, resubmit certmonger certificates): only the checked items run, each with its own command from the stored result (the browser only sends the row numbers). One at a time, never in parallel; one migration / volume migration / image clean-up job per site. Items that delete: type the count and the kind ("3 images"). Job timeout = number of items × timeout per item (max. 24 hours) |
| No fix | VMware Cloud (VMware/vCloud) stays read-only (needs a human check); Huawei uses a change request |

### Pre-check and engineer review

The flow: pre-check, then an engineer's review, then the operator runs the fix within a short time.

1. The operator presses **Run this fix**, then **Ask for review** in the dialog. Nothing changes yet. The portal runs the
   same check again with the same parameters (the **pre-check**, read-only). Its run shows in Runs like any run, with
   "pre-check of fix request #N" in Activity.
2. The pre-check passes when its new result still offers the same fix: the same kind, target, button and commands.
   A trailing `   # ...` comment of a command is not compared, because it only shows values such as the age of a
   snapshot. The ticked items must still be there with the same commands and able to run, and the requester must still
   have the fix permission. Then the request is **Waiting for review**. Otherwise it is **Pre-check failed**, with why
   (for example the problem is gone, or the commands changed).
3. An engineer opens **Fix reviews** (History menu), reads the commands and the pre-check, then chooses **Approve** or
   **Reject**. A rejection needs a note. An engineer is an administrator or an account with **Runbook Automation:
   review fixes** (`wi-fix-review`) checked on the Users page. "All modules" does not include this permission.
   **Nobody reviews their own request, administrators included.**
4. Once approved, the requester has **Run now** for **15 minutes** (default). Administrators can change it on Fix
   reviews, 5 to 30 minutes; 60 minutes was refused as too long. Run now never lasts past the age limit of the pre-check
   (120 minutes). After that the request is **Expired** and needs a new pre-check and review. A request still waiting
   for review also expires once its pre-check is older than 120 minutes.
5. **Run now** runs the fix of the pre-check's result, that is the commands that were reviewed, and the fix shows on the
   run it was asked from. The typed confirmation of a high-risk fix is asked at Run now. The re-checks inside a fix
   (OpenStack `require` / `wait`) still run right before the change. Only the requester can press Run now, and one fix
   has at most one open request. The requester can **Withdraw** a request that has not run.
6. Exception: the automatic actions of alert rules (robot account `grafana`) do not go through this gate, because the
   owner's approval is recorded on the rule ([GRAFANA-ALERTS.md](GRAFANA-ALERTS.md)). The change steps of a template are
   a fix and **do** go through it. The console test (one Enter key after a fix) and Cancel of a migration do not.
7. Activity: `wi.fix_request`, `wi.fix_precheck`, `wi.fix_approve`, `wi.fix_reject`, `wi.fix_withdraw`,
   `wi.fix_expired`, `wi.fix_review_settings`, then `wi.fix` with the request number and the reviewer.
8. Metric for Grafana: `ops_fix_reviews_waiting{site}` on `/runbook/api/alerts/metrics`, so the engineers can be told that
   a review is waiting.

## Log collection (*collect logs* permission)

| Requirement | Details |
|---|---|
| Who | Administrator, or an operator with **Runbook Automation: collect logs** checked on the Users page. This permission is also needed for the **Raw output (.zip)** and **Download log bundle** buttons |
| Overcloud nodes | The same access as the overcloud checks (`heat-admin` / `tripleo-admin` from the director, passwordless sudo). The node needs `python3` (RHEL 9) or `/usr/libexec/platform-python` (RHEL 8), `gzip`, `base64`; sos report needs the `sos` package, and on a controller `sudo -n pcs property config stonith-enabled` (fencing is checked before a sos report) |
| Node disk | Collect logs: ≥ 1 GB free in `/var/tmp` (temporary file per log, deleted immediately). sos report: ≥ 5 GB (10 GB with all logs) |
| Portal server | Bundles are kept for 7 days in `/var/lib/ops-portal/wi-files/bundles/`; a run is rejected if free disk is < 5 GB or the bundles are > 40 GB |
| BMC, ONTAP, vCenter | The same accounts as the other checks (BMC web account, Snapshot Restore account, vCenter read-only account); GET / read only |

ONTAP cluster health: reverts the `cluster_mgmt` LIF to its home port (and brings it up if it is down) through REST with the Snapshot
Restore account of that site (`ontap:<site>`), using the cluster management address or, if that does not answer, the node management address.

Example credential for fixes on Linux (limited sudo NOPASSWD is impractical because the fix commands vary; use a
dedicated, audited account):

```
useradd -m -s /bin/bash wi-fix
echo 'wi-fix ALL=(root) NOPASSWD: ALL' > /etc/sudoers.d/wi-fix && chmod 440 /etc/sudoers.d/wi-fix
```

VyOS: an account with configuration rights (user `vyos` or equivalent). ESXi: `root` (fixes use `esxcli`).

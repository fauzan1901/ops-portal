# Operation Automation: read-only account per system

Operation Automation only **reads**. To make sure the target system guarantees this, and not only the portal, each system is
read with a service account that has no right to change anything. Operators still log in to the portal with their own AD
accounts; the history (Runs and Activity) records who ran each check.

| System | Account | Rights | Filled in at |
|---|---|---|---|
| ONTAP (per site) | existing ONTAP Restore account (`ontap:<site>`) | Operation Automation only sends GET (and ONTAP fixes run by an authorized operator); there is no separate ONTAP account | Administration → Credentials → `ontap:<site>` |
| vCenter (per site) | e.g. `wi-readonly@vsphere.local` | built-in **Read-only** role, set at the vCenter root, *Propagate to children*. Used for the REST API and for the host / VM / resource pool / cluster inventory (pyVmomi, PropertyCollector only) | `ro-vcenter:<site>` (the vCenter address is entered in the same dialog) |
| vCloud Director (**one for all sites**: one vCloud serves DCB, DCA, DCC) | e.g. `wi-readonly@System` (provider account, written as `user@System`) | a new provider role that contains only **View** rights (VM, vApp, task, Org VDC, network, edge gateway, IPsec, NAT, firewall, cell, Certificate Library, Trusted Certificates). Do not use *System Administrator* | `ro-vcd` (the vCloud Director address is entered in the same dialog) |
| NSX-T Manager (per site) | e.g. `wi-readonly` | **Auditor** role | `ro-nsxt:<site>` (the NSX Manager address is entered in the same dialog) |
| OpenStack | same path as ONTAP Restore (management host → director → `overcloudrc`) | the portal only allows the commands `list` / `show` / `get-pools` / `quota show` / `limits show` (other commands are rejected before they are sent) | `sites.yml` (`mgmt`, `director`) |
| Linux hosts (CDN, DNS, repo, VM, collector, GB200) | `wi-ro` with an SSH key | regular user + the limited sudoers below | `sites.yml` → `hosts.<group>` |
| VyOS | `wi-ro` | VyOS 1.4/1.5 no longer has the *operator* user level: restrict it through `command=` in authorized_keys or use it only in a lab first | `hosts.vyos` |
| Huawei RCGW | `wi-ro` | monitoring-level user (privilege level 1), `display` only | `hosts.huawei` |
| ESXi | `wi-ro` | ReadOnly role on the host; SSH only if it is actually enabled | `hosts.esxi` |

vCenter, NSX-T and vCloud Director are read through their APIs (login to their portal/API, not SSH). Their address (IP or DNS name,
optionally with `:port`, always HTTPS) is entered by the administrator in **Administration → Credentials** together with the account, and can be
changed there at any time; the address on that page replaces `host` in `sites.yml`. When the address is changed, the password must
be typed again: a stored password is only sent to the address it was entered for.

A host that has no IP the portal can reach (e.g. a CDN node behind an LB) is added in **Hosts & SSH** with
**Connect through**: pick a jump host (another host on the same site that is reached directly, e.g. the LB). The portal logs in to the jump
host with that jump host's credential, then from there opens SSH to the target host with the target host's credential (`ssh -W`,
one hop). A jump host with a password uses `sshpass` on the portal server.

The portal server (bastion) has no direct route to the internet: its Windows default gateway is 172.26.0.1 (management path,
not changed). The public networks that checks target are sent to pfSense (172.26.0.242) with one route per network on the
Windows bastion; pfSense passes and NATs the bastion traffic (172.26.0.100 → 11.7.90.251):

| Site | Public networks (route to 172.26.0.242) |
|---|---|
| DCA | 11.10.134.0/24, 11.9.190.0/23, 11.11.214.0/23, 11.12.15.0/24, 11.10.135.0/24 |
| DCB | 11.5.244.0/23, 11.7.101.0/24, 11.13.130.0/24, 11.6.214.0/23 |
| DCC | 11.12.17.0/24 |

New network: add its route on the bastion (PowerShell as Administrator):
`New-NetRoute -InterfaceAlias Ethernet0 -DestinationPrefix <network/prefix> -NextHop 172.26.0.242`.

Alternative without routes (not used at present): SSH to the **public address** through the pfSense Squid proxy (`WI_SSH_PROXY=172.26.0.242:3128` in
`/etc/ops-portal/ops-portal.env`, HTTP CONNECT with `nc -X connect`); private addresses still go direct, and
hosts behind a jump host are reached by their jump host. Squid must allow CONNECT to the SSH port: in pfSense
**Services → Squid Proxy Server → ACLs → Squid Allowed Ports**: add `22` to **ACL SafePorts** and **ACL SSLPorts**
(other SSH ports too, if any). Without this, the Test button shows "The web proxy … refused the SSH connection (HTTP 403)".

The vCenter check "Host high CPU / memory, VM resource pool" needs the `pyvmomi` package in the portal venv
(`requirements.txt`). Without it the step fails with a clear message; other checks are not affected.

The Acme Flex check "OVN FDB learning" reads the OVN Southbound DB through the `ovn_controller` container of the compute
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

## Sudoers for `wi-ro` (Linux hosts)

The catalog uses only read commands. Save it as `/etc/sudoers.d/wi-ro` and check it with `visudo -cf`.
Do not add `wi-ro` to the `docker` group (equivalent to root); allow only the docker commands below.

```
Cmnd_Alias WI_DISK   = /usr/bin/du -sk /run/aide, /usr/bin/find /run/aide -type f, /usr/bin/du -xsk *, \
                       /usr/bin/stat -c %s /var/log/haproxy.log, /usr/bin/lsof -nP +L1, /usr/bin/du -sk /var/log/syslog*
Cmnd_Alias WI_CDN    = /usr/bin/docker ps -a, /usr/bin/docker stats --no-stream, \
                       /usr/bin/docker exec lb sh -c grep -iA3 prometheus /usr/local/etc/haproxy/haproxy.cfg, \
                       /usr/sbin/nginx -t, /usr/bin/grep -nE database_size|filename|size /var/lib/mse/mse.conf, \
                       /usr/bin/varnishstat -1, /usr/bin/varnishadm ping, /usr/bin/stat -c %s %U\:%G %a /cache/mse/store.dat
Cmnd_Alias WI_LOGS   = /usr/bin/grep -HsE *, /usr/bin/grep -rhsE *, /usr/bin/tail -n 2000 /var/log/syslog, \
                       /usr/bin/journalctl -u rsyslog -n 300 --no-pager, /usr/sbin/rsyslogd -N1
Cmnd_Alias WI_NET    = /usr/bin/ss -H -lntup, /usr/sbin/nft -a list ruleset, /usr/sbin/iptables-save, /usr/sbin/ufw status numbered, \
                       /usr/bin/firewall-cmd --list-ports, /usr/sbin/semanage port -l, /usr/sbin/ethtool *, /usr/bin/dmesg
wi-ro ALL=(root) NOPASSWD: WI_DISK, WI_CDN, WI_LOGS, WI_NET
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
never run.

| Requirement | Details |
|---|---|
| Who | Administrator, or an operator with **Operation Automation: run fixes** checked on the Users page. "All modules" does not include this permission |
| Host | Hosts on the **Hosts & SSH** page whose SSH credential has *May run fixes* checked. Hosts from `sites.yml` stay read-only |
| SSH credential | Private key (no passphrase) or password, stored encrypted (portal vault), never shown again. Root: root login, sudo NOPASSWD, or sudo with the login password |
| Result age | Fixes only from results younger than 120 minutes (`WI_FIX_MAX_AGE_MINUTES`): old values may have changed |
| High risk | Delete files/logs, kill/restart/stop a service, reboot, mkfs, VyOS commit, bounce a link: the operator must type the host name |
| After the fix | The same check is run again automatically; its result is linked under the fix. Everything is recorded in Runs and Activity (`wi.fix`, `wi.fix_ok`, `wi.fix_failed`) |
| OpenStack | Separate permission **Operation Automation: run OpenStack fixes**. Only changes from the allowlist `wi_analysis.OPENSTACK_FIX`, run on the director as admin (`overcloudrc`); the condition is re-checked right before changing. Deleting: type the ID/name |
| Checked items | Fixes with a checkbox table (live/cold migration of instances from one compute node, delete images, migrate Cinder volumes, resubmit certmonger certificates): only the checked items run, each with its own command from the stored result (the browser only sends the row numbers). One at a time, never in parallel; one migration / volume migration / image clean-up job per site. Items that delete: type the count and the kind ("3 images"). Job timeout = number of items × timeout per item (max. 24 hours) |
| No fix | Acme Prime (VMware/vCloud) stays read-only (needs a human check); Huawei uses a change request |

## Log collection (*collect logs* permission)

| Requirement | Details |
|---|---|
| Who | Administrator, or an operator with **Operation Automation: collect logs** checked on the Users page. This permission is also needed for the **Raw output (.zip)** and **Download log bundle** buttons |
| Overcloud nodes | The same access as the overcloud checks (`heat-admin` / `tripleo-admin` from the director, passwordless sudo). The node needs `python3` (RHEL 9) or `/usr/libexec/platform-python` (RHEL 8), `gzip`, `base64`; sos report needs the `sos` package |
| Node disk | Collect logs: ≥ 1 GB free in `/var/tmp` (temporary file per log, deleted immediately). sos report: ≥ 5 GB (10 GB with all logs) |
| Portal server | Bundles are kept for 7 days in `/var/lib/ops-portal/wi-files/bundles/`; a run is rejected if free disk is < 5 GB or the bundles are > 40 GB |
| BMC, ONTAP, vCenter | The same accounts as the other checks (BMC web account, ONTAP Restore account, vCenter read-only account); GET / read only |

ONTAP cluster health: reverts the `cluster_mgmt` LIF to its home port (and brings it up if it is down) through REST with the ONTAP
Restore account of that site (`ontap:<site>`), using the cluster management address or, if that does not answer, the node management address.

Example credential for fixes on Linux (limited sudo NOPASSWD is impractical because the fix commands vary; use a
dedicated, audited account):

```
useradd -m -s /bin/bash wi-fix
echo 'wi-fix ALL=(root) NOPASSWD: ALL' > /etc/sudoers.d/wi-fix && chmod 440 /etc/sudoers.d/wi-fix
```

VyOS: an account with configuration rights (user `vyos` or equivalent). ESXi: `root` (fixes use `esxcli`).

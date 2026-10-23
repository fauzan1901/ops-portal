# WI Knowledge Base Coverage in Operation Automation

Reviewed on 10 October 2026 against the "Knowledge Based" KB (81 pages): 59 WIs contain procedures, 22 pages are indexes (Readme)
or empty (`Request Handling`, `NO.docx`). OpenStack commands were matched against the official Red Hat OpenStack
Platform 16.2/17.1 documentation and the upstream python-openstackclient / python-cinderclient.

Meaning of the **Fix in portal** column:

- **Yes**: the check result has a *Run this fix* button (a command with the values that were found, run by the portal, after
  which the check is repeated automatically). Permission: *run fixes* (SSH host, ONTAP) or *run OpenStack fixes* (Acme Flex).
- **Type the name**: a fix that deletes; the operator types the ID/name of the object before it runs.
- **Command**: the portal shows the full command with the values, and a person runs it (decision: Acme Prime/VMware and
  Huawei stay read-only; steps in the Service Portal have no API).
- **Manual**: the procedure cannot be read or automated from the portal (rescue console, customer device, Service Portal).

## Acme Flex (OpenStack)

| WI | Check | Fix in portal |
|---|---|---|
| Cinder Volume Over 80% | Cinder volume over 80% | Yes, **choose volumes (checkbox)**: migrate one volume at a time to the cheapest pool (waits until it finishes before the next volume; max. 40 per run). Volumes that have snapshots are also offered (not ticked automatically): their snapshots are deleted first (only those seen at check time; a new snapshot stops the fix), then the volume is migrated — type the number of volumes ("2 volumes"). If the migration fails: the temporary replica (`migration_status target:<id>`) is reset and deleted automatically, then the next pool is tried. Delete snapshots older than 14 days per volume (type the volume name) |
| WI_custom_port_tcp_down | Custom port TCP down, Service not answering | Yes: start the instance, security group rule; restart the service on the host (SSH) |
| Backup Scheduler Does Not Run Snapshots | Volumes on an old volume type | Yes: `cinder retype --migration-policy on-demand` per project, one volume at a time (waits for the status to return and `migration_status success` before the next volume; max. 10 per run). Re-add scheduler: Service Portal (manual) |
| Floating IP Cannot Be Attached to a VPC Instance Interface | Instance cannot be reached | Command (Floating IP / NAT Gateway through the Service Portal) |
| Failed to Create a New Instance | Project quota full | Yes: `openstack quota set` (after Sales approves) |
| IP Route on VyOS Does Not Show the Static Route | VyOS static route | Yes (VyOS over SSH); re-add in the Service Portal stays manual |
| Instance Stuck in Building Status | Instances or volumes stuck | Type the name: delete instances that are still `BUILD` |
| Instance Cannot Connect Through the Metro Network | Instance cannot be reached | Yes: live migration (client ≥ 3.19); report the ACI path to the Network team |
| Instance Cannot Connect (SSH, HTTPS, Ping) (*Instance Cannot Connect (SSH, HTTPS, Ping)*) | Instance cannot be reached | Yes: start, TCP/ICMP security group rule |
| Rollback Volume Type | Instances or volumes stuck | Type the replica ID: reset the replica, delete the replica, reset the original volume |
| Volume Snapshot Error on the Backend | Volumes on an old volume type | Yes: retype |
| Storage Cannot Be Re-Attached (pointer) | Volume cannot be attached again | Yes (see the row below) |
| VM Fails to Resize Root Disk | Project quota full, Volumes on an old type | Yes: quota, retype |
| VM Not Synchronized in the Service Portal | Instance cannot be reached (status and ID) | Manual: Sync Instance in the Service Portal |
| VPN Problem (IPsec & OpenVPN) (*VPN Problem (IPsec & OpenVPN)*) | — | Manual: the customer's pfSense, OpenVPN user in the Service Portal |
| VPN Cannot Connect (Handshake Error) (*VPN Cannot Connect (Handshake Error)*) | — | Manual: the customer's pfSense certificate |
| Volume Cannot Be Re-Attached | Volume cannot be attached again, Instances or volumes stuck | Yes: detach, stop + detach (customer permission), reset to available only when there is no attachment; re-attach through the Service Portal |

Every OpenStack fix re-checks the condition right before it changes anything (`require` / `wait`): if the status is already
different from the time of the check, the fix stops and nothing is changed. Projects are shown by name (as in Horizon);
commands still use the ID.

### Operations on selected items (checkbox)

Three platform operations (not from KB pages) run the ticked items **one by one, never at the same time**
(one migration / image clean-up job per site). For each item `wi_analysis/wi_ops.py` runs on the director: it is re-checked,
changed, followed until it is done, and what is safe is repaired automatically. The result per item appears directly on the run page.

| Check | What runs | Automatic repair |
|---|---|---|
| Live migrate instances of a compute (choose the instances) | instances ticked by the operator (none is ticked automatically), each to the compute with the lowest usage whose CPU and RAM stay below the limit (default 70%, measured right before the migration; if there is none: skipped, exit 7); disable / enable nova-compute (optional, to empty a compute); `server migrate --live-migration [--host]` for ACTIVE, `server migrate` + `resize confirm` for SHUTOFF (OSC 5.5 on RHOSP 17.1; `nova live-migration` / `migration-list` on 16.2) | the destination refuses (no valid host, incompatible CPU, not enough resources, compute down, pre-check): the instance stays on the source, the next compute is tried (max. 3); not finished within the time limit: **abort** (default) or **force-complete**; an instance left in ERROR / MIGRATING with no migration running: `server set --state active` **only** if `virsh domstate` (through the director, ssh to ctlplane) shows the domain running on the compute recorded by Nova and not on another compute. PCI passthrough / vGPU / running tasks are not offered |
| Image housekeeping (size 0, deleted projects) | `image delete` (+ `volume snapshot delete` for boot-from-volume instance snapshots) | re-checked before deleting: still exists, not protected, not used by an instance, still size 0; snapshots in `error_deleting` are reset to available and then deleted once more |
| Cinder volume over 80% | see the row above | see the row above |

Items ticked by default: uploads that never finished (image), the largest volumes without snapshots that fit
(Cinder), all instances that can be moved (compute). Items that delete (images, volumes with snapshots) require
typing the number of items ("3 images").

## NetApp ONTAP

| WI | Check | Fix in portal |
|---|---|---|
| Restore Openstack Volume from a NetApp ONTAP Snapshot | ONTAP Restore module | Yes (own module) |
| WI NetApp Cluster Management Recovery | ONTAP cluster health | Yes: revert LIF `cluster_mgmt` |

## Acme Prime (VMware, vCloud Director, NSX-T) — read-only

| WI | Check | Fix in portal |
|---|---|---|
| Check the VM Resource Pool Correctly | Host high CPU / memory, VM resource pool | Command (`Move-VM` / `govc`) |
| Datastore Low Free Space | Datastore low free space | Command (Storage vMotion, snapshot, consolidation) |
| Host High CPU/Memory Usage | Host high CPU / memory | Command (vMotion, DRS) |
| Slow Power On/Off or Edit Action on a VM in vCloud | VM power on fails / inconsistent / slow tasks | Command (cell) |
| Error on VM Power On / IP Conflict / after NIC Change | VM power on fails | Command |
| VM in Inconsistent Status in vCloud | VM power on fails | Command |
| Metro PTP Connection, Service on a VM Not Reachable, IPSec State Down, VM Cannot Connect | Edge gateway (vCloud) | Command |
| WI_Configure_Priority_SNAT_Internet_Colo_MPLS_NSX-T | SNAT priority (NSX-T) | Command |
| WI troubleshooting firewall nsxt & linux | Port blocked on a Linux VM | Yes (Linux VM over SSH): insert a specific accept rule |
| NIC Error/CPU Upgrade (Error Name), VM Forgotten Password, Org & VDC Creation (*NIC Error/CPU Upgrade (Error Name), VM Forgotten Password, Org & VDC Creation*) | — | Manual (vCloud UI / request) |
| WI_IPSec_MikroTik_to_NSX-T | — | Manual (customer device) |

## Acme CDN, Acme DNS, VyOS, SIEM, GB200, Huawei, ACI, Acme Tolong, Acme Box

| WI | Check | Fix in portal |
|---|---|---|
| Disk Full Alert on /run | Disk full on /run | Yes |
| Alert Root Disk Troubleshooting | Root disk full | Yes (truncate logs, logrotate, journald) |
| Memory Alert CDN | Memory alert | Yes (restart varnish / lb, stop logparser) |
| Datasource Error | DatasourceError | Yes (start/restart the `lb` container) |
| cdn user alert repo | Repository site | Yes (nginx, certbot) |
| WI Resize Varnish MSE Cache | Varnish MSE pre-check | Pre-check; the resize still goes through a change (manual) |
| WI Recursive DNS Disk Log Full Alert | DNS recursor syslog | Yes (`quiet=yes`, restart, empty the syslog) |
| WI Troubleshooting SNAT DNAT VyOS 1.5, WI VyOS 1.5 NAT Static Route DNS Forwarder | VyOS SNAT/DNAT | Yes (VyOS configuration, commit/save; type the host name) |
| Inter-connection problem of the Metro link from the NAT Gateway (VyOS) (*Metro Link Interconnection Problems from the NAT Gateway (VyOS)*) | VyOS static route | Yes |
| WI VyOS Upgrade + CVE Mitigation | VyOS upgrade pre-check; **VyOS upgrade (image from the jump host)** | Yes: VyOS in Hosts & SSH (management IP, *Connect through* = the jumphost that holds the ISO, key credential). Steps: re-read, back up the config **to the jumphost** (`save` on VyOS, then the jumphost fetches `/config/config.boot` with scp to `/home/vyos/config-backup/<VyOS>/config.boot.<time>.before-<version>`, mode 600, sha256 compared; no copy stays on VyOS; the folder can be changed with a parameter), hw-id (an interface that is in the config but whose NIC is not installed / has no MAC is skipped with a warning; its config stays, and the check optionally suggests `delete interfaces ethernet ethX`; an hw-id that differs from the MAC still stops the upgrade), check the ISO on the jumphost (size, sha256), check the space (VyOS `/tmp` is in RAM, half the size of the VM's RAM; if the ISO does not fit, the ISO goes to disk automatically — the login user's home folder, the same partition as the image store — without resizing the VM, and it is deleted after the install; if the image store is short and its partition is the last ext4 partition: the partition + filesystem are enlarged online to the whole disk — `sfdisk -N`, `partx -u`, `resize2fs`, the old partition table is printed in the output — without a reboot if the space outside the partition is already visible; if not: the Room is set to **fail** with the notification "enlarge the VM disk (OpenStack/vCenter, not inside VyOS) by at least X GB", the Upgrade VyOS button does not appear, and *Disk enlarged: reboot, grow, upgrade* appears instead — VyOS is rebooted to read the new size, the partition is enlarged, and the upgrade continues; if the space is still short after the reboot, it stops before the install. Only for VyOS whose image store really is short), scp from the jumphost (the VyOS key is forwarded only for that command), sha256 on VyOS, `add system image` (all Yes/No questions are answered **Yes**, other questions use the default value/Enter — including replacing an image with the same name left over from a stopped installation; a question without Yes/No and without a default = stop; if the fix stops after scp, the ISO in /tmp is deleted because VyOS /tmp is in RAM), regenerate the dropbear key (CVE), reboot, SSH again every 15 seconds for max. 15 minutes (the boot ID must change), post-check against the baseline (version, MAC and **all** addresses of each interface — including a second IP on one interface —, a NIC that is not in the config (admin down) gets no hw-id but its name/MAC is checked to stay the same, gateway, routes, NAT, ping to the default gateway and the next hop of static routes — no internet address; they are also pinged before the upgrade, and one that did not answer from the start is not counted as a failure). `show system image` is read in the 1.3 format (numbered list) as well as 1.4+/2026.x (Name / Default boot / Running table). The reboot is detected from the boot ID (`/proc/sys/kernel/random/boot_id`). Afterwards *Roll back to <old image>* is available. Type the host name to confirm |
| WI_OpenStack_RHEL_Forward_Log_to_172.26.0.40_Port_541 | SIEM forwarder | Yes |
| WI Forward Log ESXi To RHEL Collector | SIEM collector, ESXi syslog | Yes |
| WI_NXLog_Windows_AD_and_Veeam_to_RHEL_Collector | SIEM collector (collector side) | Windows side: planned |
| SOP_CT_Linkdown_check | GB200 NIC link | Yes |
| SOP_NVLink_Status_Check_GB200 | — | Planned |
| WI-Adding-Internet-Subnet-Huawei-RCGW | Huawei BGP prefix | Command (read-only, changes go through a change) |
| WI Ansible Static Port ACI | ACI module | Yes (own module) |
| WI_Nginx_Port_Conflict | Service not answering / port conflict | Yes (stop/disable the conflicting service) |
| WI_Emergency_Mode_Recovery, WI_VM_Recovery_Poltekkes_Malang | — | Manual (rescue boot / console) |
| Technical Lessons Learned BPKAD Aceh Acmebox | — | Manual (reference) |

## Outside the KB: platform health

The checks below do not come from KB pages (label **Platform health** in the catalog). They all only read. Every finding
carries a **Vendor reference**: a link to the main vendor documentation. The list of links is in `wi_analysis/references.py`
and all of them were verified when they were added (11 October 2026).

| Check | Reads | Findings | Vendor reference |
|---|---|---|---|
| OpenStack services and agents | director (overcloudrc): `compute service list`, `volume service list`, `network agent list`, `ip availability list`, `network list --external`, `server list --host`, `floating ip list --network` | nova/cinder services down with the affected instances, dead OVN/OVS agents, old records of nodes that have been removed (not reporting for > 7 days and with no instances; kept separate from outages), floating IP pool almost full and unattached floating IPs per project | Red Hat RHOSP 16.2 and 17.1 (Compute node failures, containerized services, evacuate, Pacemaker resources, Block Storage HA, OVN, floating IP, removing compute, cinder-manage) |
| Bare metal nodes (BMC power state) | director (stackrc): `openstack baremetal node list --long` | nodes that are deployed but powered off, maintenance, fault `power failure` (the BMC does not answer: that controller also cannot be fenced) | Red Hat (power fault recovery, troubleshooting Bare Metal, fencing STONITH, RHEL fencing) |
| vCenter alarms, events and hardware | vCenter (read-only account, pyVmomi): triggered alarms, error/warning events for N hours, hardware sensors (CIM), datastore, snapshot/consolidation | critical alarms, host not responding, red sensors, datastore not accessible, APD/PDL, VMFS heartbeat, latency, uplink down, HA, failed vMotion, snapshots > 3 days | Broadcom KB 2004684, 2136081, 2007236, 1025279, 1002310, 1003409, 2004429, uplink redundancy, vSphere 8 alarms/host health |
| NSX-T alarms and transport nodes | NSX Manager API (read-only account): `/api/v1/alarms`, `/api/v1/cluster/status`, `/api/v1/transport-nodes/state` | OPEN/ACKNOWLEDGED alarms with the description and *recommended action* from NSX itself, manager cluster not STABLE, failed transport nodes | Broadcom NSX Event Catalog |
| Pacemaker and fencing (controllers) | controllers through the director (`ssh heat-admin`/`tripleo-admin` to the ctlplane address, node list from the undercloud): `pcs status --full`, `pcs stonith history`, `pcs property`, `corosync-quorumtool -s`, `rabbitmqctl cluster_status`, `chronyc tracking` | quorum, offline/unclean nodes, stopped/FAILED resources (Galera that is not Master), failed actions, stonith-enabled, stonith devices that are not running, fencing that failed or has happened, RabbitMQ partitions/alarms, time offset | Red Hat (Pacemaker resources, bundle status, Galera, fencing STONITH, fencing daemons, RHEL cleanup) |
| Overcloud logs (errors and known problems) | container logs (`/var/log/containers/...`), Pacemaker/corosync and kernel journal on the controllers (and the computes of the instance, or one node), last N hours, warning level and above | recognized patterns (RabbitMQ unreachable, port binding, network-vif-plugged, No valid host, Galera, NetApp, fencing, corosync, HAProxy down, OOM, conntrack full, hardware/I/O errors), other errors are grouped, request ID timeline from `server event list` | Red Hat per pattern |
| Overcloud node health (CPU, memory, disk, containers) | controllers/computes through the director: `df`, `free`, `/proc/stat` (2 seconds), load, `systemctl --failed`, largest processes, `podman ps -a` | CPU/memory/disk/inode above the threshold, failed `tripleo_*` units, unhealthy containers or containers that exited with an error (one-shot containers such as `*_init`/`*_db_sync` are not counted) | Red Hat (containerized services, Pacemaker resources) |
| Compute capacity (vCPU, RAM per hypervisor) | `openstack hypervisor list --long`, `compute service list --service nova-compute`, `aggregate list/show` | computes above the threshold relative to the allocation ratio (parameter, matching nova on the site), computes down, total remaining space, per compute and per aggregate (cause of "No valid host") | Red Hat (Compute node failures) |
| Live migrate instances of a compute (choose the instances) | `compute service list`, one `server list --all-projects --host <compute> --long` (no `server show` per instance, except client 4.x on RHOSP 16.2 for the project name), `flavor list --all --long`, `project list`; overcloud nodes from the undercloud (for virsh) | list of all VMs on that compute: status, flavor, boot, how to move (live / cold / cannot, and the reason: PCI passthrough, vGPU, running task, ERROR) and notes (local disk = block migration, CPU pinning/NUMA). The operator ticks the VMs to move. Destination: a compute whose **real CPU and RAM usage is below 70%** (parameter, default 70), measured directly on each compute (`/proc/stat` 2 seconds, `MemTotal - MemAvailable`), all at once through the director; the check result shows the current usage, and right before each migration it is measured again (RAM plus the RAM of the instance) and the lowest one is used. If none is below the limit: the instance is **not moved** (skipped) and the next instance still runs. Without allocation ratio | Red Hat RHOSP 17.1 (Migrating instances between Compute nodes), Nova (live-migrate: progress, abort, force-complete) |
| Image housekeeping (size 0, deleted projects) | `image list --long`, `image show`, `server list --long`, `volume snapshot list`, `project list` | images with size 0 (unfinished upload, empty active, boot-from-volume instance snapshots with their volume snapshots), images owned by deleted projects; those that are protected / used by an instance / newer than N days are only shown | — |
| ONTAP capacity | ONTAP REST (ONTAP Restore account): aggregate, FlexVol, snapshot, disk | aggregates/FlexVols above the threshold, snapshots exceeding the reserve, disks broken / in maintenance | — |
| Server resources (CPU, memory, disk) | one Linux server from Hosts & SSH (CDN, repo, DNS, SIEM, GB200, Linux VM, VyOS) | same as the overcloud nodes, without containers | — |
| Certificates expiring | TLS handshake from the portal server to vCenter, NSX-T, vCloud, ONTAP, Horizon and all BMCs (no account) | certificates that expire within N days, addresses that cannot be read | — |
| Server hardware (BMC) | BMC per server (the **BMC** page): Redfish GET over HTTPS to the management IP, BMC web account | health; PSU per unit (model, serial, firmware, input voltage/power; a PSU with no input is flagged) and redundancy; all fans and temperature sensors with their thresholds (the *Margin* sensor = distance to the maximum CPU temperature, the larger the safer; sensors with no reading or not installed are not counted); each DIMM (slot, size, type/speed, manufacturer, part number, serial, health); processors; RAID and drives; active alerts (Lenovo ActiveLog); hardware event log for N days by the BMC clock (Lenovo PlatformLog, Inspur SEL; the `YY-MM-DD` time format is read; events that are already *Deasserted* are shown as done, not as findings; old events / events without a time are counted separately), with the sensor, OEM details, and DIMM slot named by the event | Lenovo Docs per model (Memory/Power/Observable problems, list of XCC events with the FQXSP… IDs that were found), Inspur BMC User Manual |

BMC note: the address and account are entered by the administrator in **Operation Automation → BMC** (not SSH). An account
with the read-only role is enough. The check reads the system list first, so a wrong password only produces one failed
login per run. This matters because XCC locks an account after a few failed logins.

Access to the overcloud nodes (approved 11 October 2026): only fixed read commands (`wi_analysis/overcloud.py`,
validated arguments), SSH from the director with the director's own key. The user is `heat-admin` (16.x) or `tripleo-admin`
(17.x), determined from `/etc/rhosp-release` or `director.overcloud_user` in sites.yml. If a controller name does not
contain "controller", fill in `director.controllers`. Passwords in log lines (for example `rabbit://user:password@`) are masked.

## Log collection (*collect logs* permission)

Approved 19 October 2026. Only administrators and operators with **Operation Automation: collect logs** ticked on the
Users page can run the checks below and download the results. All files are stored on the portal server
(`/var/lib/ops-portal/wi-files/`) and are **deleted automatically 7 days** after they are created (`WI_FILES_KEEP_DAYS`). Collect logs
and sos report are refused if the portal server has < 5 GB of disk left (`WI_FILES_MIN_FREE_GB`) or the existing bundles are already > 40 GB
(`WI_BUNDLES_MAX_GB`). Every download is recorded in Activity (`wi.download`).

| Check / download | Reads | Result | Limit |
|---|---|---|---|
| **Raw output (.zip)** (button on every run) | everything that check reads | every command / REST path / probe with its full output (`reads/`), the result (`result.json`), the Ansible log, the full output of every fix from that result (`fixes/`), and the event log CSV (`export/`). Secrets are masked | fix output on the run page shows only the tail; the zip has it in full |
| Collect logs (overcloud nodes, full log bundle) | overcloud nodes through the director (`wi_collect.py` with sudo): container log files (nova, placement, libvirt/QEMU, neutron, OVN/OVS, cinder, glance, keystone, heat, Horizon, RabbitMQ, Galera, HAProxy, Pacemaker), `/var/log/messages`, Pacemaker/corosync/pcsd journal, kernel, iscsid/multipathd | **all lines** within the time range (1–72 hours, can end at a given hour), including rotated files (`.1`, `.gz`, `-YYYYMMDD`); tracebacks stay whole. One `.tar.gz` per node + `MANIFEST.txt` (lines, size, sha256 per file) in one `.tar` bundle | max. 12 nodes per run; 50–4096 MB per node (default 1024); the oldest rotated files are skipped when the limit is reached (recorded in the manifest) |
| sos report for Red Hat support | `sos report --batch --label run<id> [--case-id] [--all-logs]` on the node, in a new folder in `/var/tmp` | the sosreport archive as is, one per node, in a `.tar` bundle; deleted from the node after it is fetched | max. 4 nodes, one after another (not at the same time); needs 5 GB free in `/var/tmp` (10 GB with all logs) and the `sos` package |
| Collect BMC event logs | BMC (Redfish GET over HTTPS, BMC web account): all log services (SEL, platform/active log, audit log), all pages | summary per log and severity, the 200 newest entries; all entries in `export/bmc-events.csv` | max. 5000 entries per log |
| Collect ONTAP EMS events | ONTAP REST (ONTAP Restore account): `/api/support/ems/events` with a time filter, page by page (`_links.next`) | per severity and per message, the 200 newest events; all in `export/ontap-ems.csv` | max. 10.000 events (10 pages) |
| Collect vCenter events | vCenter (read-only account, pyVmomi `EventHistoryCollector`) | all categories (info, user, warning, error), per type, the 200 newest; all in `export/vcenter-events.csv` | max. 10.000 events |

How Collect logs and sos report work: the archive is streamed **node → director → management host → portal server** over
the SSH that already exists (no file is left on the node, the director, or the management host). For logs, all nodes are read
at the same time; sos report goes one node after another because it loads a node for a few minutes. Masking of secrets (passwords,
Keystone tokens, `X-Auth-Token`, credentials in URLs such as `rabbit://user:password@`, password hashes) is done **on the node** before the
log lines leave it. A vCenter / NSX-T support bundle is not made: it needs a diagnostic account, not a read-only one.

Opening a log bundle: `tar xf logs-<site>-run<id>-<time>.tar`, then in the folder of each node `tar xzf <node>.logs.tar.gz`.

Export: every check result can be downloaded as **CSV** (all tables per step, including the CPU / memory / disk /
pool values and their status, plus *How to fix it*) or opened as a **PDF** report (Print → Save as PDF).

## Automation flows that differ from the WI text

The KB content is not changed. When a WI step is wrong or risky, the automation uses the corrected flow below.

| WI | WI text | Flow in the automation |
|---|---|---|
| Rollback Volume Type | `cinder manage --migration-policy on-demand <id>` is not a correct command (`cinder manage` is for importing volumes from the backend). The original volume is always reset to `in-use`, while a volume that is not *attached* must be `available` | Remove `cinder manage`; reset the original volume to `in-use --attach-status attached` only if it is *attached*, otherwise `available --attach-status detached`; first check that the replica is still `migration_status target:<id>` |
| Cinder Volume Over 80% | The calculation basis is still *allocated* (overcommit 2:1 at DCA) | Use *used*: ONTAP FlexVol used %, or Cinder total − free; only snapshots older than 14 days are cleaned up |
| Snapshot Volume Error, VM Fails to Resize, Backup Scheduler | Retype is mentioned only through Horizon | Add the CLI per Red Hat: `cinder retype --migration-policy on-demand <volume> <type>` (`openstack volume set --retype-policy` has been renamed) |
| Volume Cannot Be Re-Attached, Cinder Volume Over 80% | The "Automation" section says all actions are manual | The actions can be run from the portal by an authorized operator, with a re-check before anything is changed |
| Instance Cannot Connect Through the Metro Network | There is no migration command | `openstack server migrate --live-migration <server>` (RHOSP 16.2/17.1; RHOSP 13 uses `--live <host>`) |
| WI troubleshooting firewall nsxt & linux | `nft flush ruleset` followed by `systemctl mask nftables` turns off the whole host firewall | Insert a specific accept rule (source, port) like the one the portal creates; flush only with the approval of the VM owner |
| Memory Alert CDN | `kill -9` directly on logparser | `kill -TERM` first, `kill -9` only if it does not stop |
| Disk Full Alert on /run | `rm -rf /run/aide/*` while AIDE may still be running | Stop the `aide` process first, then delete the contents of `/run/aide` |

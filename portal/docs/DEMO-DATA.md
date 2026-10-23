# Demo data for testing (test_mode.sh)

All IDs, names, and hosts below exist in the local demo (`./test_mode.sh`, http://localhost:8083). All the systems
are fake (mocks) and no real system is touched. The demo login accounts are printed by `test_mode.sh` at start:
`portaladmin` (local administrator), `operator` and `l1` (fake AD accounts).

The "Expected result" column lists the findings that are deliberately built into the demo data.

## 1. Operation Automation — Acme Flex (OpenStack)

Applies to all sites (DCB, DCA, DCC). Pool names follow the site: `DCBOPNSTACK_…`, `DCAOPNSTACK_…`, `DCCOPNSTACK_…`.

### Project

| Name | ID |
|---|---|
| customer-a80 | `c0ffee00000000000000000000000001` |
| customer-other | `c0ffee00000000000000000000000002` |
| admin | `ad000000000000000000000000000000` |

### Instance

| Name | ID | Status | Notes |
|---|---|---|---|
| web-01 | `5e5e5e5e-0000-4000-8000-000000000001` | ACTIVE | floating IP 203.0.113.10, IP 10.249.1.15, SG default + web (22, 80, 443, ICMP) |
| app-02 | `5e5e5e5e-0000-4000-8000-000000000002` | SHUTOFF | IP 10.249.1.16, no floating IP |
| build-03 | `5e5e5e5e-0000-4000-8000-000000000003` | BUILD | stuck for about 3 hours |
| err-04 | `5e5e5e5e-0000-4000-8000-000000000004` | ERROR | "No valid host was found" (project customer-other) |

### Volume

| Name | ID | Status | Type | Notes |
|---|---|---|---|---|
| db-prod-data | `11111111-0000-4000-8000-000000000001` | in-use | standard (old on DCA) | on web-01, has 4 snapshots |
| web-01-root | `11111111-0000-4000-8000-000000000002` | in-use | fas500f-standard | on web-01 |
| archive-2024 | `11111111-0000-4000-8000-000000000003` | available | basic (old on DCA) | project customer-other |
| logs-old | `11111111-0000-4000-8000-000000000004` | available | fas500f-basic | has 3 snapshots |
| app-02-root | `11111111-0000-4000-8000-000000000005` | in-use | premium (old on DCA) | on app-02 |
| app-02-data | `11111111-0000-4000-8000-000000000006` | **attaching** | fas500f-standard | attach is stuck, with no attachment |
| report-db | `11111111-0000-4000-8000-000000000007` | **reserved** | standard | retype/migration failed (migstat migrating) |
| build-03-root | `11111111-0000-4000-8000-000000000008` | **error** | fas500f-standard | |
| backup-target | `11111111-0000-4000-8000-000000000009` | available | fas500f-standard | |
| erp-data | `11111111-0000-4000-8000-00000000000a` | in-use | affa-premium | on web-01 |
| report-db (copy) | `11111111-0000-4000-8000-00000000000b` | available | fas500f-standard | temporary volume for the migration (`target:…0007`) |

### Checks and inputs

| Check | Input | Expected result |
|---|---|---|
| Cinder volume over 80% | empty (or pool `CINDER_15`) | CINDER_14 and CINDER_15 ≥ 80% (ONTAP FlexVol) → `openstack volume migrate` command to a pool with more free space |
| Old volume types | site **DCA**, project empty or `customer-a80` | old volume types (standard/basic/premium) → retype command |
| Project quota full | `customer-a80` | compute full (10/10 instances) → `openstack quota set` with the new value |
| Instances or volumes stuck | empty (or project `customer-a80`) | build-03 BUILD, app-02-data attaching, report-db reserved/failed migration, build-03-root error |
| Volume cannot be attached again | volume `11111111-0000-4000-8000-000000000006`, instance `5e5e5e5e-0000-4000-8000-000000000001` | reset-state, then attach to web-01 |
| | volume `11111111-0000-4000-8000-000000000001` | still attached to web-01 → detach first |
| | volume `11111111-0000-4000-8000-000000000008` | status error → check the log, escalate |
| Instance cannot be reached | `5e5e5e5e-0000-4000-8000-000000000001`, port 443 | OK (SG allows 443) |
| | `5e5e5e5e-0000-4000-8000-000000000001`, port 6600 | SG does not allow 6600 → `security group rule create` command |
| | `5e5e5e5e-0000-4000-8000-000000000002` | instance SHUTOFF, no floating IP |
| Custom Port TCP is DOWN | IP 203.0.113.10, port 6600 | instance web-01 found, SG blocks 6600 |

## 2. Operation Automation — NetApp ONTAP

| Check | Site | Expected result |
|---|---|---|
| ONTAP cluster health | DCC | LIF cluster_mgmt is not on its home port → revert command in the ONTAP CLI |
| | DCB / DCA | healthy |

## 3. Operation Automation — Linux hosts, CDN, DNS, SIEM, GB200

Host names follow the site: `dcb-…`, `dca-…`, `dcc-…`. The IPs are the same on all sites.

| Check | Host (or IP from the alert) | Other input | Expected result |
|---|---|---|---|
| Alert: disk full on /run | `dca-cdn-lb-01` (or `172.31.10.67:9100`) | | /run 97% used by AIDE files → `rm -rf /run/aide/*` |
| Alert: root disk full | `dca-cdn-lb-01` | | haproxy.log 141 GB, no logrotate, journal 2.1 GB |
| Alert: memory | `dca-cdn-lb-01` | | 5 stuck logparser processes → `kill -9` their PIDs |
| Alert: DatasourceError | `dca-cdn-lb-02` (172.31.10.68) | | container lb exited with 137 → `docker start lb` |
| Repository website down | `dca-repo-01` (172.31.20.5) | default domain | nginx failed, certificate expired |
| Varnish MSE resize | `dca-cdn-vcp-2` (172.31.10.71) | | store 940G → resize command to 460G |
| DNS recursor syslog full | `dca-dns-recursive` (172.31.30.9) | | quiet=no in recursor-local.conf, syslog 44 GB |
| Service not answering / port conflict | `app-vm-01` (10.249.1.20) | port 80, service nginx | apache2 holds port 80 |
| Port blocked on a Linux VM | `app-vm-01` | port 27017, source 10.249.2.15 | nftables handle 6 rejects 27017 → `nft insert rule … position 6` |
| OpenStack RHEL forwards logs | `rhel-vm-01` (10.249.1.21) | default collector | SELinux does not allow TCP 541 → `semanage port -a` |
| SIEM collector | `siem-collector-01` (172.26.0.40) | | veeam logs stopped, files from 10.246.5.21/.22 end up in the unknown folder |
| ESXi sends syslog | `esxi-dca-07` (172.25.10.7) | default collector | remote host is empty, syslog ruleset is off |
| GB200 NIC link down | `gb200-ct-01` (10.243.0.11) | | `ens1f1np1` has no link |

## 4. Operation Automation — network

| Check | Site / host | Other input | Expected result |
|---|---|---|---|
| VyOS SNAT / DNAT not working | `dca-natgw-01` (11.7.101.238) | WAN empty | WAN-IN without established/related (rule 5), UDP 514 not allowed (rule 71) |
| VyOS static route / Metro | `dca-natgw-01` | prefix 10.242.0.0/16, gateway 172.26.220.1 | 172.0.0.0/8 is not active (next hop outside the subnet), 10.242.0.0/16 does not exist yet |
| VyOS upgrade pre-check | `dca-natgw-01` | | hw-id of eth1/eth2 not set, dropbear key present, upgrade order 1.3.8 → 1.5 |
| Huawei RCGW prefix | site **DCB**, `DCB02RCGW03` (172.26.15.15) | prefix 11.5.244.0/23 | complete change block (BGP, NULL0, ALLOWED_BGP_OUT 12 entries + new) |

## 5. Operation Automation — Acme Prime (VMware)

vCenter and NSX-T exist only on the DCA site. There is only one vCloud Director for all sites (credential `ro-vcd`), and the
vCloud VM checks compare it with the vCenter of the selected site.

The read-only accounts for vCenter, NSX-T, and vCloud Director are already filled in automatically in Administration → Credentials.

### vCenter / NSX-T

| Check | Input | Expected result |
|---|---|---|
| Datastore low free space | minimum free 20 | DCA-DS-SSD-01 7% free (14 VMs → `Move-VM` to DCA-DS-ARCHIVE); DCA-DS-SSD-02 (2 VMs → old snapshots) |
| SNAT priority (NSX-T) | Tier-1 `t1-cust-a`, source 172.31.50.2 (optional) | the specific SNAT-Colo rule is processed after the catch-all → PATCH priority 100/200 |
| Host high CPU / memory, VM resource pool | host `esxi-dca-02` (or empty) | CPU 94% from render-farm-01 → `Move-VM` to esxi-dca-03; DRS partiallyAutomated; app-04 outside the Org VDC pool |

Demo vCenter hosts: `esxi-dca-01`, `esxi-dca-02` (hot), `esxi-dca-03` (spare capacity), `esxi-dca-04` (maintenance), cluster
`DCA-CL-PRIME-01`.

### vCloud Director

| Check | Input | Expected result |
|---|---|---|
| VM power on fails / inconsistent / slow tasks | VM `erp-app-01` | memory quota of Org VDC CUST-A-VDC is too low → raise it to at least 73728 MB |
| | VM `web-02` | IP 11.15.66.102 is used by web-03 → change to the free IP 11.15.66.100 |
| | VM `db-03` | vCloud POWERED_OFF, vCenter POWERED_ON (inconsistent) |
| | VM `app-04` | VM is not in the Org VDC resource pool → `Move-VM` |
| | VM `report-05` | task stuck for 95 minutes → `cell-management-tool` steps |
| Edge gateway (IPsec, NAT, firewall) | edge `CUST-A-EDGE`, VM IP 10.249.10.16, port 8443, public IP 11.4.20.31 | tunnel to-HQ DOWN; DNAT exists; firewall blocks 8443 (default_rule) |
| | edge `CUST-A-EDGE`, VM IP 10.249.10.15, port 443 | firewall allows (allow-https) |

## 6. ONTAP Restore

Example volumes (on all sites):

| ID | Name | Notes |
|---|---|---|
| `a80a1a07-06b8-489b-a984-b046981f68b9` | vm-01-data | extra disk (vdb) of vm-01: transfer or attach |
| `55555555-5555-4555-8555-555555555555` | vm-01-root | boot disk (vda) of vm-01: also "create a new instance like vm-01" |
| `22222222-2222-4222-8222-222222222222` | vm-02-data | FlexVol full: restore is rejected |
| `33333333-3333-4333-8333-333333333333` | vm-03-retype | LUN uses name_id (`volume-44444444-…`) |

- Snapshots: `weekly.2025-12-14_0015`, `daily.2025-12-17_0010`, `hourly.2025-12-17_1705`, `…_1805`, `…_1905`, `…_2005`.
- Target project: empty (source project customer-a80) or `c0ffee00000000000000000000000002` (customer-other).
- Pools in Review: CINDER_14 (LUN pool), CINDER_16 (lun move), CINDER_15 full, CINDER_17 on another SVM, CINDER_TEST50 test pool.
- Instances for attach: vm-01 `5e000000-0000-4000-8000-000000000001`, vm-02 `5e000000-0000-4000-8000-000000000002` (SHUTOFF), vm-03 `5e000000-0000-4000-8000-000000000003` (ERROR, rejected).

## 7. ACI

| Object | Value |
|---|---|
| Tenant | `CLOUD-1` (`common`, `OpenStack-Tenant`, and `<SITE>-Only` also exist) |
| Application profile | `MGMT-InBand`, `PUBLIC-CLOUD-OPENSTACK` |
| EPG | `Mgmt-InBand-EPG`, `MGMT-VYOS` |
| Domain | `<SITE>-PHYS`, `<SITE>-DVS`, `<SITE>-OSP` |
| Path | leaf 101 `eth1/1`, `eth1/13`; leaf 106 `eth1/17`; PC `PC-SERVER-01`; FEX 111 `eth1/5`; vPC 103-104 `Openstack-Traffic-A-PG` |
| VLAN | 300–302 are already used by other EPGs/L3Outs (conflict test); 303–310 are free in pool `<SITE>-PHYS-VLANS` |
| APIC service account | any user, demo password from `tests/mock_apic.py` (already filled in Credentials) |

## 8. Direct fixes (Run this fix)

- Accounts: `portaladmin` and `operator` may run fixes; `l1` can only run checks (the button is locked and the reason is shown).
- DCA hosts in **Hosts & SSH** use the credential `ops-root-key` (*May run fixes*). `gb200-ct-01` uses `wi-ro-password` (read only).
  DCB and DCC hosts come only from `sites.yml`, so they are read-only.
- After a fix, the check runs again automatically. The fake host remembers the fix, so the result changes to OK.

| Try | Input | Fix |
|---|---|---|
| Alert: DatasourceError | `dca-cdn-lb-02` | `docker start lb` (standard), re-check OK |
| Alert: disk full on /run | `dca-cdn-lb-01` | delete AIDE files (high risk: type `dca-cdn-lb-01`) |
| Alert: memory | `dca-cdn-lb-01` | kill -9 the logparser processes (high risk) |
| DNS recursor syslog full | `dca-dns-recursive` | quiet=yes + restart, empty the syslog |
| Port blocked on a Linux VM | `app-vm-01`, port 27017, source 10.249.2.15 | `nft insert rule … accept` (standard) |
| Service not answering | `app-vm-01`, port 80, service nginx | stop apache2, start nginx |
| VyOS SNAT / DNAT | `dca-natgw-01` | rule 5 / rule 71 + commit (high risk) |
| ESXi sends syslog | `esxi-dca-07` | `esxcli` loghost + ruleset (standard) |
| ONTAP cluster health | site **DCC** | revert `cluster_mgmt` to its home port (account `ontap:DCC`), re-check OK |

## 9. Where to look (screens + after the fix)

Every run result has a **Where to look** card: one tab per screen, with the options **Now** (what this run found),
**After the fix · expected** (the state after How to fix it), and — if the fix was run from the portal — **After fix #N · as it ran**.

| Demo run | Screens shown |
|---|---|
| `vcd-edge` CUST-A-EDGE, VM 10.249.10.16, port 8443, public 11.4.20.31 | vCloud tenant: Edge General, IPSec VPN (+Statistics), NAT, Firewall (new rule above default_rule) |
| `vcd-vm-power` web-02 / erp-app-01 / db-03 / app-04 | VM list, NICs (new IP), IP Allocations, Org VDC Allocation (provider), Tasks, vSphere VM |
| `vmware-host-usage` esxi-dca-02 | vSphere: Hosts cluster, VMs host (vMotion plan), DRS, resource pool |
| `vcenter-datastore` | vSphere Storage: Datastores, VMs per datastore + capacity bar |
| `nsxt-snat-priority` t1-cust-a | NSX Manager → NAT (new priority) |
| `ontap-cluster-health` (DCC) | System Manager: Network interfaces (cluster_mgmt back on its home port), Nodes, e0M, Events |
| `project-quota` customer-a80, `stuck-resources`, `volume-attach`, `custom-port-tcp`, `cinder-pool-usage`, `volume-type-legacy` | Horizon RHOSP (Overview Limit Summary, Instances, Volumes, Volume Types, Security Groups) + terminal director |
| SSH checks (CDN, DNS, Linux, VyOS, Huawei, SIEM, ESXi, GB200) | Host terminal: commands + output (secrets masked), numbered finding lines |

# ACI Web UI Automation: What Is Sent to APIC

This document describes every call the ACI Web UI makes to APIC: when it happens, which API is used, and which calls only read and which change the fabric. It is based on `aci_webui/apic_sites.py` (connection) and `aci_webui/aci.py` (data and changes), version of 28 Sep 2026 (including the check for VLANs already used by another EPG, free VLAN suggestions, binding source in the Report, and static port undo).

> **ACI Web UI does not use Ansible.** This Python (Flask) application calls the APIC REST API directly. The principle is the same as ONTAP Restore (see `ontap_restore/docs/AUTOMATION.md`): read and show a comparison first (Review), then send the change once after confirmation (Apply).

## Summary

- **Connection direction:** the `aci-webui` service on the bastion (`/opt/aci_webui`) connects to the APIC of each site over HTTPS 443, directly without a proxy.

  | Site | APIC |
  |---|---|
  | DCB | 172.26.2.250 |
  | DCA | 172.24.27.251 |
  | DCC | 172.25.172.53 |

  This list is set in `ACI_SITES` in `/etc/aci_webui/aci-webui.env`.
- **Accounts:** operators sign in to the portal with an AD account through Duo SSO (or a local portal account), not with a personal ACI account. The Web UI connects to the APIC of each site with **one service account per site**, which the administrator enters in **Administration → Credentials** (the password is stored encrypted on the server). In the APIC audit log, changes are recorded under the service account; in the **History** menu, the portal user (AD) who made the change is recorded together with the APIC account.
- **Only two kinds of changes:** **Static Port** (path binding to an EPG) and **Provisioning** (Tenant/VRF/BD/Application Profile/EPG/domain). Other menus only read.
- **One Apply = one POST.** APIC processes it as one transaction: all succeed or all fail.
- **No deletion.** The application never sends DELETE or `status: deleted`.

## 1. Connection to APIC (service account per site)

| When | APIC call |
|---|---|
| The first time a site is used, or the token is rejected | `POST /api/aaaLogin.json` with the service account of that site. The token is kept in server memory. |
| While in use | `GET /api/aaaRefresh.json` after half of the token lifetime (`refreshTimeoutSeconds` of APIC); if APIC rejects the token, log in again once. |
| The administrator saves a service account (Credentials) | `POST /api/aaaLogin.json` as a connection test; the result is shown on the Credentials page |

A site without a service account is marked *No service account* and its APIC is not contacted; a site whose last login failed gets a warning icon. Validation of the APIC TLS certificate is optional.

## 2. Reading data (changes nothing)

All reads use APIC paging (`page-size=5000&page=N`) until all objects are retrieved.

| Web UI function | APIC call |
|---|---|
| Tenant dropdown | `GET /api/node/class/fvTenant.json` |
| Application Profile dropdown | `GET /api/node/mo/uni/tn-<T>.json?query-target=children&target-subtree-class=fvAp` |
| EPG dropdown | `GET /api/node/mo/uni/tn-<T>/ap-<A>.json?query-target=children&target-subtree-class=fvAEPg` |
| Provisioning: VRF, BD, App Profile, L3Out owned by the tenant | `GET /api/node/mo/uni/tn-<T>.json?query-target=children&target-subtree-class=fvCtx,fvBD,fvAp,l3extOut` |
| Provisioning: Physical/VMM domains | `GET /api/node/class/physDomP.json` and `GET /api/node/class/vmmDomP.json` |
| Static Port: **Search APIC**; product template (marks paths that exist/do not exist) | `GET /api/node/class/fabricPathEp.json?order-by=fabricPathEp.dn` |
| Static Port: **Binding existing**; comparison in Review | `GET /api/node/mo/<dn EPG>.json?query-target=children&target-subtree-class=fvRsPathAtt` |
| Static Port: **VLAN check on entry** (and again in Review/Apply) | `GET /api/node/class/fvRsPathAtt.json?query-target-filter=or(eq(fvRsPathAtt.encap,"vlan-300"),…)`, the same for `fvRsNodeAtt` (static leaf) and `l3extRsPathL3OutAtt` (L3Out interface); max. 40 VLANs per query |
| Check whether an object already exists (EPG, tenant, BD relation of an EPG) | `GET /api/node/mo/<dn>.json` |
| Report per EPG / App Profile / Tenant | `GET /api/node/mo/<dn>.json?query-target=children` (EPG) or `query-target=subtree` (App Profile/Tenant), with `target-subtree-class=fvRsPathAtt&order-by=fvRsPathAtt.dn` |
| Report of all bindings | `GET /api/node/class/fvRsPathAtt.json?order-by=fvRsPathAtt.dn` |
| Report: **Source** and **Last changed (APIC)** columns | From the same Report query (attribute `modTs`), compared with the portal history (`audit.db`): *Portal* (change #N), *Outside portal*, *Changed outside portal*, *Removed outside portal*. No extra APIC call |
| Export Excel/CSV | The same data as the Report, processed on the server (`report.py`); extra columns Source, Portal Change, Portal Setting, Last Changed (APIC) |
| Static Port: **Suggest free VLAN** | `GET /api/node/mo/<dn EPG>.json?query-target=children&target-subtree-class=fvRsDomAtt` (EPG domain) → per domain `GET /api/node/mo/<dn domain>.json?query-target=children&target-subtree-class=infraRsVlanNs` (VLAN pool) → per pool `GET /api/node/mo/uni/infra/vlanns-[<pool>]-<static\|dynamic>.json?query-target=children&target-subtree-class=fvnsEncapBlk` (VLAN blocks); used VLANs: `GET /api/node/class/fvRsPathAtt.json`, `fvRsNodeAtt.json`, `l3extRsPathL3OutAtt.json`. Only static blocks (an `inherit` block follows the pool mode) |
| **IP Usage**: learned IPs per EPG and subnet, free IPs, IP suggestion | `GET /api/node/class/fvCEp.json`, `fvIp.json`, `fvRsCEpToPathEp.json` (endpoints, their IPs, and the paths where they were learned; cached for 60 seconds per site), `GET /api/node/mo/<tenant / app profile / EPG>.json?query-target=subtree&target-subtree-class=fvAEPg` and `...fvRsBd` (or class `fvAEPg` / `fvRsBd` for all tenants), `GET /api/node/class/fvSubnet.json` (BD and EPG subnets). Used IP = subnet gateway + IP learned on any endpoint in the fabric of that site. Every learned IP is also recorded in the portal database (`aci_ip_seen`); an IP seen in the last 30 days (`ACI_IP_RECENT_DAYS`) is not suggested as a free IP. Nothing is sent to APIC |
| **Templates** (product templates): check new paths on entry, again in Review and Save | `GET /api/node/class/fabricPathEp.json?order-by=fabricPathEp.dn` (the same as Search APIC). A path added to a template must exist in the fabric of that site; old paths that no longer exist are only marked. Saving a template **sends nothing to APIC**: the template is stored in the portal database (`aci_templates`, `aci_products`) per site and product, and recorded in History (Action *Product template*) in the same transaction |
| History: **Undo** (Review undo) | `GET /api/node/mo/<dn EPG>.json` and the existing bindings of the EPG (see the Binding existing row), then the VLAN check as in Apply for the restored values |

## 3. Static Port (changes)

**VLAN check on entry** (read only): as soon as a VLAN is entered (table row, *VLAN for all paths* on the product template, Search APIC, Interface range), the browser calls `/api/vlan-usage` and the server asks APIC where that VLAN is already used (see the table in section 2):
- used by **another EPG** (static path / static leaf) or an **L3Out interface** in that site → the VLAN column turns red with the name of the user; the row is counted as *to fix* and **Review & apply** cannot continue until the VLAN ID is changed;
- bindings that belong to the selected EPG itself are not counted (an EPG may use its VLAN on many ports);
- the result is cached briefly (1 minute) in the browser per site and EPG.

**Review** (read only): the server fetches the existing bindings of that EPG and compares them with the binding table, and **checks the VLAN again** for every new binding or binding whose VLAN changed. A conflicting VLAN is shown in red with the EPG/L3Out that uses it, and the Apply button is disabled. Bindings that only change mode/immediacy are not checked (their VLAN stays the same). Each row gets a status:
- **New**: the path does not exist in the EPG yet.
- **Changed**: the path already exists, but the encap, mode, or immediacy is different.
- **Same**: not sent.

**Apply**:
1. The server **recalculates** the comparison and the VLAN check from the APIC data at that moment, and does not use the results from the browser. If a VLAN is still used by another EPG → rejected ("VLAN 300 is already used by EPG …. Use a new VLAN ID"), nothing is sent and nothing is recorded.
2. The history record is written (see section 5).
3. One POST is sent, containing only the **New** and **Changed** bindings:
   ```
   POST /api/node/mo/uni/tn-<T>/ap-<A>/epg-<E>.json
   {"fvAEPg": {"attributes": {"dn": "uni/tn-<T>/ap-<A>/epg-<E>"},
     "children": [
       {"fvRsPathAtt": {"attributes": {"tDn": "topology/pod-1/protpaths-118-119/pathep-[Openstack-Traffic-A-PG]",
                                       "encap": "vlan-186", "mode": "regular", "instrImedcy": "immediate"}}},
       …]}}
   ```
   - `mode`: `regular` (Trunk), `native` (Access 802.1P), `untagged` (Access Untagged).
   - `instrImedcy`: `immediate` or `lazy` (On Demand).
   - `tDn`: physical path (`paths-<node>/pathep-[ethX/Y]`), port-channel/vPC (`protpaths-<a>-<b>/pathep-[<PG>]`), or FEX (`extpaths`).

Other bindings that already exist in the EPG but are not in the table are **not touched**. The "Changed" status updates the encap/mode/immediacy of that binding.

**Undo of a static port change** (History → change detail → *Undo this change…*; only administrators and the user who made the change; not for provisioning):
1. The server reads the bindings of that EPG in APIC now (the site comes from the history record, not the site selected in the browser). For each path of the original change:
   - **New** and still exactly as sent → **deleted**;
   - **Changed** and still exactly as sent → **restored** to the previous values (encap, mode, immediacy);
   - changed or deleted by someone else since then → **skipped** (a newer change is never overwritten).
2. The restored VLAN is checked as in Apply; if it is already used by another EPG or L3Out, the undo is rejected.
3. The history record is written first (a new change with `undo_of`), then one POST:
   ```
   POST /api/node/mo/uni/tn-<T>/ap-<A>/epg-<E>.json
   {"fvAEPg": {"attributes": {"dn": "uni/tn-<T>/ap-<A>/epg-<E>"},
     "children": [
       {"fvRsPathAtt": {"attributes": {"tDn": "<new path>", "status": "deleted"}}},
       {"fvRsPathAtt": {"attributes": {"tDn": "<changed path>", "encap": "<old>", "mode": "<old>", "instrImedcy": "<old>"}}}]}}
   ```
4. Success → the original change is marked `undone_by`; activity log `static_port.undone`. A change that has already been undone, or the undo change itself, cannot be undone again. If the EPG no longer exists → the undo is rejected (the POST would not create a new EPG).

## 4. Provisioning (changes)

**Review** shows each object with its action (create new / use existing / already exists, updated), warnings, and the full JSON payload.

**Apply**: the server recalculates, writes the history record, then sends **one POST** containing the tenant tree:
```
POST /api/node/mo/uni/tn-<T>.json
fvTenant (dn; name + descr if the tenant is new)
 ├─ fvCtx            new VRF (name, descr)
 ├─ fvBD             new BD (name, descr, arpFlood, unkMacUcastAct)
 │   ├─ fvRsCtx       relation BD → VRF
 │   ├─ fvSubnet      per gateway (ip, scope, preferred, virtual)
 │   └─ fvRsBDToOut   per L3Out
 └─ fvAp             Application Profile (name, descr if new)
     └─ fvAEPg        EPG (name, descr)
         ├─ fvRsBd     relation EPG → BD
         └─ fvRsDomAtt per domain Physical/VMM (tDn, instrImedcy, resImedcy)
```
- Objects in **use existing** mode are only referenced, with no changed attributes.
- If an object requested as **create new** turns out to exist already, Review warns that the object will be updated.
- If the EPG already uses another BD, Review warns that the BD relation will be moved.

## 5. History (audit) and guarantees

- **Record before sending.** Every Apply is recorded in `/var/lib/aci_webui/audit.db` **before** it is sent to APIC. It contains:
  - user, site, APIC, action, target DN, product, summary;
  - the list of bindings sent (Static Port), or the provisioning steps with their JSON payload;
  - client address (on the bastion through PortalProxy: the real IP of the browser; for a browser on the bastion itself also its Remote Desktop session, e.g. `172.26.0.100 (RDP 10.252.2.3, INTRANET\jdoe)`).
- **User activity log.** Every Apply is also entered in **Users → Recent activity** (`static_port.applied/failed/unknown/undone`, `provisioning.*`): target DN, site, product, summary, VLAN, error, and a "change #N" link to History. The log can be filtered by user, activity type, and date, then downloaded with **Export CSV** (administrator; `/export/events.csv`).
- **No record, no change.** If the record cannot be written, Apply is cancelled.
- **The final status** is recorded after APIC replies:

  | Status | Meaning |
  |---|---|
  | Succeeded | APIC accepted the change |
  | Failed | APIC rejected it (the APIC error message is stored) |
  | Unknown | The connection dropped before there was a reply; check the object directly in APIC |
  | Incomplete | The Web UI process stopped in the middle of Apply |
- **What the application never does:**
  - delete objects;
  - change fabric access policies (interface policy group, AEP, VLAN pool);
  - store personal APIC passwords (only one service account per site, encrypted).
- **Matching with the APIC audit.** The APIC audit log records the site service account; the Web UI History records the portal user (AD) who made the change together with the APIC account used, so the two can be matched by time and target DN. Records from before the service account model show the personal ACI account in the User column.
